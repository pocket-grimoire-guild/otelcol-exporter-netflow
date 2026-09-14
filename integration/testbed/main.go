//go:build linux

// Command testbed runs one bounded Collector and pprof qualification case. Testbed's
// logs sender drives canonical receiver-shaped records into a task-local OCB
// process. Exporter output is captured by an independent UDP socket and
// decoded by TShark; the probe does not use the exporter as its decoder.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/testbed"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const (
	caseTimeout      = 30 * time.Second
	records          = 100 // baseline record count retained for test and wrapper compatibility
	sustainedRecords = 1000
	overloadRecords  = 1000
	overloadWorkers  = 4
	captureCap       = 1 << 20
	outputCap        = 1 << 20
	profileCap       = 2 << 20
	artifactCap      = 64 << 20
	stopWait         = 3 * time.Second
	pacing           = 10 * time.Millisecond
)

type runOptions struct {
	name        string
	records     int
	pacing      time.Duration
	concurrency int
}

func scenarioOptions(name string) (runOptions, error) {
	switch name {
	case "baseline":
		return runOptions{name: name, records: records, pacing: pacing, concurrency: 1}, nil
	case "sustained":
		return runOptions{name: name, records: sustainedRecords, pacing: pacing, concurrency: 1}, nil
	case "overload":
		return runOptions{name: name, records: overloadRecords, pacing: 0, concurrency: overloadWorkers}, nil
	case "recovery":
		return runOptions{name: name, records: recoveryRecords, pacing: recoveryPacing, concurrency: 1}, nil
	default:
		return runOptions{}, fmt.Errorf("unsupported scenario %q (want baseline, sustained, overload, or recovery)", name)
	}
}

func baselineOptions() runOptions {
	return runOptions{name: "baseline", records: records, pacing: pacing, concurrency: 1}
}

func (o runOptions) validate() error {
	want, err := scenarioOptions(o.name)
	if err != nil {
		return err
	}
	if o.records != want.records || o.pacing != want.pacing || o.concurrency != want.concurrency {
		return fmt.Errorf("scenario %q options are not fixed at %d records, %s pacing, and %d workers", o.name, want.records, want.pacing, want.concurrency)
	}
	return nil
}

type protocol struct {
	name, wire, profile string
	version, port       int
	origin              uint64
}

func tsharkExecutable() string {
	if path := os.Getenv("TSHARK_BIN"); path != "" {
		return path
	}
	return "tshark"
}

var protocols = map[string]protocol{
	"v5": {
		name: "v5", wire: "netflow_v5", profile: "contrib-netflowreceiver-v0.160.0/netflow-v5-fixed-v1",
		version: 5, port: 2055, origin: 1788220799000000000,
	},
	"v9": {
		name: "v9", wire: "netflow_v9", profile: "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1",
		version: 9, port: 2055, origin: 1788220799000000000,
	},
	"ipfix": {
		name: "ipfix", wire: "ipfix", profile: "contrib-netflowreceiver-v0.160.0/ipfix-general-v1",
		version: 10, port: 4739,
	},
}

// canonicalProvider is a real Testbed DataProvider. It returns one
// receiver-shaped record per call and stops at its explicit limit.
type canonicalProvider struct {
	limit     int64
	count     atomic.Int64
	generated *atomic.Uint64
	unique    bool
}

func (p *canonicalProvider) SetLoadGeneratorCounters(c *atomic.Uint64) { p.generated = c }

func (*canonicalProvider) GenerateTraces() (ptrace.Traces, bool) {
	return ptrace.NewTraces(), true
}

func (*canonicalProvider) GenerateMetrics() (pmetric.Metrics, bool) {
	return pmetric.NewMetrics(), true
}

func (p *canonicalProvider) GenerateLogs() (plog.Logs, bool) {
	for {
		current := p.count.Load()
		if current >= p.limit {
			return plog.NewLogs(), true
		}
		if p.count.CompareAndSwap(current, current+1) {
			if p.generated != nil {
				p.generated.Add(1)
			}
			logs := testpdata.CanonicalIPv4Logs()
			if p.unique {
				logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("source.port", current+1)
			}
			return logs, false
		}
	}
}

var _ testbed.DataProvider = (*canonicalProvider)(nil)

type packet struct {
	b []byte
	t time.Time
}

// capture owns the independent UDP handoff boundary. closeCapture is
// deliberately idempotent because all error paths use deferred cleanup.
type capture struct {
	conn  *net.UDPConn
	stop  chan struct{}
	done  chan struct{}
	close sync.Once
	mu    sync.Mutex
	pkts  []packet
	bytes int
	err   error
	peer  *net.UDPAddr
	copy  []packet
	cerr  error
}

func newCapture() (*capture, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	c := &capture{conn: conn, stop: make(chan struct{}), done: make(chan struct{})}
	go c.read()
	return c, nil
}

func (c *capture) read() {
	defer close(c.done)
	buf := make([]byte, 65535)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, peer, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-c.stop:
					return
				default:
					continue
				}
			}
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		if !peer.IP.IsLoopback() {
			c.err = fmt.Errorf("capture received non-loopback peer %s", peer)
			c.mu.Unlock()
			return
		}
		if c.peer == nil {
			c.peer = &net.UDPAddr{IP: append(net.IP(nil), peer.IP...), Port: peer.Port}
		} else if !c.peer.IP.Equal(peer.IP) || c.peer.Port != peer.Port {
			c.err = fmt.Errorf("capture peer changed from %s to %s", c.peer, peer)
			c.mu.Unlock()
			return
		}
		if c.bytes+n > captureCap {
			c.err = fmt.Errorf("capture byte cap exceeded: %d > %d", c.bytes+n, captureCap)
			c.mu.Unlock()
			return
		}
		// Clone before releasing the read buffer. The cap is checked first.
		payload := append([]byte(nil), buf[:n]...)
		c.pkts = append(c.pkts, packet{b: payload, t: time.Now()})
		c.bytes += n
		c.mu.Unlock()
	}
}

func (c *capture) closeCapture() ([]packet, error) {
	if c == nil {
		return nil, nil
	}
	c.close.Do(func() {
		close(c.stop)
		_ = c.conn.Close()
		<-c.done
		c.mu.Lock()
		c.copy = append([]packet(nil), c.pkts...)
		c.cerr = c.err
		c.mu.Unlock()
	})
	return append([]packet(nil), c.copy...), c.cerr
}

func (c *capture) packetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pkts)
}

type boundedFile struct {
	mu       sync.Mutex
	f        *os.File
	n        int64
	overflow bool
}

func (w *boundedFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n+int64(len(p)) > outputCap {
		w.overflow = true
		return 0, io.ErrShortWrite
	}
	n, err := w.f.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *boundedFile) exceeded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.overflow
}

type child struct {
	cmd      *exec.Cmd
	log      *boundedFile
	waitDone chan struct{}

	mu      sync.Mutex
	waitErr error
	stopErr error
	stop    sync.Once
}

func startChild(ctx context.Context, binary, config, logPath string) (*child, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	log := &boundedFile{f: logFile}
	// Apply the task-local file-descriptor bound in a tiny pre-exec shell and
	// replace it with the Collector, so pprof and /proc observations still name
	// the actual Collector process.
	cmd := exec.Command("/bin/bash", "-c", "ulimit -n 256 || exit 125; exec \"$1\" --config \"$2\"", "testbed-collector", binary, config)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = collectorEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	c := &child{cmd: cmd, log: log, waitDone: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		_ = logFile.Close()
		c.mu.Lock()
		c.waitErr = err
		c.mu.Unlock()
		close(c.waitDone)
	}()
	// CommandContext only kills the direct process. Keep the collector process
	// group bounded when the case context expires as well.
	go func() {
		select {
		case <-ctx.Done():
			_ = c.stopProcess()
		case <-c.waitDone:
		}
	}()
	return c, nil
}

func collectorEnv() []string {
	env := make([]string, 0, 4)
	if path := os.Getenv("PATH"); path != "" {
		env = append(env, "PATH="+path)
	}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	return append(env, "GOMAXPROCS=2", "GOMEMLIMIT=512MiB")
}

func (c *child) stopProcess() error {
	if c == nil {
		return nil
	}
	c.stop.Do(func() {
		forced := false
		var signalErr error
		alreadyDone := false
		select {
		case <-c.waitDone:
			alreadyDone = true
		default:
		}
		if !alreadyDone && c.cmd.Process != nil {
			err := syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				signalErr = err
			}
		}
		if !alreadyDone {
			select {
			case <-c.waitDone:
			case <-time.After(stopWait):
				forced = true
				if c.cmd.Process != nil {
					_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
				}
				<-c.waitDone
			}
		}
		c.mu.Lock()
		waitErr := c.waitErr
		c.mu.Unlock()
		if forced {
			cleanupErr := errors.New("collector required SIGKILL during cleanup")
			if waitErr != nil {
				cleanupErr = errors.Join(cleanupErr, waitErr)
			}
			if signalErr != nil {
				cleanupErr = errors.Join(cleanupErr, signalErr)
			}
			c.mu.Lock()
			c.stopErr = cleanupErr
			c.mu.Unlock()
		} else if waitErr != nil || signalErr != nil {
			cleanupErr := errors.Join(waitErr, signalErr)
			c.mu.Lock()
			c.stopErr = cleanupErr
			c.mu.Unlock()
		}
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopErr != nil {
		return c.stopErr
	}
	if c.log.exceeded() {
		return fmt.Errorf("collector output exceeded %d bytes", outputCap)
	}
	return nil
}

type procSample struct {
	at          time.Time
	userTicks   int64
	systemTicks int64
	rssKB       int64
}

func parseProcClockTicks(data string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(data), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid CLK_TCK %q: %v", strings.TrimSpace(data), err)
	}
	return value, nil
}

func procClockTicks(ctx context.Context) (int64, error) {
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, "getconf", "CLK_TCK")
	var out limitedBuffer
	out.limit = outputCap
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("getconf CLK_TCK: %w", err)
	}
	return parseProcClockTicks(out.String())
}

type processStats struct {
	before  procSample
	after   procSample
	peakRSS int64
	samples int
}

// parseProcStat extracts the Linux /proc/<pid>/stat CPU counters. The comm
// field can contain spaces and ')' characters, so parsing starts after its
// final closing parenthesis rather than splitting the complete line.
func parseProcStat(data string) (userTicks, systemTicks int64, err error) {
	end := strings.LastIndexByte(data, ')')
	if end < 0 || end+1 >= len(data) {
		return 0, 0, errors.New("malformed /proc stat comm field")
	}
	fields := strings.Fields(data[end+1:])
	// fields[0] is state (field 3); utime/stime are fields 14/15.
	if len(fields) <= 12 {
		return 0, 0, errors.New("/proc stat is missing CPU counters")
	}
	userTicks, err = strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse /proc utime: %w", err)
	}
	systemTicks, err = strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse /proc stime: %w", err)
	}
	if userTicks < 0 || systemTicks < 0 {
		return 0, 0, errors.New("negative /proc CPU counter")
	}
	return userTicks, systemTicks, nil
}

func parseProcRSS(data string) (int64, error) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "VmRSS:" || fields[2] != "kB" {
			continue
		}
		rss, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || rss < 0 {
			return 0, fmt.Errorf("parse VmRSS %q: %v", strings.TrimSpace(line), err)
		}
		return rss, nil
	}
	return 0, errors.New("/proc status is missing VmRSS")
}

func readProcSample(pid int) (procSample, error) {
	if pid <= 0 {
		return procSample{}, errors.New("invalid Collector pid")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procSample{}, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return procSample{}, err
	}
	userTicks, systemTicks, err := parseProcStat(string(stat))
	if err != nil {
		return procSample{}, err
	}
	rssKB, err := parseProcRSS(string(status))
	if err != nil {
		return procSample{}, err
	}
	return procSample{at: time.Now(), userTicks: userTicks, systemTicks: systemTicks, rssKB: rssKB}, nil
}

type procSampler struct {
	pid  int
	stop chan struct{}
	done chan struct{}

	mu        sync.Mutex
	before    procSample
	last      procSample
	peakRSS   int64
	samples   int
	sampleErr error

	stopOnce sync.Once
	stats    processStats
	err      error
}

func startProcSampler(pid int) (*procSampler, error) {
	before, err := readProcSample(pid)
	if err != nil {
		return nil, err
	}
	s := &procSampler{
		pid: pid, stop: make(chan struct{}), done: make(chan struct{}),
		before: before, last: before, peakRSS: before.rssKB, samples: 1,
	}
	go s.run()
	return s, nil
}

func (s *procSampler) run() {
	defer close(s.done)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.sample()
		}
	}
}

func (s *procSampler) sample() {
	sample, err := readProcSample(s.pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.sampleErr == nil {
			s.sampleErr = err
		}
		return
	}
	s.last = sample
	s.samples++
	if sample.rssKB > s.peakRSS {
		s.peakRSS = sample.rssKB
	}
}

func (s *procSampler) stopSampling() (processStats, error) {
	if s == nil {
		return processStats{}, nil
	}
	s.stopOnce.Do(func() {
		close(s.stop)
		<-s.done
		after, err := readProcSample(s.pid)
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil {
			s.err = err
		} else {
			s.last = after
			s.samples++
			if after.rssKB > s.peakRSS {
				s.peakRSS = after.rssKB
			}
		}
		s.stats = processStats{before: s.before, after: s.last, peakRSS: s.peakRSS, samples: s.samples}
		if s.err == nil && s.sampleErr != nil {
			s.err = s.sampleErr
		}
	})
	return s.stats, s.err
}

func freePort() (int, error) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	p := l.Addr().(*net.TCPAddr).Port
	return p, l.Close()
}

func freePorts(count int) ([]int, error) {
	if count < 1 {
		return nil, errors.New("port count must be positive")
	}
	listeners := make([]*net.TCPListener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func collectorFDLimit(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.Join(fields[:3], " ") == "Max open files" {
			if fields[3] != "256" || fields[4] != "256" {
				return "", fmt.Errorf("unexpected collector file limit %q", strings.TrimSpace(line))
			}
			return strings.TrimSpace(line), nil
		}
	}
	return "", errors.New("collector file limit is absent from /proc limits")
}

// configFor mirrors the public Config/mapstructure shape in config.go.
// templates and mapping are exporter children; uptime_origin is a root
// exporter field; IPFIX intentionally has no uptime_origin.
func configFor(p protocol, in, out, pprof int) string {
	var b strings.Builder
	b.WriteString("extensions:\n  pprof:\n    endpoint: 127.0.0.1:")
	fmt.Fprintf(&b, "%d\n", pprof)
	b.WriteString("receivers:\n  otlp:\n    protocols:\n      grpc:\n        endpoint: 127.0.0.1:")
	fmt.Fprintf(&b, "%d\n", in)
	b.WriteString("exporters:\n  netflow:\n    endpoint: 127.0.0.1:")
	fmt.Fprintf(&b, "%d\n    protocol: %s\n    schema: contrib-netflowreceiver-v0.160.0\n", out, p.wire)
	switch p.name {
	case "v5":
		b.WriteString("    identity:\n      engine_type: 0\n      engine_id: 0\n")
		fmt.Fprintf(&b, "    uptime_origin: %d\n", p.origin)
	case "v9":
		b.WriteString("    identity:\n      source_id: 42\n")
		fmt.Fprintf(&b, "    uptime_origin: %d\n", p.origin)
		b.WriteString("    templates:\n      id_base: 300\n")
	case "ipfix":
		b.WriteString("    identity:\n      observation_domain_id: 42\n")
		b.WriteString("    templates:\n      id_base: 300\n")
	default:
		panic("unsupported protocol " + p.name)
	}
	b.WriteString("    mapping:\n")
	if p.name != "v5" {
		b.WriteString("      network_type_versions: [{token: ipv4, version: 4}, {token: ipv6, version: 6}]\n")
	}
	fmt.Fprintf(&b, "      profile: %s\n      protocol_identifiers: [{token: tcp, number: 6}]\n      loss_policy: encode_and_count\n", p.profile)
	if p.name == "v5" {
		b.WriteString("      input_guarantees: {flow_io_bytes: layer3_total_octets}\n")
	}
	b.WriteString("service:\n  extensions: [pprof]\n  telemetry:\n    metrics:\n      level: none\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [netflow]\n")
	return b.String()
}

func waitPprof(ctx context.Context, port int, child *child) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/", port)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-child.waitDone:
			child.mu.Lock()
			err := child.waitErr
			child.mu.Unlock()
			if err == nil {
				return errors.New("collector exited before pprof became ready")
			}
			return fmt.Errorf("collector exited before pprof became ready: %w", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func profile(ctx context.Context, port int, endpoint, path string) error {
	profileCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(profileCtx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/%s", port, endpoint), nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pprof status %s", resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, profileCap+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		return fmt.Errorf("write profile: %v %v", copyErr, closeErr)
	}
	if n == 0 || n > profileCap {
		return fmt.Errorf("profile size %d outside bounded range", n)
	}
	return nil
}

func parseProfile(ctx context.Context, path string) (string, error) {
	return parseProfileForBuild(ctx, path, "")
}

func parseProfileForBuild(ctx context.Context, path, wantBuildID string) (string, error) {
	return parseProfileForBuildIndex(ctx, path, wantBuildID, "")
}

func parseProfileForBuildIndex(ctx context.Context, path, wantBuildID, sampleIndex string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := []string{"tool", "pprof", "-top", "-nodecount=5"}
	if sampleIndex != "" {
		args = append(args, "-sample_index="+sampleIndex)
	}
	args = append(args, path)
	cmd := exec.CommandContext(ctx, "go", args...)
	var out limitedBuffer
	out.limit = outputCap
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	text := out.String()
	if !strings.Contains(text, "Showing nodes") {
		return "", errors.New("missing pprof top table")
	}
	if wantBuildID != "" && !strings.Contains(text, "Build ID: "+wantBuildID) {
		return "", fmt.Errorf("profile build ID does not match Collector %q", wantBuildID)
	}
	lines := strings.Split(text, "\n")
	var summary []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "File:") || strings.HasPrefix(trimmed, "Build ID:") ||
			strings.HasPrefix(trimmed, "Type:") || strings.HasPrefix(trimmed, "Duration:") ||
			strings.Contains(trimmed, "Total samples =") || strings.HasPrefix(trimmed, "Showing nodes accounting") {
			summary = append(summary, trimmed)
		}
	}
	if strings.Contains(text, "Type: cpu") {
		foundSamples := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "Total samples =") {
				foundSamples = true
				parts := strings.SplitN(trimmed, "Total samples =", 2)
				if len(parts) == 2 && strings.HasPrefix(strings.TrimSpace(parts[1]), "0") {
					return "", errors.New("CPU profile has zero samples")
				}
			}
		}
		if !foundSamples {
			return "", errors.New("CPU profile has no total sample summary")
		}
	}
	if sampleIndex != "" && !strings.Contains(text, "Type: "+sampleIndex) {
		return "", fmt.Errorf("pprof profile has no %s sample table", sampleIndex)
	}
	if len(summary) == 0 {
		return "", errors.New("pprof summary is empty")
	}
	return strings.Join(summary, "; "), nil
}

func parseGoroutineCount(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 || len(data) > profileCap {
		return 0, fmt.Errorf("goroutine profile size %d outside bounded range", len(data))
	}
	const prefix = "goroutine profile: total "
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
		if err != nil || count < 0 {
			return 0, fmt.Errorf("parse goroutine count %q: %v", line, err)
		}
		return count, nil
	}
	return 0, errors.New("goroutine profile is missing total count")
}

func parseHeapStats(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > profileCap {
		return "", fmt.Errorf("heap stats size %d outside bounded range", len(data))
	}
	wanted := []string{"TotalAlloc", "Mallocs", "Frees", "HeapAlloc", "NumGC"}
	values := make(map[string]int64, len(wanted))
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) != 3 || fields[1] != "=" {
			continue
		}
		for _, key := range wanted {
			if fields[0] != key {
				continue
			}
			value, parseErr := strconv.ParseInt(fields[2], 10, 64)
			if parseErr != nil || value < 0 {
				return "", fmt.Errorf("parse heap stat %q: %v", line, parseErr)
			}
			values[key] = value
		}
	}
	parts := make([]string, 0, len(wanted))
	for _, key := range wanted {
		value, ok := values[key]
		if !ok {
			return "", fmt.Errorf("heap stats missing %s", key)
		}
		parts = append(parts, strings.ToLower(key)+"="+strconv.FormatInt(value, 10))
	}
	return strings.Join(parts, ","), nil
}

func collectorBuildID(ctx context.Context, path string) (string, error) {
	profileCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(profileCtx, "readelf", "-n", path)
	var out limitedBuffer
	out.limit = outputCap
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Build ID:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "Build ID:"))
			if id != "" {
				return id, nil
			}
		}
	}
	return "", errors.New("empty Collector build ID")
}

func writePCAP(path string, packets []packet, source, dest int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := binary.Write(f, binary.LittleEndian, struct {
		Magic           uint32
		Major, Minor    uint16
		Zone            int32
		Sig, Snap, Link uint32
	}{0xa1b2c3d4, 2, 4, 0, 0, 65535, 1}); err != nil {
		return err
	}
	written := 24
	for _, p := range packets {
		frame := frameFor(p.b, uint16(source), uint16(dest))
		if written+16+len(frame) > outputCap {
			return fmt.Errorf("pcap exceeds %d byte cap", outputCap)
		}
		if err := binary.Write(f, binary.LittleEndian, struct{ Sec, Usec, Incl, Orig uint32 }{
			uint32(p.t.Unix()), uint32(p.t.Nanosecond() / 1000), uint32(len(frame)), uint32(len(frame)),
		}); err != nil {
			return err
		}
		if _, err := f.Write(frame); err != nil {
			return err
		}
		written += 16 + len(frame)
	}
	return f.Sync()
}

func frameFor(payload []byte, source, dest uint16) []byte {
	udpLen := 8 + len(payload)
	b := make([]byte, 14+20+udpLen)
	copy(b[:6], []byte{2, 0, 0, 0, 0, 2})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+udpLen))
	copy(ip[12:16], []byte{192, 0, 2, 254})
	copy(ip[16:20], []byte{192, 0, 2, 253})
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	u := ip[20:]
	binary.BigEndian.PutUint16(u[0:2], source)
	binary.BigEndian.PutUint16(u[2:4], dest)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	copy(u[8:], payload)
	binary.BigEndian.PutUint16(u[6:8], udpChecksum(ip[12:20], u))
	return b
}

func checksum(b []byte) uint16 {
	var n uint32
	for len(b) >= 2 {
		n += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	for n>>16 != 0 {
		n = n&0xffff + n>>16
	}
	return ^uint16(n)
}

func udpChecksum(addr, udp []byte) uint16 {
	b := append([]byte(nil), udp...)
	b[6], b[7] = 0, 0
	pseudo := append(append([]byte(nil), addr...), []byte{0, 17, byte(len(udp) >> 8), byte(len(udp))}...)
	pseudo = append(pseudo, b...)
	result := checksum(pseudo)
	if result == 0 {
		return 0xffff
	}
	return result
}

type decodeResult struct {
	records       int
	templates     int
	template300   bool
	firstData     int
	firstTempl    int
	lastTempl     int
	lastBootstrap int
	identities    []decodedRecord
	text          string
}

type decodedRecord struct {
	frame         int
	identity      int
	frameTime     time.Time
	frameTimeText string
}

func decode(ctx context.Context, path string, port, version int) (decodeResult, error) {
	return decodeExpected(ctx, path, port, version, 0)
}

func decodeExpected(ctx context.Context, path string, port, version, expectedFrames int) (decodeResult, error) {
	var out limitedBuffer
	out.limit = outputCap
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tsharkExecutable(), "-r", path, "-d", fmt.Sprintf("udp.port==%d,cflow", port), "-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-e", "frame.number", "-e", "cflow.version", "-e", "cflow.flowset_id", "-e", "cflow.template_id", "-e", "cflow.srcaddr", "-e", "cflow.srcport", "-e", "frame.time_epoch")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return decodeResult{text: out.String()}, err
	}
	result := decodeResult{firstData: -1, firstTempl: -1, lastTempl: -1, lastBootstrap: -1, text: strings.TrimSpace(out.String())}
	if result.text == "" {
		return result, errors.New("TShark produced no frame output")
	}
	seenFrames := make(map[int]struct{})
	for lineNumber, line := range strings.Split(result.text, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 7 || fields[1] != strconv.Itoa(version) {
			return result, fmt.Errorf("TShark frame line %d is short or has version %q, want %d", lineNumber+1, fieldAt(fields, 1), version)
		}
		frame, err := strconv.Atoi(fields[0])
		if err != nil {
			return result, fmt.Errorf("TShark frame line %d has invalid frame number %q", lineNumber+1, fields[0])
		}
		if frame != lineNumber+1 {
			return result, fmt.Errorf("TShark frame order is %d at line %d, want %d", frame, lineNumber+1, lineNumber+1)
		}
		if _, exists := seenFrames[frame]; exists {
			return result, fmt.Errorf("TShark decoded duplicate frame %d", frame)
		}
		seenFrames[frame] = struct{}{}
		flowsets := splitFields(fields[2])
		templateIDs := splitFields(fields[3])
		sources := splitFields(fields[4])
		sourcePorts := splitFields(fields[5])
		templateFlowset := "0"
		if version == 10 {
			templateFlowset = "2"
		}
		if version == 5 && (len(flowsets) != 0 || len(templateIDs) != 0) {
			return result, fmt.Errorf("v5 frame %d unexpectedly contains templates or flowsets", frame)
		}
		for _, id := range flowsets {
			if id != templateFlowset && id != "300" {
				return result, fmt.Errorf("frame %d contains unexpected flowset %q", frame, id)
			}
		}
		if version != 5 && contains(flowsets, "300") != (len(sources) > 0) {
			return result, fmt.Errorf("frame %d data flowset and decoded records disagree", frame)
		}
		isTemplate := contains(flowsets, templateFlowset) && len(templateIDs) > 0
		if len(sources) != len(sourcePorts) {
			return result, fmt.Errorf("TShark frame %d source/port occurrence mismatch: %d/%d", frame, len(sources), len(sourcePorts))
		}
		if !isTemplate && len(sources) == 0 {
			return result, fmt.Errorf("TShark frame %d is neither a template nor a decoded data record", frame)
		}
		if !isTemplate && version != 5 && !contains(flowsets, "300") {
			return result, fmt.Errorf("TShark frame %d has unexpected data flowset %v", frame, flowsets)
		}
		if isTemplate {
			for _, id := range templateIDs {
				if id != "300" && id != "301" {
					return result, fmt.Errorf("unexpected template id %q in frame %d", id, frame)
				}
				if id == "300" {
					result.template300 = true
				}
			}
			result.templates += len(templateIDs)
			if result.firstTempl < 0 || frame < result.firstTempl {
				result.firstTempl = frame
			}
			if result.firstData < 0 && frame > result.lastBootstrap {
				result.lastBootstrap = frame
			}
			if frame > result.lastTempl {
				result.lastTempl = frame
			}
		}
		for i, source := range sources {
			if source != "192.0.2.1" {
				return result, fmt.Errorf("TShark frame %d has unexpected source address %q", frame, source)
			}
			if i >= len(sourcePorts) {
				return result, fmt.Errorf("TShark record frame %d has no source-port identity", frame)
			}
			identity, err := strconv.Atoi(sourcePorts[i])
			if err != nil || identity < 1 || identity > 65535 {
				return result, fmt.Errorf("TShark record frame %d has invalid source-port identity %q", frame, sourcePorts[i])
			}
			frameTime, err := parseEpoch(fields[6])
			if err != nil {
				return result, fmt.Errorf("TShark record frame %d has invalid frame time %q: %w", frame, fields[6], err)
			}
			result.records++
			if result.firstData < 0 || frame < result.firstData {
				result.firstData = frame
			}
			result.identities = append(result.identities, decodedRecord{frame: frame, identity: identity, frameTime: frameTime, frameTimeText: fields[6]})
		}
	}
	if expectedFrames > 0 && len(seenFrames) != expectedFrames {
		return result, fmt.Errorf("TShark decoded %d frames, want %d", len(seenFrames), expectedFrames)
	}
	if result.records == 0 {
		return result, errors.New("TShark decoded no canonical flow records")
	}
	if version != 5 {
		if !result.template300 {
			return result, errors.New("TShark decoded no exact template id 300")
		}
		if result.firstData < 0 || result.lastBootstrap < 0 || result.lastBootstrap >= result.firstData {
			return result, fmt.Errorf("template bootstrap does not precede data: last_template=%d data=%d", result.lastBootstrap, result.firstData)
		}
	}
	return result, nil
}

func fieldAt(fields []string, index int) string {
	if index < 0 || index >= len(fields) {
		return "<missing>"
	}
	return fields[index]
}

func parseEpoch(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("empty epoch")
	}
	parts := strings.SplitN(value, ".", 2)
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	nanos := int64(0)
	if len(parts) == 2 {
		fraction := parts[1]
		if len(fraction) > 9 {
			fraction = fraction[:9]
		}
		fraction += strings.Repeat("0", 9-len(fraction))
		nanos, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return time.Time{}, err
		}
	}
	return time.Unix(seconds, nanos), nil
}

func verifyIdentityOrder(got []decodedRecord, want int) error {
	if len(got) != want {
		return fmt.Errorf("decoded identity count %d, want %d", len(got), want)
	}
	seen := make(map[int]struct{}, len(got))
	for i, record := range got {
		expected := i + 1
		if record.identity != expected {
			if _, ok := seen[record.identity]; ok {
				return fmt.Errorf("decoded duplicate identity %d at position %d (expected %d)", record.identity, i, expected)
			}
			return fmt.Errorf("decoded identity %d at position %d, want %d", record.identity, i, expected)
		}
		if _, ok := seen[record.identity]; ok {
			return fmt.Errorf("decoded duplicate identity %d at position %d", record.identity, i)
		}
		seen[record.identity] = struct{}{}
	}
	return nil
}

func splitFields(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' })
	result := parts[:0]
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type sendMeasurement struct {
	identity  int
	start     time.Time
	end       time.Time
	failed    bool
	errorText string
}

// canonicalIdentity extracts the identity added by canonicalProvider. Keeping
// this at the OTLP input boundary lets concurrent workers associate a receipt
// with the exact generated record rather than with worker completion order.
func canonicalIdentity(logs plog.Logs) (int, error) {
	if logs.ResourceLogs().Len() != 1 {
		return 0, fmt.Errorf("canonical logs have %d resources, want 1", logs.ResourceLogs().Len())
	}
	resource := logs.ResourceLogs().At(0)
	if resource.ScopeLogs().Len() != 1 || resource.ScopeLogs().At(0).LogRecords().Len() != 1 {
		return 0, errors.New("canonical logs do not contain exactly one record")
	}
	value, ok := resource.ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("source.port")
	if !ok || value.Type() != pcommon.ValueTypeInt {
		return 0, errors.New("canonical record is missing integer source.port identity")
	}
	identity := value.Int()
	if identity < 1 || identity > 65535 {
		return 0, fmt.Errorf("canonical source.port identity %d is outside UDP port range", identity)
	}
	return int(identity), nil
}

const overloadErrorCap = 256

func boundedErrorText(err error) string {
	if err == nil {
		return ""
	}
	text := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	if len(text) <= overloadErrorCap {
		return text
	}
	return text[:overloadErrorCap-3] + "..."
}

// overloadSummary describes the three distinct boundaries in an overload
// attempt: generated OTLP offers, successful ConsumeLogs calls, and records
// independently decoded from the UDP capture. Missing successful receipts
// remain visible and are not reclassified as OTLP failures.
type overloadSummary struct {
	attempts, successes, failures  int
	received, missing              int
	missingSuccess, receivedFailed int
	unknown, duplicates            int
	reordered                      bool
	offeredWindow, receiptWindow   time.Duration
	callStats                      durationSummary
	latencyStats                   durationSummary
}

func overloadAccounting(sends []sendMeasurement, decoded []decodedRecord, expected int) (overloadSummary, error) {
	var summary overloadSummary
	if expected < 1 || len(sends) != expected {
		return summary, fmt.Errorf("overload send measurement count %d, want %d", len(sends), expected)
	}

	byIdentity := make(map[int]sendMeasurement, len(sends))
	callDurations := make([]time.Duration, 0, len(sends))
	successful := make(map[int]struct{}, len(sends))
	ordered := append([]sendMeasurement(nil), sends...)
	for _, send := range sends {
		if send.identity < 1 || send.identity > expected || !send.end.After(send.start) {
			return summary, fmt.Errorf("invalid overload send timing identity=%d start=%s end=%s", send.identity, send.start, send.end)
		}
		if _, exists := byIdentity[send.identity]; exists {
			return summary, fmt.Errorf("duplicate overload send identity %d", send.identity)
		}
		byIdentity[send.identity] = send
		callDurations = append(callDurations, send.end.Sub(send.start))
		if !send.failed {
			successful[send.identity] = struct{}{}
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].start.Equal(ordered[j].start) {
			return ordered[i].identity < ordered[j].identity
		}
		return ordered[i].start.Before(ordered[j].start)
	})
	if len(ordered) == 0 {
		return summary, errors.New("overload has no send attempts")
	}
	latestEnd := ordered[0].end
	for _, send := range ordered[1:] {
		if send.end.After(latestEnd) {
			latestEnd = send.end
		}
	}
	offeredWindow := latestEnd.Sub(ordered[0].start)
	if offeredWindow <= 0 {
		return summary, errors.New("overload offered window must be positive")
	}

	rank := make(map[int]int, len(ordered))
	for index, send := range ordered {
		rank[send.identity] = index
	}
	seen := make(map[int]struct{}, len(decoded))
	previousRank := -1
	for _, record := range decoded {
		if record.identity < 1 || record.identity > expected {
			summary.unknown++
			return summary, fmt.Errorf("overload decoded unknown identity %d", record.identity)
		}
		if _, ok := byIdentity[record.identity]; !ok {
			summary.unknown++
			return summary, fmt.Errorf("overload decoded identity %d without a known OTLP attempt", record.identity)
		}
		if _, ok := seen[record.identity]; ok {
			summary.duplicates++
			return summary, fmt.Errorf("overload decoded duplicate identity %d", record.identity)
		}
		seen[record.identity] = struct{}{}
		currentRank := rank[record.identity]
		if currentRank < previousRank {
			summary.reordered = true
		}
		previousRank = currentRank
	}
	for identity := range successful {
		if _, ok := seen[identity]; !ok {
			summary.missingSuccess++
		}
	}
	for identity := range byIdentity {
		if _, ok := seen[identity]; !ok {
			summary.missing++
		}
	}
	summary.attempts = len(sends)
	summary.successes = len(successful)
	summary.failures = summary.attempts - summary.successes
	summary.received = len(decoded)
	for identity := range seen {
		if _, ok := successful[identity]; !ok {
			summary.receivedFailed++
		}
	}
	summary.callStats = summarizeDurations(callDurations)
	if len(decoded) > 0 {
		latencies := make([]time.Duration, 0, len(decoded))
		for _, record := range decoded {
			send := byIdentity[record.identity]
			latencies = append(latencies, record.frameTime.Sub(send.start))
		}
		summary.latencyStats = summarizeDurations(latencies)
		// The independent socket capture records frame order. A partial
		// receipt can have a zero-width window; retain it as an observation.
		summary.receiptWindow = decoded[len(decoded)-1].frameTime.Sub(decoded[0].frameTime)
		if summary.receiptWindow < 0 {
			summary.receiptWindow = 0
		}
	}
	summary.offeredWindow = offeredWindow
	return summary, nil
}

func writeOverloadMeasurements(path string, sends []sendMeasurement, packets []packet, decoded decodeResult, expected int) (overloadSummary, error) {
	summary, err := overloadAccounting(sends, decoded.identities, expected)
	if err != nil {
		return summary, err
	}
	if len(packets) == 0 {
		return summary, errors.New("cannot measure overload receipt timing without packets")
	}
	byIdentity := make(map[int]decodedRecord, len(decoded.identities))
	for _, record := range decoded.identities {
		if record.frame < 1 || record.frame > len(packets) {
			return summary, fmt.Errorf("identity %d references frame %d outside %d captured packets", record.identity, record.frame, len(packets))
		}
		byIdentity[record.identity] = record
	}
	sendsByIdentity := make(map[int]sendMeasurement, len(sends))
	for _, send := range sends {
		sendsByIdentity[send.identity] = send
	}
	if len(decoded.identities) > 0 {
		latencies := make([]time.Duration, 0, len(decoded.identities))
		for _, record := range decoded.identities {
			latencies = append(latencies, packets[record.frame-1].t.Sub(sendsByIdentity[record.identity].start))
		}
		summary.latencyStats = summarizeDurations(latencies)
		summary.receiptWindow = packets[decoded.identities[len(decoded.identities)-1].frame-1].t.Sub(packets[decoded.identities[0].frame-1].t)
		if summary.receiptWindow < 0 {
			summary.receiptWindow = 0
		}
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"identity", "send_start_unix_nano", "send_end_unix_nano", "otlp_call_duration_ns", "otlp_status", "otlp_error", "receipt_status", "frame", "frame_time_epoch", "receipt_unix_nano", "send_start_to_udp_receipt_ns"}); err != nil {
		return summary, err
	}
	for identity := 1; identity <= expected; identity++ {
		send := sendsByIdentity[identity]
		status, receiptStatus, frame, frameTime, receiptNanos, latency := "success", "missing", "", "", "", ""
		if record, ok := byIdentity[identity]; ok {
			receipt := packets[record.frame-1].t
			frameDelta := receipt.Sub(record.frameTime)
			if frameDelta < 0 {
				frameDelta = -frameDelta
			}
			if frameDelta > 2*time.Microsecond {
				return summary, fmt.Errorf("identity %d frame time differs from captured receipt by %s", identity, frameDelta)
			}
			latencyValue := receipt.Sub(send.start)
			if latencyValue < 0 {
				return summary, fmt.Errorf("identity %d receipt precedes send start by %s", identity, latencyValue)
			}
			if !send.failed {
				receiptStatus = "received"
			} else {
				status, receiptStatus = "failure", "received_after_error"
			}
			frame = strconv.Itoa(record.frame)
			frameTime = record.frameTimeText
			receiptNanos = strconv.FormatInt(receipt.UnixNano(), 10)
			latency = strconv.FormatInt(latencyValue.Nanoseconds(), 10)
		} else if send.failed {
			status, receiptStatus = "failure", "not_observed"
		}
		if err := w.Write([]string{strconv.Itoa(identity), strconv.FormatInt(send.start.UnixNano(), 10), strconv.FormatInt(send.end.UnixNano(), 10), strconv.FormatInt(send.end.Sub(send.start).Nanoseconds(), 10), status, send.errorText, receiptStatus, frame, frameTime, receiptNanos, latency}); err != nil {
			return summary, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return summary, err
	}
	if b.Len() > outputCap {
		return summary, fmt.Errorf("overload measurement output exceeds %d bytes", outputCap)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		return summary, err
	}
	return summary, nil
}

func runOverloadSends(ctx context.Context, endpointHost string, endpointPort, expected, workers int) ([]sendMeasurement, *canonicalProvider, error) {
	if expected < 1 || workers < 1 || workers > expected {
		return nil, nil, fmt.Errorf("invalid overload bounds: records=%d workers=%d", expected, workers)
	}
	provider := &canonicalProvider{limit: int64(expected), unique: true}
	var generated atomic.Uint64
	provider.SetLoadGeneratorCounters(&generated)
	senders := make([]testbed.LogDataSender, workers)
	for i := range senders {
		senders[i] = testbed.NewOTLPLogsDataSender(endpointHost, endpointPort)
		if err := senders[i].Start(); err != nil {
			return nil, provider, fmt.Errorf("start overload Testbed logs sender %d: %w", i, err)
		}
	}
	measurements := make([]sendMeasurement, 0, expected)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range senders {
		sender := senders[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer sender.Flush()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				logs, done := provider.GenerateLogs()
				if done {
					return
				}
				identity, err := canonicalIdentity(logs)
				if err != nil {
					// This is a provider/fixture defect, so stop this worker
					// rather than fabricate an identity for accounting.
					mu.Lock()
					now := time.Now()
					measurements = append(measurements, sendMeasurement{identity: 0, start: now, end: now, failed: true, errorText: boundedErrorText(err)})
					mu.Unlock()
					return
				}
				sendStart := time.Now()
				sendErr := sender.ConsumeLogs(ctx, logs)
				sendEnd := time.Now()
				measurement := sendMeasurement{identity: identity, start: sendStart, end: sendEnd, failed: sendErr != nil, errorText: boundedErrorText(sendErr)}
				mu.Lock()
				measurements = append(measurements, measurement)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if provider.count.Load() != int64(expected) {
		return measurements, provider, fmt.Errorf("overload generated %d records, want %d", provider.count.Load(), expected)
	}
	if generated.Load() != uint64(expected) {
		return measurements, provider, fmt.Errorf("overload Testbed generated counter=%d, want %d", generated.Load(), expected)
	}
	if len(measurements) != expected {
		return measurements, provider, fmt.Errorf("overload recorded %d send attempts, want %d", len(measurements), expected)
	}
	return measurements, provider, nil
}

type durationSummary struct {
	count int
	min   time.Duration
	p50   time.Duration
	p95   time.Duration
	max   time.Duration
}

func summarizeDurations(values []time.Duration) durationSummary {
	if len(values) == 0 {
		return durationSummary{}
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	p95Index := (len(ordered)*95+99)/100 - 1
	return durationSummary{
		count: len(ordered), min: ordered[0], p50: ordered[len(ordered)/2],
		p95: ordered[p95Index], max: ordered[len(ordered)-1],
	}
}

func ratePerSecond(count int, window time.Duration) float64 {
	if count == 0 || window <= 0 {
		return 0
	}
	return float64(count) / window.Seconds()
}

func writeMeasurements(path string, sends []sendMeasurement, packets []packet, decoded decodeResult, expectedRecords int) (durationSummary, durationSummary, time.Duration, time.Duration, error) {
	if expectedRecords < 1 {
		return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("expected record count must be positive: %d", expectedRecords)
	}
	if len(sends) != expectedRecords {
		return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("send measurement count %d, want %d", len(sends), expectedRecords)
	}
	sendsByIdentity := make(map[int]sendMeasurement, len(sends))
	callDurations := make([]time.Duration, 0, len(sends))
	for _, send := range sends {
		if send.identity < 1 || send.identity > expectedRecords || !send.end.After(send.start) {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("invalid send timing identity=%d start=%s end=%s", send.identity, send.start, send.end)
		}
		if send.failed {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("baseline send identity %d failed: %s", send.identity, send.errorText)
		}
		if _, exists := sendsByIdentity[send.identity]; exists {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("duplicate send timing identity %d", send.identity)
		}
		sendsByIdentity[send.identity] = send
		callDurations = append(callDurations, send.end.Sub(send.start))
	}
	if err := verifyIdentityOrder(decoded.identities, expectedRecords); err != nil {
		return durationSummary{}, durationSummary{}, 0, 0, err
	}
	if len(packets) == 0 {
		return durationSummary{}, durationSummary{}, 0, 0, errors.New("cannot measure receipt timing without packets")
	}
	var b strings.Builder
	b.WriteString("identity,send_start_unix_nano,send_end_unix_nano,otlp_call_duration_ns,frame,frame_time_epoch,receipt_unix_nano,send_start_to_udp_receipt_ns\n")
	latencies := make([]time.Duration, 0, len(decoded.identities))
	receiptTimes := make([]time.Time, 0, len(decoded.identities))
	for _, decodedRecord := range decoded.identities {
		if decodedRecord.frame < 1 || decodedRecord.frame > len(packets) {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("identity %d references frame %d outside %d captured packets", decodedRecord.identity, decodedRecord.frame, len(packets))
		}
		send, ok := sendsByIdentity[decodedRecord.identity]
		if !ok {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("identity %d has no send timing", decodedRecord.identity)
		}
		receipt := packets[decodedRecord.frame-1].t
		frameDelta := receipt.Sub(decodedRecord.frameTime)
		if frameDelta < 0 {
			frameDelta = -frameDelta
		}
		if frameDelta > 2*time.Microsecond {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("identity %d frame time differs from captured receipt by %s", decodedRecord.identity, frameDelta)
		}
		latency := receipt.Sub(send.start)
		if latency < 0 {
			return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("identity %d receipt precedes send start by %s", decodedRecord.identity, latency)
		}
		latencies = append(latencies, latency)
		receiptTimes = append(receiptTimes, receipt)
		fmt.Fprintf(&b, "%d,%d,%d,%d,%d,%s,%d,%d\n", decodedRecord.identity, send.start.UnixNano(), send.end.UnixNano(), send.end.Sub(send.start).Nanoseconds(), decodedRecord.frame, decodedRecord.frameTimeText, receipt.UnixNano(), latency.Nanoseconds())
	}
	if b.Len() > outputCap {
		return durationSummary{}, durationSummary{}, 0, 0, fmt.Errorf("measurement output exceeds %d bytes", outputCap)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return durationSummary{}, durationSummary{}, 0, 0, err
	}
	offeredWindow := sends[len(sends)-1].end.Sub(sends[0].start)
	receiptWindow := receiptTimes[len(receiptTimes)-1].Sub(receiptTimes[0])
	if offeredWindow <= 0 || receiptWindow <= 0 {
		return durationSummary{}, durationSummary{}, 0, 0, errors.New("offered and data receipt windows must be positive")
	}
	return summarizeDurations(callDurations), summarizeDurations(latencies), offeredWindow, receiptWindow, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(p)
}

func runCase(root, collector string, p protocol) error {
	return runCaseContext(context.Background(), root, collector, p)
}

func runCaseContext(parent context.Context, root, collector string, p protocol) (err error) {
	return runCaseContextWithOptions(parent, root, collector, p, baselineOptions())
}

func runCaseContextWithOptions(parent context.Context, root, collector string, p protocol, options runOptions) (err error) {
	if err = options.validate(); err != nil {
		return err
	}
	if options.name == "recovery" {
		return runRecoveryCaseContext(parent, root, collector, p)
	}
	if root == "" || collector == "" {
		return errors.New("artifact root and collector are required")
	}
	if err = os.Mkdir(root, 0o700); err != nil {
		return err
	}
	defer func() {
		if e := checkArtifactCap(root); err == nil {
			err = e
		}
	}()

	cap, err := newCapture()
	if err != nil {
		return err
	}
	defer func() {
		_, closeErr := cap.closeCapture()
		if err == nil {
			err = closeErr
		}
	}()

	out := cap.conn.LocalAddr().(*net.UDPAddr).Port
	ports, err := freePorts(2)
	if err != nil {
		return err
	}
	in, pprofPort := ports[0], ports[1]
	configPath := filepath.Join(root, "collector.yaml")
	if err = os.WriteFile(configPath, []byte(configFor(p, in, out, pprofPort)), 0o600); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parent, caseTimeout)
	defer cancel()
	clockTicks, err := procClockTicks(ctx)
	if err != nil {
		return fmt.Errorf("/proc CPU clock: %w", err)
	}
	collectorID, err := collectorBuildID(ctx, collector)
	if err != nil {
		return fmt.Errorf("Collector build ID: %w", err)
	}
	proc, err := startChild(ctx, collector, configPath, filepath.Join(root, "collector.log"))
	if err != nil {
		return err
	}
	defer func() {
		if stopErr := proc.stopProcess(); err == nil && stopErr != nil {
			err = stopErr
		}
	}()
	if err = waitPprof(ctx, pprofPort, proc); err != nil {
		return err
	}
	fdLimit, err := collectorFDLimit(proc.cmd.Process.Pid)
	if err != nil {
		return fmt.Errorf("collector fd limit: %w", err)
	}
	if err = os.WriteFile(filepath.Join(root, "collector.fd-limit"), []byte(fdLimit+"\n"), 0o600); err != nil {
		return err
	}
	procMetrics, err := startProcSampler(proc.cmd.Process.Pid)
	if err != nil {
		return fmt.Errorf("start /proc sampler: %w", err)
	}
	defer func() {
		if _, sampleErr := procMetrics.stopSampling(); err == nil && sampleErr != nil {
			err = fmt.Errorf("/proc sampler: %w", sampleErr)
		}
	}()

	var provider *canonicalProvider
	runStart := time.Now()
	sends := make([]sendMeasurement, 0, options.records)
	cpuPath, heapPath := filepath.Join(root, "cpu.pb.gz"), filepath.Join(root, "heap.pb.gz")
	heapStatsPath := filepath.Join(root, "heap-stats.txt")
	goroutinePath := filepath.Join(root, "goroutine.txt")
	cpuDone := make(chan error, 1)
	// Request a two-second CPU sample concurrently with the selected records; the
	// sample covers only that request interval, while process observations span
	// the broader bounded workload and profiling window.
	go func() { cpuDone <- profile(ctx, pprofPort, "profile?seconds=2", cpuPath) }()
	if options.name == "overload" {
		sends, provider, err = runOverloadSends(ctx, "127.0.0.1", in, options.records, options.concurrency)
		if err != nil {
			return err
		}
	} else {
		provider = &canonicalProvider{limit: int64(options.records), unique: true}
		sender := testbed.NewOTLPLogsDataSender("127.0.0.1", in)
		if err = sender.Start(); err != nil {
			return fmt.Errorf("start Testbed logs sender: %w", err)
		}
		for i := 0; i < options.records; i++ {
			logs, done := provider.GenerateLogs()
			if done {
				return fmt.Errorf("provider ended at record %d", i)
			}
			sendStart := time.Now()
			if err = sender.ConsumeLogs(ctx, logs); err != nil {
				return fmt.Errorf("OTLP send record %d: %w", i, err)
			}
			sends = append(sends, sendMeasurement{identity: i + 1, start: sendStart, end: time.Now()})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(options.pacing):
			}
		}
		sender.Flush()
	}
	if offered := provider.count.Load(); offered != int64(options.records) {
		return fmt.Errorf("offered %d records, want %d", offered, options.records)
	}
	if err = <-cpuDone; err != nil {
		return fmt.Errorf("CPU profile: %w", err)
	}
	if err = profile(ctx, pprofPort, "heap", heapPath); err != nil {
		return fmt.Errorf("heap profile: %w", err)
	}
	if err = profile(ctx, pprofPort, "heap?debug=1", heapStatsPath); err != nil {
		return fmt.Errorf("heap stats: %w", err)
	}
	if err = profile(ctx, pprofPort, "goroutine?debug=1", goroutinePath); err != nil {
		return fmt.Errorf("goroutine profile: %w", err)
	}
	// Sender calls are synchronous at the OTLP input boundary. Give the
	// independent socket a short quiet period before terminating the child.
	time.Sleep(250 * time.Millisecond)
	procStats, err := procMetrics.stopSampling()
	if err != nil {
		return fmt.Errorf("/proc sampler: %w", err)
	}
	if err = proc.stopProcess(); err != nil {
		return err
	}
	packets, err := cap.closeCapture()
	if err != nil {
		return err
	}
	if len(packets) == 0 {
		return errors.New("no independent UDP receipt")
	}
	datagramWindow := packets[len(packets)-1].t.Sub(packets[0].t)
	if datagramWindow <= 0 && options.name != "overload" {
		return errors.New("captured datagram timestamp window must be positive")
	}

	pcapPath := filepath.Join(root, p.name+".pcap")
	if err = writePCAP(pcapPath, packets, 40000, p.port); err != nil {
		return err
	}
	decoded, err := decodeExpected(ctx, pcapPath, p.port, p.version, len(packets))
	if err != nil {
		return err
	}
	if options.name != "overload" {
		if decoded.records != options.records {
			return fmt.Errorf("TShark decoded %d records, want %d", decoded.records, options.records)
		}
		if err = verifyIdentityOrder(decoded.identities, options.records); err != nil {
			return fmt.Errorf("independent identity verification: %w", err)
		}
	}
	if err = os.WriteFile(filepath.Join(root, "tshark.fields"), []byte(decoded.text+"\n"), 0o600); err != nil {
		return err
	}
	var callStats, latencyStats durationSummary
	var offeredWindow, receiptWindow time.Duration
	var overloadStats overloadSummary
	if options.name == "overload" {
		overloadStats, err = writeOverloadMeasurements(filepath.Join(root, "measurements.csv"), sends, packets, decoded, options.records)
		if err != nil {
			return fmt.Errorf("overload accounting: %w", err)
		}
		callStats, latencyStats = overloadStats.callStats, overloadStats.latencyStats
		offeredWindow, receiptWindow = overloadStats.offeredWindow, overloadStats.receiptWindow
	} else {
		callStats, latencyStats, offeredWindow, receiptWindow, err = writeMeasurements(filepath.Join(root, "measurements.csv"), sends, packets, decoded, options.records)
		if err != nil {
			return fmt.Errorf("measurements: %w", err)
		}
	}
	cpu, err := parseProfileForBuild(ctx, cpuPath, collectorID)
	if err != nil {
		return fmt.Errorf("CPU parse: %w", err)
	}
	heap, err := parseProfileForBuild(ctx, heapPath, collectorID)
	if err != nil {
		return fmt.Errorf("heap parse: %w", err)
	}
	allocSpace, err := parseProfileForBuildIndex(ctx, heapPath, collectorID, "alloc_space")
	if err != nil {
		return fmt.Errorf("alloc_space heap parse: %w", err)
	}
	heapStats, err := parseHeapStats(heapStatsPath)
	if err != nil {
		return fmt.Errorf("heap stats parse: %w", err)
	}
	goroutines, err := parseGoroutineCount(goroutinePath)
	if err != nil {
		return fmt.Errorf("goroutine profile parse: %w", err)
	}
	if procStats.after.userTicks < procStats.before.userTicks || procStats.after.systemTicks < procStats.before.systemTicks {
		return errors.New("/proc CPU counters moved backwards")
	}
	beforeCPU := procStats.before.userTicks + procStats.before.systemTicks
	afterCPU := procStats.after.userTicks + procStats.after.systemTicks
	identityPolicy := fmt.Sprintf("source.port_1_to_%d_exactly_once_in_order", options.records)
	if options.name == "overload" {
		identityPolicy = fmt.Sprintf("source.port_1_to_%d_unique_attempts; receipt_order_compared_to_send_start", options.records)
	}
	result := fmt.Sprintf("protocol=%s\nscenario=%s\nrecords_per_case=%d\npacing_ms=%d\nconcurrency=%d\noffered_records=%d\nreceived_datagrams=%d\ndecoded_records=%d\ntemplates=%d\nelapsed=%s\nindependent_udp_receipt=true\nwire_decode=tshark\nidentity_policy=%s\ncpu_profile_scope=2s_sample_requested_concurrently_with_selected_workload\ncollector_build_id=%s\nfd_limit=%s\noffered_window_ns=%d\noffered_rate_records_per_sec=%.3f\nreceipt_window_ns=%d\nreceipt_record_rate_per_sec=%.3f\nreceipt_datagram_window_ns=%d\nreceipt_datagram_rate_per_sec=%.3f\notlp_call_duration_count=%d\notlp_call_duration_min_ns=%d\notlp_call_duration_p50_ns=%d\notlp_call_duration_p95_ns=%d\notlp_call_duration_max_ns=%d\nsend_start_to_udp_receipt_count=%d\nsend_start_to_udp_receipt_min_ns=%d\nsend_start_to_udp_receipt_p50_ns=%d\nsend_start_to_udp_receipt_p95_ns=%d\nsend_start_to_udp_receipt_max_ns=%d\nproc_pid=%d\nproc_cpu_user_hz=%d\nproc_cpu_seconds_delta=%.6f\nproc_sample_start_unix_nano=%d\nproc_sample_end_unix_nano=%d\nproc_sample_window_ns=%d\nproc_cpu_ticks_before=%d\nproc_cpu_ticks_after=%d\nproc_cpu_ticks_delta=%d\nproc_rss_kb_before=%d\nproc_rss_kb_after=%d\nproc_rss_kb_peak=%d\nproc_samples=%d\ngoroutine_count=%d\ncpu=%s\nheap=%s\nheap_alloc_space=%s\nheap_stats=%s\nrun_start_unix_nano=%d\nrun_end_unix_nano=%d\n", p.name, options.name, options.records, options.pacing.Milliseconds(), options.concurrency, provider.count.Load(), len(packets), decoded.records, decoded.templates, time.Since(runStart).Round(time.Millisecond), identityPolicy, collectorID, fdLimit, offeredWindow.Nanoseconds(), ratePerSecond(options.records, offeredWindow), receiptWindow.Nanoseconds(), ratePerSecond(decoded.records, receiptWindow), datagramWindow.Nanoseconds(), ratePerSecond(len(packets), datagramWindow), callStats.count, callStats.min.Nanoseconds(), callStats.p50.Nanoseconds(), callStats.p95.Nanoseconds(), callStats.max.Nanoseconds(), latencyStats.count, latencyStats.min.Nanoseconds(), latencyStats.p50.Nanoseconds(), latencyStats.p95.Nanoseconds(), latencyStats.max.Nanoseconds(), proc.cmd.Process.Pid, clockTicks, float64(afterCPU-beforeCPU)/float64(clockTicks), procStats.before.at.UnixNano(), procStats.after.at.UnixNano(), procStats.after.at.Sub(procStats.before.at).Nanoseconds(), beforeCPU, afterCPU, afterCPU-beforeCPU, procStats.before.rssKB, procStats.after.rssKB, procStats.peakRSS, procStats.samples, goroutines, cpu, heap, allocSpace, heapStats, runStart.UnixNano(), time.Now().UnixNano())
	if options.name == "overload" {
		result += fmt.Sprintf("otlp_attempts=%d\notlp_successes=%d\notlp_failures=%d\nreceipt_attempts_observed=%d\nreceipt_attempts_missing=%d\nreceipt_successes_missing=%d\nreceipt_failed_calls_observed=%d\nreceipt_reordered_by_send_start=%t\nreceipt_accounting_unknown=%d\nreceipt_accounting_duplicates=%d\nfailed_call_error_cap_bytes=%d\nexporter_handoff_metrics=unmeasured\notlp_success_is_local_input_result=true\n", overloadStats.attempts, overloadStats.successes, overloadStats.failures, overloadStats.received, overloadStats.missing, overloadStats.missingSuccess, overloadStats.receivedFailed, overloadStats.reordered, overloadStats.unknown, overloadStats.duplicates, overloadErrorCap)
	}
	return os.WriteFile(filepath.Join(root, "result.txt"), []byte(result), 0o600)
}

func checkArtifactCap(root string) error {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > artifactCap {
				return fmt.Errorf("artifact cap exceeded: %d > %d", total, artifactCap)
			}
		}
		return nil
	})
	return err
}

func main() {
	runtime.GOMAXPROCS(2)
	collector := flag.String("collector", "dist/testbed/otel-netflow-testbed-collector", "pinned OCB binary")
	protocolName := flag.String("protocol", "", "one protocol: v5, v9, or ipfix")
	scenarioName := flag.String("scenario", "baseline", "one scenario: baseline, sustained, overload, or recovery")
	root := flag.String("artifacts", "", "fresh private artifact directory")
	flag.Parse()
	options, err := scenarioOptions(*scenarioName)
	if err != nil {
		fatal("--scenario: %v", err)
	}
	p, ok := protocols[*protocolName]
	if !ok {
		fatal("--protocol must be one of v5, v9, ipfix")
	}
	if *root == "" {
		fatal("--artifacts is required and must be fresh")
	}
	if _, err := os.Stat(*collector); err != nil {
		fatal("collector preflight: %v", err)
	}
	if _, err := exec.LookPath(tsharkExecutable()); err != nil {
		fatal("TShark preflight: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runCaseContextWithOptions(ctx, *root, *collector, p, options); err != nil {
		fatal("%s: %v", p.name, err)
	}
	if options.name == "overload" {
		fmt.Printf("PASS: %s bounded overload attempt with independently decoded receipt accounting and pprof profiles; artifacts=%s\n", p.name, *root)
		return
	}
	if options.name == "recovery" {
		fmt.Printf("PASS: %s bounded receiver interruption/recovery with warm-cache and fresh-cache accounting plus pprof profiles; artifacts=%s\n", p.name, *root)
		return
	}
	fmt.Printf("PASS: %s %s receipt, exact %d-record TShark decode and pprof profiles; artifacts=%s\n", p.name, options.name, options.records, *root)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
