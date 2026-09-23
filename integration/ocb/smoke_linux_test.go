package ocb_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type flowCase struct {
	Protocol string `json:"protocol"`
	Golden   string `json:"golden"`
	Records  int    `json:"records"`
	IPv6     bool   `json:"ipv6"`
}

// This test runs the generated Collector executable, not component factories.
// Received application datagrams are retained unchanged. Outer IP/UDP headers
// and checksums need the separate live-network/TShark acceptance check.
func TestCollectorSmoke(t *testing.T) {
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and run smoke_test.sh to exercise the executable")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	dir := t.TempDir()
	if base := os.Getenv("NETFLOW_OCB_ARTIFACTS"); base != "" {
		dir, err = os.MkdirTemp(base, "ocb-")
		must(t, err)
		t.Logf("retained integration artifacts: %s", dir)
	}
	config := legacyMatrixConfig(t)
	// This is a test-owned socket, never a Collector metrics endpoint. With
	// level none, the retained reader must be ignored even while its port is
	// occupied. Hold the reservation until the Collector has fully stopped.
	metrics := reserveMetricsPort(t)
	metricsAddress := metrics.Addr().String()
	if os.Getenv("NETFLOW_OCB_NETNS") != "" {
		config = strings.ReplaceAll(config, "hostname: 127.0.0.1", "hostname: 198.18.0.2")
	}
	fixture := os.Getenv("NETFLOW_OCB_FIXTURE")
	if fixture == "" {
		fixture = "../testdata/ocb/canonical.yaml"
	}
	var fixtures struct {
		Description string     `json:"description"`
		Cases       []flowCase `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(readFile(t, fixture)))
	decoder.DisallowUnknownFields()
	must(t, decoder.Decode(&fixtures))
	// Keep the all-protocol acceptance matrix fixed: a reduced fixture cannot
	// turn an incomplete run into PASS.
	expected := []flowCase{
		{"v5", "canonical-ipv4-v1.bin", 1, false},
		{"v9", "canonical-ipv4-v1.bin", 1, false},
		{"v9", "canonical-ipv6-v1.bin", 1, true},
		{"v9", "sampling-ie34-two-distinct-rates-v1.bin", 2, false},
		{"ipfix", "canonical-ipv4-v1.bin", 1, false},
		{"ipfix", "canonical-ipv6-v1.bin", 1, true},
		{"ipfix", "sampling-ie34-two-distinct-rates-v1.bin", 2, false},
	}
	if !slices.Equal(fixtures.Cases, expected) {
		t.Fatal("fixture must contain the complete ordered seven-case matrix")
	}
	inputs, outputs := map[string]*net.UDPConn{}, map[string]*net.UDPConn{}
	ports := map[string]int{}
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		inputs[protocol], outputs[protocol] = listen(t), listen(t)
		ports[protocol] = inputs[protocol].LocalAddr().(*net.UDPAddr).Port
		t.Setenv("NETFLOW_"+strings.ToUpper(protocol)+"_PORT", fmt.Sprint(ports[protocol]))
		t.Setenv("NETFLOW_"+strings.ToUpper(protocol)+"_ENDPOINT", outputs[protocol].LocalAddr().String())
	}
	origin := time.Now().Truncate(time.Second).Add(-4 * time.Second)
	t.Setenv("NETFLOW_V5_ORIGIN", fmt.Sprint(origin.UnixNano()))
	t.Setenv("NETFLOW_V9_ORIGIN", fmt.Sprint(origin.UnixNano()))
	outputs["rejected"] = listen(t)
	t.Setenv("NETFLOW_REJECTED_ENDPOINT", outputs["rejected"].LocalAddr().String())
	configPath := filepath.Join(dir, "config.yaml")
	must(t, os.WriteFile(configPath, []byte(config), 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	for _, tc := range []struct{ old, new string }{
		{"    protocol: ipfix", "    protocol: sflow"},
		{"    protocol: ipfix", "    protocol: ipfix\n    sending_queue: {enabled: true}"},
		{"    protocol: ipfix", "    protocol: ipfix\n    unknown_option: true"},
	} {
		bad := replaceOnce(t, config, tc.old, tc.new)
		path := filepath.Join(dir, "invalid-config.yaml")
		must(t, os.WriteFile(path, []byte(bad), 0600))
		runCommand(t, bin, false, "validate", "--config", path)
	}
	// All reservations remain held during validation, which must do no binds
	// or template writes. A real Start gets exactly one bind attempt afterward.
	for _, out := range outputs {
		assertQuiet(t, out)
	}
	// The sibling has an intentionally narrower, valid operator token map.
	// TCP fails only that instance; a later UDP record must succeed at sequence 0.
	exporters := strings.Split(config, "exporters:\n")[1]
	stanza := "  netflow/ipfix:\n" + strings.Split(strings.Split(exporters, "  netflow/ipfix:\n")[1], "service:\n")[0]
	stanza = replaceOnce(t, stanza, "  netflow/ipfix:", "  netflow/rejected:")
	stanza = replaceOnce(t, stanza, "NETFLOW_IPFIX_ENDPOINT", "NETFLOW_REJECTED_ENDPOINT")
	stanza = replaceOnce(t, stanza, "observation_domain_id: 42", "observation_domain_id: 43")
	stanza = replaceOnce(t, stanza, "[{token: tcp, number: 6}, {token: udp, number: 17}]", "[{token: udp, number: 17}]")
	config = replaceOnce(t, config, "service:\n", stanza+"service:\n")
	config = replaceOnce(t, config, "exporters: [netflow/ipfix]", "exporters: [netflow/ipfix, netflow/rejected]")
	// Retain the effective configuration, including endpoint and origin values.
	for _, key := range []string{"NETFLOW_V5_PORT", "NETFLOW_V9_PORT", "NETFLOW_IPFIX_PORT", "NETFLOW_V5_ENDPOINT", "NETFLOW_V9_ENDPOINT", "NETFLOW_IPFIX_ENDPOINT", "NETFLOW_REJECTED_ENDPOINT", "NETFLOW_V5_ORIGIN", "NETFLOW_V9_ORIGIN", "NETFLOW_METRICS_PORT"} {
		config = strings.ReplaceAll(config, "${env:"+key+"}", os.Getenv(key))
	}
	must(t, os.WriteFile(configPath, []byte(config), 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	for _, in := range inputs {
		must(t, in.Close())
	}
	p := startCollector(t, bin, configPath)
	defer func() {
		must(t, os.WriteFile(filepath.Join(dir, "collector.log"), []byte(p.log.String()), 0600))
	}()
	waitReady(t, p)
	before := uint32(p.started.Unix())
	var captures []capture
	peers := map[string]string{}
	receive := func(protocol string) []byte {
		t.Helper()
		out := outputs[protocol]
		must(t, out.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 65535)
		n, peer, err := out.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("%s receive: %v\n%s", protocol, err, p.log.String())
		}
		if peers[protocol] == "" {
			peers[protocol] = peer.String()
		} else if peers[protocol] != peer.String() {
			t.Fatal("source socket changed within a destination epoch")
		}
		packet := buf[:n]
		name := fmt.Sprintf("%02d-%s.bin", len(captures), protocol)
		must(t, os.WriteFile(filepath.Join(dir, name), packet, 0600))
		captures = append(captures, capture{name, n, hash(packet), peer.String(), out.LocalAddr().String()})
		return packet
	}
	for _, protocol := range []string{"v9", "ipfix", "rejected"} {
		wireProtocol, domain := protocol, uint32(42)
		if protocol == "rejected" {
			wireProtocol, domain = "ipfix", 43
		}
		for i := range 4 {
			name := []string{"canonical-ipv4-v1.bin", "canonical-ipv6-v1.bin"}[i%2]
			golden := goldenFile(t, wireProtocol, name)
			header, data := offsets(wireProtocol)
			seq := uint32(0)
			if wireProtocol == "v9" {
				seq = uint32(i)
			}
			assertPacket(t, wireProtocol, receive(protocol), golden[header:data], seq, 1, domain, before, origin)
		}
	}
	for _, out := range outputs {
		assertQuiet(t, out)
	}
	senders := map[string]*net.UDPConn{}
	for protocol, port := range ports {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: receiverIP(), Port: port})
		must(t, err)
		t.Cleanup(func() { conn.Close() })
		senders[protocol] = conn
	}
	sequences := map[string]uint32{"v5": 0, "v9": 4, "ipfix": 0}
	var sent []capture
	send := func(tc flowCase, packet []byte) {
		t.Helper()
		name := fmt.Sprintf("input-%02d-%s.bin", len(sent), tc.Protocol)
		must(t, os.WriteFile(filepath.Join(dir, name), packet, 0600))
		conn := senders[tc.Protocol]
		sent = append(sent, capture{name, len(packet), hash(packet), conn.LocalAddr().String(), conn.RemoteAddr().String()})
		must(t, conn.SetWriteDeadline(time.Now().Add(time.Second)))
		n, err := conn.Write(packet)
		must(t, err)
		if n != len(packet) {
			t.Fatal("short fixture write")
		}
	}
	for _, tc := range fixtures.Cases {
		golden := goldenFile(t, tc.Protocol, tc.Golden)
		input := bytes.Clone(golden)
		if tc.Protocol == "v5" {
			// Rebase only the header export time and configured origin together.
			// The golden's 3000 ms uptime and every record byte remain unchanged.
			binary.BigEndian.PutUint32(input[8:], uint32(origin.Unix()+3))
		}
		send(tc, input)
		want := projectedData(tc, golden, false)
		assertPacket(t, tc.Protocol, receive(tc.Protocol), want, sequences[tc.Protocol], tc.Records, 42, before, origin)
		if tc.Protocol == "v9" {
			sequences[tc.Protocol]++
		} else {
			sequences[tc.Protocol] += uint32(tc.Records)
		}
		assertQuiet(t, outputs[tc.Protocol])
		assertQuiet(t, outputs["rejected"])
	}
	if !strings.Contains(p.log.String(), "netflow/rejected") || !strings.Contains(p.log.String(), "netflow: records rejected") {
		t.Fatalf("missing evidence of sibling TCP rejection:\n%s", p.log.String())
	}
	// Inject UDP by changing just the protocol octet of the canonical IPFIX
	// input. This is a declared derivative, not a replacement immutable golden.
	tc := flowCase{"ipfix", "canonical-ipv4-v1.bin", 1, false}
	golden := goldenFile(t, tc.Protocol, tc.Golden)
	input := bytes.Clone(golden)
	input[104+4+16] = 17
	send(tc, input)
	want := projectedData(tc, golden, true)
	assertPacket(t, "ipfix", receive("ipfix"), want, 4, 1, 42, before, origin)
	assertPacket(t, "ipfix", receive("rejected"), want, 0, 1, 43, before, origin)
	if peers["ipfix"] == peers["rejected"] {
		t.Fatal("named instances share a socket")
	}
	stopCollector(t, p)
	if !strings.Contains(p.log.String(), "Internal metrics telemetry disabled") {
		t.Fatal("smoke did not report deliberate disabled metrics")
	}
	must(t, metrics.Close())
	assertMetricsPortReleased(t, metricsAddress)
	t.Log("disabled provider ignored retained reader while the test-owned metrics port stayed occupied through shutdown")
	for _, out := range outputs {
		assertQuiet(t, out)
	}
	// Receivers must release their actual ports after graceful process exit.
	for _, port := range ports {
		if ns := os.Getenv("NETFLOW_OCB_NETNS"); ns != "" {
			// Run the same bind check in the receiver's actual network namespace.
			exe, err := os.Executable()
			must(t, err)
			t.Setenv("NETFLOW_OCB_RELEASE_PORT", fmt.Sprint(port))
			runCommand(t, "/usr/bin/nsenter", true, "--net="+ns, "--", exe, "-test.run=^TestLiveReceiverPortReleased$")
		} else {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: receiverIP(), Port: port})
			must(t, err)
			must(t, conn.Close())
		}
	}
	identity := struct {
		PID             int
		BinarySHA256    string
		ConfigSHA256    string
		OriginUnixNano  int64
		Inputs, Outputs []capture
	}{p.cmd.Process.Pid, hash(readFile(t, bin)), hash([]byte(config)), origin.UnixNano(), sent, captures}
	data, err := json.MarshalIndent(identity, "", "  ")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "capture.json"), append(data, '\n'), 0600))
	t.Logf("OCB receiver-to-exporter PASS: 7 canonical cases + sibling recovery, %d sent / %d received datagrams; clean SIGTERM exit", len(sent), len(captures))
}

type capture struct {
	File                     string
	Length                   int
	SHA256, Source, Endpoint string
}

func projectedData(tc flowCase, golden []byte, udp bool) []byte {
	_, offset := offsets(tc.Protocol)
	want := bytes.Clone(golden[offset:])
	if tc.Protocol == "v5" {
		return want
	}
	width, sampling, proto := 43, 37, 8
	if tc.Protocol == "ipfix" {
		width, sampling, proto = 72, 50, 16
	}
	if tc.IPv6 {
		width += 24
		sampling += 24
	}
	for i := range tc.Records {
		record := want[4+i*width:]
		clear(record[sampling : sampling+4]) // receiver ignores ordinary IE 34
		if udp {
			record[proto] = 17
		}
		if tc.Protocol == "ipfix" {
			// Pinned GoFlow2 floors 1 ms NTP to 999999 ns. Re-encoding with
			// the accepted nearest-NTP rule produces literal fraction 0x418933.
			binary.BigEndian.PutUint32(record[width-4:], 0x00418933)
		}
	}
	return want
}

func offsets(protocol string) (header, data int) {
	switch protocol {
	case "v5":
		return 24, 24
	case "v9":
		return 20, 100
	default:
		return 16, 104
	}
}

func assertPacket(t *testing.T, protocol string, packet, want []byte, seq uint32, count int, domain, before uint32, origin time.Time) {
	t.Helper()
	must(t, validatePacket(protocol, packet, want, seq, count, domain, before, uint32(time.Now().Unix()), origin))
}

func validatePacket(protocol string, packet, want []byte, seq uint32, count int, domain, before, after uint32, origin time.Time) error {
	header, _ := offsets(protocol)
	if len(packet) < header {
		return fmt.Errorf("%s truncated header", protocol)
	}
	version, sequenceOffset, timeOffset := uint16(9), 12, 8
	if protocol == "v5" {
		version, sequenceOffset = 5, 16
	} else if protocol == "ipfix" {
		version, sequenceOffset, timeOffset = 10, 8, 4
	}
	if len(packet) != header+len(want) || binary.BigEndian.Uint16(packet) != version || binary.BigEndian.Uint32(packet[sequenceOffset:]) != seq {
		return fmt.Errorf("%s unexpected header/length/sequence %d: %x", protocol, seq, packet)
	}
	if !bytes.Equal(packet[header:], want) {
		return fmt.Errorf("%s projected golden mismatch:\n got %x\nwant %x", protocol, packet[header:], want)
	}
	exported := binary.BigEndian.Uint32(packet[timeOffset:])
	if exported < before || exported > after {
		return fmt.Errorf("export time outside live process interval")
	}
	if protocol == "ipfix" {
		if int(binary.BigEndian.Uint16(packet[2:])) != len(packet) {
			return fmt.Errorf("IPFIX length")
		}
	} else if int(binary.BigEndian.Uint16(packet[2:])) != count {
		return fmt.Errorf("NetFlow record count")
	}
	if protocol == "v5" {
		if !bytes.Equal(packet[20:24], []byte{1, 1, 3, 232}) {
			return fmt.Errorf("v5 engine identity/sampling")
		}
		nanos := binary.BigEndian.Uint32(packet[12:])
		wall := int64(exported)*1_000_000_000 + int64(nanos)
		millis := (wall - origin.UnixNano()) / 1_000_000
		if nanos >= 1_000_000_000 || nanos%1_000_000 != 0 || wall < origin.UnixNano() || millis > int64(^uint32(0)) || uint32(millis) != binary.BigEndian.Uint32(packet[4:]) {
			return fmt.Errorf("v5 wall clock and uptime differ")
		}
	} else if binary.BigEndian.Uint32(packet[header-4:]) != domain {
		return fmt.Errorf("source/observation domain identity")
	}
	if protocol == "v9" && uint64(binary.BigEndian.Uint32(packet[4:])) > (uint64(after)-uint64(before)+1)*1000 {
		return fmt.Errorf("v9 uptime exceeds process lifetime")
	}
	return nil
}

func goldenFile(t *testing.T, protocol, name string) []byte {
	t.Helper()
	var manifest struct {
		Slots []struct {
			Payloads []struct {
				Path, SHA256 string
				Length       int
			}
		}
	}
	must(t, json.Unmarshal(readFile(t, "../testdata/golden/manifest.json"), &manifest))
	path := protocol + "/" + name
	data := readFile(t, "../testdata/golden/"+path)
	for _, slot := range manifest.Slots {
		for _, payload := range slot.Payloads {
			if payload.Path == path && payload.Length == len(data) && payload.SHA256 == hash(data) {
				return data
			}
		}
	}
	t.Fatalf("golden length/hash is not bound by manifest: %s", path)
	return nil
}

func assertBuild(t *testing.T, bin string) {
	t.Helper()
	info, err := buildinfo.ReadFile(bin)
	must(t, err)
	if info.GoVersion != "go1.26.8" {
		t.Fatalf("binary Go version: %s", info.GoVersion)
	}
	pins := map[string]string{
		"go.opentelemetry.io/collector/exporter":                                             "v1.66.0",
		"go.opentelemetry.io/collector/confmap/provider/envprovider":                         "v1.66.0",
		"go.opentelemetry.io/collector/confmap/provider/fileprovider":                        "v1.66.0",
		"go.opentelemetry.io/collector/otelcol":                                              "v0.160.0",
		"go.opentelemetry.io/collector/service":                                              "v0.160.0",
		"go.opentelemetry.io/collector/component":                                            "v1.66.0",
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver": "v0.160.0",
		"github.com/netsampler/goflow2/v2":                                                   "v2.2.6",
	}
	var exporter string
	for _, dep := range info.Deps {
		if version, ok := pins[dep.Path]; ok {
			if dep.Version != version || dep.Replace != nil {
				t.Fatalf("binary dependency changed: %+v", dep)
			}
			delete(pins, dep.Path)
		}
		if dep.Path == "github.com/pocket-grimoire-guild/otelcol-exporter-netflow" {
			if dep.Replace != nil {
				exporter = dep.Version + " => " + dep.Replace.Path + " (" + dep.Replace.Version + ")"
			} else {
				exporter = dep.Version
			}
		}
	}
	if len(pins) != 0 {
		t.Fatalf("missing pinned components: %v", pins)
	}
	must(t, checkExporterBuildIdentity(exporter, os.Getenv("NETFLOW_OCB_BUILD")))
}

func checkExporterBuildIdentity(exporter, buildMode string) error {
	var want string
	switch buildMode {
	case "", "development":
		want = "v0.0.0 => ../.. ((devel))"
	case "versioned":
		want = "v0.2.0"
	case "staged":
		want = "v0.1.0-alpha.1"
	default:
		return fmt.Errorf("unsupported NETFLOW_OCB_BUILD=%q", buildMode)
	}
	if exporter != want {
		return fmt.Errorf("exporter identity=%q want=%q mode=%q", exporter, want, buildMode)
	}
	return nil
}

func TestExporterBuildIdentity(t *testing.T) {
	// Each source path must reject the other paths' identities, even when the
	// exporter has the right module name. No arbitrary version override exists.
	identities := map[string]string{
		"development": "v0.0.0 => ../.. ((devel))",
		"versioned":   "v0.2.0",
		"staged":      "v0.1.0-alpha.1",
	}
	for mode, identity := range identities {
		for source, candidate := range identities {
			t.Run(mode+"/"+source, func(t *testing.T) {
				err := checkExporterBuildIdentity(candidate, mode)
				if (err == nil) != (source == mode) {
					t.Fatalf("identity=%q mode=%q: %v", candidate, mode, err)
				}
			})
		}
		for _, candidate := range []string{"", "v0.1.0", identity + " => ../.. ((devel))"} {
			if err := checkExporterBuildIdentity(candidate, mode); err == nil {
				t.Fatalf("accepted missing, old, or replaced exporter %q in mode %q", candidate, mode)
			}
		}
	}
	must(t, checkExporterBuildIdentity(identities["development"], ""))
	if err := checkExporterBuildIdentity(identities["versioned"], "unknown"); err == nil {
		t.Fatal("accepted unsupported build mode")
	}
}

// Exec copies stdout/stderr concurrently; keep diagnostic memory bounded.
type boundedLog struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if remaining := (1 << 20) - b.buf.Len(); n > remaining {
		p, b.overflow = p[:remaining], true
	}
	b.buf.Write(p)
	return n, nil
}
func (b *boundedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return "LOG LIMIT EXCEEDED\n" + b.buf.String()
	}
	return b.buf.String()
}

type collectorProcess struct {
	cmd     *exec.Cmd
	log     *boundedLog
	done    chan struct{}
	err     error // read only after done closes
	started time.Time
}

func command(ctx context.Context, bin string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	return cmd
}

func runCommand(t *testing.T, bin string, success bool, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := command(ctx, bin, args...)
	log := &boundedLog{}
	cmd.Stdout, cmd.Stderr = log, log
	err := cmd.Run()
	if ctx.Err() != nil || (err == nil) != success || strings.Contains(log.String(), "LOG LIMIT EXCEEDED") {
		t.Fatalf("Collector %v: %v\n%s", args, err, log.String())
	}
	if !success && !strings.Contains(log.String(), "netflow: invalid configuration") {
		t.Fatalf("invalid config failed without component evidence: %s", log.String())
	}
}

func startCollector(t *testing.T, bin, config string) *collectorProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	p := &collectorProcess{cmd: command(ctx, bin, "--config", config), log: &boundedLog{}, done: make(chan struct{}), started: time.Now()}
	if ns := os.Getenv("NETFLOW_OCB_NETNS"); ns != "" {
		p.cmd = command(ctx, "/usr/bin/nsenter", "--net="+ns, "--", bin, "--config", config)
	}
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Error("Collector did not exit after forced cleanup")
		}
	})
	return p
}

func waitReady(t *testing.T, p *collectorProcess) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Contains(p.log.String(), `"msg":"Everything is ready. Begin running and processing data."`) {
			return
		}
		select {
		case <-p.done:
			t.Fatalf("Collector exited before readiness: %v\n%s", p.err, p.log.String())
		case <-timer.C:
			t.Fatalf("Collector readiness timeout\n%s", p.log.String())
		case <-ticker.C:
		}
	}
}

func stopCollector(t *testing.T, p *collectorProcess) {
	t.Helper()
	must(t, p.cmd.Process.Signal(syscall.SIGTERM))
	select {
	case <-p.done:
		if p.err != nil || !strings.Contains(p.log.String(), "Shutdown complete.") || strings.Contains(p.log.String(), "LOG LIMIT EXCEEDED") {
			t.Fatalf("Collector shutdown: %v\n%s", p.err, p.log.String())
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Collector exceeded graceful shutdown bound")
	}
}

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if os.Getenv("NETFLOW_OCB_NETNS") != "" {
		ip = net.IPv4(198, 18, 0, 1)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	must(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func receiverIP() net.IP {
	if os.Getenv("NETFLOW_OCB_NETNS") != "" {
		return net.IPv4(198, 18, 0, 2)
	}
	return net.IPv4(127, 0, 0, 1)
}

func TestLiveReceiverPortReleased(t *testing.T) {
	port := os.Getenv("NETFLOW_OCB_RELEASE_PORT")
	if port == "" {
		t.Skip("internal live-network port-release check")
	}
	conn, err := net.ListenPacket("udp4", net.JoinHostPort(receiverIP().String(), port))
	must(t, err)
	must(t, conn.Close())
}
func assertQuiet(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	must(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	var packet [65535]byte
	n, _, err := conn.ReadFromUDP(packet[:])
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatalf("unexpected extra datagram (%d bytes) or read error: %v", n, err)
	}
}
func replaceOnce(t *testing.T, input, old, new string) string {
	t.Helper()
	if strings.Count(input, old) != 1 {
		t.Fatalf("expected one config occurrence of %q", old)
	}
	return strings.Replace(input, old, new, 1)
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return b
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Legacy matrix receipts keep their original wire layouts. The operator example
// test separately runs the checked-in general-profile configuration unchanged.
func legacyMatrixConfig(t *testing.T) string {
	t.Helper()
	config := string(readFile(t, "../../distribution/ocb/config.yaml"))
	// Only the legacy smoke matrix disables telemetry; keep the operator's
	// reader stanza so the occupied-port control exercises the no-op provider.
	// transportConfig extracts only component stanzas and supplies its own
	// explicit disabled/no-reader service, without a metrics env requirement.
	config = replaceOnce(t, config, "      level: normal\n", "      level: none\n")
	config = replaceOnce(t, config, "/netflow-v9-timed-v1", "/netflow-v9-core-v1")
	config = replaceOnce(t, config, "/ipfix-general-v1", "/ipfix-core-v1")
	config = strings.ReplaceAll(config, "    templates: {id_base: 300}\n", "    templates: {id_base: 256}\n")
	return replaceOnce(t, config, "    uptime_origin: ${env:NETFLOW_V9_ORIGIN}\n", "")
}
