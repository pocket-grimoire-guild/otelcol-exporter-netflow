package independent_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in test runs an actual stock upstream receiver. An explicitly set
// but unavailable/broken binary fails; ordinary Go tests do not install tools.
func TestNfacctd(t *testing.T) {
	bin := os.Getenv("NFACCTD_BINARY")
	if bin == "" {
		t.Skip("set NFACCTD_BINARY to a stock pmacct 1.7.9 binary with Jansson")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	must(t, err)
	if !bytes.Contains(version, []byte("1.7.9")) || !bytes.Contains(bytes.ToLower(version), []byte("jansson")) {
		t.Fatalf("requires pmacct 1.7.9 with Jansson: %s", version)
	}
	root := os.Getenv("NFACCTD_ARTIFACTS")
	if root == "" {
		root = t.TempDir()
	} else {
		root, err = filepath.Abs(root)
		must(t, err)
		// Refuse reuse: stale output must never satisfy a fresh receiver case.
		must(t, os.Mkdir(root, 0700))
	}
	must(t, os.WriteFile(filepath.Join(root, "version.txt"), version, 0600))
	writeJSON(t, filepath.Join(root, "binary.json"), map[string]string{
		"path": bin, "sha256": fmt.Sprintf("%x", sha256.Sum256(readFile(t, bin))),
	})
	t.Logf("receiver artifacts: %s", root)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		var ledger fixtureLedger
		decodeJSON(t, readFile(t, filepath.Join("..", "testdata", "receiver", protocol, "ledger.json")), &ledger)
		if len(ledger.Cases) == 0 {
			t.Fatal("empty fixture ledger")
		}
		for _, tc := range ledger.Cases {
			t.Run(protocol+"/"+tc.Name, func(t *testing.T) {
				runNfacctd(t, bin, root, protocol, ledger, tc, -1)
			})
		}
		if protocol == "ipfix" {
			for _, n := range []int{3, 255} {
				t.Run(fmt.Sprintf("ipfix/enterprise-%d", n), func(t *testing.T) {
					runNfacctd(t, bin, root, protocol, ledger, ledger.Cases[0], n)
				})
			}
		}
	}
}

type capturedPacket struct {
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Length   int    `json:"length"`
	Phase    string `json:"phase"`
	Sequence uint32 `json:"sequence"`
	Source   string `json:"source"`
}

func runNfacctd(t *testing.T, bin, root, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int) {
	t.Helper()
	dir := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	must(t, os.Mkdir(dir, 0700))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reservation := udpListener(t)
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	if port < 1024 {
		t.Fatal("receiver reservation must use an unprivileged port")
	}
	output := filepath.Join(dir, "decoded.jsonl")
	config := fmt.Sprintf(`daemonize: false
plugins: print
nfacctd_ip: 127.0.0.1
nfacctd_port: %d
nfacctd_renormalize: false
nfacctd_as: netflow
nfacctd_net: netflow
aggregate: src_host,dst_host,src_port,dst_port,proto,tos,tcpflags,in_iface,out_iface,src_as,dst_as,src_mask,dst_mask,flows,timestamp_start,timestamp_end,timestamp_export,sampling_rate,export_proto_seqno,export_proto_version,export_proto_sysid
timestamps_since_epoch: true
tcpflags_encode_as_array: false
print_output: json
print_refresh_time: 1
print_output_file: %s
print_output_file_append: true
`, port, output)
	if customLen >= 0 {
		primitives := filepath.Join(dir, "primitives.lst")
		must(t, os.WriteFile(primitives, []byte("name=pen_fixed field_type=32473:400 len=4 semantics=raw\nname=pen_vlen field_type=32473:401 len=vlen semantics=raw\n"), 0600))
		config = strings.Replace(config, "aggregate: src_host", "aggregate: pen_fixed,pen_vlen,src_host", 1)
		config += "aggregate_primitives: " + primitives + "\n"
	}
	configPath := filepath.Join(dir, "nfacctd.conf")
	must(t, os.WriteFile(configPath, []byte(config), 0600))
	must(t, reservation.Close()) // One attempt: a bind race fails readiness.
	stop := startNfacctd(t, ctx, bin, configPath, dir, port)

	stream, custom := exportStream(t, ctx, dir, port, protocol, ledger, tc, customLen)
	var expected []map[string]any
	for _, packet := range stream {
		if packet.phase == "data" {
			expected = append(expected, pmacctProjection(protocol, tc, packet.bytes, packet.sequence, custom)...)
		}
	}

	writeJSON(t, filepath.Join(dir, "expected.json"), expected)
	// Three sequence-distinct exports keep pmacct aggregates distinct. Require
	// exact count, values and types, then stability and a post-shutdown check.
	var stable time.Time
	for {
		rows, err := readRows(output, false)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if len(rows) > len(expected) {
			t.Fatalf("extra decoded rows: %d > %d", len(rows), len(expected))
		}
		if len(rows) == len(expected) {
			must(t, compareRows(rows, expected))
			if stable.IsZero() {
				stable = time.Now()
			} else if time.Since(stable) >= 1100*time.Millisecond {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("decoded %d/%d rows: %v; see %s", len(rows), len(expected), ctx.Err(), dir)
		case <-time.After(20 * time.Millisecond):
		}
	}
	stop()
	rows, err := readRows(output, true)
	must(t, err)
	must(t, compareRows(rows, expected))
	t.Logf("%d decoded aggregates from %d retained datagrams; three data messages, refresh=%v", len(rows), len(stream), protocol != "v5")
}

func ptr[T any](v T) *T { return &v }

func udpListener(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func startNfacctd(t *testing.T, ctx context.Context, bin, config, dir string, port int) func() {
	t.Helper()
	logPath := filepath.Join(dir, "receiver.log")
	log, err := os.Create(logPath)
	must(t, err)
	t.Cleanup(func() { _ = log.Close() })
	cmd := exec.Command(bin, "-f", config)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	must(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		// SIGINT asks the core to flush and stop its print child. Always kill
		// the entire group afterward, including on a failed readiness/decode.
		defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Signal(syscall.SIGINT)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("nfacctd exit: %v; see %s", err, logPath)
			}
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			t.Errorf("nfacctd shutdown exceeded 5 seconds; see %s", logPath)
		}
	}
	t.Cleanup(stop)
	for {
		data := readFile(t, logPath)
		// The core's bind message precedes print-child readiness. Wait for
		// the first empty purge as well: the child has entered its poll loop
		// and enabled pipe wakeups before any exporter datagram is sent.
		if bytes.Contains(data, []byte("waiting for NetFlow/IPFIX data")) && bytes.Contains(data, []byte(fmt.Sprintf("port=%d/udp", port))) && bytes.Contains(data, []byte("QN: 0/0")) {
			return stop
		}
		select {
		case err := <-done:
			stopped = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Fatalf("nfacctd exited before readiness: %v\n%s", err, data)
		case <-ctx.Done():
			t.Fatalf("nfacctd readiness: %v\n%s", ctx.Err(), data)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func readRows(path string, complete bool) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRows(data, complete)
}

func parseRows(data []byte, complete bool) ([]map[string]any, error) {
	// The print child may be appending a line while we poll. Only complete
	// lines count during the run; after shutdown a partial tail is an error.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if complete {
			return nil, errors.New("incomplete receiver output")
		}
		data = data[:bytes.LastIndexByte(data, '\n')+1]
	}
	var rows []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row map[string]any
		d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		d.UseNumber()
		if err := d.Decode(&row); err != nil {
			return nil, err
		}
		if row == nil {
			return nil, errors.New("null receiver row")
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return nil, errors.New("trailing receiver output on JSON line")
		}
		rows = append(rows, row)
	}
	return rows, scanner.Err()
}

func compareRows(got, want []map[string]any) error {
	if len(got) != len(want) {
		return fmt.Errorf("decoded rows=%d, want %d", len(got), len(want))
	}
	key := func(row map[string]any) string {
		return fmt.Sprint(row["export_proto_seqno"], "/", row["sampling_rate"])
	}
	sort.Slice(got, func(i, j int) bool { return key(got[i]) < key(got[j]) })
	sort.Slice(want, func(i, j int) bool { return key(want[i]) < key(want[j]) })
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			return fmt.Errorf("row %d:\n got %#v\nwant %#v", i, got[i], want[i])
		}
	}
	return nil
}
