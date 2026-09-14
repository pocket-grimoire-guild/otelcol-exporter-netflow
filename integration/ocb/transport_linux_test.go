package ocb_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCollectorTransportIsolation uses the built Collector and real connected
// Linux UDP sockets. Closing just one destination queues an ICMP error after
// its first locally successful send; the following send must fail. No fake
// transport, automatic retry, or replacement Collector satisfies this check.
func TestCollectorTransportIsolation(t *testing.T) {
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and run smoke_test.sh to exercise the executable")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) { collectorTransportIsolation(t, bin, protocol) })
	}
}

func collectorTransportIsolation(t *testing.T, bin, protocol string) {
	dir := t.TempDir()
	if base := os.Getenv("NETFLOW_OCB_ARTIFACTS"); base != "" {
		var err error
		dir, err = os.MkdirTemp(base, "ocb-transport-"+protocol+"-")
		must(t, err)
		t.Logf("retained integration artifacts: %s", dir)
	}
	input, healthy, failing := listen(t), listen(t), listen(t)
	inputAddr := input.LocalAddr().(*net.UDPAddr)
	failingAddr := failing.LocalAddr().(*net.UDPAddr)
	origin := time.Now().Truncate(time.Second).Add(-4 * time.Second)
	config := transportConfig(t, protocol, inputAddr.Port, healthy.LocalAddr().String(), failingAddr.String(), origin)
	configPath := filepath.Join(dir, "config.yaml")
	must(t, os.WriteFile(configPath, []byte(config), 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	assertQuiet(t, healthy)
	assertQuiet(t, failing)
	must(t, input.Close())
	p := startCollector(t, bin, configPath)
	defer func() { must(t, os.WriteFile(filepath.Join(dir, "collector.log"), []byte(p.log.String()), 0600)) }()
	waitReady(t, p)
	before := uint32(p.started.Unix())
	var inputs, outputs []transportCapture
	peers := map[string]string{}
	receive := func(conn *net.UDPConn, instance, phase string, want []byte, seq uint32) {
		t.Helper()
		must(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		var buf [65535]byte
		n, peer, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			t.Fatalf("%s %s receive: %v\n%s", instance, phase, err, p.log.String())
		}
		if prior := peers[instance]; prior != "" && prior != peer.String() {
			t.Fatal("source socket changed within a destination epoch")
		}
		peers[instance] = peer.String()
		domain := uint32(42)
		if instance == "failing" {
			domain = 43
		}
		packet := buf[:n]
		assertPacket(t, protocol, packet, want, seq, 1, domain, before, origin)
		name := fmt.Sprintf("output-%02d-%s-%s.bin", len(outputs), instance, phase)
		must(t, os.WriteFile(filepath.Join(dir, name), packet, 0600))
		outputs = append(outputs, transportCapture{phase, instance, capture{name, n, hash(packet), peer.String(), conn.LocalAddr().String()}})
	}
	baseSeq := uint32(0)
	if protocol != "v5" {
		for i := range 4 {
			golden := goldenFile(t, protocol, []string{"canonical-ipv4-v1.bin", "canonical-ipv6-v1.bin"}[i%2])
			header, data := offsets(protocol)
			seq := uint32(0)
			if protocol == "v9" {
				seq = uint32(i)
				baseSeq = 4
			}
			receive(healthy, "healthy", "bootstrap", golden[header:data], seq)
			receive(failing, "failing", "bootstrap", golden[header:data], seq)
		}
	}
	assertQuiet(t, healthy)
	assertQuiet(t, failing)
	sender, err := net.DialUDP("udp4", nil, inputAddr)
	must(t, err)
	t.Cleanup(func() { sender.Close() })
	golden := goldenFile(t, protocol, "canonical-ipv4-v1.bin")
	tc := flowCase{Protocol: protocol, Records: 1}
	send := func(phase string, ordinal uint16) []byte {
		t.Helper()
		packet, want := transportRecord(t, tc, golden, origin, ordinal)
		name := fmt.Sprintf("input-%02d-%s.bin", len(inputs), phase)
		must(t, os.WriteFile(filepath.Join(dir, name), packet, 0600))
		inputs = append(inputs, transportCapture{phase, "receiver", capture{name, len(packet), hash(packet), sender.LocalAddr().String(), sender.RemoteAddr().String()}})
		must(t, sender.SetWriteDeadline(time.Now().Add(time.Second)))
		n, err := sender.Write(packet)
		must(t, err)
		if n != len(packet) {
			t.Fatal("short fixture write")
		}
		return want
	}
	want := send("baseline", 0)
	receive(healthy, "healthy", "baseline", want, baseSeq)
	receive(failing, "failing", "baseline", want, baseSeq)
	if peers["healthy"] == peers["failing"] {
		t.Fatal("named instances share a socket")
	}
	assertQuiet(t, healthy)
	assertQuiet(t, failing)
	must(t, checkTransportErrors(p.log.String(), false))

	// The first send to a closed destination can commit locally even though no
	// receiver gets it. Its ICMP error must affect only the next sibling send.
	must(t, failing.Close())
	want = send("closed-port-handoff", 1)
	receive(healthy, "healthy", "closed-port-handoff", want, baseSeq+1)
	// Also allow 100 ms for Linux to deliver the loopback ICMP error before
	// the next request. Missing/suppressed ICMP fails the bounded error check.
	assertQuiet(t, healthy)
	must(t, checkTransportErrors(p.log.String(), false))
	want = send("failed-handoff", 2)
	receive(healthy, "healthy", "failed-handoff", want, baseSeq+2)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := checkTransportErrors(p.log.String(), true); err == nil {
			break
		}
		select {
		case <-p.done:
			t.Fatalf("Collector exited during failure injection: %v\n%s", p.err, p.log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing isolated transient handoff error: %v\n%s", checkTransportErrors(p.log.String(), true), p.log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A bind race, suppressed ICMP, missing error, or different sequence is a
	// failure, never a skipped test or an adaptive retry counted as success.
	failing, err = net.ListenUDP("udp4", failingAddr)
	must(t, err)
	t.Cleanup(func() { failing.Close() })
	assertQuiet(t, failing) // no retained request/automatic retry on recovery
	for i, phase := range []string{"recovered", "continued"} {
		want = send(phase, uint16(3+i))
		receive(healthy, "healthy", phase, want, baseSeq+3+uint32(i))
		receive(failing, "failing", phase, want, baseSeq+2+uint32(i))
		assertQuiet(t, healthy)
		assertQuiet(t, failing)
	}
	stopCollector(t, p)
	assertQuiet(t, healthy)
	assertQuiet(t, failing)
	log := p.log.String()
	if !strings.HasSuffix(log, "\n") {
		t.Fatal("incomplete final Collector log")
	}
	must(t, checkTransportErrors(log, true))
	for _, address := range []string{inputAddr.String(), peers["healthy"], peers["failing"]} {
		addr, err := net.ResolveUDPAddr("udp4", address)
		must(t, err)
		conn, err := net.ListenUDP("udp4", addr)
		must(t, err)
		must(t, conn.Close())
	}
	ledger := struct {
		Protocol                   string
		PID                        int
		BinarySHA256, ConfigSHA256 string
		OriginUnixNano             int64
		Inputs, Outputs            []transportCapture
	}{protocol, p.cmd.Process.Pid, hash(readFile(t, bin)), hash([]byte(config)), origin.UnixNano(), inputs, outputs}
	data, err := json.MarshalIndent(ledger, "", "  ")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "capture.json"), append(data, '\n'), 0600))
	t.Logf("%s transport isolation PASS: five distinct inputs, uninterrupted healthy sequence, one sibling transient handoff, same-socket recovery and clean shutdown", protocol)
}

type transportCapture struct {
	Phase, Instance string
	capture
}

// Reuse the example's reviewed receiver/exporter stanzas, selecting one real
// pipeline and duplicating only its destination. Materialize endpoint/origin
// substitutions so the retained config hash describes the actual input.
func transportConfig(t *testing.T, protocol string, port int, healthy, failing string, origin time.Time) string {
	t.Helper()
	base := legacyMatrixConfig(t)
	parts := strings.Split(base, "exporters:\n")
	if len(parts) != 2 {
		t.Fatal("expected one exporters section")
	}
	stanza := func(section string) string {
		t.Helper()
		start := "  netflow/" + protocol + ":\n"
		if strings.Count(section, start) != 1 {
			t.Fatal("missing or duplicate protocol stanza")
		}
		_, rest, _ := strings.Cut(section, start)
		lines := strings.SplitAfter(rest, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "  netflow/") || strings.HasPrefix(line, "service:") {
				return start + strings.Join(lines[:i], "")
			}
		}
		return start + rest
	}
	rx, exporter := stanza(parts[0]), stanza(parts[1])
	sibling := replaceOnce(t, exporter, "  netflow/"+protocol+":", "  netflow/failing:")
	sibling = replaceOnce(t, sibling, "${env:NETFLOW_"+strings.ToUpper(protocol)+"_ENDPOINT}", failing)
	if protocol != "v5" {
		sibling = replaceOnce(t, sibling, "_id: 42", "_id: 43")
	}
	config := "receivers:\n" + rx + "exporters:\n" + exporter + sibling + fmt.Sprintf(`service:
  telemetry:
    logs:
      encoding: json
    metrics:
      level: none
  pipelines:
    logs/isolation:
      receivers: [netflow/%s]
      exporters: [netflow/%s, netflow/failing]
`, protocol, protocol)
	config = strings.ReplaceAll(config, "${env:NETFLOW_"+strings.ToUpper(protocol)+"_PORT}", fmt.Sprint(port))
	config = strings.ReplaceAll(config, "${env:NETFLOW_"+strings.ToUpper(protocol)+"_ENDPOINT}", healthy)
	config = strings.ReplaceAll(config, "${env:NETFLOW_V5_ORIGIN}", fmt.Sprint(origin.UnixNano()))
	if strings.Contains(config, "${") {
		t.Fatal("unresolved config substitution")
	}
	return config
}

func transportRecord(t *testing.T, tc flowCase, golden []byte, origin time.Time, ordinal uint16) (input, want []byte) {
	t.Helper()
	input = bytes.Clone(golden)
	if tc.Protocol == "v5" {
		binary.BigEndian.PutUint32(input[8:], uint32(origin.Unix()+3))
	}
	// Independent fixed-profile source-port offsets: v5 record byte 32,
	// v9 record byte 11, IPFIX record byte 20. The templated Set header is 4.
	recordPort := map[string]int{"v5": 32, "v9": 4 + 11, "ipfix": 4 + 20}[tc.Protocol]
	_, data := offsets(tc.Protocol)
	if !bytes.Equal(input[data+recordPort:data+recordPort+2], []byte{0x30, 0x39}) {
		t.Fatal("golden source port must be 12345 before deriving phase identity")
	}
	port := uint16(12345) + ordinal
	binary.BigEndian.PutUint16(input[data+recordPort:], port)
	want = projectedData(tc, golden, false)
	binary.BigEndian.PutUint16(want[recordPort:], port)
	return input, want
}

// The pinned helper reports the fixed exporter error with its component ID.
// Receiver diagnostics may repeat it; only exporter-owned error events count.
// Inspect complete JSON lines while the process is live, then again after exit.
func checkTransportErrors(log string, wantFailure bool) error {
	if strings.Contains(log, "LOG LIMIT EXCEEDED") {
		return fmt.Errorf("Collector log exceeded its bound")
	}
	failures := 0
	lines := strings.Split(log, "\n")
	for _, line := range lines[:len(lines)-1] {
		var event struct {
			Level     string `json:"level"`
			Component string `json:"otelcol.component.id"`
			Kind      string `json:"otelcol.component.kind"`
			Signal    string `json:"otelcol.signal"`
			Message   string `json:"msg"`
			Error     string `json:"error"`
			Rejected  int    `json:"rejected_items"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return fmt.Errorf("invalid Collector JSON log: %w", err)
		}
		if event.Level != "error" || event.Kind != "exporter" {
			continue
		}
		if event.Component == "netflow/failing" && event.Signal == "logs" && event.Message == "Exporting failed. Rejecting data." && event.Error == "netflow: transient packet handoff" && event.Rejected == 1 {
			failures++
		} else {
			return fmt.Errorf("unexpected exporter rejection: %+v", event)
		}
	}
	want := 0
	if wantFailure {
		want = 1
	}
	if failures != want {
		return fmt.Errorf("got %d sibling transient errors, want %d", failures, want)
	}
	return nil
}
