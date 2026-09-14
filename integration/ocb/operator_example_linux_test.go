package ocb_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCollectorOperatorExample runs the checked-in operator configuration as
// written. The Collector, rather than the test, expands its env: providers;
// this catches a broken provider pin or a stale placeholder as well as proving
// startup, all three output protocols, and graceful shutdown.
func TestCollectorOperatorExample(t *testing.T) {
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and set NETFLOW_OCB_BINARY to exercise the operator example")
	}
	if os.Getenv("NETFLOW_OCB_NETNS") != "" {
		t.Skip("the checked-in operator example targets ordinary loopback")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	config := readFile(t, "../../distribution/ocb/config.yaml")
	if !bytes.Contains(config, []byte("${env:NETFLOW_V5_PORT}")) ||
		!bytes.Contains(config, []byte("${env:NETFLOW_V9_PORT}")) ||
		!bytes.Contains(config, []byte("${env:NETFLOW_IPFIX_PORT}")) ||
		!bytes.Contains(config, []byte("${env:NETFLOW_V9_ORIGIN}")) {
		t.Fatal("operator example must retain Collector env-provider placeholders")
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

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	// Preserve the exact checked-in bytes. Substitution is deliberately left to
	// the pinned Collector env provider in both validate and the real process.
	must(t, os.WriteFile(configPath, config, 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	for _, input := range inputs {
		must(t, input.Close())
	}
	p := startCollector(t, bin, configPath)
	waitReady(t, p)
	before := uint32(p.started.Unix())

	receive := func(protocol string, want []byte, sequence uint32, count int) {
		t.Helper()
		out := outputs[protocol]
		must(t, out.SetReadDeadline(time.Now().Add(5*time.Second)))
		var buf [65535]byte
		n, _, err := out.ReadFromUDP(buf[:])
		must(t, err)
		packet := buf[:n]
		if protocol == "v9" {
			assertTimedV9Packet(t, packet, want, sequence, count, before, origin)
		} else {
			assertPacket(t, protocol, packet, want, sequence, count, 42, before, origin)
		}
	}

	// The v9 and IPFIX profiles have two family templates and two initial
	// copies. v5 is fixed-format and emits no bootstrap template datagrams.
	for _, protocol := range []string{"v9", "ipfix"} {
		for i := range 4 {
			name := []string{"canonical-ipv4-v1.bin", "canonical-ipv6-v1.bin"}[i%2]
			golden := operatorGolden(t, protocol, name)
			if protocol == "v9" {
				// The timed profile uses a fresh range while its input fixture
				// retains the canonical 256/257 IDs.
				golden = bytes.Clone(golden)
				binary.BigEndian.PutUint16(golden[24:26], uint16(300+i%2))
			} else if protocol == "ipfix" {
				// The operator configuration selects the general profile
				// with a 300 base; fixture bytes retain the canonical 256/257
				// IDs so this test rebases only the expected template packet.
				golden = bytes.Clone(golden)
				binary.BigEndian.PutUint16(golden[20:22], uint16(300+i%2))
			}
			header, data := offsets(protocol)
			if protocol == "v9" {
				data = 108 // timed v9 template/data boundary
			}
			sequence := uint32(0)
			if protocol == "v9" {
				sequence = uint32(i)
			}
			receive(protocol, golden[header:data], sequence, 1)
		}
	}

	senders := map[string]*net.UDPConn{}
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: receiverIP(), Port: ports[protocol]})
		must(t, err)
		t.Cleanup(func() { sender.Close() })
		senders[protocol] = sender
	}
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		golden := operatorGolden(t, protocol, "canonical-ipv4-v1.bin")
		input := bytes.Clone(golden)
		if protocol == "v5" {
			// Rebase only the v5 packet's export seconds to the test origin;
			// its canonical 3000 ms sysUpTime and record bytes stay unchanged.
			binary.BigEndian.PutUint32(input[8:], uint32(origin.Unix()+3))
		} else if protocol == "v9" {
			// Rebase the v9 timed fixture's header seconds to this test's
			// deployment-owned origin. Its 3000/4000ms switched values stay
			// measured and remain integral relative uptime.
			binary.BigEndian.PutUint32(input[8:], uint32(origin.Unix()+5))
		}
		sender := senders[protocol]
		must(t, sender.SetWriteDeadline(time.Now().Add(time.Second)))
		n, err := sender.Write(input)
		must(t, err)
		if n != len(input) {
			t.Fatalf("%s input short write: %d/%d", protocol, n, len(input))
		}
		sequence := map[string]uint32{"v5": 0, "v9": 4, "ipfix": 0}[protocol]
		want := projectedData(flowCase{Protocol: protocol, Records: 1}, golden, false)
		if protocol == "v9" {
			want = projectedTimedData(t, golden, false)
		} else if protocol == "ipfix" {
			want = projectedGeneralData(t, golden, false)
		}
		receive(protocol, want, sequence, 1)
	}
	// Exercise the second timed v9 template with measured IPv6 source times.
	goldenV9IPv6 := operatorGolden(t, "v9", "canonical-ipv6-v1.bin")
	inputV9IPv6 := bytes.Clone(goldenV9IPv6)
	binary.BigEndian.PutUint32(inputV9IPv6[8:], uint32(origin.Unix()+5))
	must(t, senders["v9"].SetWriteDeadline(time.Now().Add(time.Second)))
	n, err := senders["v9"].Write(inputV9IPv6)
	must(t, err)
	if n != len(inputV9IPv6) {
		t.Fatalf("IPv6 v9 input short write: %d/%d", n, len(inputV9IPv6))
	}
	receive("v9", projectedTimedData(t, goldenV9IPv6, true), 5, 1)

	// A legacy time-free v9 input has no measured 22/21 provenance. If the
	// upstream receiver supplies a fallback, it must not be mistaken for the
	// measured 3000/4000ms interval used above; a correctly rejecting pipeline
	// may produce no packet at all.
	legacyNoTime := goldenFile(t, "v9", "canonical-ipv4-v1.bin")
	must(t, senders["v9"].SetWriteDeadline(time.Now().Add(time.Second)))
	n, err = senders["v9"].Write(legacyNoTime)
	must(t, err)
	if n != len(legacyNoTime) {
		t.Fatalf("legacy no-time v9 input short write: %d/%d", n, len(legacyNoTime))
	}
	assertNoMeasuredV9Fallback(t, outputs["v9"])

	// Exercise the second recommended template with measured IPv6 source times.
	golden6 := operatorGolden(t, "ipfix", "canonical-ipv6-v1.bin")
	must(t, senders["ipfix"].SetWriteDeadline(time.Now().Add(time.Second)))
	n, err = senders["ipfix"].Write(golden6)
	must(t, err)
	if n != len(golden6) {
		t.Fatalf("IPv6 input short write: %d/%d", n, len(golden6))
	}
	receive("ipfix", projectedGeneralData(t, golden6, true), 1, 1)
	stopCollector(t, p)
	for _, output := range outputs {
		assertQuiet(t, output)
	}
	for protocol, port := range ports {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: receiverIP(), Port: port})
		if err != nil {
			t.Fatalf("%s receiver port %d was not released: %v", protocol, port, err)
		}
		must(t, conn.Close())
	}
	t.Log("checked-in operator example passed Collector env expansion, v5/v9/IPFIX export, and shutdown")
}

func assertTimedV9Packet(t *testing.T, packet, want []byte, sequence uint32, count int, processStart uint32, origin time.Time) {
	t.Helper()
	// The configured origin intentionally predates process start by a bounded
	// deployment interval. Use it for the generic uptime lifetime check, then
	// separately retain the actual process-start export-time assertion.
	after := uint32(time.Now().Unix())
	if err := validatePacket("v9", packet, want, sequence, count, 42, uint32(origin.Unix()), after, origin); err != nil {
		t.Fatalf("timed v9 packet: %v", err)
	}
	exported := binary.BigEndian.Uint32(packet[8:12])
	if exported < processStart || exported > after {
		t.Fatalf("timed v9 export time outside live process interval: %d not in %d..%d", exported, processStart, after)
	}
	assertTimedHeaderBase(t, packet, origin)
	if len(want) != 88 {
		assertTimedHeader(t, want, packet, origin)
	}
}

func assertTimedHeaderBase(t *testing.T, packet []byte, origin time.Time) {
	t.Helper()
	if len(packet) < 12 {
		t.Fatalf("timed v9 header is truncated: %d", len(packet))
	}
	baseMillis := int64(binary.BigEndian.Uint32(packet[8:12]))*1000 - int64(binary.BigEndian.Uint32(packet[4:8]))
	shift := origin.UnixMilli() - baseMillis
	if shift < 0 || shift > 999 {
		t.Fatalf("timed v9 header origin projection base=%d origin=%d shift=%d", baseMillis, origin.UnixMilli(), shift)
	}
}

func assertTimedHeader(t *testing.T, want, packet []byte, origin time.Time) {
	t.Helper()
	const recordOffset = 4
	startOffset := 43
	if len(want) >= recordOffset+75 {
		startOffset = 67
	}
	if len(want) < recordOffset+startOffset+8 || len(packet) < 20+len(want) {
		t.Fatalf("timed output is truncated: packet=%d data=%d", len(packet), len(want))
	}
	baseMillis := int64(binary.BigEndian.Uint32(packet[8:12]))*1000 - int64(binary.BigEndian.Uint32(packet[4:8]))
	originMillis := origin.UnixNano() / int64(time.Millisecond)
	shiftStart := originMillis + 3000 - (baseMillis + int64(binary.BigEndian.Uint32(want[recordOffset+startOffset:])))
	shiftEnd := originMillis + 4000 - (baseMillis + int64(binary.BigEndian.Uint32(want[recordOffset+startOffset+4:])))
	if shiftStart != shiftEnd || shiftStart < 0 || shiftStart > 999 {
		t.Fatalf("timed header origin projection base=%d origin=%d shifts=%d/%d", baseMillis, originMillis, shiftStart, shiftEnd)
	}
}

func operatorGolden(t *testing.T, protocol, name string) []byte {
	t.Helper()
	if protocol == "v9" {
		path := "../testdata/golden/v9/timed-" + strings.TrimPrefix(name, "canonical-")
		data := readFile(t, path)
		wants := map[string]struct {
			length int
			hash   string
		}{
			"canonical-ipv4-v1.bin": {164, "204cd5586cc098c407ebfbae6dab6587710b80dc82d8eb27c0b9b6ce156dd20b"},
			"canonical-ipv6-v1.bin": {188, "66f7a79d1304e3921824dbb90bcfe0577f0fdd75024591b54bdd67b9f4e0d4e8"},
		}
		want, ok := wants[name]
		if !ok || len(data) != want.length || hash(data) != want.hash {
			t.Fatalf("timed v9 golden length/hash mismatch: %s", path)
		}
		return data
	}
	if protocol != "ipfix" {
		return goldenFile(t, protocol, name)
	}
	path := "../testdata/golden/ipfix/general-" + strings.TrimPrefix(name, "canonical-")
	data := readFile(t, path)
	wants := map[string]struct {
		length int
		hash   string
	}{
		"canonical-ipv4-v1.bin": {180, "d13784d17f685d41faa64d40b371b4037031ababecc52b534fe0aafab4a12b01"},
		"canonical-ipv6-v1.bin": {204, "7ef96d2a3b76ad904d3c08d91a98122f6f6d4f01b790c3f3c166a67820ddbed6"},
	}
	want, ok := wants[name]
	if !ok || len(data) != want.length || hash(data) != want.hash {
		t.Fatalf("general IPFIX golden length/hash mismatch: %s", path)
	}
	return data
}

func projectedTimedData(t *testing.T, golden []byte, ipv6 bool) []byte {
	t.Helper()
	const dataOffset = 108
	if len(golden) < dataOffset {
		t.Fatalf("timed v9 golden is truncated: %d", len(golden))
	}
	want := bytes.Clone(golden[dataOffset:])
	width, sampling := 51, 37
	if ipv6 {
		width, sampling = 75, 61
	}
	if len(want) < 4+width {
		t.Fatalf("timed v9 data golden is truncated: %d", len(want))
	}
	for i := range 1 {
		record := want[4+i*width:]
		clear(record[sampling : sampling+4]) // receiver ignores ordinary IE 34
	}
	// The operator config uses template IDs 300/301 while the immutable
	// fixture is authored at 256/257.
	binary.BigEndian.PutUint16(want[0:2], binary.BigEndian.Uint16(want[0:2])+44)
	return want
}

func assertNoMeasuredV9Fallback(t *testing.T, output *net.UDPConn) {
	t.Helper()
	must(t, output.SetReadDeadline(time.Now().Add(5*time.Second)))
	var packet [65535]byte
	n, _, err := output.ReadFromUDP(packet[:])
	if err != nil {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return
		}
		t.Fatal(err)
	}
	if n < 76 || binary.BigEndian.Uint16(packet[0:2]) != 9 || binary.BigEndian.Uint16(packet[20:22]) != 300 || binary.BigEndian.Uint16(packet[22:24]) != 56 {
		t.Fatalf("legacy no-time v9 output envelope: %x", packet[:min(n, 24)])
	}
	first := binary.BigEndian.Uint32(packet[24+43 : 24+47])
	last := binary.BigEndian.Uint32(packet[24+47 : 24+51])
	if first == 3000 && last == 4000 {
		t.Fatal("legacy no-time v9 input was reported as the measured interval")
	}
}

func projectedGeneralData(t *testing.T, golden []byte, ipv6 bool) []byte {
	t.Helper()
	_, offset := offsets("ipfix")
	want := bytes.Clone(golden[offset:])
	width, sampling := 72, 50
	if ipv6 {
		width, sampling = 96, 74
	}
	if len(want) < 4+width {
		t.Fatalf("general data golden is truncated: %d", len(want))
	}
	record := want[4 : 4+width]
	// GoFlow2 does not preserve ordinary IE 34 in the receiver record.
	clear(record[sampling : sampling+4])
	binary.BigEndian.PutUint16(want[0:2], binary.BigEndian.Uint16(want[0:2])+44)
	return want
}

// TestCollectorOperatorExampleRejectsQueue covers the operator-facing failure
// mode that most often results from copying a generic Collector example. The
// exporter intentionally has no queue or retry implementation.
func TestCollectorOperatorExampleRejectsQueue(t *testing.T) {
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and set NETFLOW_OCB_BINARY to exercise configuration validation")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	for key, value := range map[string]string{
		"V5_PORT": "20550", "V9_PORT": "20551", "IPFIX_PORT": "20552",
	} {
		t.Setenv("NETFLOW_"+key, value)
	}
	for key, value := range map[string]string{
		"V5_ENDPOINT": "127.0.0.1:25050", "V9_ENDPOINT": "127.0.0.1:25051", "IPFIX_ENDPOINT": "127.0.0.1:25052",
	} {
		t.Setenv("NETFLOW_"+key, value)
	}
	t.Setenv("NETFLOW_V5_ORIGIN", "1788220799000000000")
	t.Setenv("NETFLOW_V9_ORIGIN", "1788220799000000000")
	config := string(readFile(t, "../../distribution/ocb/config.yaml"))
	validPath := filepath.Join(t.TempDir(), "valid.yaml")
	must(t, os.WriteFile(validPath, []byte(config), 0600))
	runCommand(t, bin, true, "validate", "--config", validPath)
	config = replaceOnce(t, config, "    protocol: ipfix\n    schema:", "    protocol: ipfix\n    sending_queue: {enabled: true}\n    schema:")
	path := filepath.Join(t.TempDir(), "invalid-queue.yaml")
	must(t, os.WriteFile(path, []byte(config), 0600))
	runCommand(t, bin, false, "validate", "--config", path)
}

func TestCollectorConsumer30sRefreshConfig(t *testing.T) {
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and set NETFLOW_OCB_BINARY to exercise consumer configuration validation")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	for key, value := range map[string]string{
		"V5_PORT": "20550", "V9_PORT": "20551", "IPFIX_PORT": "20552",
	} {
		t.Setenv("NETFLOW_"+key, value)
	}
	for key, value := range map[string]string{
		"V5_ENDPOINT": "127.0.0.1:25050", "V9_ENDPOINT": "127.0.0.1:25051", "IPFIX_ENDPOINT": "127.0.0.1:25052",
	} {
		t.Setenv("NETFLOW_"+key, value)
	}
	t.Setenv("NETFLOW_V5_ORIGIN", "1788220799000000000")
	t.Setenv("NETFLOW_V9_ORIGIN", "1788220799000000000")

	config := string(readFile(t, "../../distribution/ocb/config-consumer-30s.yaml"))
	if got := strings.Count(config, "refresh_interval: 30s"); got != 2 {
		t.Fatalf("consumer config refresh intervals=%d, want v9 and IPFIX entries", got)
	}
	_, exporters, found := strings.Cut(config, "\nexporters:\n")
	if !found {
		t.Fatal("consumer config is missing exporters")
	}
	for _, protocol := range []string{"v9", "ipfix"} {
		marker := "  netflow/" + protocol + ":\n"
		start := strings.Index(exporters, marker)
		if start < 0 {
			t.Fatalf("consumer config is missing exporter netflow/%s", protocol)
		}
		section := exporters[start+len(marker):]
		if next := strings.Index(section, "\n  netflow/"); next >= 0 {
			section = section[:next]
		}
		if strings.Count(section, "refresh_interval: 30s") != 1 {
			t.Fatalf("consumer config exporter netflow/%s does not set exactly one 30s refresh", protocol)
		}
	}
	validPath := filepath.Join(t.TempDir(), "consumer-30s.yaml")
	must(t, os.WriteFile(validPath, []byte(config), 0600))
	runCommand(t, bin, true, "validate", "--config", validPath)

	invalid := strings.Replace(config, "refresh_interval: 30s", "refresh_interval: 29.999999999s", 1)
	invalidPath := filepath.Join(t.TempDir(), "consumer-below-minimum.yaml")
	must(t, os.WriteFile(invalidPath, []byte(invalid), 0600))
	runCommand(t, bin, false, "validate", "--config", invalidPath)
}
