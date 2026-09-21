package ocb_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
		!bytes.Contains(config, []byte("${env:NETFLOW_V9_ORIGIN}")) ||
		!bytes.Contains(config, []byte("${env:NETFLOW_METRICS_PORT}")) {
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
	metrics := reserveMetricsPort(t)
	metricsAddress := metrics.Addr().String()
	scraper := newOperatorScraper(t, metricsAddress)

	dir := t.TempDir()
	if base := os.Getenv("NETFLOW_OCB_ARTIFACTS"); base != "" {
		dir, err = os.MkdirTemp(base, "ocb-operator-")
		must(t, err)
		t.Logf("retained operator artifacts: %s", dir)
	}
	configPath := filepath.Join(dir, "config.yaml")
	// Preserve the exact checked-in bytes. Substitution is deliberately left to
	// the pinned Collector env provider in both validate and the real process.
	must(t, os.WriteFile(configPath, config, 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	for _, input := range inputs {
		must(t, input.Close())
	}
	must(t, metrics.Close()) // one real bind attempt; a race fails readiness
	p := startCollector(t, bin, configPath)
	defer func() {
		must(t, os.WriteFile(filepath.Join(dir, "collector.log"), []byte(p.log.String()), 0600))
	}()
	waitReady(t, p)
	before := uint32(p.started.Unix())
	initial := scraper.poll(t, "startup", dir, func(s operatorScrape) bool { return true })
	assertOperatorLifetimeProjection(t, initial, map[string]time.Time{"v5": origin, "v9": origin}, 0)

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
			sequence := uint32(0)
			if protocol == "v9" {
				sequence = uint32(i)
			}
			receive(protocol, operatorBootstrapTemplate(t, protocol, i%2), sequence, 1)
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
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		id := "netflow/" + protocol
		baseline := initial.accounting(t, id, false)
		scraper.poll(t, protocol+"-valid", dir, func(s operatorScrape) bool {
			return s.accounting(t, id, true) == baseline.add(1, 0, 0, 1)
		})
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
	baseline := initial.accounting(t, "netflow/ipfix", false).add(2, 0, 0, 2)
	scraper.poll(t, "ipfix-before-mixed", dir, func(s operatorScrape) bool {
		return s.accounting(t, "netflow/ipfix", true) == baseline
	})
	// Derive two records from the hash-checked general fixture. Only the
	// second protocolIdentifier changes; the receiver maps 255 to unknown,
	// which is absent from the example's tcp/udp token map.
	golden := operatorGolden(t, "ipfix", "canonical-ipv4-v1.bin")
	mixed := mixedProtocolIPFIX(t, golden)
	must(t, os.WriteFile(filepath.Join(dir, "mixed-ipfix.bin"), mixed, 0600))
	must(t, senders["ipfix"].SetWriteDeadline(time.Now().Add(time.Second)))
	n, err = senders["ipfix"].Write(mixed)
	must(t, err)
	if n != len(mixed) {
		t.Fatalf("mixed IPFIX short write: %d/%d", n, len(mixed))
	}
	receive("ipfix", projectedGeneralData(t, golden, false), 2, 1)
	assertOperatorQuiet(t, outputs["ipfix"])
	afterMixed := baseline.add(1, 1, 1, 2)
	scraper.poll(t, "ipfix-mixed", dir, func(s operatorScrape) bool {
		return s.accounting(t, "netflow/ipfix", true) == afterMixed
	})
	must(t, senders["ipfix"].SetWriteDeadline(time.Now().Add(time.Second)))
	n, err = senders["ipfix"].Write(golden)
	must(t, err)
	if n != len(golden) {
		t.Fatalf("next valid IPFIX short write: %d/%d", n, len(golden))
	}
	receive("ipfix", projectedGeneralData(t, golden, false), 3, 1)
	assertOperatorQuiet(t, outputs["ipfix"])
	later := scraper.poll(t, "ipfix-next-valid", dir, func(s operatorScrape) bool {
		return s.accounting(t, "netflow/ipfix", true) == afterMixed.add(1, 0, 0, 1)
	})
	assertOperatorLifetimeProjection(t, later, map[string]time.Time{"v5": origin, "v9": origin}, 0)
	t.Log("mixed IPFIX deltas: confirmed=1 invalid=1 rejected/map_miss=1 helper_sent=2 helper_failed=0; in-flight=0; next valid preserves rejections")
	stopCollector(t, p)
	assertMetricsPortReleased(t, metricsAddress)
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
	reserveMetricsPort(t) // numeric env expansion; validation must not bind
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
	reserveMetricsPort(t)
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
	const readerPolicy = `    metrics:
      level: normal
      readers:
        - pull:
            exporter:
              prometheus:
                host: 127.0.0.1
                port: ${env:NETFLOW_METRICS_PORT}
                without_scope_info: true
                without_units: true
                without_type_suffix: true
`
	for _, name := range []string{"config.yaml", "config-consumer-30s.yaml"} {
		data := readFile(t, "../../distribution/ocb/"+name)
		if bytes.Count(data, []byte(readerPolicy)) != 1 || bytes.Count(data, []byte("    metrics:\n")) != 1 {
			t.Fatalf("%s must share the exact normal/loopback/env-port reader policy", name)
		}
		path := filepath.Join(t.TempDir(), name)
		must(t, os.WriteFile(path, data, 0600))
		runCommand(t, bin, true, "validate", "--config", path)
	}

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
	invalid := strings.Replace(config, "refresh_interval: 30s", "refresh_interval: 29.999999999s", 1)
	invalidPath := filepath.Join(t.TempDir(), "consumer-below-minimum.yaml")
	must(t, os.WriteFile(invalidPath, []byte(invalid), 0600))
	runCommand(t, bin, false, "validate", "--config", invalidPath)
}

func reserveMetricsPort(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { listener.Close() })
	t.Setenv("NETFLOW_METRICS_PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	return listener
}

func assertMetricsPortReleased(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	must(t, err)
	must(t, listener.Close())
}

func assertOperatorQuiet(t *testing.T, output *net.UDPConn) {
	t.Helper()
	must(t, output.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	var packet [65535]byte
	n, _, err := output.ReadFromUDP(packet[:])
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("extra data (%d bytes) or read error: %v", n, err)
	}
}

// Walk the checked fixture's ordinary fixed-width template. This establishes
// the record width and protocolIdentifier offset independently of the encoder.
func mixedProtocolIPFIX(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) < 24 || binary.BigEndian.Uint16(golden[:2]) != 10 ||
		int(binary.BigEndian.Uint16(golden[2:4])) != len(golden) ||
		binary.BigEndian.Uint16(golden[16:18]) != 2 {
		t.Fatal("invalid general IPFIX fixture envelope")
	}
	end := 16 + int(binary.BigEndian.Uint16(golden[18:20]))
	fields := int(binary.BigEndian.Uint16(golden[22:24]))
	if end != 24+4*fields || end+4 > len(golden) ||
		!bytes.Equal(golden[20:22], golden[end:end+2]) {
		t.Fatal("general IPFIX fixture must have one ordinary template and its data Set")
	}
	width, protocol := 0, -1
	for offset := 24; offset < end; offset += 4 {
		id := binary.BigEndian.Uint16(golden[offset : offset+2])
		length := int(binary.BigEndian.Uint16(golden[offset+2 : offset+4]))
		if id&0x8000 != 0 || length == 0 || length == 65535 {
			t.Fatal("mixed fixture requires ordinary fixed-width fields")
		}
		if id == 4 {
			if protocol != -1 || length != 1 {
				t.Fatal("protocolIdentifier must occur once with width one")
			}
			protocol = width
		}
		width += length
	}
	if protocol < 0 || width != 72 || end != 104 ||
		int(binary.BigEndian.Uint16(golden[end+2:end+4])) != 4+width || len(golden) != end+4+width {
		t.Fatal("general IPv4 fixture must contain exactly one 72-byte record without padding")
	}
	record := golden[end+4:]
	if record[protocol] != 6 {
		t.Fatal("golden control must be TCP")
	}
	mixed := append(bytes.Clone(golden), record...)
	mixed[end+4+width+protocol] = 255 // pinned receiver getTransportName => unknown
	binary.BigEndian.PutUint16(mixed[2:4], uint16(len(mixed)))
	binary.BigEndian.PutUint16(mixed[end+2:end+4], uint16(4+2*width))
	t.Logf("mixed derivative: template fields=%d record width=%d protocol offset=%d; only second protocol byte and envelope lengths change", fields, width, protocol)
	return mixed
}

type operatorAccounting struct {
	confirmed, invalid, ambiguous, unsent, rejected, mapMiss, sent, failed, inFlight int64
	localFailures, internalFailures                                                  int64
}

func (a operatorAccounting) add(confirmed, invalid, rejected, sent int64) operatorAccounting {
	a.confirmed += confirmed
	a.invalid += invalid
	a.rejected += rejected
	a.mapMiss += rejected
	a.sent += sent
	return a
}

type operatorSample struct {
	name       string
	labels     map[string]string
	value      int64 // Counters and integer gauges remain integer-exact.
	floatValue *float64
}

type operatorScrape struct {
	raw                     []byte
	samples                 []operatorSample
	requestedAt, receivedAt time.Time // enclosing the real reader's collection
}

type operatorScraper struct {
	client *http.Client
	url    string
}

func newOperatorScraper(t *testing.T, address string) operatorScraper {
	t.Helper()
	// No proxy or pooled connection can redirect or outlive this loopback test.
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return operatorScraper{client: &http.Client{
		Timeout: time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, url: "http://" + address + "/metrics"}
}

func (s operatorScraper) poll(t *testing.T, phase, dir string, ready func(operatorScrape) bool) operatorScrape {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var last operatorScrape
	var lastErr error
	for ctx.Err() == nil {
		requestedAt := time.Now()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
		must(t, err)
		request.Header.Set("Accept", "text/plain; version=0.0.4")
		response, err := s.client.Do(request)
		lastErr = err
		if err == nil {
			const limit = 1 << 20
			data, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
			closeErr := response.Body.Close()
			must(t, readErr)
			must(t, closeErr)
			if response.StatusCode != http.StatusOK || len(data) > limit {
				t.Fatalf("metrics status=%d bytes=%d (limit %d)", response.StatusCode, len(data), limit)
			}
			// Retain the bounded response even if a semantic assertion fails.
			must(t, os.WriteFile(filepath.Join(dir, phase+".prom"), data, 0600))
			last = parseOperatorScrape(t, data)
			last.requestedAt, last.receivedAt = requestedAt, time.Now()
			if ready(last) {
				return last
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	must(t, os.WriteFile(filepath.Join(dir, phase+"-timeout.prom"), last.raw, 0600))
	t.Fatalf("metrics %s did not reach expected accounting in 10s: %v; selected samples=%+v", phase, lastErr, last.samples)
	return operatorScrape{}
}

var operatorSamplePattern = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? ([^ ]+)$`)
var operatorLabelPattern = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)=("(?:[^"\\]|\\.)*")(?:,|$)`)

// Parse only the selected exporter families; reject malformed or unexpected
// labels instead of allowing a substring match against an unrelated series.
// No new Prometheus parser dependency is needed for this bounded fixture.
func parseOperatorScrape(t *testing.T, data []byte) operatorScrape {
	t.Helper()
	scrape, err := decodeOperatorScrape(data)
	must(t, err)
	return scrape
}

func decodeOperatorScrape(data []byte) (operatorScrape, error) {
	scrape := operatorScrape{raw: data}
	types := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			fields := strings.Fields(line)
			if len(fields) == 4 {
				types[fields[2]] = fields[3]
			}
		}
		if !strings.HasPrefix(line, "otelcol_netflow_exporter_") &&
			!strings.HasPrefix(line, "otelcol_exporter_sent_log_records") &&
			!strings.HasPrefix(line, "otelcol_exporter_send_failed_log_records") &&
			!strings.HasPrefix(line, "otelcol_exporter_in_flight_requests") {
			continue
		}
		match := operatorSamplePattern.FindStringSubmatch(line)
		if match == nil {
			return operatorScrape{}, fmt.Errorf("malformed exporter sample: %q", line)
		}
		for _, canary := range []string{"192.0.2.1", "198.51.100.2", "2001:db8::1", "2001:db8::2"} {
			if strings.Contains(match[1]+match[2], canary) {
				return operatorScrape{}, fmt.Errorf("flow canary in metric name/attributes: %q", line)
			}
		}
		labels := map[string]string{}
		for remaining := match[2]; remaining != ""; {
			label := operatorLabelPattern.FindStringSubmatch(remaining)
			if label == nil {
				return operatorScrape{}, fmt.Errorf("malformed metric labels: %q", remaining)
			}
			if _, duplicate := labels[label[1]]; duplicate {
				return operatorScrape{}, fmt.Errorf("duplicate metric label: %s", label[1])
			}
			value, err := strconv.Unquote(label[2])
			if err != nil {
				return operatorScrape{}, fmt.Errorf("invalid metric label: %w", err)
			}
			if slices.Contains([]string{"12345", "56789", "tcp", "unknown"}, value) {
				return operatorScrape{}, fmt.Errorf("flow canary in metric attribute: %s=%s", label[1], value)
			}
			labels[label[1]] = value
			remaining = remaining[len(label[0]):]
			if remaining == "" && strings.HasSuffix(label[0], ",") {
				return operatorScrape{}, fmt.Errorf("trailing comma in metric labels")
			}
		}
		name := match[1]
		sample := operatorSample{name: name, labels: labels}
		expectedLabels, known := map[string][]string{
			"otelcol_netflow_exporter_admission":        {"exporter", "reason"},
			"otelcol_netflow_exporter_bytes":            {"exporter", "message_kind", "outcome"},
			"otelcol_netflow_exporter_data_messages":    {"exporter", "outcome"},
			"otelcol_netflow_exporter_dns":              {"exporter", "outcome"},
			"otelcol_netflow_exporter_endpoint_epochs":  {"exporter"},
			"otelcol_netflow_exporter_failures":         {"exporter", "reason"},
			"otelcol_netflow_exporter_losses":           {"exporter", "loss_class"},
			"otelcol_netflow_exporter_records":          {"exporter", "outcome"},
			"otelcol_netflow_exporter_rejected_records": {"exporter", "rejection_reason"},
			"otelcol_netflow_exporter_templates":        {"exporter", "message_kind", "outcome"},
			"otelcol_netflow_exporter_uptime_remaining": {"exporter"},
			"otelcol_netflow_exporter_uptime_exhausted": {"exporter"},
			"otelcol_exporter_sent_log_records":         {"exporter"},
			"otelcol_exporter_send_failed_log_records":  {"exporter"},
			"otelcol_exporter_in_flight_requests":       {"exporter", "data_type"},
		}[name]
		if !known || len(labels) != len(expectedLabels) {
			return operatorScrape{}, fmt.Errorf("unknown metric or unexpected labels: %s %v", name, labels)
		}
		for _, key := range expectedLabels {
			if labels[key] == "" {
				return operatorScrape{}, fmt.Errorf("metric %s missing nonempty %s label", name, key)
			}
		}
		if name == "otelcol_netflow_exporter_failures" &&
			!slices.Contains([]string{"busy", "closed", "unavailable", "internal", "candidate", "bootstrap", "refresh"}, labels["reason"]) {
			return operatorScrape{}, fmt.Errorf("unexpected local failure reason %q", labels["reason"])
		}
		wantType := "counter"
		lifetime := name == "otelcol_netflow_exporter_uptime_remaining" || name == "otelcol_netflow_exporter_uptime_exhausted"
		if name == "otelcol_exporter_in_flight_requests" || lifetime {
			wantType = "gauge"
		}
		if types[name] != wantType {
			return operatorScrape{}, fmt.Errorf("metric %s type=%q, want %s", name, types[name], wantType)
		}
		if name == "otelcol_netflow_exporter_uptime_remaining" {
			value, err := strconv.ParseFloat(match[3], 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				return operatorScrape{}, fmt.Errorf("invalid remaining lifetime: %q", match[3])
			}
			sample.floatValue = &value
		} else {
			value, err := strconv.ParseInt(match[3], 10, 64)
			if err != nil || value < 0 {
				return operatorScrape{}, fmt.Errorf("invalid integer exporter sample: %q", match[3])
			}
			if name == "otelcol_netflow_exporter_uptime_exhausted" && value > 1 {
				return operatorScrape{}, fmt.Errorf("exhausted lifetime is not binary: %d", value)
			}
			sample.value = value
		}
		scrape.samples = append(scrape.samples, sample)
	}
	return scrape, nil
}

func (s operatorScrape) accounting(t *testing.T, exporter string, requireCompleted bool) operatorAccounting {
	t.Helper()
	var a operatorAccounting
	seen := map[string]bool{}
	for _, sample := range s.samples {
		if sample.labels["exporter"] != exporter {
			continue
		}
		keys := []string{"exporter"}
		switch sample.name {
		case "otelcol_netflow_exporter_records":
			keys = append(keys, "outcome")
			outcome := sample.labels["outcome"]
			switch outcome {
			case "confirmed":
				a.confirmed += sample.value
			case "invalid":
				a.invalid += sample.value
			case "ambiguous":
				a.ambiguous += sample.value
			case "unsent":
				a.unsent += sample.value
			default:
				t.Fatalf("unexpected record outcome %q", outcome)
			}
		case "otelcol_netflow_exporter_rejected_records":
			keys = append(keys, "rejection_reason")
			a.rejected += sample.value
			if sample.labels["rejection_reason"] == "map_miss" {
				a.mapMiss += sample.value
			}
		case "otelcol_netflow_exporter_failures":
			keys = append(keys, "reason")
			a.localFailures += sample.value
			if sample.labels["reason"] == "internal" {
				a.internalFailures += sample.value
			}
		case "otelcol_exporter_sent_log_records":
			a.sent += sample.value
		case "otelcol_exporter_send_failed_log_records":
			a.failed += sample.value
		case "otelcol_exporter_in_flight_requests":
			keys = append(keys, "data_type")
			if sample.labels["data_type"] != "logs" {
				t.Fatalf("in-flight data_type=%q, want logs", sample.labels["data_type"])
			}
			a.inFlight += sample.value
		default:
			continue
		}
		if len(sample.labels) != len(keys) {
			t.Fatalf("%s label keys: %v, want %v", sample.name, sample.labels, keys)
		}
		for _, key := range keys {
			if sample.labels[key] == "" {
				t.Fatalf("%s missing nonempty %s label: %v", sample.name, key, sample.labels)
			}
		}
		// There must be only one series per trusted identity and semantic label.
		series := sample.name + "/" + sample.labels["outcome"] + "/" + sample.labels["rejection_reason"] + "/" + sample.labels["reason"]
		if seen[series] {
			t.Fatalf("duplicate exporter accounting series %s", series)
		}
		seen[series] = true
	}
	if requireCompleted && (!seen["otelcol_exporter_in_flight_requests///"] ||
		!seen["otelcol_exporter_sent_log_records///"] || !seen["otelcol_netflow_exporter_records/confirmed//"]) {
		a.inFlight = -1 // poll until the request and its first series are observable
	}
	// Never-used failed/rejected/outcome series are absent, hence zero. Completion
	// checks require local records, helper sent and the in-flight zero sample.
	return a
}

// These literal fixtures qualify the typed parser independently of the live
// Collector example; I6.3 supplies the separate real-scrape lifecycle evidence.
func TestOperatorLifetimeScrapeParsing(t *testing.T) {
	const fixture = `# TYPE otelcol_netflow_exporter_uptime_remaining gauge
	otelcol_netflow_exporter_uptime_remaining{exporter="netflow/live"} 0.001
# TYPE otelcol_netflow_exporter_uptime_exhausted gauge
	otelcol_netflow_exporter_uptime_exhausted{exporter="netflow/live"} 0
	otelcol_netflow_exporter_uptime_exhausted{exporter="netflow/expired"} 1
# TYPE otelcol_netflow_exporter_records counter
	otelcol_netflow_exporter_records{exporter="netflow/live",outcome="confirmed"} 9007199254740993
# TYPE otelcol_exporter_sent_log_records counter
	otelcol_exporter_sent_log_records{exporter="netflow/live"} 9007199254740993
# TYPE otelcol_exporter_in_flight_requests gauge
	otelcol_exporter_in_flight_requests{exporter="netflow/live",data_type="logs"} 0
`
	data := strings.ReplaceAll(fixture, "\t", "")
	scrape := parseOperatorScrape(t, []byte(data))
	if len(scrape.samples) != 6 || scrape.samples[0].floatValue == nil || *scrape.samples[0].floatValue != 0.001 ||
		scrape.samples[1].floatValue != nil || scrape.samples[1].value != 0 || scrape.samples[2].value != 1 {
		t.Fatalf("typed gauge parsing: %+v", scrape.samples)
	}
	a := scrape.accounting(t, "netflow/live", true)
	if a.confirmed != 9007199254740993 || a.sent != 9007199254740993 || a.inFlight != 0 {
		t.Fatalf("lost exact integer accounting above 2^53: %+v", a)
	}
	for _, value := range []string{"0", "1.25", "4.294967296e6"} {
		t.Run("remaining-"+value, func(t *testing.T) {
			if _, err := decodeOperatorScrape([]byte(strings.Replace(data, " 0.001", " "+value, 1))); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"uptime_remaining", "uptime_exhausted"} {
		for _, value := range []string{"NaN", "+Inf", "-Inf", "-1", "true", "1e999"} {
			t.Run(name+"/invalid-"+value, func(t *testing.T) {
				literal := "# TYPE otelcol_netflow_exporter_" + name + " gauge\notelcol_netflow_exporter_" + name + "{exporter=\"netflow/live\"} " + value + "\n"
				if _, err := decodeOperatorScrape([]byte(literal)); err == nil {
					t.Fatalf("accepted invalid %s value %q", name, value)
				}
			})
		}
		for _, labels := range []string{"", `{}`, `{exporter=""}`, `{reason="accepted"}`, `{exporter="netflow/live",reason="accepted"}`, `{exporter="netflow/live",exporter="duplicate"}`, `{exporter=bad}`, `{exporter="netflow/live",}`, `{exporter="192.0.2.1"}`, `{exporter="tcp"}`} {
			t.Run(name+"/attributes-"+labels, func(t *testing.T) {
				literal := "# TYPE otelcol_netflow_exporter_" + name + " gauge\notelcol_netflow_exporter_" + name + labels + " 0\n"
				if _, err := decodeOperatorScrape([]byte(literal)); err == nil {
					t.Fatalf("accepted invalid labels %q", labels)
				}
			})
		}
		for _, typ := range []string{"counter", "histogram", "untyped", ""} {
			t.Run(name+"/type-"+typ, func(t *testing.T) {
				literal := "# TYPE otelcol_netflow_exporter_" + name + " " + typ + "\notelcol_netflow_exporter_" + name + "{exporter=\"netflow/live\"} 0\n"
				if _, err := decodeOperatorScrape([]byte(literal)); err == nil {
					t.Fatalf("accepted wrong gauge TYPE %q", typ)
				}
			})
		}
	}
	for _, value := range []string{"2", "0.5", "1.0", "1e0"} {
		t.Run("exhausted-nonbinary-"+value, func(t *testing.T) {
			literal := "# TYPE otelcol_netflow_exporter_uptime_exhausted gauge\notelcol_netflow_exporter_uptime_exhausted{exporter=\"netflow/live\"} " + value + "\n"
			if _, err := decodeOperatorScrape([]byte(literal)); err == nil {
				t.Fatalf("accepted nonbinary/noninteger exhaustion %q", value)
			}
		})
	}
	for _, broken := range []string{
		strings.Replace(data, "otelcol_netflow_exporter_records counter", "otelcol_netflow_exporter_records gauge", 1),
		strings.Replace(data, "9007199254740993", "9007199254740993.0", 1),
		strings.Replace(data, "9007199254740993", "-1", 1),
		strings.ReplaceAll(data, "uptime_remaining", "unknown"),
	} {
		if _, err := decodeOperatorScrape([]byte(broken)); err == nil {
			t.Fatal("accepted malformed counter or unknown instrument")
		}
	}
}
