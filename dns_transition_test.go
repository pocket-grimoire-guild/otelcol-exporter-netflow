package netflowexporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const dnsTransitionHost = "collector.example"

type dnsTransitionFixture struct {
	exporter     *logsExporter
	runtime      *destination.Runtime
	clock        *testclock.Clock
	lookup       *testtransport.Resolver
	dnsTimer     *testclock.Timer
	refreshTimer *testclock.Timer
	reader       *sdkmetric.ManualReader
	provider     *sdkmetric.MeterProvider
	events       *dnsTransitionEvents
}

type dnsTransitionEvents struct {
	mu      sync.Mutex
	counts  map[destination.Event]int
	changed chan struct{}
}

func newDNSTransitionEvents() *dnsTransitionEvents {
	return &dnsTransitionEvents{counts: make(map[destination.Event]int), changed: make(chan struct{})}
}

func (e *dnsTransitionEvents) observe(event destination.Event) {
	e.mu.Lock()
	e.counts[event]++
	close(e.changed)
	e.changed = make(chan struct{})
	e.mu.Unlock()
}

func (e *dnsTransitionEvents) count(event destination.Event) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.counts[event]
}

func (e *dnsTransitionEvents) wait(t *testing.T, event destination.Event, want int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		e.mu.Lock()
		if e.counts[event] >= want {
			e.mu.Unlock()
			return
		}
		changed := e.changed
		e.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("event %d count=%d, want %d", event, e.count(event), want)
		}
	}
}

func dnsTransitionFixtureFor(t *testing.T, protocol string, port int, lookup *testtransport.Resolver) *dnsTransitionFixture {
	return dnsTransitionFixtureForName(t, protocol, port, lookup, "dns-transition-"+protocol)
}

func dnsTransitionFixtureForName(t *testing.T, protocol string, port int, lookup *testtransport.Resolver, name string) *dnsTransitionFixture {
	return dnsTransitionFixtureForNameWithDNS(t, protocol, port, lookup, name, time.Second, 5*time.Second)
}

func dnsTransitionFixtureForNameWithDNS(t *testing.T, protocol string, port int, lookup *testtransport.Resolver, name string, dnsRefresh, dnsStaleAfter time.Duration) *dnsTransitionFixture {
	t.Helper()
	c := validConfig(protocol)
	c.Endpoint = net.JoinHostPort(dnsTransitionHost, fmt.Sprint(port))
	c.DNS.RefreshInterval = dnsRefresh
	c.DNS.StaleAfter = dnsStaleAfter
	c.DNS.Timeout = time.Second
	c.Templates.RefreshInterval = 30 * time.Second
	p := conditionalProtocol(protocol)
	profile := *c.Mapping.Profile
	mappingConfig := mapping.Config{
		Schema: c.Schema, Protocol: p, Profile: profile,
		ProtocolIdentifiers: c.Mapping.ProtocolIdentifiers,
		NetworkTypeVersions: c.Mapping.NetworkTypeVersions,
		InputGuarantees:     c.Mapping.InputGuarantees,
		LossPolicy:          *c.Mapping.LossPolicy, IDBase: c.Templates.IDBase,
		MaxDatagramSize: c.MaxDatagramSize, Endpoint: c.Endpoint,
	}
	if p == wire.ProtocolV5 {
		mappingConfig.IDBase = 0
	}
	if c.UptimeOrigin != nil {
		mappingConfig.HasUptimeOrigin = true
		mappingConfig.UptimeOriginUnixNanos = *c.UptimeOrigin
	}
	compiled, err := mapping.Compile(mappingConfig)
	if err != nil {
		t.Fatal(err)
	}
	var writer wire.ContractWriter
	switch p {
	case wire.ProtocolV5:
		writer = netflow5.NewWriter()
	case wire.ProtocolV9:
		writer = netflow9.NewWriter()
	case wire.ProtocolIPFIX:
		writer = ipfix.NewWriter()
	}
	state := destination.DefaultConfig(p)
	state.MaxDatagramSize = c.MaxDatagramSize
	state.InitialCopies = c.Templates.InitialCopies
	state.RefreshInterval = c.Templates.RefreshInterval
	state.V9RefreshPacketCount = 1000
	state.IPFIXDataMessageRefreshCount = 1000
	switch p {
	case wire.ProtocolV5:
		state.EngineType = *c.Identity.EngineType
		state.EngineID = *c.Identity.EngineID
		state.HasUptimeOrigin = true
		state.UptimeOriginUnixNanos = *c.UptimeOrigin
	case wire.ProtocolV9:
		state.SourceID = *c.Identity.SourceID
	case wire.ProtocolIPFIX:
		state.ObservationDomainID = *c.Identity.ObservationDomainID
	}
	resolver, err := transport.NewResolverWithLookup("udp", dnsTransitionHost, c.DNS.Timeout, lookup)
	if err != nil {
		t.Fatal(err)
	}
	dialer := transport.NewDialer("udp", netip.AddrPort{})
	candidateDialer, err := transport.NewCandidateDialer(resolver, uint16(port), c.MaxDatagramSize, compiled.MaxDatagramSize(), 0, dialer.Dial, c.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1788220802000000000, 0)
	var runtimeClock transport.Clock = clock
	if p != wire.ProtocolIPFIX {
		runtimeClock = millisecondClock{clock: clock, origin: state.UptimeOriginUnixNanos, checkUptime: state.HasUptimeOrigin}
	}
	events := newDNSTransitionEvents()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), name)
	set.Logger = zap.NewNop()
	set.MeterProvider = provider
	set.TracerProvider = trace.NewNoopTracerProvider()
	builder, err := metadata.NewTelemetryBuilder(set.TelemetrySettings)
	if err != nil {
		t.Fatal(err)
	}
	tel := telemetry{builder: builder, instance: attribute.String("exporter", set.ID.String())}
	observe := func(ctx context.Context, event destination.Event, bytes uint64) {
		tel.observe(ctx, event, bytes)
		events.observe(event)
	}
	fixture := &dnsTransitionFixture{clock: clock, lookup: lookup, reader: reader, provider: provider, events: events}
	config := destination.RuntimeConfig{State: state, DNSRefresh: c.DNS.RefreshInterval, DNSStaleAfter: c.DNS.StaleAfter, Observe: observe}
	config.NewTimer = func(time.Duration) transport.Timer {
		timer := testclock.NewTimer()
		if fixture.dnsTimer == nil {
			fixture.dnsTimer = timer
		} else if fixture.refreshTimer == nil {
			fixture.refreshTimer = timer
		}
		return timer
	}
	fixture.runtime, err = destination.NewRuntime(compiled, writer, config, candidateDialer, runtimeClock)
	if err != nil {
		t.Fatal(err)
	}
	e := &logsExporter{runtime: fixture.runtime, telemetry: tel}
	helper, err := exporterhelper.NewLogs(context.Background(), set, c, e.pushLogs,
		exporterhelper.WithStart(func(ctx context.Context, _ component.Host) error { return fixture.runtime.Start(ctx) }),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithTimeout(exporterhelper.TimeoutConfig{Timeout: 0}),
	)
	if err != nil {
		t.Fatal(err)
	}
	e.helper = helper
	fixture.exporter = e
	t.Cleanup(func() {
		_ = e.Shutdown(context.Background())
		_ = provider.Shutdown(context.Background())
	})
	return fixture
}

type dnsTransitionDatagram struct {
	payload     []byte
	peer        *net.UDPAddr
	destination netip.Addr
	at          time.Time
}

func readDNSTransitionDatagram(t *testing.T, conn *net.UDPConn) dnsTransitionDatagram {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65507)
	n, peer, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if peer == nil || !peer.IP.IsLoopback() || peer.Port == 0 {
		t.Fatalf("unexpected UDP peer %v", peer)
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil || local.IP.To4() == nil {
		t.Fatalf("unexpected UDP listener address %v", conn.LocalAddr())
	}
	var destinationBytes [4]byte
	copy(destinationBytes[:], local.IP.To4())
	return dnsTransitionDatagram{payload: append([]byte(nil), buffer[:n]...), peer: peer, destination: netip.AddrFrom4(destinationBytes), at: time.Now()}
}

func readDNSTransitionDatagrams(t *testing.T, conn *net.UDPConn, count int) []dnsTransitionDatagram {
	t.Helper()
	packets := make([]dnsTransitionDatagram, 0, count)
	for range count {
		packets = append(packets, readDNSTransitionDatagram(t, conn))
	}
	return packets
}

func assertNoDNSTransitionReceipt(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65507)
	if n, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatalf("unexpected %d-byte UDP receipt", n)
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("unexpected no-receipt error: %v", err)
	}
}

func transitionBootstrapCount(protocol string) int {
	if protocol == "netflow_v5" {
		return 0
	}
	return 4
}

func assertTransitionBootstrap(t *testing.T, protocol string, packets []dnsTransitionDatagram) {
	t.Helper()
	want := transitionBootstrapCount(protocol)
	if len(packets) != want {
		t.Fatalf("bootstrap packets=%d, want %d", len(packets), want)
	}
	for index, packet := range packets {
		if len(packet.payload) < 24 {
			t.Fatalf("bootstrap packet %d too short: %d", index, len(packet.payload))
		}
		version := binary.BigEndian.Uint16(packet.payload)
		if (protocol == "netflow_v9" && version != 9) || (protocol == "ipfix" && version != 10) {
			t.Fatalf("bootstrap packet %d version=%d", index, version)
		}
		if protocol == "netflow_v9" && binary.BigEndian.Uint16(packet.payload[20:]) != 0 {
			t.Fatalf("v9 bootstrap packet %d set id=%d, want template set", index, binary.BigEndian.Uint16(packet.payload[20:]))
		}
		if protocol == "ipfix" && binary.BigEndian.Uint16(packet.payload[16:]) != 2 {
			t.Fatalf("IPFIX bootstrap packet %d set id=%d, want template set", index, binary.BigEndian.Uint16(packet.payload[16:]))
		}
	}
}

func assertTransitionData(t *testing.T, protocol string, packet dnsTransitionDatagram, records int) {
	t.Helper()
	if len(packet.payload) < 24 {
		t.Fatalf("data packet too short: %d", len(packet.payload))
	}
	wantVersion := uint16(5)
	switch protocol {
	case "netflow_v9":
		wantVersion = 9
	case "ipfix":
		wantVersion = 10
	}
	if binary.BigEndian.Uint16(packet.payload) != wantVersion {
		t.Fatalf("data version=%d, want %d", binary.BigEndian.Uint16(packet.payload), wantVersion)
	}
	switch protocol {
	case "netflow_v5", "netflow_v9":
		if got := int(binary.BigEndian.Uint16(packet.payload[2:])); got != records {
			t.Fatalf("%s data records=%d, want %d", protocol, got, records)
		}
	case "ipfix":
		if binary.BigEndian.Uint16(packet.payload[16:]) < 256 {
			t.Fatalf("IPFIX data set id=%d, want data set", binary.BigEndian.Uint16(packet.payload[16:]))
		}
	}
}

func writeDNSTransitionPCAP(path string, packets []dnsTransitionDatagram, port int) error {
	if len(packets) == 0 || len(packets) > 64 {
		return fmt.Errorf("invalid transition packet count %d", len(packets))
	}
	var output bytes.Buffer
	var global [24]byte
	binary.LittleEndian.PutUint32(global[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:], 2)
	binary.LittleEndian.PutUint16(global[6:], 4)
	binary.LittleEndian.PutUint32(global[16:], 65535)
	binary.LittleEndian.PutUint32(global[20:], 101) // DLT_RAW: synthetic IPv4 envelope.
	output.Write(global[:])
	for _, packet := range packets {
		frame, err := transitionIPv4UDPFrame(packet, port)
		if err != nil {
			return err
		}
		if len(frame) > 65535 {
			return fmt.Errorf("transition frame exceeds pcap limit: %d", len(frame))
		}
		stamp := packet.at
		if stamp.IsZero() {
			stamp = time.Unix(1788220802, 0)
		}
		var header [16]byte
		binary.LittleEndian.PutUint32(header[0:], uint32(stamp.Unix()))
		binary.LittleEndian.PutUint32(header[4:], uint32(stamp.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(frame)))
		output.Write(header[:])
		output.Write(frame)
	}
	return os.WriteFile(path, output.Bytes(), 0o600)
}

func transitionIPv4UDPFrame(packet dnsTransitionDatagram, port int) ([]byte, error) {
	if packet.peer == nil || packet.peer.IP.To4() == nil || !packet.destination.Is4() || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid transition frame identity")
	}
	source := packet.peer.IP.To4()
	destination := packet.destination.As4()
	if len(packet.payload) > 65507 {
		return nil, fmt.Errorf("transition payload exceeds UDP limit: %d", len(packet.payload))
	}
	frame := make([]byte, 20+8+len(packet.payload))
	frame[0], frame[1] = 0x45, 0
	binary.BigEndian.PutUint16(frame[2:], uint16(len(frame)))
	frame[8], frame[9] = 64, 17
	copy(frame[12:16], source)
	copy(frame[16:20], destination[:])
	binary.BigEndian.PutUint16(frame[10:], ipv4HeaderChecksum(frame[:20]))
	udp := frame[20:]
	binary.BigEndian.PutUint16(udp[0:], uint16(packet.peer.Port))
	binary.BigEndian.PutUint16(udp[2:], uint16(port))
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	// A zero IPv4 UDP checksum is legal and avoids making the synthetic frame
	// a second protocol implementation; TShark still validates cflow payloads.
	copy(udp[8:], packet.payload)
	return frame, nil
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func transitionArtifactDir(t *testing.T, protocol string) string {
	t.Helper()
	root := os.Getenv("NETFLOW_DNS_ARTIFACTS")
	if root == "" {
		root = t.TempDir()
	} else if !filepath.IsAbs(root) {
		t.Fatalf("NETFLOW_DNS_ARTIFACTS must be absolute: %q", root)
	}
	dir, err := os.MkdirTemp(root, "dns-transition-"+protocol+"-")
	if err != nil {
		t.Fatalf("create DNS artifact directory: %v", err)
	}
	return dir
}

func runDNSTransitionTShark(t *testing.T, protocol, endpoint string, port int, packets []dnsTransitionDatagram, wantPorts [][]int) string {
	t.Helper()
	if os.Getenv("NETFLOW_DNS_TSHARK") != "1" {
		return ""
	}
	dir := transitionArtifactDir(t, protocol)
	pcapPath := filepath.Join(dir, protocol+"-dns-transition-"+endpoint+".pcap")
	if err := writeDNSTransitionPCAP(pcapPath, packets, port); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("TSHARK_BIN")
	if bin == "" {
		bin = "tshark"
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		t.Fatalf("NETFLOW_DNS_TSHARK=1 requires TShark 4.4.18: %v", err)
	}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), time.Second)
	var versionBuffer, versionStderr transitionOutputBuffer
	versionCommand := exec.CommandContext(versionCtx, resolved, "--version")
	versionCommand.Stdout = &versionBuffer
	versionCommand.Stderr = &versionStderr
	versionErr := versionCommand.Run()
	versionOutput := versionBuffer.Bytes()
	versionCancel()
	if versionErr != nil || versionBuffer.overflow || versionStderr.overflow || !strings.Contains(string(versionOutput), "4.4.18") {
		t.Fatalf("TShark version=%q, want 4.4.18", strings.TrimSpace(string(versionOutput)))
	}
	info, err := os.Stat(resolved)
	if err != nil || info.Size() > 64<<20 {
		t.Fatalf("TShark executable is unavailable or exceeds the 64 MiB hash bound: %v", err)
	}
	executable, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	executableHash := sha256.Sum256(executable)
	pcap, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	pcapHash := sha256.Sum256(pcap)
	manifest := fmt.Sprintf("protocol=%s\nendpoint=%s\nframes=%d\nunique_source_ports=%d\ntshark=%s\ntshark_version_sha256=%x\ntshark_executable_sha256=%x\npcap_sha256=%x\n", protocol, endpoint, len(packets), countTransitionPorts(wantPorts), resolved, sha256.Sum256(versionOutput), executableHash, pcapHash)
	if err := os.WriteFile(filepath.Join(dir, "evidence.txt"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	decodeCtx, decodeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer decodeCancel()
	command := exec.CommandContext(decodeCtx, resolved, "-r", pcapPath,
		"-d", fmt.Sprintf("udp.port==%d,cflow", port), "-T", "fields",
		"-E", "separator=|", "-E", "occurrence=a",
		"-e", "frame.number", "-e", "cflow.version", "-e", "cflow.flowset_id", "-e", "cflow.srcport")
	var decodedBuffer, stderrBuffer transitionOutputBuffer
	command.Stdout = &decodedBuffer
	command.Stderr = &stderrBuffer
	err = command.Run()
	decoded := decodedBuffer.Bytes()
	if err != nil {
		t.Fatalf("TShark decode failed: %v\nstdout=%s\nstderr=%s", err, boundedTransitionOutput(decoded), boundedTransitionOutput(stderrBuffer.Bytes()))
	}
	if decodeCtx.Err() != nil {
		t.Fatalf("TShark decode timed out: %v", decodeCtx.Err())
	}
	if decodedBuffer.overflow || stderrBuffer.overflow {
		t.Fatalf("TShark output exceeded bounded capture: stdout_overflow=%v stderr_overflow=%v", decodedBuffer.overflow, stderrBuffer.overflow)
	}
	outputPath := filepath.Join(dir, protocol+"-tshark-fields-"+endpoint+".txt")
	if err := os.WriteFile(outputPath, decoded, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	if len(lines) != len(packets) {
		t.Fatalf("TShark frames=%d, want %d; output=%s", len(lines), len(packets), outputPath)
	}
	wantVersion := map[string]string{"netflow_v5": "5", "netflow_v9": "9", "ipfix": "10"}[protocol]
	portCounts := make(map[int]int)
	dataFrame := 0
	for index, line := range lines {
		fields := strings.Split(line, "|")
		if len(fields) < 4 || fields[1] != wantVersion {
			t.Fatalf("TShark row=%q, want cflow version %s", line, wantVersion)
		}
		frameNumber, err := strconv.Atoi(fields[0])
		if err != nil || frameNumber != index+1 {
			t.Fatalf("TShark frame number=%q at row %d, want %d", fields[0], index, index+1)
		}
		setIDs := strings.FieldsFunc(fields[2], func(r rune) bool { return r == ',' || r == ';' })
		if fields[3] == "" {
			if protocol == "netflow_v5" {
				t.Fatalf("v5 row %d unexpectedly has no decoded source ports", index+1)
			}
			wantSet := "0"
			if protocol == "ipfix" {
				wantSet = "2"
			}
			if len(setIDs) != 1 || setIDs[0] != wantSet {
				t.Fatalf("template row %d flowset ids=%q, want %s", index+1, fields[2], wantSet)
			}
			continue
		}
		if dataFrame >= len(wantPorts) {
			t.Fatalf("extra decoded data frame at row %d", index+1)
		}
		if protocol == "netflow_v5" {
			if len(setIDs) != 0 {
				t.Fatalf("v5 data row %d unexpectedly has flowset ids=%q", index+1, fields[2])
			}
		} else {
			if len(setIDs) != 1 {
				t.Fatalf("data row %d flowset ids=%q, want one data set", index+1, fields[2])
			}
			setID, err := strconv.Atoi(setIDs[0])
			if err != nil || setID < 256 {
				t.Fatalf("data row %d flowset id=%q, want >=256", index+1, fields[2])
			}
		}
		values := strings.FieldsFunc(fields[3], func(r rune) bool { return r == ',' || r == ';' })
		if len(values) != len(wantPorts[dataFrame]) {
			t.Fatalf("data row %d decoded source ports=%q, want %v", index+1, fields[3], wantPorts[dataFrame])
		}
		wantSet := make(map[int]bool, len(wantPorts[dataFrame]))
		for _, want := range wantPorts[dataFrame] {
			wantSet[want] = true
		}
		for _, value := range values {
			portNumber, err := strconv.Atoi(value)
			if err != nil || !wantSet[portNumber] || portCounts[portNumber] != 0 {
				t.Fatalf("data row %d decoded unknown/duplicate source port=%q", index+1, value)
			}
			portCounts[portNumber]++
		}
		dataFrame++
	}
	if dataFrame != len(wantPorts) {
		t.Fatalf("TShark data frames=%d, want %d; output=%s", dataFrame, len(wantPorts), outputPath)
	}
	for _, group := range wantPorts {
		for _, portNumber := range group {
			if portCounts[portNumber] != 1 {
				t.Fatalf("TShark source port %d count=%d, want one; output=%s", portNumber, portCounts[portNumber], outputPath)
			}
		}
	}
	t.Logf("independent TShark 4.4.18 decode endpoint=%s frames=%d unique_records=%d artifact=%s", endpoint, len(lines), countTransitionPorts(wantPorts), dir)
	return dir
}

type transitionOutputBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *transitionOutputBuffer) Write(data []byte) (int, error) {
	const outputLimit = 64 * 1024
	if b.Len()+len(data) > outputLimit {
		remaining := outputLimit - b.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(data[:remaining])
		}
		b.overflow = true
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

func countTransitionPorts(groups [][]int) int {
	count := 0
	for _, group := range groups {
		count += len(group)
	}
	return count
}

func boundedTransitionOutput(output []byte) string {
	const max = 4096
	if len(output) > max {
		output = output[:max]
	}
	return string(output)
}

func transitionLogs(t *testing.T, startPort int64) (logs plog.Logs) {
	t.Helper()
	logs = plog.NewLogs()
	baseLogs := testpdata.CanonicalLogs()
	source := baseLogs.ResourceLogs().At(0)
	resource := logs.ResourceLogs().AppendEmpty()
	source.Resource().CopyTo(resource.Resource())
	resource.SetSchemaUrl(source.SchemaUrl())
	scopeSource := source.ScopeLogs().At(0)
	scope := resource.ScopeLogs().AppendEmpty()
	scopeSource.Scope().CopyTo(scope.Scope())
	scope.SetSchemaUrl(scopeSource.SchemaUrl())
	baseRecord := scopeSource.LogRecords().At(0)
	for i := int64(0); i < 3; i++ {
		record := scope.LogRecords().AppendEmpty()
		baseRecord.CopyTo(record)
		record.Attributes().PutInt("source.port", startPort+i)
	}
	logs.MarkReadOnly()
	return logs
}

func TestDNSResolutionTransitionRealUDP(t *testing.T) {
	// This is a direct pushLogs qualification supplement, with no OTLP call.
	// The caller offers three records per request; local handoff and independent
	// UDP receipt remain separate evidence boundaries.
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			listenerA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listenerA.Close()
			port := listenerA.LocalAddr().(*net.UDPAddr).Port
			listenerB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			defer listenerB.Close()
			addrA := netip.MustParseAddr("127.0.0.1")
			addrB := netip.MustParseAddr("127.0.0.2")
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{addrA}},
				testtransport.ResolverStep{Err: errors.New("scripted DNS outage")},
				testtransport.ResolverStep{Answers: []netip.Addr{addrB}},
			)
			fixture := dnsTransitionFixtureFor(t, protocol, port, lookup)
			if err := fixture.exporter.Start(ctx, componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			fixture.events.wait(t, destination.DNSSucceeded, 1)
			fixture.events.wait(t, destination.EpochPublished, 1)
			waitDNSTransitionTimer(t, fixture.dnsTimer, 1)
			startup := readDNSTransitionDatagrams(t, listenerA, transitionBootstrapCount(protocol))
			assertTransitionBootstrap(t, protocol, startup)
			assertNoDNSTransitionReceipt(t, listenerB)

			if err := fixture.exporter.pushLogs(ctx, transitionLogs(t, 10001)); err != nil {
				t.Fatalf("startup pushLogs: %v", err)
			}
			startupData := readDNSTransitionDatagram(t, listenerA)
			assertTransitionData(t, protocol, startupData, 3)

			fixture.clock.Advance(0, uint64(time.Second))
			if !fixture.dnsTimer.Fire() {
				t.Fatal("DNS timer was not armed for failed refresh")
			}
			fixture.events.wait(t, destination.DNSFailed, 1)
			if fixture.events.count(destination.EpochPublished) != 1 {
				t.Fatalf("failed DNS refresh published epoch=%d, want 1", fixture.events.count(destination.EpochPublished))
			}
			if err := fixture.exporter.pushLogs(ctx, transitionLogs(t, 10004)); err != nil {
				t.Fatalf("retained endpoint pushLogs: %v", err)
			}
			retainedData := readDNSTransitionDatagram(t, listenerA)
			assertTransitionData(t, protocol, retainedData, 3)

			waitDNSTransitionTimer(t, fixture.dnsTimer, 2)
			fixture.clock.Advance(0, uint64(time.Second))
			if !fixture.dnsTimer.Fire() {
				t.Fatal("DNS timer was not armed for changed refresh")
			}
			fixture.events.wait(t, destination.DNSSucceeded, 2)
			fixture.events.wait(t, destination.EpochPublished, 2)
			waitDNSTransitionTimer(t, fixture.dnsTimer, 3)
			changed := readDNSTransitionDatagrams(t, listenerB, transitionBootstrapCount(protocol))
			assertTransitionBootstrap(t, protocol, changed)
			assertNoDNSTransitionReceipt(t, listenerA)
			if err := fixture.exporter.pushLogs(ctx, transitionLogs(t, 10007)); err != nil {
				t.Fatalf("changed endpoint pushLogs: %v", err)
			}
			changedData := readDNSTransitionDatagram(t, listenerB)
			assertTransitionData(t, protocol, changedData, 3)
			assertDNSTransitionResolverTrace(t, fixture.lookup)
			aCapture := append(append([]dnsTransitionDatagram{}, startup...), startupData, retainedData)
			bCapture := append(append([]dnsTransitionDatagram{}, changed...), changedData)
			dirA := runDNSTransitionTShark(t, protocol, "a", port, aCapture, [][]int{{10001, 10002, 10003}, {10004, 10005, 10006}})
			dirB := runDNSTransitionTShark(t, protocol, "b", port, bCapture, [][]int{{10007, 10008, 10009}})

			snapshot := assertDNSMetrics(t, fixture, protocol)
			if dirA != "" {
				writeConditionalSnapshot(t, filepath.Join(dirA, "telemetry-snapshot.json"), snapshot)
				writeConditionalSnapshot(t, filepath.Join(dirB, "telemetry-snapshot.json"), snapshot)
			} else {
				t.Log("independent TShark decoding is opt-in; local UDP receipt and direct pushLogs accounting passed")
			}
			if err := fixture.exporter.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertDNSTransitionTimerStopped(t, fixture.dnsTimer)
			if fixture.refreshTimer != nil {
				assertDNSTransitionTimerStopped(t, fixture.refreshTimer)
			}
			assertNoDNSTransitionReceipt(t, listenerA)
			assertNoDNSTransitionReceipt(t, listenerB)
		})
	}
}

func assertDNSTransitionResolverTrace(t *testing.T, lookup *testtransport.Resolver) {
	t.Helper()
	events := lookup.Events()
	if len(events) != 3 {
		t.Fatalf("resolver events=%d, want startup success, refresh failure, and changed-answer success", len(events))
	}
	if events[0].AnswerCount != 1 || events[0].HadError || events[1].AnswerCount != 0 || !events[1].HadError || events[2].AnswerCount != 1 || events[2].HadError {
		t.Fatalf("resolver trace=%+v, want answer/error/answer", events)
	}
}

func assertDNSTransitionTimerStopped(t *testing.T, timer *testclock.Timer) {
	t.Helper()
	if timer == nil {
		t.Fatal("maintenance timer is nil")
	}
	_, stopped, _ := timer.Snapshot()
	if !stopped || timer.Fire() {
		t.Fatal("maintenance timer remained active after shutdown")
	}
}

func waitDNSTransitionTimer(t *testing.T, timer *testclock.Timer, resets int) {
	t.Helper()
	if timer == nil {
		t.Fatal("DNS timer was not created")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		delays, _, changed := timer.Snapshot()
		if len(delays) >= resets {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("DNS timer resets=%d, want %d", len(delays), resets)
		}
	}
}

func assertDNSMetrics(t *testing.T, fixture *dnsTransitionFixture, protocol string) conditionalSnapshot {
	t.Helper()
	var metrics metricdata.ResourceMetrics
	if err := fixture.reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatal(err)
	}
	values := conditionalMetricValues(conditionalSnapshotFromMetrics(&metrics))
	exporter := "exporter=netflow/dns-transition-" + protocol
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|"+exporter+"|outcome=succeeded", 2)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|"+exporter+"|outcome=failed", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.endpoint_epochs|"+exporter, 2)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.records|"+exporter+"|outcome=confirmed", 9)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.data_messages|"+exporter+"|outcome=confirmed", 3)
	for _, outcome := range []string{"ambiguous", "unsent", "invalid"} {
		if got := values["otelcol_netflow.exporter.records|"+exporter+"|outcome="+outcome]; got != 0 {
			t.Fatalf("records outcome=%s count=%d, want 0", outcome, got)
		}
	}
	wantTemplates := int64(0)
	if protocol != "netflow_v5" {
		wantTemplates = 8
	}
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|"+exporter+"|message_kind=bootstrap|outcome=confirmed", wantTemplates)
	snapshot := conditionalSnapshotFromMetrics(&metrics)
	snapshot.Source = "TestDNSResolutionTransitionRealUDP"
	return snapshot
}
