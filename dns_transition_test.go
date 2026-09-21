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
	"slices"
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
	templateCopies := make(map[uint16]int)
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
		offset := 24 // v9 header and template-set header.
		if protocol == "ipfix" {
			offset = 20
		}
		if len(packet.payload) < offset+2 {
			t.Fatalf("bootstrap packet %d lacks template ID", index)
		}
		templateCopies[binary.BigEndian.Uint16(packet.payload[offset:])]++
	}
	if protocol != "netflow_v5" && (len(templateCopies) != 2 || templateCopies[256] != 2 || templateCopies[257] != 2) {
		t.Fatalf("bootstrap template copies=%v, want two each of IDs 256 and 257", templateCopies)
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
	if len(packets) == 0 || len(packets) > 16 {
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
		if output.Len() > 64<<10 {
			return fmt.Errorf("transition capture exceeds 64 KiB")
		}
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
	t.Cleanup(func() {
		var total int64
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
			if total > 16<<20 {
				return fmt.Errorf("transition artifacts exceed 16 MiB at %s", path)
			}
			return nil
		})
		if err != nil {
			t.Errorf("transition artifact budget: %v", err)
		}
	})
	return dir
}

// Header expectations are literal fixture contracts, independent of packet bytes,
// exporter state and the writer. The identity order is the applicable field order
// below: v5 engine type/ID, v9 Source ID, or IPFIX Observation Domain ID.
type transitionHeaderExpectation struct {
	sequence []uint32
	identity []uint32
}

type transitionHeaderMutation struct {
	name, field string
	values      []uint32 // One value applies to every frame; otherwise one per frame.
}

type transitionHeaderCase struct {
	want    transitionHeaderExpectation
	mutants []transitionHeaderMutation
}

type transitionScalarField struct {
	name string
	bits int
}

func transitionHeaderFields(protocol string) []transitionScalarField {
	fields := []transitionScalarField{{"cflow.sequence", 32}}
	switch protocol {
	case "netflow_v5":
		return append(fields, transitionScalarField{"cflow.engine_type", 8}, transitionScalarField{"cflow.engine_id", 8})
	case "netflow_v9":
		return append(fields, transitionScalarField{"cflow.source_id", 32})
	case "ipfix":
		return append(fields, transitionScalarField{"cflow.od_id", 32})
	default:
		panic("unknown transition protocol: " + protocol)
	}
}

func dnsTransitionHeaderCase(protocol, endpoint string) transitionHeaderCase {
	switch protocol + "/" + endpoint {
	case "netflow_v5/a":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0, 3}, []uint32{0, 0}}, []transitionHeaderMutation{
			{"packet-count", "cflow.sequence", []uint32{0, 1}},
			{"engine-type", "cflow.engine_type", []uint32{1}},
			{"engine-id", "cflow.engine_id", []uint32{1}},
		}}
	case "netflow_v5/b":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0}, []uint32{0, 0}}, []transitionHeaderMutation{
			{"false-continuation", "cflow.sequence", []uint32{6}},
		}}
	case "netflow_v9/a":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0, 1, 2, 3, 4, 5}, []uint32{0}}, []transitionHeaderMutation{
			{"omitted-bootstrap-charge", "cflow.sequence", []uint32{0, 0, 0, 0, 0, 1}},
			{"source-id", "cflow.source_id", []uint32{1}},
		}}
	case "netflow_v9/b":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0, 1, 2, 3, 4}, []uint32{0}}, []transitionHeaderMutation{
			{"false-continuation", "cflow.sequence", []uint32{6, 7, 8, 9, 10}},
		}}
	case "ipfix/a":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0, 0, 0, 0, 0, 3}, []uint32{0}}, []transitionHeaderMutation{
			{"packet-count", "cflow.sequence", []uint32{0, 0, 0, 0, 0, 1}},
			{"spurious-bootstrap-charge", "cflow.sequence", []uint32{0, 1, 2, 3, 4, 7}},
			{"domain-id", "cflow.od_id", []uint32{1}},
		}}
	case "ipfix/b":
		return transitionHeaderCase{transitionHeaderExpectation{[]uint32{0, 0, 0, 0, 0}, []uint32{0}}, []transitionHeaderMutation{
			{"false-continuation", "cflow.sequence", []uint32{6}},
		}}
	default:
		panic("unknown DNS transition capture: " + protocol + "/" + endpoint)
	}
}

type transitionDecodedFrame struct {
	sets, ports string
	headers     []uint32
}

func parseTransitionFields(protocol string, decoded []byte, count int) ([]transitionDecodedFrame, error) {
	lines := strings.Split(strings.TrimSuffix(string(decoded), "\n"), "\n")
	if len(lines) != count {
		return nil, fmt.Errorf("TShark frames=%d, want %d", len(lines), count)
	}
	wantVersion := map[string]string{"netflow_v5": "5", "netflow_v9": "9", "ipfix": "10"}[protocol]
	headerFields := transitionHeaderFields(protocol)
	frames := make([]transitionDecodedFrame, 0, count)
	for index, line := range lines {
		fields := strings.Split(line, "|")
		if len(fields) != 4+len(headerFields) {
			return nil, fmt.Errorf("TShark row %d columns=%d, want %d", index+1, len(fields), 4+len(headerFields))
		}
		if fields[0] != strconv.Itoa(index+1) || fields[1] != wantVersion {
			return nil, fmt.Errorf("TShark row %d frame/version=%q/%q, want %d/%s", index+1, fields[0], fields[1], index+1, wantVersion)
		}
		frame := transitionDecodedFrame{sets: fields[2], ports: fields[3]}
		for column, field := range headerFields {
			value := fields[4+column]
			if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
				return nil, fmt.Errorf("header %s frame %d: expected one decimal scalar, got %q", field.name, index+1, value)
			}
			scalar, err := strconv.ParseUint(value, 10, field.bits)
			if err != nil {
				return nil, fmt.Errorf("header %s frame %d: invalid uint%d %q", field.name, index+1, field.bits, value)
			}
			frame.headers = append(frame.headers, uint32(scalar))
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func checkTransitionHeaders(protocol string, frames []transitionDecodedFrame, want transitionHeaderExpectation) error {
	fields := transitionHeaderFields(protocol)
	if len(frames) != len(want.sequence) || len(want.identity) != len(fields)-1 {
		return fmt.Errorf("header expectation dimensions: frames=%d sequences=%d identity=%d", len(frames), len(want.sequence), len(want.identity))
	}
	for index, frame := range frames {
		if len(frame.headers) != len(fields) {
			return fmt.Errorf("header frame %d scalar count=%d, want %d", index+1, len(frame.headers), len(fields))
		}
		for column, field := range fields {
			expected := want.sequence[index]
			if column > 0 {
				expected = want.identity[column-1]
			}
			if frame.headers[column] != expected {
				return fmt.Errorf("header %s frame %d: got %d, want %d", field.name, index+1, frame.headers[column], expected)
			}
		}
	}
	return nil
}

// Record/cache checks deliberately run independently of header assertions. A
// mutant cannot pass its negative control because its records failed to decode.
func checkTransitionRecords(protocol string, frames []transitionDecodedFrame, wantPorts [][]int) error {
	portCounts := make(map[int]int)
	dataFrame := 0
	for index, frame := range frames {
		setIDs := strings.FieldsFunc(frame.sets, func(r rune) bool { return r == ',' || r == ';' })
		if frame.ports == "" {
			if protocol == "netflow_v5" {
				return fmt.Errorf("v5 row %d unexpectedly has no decoded source ports", index+1)
			}
			wantSet := "0"
			if protocol == "ipfix" {
				wantSet = "2"
			}
			if len(setIDs) != 1 || setIDs[0] != wantSet {
				return fmt.Errorf("template row %d flowset ids=%q, want %s", index+1, frame.sets, wantSet)
			}
			continue
		}
		if dataFrame >= len(wantPorts) {
			return fmt.Errorf("extra decoded data frame at row %d", index+1)
		}
		if protocol == "netflow_v5" {
			if len(setIDs) != 0 {
				return fmt.Errorf("v5 data row %d unexpectedly has flowset ids=%q", index+1, frame.sets)
			}
		} else {
			if len(setIDs) != 1 {
				return fmt.Errorf("data row %d flowset ids=%q, want one data set", index+1, frame.sets)
			}
			setID, err := strconv.Atoi(setIDs[0])
			if err != nil || setID < 256 {
				return fmt.Errorf("data row %d flowset id=%q, want >=256", index+1, frame.sets)
			}
		}
		values := strings.FieldsFunc(frame.ports, func(r rune) bool { return r == ',' || r == ';' })
		if len(values) != len(wantPorts[dataFrame]) {
			return fmt.Errorf("data row %d decoded source ports=%q, want %v", index+1, frame.ports, wantPorts[dataFrame])
		}
		wantSet := make(map[int]bool, len(wantPorts[dataFrame]))
		for _, want := range wantPorts[dataFrame] {
			wantSet[want] = true
		}
		for _, value := range values {
			portNumber, err := strconv.Atoi(value)
			if err != nil || !wantSet[portNumber] || portCounts[portNumber] != 0 {
				return fmt.Errorf("data row %d decoded unknown/duplicate source port=%q", index+1, value)
			}
			portCounts[portNumber]++
		}
		dataFrame++
	}
	if dataFrame != len(wantPorts) {
		return fmt.Errorf("TShark data frames=%d, want %d", dataFrame, len(wantPorts))
	}
	for _, group := range wantPorts {
		for _, portNumber := range group {
			if portCounts[portNumber] != 1 {
				return fmt.Errorf("TShark source port %d count=%d, want one", portNumber, portCounts[portNumber])
			}
		}
	}
	return nil
}

func mutateTransitionHeaders(protocol string, packets []dnsTransitionDatagram, mutant transitionHeaderMutation) ([]dnsTransitionDatagram, error) {
	// Offsets are used only to inject errors, never to extract observed headers
	// or compute expectations. Lengths, sets, records and UDP peers are untouched.
	offsets := map[string]map[string]int{
		"netflow_v5": {"cflow.sequence": 16, "cflow.engine_type": 20, "cflow.engine_id": 21},
		"netflow_v9": {"cflow.sequence": 12, "cflow.source_id": 16},
		"ipfix":      {"cflow.sequence": 8, "cflow.od_id": 12},
	}
	offset, ok := offsets[protocol][mutant.field]
	if !ok || (len(mutant.values) != 1 && len(mutant.values) != len(packets)) || len(mutant.values) == 0 {
		return nil, fmt.Errorf("invalid transition mutant %q field/values", mutant.name)
	}
	width := 4
	if mutant.field == "cflow.engine_type" || mutant.field == "cflow.engine_id" {
		width = 1
	}
	out := make([]dnsTransitionDatagram, len(packets))
	for index, packet := range packets {
		value := mutant.values[0]
		if len(mutant.values) > 1 {
			value = mutant.values[index]
		}
		if len(packet.payload) < offset+width || (width == 1 && value > 255) {
			return nil, fmt.Errorf("invalid transition mutant %q frame %d length/value", mutant.name, index+1)
		}
		out[index] = packet
		out[index].payload = bytes.Clone(packet.payload)
		if width == 1 {
			out[index].payload[offset] = byte(value)
		} else {
			binary.BigEndian.PutUint32(out[index].payload[offset:], value)
		}
	}
	return out, nil
}

func decodeTransitionCapture(t *testing.T, ctx context.Context, bin, protocol, path string, port, count int) []transitionDecodedFrame {
	t.Helper()
	decodeCtx, decodeCancel := context.WithTimeout(ctx, 3*time.Second)
	defer decodeCancel()
	args := []string{"-r", path, "-d", fmt.Sprintf("udp.port==%d,cflow", port), "-T", "fields",
		"-E", "separator=|", "-E", "occurrence=a", "-e", "frame.number", "-e", "cflow.version", "-e", "cflow.flowset_id", "-e", "cflow.srcport"}
	for _, field := range transitionHeaderFields(protocol) {
		args = append(args, "-e", field.name)
	}
	command := exec.CommandContext(decodeCtx, bin, args...)
	var decoded, stderr transitionOutputBuffer
	command.Stdout, command.Stderr = &decoded, &stderr
	err := command.Run()
	for suffix, data := range map[string][]byte{".fields.txt": decoded.Bytes(), ".stderr.txt": stderr.Bytes()} {
		if writeErr := os.WriteFile(path+suffix, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err != nil || decodeCtx.Err() != nil || decoded.overflow || stderr.overflow {
		t.Fatalf("TShark decode failed: err=%v context=%v stdout_overflow=%v stderr_overflow=%v stderr=%s", err, decodeCtx.Err(), decoded.overflow, stderr.overflow, boundedTransitionOutput(stderr.Bytes()))
	}
	frames, err := parseTransitionFields(protocol, decoded.Bytes(), count)
	if err != nil {
		t.Fatalf("TShark fields %s: %v", path, err)
	}
	return frames
}

func runDNSTransitionTShark(t *testing.T, ctx context.Context, protocol, endpoint string, port int, packets []dnsTransitionDatagram, wantPorts [][]int, headers transitionHeaderCase) string {
	t.Helper()
	if os.Getenv("NETFLOW_DNS_TSHARK") != "1" {
		return ""
	}
	if len(headers.mutants) > 16 {
		t.Fatal("transition mutant count exceeds 16")
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
	versionCtx, versionCancel := context.WithTimeout(ctx, time.Second)
	var versionBuffer, versionStderr transitionOutputBuffer
	versionCommand := exec.CommandContext(versionCtx, resolved, "--version")
	versionCommand.Stdout = &versionBuffer
	versionCommand.Stderr = &versionStderr
	versionErr := versionCommand.Run()
	versionOutput := versionBuffer.Bytes()
	versionCancel()
	if versionErr != nil || versionBuffer.overflow || versionStderr.overflow || !strings.HasPrefix(string(versionOutput), "TShark (Wireshark) 4.4.18.") {
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
	pcap, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf("protocol=%s\nendpoint=%s\nframes=%d\nunique_source_ports=%d\nexpected_sequences=%v\nexpected_identity=%v\ntshark=%s\ntshark_version_sha256=%x\ntshark_executable_sha256=%x\npcap_sha256=%x\n", protocol, endpoint, len(packets), countTransitionPorts(wantPorts), headers.want.sequence, headers.want.identity, resolved, sha256.Sum256(versionOutput), sha256.Sum256(executable), sha256.Sum256(pcap))
	if err := os.WriteFile(filepath.Join(dir, "evidence.txt"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every call creates a fresh process/cache, including DNS A, DNS B and the
	// idle capture that deliberately omits bootstrap packets.
	frames := decodeTransitionCapture(t, ctx, resolved, protocol, pcapPath, port, len(packets))
	if err := checkTransitionRecords(protocol, frames, wantPorts); err != nil {
		t.Fatal(err)
	}
	if err := checkTransitionHeaders(protocol, frames, headers.want); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent TShark 4.4.18 decode endpoint=%s frames=%d unique_records=%d headers=PASS artifact=%s", endpoint, len(frames), countTransitionPorts(wantPorts), dir)
	for _, mutant := range headers.mutants {
		t.Run("header-mutant-"+endpoint+"-"+mutant.name, func(t *testing.T) {
			copied, err := mutateTransitionHeaders(protocol, packets, mutant)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "mutant-"+endpoint+"-"+mutant.name+".pcap")
			if err := writeDNSTransitionPCAP(path, copied, port); err != nil {
				t.Fatal(err)
			}
			observed := decodeTransitionCapture(t, ctx, resolved, protocol, path, port, len(copied))
			if err := checkTransitionRecords(protocol, observed, wantPorts); err != nil {
				t.Fatalf("mutant record/cache control failed: %v", err)
			}
			for index, frame := range observed {
				if frame.sets != frames[index].sets || frame.ports != frames[index].ports {
					t.Fatalf("mutant changed template/record fields at frame %d", index+1)
				}
			}
			headerErr := checkTransitionHeaders(protocol, observed, headers.want)
			if headerErr == nil || !strings.HasPrefix(headerErr.Error(), "header "+mutant.field+" frame ") {
				t.Fatalf("mutant must fail named header assertion %s; got %v", mutant.field, headerErr)
			}
			result := fmt.Sprintf("original_control=PASS\ndecoder=PASS\nrecords_and_templates=PASS\nmutated_field=%s\nmutated_values=%v\nrejection=%v\n", mutant.field, mutant.values, headerErr)
			if err := os.WriteFile(path+".result.txt", []byte(result), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Logf("independent mutant rejected: %v; records/templates unchanged", headerErr)
		})
	}
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
			dirA := runDNSTransitionTShark(t, ctx, protocol, "a", port, aCapture, [][]int{{10001, 10002, 10003}, {10004, 10005, 10006}}, dnsTransitionHeaderCase(protocol, "a"))
			dirB := runDNSTransitionTShark(t, ctx, protocol, "b", port, bCapture, [][]int{{10007, 10008, 10009}}, dnsTransitionHeaderCase(protocol, "b"))

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

type transitionHeaderLiteralCase struct {
	name      string
	protocol  string
	headers   transitionHeaderCase
	sequence  []uint32
	identity  []uint32
	templates int
	ports     [][]int
}

func transitionHeaderLiteralCases() []transitionHeaderLiteralCase {
	return []transitionHeaderLiteralCase{
		{
			name: "dns-a-v5", protocol: "netflow_v5", headers: dnsTransitionHeaderCase("netflow_v5", "a"),
			sequence: []uint32{0, 3}, identity: []uint32{0, 0},
			ports: [][]int{{10001, 10002, 10003}, {10004, 10005, 10006}},
		},
		{
			name: "dns-b-v5", protocol: "netflow_v5", headers: dnsTransitionHeaderCase("netflow_v5", "b"),
			sequence: []uint32{0}, identity: []uint32{0, 0},
			ports: [][]int{{10007, 10008, 10009}},
		},
		{
			name: "dns-a-v9", protocol: "netflow_v9", headers: dnsTransitionHeaderCase("netflow_v9", "a"),
			sequence: []uint32{0, 1, 2, 3, 4, 5}, identity: []uint32{0}, templates: 4,
			ports: [][]int{{10001, 10002, 10003}, {10004, 10005, 10006}},
		},
		{
			name: "dns-b-v9", protocol: "netflow_v9", headers: dnsTransitionHeaderCase("netflow_v9", "b"),
			sequence: []uint32{0, 1, 2, 3, 4}, identity: []uint32{0}, templates: 4,
			ports: [][]int{{10007, 10008, 10009}},
		},
		{
			name: "dns-a-ipfix", protocol: "ipfix", headers: dnsTransitionHeaderCase("ipfix", "a"),
			sequence: []uint32{0, 0, 0, 0, 0, 3}, identity: []uint32{0}, templates: 4,
			ports: [][]int{{10001, 10002, 10003}, {10004, 10005, 10006}},
		},
		{
			name: "dns-b-ipfix", protocol: "ipfix", headers: dnsTransitionHeaderCase("ipfix", "b"),
			sequence: []uint32{0, 0, 0, 0, 0}, identity: []uint32{0}, templates: 4,
			ports: [][]int{{10007, 10008, 10009}},
		},
		{
			name: "idle-v5", protocol: "netflow_v5", headers: timeRefreshHeaderCase("netflow_v5"),
			sequence: []uint32{0, 3, 6}, identity: []uint32{0, 0},
			ports: [][]int{{20001, 20002, 20003}, {20004, 20005, 20006}, {20007, 20008, 20009}},
		},
		{
			name: "idle-v9", protocol: "netflow_v9", headers: timeRefreshHeaderCase("netflow_v9"),
			sequence: []uint32{4, 5, 6, 7, 8}, identity: []uint32{0}, templates: 2,
			ports: [][]int{{20001, 20002, 20003}, {20004, 20005, 20006}, {20007, 20008, 20009}},
		},
		{
			name: "idle-ipfix", protocol: "ipfix", headers: timeRefreshHeaderCase("ipfix"),
			sequence: []uint32{0, 0, 0, 3, 6}, identity: []uint32{0}, templates: 2,
			ports: [][]int{{20001, 20002, 20003}, {20004, 20005, 20006}, {20007, 20008, 20009}},
		},
	}
}

func transitionHeaderTestFrames(protocol string, want transitionHeaderExpectation, templates int, ports [][]int) []transitionDecodedFrame {
	frames := make([]transitionDecodedFrame, len(want.sequence))
	for index, sequence := range want.sequence {
		frames[index].headers = append([]uint32{sequence}, want.identity...)
		if index < templates {
			frames[index].sets = "0"
			if protocol == "ipfix" {
				frames[index].sets = "2"
			}
			continue
		}
		portGroup := ports[index-templates]
		values := make([]string, len(portGroup))
		for portIndex, port := range portGroup {
			values[portIndex] = strconv.Itoa(port)
		}
		frames[index].ports = strings.Join(values, ",")
		if protocol != "netflow_v5" {
			frames[index].sets = "256"
		}
	}
	return frames
}

func transitionHeaderTestMutation(frames []transitionDecodedFrame, protocol string, mutation transitionHeaderMutation) ([]transitionDecodedFrame, error) {
	fields := transitionHeaderFields(protocol)
	column := -1
	for index, field := range fields {
		if field.name == mutation.field {
			column = index
			break
		}
	}
	if column < 0 || len(mutation.values) == 0 || (len(mutation.values) != 1 && len(mutation.values) != len(frames)) {
		return nil, fmt.Errorf("invalid test mutation %q", mutation.name)
	}
	out := make([]transitionDecodedFrame, len(frames))
	for index, frame := range frames {
		out[index] = frame
		out[index].headers = append([]uint32(nil), frame.headers...)
		value := mutation.values[0]
		if len(mutation.values) > 1 {
			value = mutation.values[index]
		}
		out[index].headers[column] = value
	}
	return out, nil
}

func transitionHeaderFieldLine(protocol string, values []string) []byte {
	version := map[string]string{"netflow_v5": "5", "netflow_v9": "9", "ipfix": "10"}[protocol]
	columns := []string{"1", version, "0", ""}
	columns = append(columns, values...)
	return []byte(strings.Join(columns, "|") + "\n")
}

func transitionHeaderScalarMax(bits int) string {
	if bits == 8 {
		return "255"
	}
	return "4294967295"
}

func transitionHeaderScalarOverflow(bits int) string {
	if bits == 8 {
		return "256"
	}
	return "4294967296"
}

func TestTransitionHeaderLiteralAccounting(t *testing.T) {
	mutantCount := 0
	for _, tc := range transitionHeaderLiteralCases() {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Equal(tc.headers.want.sequence, tc.sequence) {
				t.Fatalf("helper sequence=%v, want literal %v", tc.headers.want.sequence, tc.sequence)
			}
			if !slices.Equal(tc.headers.want.identity, tc.identity) {
				t.Fatalf("helper identity=%v, want literal %v", tc.headers.want.identity, tc.identity)
			}
			frames := transitionHeaderTestFrames(tc.protocol, transitionHeaderExpectation{sequence: tc.sequence, identity: tc.identity}, tc.templates, tc.ports)
			if err := checkTransitionHeaders(tc.protocol, frames, transitionHeaderExpectation{sequence: tc.sequence, identity: tc.identity}); err != nil {
				t.Fatalf("valid headers rejected: %v", err)
			}
			if err := checkTransitionRecords(tc.protocol, frames, tc.ports); err != nil {
				t.Fatalf("valid records/templates rejected: %v", err)
			}
			for _, mutant := range tc.headers.mutants {
				mutantCount++
				mutated, err := transitionHeaderTestMutation(frames, tc.protocol, mutant)
				if err != nil {
					t.Fatal(err)
				}
				if err := checkTransitionRecords(tc.protocol, mutated, tc.ports); err != nil {
					t.Fatalf("%s changed record/template evidence: %v", mutant.name, err)
				}
				rejection := checkTransitionHeaders(tc.protocol, mutated, transitionHeaderExpectation{sequence: tc.sequence, identity: tc.identity})
				if rejection == nil || !strings.HasPrefix(rejection.Error(), "header "+mutant.field+" frame ") {
					t.Fatalf("%s did not produce named %s rejection: %v", mutant.name, mutant.field, rejection)
				}
			}
		})
	}
	if mutantCount != 13 || mutantCount > 16 {
		t.Fatalf("header mutant roster=%d, want 13 and <=16", mutantCount)
	}
}

func TestTransitionHeaderScalarParsing(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		fields   []transitionScalarField
	}{
		{"netflow_v5", []transitionScalarField{{"cflow.sequence", 32}, {"cflow.engine_type", 8}, {"cflow.engine_id", 8}}},
		{"netflow_v9", []transitionScalarField{{"cflow.sequence", 32}, {"cflow.source_id", 32}}},
		{"ipfix", []transitionScalarField{{"cflow.sequence", 32}, {"cflow.od_id", 32}}},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			protocol, fields := tc.protocol, tc.fields
			if got := transitionHeaderFields(protocol); !slices.Equal(got, fields) {
				t.Fatalf("header field definitions=%v, want %v", got, fields)
			}
			valid := make([]string, len(fields))
			for index, field := range fields {
				valid[index] = transitionHeaderScalarMax(field.bits)
			}
			frames, err := parseTransitionFields(protocol, transitionHeaderFieldLine(protocol, valid), 1)
			if err != nil {
				t.Fatalf("valid width edges rejected: %v", err)
			}
			if len(frames) != 1 || len(frames[0].headers) != len(fields) {
				t.Fatalf("valid scalar row=%+v, want %d fields", frames, len(fields))
			}
			for index, field := range fields {
				if got := strconv.FormatUint(uint64(frames[0].headers[index]), 10); got != valid[index] {
					t.Fatalf("decoded %s=%s, want %s", field.name, got, valid[index])
				}
				for _, invalid := range []struct {
					name, value string
				}{
					{"missing", ""},
					{"malformed", "1.0"},
					{"duplicate", "0,0"},
					{"signed", "+1"},
					{"negative", "-1"},
					{"whitespace", "0 "},
					{"hex", "0x1"},
					{"overflow", transitionHeaderScalarOverflow(field.bits)},
				} {
					values := make([]string, len(fields))
					for valueIndex := range fields {
						values[valueIndex] = "0"
						if valueIndex == index {
							values[valueIndex] = invalid.value
						}
					}
					_, parseErr := parseTransitionFields(protocol, transitionHeaderFieldLine(protocol, values), 1)
					if parseErr == nil || !strings.Contains(parseErr.Error(), field.name) {
						t.Errorf("%s %s accepted or unnamed: %v", field.name, invalid.name, parseErr)
					}
				}
			}
		})
	}
}

func TestTransitionHeaderRetainsRecordAndFrameControls(t *testing.T) {
	caseData := transitionHeaderLiteralCases()[2] // DNS A v9 includes templates and data.
	frames := transitionHeaderTestFrames(caseData.protocol, transitionHeaderExpectation{sequence: caseData.sequence, identity: caseData.identity}, caseData.templates, caseData.ports)

	t.Run("duplicate-record", func(t *testing.T) {
		mutated := append([]transitionDecodedFrame(nil), frames...)
		mutated[4].ports = "10001,10001,10003"
		if err := checkTransitionRecords(caseData.protocol, mutated, caseData.ports); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate record was not rejected: %v", err)
		}
	})
	t.Run("missing-record", func(t *testing.T) {
		mutated := append([]transitionDecodedFrame(nil), frames...)
		mutated[4].ports = "10001,10003"
		if err := checkTransitionRecords(caseData.protocol, mutated, caseData.ports); err == nil || !strings.Contains(err.Error(), "source ports") {
			t.Fatalf("missing record was not rejected: %v", err)
		}
	})
	t.Run("wrong-template", func(t *testing.T) {
		mutated := append([]transitionDecodedFrame(nil), frames...)
		mutated[0].sets = "99"
		if err := checkTransitionRecords(caseData.protocol, mutated, caseData.ports); err == nil || !strings.Contains(err.Error(), "template") {
			t.Fatalf("wrong template was not rejected: %v", err)
		}
	})
	t.Run("wrong-frame", func(t *testing.T) {
		line := transitionHeaderFieldLine(caseData.protocol, []string{"0", "0"})
		line = []byte(strings.Replace(string(line), "1|9|", "2|9|", 1))
		if _, err := parseTransitionFields(caseData.protocol, line, 1); err == nil || !strings.Contains(err.Error(), "frame/version") {
			t.Fatalf("wrong frame was not rejected: %v", err)
		}
	})
	t.Run("wrong-version", func(t *testing.T) {
		line := transitionHeaderFieldLine(caseData.protocol, []string{"0", "0"})
		line = []byte(strings.Replace(string(line), "1|9|", "1|10|", 1))
		if _, err := parseTransitionFields(caseData.protocol, line, 1); err == nil || !strings.Contains(err.Error(), "frame/version") {
			t.Fatalf("wrong version was not rejected: %v", err)
		}
	})
	t.Run("missing-column", func(t *testing.T) {
		line := transitionHeaderFieldLine(caseData.protocol, []string{"0"})
		if _, err := parseTransitionFields(caseData.protocol, line, 1); err == nil || !strings.Contains(err.Error(), "columns") {
			t.Fatalf("missing column was not rejected: %v", err)
		}
	})
}

func TestTransitionHeaderMutationCopiesAndPreservesFraming(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	offsets := map[string]map[string]int{
		"netflow_v5": {"cflow.sequence": 16, "cflow.engine_type": 20, "cflow.engine_id": 21},
		"netflow_v9": {"cflow.sequence": 12, "cflow.source_id": 16},
		"ipfix":      {"cflow.sequence": 8, "cflow.od_id": 12},
	}
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		for _, field := range transitionHeaderFields(protocol) {
			t.Run(protocol+"/"+field.name, func(t *testing.T) {
				original := []dnsTransitionDatagram{
					{payload: bytes.Repeat([]byte{0xa5}, 40), peer: peer, destination: netip.MustParseAddr("127.0.0.1"), at: time.Unix(1, 2)},
					{payload: bytes.Repeat([]byte{0xa5}, 40), peer: peer, destination: netip.MustParseAddr("127.0.0.1"), at: time.Unix(3, 4)},
				}
				before := [][]byte{bytes.Clone(original[0].payload), bytes.Clone(original[1].payload)}
				mutated, err := mutateTransitionHeaders(protocol, original, transitionHeaderMutation{name: "copy", field: field.name, values: []uint32{1, 2}})
				if err != nil {
					t.Fatal(err)
				}
				for index := range original {
					if !bytes.Equal(original[index].payload, before[index]) || len(mutated[index].payload) != len(original[index].payload) {
						t.Fatalf("mutation changed original/framing at frame %d", index+1)
					}
					if &mutated[index].payload[0] == &original[index].payload[0] {
						t.Fatalf("mutation reused payload backing array at frame %d", index+1)
					}
					got := uint32(mutated[index].payload[offsets[protocol][field.name]])
					if field.bits == 32 {
						got = binary.BigEndian.Uint32(mutated[index].payload[offsets[protocol][field.name]:])
					}
					if got != uint32(index+1) {
						t.Fatalf("mutation field %s frame %d=%d, want %d", field.name, index+1, got, index+1)
					}
					expected := bytes.Clone(before[index])
					offset, width := offsets[protocol][field.name], field.bits/8
					clear(expected[offset : offset+width])
					expected[offset+width-1] = byte(index + 1)
					if !bytes.Equal(mutated[index].payload, expected) {
						t.Fatalf("mutation changed bytes outside %s at frame %d", field.name, index+1)
					}
					if mutated[index].peer != original[index].peer || mutated[index].destination != original[index].destination || !mutated[index].at.Equal(original[index].at) {
						t.Fatalf("mutation changed frame envelope identity at frame %d", index+1)
					}
				}
			})
		}
	}
}
