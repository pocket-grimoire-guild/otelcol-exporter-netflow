package receiver_test

// These tests are deliberately receiver-first.  Each input below is an
// independently constructed UDP payload; the exporter only sees the
// attributes projected by the pinned receiver.  The literal packet checks in
// this file do not use the exporter's shape catalog to derive IDs or widths.

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

type flowTimeField struct {
	id    uint16
	value []byte
}

type flowTimeFixture struct {
	name, protocol string
	fields         []flowTimeField
	start, end     uint64
	inputExport    uint64
	inputPresence  string
	ipv6, v5Zero   bool
}

type receiverFlowResult struct {
	fixture                       flowTimeFixture
	raw                           []byte
	logs                          plog.Logs
	origin                        uint64
	receivedBefore, receivedAfter uint64
}

type capturedFlowOutput struct {
	profile                     string
	packets                     [][]byte
	rejected                    bool
	startBefore, startAfter     uint64
	consumeBefore, consumeAfter uint64
}

type literalField struct {
	id, width uint16
}

var (
	v9CoreLiteral       = []literalField{{1, 4}, {2, 4}, {4, 1}, {5, 1}, {6, 1}, {7, 2}, {8, 4}, {9, 1}, {10, 2}, {11, 2}, {12, 4}, {13, 1}, {14, 2}, {16, 4}, {17, 4}, {34, 4}, {52, 1}, {60, 1}}
	v9TimedLiteral      = append(append([]literalField(nil), v9CoreLiteral...), literalField{22, 4}, literalField{21, 4})
	ipfixCoreLiteral    = []literalField{{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 2}, {7, 2}, {8, 4}, {9, 1}, {10, 4}, {11, 2}, {12, 4}, {13, 1}, {14, 4}, {16, 4}, {17, 4}, {34, 4}, {52, 1}, {60, 1}, {156, 8}, {157, 8}}
	ipfixGeneralLiteral = []literalField{{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 2}, {7, 2}, {8, 4}, {9, 1}, {10, 4}, {11, 2}, {12, 4}, {13, 1}, {14, 4}, {16, 4}, {17, 4}, {34, 4}, {52, 1}, {60, 1}, {152, 8}, {153, 8}}
)

func u16FlowTime(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func u32FlowTime(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func u64FlowTime(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func ntpFlowTime(seconds uint64, fraction uint32) uint64 {
	return (seconds+2_208_988_800)<<32 | uint64(fraction)
}

func flowTimeFixtures(base uint64) []flowTimeFixture {
	b := base * 1_000_000_000
	return []flowTimeFixture{
		{name: "v5-measured", protocol: "netflow_v5", start: b - 8_000_000_000 + 250_000_000, end: b - 4_500_000_000 + 250_000_000, inputExport: b + 250_000_000, inputPresence: "measured"},
		{name: "v5-zero-slots", protocol: "netflow_v5", start: b - 20_000_000_000 + 250_000_000, end: b - 20_000_000_000 + 250_000_000, inputExport: b + 250_000_000, inputPresence: "explicit-zero", v5Zero: true},
		{name: "v9-measured", protocol: "netflow_v9", fields: []flowTimeField{{22, u32FlowTime(12000)}, {21, u32FlowTime(15500)}}, start: b - 8_000_000_000, end: b - 4_500_000_000, inputExport: b, inputPresence: "measured"},
		{name: "v9-absent", protocol: "netflow_v9", start: b, end: b, inputExport: b, inputPresence: "absent"},
		{name: "v9-start-only", protocol: "netflow_v9", fields: []flowTimeField{{22, u32FlowTime(12000)}}, start: b - 8_000_000_000, end: b, inputExport: b, inputPresence: "partial-start"},
		{name: "ipfix-seconds", protocol: "ipfix", fields: []flowTimeField{{150, u32FlowTime(uint32(base - 8))}, {151, u32FlowTime(uint32(base - 4))}}, start: b - 8_000_000_000, end: b - 4_000_000_000, inputExport: b, inputPresence: "measured"},
		{name: "ipfix-milliseconds", protocol: "ipfix", fields: []flowTimeField{{152, u64FlowTime(base*1000 - 7750)}, {153, u64FlowTime(base*1000 - 4500)}}, start: b - 7_750_000_000, end: b - 4_500_000_000, inputExport: b, inputPresence: "measured"},
		{name: "ipfix-microseconds", protocol: "ipfix", fields: []flowTimeField{{154, u64FlowTime(ntpFlowTime(base-8, 0x40000000))}, {155, u64FlowTime(ntpFlowTime(base-5, 0x80000000))}}, start: b - 7_750_000_000, end: b - 4_500_000_000, inputExport: b, inputPresence: "measured"},
		{name: "ipfix-microseconds-lowbits", protocol: "ipfix", fields: []flowTimeField{{154, u64FlowTime(ntpFlowTime(base-8, 0x40000005))}, {155, u64FlowTime(ntpFlowTime(base-5, 0x80000005))}}, start: b - 7_750_000_000 + 1, end: b - 4_500_000_000 + 1, inputExport: b, inputPresence: "measured-lowbits"},
		{name: "ipfix-nanoseconds", protocol: "ipfix", fields: []flowTimeField{{156, u64FlowTime(ntpFlowTime(base-8, 0x00000005))}, {157, u64FlowTime(ntpFlowTime(base-5, 0x80000005))}}, start: b - 8_000_000_000 + 1, end: b - 4_500_000_000 + 1, inputExport: b, inputPresence: "measured"},
		{name: "ipfix-delta", protocol: "ipfix", fields: []flowTimeField{{158, u32FlowTime(7750123)}, {159, u32FlowTime(4500001)}}, start: b - 7_750_123_000, end: b - 4_500_001_000, inputExport: b, inputPresence: "measured-delta"},
		{name: "ipfix-absent", protocol: "ipfix", start: b, end: b, inputExport: b, inputPresence: "absent"},
		{name: "ipfix-start-only", protocol: "ipfix", fields: []flowTimeField{{152, u64FlowTime(base*1000 - 7750)}}, start: b - 7_750_000_000, end: b, inputExport: b, inputPresence: "partial-start"},
		{name: "v9-measured-ipv6", protocol: "netflow_v9", fields: []flowTimeField{{22, u32FlowTime(12000)}, {21, u32FlowTime(15500)}}, start: b - 8_000_000_000, end: b - 4_500_000_000, inputExport: b, inputPresence: "measured", ipv6: true},
		{name: "ipfix-ms-ipv6", protocol: "ipfix", fields: []flowTimeField{{152, u64FlowTime(base*1000 - 7750)}, {153, u64FlowTime(base*1000 - 4500)}}, start: b - 7_750_000_000, end: b - 4_500_000_000, inputExport: b, inputPresence: "measured", ipv6: true},
	}
}

func flowTimeInputPacket(tc flowTimeFixture, base uint64) []byte {
	if tc.protocol == "netflow_v5" {
		p := make([]byte, 72)
		binary.BigEndian.PutUint16(p, 5)
		binary.BigEndian.PutUint16(p[2:], 1)
		binary.BigEndian.PutUint32(p[4:], 20000)
		binary.BigEndian.PutUint32(p[8:], uint32(base))
		binary.BigEndian.PutUint32(p[12:], 250000000)
		copy(p[24:], net.ParseIP("192.0.2.1").To4())
		copy(p[28:], net.ParseIP("198.51.100.2").To4())
		binary.BigEndian.PutUint32(p[40:], 7)
		binary.BigEndian.PutUint32(p[44:], 700)
		if !tc.v5Zero {
			binary.BigEndian.PutUint32(p[48:], 12000)
			binary.BigEndian.PutUint32(p[52:], 15500)
		}
		binary.BigEndian.PutUint16(p[56:], 12345)
		binary.BigEndian.PutUint16(p[58:], 443)
		p[61], p[62] = 18, 6
		return p
	}
	fields := []flowTimeField{{8, net.ParseIP("192.0.2.1").To4()}, {12, net.ParseIP("198.51.100.2").To4()}, {4, []byte{6}}, {7, u16FlowTime(12345)}, {11, u16FlowTime(443)}, {1, u32FlowTime(700)}, {2, u32FlowTime(7)}, {15, net.IPv4zero.To4()}}
	if tc.ipv6 {
		fields[0] = flowTimeField{27, net.ParseIP("2001:db8::1").To16()}
		fields[1] = flowTimeField{28, net.ParseIP("2001:db8::2").To16()}
		fields[7] = flowTimeField{62, net.IPv6zero}
	}
	fields = append(fields, tc.fields...)
	template := append(u16FlowTime(300), u16FlowTime(uint16(len(fields)))...)
	var data []byte
	for _, f := range fields {
		template = append(template, u16FlowTime(f.id)...)
		template = append(template, u16FlowTime(uint16(len(f.value)))...)
		data = append(data, f.value...)
	}
	set := func(id uint16, body []byte) []byte {
		for (len(body)+4)%4 != 0 {
			body = append(body, 0)
		}
		return append(append(u16FlowTime(id), u16FlowTime(uint16(4+len(body)))...), body...)
	}
	templateSet := uint16(2)
	if tc.protocol == "netflow_v9" {
		templateSet = 0
	}
	sets := append(set(templateSet, template), set(300, data)...)
	var header []byte
	if tc.protocol == "netflow_v9" {
		header = append(u16FlowTime(9), u16FlowTime(2)...)
		header = append(header, u32FlowTime(20000)...)
		header = append(header, u32FlowTime(uint32(base))...)
		header = append(header, u32FlowTime(0)...)
		header = append(header, u32FlowTime(42)...)
	} else {
		header = append(u16FlowTime(10), u16FlowTime(uint16(16+len(sets)))...)
		header = append(header, u32FlowTime(uint32(base))...)
		header = append(header, u32FlowTime(0)...)
		header = append(header, u32FlowTime(42)...)
	}
	return append(header, sets...)
}

func TestReceiverFirstFlowTime(t *testing.T) {
	base := uint64(time.Now().Unix() - 3)
	fixtures := flowTimeFixtures(base)
	if len(fixtures) != 15 {
		t.Fatalf("fixture count=%d, want 15", len(fixtures))
	}
	byName := map[string]flowTimeFixture{}
	for _, fixture := range fixtures {
		byName[fixture.name] = fixture
	}
	if byName["ipfix-microseconds-lowbits"].start != byName["ipfix-microseconds"].start+1 || byName["ipfix-microseconds-lowbits"].end != byName["ipfix-microseconds"].end+1 {
		t.Fatal("paired IPFIX microsecond low-bit control is not exactly +1ns")
	}
	microRaw := flowTimeInputPacket(byName["ipfix-microseconds"], base)
	lowBitsRaw := flowTimeInputPacket(byName["ipfix-microseconds-lowbits"], base)
	for _, id := range []uint16{154, 155} {
		micro, ok := inputFlowFieldBytes(t, microRaw, id)
		if !ok {
			t.Fatalf("paired IPFIX microsecond field %d missing", id)
		}
		lowBits, ok := inputFlowFieldBytes(t, lowBitsRaw, id)
		if !ok {
			t.Fatalf("paired IPFIX low-bit field %d missing", id)
		}
		if got := binary.BigEndian.Uint32(lowBits[4:]) - binary.BigEndian.Uint32(micro[4:]); got != 5 {
			t.Fatalf("paired IPFIX field %d fraction delta=%d, want 5 binary ticks", id, got)
		}
	}
	var attempts, successes, rejected int
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			result := receiveFlowTimeFixture(t, tc, base)
			assertFlowTimeIntermediate(t, result)
			profiles := []string{"netflow-v5-fixed-v1", "netflow-v9-core-v1", "netflow-v9-timed-v1", "ipfix-core-v1", "ipfix-general-v1"}
			if tc.ipv6 {
				profiles = []string{"netflow-v9-core-v1", "netflow-v9-timed-v1", "ipfix-core-v1", "ipfix-general-v1"}
			}
			for _, profile := range profiles {
				t.Run(profile, func(t *testing.T) {
					out := exportFlowTime(t, result, profile)
					assertFlowTimeOutput(t, result, out)
					attempts++
					if out.rejected {
						rejected++
					} else {
						successes++
					}
				})
			}
		})
	}
	if attempts != 73 || successes != 67 || rejected != 6 {
		t.Fatalf("flow-time attempts=%d successes=%d rejected=%d, want 73/67/6", attempts, successes, rejected)
	}
}

func receiveFlowTimeFixture(t *testing.T, tc flowTimeFixture, base uint64) receiverFlowResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reserve, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	port := reserve.LocalAddr().(*net.UDPAddr).Port
	factory := netflowreceiver.NewFactory()
	cfg := factory.CreateDefaultConfig().(*netflowreceiver.Config)
	cfg.Scheme, cfg.Hostname, cfg.Port = "netflow", "127.0.0.1", port
	cfg.Sockets, cfg.Workers, cfg.QueueSize, cfg.SendRaw = 1, 1, 64, false
	must(t, cfg.Validate())
	sink := &consumertest.LogsSink{}
	rx, err := factory.CreateLogs(ctx, receivertest.NewNopSettings(factory.Type()), cfg, sink)
	must(t, err)
	stopped := false
	defer func() {
		if !stopped {
			shutdown(t, rx)
		}
	}()
	must(t, reserve.Close())
	must(t, rx.Start(ctx, componenttest.NewNopHost()))
	raw := flowTimeInputPacket(tc, base)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	must(t, err)
	receiveBefore := uint64(time.Now().UnixNano())
	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("input write=(%d,%v), want %d", n, err, len(raw))
	}
	must(t, conn.Close())
	stableRecords(t, ctx, sink, 1)
	receiveAfter := uint64(time.Now().UnixNano())
	shutdown(t, rx)
	stopped = true
	if sink.LogRecordCount() != 1 {
		t.Fatalf("receiver records after shutdown=%d, want 1", sink.LogRecordCount())
	}
	all := sink.AllLogs()
	logs := plog.NewLogs()
	for _, batch := range all {
		for i := 0; i < batch.ResourceLogs().Len(); i++ {
			batch.ResourceLogs().At(i).CopyTo(logs.ResourceLogs().AppendEmpty())
		}
	}
	if logs.LogRecordCount() != 1 {
		t.Fatalf("flattened receiver records=%d, want 1", logs.LogRecordCount())
	}
	return receiverFlowResult{fixture: tc, raw: raw, logs: logs, origin: (base - 20) * 1_000_000_000, receivedBefore: receiveBefore, receivedAfter: receiveAfter}
}

func assertFlowTimeIntermediate(t *testing.T, result receiverFlowResult) {
	t.Helper()
	tc := result.fixture
	r := result.logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	a := r.Attributes()
	start, end, received := intAttribute(t, a, "flow.start"), intAttribute(t, a, "flow.end"), intAttribute(t, a, "flow.time_received")
	if uint64(start) != tc.start || uint64(end) != tc.end {
		t.Fatalf("%s receiver timing=%d/%d, want %d/%d", tc.name, start, end, tc.start, tc.end)
	}
	if start > end || uint64(r.Timestamp()) != tc.start || uint64(r.ObservedTimestamp()) != uint64(received) {
		t.Fatalf("%s envelope/order mismatch", tc.name)
	}
	if received < int64(result.receivedBefore) || received > int64(result.receivedAfter) || uint64(received) <= tc.inputExport {
		t.Fatalf("%s receive time=%d outside [%d,%d] or not after input export %d", tc.name, received, result.receivedBefore, result.receivedAfter, tc.inputExport)
	}
	if a.Len() < 12 {
		t.Fatalf("%s intermediate attributes=%d, want receiver projection", tc.name, a.Len())
	}
	if tc.inputPresence == "absent" && tc.protocol != "netflow_v5" && (uint64(start) != tc.inputExport || uint64(end) != tc.inputExport) {
		t.Fatalf("%s absent timing did not use independent export fallback", tc.name)
	}
	seen := map[uint16]bool{}
	for _, f := range tc.fields {
		seen[f.id] = true
	}
	partial := (seen[22] && !seen[21]) || (seen[150] && !seen[151]) || (seen[152] && !seen[153]) || (seen[154] && !seen[155]) || (seen[156] && !seen[157]) || (seen[158] && !seen[159])
	if (tc.inputPresence == "partial-start") != partial {
		t.Fatalf("%s presence classification drift", tc.name)
	}
	assertFlowTimeInputLiteral(t, result)
}

func assertFlowTimeInputLiteral(t *testing.T, result receiverFlowResult) {
	t.Helper()
	tc := result.fixture
	raw := result.raw
	if tc.protocol == "netflow_v5" {
		if len(raw) != 72 || binary.BigEndian.Uint16(raw) != 5 || binary.BigEndian.Uint16(raw[2:]) != 1 || binary.BigEndian.Uint32(raw[8:]) != uint32(tc.inputExport/1_000_000_000) || binary.BigEndian.Uint32(raw[12:]) != uint32(tc.inputExport%1_000_000_000) {
			t.Fatalf("%s v5 input header drift", tc.name)
		}
		if tc.v5Zero != (binary.BigEndian.Uint32(raw[48:52]) == 0 && binary.BigEndian.Uint32(raw[52:56]) == 0) {
			t.Fatalf("%s v5 zero-slot classification drift", tc.name)
		}
		return
	}
	version := binary.BigEndian.Uint16(raw)
	header := 16
	if tc.protocol == "netflow_v9" {
		header = 20
		if version != 9 {
			t.Fatalf("%s input version=%d, want 9", tc.name, version)
		}
	} else if version != 10 {
		t.Fatalf("%s input version=%d, want 10", tc.name, version)
	}
	if binary.BigEndian.Uint32(raw[header-12:header-8]) != uint32(tc.inputExport/1_000_000_000) {
		t.Fatalf("%s input export seconds drift", tc.name)
	}
	if binary.BigEndian.Uint32(raw[header-4:header]) != 42 {
		t.Fatalf("%s input identity drift", tc.name)
	}
	records, templates := decodeFlowTimePackets(t, [][]byte{raw}, flowTimeInputProfile(tc), false)
	if len(records) != 1 {
		t.Fatalf("%s input data records=%d, want 1", tc.name, len(records))
	}
	wantTemplate := flowTimeInputTemplate(tc)
	gotTemplate, ok := templates[300]
	if !ok {
		t.Fatalf("%s input template 300 missing", tc.name)
	}
	if len(gotTemplate) != len(wantTemplate) {
		t.Fatalf("%s input template fields=%d, want %d", tc.name, len(gotTemplate), len(wantTemplate))
	}
	for i := range wantTemplate {
		if gotTemplate[i] != wantTemplate[i] {
			t.Fatalf("%s input template field %d=%v, want %v", tc.name, i, gotTemplate[i], wantTemplate[i])
		}
	}
	record := records[0]
	if len(record) != len(wantTemplate) {
		t.Fatalf("%s input record fields=%d, want %d", tc.name, len(record), len(wantTemplate))
	}
	for _, field := range tc.fields {
		got, ok := record[field.id]
		if !ok || !bytes.Equal(got, field.value) {
			t.Fatalf("%s input IE %d value=%x, want %x", tc.name, field.id, got, field.value)
		}
	}
	for _, id := range []uint16{22, 21, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159} {
		_, got := record[id]
		want := false
		for _, field := range tc.fields {
			if field.id == id {
				want = true
				break
			}
		}
		if got != want {
			t.Fatalf("%s input IE %d presence=%v, want %v", tc.name, id, got, want)
		}
	}
}

func inputFlowFieldBytes(t *testing.T, raw []byte, wantID uint16) ([]byte, bool) {
	t.Helper()
	records, _ := decodeFlowTimePackets(t, [][]byte{raw}, flowTimeInputProfileFromVersion(binary.BigEndian.Uint16(raw)), false)
	if len(records) != 1 {
		return nil, false
	}
	value, ok := records[0][wantID]
	return value, ok
}

func exportFlowTime(t *testing.T, result receiverFlowResult, profile string) capturedFlowOutput {
	t.Helper()
	tc := result.fixture
	capture, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	defer capture.Close()
	factory := netflowexporter.NewFactory()
	cfg := factory.CreateDefaultConfig().(*netflowexporter.Config)
	cfg.Endpoint, cfg.Protocol = capture.LocalAddr().String(), profileProtocol(profile)
	fullProfile := "contrib-netflowreceiver-v0.160.0/" + profile
	cfg.Mapping.Profile = &fullProfile
	loss := netflowexporter.LossPolicy("encode_and_count")
	cfg.Mapping.LossPolicy = &loss
	cfg.Mapping.ProtocolIdentifiers = []netflowexporter.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	identity := uint32(42)
	zero := uint8(0)
	if cfg.Protocol == "netflow_v5" {
		cfg.Identity.EngineType, cfg.Identity.EngineID = &zero, &zero
		cfg.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		cfg.UptimeOrigin = &result.origin
	} else if cfg.Protocol == "netflow_v9" {
		cfg.Identity.SourceID = &identity
		cfg.UptimeOrigin = &result.origin
		cfg.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	} else {
		cfg.Identity.ObservationDomainID = &identity
		cfg.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	must(t, cfg.Validate())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ex, err := factory.CreateLogs(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	must(t, err)
	startBefore := uint64(time.Now().UnixNano())
	must(t, ex.Start(ctx, componenttest.NewNopHost()))
	startAfter := uint64(time.Now().UnixNano())
	stopped := false
	defer func() {
		if !stopped {
			shutdown(t, ex)
		}
	}()
	// Controls run before a valid call. They must be permanent, must not emit
	// data, and must leave the receiver-produced input untouched.
	bad := plog.NewLogs()
	result.logs.CopyTo(bad)
	bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Remove("flow.start")
	bad.MarkReadOnly()
	badBefore := flowTimeLogsJSON(t, bad)
	if err := ex.ConsumeLogs(ctx, bad); !consumererror.IsPermanent(err) {
		t.Fatalf("missing flow.start error=%v", err)
	}
	if got := flowTimeLogsJSON(t, bad); !bytes.Equal(badBefore, got) {
		t.Fatal("missing-key control envelope mutated")
	}
	var priorPackets [][]byte
	if packets := readFlowPackets(t, capture); len(packets) != 0 {
		if dataCount := len(dataRecordsFlowTime(t, packets, profile)); dataCount != 0 {
			t.Fatalf("missing-key rejection emitted %d data records", dataCount)
		}
		// Non-v5 exporters bootstrap their fresh template cache during Start;
		// retain those exact packets for the final stream decode.
		priorPackets = append(priorPackets, packets...)
	}
	reversedExpected := profile == "ipfix-core-v1" || profile == "ipfix-general-v1"
	if reversedExpected {
		reversed := plog.NewLogs()
		result.logs.CopyTo(reversed)
		rr := reversed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		// Keep the reversed pair within one millisecond. IPFIX must validate
		// ordering before flooring to milliseconds.
		rr.Attributes().PutInt("flow.start", int64(tc.start+1))
		rr.Attributes().PutInt("flow.end", int64(tc.start))
		reversed.MarkReadOnly()
		reversedBefore := flowTimeLogsJSON(t, reversed)
		if err := ex.ConsumeLogs(ctx, reversed); !consumererror.IsPermanent(err) {
			t.Fatalf("reversed timing error=%v", err)
		}
		if got := flowTimeLogsJSON(t, reversed); !bytes.Equal(reversedBefore, got) {
			t.Fatal("reversed control envelope mutated")
		}
		if packets := readFlowPackets(t, capture); len(packets) != 0 {
			if dataCount := len(dataRecordsFlowTime(t, packets, profile)); dataCount != 0 {
				t.Fatalf("reversed control emitted %d data records", dataCount)
			}
		}
	}
	inputBefore := flowTimeLogsJSON(t, result.logs)
	result.logs.MarkReadOnly()
	consumeBefore := uint64(time.Now().UnixNano())
	err = ex.ConsumeLogs(ctx, result.logs)
	consumeAfter := uint64(time.Now().UnixNano())
	rejected := false
	if (profile == "netflow-v5-fixed-v1" || profile == "netflow-v9-timed-v1") && (tc.start%1_000_000 != 0 || tc.end%1_000_000 != 0) {
		rejected = true
		if !consumererror.IsPermanent(err) {
			t.Fatalf("non-ms %s accepted: %v", tc.name, err)
		}
	} else if err != nil {
		t.Fatalf("valid %s export: %v", profile, err)
	}
	must(t, ex.Shutdown(ctx))
	stopped = true
	packets := append(priorPackets, readFlowPackets(t, capture)...)
	if got := flowTimeLogsJSON(t, result.logs); !bytes.Equal(inputBefore, got) {
		t.Fatal("receiver-produced input mutated by exporter")
	}
	return capturedFlowOutput{profile: profile, packets: packets, rejected: rejected, startBefore: startBefore, startAfter: startAfter, consumeBefore: consumeBefore, consumeAfter: consumeAfter}
}

func profileProtocol(profile string) string {
	if profile == "netflow-v5-fixed-v1" {
		return "netflow_v5"
	}
	if profile[:2] == "ne" {
		return "netflow_v9"
	}
	return "ipfix"
}

func flowTimeLogsJSON(t *testing.T, logs plog.Logs) []byte {
	t.Helper()
	marshaler := plog.JSONMarshaler{}
	data, err := marshaler.MarshalLogs(logs)
	must(t, err)
	return data
}

func readFlowPackets(t *testing.T, conn *net.UDPConn) [][]byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var packets [][]byte
	for {
		b := make([]byte, 65535)
		n, _, err := conn.ReadFromUDP(b)
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatalf("read output: %v", err)
			}
			break
		}
		packets = append(packets, append([]byte(nil), b[:n]...))
	}
	return packets
}

func assertFlowTimeOutput(t *testing.T, result receiverFlowResult, out capturedFlowOutput) {
	t.Helper()
	tc := result.fixture
	records := dataRecordsFlowTime(t, out.packets, out.profile)
	for _, packet := range out.packets {
		assertFlowTimePacketHeader(t, packet, out, result.origin)
	}
	if out.rejected {
		if len(records) != 0 {
			t.Fatalf("rejected %s emitted %d data records", out.profile, len(records))
		}
		return
	}
	if len(records) != 1 {
		t.Fatalf("%s data records=%d, want 1", out.profile, len(records))
	}
	record := records[0]
	if out.profile == "netflow-v5-fixed-v1" {
		if len(out.packets) != 1 || len(out.packets[0]) != 72 || binary.BigEndian.Uint16(out.packets[0]) != 5 {
			t.Fatalf("v5 packet envelope drift")
		}
		packet := out.packets[0]
		if binary.BigEndian.Uint16(packet[2:4]) != 1 || binary.BigEndian.Uint16(packet[56:58]) != 12345 || binary.BigEndian.Uint16(packet[58:60]) != 443 {
			t.Fatal("v5 record count or port identity drift")
		}
		if !bytes.Equal(packet[24:28], net.ParseIP("192.0.2.1").To4()) || !bytes.Equal(packet[28:32], net.ParseIP("198.51.100.2").To4()) {
			t.Fatal("v5 endpoint address drift")
		}
		if binary.BigEndian.Uint32(packet[52:56]) > binary.BigEndian.Uint32(packet[4:8]) {
			t.Fatal("v5 Last exceeds header uptime")
		}
		if got := binary.BigEndian.Uint32(out.packets[0][48:52]); got != uint32((tc.start-result.origin)/1_000_000) {
			t.Fatalf("v5 First=%d", got)
		}
		if got := binary.BigEndian.Uint32(out.packets[0][52:56]); got != uint32((tc.end-result.origin)/1_000_000) {
			t.Fatalf("v5 Last=%d", got)
		}
		if binary.BigEndian.Uint32(out.packets[0][48:52]) > binary.BigEndian.Uint32(out.packets[0][52:56]) {
			t.Fatal("v5 flow time order drift")
		}
		if got := binary.BigEndian.Uint32(out.packets[0][52:56]) - binary.BigEndian.Uint32(out.packets[0][48:52]); got != uint32((tc.end-tc.start)/1_000_000) {
			t.Fatalf("v5 duration=%dms, want %dms", got, (tc.end-tc.start)/1_000_000)
		}
		if binary.BigEndian.Uint32(out.packets[0][20:24]) != 0 {
			t.Fatalf("v5 engine identity drift")
		}
		headerStamp := uint64(binary.BigEndian.Uint32(out.packets[0][8:12]))*1_000_000_000 + uint64(binary.BigEndian.Uint32(out.packets[0][12:16]))
		if headerStamp/1_000_000 < out.consumeBefore/1_000_000 || headerStamp/1_000_000 > out.consumeAfter/1_000_000 || uint64(binary.BigEndian.Uint32(out.packets[0][4:8])) != (headerStamp-result.origin)/1_000_000 {
			t.Fatalf("v5 origin/header relation drift")
		}
		return
	}
	version, header := uint16(10), 16
	if profileProtocol(out.profile) == "netflow_v9" {
		version, header = 9, 20
	}
	for _, p := range out.packets {
		if len(p) < header || binary.BigEndian.Uint16(p) != version {
			t.Fatalf("%s header version drift", out.profile)
		}
		if version == 9 {
			if binary.BigEndian.Uint32(p[16:20]) != 42 {
				t.Fatalf("v9 header identity drift")
			}
			uptime := uint64(binary.BigEndian.Uint32(p[4:8]))
			exportBase := (uint64(binary.BigEndian.Uint32(p[8:12]))*1_000_000_000 - result.origin) / 1_000_000
			if uptime < exportBase || uptime > exportBase+999 {
				t.Fatalf("v9 origin/header relation drift")
			}
		} else if binary.BigEndian.Uint32(p[12:16]) != 42 {
			t.Fatalf("IPFIX header identity drift")
		}
	}
	for _, shape := range []uint16{256, 257} {
		fields, ok := outputTemplateFlowTime(t, out.packets, out.profile, shape)
		if !ok {
			t.Fatalf("%s missing template %d", out.profile, shape)
		}
		want := flowTimeExpectedTemplate(out.profile, shape == 257)
		if len(fields) != len(want) {
			t.Fatalf("%s template %d fields=%d, want %d", out.profile, shape, len(fields), len(want))
		}
		for i := range want {
			if fields[i] != want[i] {
				t.Fatalf("%s template %d field %d=%v, want %v", out.profile, shape, i, fields[i], want[i])
			}
		}
	}
	assertFlowTimeRecordLiterals(t, record, tc.ipv6)
	if out.profile == "netflow-v9-timed-v1" {
		start := uint32FieldFlowTime(record, 22)
		end := uint32FieldFlowTime(record, 21)
		if start != uint32((tc.start-result.origin)/1_000_000) || end != uint32((tc.end-result.origin)/1_000_000) {
			t.Fatalf("timed v9 timing values drift")
		}
		if end < start || end-start != uint32((tc.end-tc.start)/1_000_000) {
			t.Fatalf("timed v9 duration/order drift")
		}
		for _, packet := range out.packets {
			_, hasData := flowTimePacketKinds(packet, 20, 0)
			if hasData && end > binary.BigEndian.Uint32(packet[4:8]) {
				t.Fatalf("timed v9 end=%d exceeds packet uptime=%d", end, binary.BigEndian.Uint32(packet[4:8]))
			}
		}
	}
	if out.profile == "ipfix-general-v1" {
		start := uint64FieldFlowTime(record, 152)
		end := uint64FieldFlowTime(record, 153)
		if start != tc.start/1_000_000 || end != tc.end/1_000_000 {
			t.Fatalf("general IPFIX millisecond values drift")
		}
		if end < start || end-start != tc.end/1_000_000-tc.start/1_000_000 {
			t.Fatalf("general IPFIX duration/order drift")
		}
	}
	if out.profile == "ipfix-core-v1" {
		if _, ok := record[152]; ok {
			t.Fatal("IPFIX core emitted millisecond IE")
		}
		assertFlowTimeNTPOutput(t, record[156], tc.start)
		assertFlowTimeNTPOutput(t, record[157], tc.end)
		assertFlowTimeNTPDuration(t, record[156], record[157], tc.end-tc.start)
	}
}

func assertFlowTimeNTPOutput(t *testing.T, encoded []byte, want uint64) {
	t.Helper()
	if len(encoded) != 8 {
		t.Fatalf("IPFIX NTP width=%d, want 8", len(encoded))
	}
	numerator := flowTimeNTPErrorNumerator(encoded, want)
	if numerator.Cmp(big.NewInt(500_000_000)) > 0 {
		t.Fatalf("IPFIX NTP endpoint residual numerator=%s, want <=500000000", numerator)
	}
}

func flowTimeNTPErrorNumerator(encoded []byte, want uint64) *big.Int {
	stamp := binary.BigEndian.Uint64(encoded)
	whole := new(big.Int).SetUint64(stamp >> 32)
	whole.Sub(whole, new(big.Int).SetUint64(2_208_988_800))
	whole.Mul(whole, big.NewInt(1_000_000_000))
	whole.Sub(whole, new(big.Int).SetUint64(want))
	whole.Mul(whole, big.NewInt(4_294_967_296))
	fraction := new(big.Int).SetUint64(stamp & 0xffffffff)
	fraction.Mul(fraction, big.NewInt(1_000_000_000))
	whole.Add(whole, fraction)
	if whole.Sign() < 0 {
		whole.Neg(whole)
	}
	return whole
}

func assertFlowTimeNTPDuration(t *testing.T, startEncoded, endEncoded []byte, want uint64) {
	t.Helper()
	if len(startEncoded) != 8 || len(endEncoded) != 8 {
		t.Fatalf("IPFIX NTP duration width=%d/%d, want 8/8", len(startEncoded), len(endEncoded))
	}
	start := binary.BigEndian.Uint64(startEncoded)
	end := binary.BigEndian.Uint64(endEncoded)
	if end < start {
		t.Fatalf("IPFIX NTP flow time order drift")
	}
	got := new(big.Int).SetUint64(end >> 32)
	got.Sub(got, new(big.Int).SetUint64(start>>32))
	got.Mul(got, big.NewInt(1_000_000_000))
	got.Mul(got, big.NewInt(4_294_967_296))
	fraction := new(big.Int).SetUint64(end & 0xffffffff)
	fraction.Sub(fraction, new(big.Int).SetUint64(start&0xffffffff))
	fraction.Mul(fraction, big.NewInt(1_000_000_000))
	got.Add(got, fraction)
	wantScaled := new(big.Int).SetUint64(want)
	wantScaled.Mul(wantScaled, big.NewInt(4_294_967_296))
	difference := new(big.Int).Sub(got, wantScaled)
	if difference.Sign() < 0 {
		difference.Neg(difference)
	}
	// Two half-tick endpoint bounds permit at most one tick of duration error.
	if difference.Cmp(big.NewInt(1_000_000_000)) > 0 {
		t.Fatalf("IPFIX NTP duration residual numerator=%s got-scaled=%s want-scaled=%s", difference, got, wantScaled)
	}
}

func assertFlowTimePacketHeader(t *testing.T, packet []byte, out capturedFlowOutput, origin uint64) {
	t.Helper()
	if out.profile == "netflow-v5-fixed-v1" {
		if len(packet) != 72 || binary.BigEndian.Uint16(packet) != 5 {
			t.Fatalf("v5 packet envelope drift")
		}
		headerStamp := uint64(binary.BigEndian.Uint32(packet[8:12]))*1_000_000_000 + uint64(binary.BigEndian.Uint32(packet[12:16]))
		if headerStamp/1_000_000 < out.consumeBefore/1_000_000 || headerStamp/1_000_000 > out.consumeAfter/1_000_000 {
			t.Fatalf("v5 export/header millisecond=%d outside consume grid [%d,%d]", headerStamp/1_000_000, out.consumeBefore/1_000_000, out.consumeAfter/1_000_000)
		}
		if uint64(binary.BigEndian.Uint32(packet[4:8])) != (headerStamp-origin)/1_000_000 {
			t.Fatalf("v5 origin/header relation drift")
		}
		return
	}
	version, header, templateSet := uint16(10), 16, uint16(2)
	if profileProtocol(out.profile) == "netflow_v9" {
		version, header, templateSet = 9, 20, 0
	}
	if len(packet) < header || binary.BigEndian.Uint16(packet) != version {
		t.Fatalf("%s header version/envelope drift", out.profile)
	}
	hasTemplate, hasData := flowTimePacketKinds(packet, header, templateSet)
	if !hasTemplate && !hasData {
		t.Fatalf("%s packet has no template or data set", out.profile)
	}
	before, after := out.consumeBefore, out.consumeAfter
	if hasTemplate && !hasData {
		before, after = out.startBefore, out.startAfter
	}
	headerSecondsOffset := 4
	identityOffset := 12
	if version == 9 {
		headerSecondsOffset, identityOffset = 8, 16
	}
	headerSeconds := uint64(binary.BigEndian.Uint32(packet[headerSecondsOffset : headerSecondsOffset+4]))
	headerBase := headerSeconds * 1_000_000_000
	if headerBase > after || headerBase+999_999_999 < before {
		t.Fatalf("%s header time=%d outside interval [%d,%d]", out.profile, headerBase, before, after)
	}
	if binary.BigEndian.Uint32(packet[identityOffset:identityOffset+4]) != 42 {
		t.Fatalf("%s header identity drift", out.profile)
	}
	if version == 9 {
		uptime := uint64(binary.BigEndian.Uint32(packet[4:8]))
		if headerBase < origin {
			t.Fatalf("v9 header precedes configured origin")
		}
		exportBase := (headerBase - origin) / 1_000_000
		if uptime < exportBase || uptime > exportBase+999 {
			t.Fatalf("v9 origin/header relation drift")
		}
	}
}

func flowTimePacketKinds(packet []byte, header int, templateSet uint16) (hasTemplate, hasData bool) {
	for off := header; off < len(packet); {
		if len(packet)-off < 4 {
			return false, false
		}
		setID := binary.BigEndian.Uint16(packet[off:])
		setLength := int(binary.BigEndian.Uint16(packet[off+2:]))
		if setLength < 4 || setLength > len(packet)-off {
			return false, false
		}
		if setID == templateSet {
			hasTemplate = true
		} else if setID >= 256 {
			hasData = true
		}
		off += setLength
	}
	return hasTemplate, hasData
}

func flowTimeExpectedTemplate(profile string, ipv6 bool) []literalField {
	var fields []literalField
	switch profile {
	case "netflow-v9-core-v1":
		fields = v9CoreLiteral
	case "netflow-v9-timed-v1":
		fields = v9TimedLiteral
	case "ipfix-core-v1":
		fields = ipfixCoreLiteral
	case "ipfix-general-v1":
		fields = ipfixGeneralLiteral
	}
	fields = append([]literalField(nil), fields...)
	if ipv6 {
		fields[6].id, fields[6].width = 27, 16
		fields[7].id = 29
		fields[10].id, fields[10].width = 28, 16
		fields[11].id = 30
	}
	return fields
}

func assertFlowTimeRecordLiterals(t *testing.T, record map[uint16][]byte, ipv6 bool) {
	t.Helper()
	bytesValue := flowTimeNumeric(record[1])
	packetsValue := flowTimeNumeric(record[2])
	if bytesValue != 700 || packetsValue != 7 || len(record[4]) != 1 || record[4][0] != 6 || binary.BigEndian.Uint16(record[7]) != 12345 || binary.BigEndian.Uint16(record[11]) != 443 {
		t.Fatalf("output endpoint/protocol values drift")
	}
	addressID, destinationID := uint16(8), uint16(12)
	source, destination := net.ParseIP("192.0.2.1").To4(), net.ParseIP("198.51.100.2").To4()
	if ipv6 {
		addressID, destinationID = 27, 28
		source, destination = net.ParseIP("2001:db8::1").To16(), net.ParseIP("2001:db8::2").To16()
	}
	if !bytes.Equal(record[addressID], source) || !bytes.Equal(record[destinationID], destination) {
		t.Fatalf("output endpoint addresses drift")
	}
}

func flowTimeNumeric(value []byte) uint64 {
	var n uint64
	for _, b := range value {
		n = n<<8 | uint64(b)
	}
	return n
}

func outputTemplateFlowTime(t *testing.T, packets [][]byte, profile string, wantID uint16) ([]literalField, bool) {
	t.Helper()
	_, templates := decodeFlowTimePackets(t, packets, profile, true)
	fields, ok := templates[wantID]
	if !ok {
		return nil, false
	}
	return append([]literalField(nil), fields...), true
}

func dataRecordsFlowTime(t *testing.T, packets [][]byte, profile string) []map[uint16][]byte {
	t.Helper()
	records, _ := decodeFlowTimePackets(t, packets, profile, true)
	return records
}

func decodeFlowTimePackets(t *testing.T, packets [][]byte, profile string, checkOutputCatalog bool) ([]map[uint16][]byte, map[uint16][]literalField) {
	t.Helper()
	if profile == "netflow-v5-fixed-v1" {
		if len(packets) == 0 {
			return nil, nil
		}
		for _, p := range packets {
			if len(p) != 72 || binary.BigEndian.Uint16(p) != 5 {
				t.Fatalf("v5 output envelope")
			}
		}
		if len(packets) != 1 {
			t.Fatalf("v5 packets=%d, want 1", len(packets))
		}
		return []map[uint16][]byte{{8: append([]byte(nil), packets[0][48:52]...), 9: append([]byte(nil), packets[0][52:56]...)}}, nil
	}
	version, header, templateSet := flowTimeProfileWire(profile)
	templates := map[uint16][]literalField{}
	var records []map[uint16][]byte
	sawTemplate := false
	for _, p := range packets {
		if len(p) < header || binary.BigEndian.Uint16(p) != version {
			t.Fatalf("%s output version/envelope", profile)
		}
		off := header
		if version == 10 && int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			t.Fatalf("IPFIX length mismatch")
		}
		if off == len(p) {
			t.Fatalf("%s packet has no sets", profile)
		}
		for off < len(p) {
			if len(p)-off < 4 {
				t.Fatalf("%s trailing bytes=%d", profile, len(p)-off)
			}
			sid, n := binary.BigEndian.Uint16(p[off:]), int(binary.BigEndian.Uint16(p[off+2:]))
			if n < 4 || off+n > len(p) {
				t.Fatalf("%s set bounds", profile)
			}
			end := off + n
			if sid == templateSet {
				sawTemplate = true
				parseFlowTimeTemplateSet(t, p[off+4:end], profile, templates, checkOutputCatalog)
			} else if sid < 256 {
				t.Fatalf("%s unknown set ID %d", profile, sid)
			} else if sid >= 256 {
				fs, ok := templates[sid]
				if !ok {
					t.Fatalf("%s data before template %d", profile, sid)
				}
				recordWidth := 0
				for _, f := range fs {
					if f.width == 0 {
						t.Fatalf("%s template %d has zero-width field %d", profile, sid, f.id)
					}
					recordWidth += int(f.width)
				}
				payload := end - (off + 4)
				count := payload / recordWidth
				if count == 0 {
					t.Fatalf("%s data set %d has no complete record", profile, sid)
				}
				if rem := payload % recordWidth; rem != 0 {
					padding := p[end-rem : end]
					if len(padding) > 3 || !flowTimeAllZero(padding) {
						t.Fatalf("%s illegal data padding=%d bytes=%x", profile, rem, padding)
					}
				}
				at := off + 4
				for nrecord := 0; nrecord < count; nrecord++ {
					rec := map[uint16][]byte{}
					for _, f := range fs {
						if at+int(f.width) > end {
							t.Fatalf("%s record width", profile)
						}
						rec[f.id] = append([]byte(nil), p[at:at+int(f.width)]...)
						at += int(f.width)
					}
					records = append(records, rec)
				}
			}
			off = end
		}
	}
	if len(packets) != 0 && !sawTemplate {
		t.Fatalf("%s stream has no template", profile)
	}
	return records, templates
}

func parseFlowTimeTemplateSet(t *testing.T, body []byte, profile string, templates map[uint16][]literalField, checkOutputCatalog bool) {
	t.Helper()
	if len(body) == 0 {
		t.Fatalf("%s empty template set", profile)
	}
	at, added := 0, 0
	for at < len(body) {
		if len(body)-at < 4 {
			if !flowTimeAllZero(body[at:]) {
				t.Fatalf("%s malformed template trailing bytes=%x", profile, body[at:])
			}
			break
		}
		templateID := binary.BigEndian.Uint16(body[at:])
		fieldCount := int(binary.BigEndian.Uint16(body[at+2:]))
		if templateID < 256 || fieldCount < 1 {
			t.Fatalf("%s malformed template ID/count=%d/%d", profile, templateID, fieldCount)
		}
		var want []literalField
		if checkOutputCatalog {
			if templateID != 256 && templateID != 257 {
				t.Fatalf("%s unexpected output template ID %d", profile, templateID)
			}
			want = flowTimeExpectedTemplate(profile, templateID == 257)
			if fieldCount != len(want) {
				t.Fatalf("%s template %d field count=%d, want %d", profile, templateID, fieldCount, len(want))
			}
		}
		at += 4
		if fieldCount > (len(body)-at)/4 {
			t.Fatalf("%s template %d fields exceed set", profile, templateID)
		}
		fields := make([]literalField, 0, fieldCount)
		for i := 0; i < fieldCount; i++ {
			fieldID := binary.BigEndian.Uint16(body[at:])
			fieldWidth := binary.BigEndian.Uint16(body[at+2:])
			if fieldWidth == 0 {
				t.Fatalf("%s template %d field %d has zero width", profile, templateID, fieldID)
			}
			field := literalField{fieldID, fieldWidth}
			if checkOutputCatalog && field != want[i] {
				t.Fatalf("%s template %d field %d=%v, want %v", profile, templateID, i, field, want[i])
			}
			fields = append(fields, field)
			at += 4
		}
		templates[templateID] = fields
		added++
	}
	if added == 0 {
		t.Fatalf("%s template set has no complete template", profile)
	}
}

func flowTimeAllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func flowTimeProfileWire(profile string) (version uint16, header int, templateSet uint16) {
	version, header, templateSet = 10, 16, 2
	if profileProtocol(profile) == "netflow_v9" {
		version, header, templateSet = 9, 20, 0
	}
	return version, header, templateSet
}

func flowTimeInputProfile(tc flowTimeFixture) string {
	if tc.protocol == "netflow_v9" {
		return "netflow-v9-core-v1"
	}
	return "ipfix-core-v1"
}

func flowTimeInputProfileFromVersion(version uint16) string {
	if version == 9 {
		return "netflow-v9-core-v1"
	}
	return "ipfix-core-v1"
}

func flowTimeInputTemplate(tc flowTimeFixture) []literalField {
	fields := []literalField{{8, 4}, {12, 4}, {4, 1}, {7, 2}, {11, 2}, {1, 4}, {2, 4}, {15, 4}}
	if tc.ipv6 {
		fields[0] = literalField{27, 16}
		fields[1] = literalField{28, 16}
		fields[7] = literalField{62, 16}
	}
	for _, field := range tc.fields {
		fields = append(fields, literalField{field.id, uint16(len(field.value))})
	}
	return fields
}

func uint32FieldFlowTime(record map[uint16][]byte, id uint16) uint32 {
	return binary.BigEndian.Uint32(record[id])
}
func uint64FieldFlowTime(record map[uint16][]byte, id uint16) uint64 {
	return binary.BigEndian.Uint64(record[id])
}
