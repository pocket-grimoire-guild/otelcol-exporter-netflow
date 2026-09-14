package netflow5

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

type fixtureFile struct {
	Fixtures []fixtureEntry `json:"fixtures"`
}

type fixtureEntry struct {
	ID          string                     `json:"id"`
	BaseFixture string                     `json:"base_fixture_id"`
	Attributes  map[string]json.RawMessage `json:"attributes"`
	Overrides   fixtureOverrides           `json:"overrides"`
	Metadata    fixtureMetadata            `json:"metadata"`
}

type fixtureOverrides struct {
	Attributes map[string]json.RawMessage `json:"attributes"`
}

type fixtureMetadata struct {
	ConfiguredIDs fixtureIDs `json:"configured_ids"`
	UptimeOrigin  string     `json:"uptime_origin"`
	HeaderInstant string     `json:"reserved_header_instant"`
	SequenceStart uint32     `json:"sequence_start"`
}

type fixtureIDs struct {
	ObservationDomainID uint32 `json:"observation_domain_id"`
	SourceID            uint32 `json:"source_id"`
	EngineType          uint8  `json:"engine_type"`
	EngineID            uint8  `json:"engine_id"`
}

func TestGolden(t *testing.T) {
	request := canonicalRequest(t)
	dst := make([]byte, headerLength+recordLength)
	n, err := (Writer{}).Write(dst, request)
	if err != nil {
		t.Fatalf("canonical v5 write: %v", err)
	}
	if n != len(dst) {
		t.Fatalf("canonical length = %d, want %d", n, len(dst))
	}
	want := readGolden(t)
	if !bytes.Equal(dst, want) {
		t.Fatalf("canonical-v5-ipv4-v1 differs from immutable golden")
	}
	if len(want) != 24+48 {
		t.Fatalf("golden length = %d, want 72 (24-byte header + 48-byte record)", len(want))
	}
	// Cisco Appendix B-3/B-4 offsets and widths are asserted independently of
	// the writer implementation.  In particular both reserved pad regions are
	// required to be zero.
	if got := binary.BigEndian.Uint16(want[0:2]); got != 5 {
		t.Fatalf("version = %d, want 5", got)
	}
	if got := binary.BigEndian.Uint16(want[2:4]); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(want[4:8]); got != 3000 {
		t.Fatalf("sysUptime = %d, want 3000ms", got)
	}
	if got := binary.BigEndian.Uint32(want[8:12]); got != 1788220803 {
		t.Fatalf("unix seconds = %d, want 1788220803", got)
	}
	if got := binary.BigEndian.Uint32(want[12:16]); got != 0 {
		t.Fatalf("unix nanoseconds = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint32(want[16:20]); got != 0 {
		t.Fatalf("sequence = %d, want 0", got)
	}
	if want[20] != 1 || want[21] != 5 || binary.BigEndian.Uint16(want[22:24]) != 1000 {
		t.Fatalf("header engine/sampling bytes = %x, want 01 05 03e8", want[20:24])
	}
	if got := binary.BigEndian.Uint32(want[24:28]); got != 0xc0000201 {
		t.Fatalf("srcaddr = %#x, want 192.0.2.1", got)
	}
	if got := binary.BigEndian.Uint32(want[28:32]); got != 0xc6336402 {
		t.Fatalf("dstaddr = %#x, want 198.51.100.2", got)
	}
	if got := binary.BigEndian.Uint32(want[32:36]); got != 0xc00002fe {
		t.Fatalf("nexthop = %#x, want 192.0.2.254", got)
	}
	if got := binary.BigEndian.Uint16(want[36:38]); got != 10 {
		t.Fatalf("input = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(want[38:40]); got != 20 {
		t.Fatalf("output = %d, want 20", got)
	}
	if got := binary.BigEndian.Uint32(want[40:44]); got != 1234 {
		t.Fatalf("dPkts = %d, want 1234", got)
	}
	if got := binary.BigEndian.Uint32(want[44:48]); got != 56789 {
		t.Fatalf("dOctets = %d, want 56789", got)
	}
	if got := binary.BigEndian.Uint32(want[48:52]); got != 1000 {
		t.Fatalf("First = %d, want 1000ms", got)
	}
	if got := binary.BigEndian.Uint32(want[52:56]); got != 1001 {
		t.Fatalf("Last = %d, want 1001ms", got)
	}
	if got := binary.BigEndian.Uint16(want[56:58]); got != 12345 {
		t.Fatalf("srcport = %d, want 12345", got)
	}
	if got := binary.BigEndian.Uint16(want[58:60]); got != 443 {
		t.Fatalf("dstport = %d, want 443", got)
	}
	if want[60] != 0 || want[70] != 0 || want[71] != 0 {
		t.Fatalf("pad bytes are not zero: pad1=%x pad2=%x", want[60], want[70:72])
	}
	if want[61] != 24 || want[62] != 6 || want[63] != 0 || binary.BigEndian.Uint16(want[64:66]) != 64513 || binary.BigEndian.Uint16(want[66:68]) != 64514 || want[68] != 24 || want[69] != 24 {
		t.Fatalf("record trailing fields have wrong offsets/widths: %x", want[61:70])
	}
}

func TestBoundary(t *testing.T) {
	base := canonicalRequest(t)
	baseRecord := base.Records[0]
	for _, tc := range []struct {
		name  string
		count int
		valid bool
		want  error
	}{
		{"count-0", 0, false, wire.ErrBounds}, {"count-1", 1, true, nil}, {"count-30", 30, true, nil}, {"count-31", 31, false, wire.ErrBounds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := make([]wire.WireRecord, tc.count)
			for i := range records {
				records[i] = baseRecord
			}
			req := cloneRequest(base)
			req.Header.Count = uint16(tc.count)
			req.Records = records
			buf := bytes.Repeat([]byte{0xa5}, headerLength+recordLength*max(1, tc.count))
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, req)
			if tc.valid {
				if err != nil || n != headerLength+recordLength*tc.count {
					t.Fatalf("valid count %d: n=%d err=%v", tc.count, n, err)
				}
				if got := binary.BigEndian.Uint16(buf[2:4]); got != uint16(tc.count) {
					t.Fatalf("valid count %d encoded header count = %d", tc.count, got)
				}
			} else if err == nil || n != 0 || !bytes.Equal(buf, before) {
				t.Fatalf("invalid count %d: n=%d err=%v mutated=%v", tc.count, n, err, !bytes.Equal(buf, before))
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("invalid count %d error = %v, want %v", tc.count, err, tc.want)
			}
		})
	}

	t.Run("short-buffer", func(t *testing.T) {
		buf := bytes.Repeat([]byte{0x5a}, headerLength+recordLength-1)
		before := append([]byte(nil), buf...)
		n, err := (Writer{}).Write(buf, base)
		if err == nil || n != 0 || !bytes.Equal(buf, before) {
			t.Fatalf("short buffer: n=%d err=%v mutated=%v", n, err, !bytes.Equal(buf, before))
		}
		if !errors.Is(err, wire.ErrShortBuffer) {
			t.Fatalf("short buffer error = %v, want %v", err, wire.ErrShortBuffer)
		}
	})
	for _, mode := range []uint8{0, 1, 2, 3} {
		t.Run("sampling-mode-"+string(rune('0'+mode)), func(t *testing.T) {
			req := cloneRequest(base)
			req.Header.SamplingMode = mode
			buf := make([]byte, 72)
			if n, err := (Writer{}).Write(buf, req); err != nil || n != 72 {
				t.Fatalf("mode %d: n=%d err=%v", mode, n, err)
			}
			want := uint16(mode)<<14 | base.Header.SamplingInterval
			if got := binary.BigEndian.Uint16(buf[22:24]); got != want {
				t.Fatalf("mode %d encoded sampling word = %d, want %d", mode, got, want)
			}
		})
	}
	for _, interval := range []uint16{0, 16383} {
		t.Run("sampling-interval-"+string(rune('0'+interval/16383)), func(t *testing.T) {
			req := cloneRequest(base)
			req.Header.SamplingInterval = interval
			buf := make([]byte, 72)
			if n, err := (Writer{}).Write(buf, req); err != nil || n != 72 {
				t.Fatalf("interval %d: n=%d err=%v", interval, n, err)
			}
			if got := binary.BigEndian.Uint16(buf[22:24]); got != (uint16(base.Header.SamplingMode)<<14 | interval) {
				t.Fatalf("interval %d encoded sampling word = %d", interval, got)
			}
		})
	}

	valid := func(name string, want error, mutate func(*wire.PacketRequest)) {
		t.Run(name, func(t *testing.T) {
			req := cloneRequest(base)
			mutate(&req)
			buf := bytes.Repeat([]byte{0xc3}, 72)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, req)
			if err == nil || n != 0 || !bytes.Equal(buf, before) {
				t.Fatalf("n=%d err=%v mutated=%v", n, err, !bytes.Equal(buf, before))
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
	valid("missing-origin", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.HasUptimeOrigin = false })
	valid("source-id-inapplicable", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SourceID = 1 })
	valid("observation-domain-inapplicable", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.ObservationDomainID = 1 })
	valid("export-before-origin", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.ExportTimeUnixNanos = req.Header.UptimeOriginUnixNanos - 1 })
	valid("header-submillisecond", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.ExportTimeUnixNanos++ })
	valid("sampling-mode-overflow", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SamplingMode = 4 })
	valid("sampling-interval-overflow", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SamplingInterval = 16384 })
	valid("export-seconds-overflow", wire.ErrInvalidHeader, func(req *wire.PacketRequest) {
		req.Header.ExportTimeUnixNanos = (uint64(math.MaxUint32) + 1) * 1_000_000_000
	})
	valid("record-start-after-end", wire.ErrInvalidValue, func(req *wire.PacketRequest) {
		req.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(base.Header.ExportTimeUnixNanos), 8, wire.UnixNanosValue(base.Header.UptimeOriginUnixNanos+1_000_000))
	})
	valid("record-after-header", wire.ErrInvalidValue, func(req *wire.PacketRequest) {
		req.Records[0] = recordWith(t, base.Records[0], 8, wire.UnixNanosValue(base.Header.ExportTimeUnixNanos+1_000_000), 7, wire.UnixNanosValue(base.Header.ExportTimeUnixNanos+1_000_000))
	})
	valid("record-submillisecond", wire.ErrInvalidValue, func(req *wire.PacketRequest) {
		req.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(base.Header.UptimeOriginUnixNanos+1_000_001), 8, wire.UnixNanosValue(base.Header.UptimeOriginUnixNanos+2_000_000))
	})
	valid("mask-out-of-range", wire.ErrInvalidValue, func(req *wire.PacketRequest) { req.Records[0] = recordWith(t, base.Records[0], 17, wire.UintValue(33)) })

	t.Run("nonzero-unix-nsecs", func(t *testing.T) {
		req := cloneRequest(base)
		req.Header.ExportTimeUnixNanos += 123_000_000
		buf := make([]byte, 72)
		if n, err := (Writer{}).Write(buf, req); err != nil || n != len(buf) {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if got := binary.BigEndian.Uint32(buf[12:16]); got != 123_000_000 {
			t.Fatalf("unix_nsecs = %d, want 123000000", got)
		}
		if got := binary.BigEndian.Uint32(buf[4:8]); got != 3123 {
			t.Fatalf("sysUptime = %d, want 3123ms", got)
		}
		if got := binary.BigEndian.Uint32(buf[48:52]); got != 1000 {
			t.Fatalf("First = %d, want 1000ms", got)
		}
		if got := binary.BigEndian.Uint32(buf[52:56]); got != 1001 {
			t.Fatalf("Last = %d, want 1001ms", got)
		}
	})
}

func TestMalformed(t *testing.T) {
	base := canonicalRequest(t)
	reject := func(name string, want error, req wire.PacketRequest) {
		t.Run(name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0x7e}, 72)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, req)
			if err == nil || n != 0 || !bytes.Equal(buf, before) {
				t.Fatalf("n=%d err=%v mutated=%v", n, err, !bytes.Equal(buf, before))
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
	req := cloneRequest(base)
	req.Header.Protocol = wire.ProtocolV9
	reject("protocol-mismatch", wire.ErrInvalidShape, req)
	req = cloneRequest(base)
	req.Shape = wire.BuiltinV9().Shapes()[0]
	reject("non-v5-shape", wire.ErrInvalidShape, req)
	req = cloneRequest(base)
	req.Records[0] = mustWireRecord(t, wire.FamilyIPv4, []wire.Value{
		wire.StringValue("not-an-ip"), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UnixNanosValue(base.Header.UptimeOriginUnixNanos), wire.UnixNanosValue(base.Header.UptimeOriginUnixNanos), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0), wire.UintValue(0),
	})
	reject("wrong-address-kind", wire.ErrInvalidValue, req)
	req = cloneRequest(base)
	req.Records[0] = recordWith(t, base.Records[0], 9, wire.UintValue(65536))
	reject("port-width", wire.ErrInvalidValue, req)
	req = cloneRequest(base)
	req.Records[0] = recordWith(t, base.Records[0], 3, wire.UintValue(65536))
	reject("interface-width", wire.ErrInvalidValue, req)
	validMax := cloneRequest(base)
	validMax.Records[0] = recordWith(t, base.Records[0], 5, wire.UintValue(math.MaxUint32))
	buf := make([]byte, 72)
	if n, err := (Writer{}).Write(buf, validMax); err != nil || n != len(buf) || binary.BigEndian.Uint32(buf[40:44]) != math.MaxUint32 {
		t.Fatalf("dPkts MaxUint32: n=%d err=%v encoded=%d", n, err, binary.BigEndian.Uint32(buf[40:44]))
	}
	req = cloneRequest(base)
	req.Records[0] = recordWith(t, base.Records[0], 5, wire.UintValue(uint64(math.MaxUint32)+1))
	reject("counter-width", wire.ErrInvalidValue, req)
	req = cloneRequest(base)
	req.Records[0] = recordWith(t, base.Records[0], 13, wire.UintValue(256))
	reject("protocol-width", wire.ErrInvalidValue, req)
	req = cloneRequest(base)
	req.Records[0] = recordWith(t, base.Records[0], 15, wire.UintValue(65536))
	reject("as-width", wire.ErrInvalidValue, req)
	req = cloneRequest(base)
	req.Header.Count = 2
	reject("header-count-mismatch", wire.ErrInvalidHeader, req)

	// Every rejection class above uses a fully initialized nonzero buffer and
	// checks the entire slice, proving no header or record prefix was written.
}

func TestAllocations(t *testing.T) {
	req := canonicalRequest(t)
	dst := make([]byte, 72)
	allocs := testing.AllocsPerRun(1000, func() {
		n, err := (Writer{}).Write(dst, req)
		if err != nil || n != len(dst) {
			t.Fatalf("write: n=%d err=%v", n, err)
		}
	})
	if allocs != 0 {
		t.Fatalf("Write allocations = %v, want 0", allocs)
	}
}

func canonicalRequest(t *testing.T) wire.PacketRequest {
	t.Helper()
	entry, attrs := canonicalFixture(t)
	shape, ok := wire.BuiltinV5().ShapeAt(0)
	if !ok {
		t.Fatal("missing built-in v5 shape")
	}
	source := parseIPv4(t, attrs, "source.address")
	destination := parseIPv4(t, attrs, "destination.address")
	nextHop := parseIPv4(t, attrs, "flow.next_hop")
	values := []wire.Value{
		source, destination, nextHop,
		wire.UintValue(attrUint(t, attrs, "flow.in_if")), wire.UintValue(attrUint(t, attrs, "flow.out_if")),
		wire.UintValue(attrUint(t, attrs, "flow.io.packets")), wire.UintValue(attrUint(t, attrs, "flow.io.bytes")),
		wire.UnixNanosValue(attrUint(t, attrs, "flow.start")), wire.UnixNanosValue(attrUint(t, attrs, "flow.end")),
		wire.UintValue(attrUint(t, attrs, "source.port")), wire.UintValue(attrUint(t, attrs, "destination.port")),
		wire.UintValue(0), wire.UintValue(attrUint(t, attrs, "flow.tcp_flags")), wire.UintValue(6),
		wire.UintValue(attrUint(t, attrs, "flow.ip_tos")), wire.UintValue(attrUint(t, attrs, "flow.src_as")), wire.UintValue(attrUint(t, attrs, "flow.dst_as")),
		wire.UintValue(attrUint(t, attrs, "flow.src_net")), wire.UintValue(attrUint(t, attrs, "flow.dst_net")), wire.UintValue(0),
	}
	record := mustWireRecord(t, wire.FamilyIPv4, values)
	uptime := parseTime(t, entry.Metadata.UptimeOrigin)
	headerTime := parseTime(t, entry.Metadata.HeaderInstant)
	if entry.Metadata.ConfiguredIDs.SourceID != 0 || entry.Metadata.ConfiguredIDs.ObservationDomainID != 0 {
		t.Fatal("v5 fixture unexpectedly has source/domain identity")
	}
	if attrString(t, attrs, "network.transport") != "tcp" {
		t.Fatalf("fixture network.transport changed")
	}
	return wire.PacketRequest{
		Header: wire.HeaderMetadata{Protocol: wire.ProtocolV5, Sequence: entry.Metadata.SequenceStart, SourceID: entry.Metadata.ConfiguredIDs.SourceID, ObservationDomainID: entry.Metadata.ConfiguredIDs.ObservationDomainID, EngineType: entry.Metadata.ConfiguredIDs.EngineType, EngineID: entry.Metadata.ConfiguredIDs.EngineID, SamplingMode: 0, SamplingInterval: uint16(attrUint(t, attrs, "flow.sampling_rate")), Count: 1, ExportTimeUnixNanos: headerTime, UptimeOriginUnixNanos: uptime, HasUptimeOrigin: true},
		Shape:  shape, Records: []wire.WireRecord{record},
	}
}

func canonicalFixture(t *testing.T) (fixtureEntry, map[string]json.RawMessage) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../integration/testdata/canonical/fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureFile
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]fixtureEntry, len(manifest.Fixtures))
	for _, entry := range manifest.Fixtures {
		entries[entry.ID] = entry
	}
	entry, ok := entries["canonical-v5-ipv4-v1"]
	if !ok {
		t.Fatal("fixture canonical-v5-ipv4-v1 missing")
	}
	base, ok := entries[entry.BaseFixture]
	if !ok {
		t.Fatalf("base fixture %q missing", entry.BaseFixture)
	}
	attrs := make(map[string]json.RawMessage, len(base.Attributes)+len(entry.Overrides.Attributes))
	for key, value := range base.Attributes {
		attrs[key] = value
	}
	for key, value := range entry.Overrides.Attributes {
		attrs[key] = value
	}
	return entry, attrs
}

func readGolden(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../integration/testdata/golden/v5/canonical-ipv4-v1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func parseIPv4(t *testing.T, attrs map[string]json.RawMessage, key string) wire.Value {
	value, err := wire.ParseIPv4Value(attrString(t, attrs, key))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return value
}

func attrString(t *testing.T, attrs map[string]json.RawMessage, key string) string {
	raw, ok := attrs[key]
	if !ok {
		t.Fatalf("fixture attribute %q missing", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("fixture attribute %q: %v", key, err)
	}
	return value
}

func attrUint(t *testing.T, attrs map[string]json.RawMessage, key string) uint64 {
	raw, ok := attrs[key]
	if !ok {
		t.Fatalf("fixture attribute %q missing", key)
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("fixture attribute %q: %v", key, err)
	}
	return value
}

func parseTime(t *testing.T, value string) uint64 {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("fixture time %q: %v", value, err)
	}
	return uint64(parsed.UnixNano())
}

func mustWireRecord(t *testing.T, family wire.Family, values []wire.Value) wire.WireRecord {
	record, err := wire.NewWireRecord(family, values)
	if err != nil {
		t.Fatalf("wire record: %v", err)
	}
	return record
}

func recordWith(t *testing.T, source wire.WireRecord, index int, value wire.Value, extra ...interface{}) wire.WireRecord {
	values := source.Values()
	values[index] = value
	for i := 0; i+1 < len(extra); i += 2 {
		values[extra[i].(int)] = extra[i+1].(wire.Value)
	}
	return mustWireRecord(t, source.Family(), values)
}

func cloneRequest(source wire.PacketRequest) wire.PacketRequest {
	clone := source
	clone.Records = append([]wire.WireRecord(nil), source.Records...)
	return clone
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
