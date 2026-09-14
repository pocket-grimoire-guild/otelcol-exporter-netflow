package netflow9

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	templateFlowSetLength = 80
	ipv4RecordLength      = 43
	ipv6RecordLength      = 67
)

type fixtureManifest struct {
	Fixtures []fixtureEntry `json:"fixtures"`
}

type fixtureEntry struct {
	ID          string                     `json:"id"`
	BaseFixture string                     `json:"base_fixture_id"`
	Protocol    string                     `json:"protocol"`
	Shape       string                     `json:"shape"`
	Attributes  map[string]json.RawMessage `json:"attributes"`
	Overrides   fixtureOverrides           `json:"overrides"`
	Metadata    fixtureMetadata            `json:"metadata"`
	Records     []fixtureRecord            `json:"records"`
}

type fixtureRecord struct {
	Overrides fixtureOverrides `json:"overrides"`
}

type fixtureOverrides struct {
	Attributes       map[string]json.RawMessage `json:"attributes"`
	RemoveAttributes []string                   `json:"remove_attributes"`
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
	for _, tc := range []struct {
		fixture string
		golden  string
		length  int
		family  wire.Family
		count   uint16
		source  uint32
	}{
		{fixture: "canonical-ipv4-v1", golden: "canonical-ipv4-v1.bin", length: 148, family: wire.FamilyIPv4, count: 2, source: 42},
		{fixture: "canonical-ipv6-v1", golden: "canonical-ipv6-v1.bin", length: 172, family: wire.FamilyIPv6, count: 2, source: 43},
		{fixture: "sampling-ie34-two-distinct-rates-v9-v1", golden: "sampling-ie34-two-distinct-rates-v1.bin", length: 192, family: wire.FamilyIPv4, count: 3, source: 47},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			req := fixtureRequest(t, tc.fixture)
			if req.Shape.Family() != tc.family || req.Header.Count != tc.count || req.Header.SourceID != tc.source {
				t.Fatalf("fixture request shape/header drift: family=%v count=%d source=%d", req.Shape.Family(), req.Header.Count, req.Header.SourceID)
			}
			got := make([]byte, tc.length)
			n, err := (Writer{}).Write(got, req)
			if err != nil || n != tc.length {
				t.Fatalf("write = (%d,%v), want (%d,nil)", n, err, tc.length)
			}
			want := readGolden(t, tc.golden)
			if len(want) != tc.length {
				t.Fatalf("golden length = %d, want %d", len(want), tc.length)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("writer output differs from immutable golden")
			}
			assertIndependentPacket(t, want, tc.family, tc.count, tc.source, len(req.Records))
		})
	}
}

func assertIndependentPacket(t *testing.T, packet []byte, family wire.Family, count uint16, source uint32, records int) {
	t.Helper()
	if binary.BigEndian.Uint16(packet[0:2]) != 9 {
		t.Fatalf("version = %d, want 9", binary.BigEndian.Uint16(packet[0:2]))
	}
	if binary.BigEndian.Uint16(packet[2:4]) != count {
		t.Fatalf("count = %d, want %d", binary.BigEndian.Uint16(packet[2:4]), count)
	}
	if binary.BigEndian.Uint32(packet[4:8]) != 3000 {
		t.Fatalf("sysUptime = %d, want 3000ms", binary.BigEndian.Uint32(packet[4:8]))
	}
	if binary.BigEndian.Uint32(packet[8:12]) != 1788220803 {
		t.Fatalf("unix seconds = %d, want 1788220803", binary.BigEndian.Uint32(packet[8:12]))
	}
	if binary.BigEndian.Uint32(packet[12:16]) != 0 {
		t.Fatalf("sequence = %d, want 0", binary.BigEndian.Uint32(packet[12:16]))
	}
	if binary.BigEndian.Uint32(packet[16:20]) != source {
		t.Fatalf("source ID = %d, want %d", binary.BigEndian.Uint32(packet[16:20]), source)
	}

	// RFC 3954 §5.2: Set ID 0, length 80, then template ID, field count,
	// and eighteen independent two-byte type/length pairs.
	if binary.BigEndian.Uint16(packet[20:22]) != 0 || binary.BigEndian.Uint16(packet[22:24]) != templateFlowSetLength {
		t.Fatalf("template FlowSet header = %x, want 0000 0050", packet[20:24])
	}
	templateID := binary.BigEndian.Uint16(packet[24:26])
	if templateID != 256 && templateID != 257 {
		t.Fatalf("template ID = %d, want 256/257", templateID)
	}
	if binary.BigEndian.Uint16(packet[26:28]) != 18 {
		t.Fatalf("template field count = %d, want 18", binary.BigEndian.Uint16(packet[26:28]))
	}
	addressType := uint16(8)
	maskTypes := []uint16{9, 13}
	addressLength := uint16(4)
	if family == wire.FamilyIPv6 {
		addressType = 27
		maskTypes = []uint16{29, 30}
		addressLength = 16
	}
	destinationType := uint16(12)
	if family == wire.FamilyIPv6 {
		destinationType = 28
	}
	wantTypes := []uint16{1, 2, 4, 5, 6, 7, addressType, maskTypes[0], 10, 11, destinationType, maskTypes[1], 14, 16, 17, 34, 52, 60}
	wantLengths := []uint16{4, 4, 1, 1, 1, 2, addressLength, 1, 2, 2, addressLength, 1, 2, 4, 4, 4, 1, 1}
	for i := range wantTypes {
		offset := 28 + i*4
		if got := binary.BigEndian.Uint16(packet[offset : offset+2]); got != wantTypes[i] {
			t.Fatalf("template field %d type = %d, want %d", i, got, wantTypes[i])
		}
		if got := binary.BigEndian.Uint16(packet[offset+2 : offset+4]); got != wantLengths[i] {
			t.Fatalf("template field %d length = %d, want %d", i, got, wantLengths[i])
		}
	}

	dataOffset := 20 + templateFlowSetLength
	dataLength := uint16(48)
	recordLength := ipv4RecordLength
	if family == wire.FamilyIPv6 {
		dataLength = 72
		recordLength = ipv6RecordLength
	}
	if records == 2 {
		dataLength = 92
	}
	if binary.BigEndian.Uint16(packet[dataOffset:dataOffset+2]) != templateID || binary.BigEndian.Uint16(packet[dataOffset+2:dataOffset+4]) != dataLength {
		t.Fatalf("data FlowSet header = %x, want ID %d length %d", packet[dataOffset:dataOffset+4], templateID, dataLength)
	}
	first := dataOffset + 4
	if got := binary.BigEndian.Uint32(packet[first : first+4]); got != 56789 {
		t.Fatalf("IN_BYTES = %d, want 56789", got)
	}
	if got := binary.BigEndian.Uint32(packet[first+4 : first+8]); got != 1234 {
		t.Fatalf("IN_PKTS = %d, want 1234", got)
	}
	if packet[first+8] != 6 || packet[first+9] != 0 || packet[first+10] != 24 {
		t.Fatalf("protocol/tos/tcp flags = %x, want 06 00 18", packet[first+8:first+11])
	}
	if got := binary.BigEndian.Uint16(packet[first+11 : first+13]); got != 12345 {
		t.Fatalf("source port = %d, want 12345", got)
	}
	if family == wire.FamilyIPv4 {
		if got := binary.BigEndian.Uint32(packet[first+13 : first+17]); got != 0xc0000201 {
			t.Fatalf("source address = %#x, want 192.0.2.1", got)
		}
		if packet[first+17] != 24 || binary.BigEndian.Uint16(packet[first+18:first+20]) != 10 || binary.BigEndian.Uint16(packet[first+20:first+22]) != 443 {
			t.Fatalf("source mask/interface/dest port offsets drift: %x", packet[first+17:first+22])
		}
		if got := binary.BigEndian.Uint32(packet[first+22 : first+26]); got != 0xc6336402 {
			t.Fatalf("destination address = %#x, want 198.51.100.2", got)
		}
		if packet[first+26] != 24 || binary.BigEndian.Uint16(packet[first+27:first+29]) != 20 {
			t.Fatalf("destination mask/output interface = %x", packet[first+26:first+29])
		}
		if binary.BigEndian.Uint32(packet[first+29:first+33]) != 64513 || binary.BigEndian.Uint32(packet[first+33:first+37]) != 64514 || binary.BigEndian.Uint32(packet[first+37:first+41]) != 1000 || packet[first+41] != 64 || packet[first+42] != 4 {
			t.Fatalf("IPv4 trailing fields drift: %x", packet[first+29:first+43])
		}
	} else {
		if got := netip.AddrFrom16([16]byte(packet[first+13 : first+29])).String(); got != "2001:db8::1" {
			t.Fatalf("source IPv6 address = %s", got)
		}
		if packet[first+29] != 64 || binary.BigEndian.Uint16(packet[first+30:first+32]) != 10 || binary.BigEndian.Uint16(packet[first+32:first+34]) != 443 {
			t.Fatalf("IPv6 source mask/interface/dest port offsets drift: %x", packet[first+29:first+34])
		}
		if got := netip.AddrFrom16([16]byte(packet[first+34 : first+50])).String(); got != "2001:db8::2" {
			t.Fatalf("destination IPv6 address = %s", got)
		}
		if packet[first+50] != 64 || binary.BigEndian.Uint16(packet[first+51:first+53]) != 20 || binary.BigEndian.Uint32(packet[first+53:first+57]) != 64513 || binary.BigEndian.Uint32(packet[first+57:first+61]) != 64514 || binary.BigEndian.Uint32(packet[first+61:first+65]) != 1000 || packet[first+65] != 64 || packet[first+66] != 6 {
			t.Fatalf("IPv6 trailing fields drift: %x", packet[first+50:first+67])
		}
	}
	if records == 1 {
		if packet[first+recordLength] != 0 {
			t.Fatalf("single-record FlowSet padding = %x, want zero", packet[first+recordLength])
		}
	} else if records == 2 {
		second := first + ipv4RecordLength
		if got := binary.BigEndian.Uint32(packet[second+37 : second+41]); got != 2000 {
			t.Fatalf("second ordinary type-34 value = %d, want 2000", got)
		}
		if packet[second+43] != 0 || packet[second+44] != 0 {
			t.Fatalf("two-record FlowSet padding = %x, want two zero bytes", packet[second+43:second+45])
		}
	}
}

func TestBoundary(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	headerOnly := base
	headerOnly.Header.Count = 0
	headerOnly.TemplateRecords = 0
	headerOnly.TemplateBytes = 0
	headerOnly.Records = nil
	for _, tc := range []struct {
		name string
		cap  int
		ok   bool
	}{
		{name: "19-byte-header", cap: 19},
		{name: "20-byte-header", cap: 20, ok: true},
		{name: "21-byte-header-tail", cap: 21, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xa5}, tc.cap)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, headerOnly)
			if tc.ok {
				if err != nil || n != headerLength {
					t.Fatalf("header-only = (%d,%v), want (%d,nil)", n, err, headerLength)
				}
				if tc.cap == 21 && buf[20] != 0xa5 {
					t.Fatal("oversized caller tail was changed")
				}
			} else if err == nil || n != 0 || !bytes.Equal(buf, before) || !errors.Is(err, wire.ErrShortBuffer) {
				t.Fatalf("short header = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
			}
		})
	}

	shape := customByteShape(t)
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolV9, Count: 2, HasUptimeOrigin: true}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
	size, err := shape.DataSetSize(req.Records)
	if err != nil || size.Length() != 5 || size.Padding() != 0 {
		t.Fatalf("real five-byte single-record FlowSet size = (%d,%d,%v), want (5,0,nil)", size.Length(), size.Padding(), err)
	}
	buf := bytes.Repeat([]byte{0xc3}, 37)
	wantFiveByte := []byte{
		0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x01, 0x2c, 0x00, 0x01, 0x9c, 0x40, 0x00, 0x01,
		0x01, 0x2c, 0x00, 0x05, 0x01,
	}
	if n, err := (Writer{}).Write(buf, req); err != nil || n != len(wantFiveByte) || !bytes.Equal(buf, wantFiveByte) {
		t.Fatalf("fixed one-byte v9 FlowSet = (%d,%v) bytes=%x, want (%d,nil) %x", n, err, buf, len(wantFiveByte), wantFiveByte)
	}
	short := bytes.Repeat([]byte{0xd4}, len(wantFiveByte)-1)
	before := append([]byte(nil), short...)
	if n, err := (Writer{}).Write(short, req); n != 0 || !errors.Is(err, wire.ErrShortBuffer) || !bytes.Equal(short, before) {
		t.Fatalf("fixed one-byte v9 short buffer = (%d,%v), mutated=%v", n, err, !bytes.Equal(short, before))
	}
	// For a fixed four-byte v9 record, 65532 is the largest aligned FlowSet
	// length reachable under the 16-bit set ceiling; 65535 is not aligned.
	wide := privateUint32Shape(t, 301)
	wideRecord, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	nearMaxRecords := make([]wire.WireRecord, 16382) // 4 + 16382*4 = 65532
	for i := range nearMaxRecords {
		nearMaxRecords[i] = wideRecord
	}
	nearMax, err := wide.DataSetSize(nearMaxRecords)
	if err != nil || nearMax.Length() != 65532 || nearMax.Padding() != 0 {
		t.Fatalf("near-max fixed FlowSet size = (%d,%d,%v), want (65532,0,nil)", nearMax.Length(), nearMax.Padding(), err)
	}
	tooLargeRecords := append(append([]wire.WireRecord(nil), nearMaxRecords...), wideRecord)
	if _, err := wide.DataSetSize(tooLargeRecords); !errors.Is(err, wire.ErrBounds) {
		t.Fatalf("fixed FlowSet arithmetic at 65536 = %v, want %v", err, wire.ErrBounds)
	}
	if (65535-4)%4 == 0 {
		t.Fatal("65535 unexpectedly aligned for fixed four-byte v9 records")
	}
	// A caller cannot smuggle a declared FlowSet length around the checked
	// record arithmetic.  These malformed declarations cover the protocol's
	// lower/header-only edge and the uint16 upper edge before any write.
	for _, declared := range []uint64{4, 5, 65535, 65536} {
		t.Run("declared-set-length-"+itoa(declared), func(t *testing.T) {
			bad := headerOnly
			bad.DataBytes = declared
			buf := bytes.Repeat([]byte{0xd4}, 148)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, bad)
			if n != 0 || err == nil || !errors.Is(err, wire.ErrBounds) || !bytes.Equal(buf, before) {
				t.Fatalf("declared set length %d = (%d,%v), mutated=%v", declared, n, err, !bytes.Equal(buf, before))
			}
		})
	}
}

func TestMalformed(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	reject := func(name string, want error, mutate func(*wire.PacketRequest)) {
		t.Run(name, func(t *testing.T) {
			req := cloneRequest(base)
			mutate(&req)
			buf := bytes.Repeat([]byte{0x7e}, 148)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, req)
			if err == nil || n != 0 || !bytes.Equal(buf, before) {
				t.Fatalf("rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
	reject("protocol-mismatch", wire.ErrInvalidShape, func(req *wire.PacketRequest) { req.Header.Protocol = wire.ProtocolV5 })
	reject("missing-uptime-origin", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.HasUptimeOrigin = false })
	reject("origin-after-export", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.UptimeOriginUnixNanos = req.Header.ExportTimeUnixNanos + 1 })
	reject("submillisecond-uptime", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.ExportTimeUnixNanos++ })
	reject("unix-seconds-overflow", wire.ErrInvalidHeader, func(req *wire.PacketRequest) {
		req.Header.ExportTimeUnixNanos = (uint64(math.MaxUint32) + 1) * nanosPerSec
	})
	reject("observation-domain-mismatch", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.ObservationDomainID++ })
	reject("v5-sampling-header", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SamplingInterval = 1 })
	reject("count-mismatch", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.Count = 1 })
	reject("template-byte-mismatch", wire.ErrInvalidShape, func(req *wire.PacketRequest) { req.TemplateBytes-- })
	reject("wrong-value-kind", wire.ErrInvalidValue, func(req *wire.PacketRequest) {
		req.Records[0] = recordWith(t, req.Records[0], 0, wire.StringValue("not-a-counter"))
	})
	reject("counter-width", wire.ErrInvalidValue, func(req *wire.PacketRequest) {
		req.Records[0] = recordWith(t, req.Records[0], 0, wire.UintValue(uint64(math.MaxUint32)+1))
	})
	reject("wrong-family", wire.ErrInvalidFamily, func(req *wire.PacketRequest) {
		values := req.Records[0].Values()
		source, err := wire.ParseIPv6Value("2001:db8::1")
		if err != nil {
			t.Fatal(err)
		}
		destination, err := wire.ParseIPv6Value("2001:db8::2")
		if err != nil {
			t.Fatal(err)
		}
		values[6], values[10] = source, destination
		req.Records[0], err = wire.NewWireRecord(wire.FamilyIPv6, values)
		if err != nil {
			t.Fatalf("valid IPv6 record construction: %v", err)
		}
	})

	t.Run("invalid-options-shape", func(t *testing.T) {
		descriptor, err := wire.NewV9PrivateDescriptor("vendor.counter", 40000, wire.EncodingUnsigned32, 4)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 4, TemplateBytes: 12, Options: true})
		if err == nil || shape.Protocol() != wire.ProtocolUnknown {
			t.Fatalf("Options shape unexpectedly accepted: shape=%+v err=%v", shape, err)
		}
	})

	// A bad later record must be rejected before the first header byte is
	// touched, even when its preceding sibling is fully valid.
	t.Run("late-record-no-partial-output", func(t *testing.T) {
		req := cloneRequest(base)
		req.Records = append(req.Records, req.Records[0])
		req.Header.Count = 3
		req.Records[1] = recordWith(t, req.Records[1], 16, wire.UintValue(uint64(math.MaxUint32)+1))
		buf := bytes.Repeat([]byte{0x91}, 256)
		before := append([]byte(nil), buf...)
		n, err := (Writer{}).Write(buf, req)
		if n != 0 || err == nil || !bytes.Equal(buf, before) {
			t.Fatalf("late rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
		}
	})

	t.Run("timestamp-conversion-and-gates", func(t *testing.T) {
		origin := uint64(1_700_000_000) * nanosPerSec
		start := origin + 1234*nanosPerMS
		end := origin + 2345*nanosPerMS
		timeShape := timestampShape(t,
			wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowStart, ID: 22, Length: 4, Encoding: wire.EncodingUnsigned32},
			wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowEnd, ID: 21, Length: 4, Encoding: wire.EncodingUnsigned32},
		)
		req := timestampRequest(t, timeShape, origin, start, end, origin+3000*nanosPerMS)
		buf := make([]byte, 48)
		if n, err := (Writer{}).Write(buf, req); err != nil || n != len(buf) {
			t.Fatalf("timestamp write = (%d,%v), want (%d,nil)", n, err, len(buf))
		}
		data := 20 + int(timeShape.TemplateBytes())
		if got := binary.BigEndian.Uint32(buf[data+4 : data+8]); got != 1234 {
			t.Fatalf("FIRST_SWITCHED = %d, want 1234ms (absolute value was not converted)", got)
		}
		if got := binary.BigEndian.Uint32(buf[data+8 : data+12]); got != 2345 {
			t.Fatalf("LAST_SWITCHED = %d, want 2345ms (absolute value was not converted)", got)
		}

		reject := func(name string, want error, candidate wire.PacketRequest) {
			t.Run(name, func(t *testing.T) {
				bad := bytes.Repeat([]byte{0x6d}, 96)
				before := append([]byte(nil), bad...)
				n, err := (Writer{}).Write(bad, candidate)
				if n != 0 || err == nil || !bytes.Equal(bad, before) {
					t.Fatalf("timestamp rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(bad, before))
				}
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("timestamp error = %v, want %v", err, want)
				}
			})
		}

		missingOrigin := req
		missingOrigin.Header.HasUptimeOrigin = false
		reject("missing-origin", wire.ErrInvalidHeader, missingOrigin)
		preOrigin := req
		preOrigin.Records = []wire.WireRecord{recordWith(t, req.Records[0], 0, wire.UnixNanosValue(origin-nanosPerMS))}
		reject("pre-origin", wire.ErrInvalidValue, preOrigin)
		subMillisecond := req
		subMillisecond.Records = []wire.WireRecord{recordWith(t, req.Records[0], 0, wire.UnixNanosValue(origin+1))}
		reject("sub-millisecond", wire.ErrInvalidValue, subMillisecond)
		endSubMillisecond := req
		endSubMillisecond.Records = []wire.WireRecord{recordWith(t, req.Records[0], 1, wire.UnixNanosValue(origin+2))}
		reject("end-sub-millisecond", wire.ErrInvalidValue, endSubMillisecond)
		afterHeader := req
		afterHeader.Records = []wire.WireRecord{recordWith(t, req.Records[0], 0, wire.UnixNanosValue(origin+3001*nanosPerMS))}
		reject("after-header-sysuptime", wire.ErrInvalidValue, afterHeader)
		endAfterHeader := req
		endAfterHeader.Records = []wire.WireRecord{recordWith(t, req.Records[0], 1, wire.UnixNanosValue(origin+3001*nanosPerMS))}
		reject("end-after-header-sysuptime", wire.ErrInvalidValue, endAfterHeader)
		aboveUint32 := req
		aboveUint32.Header.ExportTimeUnixNanos = origin + uint64(math.MaxUint32)*nanosPerMS
		aboveUint32.Records = []wire.WireRecord{recordWith(t, req.Records[0], 0, wire.UnixNanosValue(origin+(uint64(math.MaxUint32)+1)*nanosPerMS))}
		reject("elapsed-over-uint32", wire.ErrInvalidValue, aboveUint32)
		ordered := timestampRequest(t, timeShape, origin, origin+2500*nanosPerMS, origin+2000*nanosPerMS, origin+3000*nanosPerMS)
		reject("start-after-end", wire.ErrInvalidValue, ordered)

		wrongIDShape := timestampShape(t, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowStart, ID: 23, Length: 4, Encoding: wire.EncodingUnsigned32})
		reject("start-wrong-id", wire.ErrInvalidDescriptor, timestampRequest(t, wrongIDShape, origin, start, end, origin+3000*nanosPerMS))
		wrongEndIDShape := timestampShape(t, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowEnd, ID: 24, Length: 4, Encoding: wire.EncodingUnsigned32})
		reject("end-wrong-id", wire.ErrInvalidDescriptor, timestampRequest(t, wrongEndIDShape, origin, start, end, origin+3000*nanosPerMS))
		wrongEncodingShape := timestampShape(t, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowStart, ID: 22, Length: 2, Encoding: wire.EncodingUnsigned16})
		reject("start-wrong-width-encoding", wire.ErrInvalidDescriptor, timestampRequest(t, wrongEncodingShape, origin, start, end, origin+3000*nanosPerMS))
		receivedShape := timestampShape(t, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowTimeReceived, ID: 20, Length: 4, Encoding: wire.EncodingUnsigned32})
		reject("canonical-time-received", wire.ErrInvalidShape, timestampRequest(t, receivedShape, origin, start, end, origin+3000*nanosPerMS))
	})
}

func TestPrivateDescriptor(t *testing.T) {
	descriptor, err := wire.NewV9PrivateDescriptor("vendor.counter", 40000, wire.EncodingUnsigned32, 4)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 4, TemplateBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(0x01020304)})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolV9, SourceID: 9, Count: 2, ExportTimeUnixNanos: 3 * nanosPerSec, UptimeOriginUnixNanos: 0, HasUptimeOrigin: true}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: 12}
	buf := make([]byte, 40)
	n, err := (Writer{}).Write(buf, req)
	if err != nil || n != 40 {
		t.Fatalf("private write = (%d,%v), want (40,nil)", n, err)
	}
	if binary.BigEndian.Uint16(buf[20:22]) != 0 || binary.BigEndian.Uint16(buf[22:24]) != 12 || binary.BigEndian.Uint16(buf[24:26]) != 300 || binary.BigEndian.Uint16(buf[26:28]) != 1 || binary.BigEndian.Uint16(buf[28:30]) != 40000 || binary.BigEndian.Uint16(buf[30:32]) != 4 {
		t.Fatalf("private template descriptor bytes = %x", buf[20:32])
	}
	if binary.BigEndian.Uint16(buf[32:34]) != 300 || binary.BigEndian.Uint16(buf[34:36]) != 8 || !bytes.Equal(buf[36:40], []byte{1, 2, 3, 4}) {
		t.Fatalf("private data FlowSet bytes = %x", buf[32:40])
	}
}

func TestAllocations(t *testing.T) {
	tests := []struct {
		name string
		req  wire.PacketRequest
		size int
	}{
		{name: "ipv4", req: fixtureRequest(t, "canonical-ipv4-v1"), size: 148},
		{name: "ipv6", req: fixtureRequest(t, "canonical-ipv6-v1"), size: 172},
	}
	privateShape := privateUint32Shape(t, 302)
	privateRecord, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(0x01020304)})
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name string
		req  wire.PacketRequest
		size int
	}{
		name: "private",
		req: wire.PacketRequest{
			Header:          wire.HeaderMetadata{Protocol: wire.ProtocolV9, SourceID: 9, Count: 2, ExportTimeUnixNanos: 3 * nanosPerSec, HasUptimeOrigin: true},
			Shape:           privateShape,
			Records:         []wire.WireRecord{privateRecord},
			TemplateRecords: 1,
			TemplateBytes:   privateShape.TemplateBytes(),
		},
		size: 40,
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, tc.size)
			allocs := testing.AllocsPerRun(1000, func() {
				n, err := (Writer{}).Write(dst, tc.req)
				if err != nil || n != len(dst) {
					t.Fatalf("write: n=%d err=%v", n, err)
				}
			})
			if allocs != 0 {
				t.Fatalf("Write allocations = %v, want 0", allocs)
			}
		})
	}
}

func fixtureRequest(t *testing.T, id string) wire.PacketRequest {
	t.Helper()
	entry, attrs := fixtureAttrs(t, id)
	shapeIndex := 0
	family := wire.FamilyIPv4
	if entry.Shape == "ipv6-core-v1" {
		shapeIndex = 1
		family = wire.FamilyIPv6
	}
	shape, ok := wire.BuiltinV9().ShapeAt(shapeIndex)
	if !ok {
		t.Fatalf("missing built-in shape for %s", entry.Shape)
	}
	build := func(values map[string]json.RawMessage) wire.WireRecord {
		ordered := make([]wire.Value, shape.FieldCount())
		for i := range ordered {
			descriptor, _ := shape.DescriptorAt(i)
			ordered[i] = fixtureValue(t, values, descriptor.Field, family)
		}
		record, err := wire.NewWireRecord(family, ordered)
		if err != nil {
			t.Fatalf("wire record %s: %v", id, err)
		}
		return record
	}
	records := []wire.WireRecord{build(attrs)}
	if len(entry.Records) != 0 {
		records = records[:0]
		for _, item := range entry.Records {
			recordAttrs := cloneAttrs(attrs)
			applyOverrides(recordAttrs, item.Overrides)
			records = append(records, build(recordAttrs))
		}
	}
	origin := parseTime(t, entry.Metadata.UptimeOrigin)
	headerTime := parseTime(t, entry.Metadata.HeaderInstant)
	return wire.PacketRequest{
		Header: wire.HeaderMetadata{
			Protocol:              wire.ProtocolV9,
			Sequence:              entry.Metadata.SequenceStart,
			ObservationDomainID:   entry.Metadata.ConfiguredIDs.ObservationDomainID,
			SourceID:              entry.Metadata.ConfiguredIDs.SourceID,
			EngineType:            entry.Metadata.ConfiguredIDs.EngineType,
			EngineID:              entry.Metadata.ConfiguredIDs.EngineID,
			Count:                 uint16(1 + len(records)),
			ExportTimeUnixNanos:   headerTime,
			UptimeOriginUnixNanos: origin,
			HasUptimeOrigin:       true,
		},
		Shape:           shape,
		Records:         records,
		TemplateRecords: 1,
		TemplateBytes:   shape.TemplateBytes(),
	}
}

func fixtureAttrs(t *testing.T, id string) (fixtureEntry, map[string]json.RawMessage) {
	t.Helper()
	manifest := readFixtures(t)
	entries := make(map[string]fixtureEntry, len(manifest.Fixtures))
	for _, item := range manifest.Fixtures {
		entries[item.ID] = item
	}
	entry, ok := entries[id]
	if !ok {
		t.Fatalf("fixture %q missing", id)
	}
	var attrs map[string]json.RawMessage
	if entry.BaseFixture != "" {
		_, attrs = fixtureAttrsFromEntries(t, entries, entry.BaseFixture)
	} else {
		attrs = cloneAttrs(entry.Attributes)
	}
	applyOverrides(attrs, entry.Overrides)
	return entry, attrs
}

func fixtureAttrsFromEntries(t *testing.T, entries map[string]fixtureEntry, id string) (fixtureEntry, map[string]json.RawMessage) {
	t.Helper()
	entry, ok := entries[id]
	if !ok {
		t.Fatalf("base fixture %q missing", id)
	}
	var attrs map[string]json.RawMessage
	if entry.BaseFixture != "" {
		_, attrs = fixtureAttrsFromEntries(t, entries, entry.BaseFixture)
	} else {
		attrs = cloneAttrs(entry.Attributes)
	}
	applyOverrides(attrs, entry.Overrides)
	return entry, attrs
}

func readFixtures(t *testing.T) fixtureManifest {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../integration/testdata/canonical/fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func cloneAttrs(source map[string]json.RawMessage) map[string]json.RawMessage {
	clone := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func applyOverrides(attrs map[string]json.RawMessage, overrides fixtureOverrides) {
	for _, key := range overrides.RemoveAttributes {
		delete(attrs, key)
	}
	for key, value := range overrides.Attributes {
		attrs[key] = value
	}
}

func fixtureValue(t *testing.T, attrs map[string]json.RawMessage, field wire.CanonicalField, family wire.Family) wire.Value {
	t.Helper()
	key := field.CanonicalName()
	if field == wire.FieldNetworkTransport {
		protocol := attrString(t, attrs, key)
		if protocol != "tcp" {
			t.Fatalf("fixture protocol %q is not the pinned tcp value", protocol)
		}
		return wire.UintValue(6)
	}
	if field == wire.FieldNetworkType {
		if attrString(t, attrs, key) == "ipv6" {
			return wire.UintValue(6)
		}
		return wire.UintValue(4)
	}
	if field == wire.FieldSourceAddress || field == wire.FieldDestinationAddress {
		text := attrString(t, attrs, key)
		parsed, err := netip.ParseAddr(text)
		if err != nil || (family == wire.FamilyIPv4 && !parsed.Is4()) || (family == wire.FamilyIPv6 && (!parsed.Is6() || parsed.Is4())) {
			t.Fatalf("fixture %s address %q invalid for %s", key, text, family)
		}
		return wire.IPValue(parsed)
	}
	return wire.UintValue(attrUint(t, attrs, key))
}

func attrString(t *testing.T, attrs map[string]json.RawMessage, key string) string {
	t.Helper()
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
	t.Helper()
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
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("fixture time %q: %v", value, err)
	}
	return uint64(parsed.UnixNano())
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../integration/testdata/golden/v9", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func customByteShape(t *testing.T) wire.Shape {
	t.Helper()
	descriptor, err := wire.NewV9PrivateDescriptor("vendor.byte", 40000, wire.EncodingUnsigned8, 1)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 1, TemplateBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	return shape
}

func privateUint32Shape(t *testing.T, id uint32) wire.Shape {
	t.Helper()
	descriptor, err := wire.NewV9PrivateDescriptor("vendor.counter", 40000, wire.EncodingUnsigned32, 4)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: id, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 4, TemplateBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	return shape
}

func timestampShape(t *testing.T, fields ...wire.FieldDescriptor) wire.Shape {
	t.Helper()
	var recordLength uint64
	for _, field := range fields {
		recordLength += uint64(field.Length)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{
		Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 303,
		Fields: fields, RecordLength: recordLength, TemplateBytes: 8 + 4*uint64(len(fields)),
	})
	if err != nil {
		t.Fatalf("timestamp shape: %v", err)
	}
	return shape
}

func timestampRequest(t *testing.T, shape wire.Shape, origin, start, end, export uint64) wire.PacketRequest {
	t.Helper()
	values := make([]wire.Value, shape.FieldCount())
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		switch descriptor.Field {
		case wire.FieldFlowStart:
			values[i] = wire.UnixNanosValue(start)
		case wire.FieldFlowEnd:
			values[i] = wire.UnixNanosValue(end)
		case wire.FieldFlowTimeReceived:
			values[i] = wire.UnixNanosValue(start)
		default:
			values[i] = wire.UintValue(0)
		}
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, values)
	if err != nil {
		t.Fatalf("timestamp record: %v", err)
	}
	return wire.PacketRequest{
		Header: wire.HeaderMetadata{
			Protocol: wire.ProtocolV9, SourceID: 9, Count: 2,
			ExportTimeUnixNanos: export, UptimeOriginUnixNanos: origin, HasUptimeOrigin: true,
		},
		Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes(),
	}
}

func recordWith(t *testing.T, source wire.WireRecord, index int, value wire.Value) wire.WireRecord {
	t.Helper()
	values := source.Values()
	values[index] = value
	record, err := wire.NewWireRecord(source.Family(), values)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func cloneRequest(source wire.PacketRequest) wire.PacketRequest {
	clone := source
	clone.Records = append([]wire.WireRecord(nil), source.Records...)
	return clone
}

func itoa(value uint64) string { return strconv.FormatUint(value, 10) }
