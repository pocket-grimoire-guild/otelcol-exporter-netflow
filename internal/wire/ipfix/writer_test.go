package ipfix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestGolden(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		golden  string
		family  wire.Family
		domain  uint32
		length  int
		records int
	}{
		{fixture: "canonical-ipv4-v1", golden: "canonical-ipv4-v1.bin", family: wire.FamilyIPv4, domain: 46, length: 180, records: 1},
		{fixture: "canonical-ipv6-v1", golden: "canonical-ipv6-v1.bin", family: wire.FamilyIPv6, domain: 51, length: 204, records: 1},
		{fixture: "sampling-ie34-two-distinct-rates-v1", golden: "sampling-ie34-two-distinct-rates-v1.bin", family: wire.FamilyIPv4, domain: 48, length: 252, records: 2},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			req := fixtureRequest(tc.fixture)
			if req.Shape.Family() != tc.family || req.Header.ObservationDomainID != tc.domain || len(req.Records) != tc.records {
				t.Fatalf("fixture request drift: family=%v domain=%d records=%d", req.Shape.Family(), req.Header.ObservationDomainID, len(req.Records))
			}
			got := make([]byte, tc.length)
			n, err := (Writer{}).Write(got, req)
			if err != nil || n != tc.length {
				t.Fatalf("write = (%d,%v), want (%d,nil)", n, err, tc.length)
			}
			want := readGolden(t, tc.golden)
			if !bytes.Equal(got, want) {
				t.Fatal("writer output differs from immutable golden")
			}
			assertIndependentPacket(t, got, tc.family, tc.domain, tc.records)
		})
	}
}

func TestGeneralProfileMillisecondsEncoding(t *testing.T) {
	for index, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		t.Run(family.String(), func(t *testing.T) {
			shape, ok := wire.BuiltinIPFIXGeneral().ShapeAt(index)
			if !ok {
				t.Fatal("missing general profile shape")
			}
			source, _ := wire.ParseIPValue("192.0.2.1")
			destination, _ := wire.ParseIPValue("198.51.100.2")
			if family == wire.FamilyIPv6 {
				source, _ = wire.ParseIPValue("2001:db8::1")
				destination, _ = wire.ParseIPValue("2001:db8::2")
			}
			values := fixtureValues(family, 1000)
			values[6], values[10] = source, destination
			values[18] = wire.UnixNanosValue(1_788_220_800_123_456_789)
			values[19] = wire.UnixNanosValue(1_788_220_801_123_999_999)
			record, err := wire.NewWireRecord(family, values)
			if err != nil {
				t.Fatal(err)
			}
			request := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 42, ExportTimeUnixNanos: 1_788_220_803_000_000_000}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
			dataSize, err := shape.DataSetSize(request.Records)
			if err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 16+int(shape.TemplateBytes())+int(dataSize.Length()))
			n, err := (Writer{}).Write(packet, request)
			if err != nil || n != len(packet) {
				t.Fatalf("write=(%d,%v), len=%d", n, err, len(packet))
			}
			goldenName := "general-ipv4-v1.bin"
			if family == wire.FamilyIPv6 {
				goldenName = "general-ipv6-v1.bin"
			}
			golden := readGolden(t, goldenName)
			if !bytes.Equal(packet, golden) {
				t.Fatalf("materializing general output differs from %s", goldenName)
			}
			templateStart := 24 + 18*4
			if got := binary.BigEndian.Uint16(packet[templateStart : templateStart+2]); got != 152 {
				t.Fatalf("template start ID=%d", got)
			}
			dataOffset := 16 + int(shape.TemplateBytes()) + 4
			startOffset := dataOffset + 56
			if family == wire.FamilyIPv6 {
				startOffset = dataOffset + 80
			}
			if got := binary.BigEndian.Uint64(packet[startOffset : startOffset+8]); got != 1_788_220_800_123 {
				t.Fatalf("encoded start=%d, want %d", got, uint64(1_788_220_800_123))
			}
			if got := binary.BigEndian.Uint64(packet[startOffset+8 : startOffset+16]); got != 1_788_220_801_123 {
				t.Fatalf("encoded end=%d, want %d", got, uint64(1_788_220_801_123))
			}

			// The incremental writer uses the same checked conversion and must
			// produce byte-identical data for the one-record data message.
			streamPacket := make([]byte, len(packet)-int(shape.TemplateBytes()))
			appender := NewDataPacket()
			if err := appender.Begin(streamPacket, wire.DataPacketRequest{Header: request.Header, Shape: shape}); err != nil {
				t.Fatal(err)
			}
			if err := appender.Append(record); err != nil {
				t.Fatal(err)
			}
			streamN, err := appender.Finish()
			if err != nil || streamN != len(streamPacket) {
				t.Fatalf("stream finish=(%d,%v), len=%d", streamN, err, len(streamPacket))
			}
			if !bytes.Equal(streamPacket[16+4:], packet[16+int(shape.TemplateBytes())+4:]) {
				t.Fatal("stream data differs from materializing data")
			}
			if !bytes.Equal(streamPacket[16:], golden[16+int(shape.TemplateBytes()):]) {
				t.Fatalf("streaming general output differs from %s data section", goldenName)
			}
		})
	}
}

func TestGeneralProfileMillisecondsArithmeticBoundaries(t *testing.T) {
	if got, err := unixMilliseconds(math.MaxInt64); err != nil || got != uint64(math.MaxInt64)/nanosPerMillisecond {
		t.Fatalf("MaxInt64 conversion=(%d,%v)", got, err)
	}
	if _, err := unixMilliseconds(uint64(math.MaxInt64) + 1); !errors.Is(err, wire.ErrTimeOutOfRange) {
		t.Fatalf("MaxInt64+1 conversion=%v", err)
	}
}

func TestBoundary(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1")
	headerOnly := base
	headerOnly.Header.Count = 0
	headerOnly.TemplateRecords = 0
	headerOnly.TemplateBytes = 0
	headerOnly.Records = nil
	for _, tc := range []struct {
		name string
		cap  int
		want error
	}{
		{name: "15-byte-header", cap: 15, want: wire.ErrShortBuffer},
		{name: "16-byte-header", cap: 16},
		{name: "17-byte-header-tail", cap: 17},
		{name: "reusable-buffer-header-tail", cap: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xa5}, tc.cap)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, headerOnly)
			if tc.want == nil {
				if err != nil || n != headerLength {
					t.Fatalf("header-only = (%d,%v), want (16,nil)", n, err)
				}
				if got := binary.BigEndian.Uint16(buf[2:4]); got != headerLength {
					t.Fatalf("header-declared length = %d, want %d", got, headerLength)
				}
				if !bytes.Equal(buf[headerLength:], before[headerLength:]) {
					t.Fatal("caller tail was changed")
				}
				return
			}
			if n != 0 || !errors.Is(err, tc.want) || !bytes.Equal(buf, before) {
				t.Fatalf("boundary = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
			}
		})
	}

	// A late record failure must occur before the header is touched.
	req := fixtureRequest("canonical-ipv4-v1")
	req.Records = append(req.Records, req.Records[0])
	req.Header.Count = 0
	req.Header.Count = 0 // IPFIX Count is always zero; this also documents the boundary.
	req.Records[1] = replaceValue(t, req.Records[1], 0, wire.StringValue("bad"))
	buf := bytes.Repeat([]byte{0x91}, 512)
	before := append([]byte(nil), buf...)
	if n, err := (Writer{}).Write(buf, req); n != 0 || err == nil || !bytes.Equal(buf, before) {
		t.Fatalf("late rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
	}

	// Declared data lengths are checked against the shape arithmetic.
	for _, declared := range []uint64{4, 5, 65535, 65536} {
		bad := fixtureRequest("canonical-ipv4-v1")
		bad.DataBytes = declared
		buf := bytes.Repeat([]byte{0xc3}, 256)
		before := append([]byte(nil), buf...)
		if n, err := (Writer{}).Write(buf, bad); n != 0 || err == nil || !bytes.Equal(buf, before) {
			t.Fatalf("declared data length %d = (%d,%v), mutated=%v", declared, n, err, !bytes.Equal(buf, before))
		}
	}

	// RFC 7011 permits a fixed one-byte record without padding when the three
	// candidate padding bytes are not shorter than that record. This is a
	// complete 21-byte data-only message, and the short buffer remains atomic.
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.fixed", 32473, 100, wire.EncodingUnsigned8, false, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 256, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 1, TemplateBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	req = wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX}, Shape: shape, Records: []wire.WireRecord{record}, DataBytes: 5}
	want := []byte{
		0x00, 0x0a, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x05, 0x01,
	}
	buf = bytes.Repeat([]byte{0xa4}, len(want))
	if n, err := (Writer{}).Write(buf, req); err != nil || n != len(want) || !bytes.Equal(buf, want) {
		t.Fatalf("fixed one-byte IPFIX = (%d,%v) bytes=%x, want (%d,nil) %x", n, err, buf, len(want), want)
	}
	short := bytes.Repeat([]byte{0xb5}, len(want)-1)
	before = append([]byte(nil), short...)
	if n, err := (Writer{}).Write(short, req); n != 0 || !errors.Is(err, wire.ErrShortBuffer) || !bytes.Equal(short, before) {
		t.Fatalf("fixed one-byte IPFIX short buffer = (%d,%v), mutated=%v", n, err, !bytes.Equal(short, before))
	}

	// Keep the complete boundary/ordering/timestamp matrix under the exact
	// protocol acceptance selector.
	t.Run("shape-ordering", testShapeOrdering)
	t.Run("variable-lengths", testVariableLengths)
	t.Run("ntp-fractions", testNTPFractions)
	t.Run("alternate-standard-descriptors", testAlternateStandardDescriptors)
}

func TestMalformed(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1")
	reject := func(name string, want error, mutate func(*wire.PacketRequest)) {
		t.Run(name, func(t *testing.T) {
			req := cloneRequest(base)
			mutate(&req)
			buf := bytes.Repeat([]byte{0x7e}, 512)
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
	reject("wrong-protocol", wire.ErrInvalidShape, func(req *wire.PacketRequest) { req.Header.Protocol = wire.ProtocolV9 })
	reject("source-id-leak", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SourceID = 1 })
	reject("engine-id-leak", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.EngineID = 1 })
	reject("sampling-header-leak", wire.ErrInvalidHeader, func(req *wire.PacketRequest) { req.Header.SamplingInterval = 1 })
	reject("unix-seconds-overflow", wire.ErrInvalidHeader, func(req *wire.PacketRequest) {
		req.Header.ExportTimeUnixNanos = (uint64(math.MaxUint32) + 1) * 1_000_000_000
	})
	reject("invalid-shape", wire.ErrInvalidShape, func(req *wire.PacketRequest) {
		req.Shape = wire.Shape{}
	})
	reject("wrong-family", wire.ErrInvalidFamily, func(req *wire.PacketRequest) {
		values := req.Records[0].Values()
		source, _ := wire.ParseIPv6Value("2001:db8::1")
		destination, _ := wire.ParseIPv6Value("2001:db8::2")
		values[6], values[10] = source, destination
		var err error
		req.Records[0], err = wire.NewWireRecord(wire.FamilyIPv6, values)
		if err != nil {
			t.Fatalf("record construction: %v", err)
		}
	})

	// Enterprise specifiers set E and append PEN; malformed identities reject.
	enterprise, err := wire.NewIPFIXEnterpriseDescriptor("vendor.counter", 32473, 100, wire.EncodingUnsigned32, false, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{enterprise}, RecordLength: 4, TemplateBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	record, _ := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(0x01020304)})
	req := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: 16}
	buf := make([]byte, 40)
	if n, err := (Writer{}).Write(buf, req); err != nil || n != 40 {
		t.Fatalf("enterprise write = (%d,%v)", n, err)
	}
	if got := binary.BigEndian.Uint16(buf[24:26]); got != 0x8064 {
		t.Fatalf("enterprise E-bit/id = %#x, want %#x", got, 0x8064)
	}
	if got := binary.BigEndian.Uint32(buf[28:32]); got != 32473 {
		t.Fatalf("enterprise PEN = %d", got)
	}
}

func testShapeOrdering(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1").Shape.Fields()
	enterprise, err := wire.NewIPFIXEnterpriseDescriptor("vendor.order", 32473, 100, wire.EncodingUnsigned32, false, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	newShape := func(fields []wire.FieldDescriptor) wire.Shape {
		var recordLength, templateBytes uint64 = 0, 8
		for _, field := range fields {
			recordLength += uint64(field.MinimumLength())
			templateBytes += 4
			if field.Enterprise {
				templateBytes += 4
			}
		}
		shape, err := wire.NewShape(wire.ShapeSpec{
			Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300,
			Fields: fields, RecordLength: recordLength, TemplateBytes: templateBytes,
		})
		if err != nil {
			t.Fatalf("shape construction: %v", err)
		}
		return shape
	}
	write := func(name string, shape wire.Shape, wantErr bool) {
		t.Run(name, func(t *testing.T) {
			req := wire.PacketRequest{
				Header:          wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9},
				Shape:           shape,
				TemplateRecords: 1,
				TemplateBytes:   shape.TemplateBytes(),
			}
			buf := bytes.Repeat([]byte{0x7e}, 128)
			before := append([]byte(nil), buf...)
			n, err := (Writer{}).Write(buf, req)
			if wantErr {
				if n != 0 || !errors.Is(err, wire.ErrInvalidDescriptor) || !bytes.Equal(buf, before) {
					t.Fatalf("ordering rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
				}
				return
			}
			wantLength := headerLength + int(shape.TemplateBytes())
			if err != nil || n != wantLength {
				t.Fatalf("ordering acceptance = (%d,%v), want (%d,nil)", n, err, wantLength)
			}
			if got := binary.BigEndian.Uint16(buf[2:4]); got != uint16(wantLength) {
				t.Fatalf("header-declared length = %d, want %d", got, wantLength)
			}
		})
	}

	write("custom-only", newShape([]wire.FieldDescriptor{enterprise}), false)
	write("canonical-prefix-custom-suffix", newShape([]wire.FieldDescriptor{base[0], enterprise}), false)
	write("custom-first-then-canonical", newShape([]wire.FieldDescriptor{enterprise, base[0]}), true)
	write("canonical-custom-canonical-interleaving", newShape([]wire.FieldDescriptor{base[0], enterprise, base[1]}), true)
	write("canonical-non-prefix-subset", newShape([]wire.FieldDescriptor{base[1], base[3]}), false)
	write("canonical-reordered-custom-suffix", newShape([]wire.FieldDescriptor{base[3], base[1], enterprise}), false)
}

func testVariableLengths(t *testing.T) {
	for _, length := range []int{0, 1, 253, 254, 255} {
		d, err := wire.NewIPFIXEnterpriseDescriptor("vendor.bytes", 32473, 100, wire.EncodingOctetArray, true, 65535, 65535)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{d}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatal(err)
		}
		value := wire.OctetsValue(string(bytes.Repeat([]byte{0x5a}, length)))
		record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
		if err != nil {
			t.Fatal(err)
		}
		req := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: 16}
		size, err := shape.DataSetSize(req.Records)
		if err != nil {
			t.Fatalf("length %d sizing: %v", length, err)
		}
		buf := make([]byte, 16+16+int(size.Length()))
		n, err := (Writer{}).Write(buf, req)
		if err != nil || n != len(buf) {
			t.Fatalf("length %d write = (%d,%v), size=%d", length, n, err, size.Length())
		}
		data := 36
		if length < 255 {
			if got := int(buf[data]); got != length {
				t.Fatalf("length %d prefix = %d", length, got)
			}
			data++
		} else {
			if buf[data] != 255 || int(binary.BigEndian.Uint16(buf[data+1:data+3])) != length {
				t.Fatalf("length %d extended prefix = %x", length, buf[data:data+3])
			}
			data += 3
		}
		if len(buf)-data < length || !bytes.Equal(buf[data:data+length], bytes.Repeat([]byte{0x5a}, length)) {
			t.Fatalf("length %d payload mismatch", length)
		}
	}
	// 65535 carries the extended prefix correctly in the checked arithmetic,
	// but the complete Set would exceed the 16-bit IPFIX message ceiling.
	{
		length := 65535
		d, err := wire.NewIPFIXEnterpriseDescriptor("vendor.bytes", 32473, 100, wire.EncodingOctetArray, true, 65535, 65535)
		if err != nil {
			t.Fatal(err)
		}
		shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{d}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatal(err)
		}
		record, _ := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.OctetsValue(string(bytes.Repeat([]byte{0x5a}, length)))})
		req := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: 16}
		buf := bytes.Repeat([]byte{0x42}, 65535)
		before := append([]byte(nil), buf...)
		if n, err := (Writer{}).Write(buf, req); n != 0 || !errors.Is(err, wire.ErrBounds) || !bytes.Equal(buf, before) {
			t.Fatalf("65535 variable value = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
		}
	}

	// A 65536-byte value is rejected before narrowing into the variable prefix.
	d, _ := wire.NewIPFIXEnterpriseDescriptor("vendor.bytes", 32473, 100, wire.EncodingOctetArray, true, 65535, 65535)
	shape, _ := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{d}, RecordLength: 1, TemplateBytes: 16})
	record, _ := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.OctetsValue(string(bytes.Repeat([]byte{0x5a}, 65536)))})
	req := wire.PacketRequest{Header: wire.PacketRequest{}.Header, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: 16}
	req.Header.Protocol = wire.ProtocolIPFIX
	buf := bytes.Repeat([]byte{0x42}, 65535)
	before := append([]byte(nil), buf...)
	if n, err := (Writer{}).Write(buf, req); n != 0 || !errors.Is(err, wire.ErrBounds) || !bytes.Equal(buf, before) {
		t.Fatalf("65536 variable value = (%d,%v), mutated=%v", n, err, !bytes.Equal(buf, before))
	}
}

func testNTPFractions(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   uint64
		want uint32
	}{
		{name: "one-ns", ns: 1, want: 0x00000004},
		{name: "one-ms", ns: 1_000_000, want: 0x00418937},
		{name: "last-ns", ns: 999_999_999, want: 0xfffffffc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ntpTimestamp(tc.ns)
			if err != nil || uint32(got) != tc.want {
				t.Fatalf("NTP fraction = %#x,%v want %#x,nil", uint32(got), err, tc.want)
			}
		})
	}
	if _, err := ntpTimestamp(maxUnixNanosIPFIX); err != nil {
		t.Fatalf("era-end rejected: %v", err)
	}
	if _, err := ntpTimestamp(maxUnixNanosIPFIX + 1); !errors.Is(err, wire.ErrTimeOutOfRange) {
		t.Fatalf("era-next = %v, want %v", err, wire.ErrTimeOutOfRange)
	}
}

func testAlternateStandardDescriptors(t *testing.T) {
	enterprise, err := wire.NewIPFIXEnterpriseDescriptor("vendor.alt", 32473, 100, wire.EncodingUnsigned32, false, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	// This order is intentionally different from the built-in catalog.  The
	// writer trusts the immutable structural Shape and does not bind selectors
	// to the catalog's twenty canonical targets.
	fields := []wire.FieldDescriptor{
		{Protocol: wire.ProtocolIPFIX, Field: wire.FieldFlowTimeReceived, ID: 325, Length: 8, Encoding: wire.EncodingDateTimeNanoseconds},
		{Protocol: wire.ProtocolIPFIX, Field: wire.FieldFlowSrcMAC, ID: 81, Length: 6, Encoding: wire.EncodingMACAddress},
		{Protocol: wire.ProtocolIPFIX, Field: wire.FieldFlowIOBytes, ID: 23, Length: 8, Encoding: wire.EncodingUnsigned64},
		enterprise,
	}
	shape, err := wire.NewShape(wire.ShapeSpec{
		Protocol:      wire.ProtocolIPFIX,
		Family:        wire.FamilyIPv4,
		ID:            300,
		Fields:        fields,
		RecordLength:  26,
		TemplateBytes: 28,
	})
	if err != nil {
		t.Fatalf("alternate shape construction: %v", err)
	}
	mac, err := wire.NewMACValue([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{
		wire.UnixNanosValue(1_500_000_000),
		mac,
		wire.UintValue(0x0102030405060708),
		wire.UintValue(0xaabbccdd),
	})
	if err != nil {
		t.Fatalf("alternate record construction: %v", err)
	}
	req := wire.PacketRequest{
		Header:          wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9, ExportTimeUnixNanos: 2_000_000_000},
		Shape:           shape,
		Records:         []wire.WireRecord{record},
		TemplateRecords: 1,
		TemplateBytes:   shape.TemplateBytes(),
	}
	buf := bytes.Repeat([]byte{0xa5}, 76)
	n, err := (Writer{}).Write(buf, req)
	if err != nil || n != len(buf) {
		t.Fatalf("alternate write = (%d,%v), want (76,nil)", n, err)
	}
	if got := binary.BigEndian.Uint16(buf[0:2]); got != 10 {
		t.Fatalf("version = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(buf[2:4]); got != 76 {
		t.Fatalf("message length = %d, want 76", got)
	}
	if got := binary.BigEndian.Uint32(buf[12:16]); got != 9 {
		t.Fatalf("observation domain = %d, want 9", got)
	}

	// The Template Set contains exact standard IE IDs/lengths (E=0), followed
	// by one enterprise specifier with its E bit and PEN.
	wantIDs := []uint16{325, 81, 23, 0x8064}
	wantLengths := []uint16{8, 6, 8, 4}
	for i := range wantIDs {
		off := 24 + i*4
		gotID := binary.BigEndian.Uint16(buf[off : off+2])
		if gotID != wantIDs[i] {
			t.Fatalf("template field %d ID = %#x, want %#x", i, gotID, wantIDs[i])
		}
		if got := binary.BigEndian.Uint16(buf[off+2 : off+4]); got != wantLengths[i] {
			t.Fatalf("template field %d length = %d, want %d", i, got, wantLengths[i])
		}
		if i < 3 && gotID&0x8000 != 0 {
			t.Fatalf("template standard field %d unexpectedly set E bit: %#x", i, gotID)
		}
	}
	if got := binary.BigEndian.Uint32(buf[40:44]); got != 32473 {
		t.Fatalf("enterprise PEN = %d, want 32473", got)
	}

	wantDataSet := []byte{
		0x01, 0x2c, 0x00, 0x20,
		0x83, 0xaa, 0x7e, 0x81, 0x80, 0x00, 0x00, 0x00,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xaa, 0xbb, 0xcc, 0xdd,
		0x00, 0x00,
	}
	dataStart := 16 + int(shape.TemplateBytes())
	if got := buf[dataStart : dataStart+len(wantDataSet)]; !bytes.Equal(got, wantDataSet) {
		t.Fatalf("alternate data set bytes = %x, want %x", got, wantDataSet)
	}
}

func TestAllocations(t *testing.T) {
	for _, id := range []string{"canonical-ipv4-v1", "canonical-ipv6-v1", "sampling-ie34-two-distinct-rates-v1"} {
		req := fixtureRequest(id)
		size := 16 + int(req.Shape.TemplateBytes())
		data, _ := req.Shape.DataSetSize(req.Records)
		size += int(data.Length())
		dst := make([]byte, size)
		allocs := testing.AllocsPerRun(1000, func() {
			n, err := (Writer{}).Write(dst, req)
			if err != nil || n != size {
				t.Fatalf("write = (%d,%v)", n, err)
			}
		})
		if allocs != 0 {
			t.Fatalf("%s allocations = %v", id, allocs)
		}
	}
}

func fixtureRequest(id string) wire.PacketRequest {
	family := wire.FamilyIPv4
	domain := uint32(46)
	shape, _ := wire.BuiltinIPFIX().ShapeAt(0)
	if id == "canonical-ipv6-v1" {
		family, domain = wire.FamilyIPv6, 51
		shape, _ = wire.BuiltinIPFIX().ShapeAt(1)
	}
	if id == "sampling-ie34-two-distinct-rates-v1" {
		domain = 48
	}
	values := fixtureValues(family, 1000)
	record, _ := wire.NewWireRecord(family, values)
	records := []wire.WireRecord{record}
	if id == "sampling-ie34-two-distinct-rates-v1" {
		second, _ := wire.NewWireRecord(family, fixtureValues(family, 2000))
		records = append(records, second)
	}
	return wire.PacketRequest{
		Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, Sequence: 0, ObservationDomainID: domain, ExportTimeUnixNanos: 1_788_220_803_000_000_000},
		Shape:  shape, Records: records, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes(),
	}
}

func fixtureValues(family wire.Family, sampling uint64) []wire.Value {
	source, _ := netip.ParseAddr("192.0.2.1")
	destination, _ := netip.ParseAddr("198.51.100.2")
	prefix := uint64(24)
	if family == wire.FamilyIPv6 {
		source, _ = netip.ParseAddr("2001:db8::1")
		destination, _ = netip.ParseAddr("2001:db8::2")
		prefix = 64
	}
	return []wire.Value{
		wire.UintValue(56789), wire.UintValue(1234), wire.UintValue(6), wire.UintValue(0), wire.UintValue(24), wire.UintValue(12345),
		wire.IPValue(source), wire.UintValue(prefix), wire.UintValue(10), wire.UintValue(443), wire.IPValue(destination), wire.UintValue(prefix),
		wire.UintValue(20), wire.UintValue(64513), wire.UintValue(64514), wire.UintValue(sampling), wire.UintValue(64),
		wire.UintValue(map[wire.Family]uint64{wire.FamilyIPv4: 4, wire.FamilyIPv6: 6}[family]),
		wire.UnixNanosValue(1_788_220_801_000_000_000), wire.UnixNanosValue(1_788_220_801_001_000_000),
	}
}

func assertIndependentPacket(t *testing.T, packet []byte, family wire.Family, domain uint32, records int) {
	t.Helper()
	if binary.BigEndian.Uint16(packet[0:2]) != 10 || binary.BigEndian.Uint16(packet[2:4]) != uint16(len(packet)) {
		t.Fatalf("header version/length = %d/%d", binary.BigEndian.Uint16(packet[0:2]), binary.BigEndian.Uint16(packet[2:4]))
	}
	if binary.BigEndian.Uint32(packet[4:8]) != 1_788_220_803 || binary.BigEndian.Uint32(packet[8:12]) != 0 || binary.BigEndian.Uint32(packet[12:16]) != domain {
		t.Fatalf("header export/sequence/domain = %x", packet[:16])
	}
	templateID := uint16(256)
	if family == wire.FamilyIPv6 {
		templateID = 257
	}
	if binary.BigEndian.Uint16(packet[16:18]) != 2 || binary.BigEndian.Uint16(packet[18:20]) != 88 || binary.BigEndian.Uint16(packet[20:22]) != templateID || binary.BigEndian.Uint16(packet[22:24]) != 20 {
		t.Fatalf("template set/header = %x", packet[16:24])
	}
	wantIDs := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 156, 157}
	wantLengths := []uint16{8, 8, 1, 1, 2, 2, 4, 1, 4, 2, 4, 1, 4, 4, 4, 4, 1, 1, 8, 8}
	if family == wire.FamilyIPv6 {
		wantIDs[6], wantIDs[10] = 27, 28
		wantIDs[7], wantIDs[11] = 29, 30
		wantLengths[6], wantLengths[10] = 16, 16
	}
	for i, id := range wantIDs {
		off := 24 + i*4
		if got := binary.BigEndian.Uint16(packet[off : off+2]); got != id {
			t.Fatalf("template IE %d = %d, want %d", i, got, id)
		}
		if got := binary.BigEndian.Uint16(packet[off+2 : off+4]); got != wantLengths[i] {
			t.Fatalf("template IE %d length = %d, want %d", i, got, wantLengths[i])
		}
	}
	data := 16 + 88
	if binary.BigEndian.Uint16(packet[data:data+2]) != templateID {
		t.Fatalf("data set ID = %d", binary.BigEndian.Uint16(packet[data:data+2]))
	}
	wantDataLength := uint16(76)
	if family == wire.FamilyIPv6 {
		wantDataLength = 100
	}
	if records == 2 {
		wantDataLength = 148
	}
	if binary.BigEndian.Uint16(packet[data+2:data+4]) != wantDataLength {
		t.Fatalf("data set length = %d", binary.BigEndian.Uint16(packet[data+2:data+4]))
	}
	record := data + 4
	// The authored canonical IPv6 fixture inherits /64, not the IPv4 /24.
	// Offsets follow the literal IE widths above, independent of fixtureValues.
	sourcePrefixOffset, destinationPrefixOffset, prefix := 26, 37, byte(24)
	if family == wire.FamilyIPv6 {
		sourcePrefixOffset, destinationPrefixOffset, prefix = 38, 61, 64
	}
	if packet[record+sourcePrefixOffset] != prefix || packet[record+destinationPrefixOffset] != prefix {
		t.Fatalf("source/destination prefix lengths differ from canonical /%d", prefix)
	}
	if binary.BigEndian.Uint64(packet[record:record+8]) != 56789 || binary.BigEndian.Uint64(packet[record+8:record+16]) != 1234 {
		t.Fatalf("counter values drift: %x", packet[record:record+16])
	}
	samplingOffset := 50
	startOffset := 56
	if family == wire.FamilyIPv6 {
		samplingOffset = 74
		startOffset = 80
	}
	if got := binary.BigEndian.Uint32(packet[record+samplingOffset : record+samplingOffset+4]); got != 1000 {
		t.Fatalf("ordinary IE34 value = %d, want 1000", got)
	}
	wantStart := (uint64(1_788_220_801+2_208_988_800) << 32)
	if got := binary.BigEndian.Uint64(packet[record+startOffset : record+startOffset+8]); got != wantStart {
		t.Fatalf("NTP start = %#x, want %#x", got, wantStart)
	}
	wantEnd := (uint64(1_788_220_801+2_208_988_800) << 32) | 0x00418937
	if got := binary.BigEndian.Uint64(packet[record+startOffset+8 : record+startOffset+16]); got != wantEnd {
		t.Fatalf("NTP end = %#x, want %#x", got, wantEnd)
	}
	if records == 2 && binary.BigEndian.Uint32(packet[data+4+72+50:data+4+72+54]) != 2000 {
		t.Fatalf("second IE34 did not remain ordinary four-byte value")
	}
}

func replaceValue(t *testing.T, record wire.WireRecord, index int, value wire.Value) wire.WireRecord {
	t.Helper()
	values := record.Values()
	values[index] = value
	replaced, err := wire.NewWireRecord(record.Family(), values)
	if err != nil {
		t.Fatal(err)
	}
	return replaced
}

func cloneRequest(req wire.PacketRequest) wire.PacketRequest {
	clone := req
	clone.Records = append([]wire.WireRecord(nil), req.Records...)
	return clone
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	path := filepath.Join(filepath.Dir(file), "../../../integration/testdata/golden/ipfix", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
