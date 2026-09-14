package ipfix

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// FuzzIPFIXWriter exercises both the immutable writer and its streaming data
// appender with a bounded four-byte grammar. Setup is deterministic and local;
// the byte checks below derive IPFIX Set lengths, padding, prefixes, and value
// bytes independently of Shape sizing or the writer implementation.
func FuzzIPFIXWriter(f *testing.F) {
	seeds := [][4]uint8{
		{0, 0, 0, 0}, {0, 1, 0, 0}, {0, 2, 0, 0},
		{1, 0, 0, 0}, {1, 1, 0, 0}, {1, 2, 0, 0}, {1, 3, 0, 0}, {1, 4, 0, 0}, {1, 5, 0, 0},
		{2, 0, 0, 0}, {2, 0, 1, 0}, {2, 0, 2, 0}, {2, 0, 3, 0}, {2, 0, 4, 0}, {2, 0, 5, 0}, {2, 0, 6, 0},
		{3, 0, 0, 0}, {3, 1, 1, 0}, {3, 0, 2, 0}, {3, 1, 3, 0},
		{4, 0, 0, 0}, {4, 0, 1, 0}, {4, 0, 2, 0}, {4, 0, 3, 0}, {4, 0, 4, 0}, {4, 0, 5, 0}, {4, 0, 6, 0}, {4, 0, 7, 0},
		{5, 0, 0, 0}, {5, 1, 1, 0}, {5, 2, 2, 0}, {5, 3, 3, 0}, {5, 4, 0, 0}, {5, 5, 1, 0}, {5, 6, 2, 0}, {5, 7, 3, 0},
		{6, 0, 0, 0}, {6, 1, 0, 0}, {6, 2, 0, 0}, {6, 3, 0, 0}, {6, 4, 0, 0}, {6, 5, 0, 0}, {6, 6, 0, 0}, {6, 7, 0, 0},
		{7, 0, 0, 0}, {7, 1, 1, 0}, {7, 2, 2, 0}, {7, 3, 3, 0},
		{8, 0, 0, 0}, {8, 1, 0, 0}, {8, 2, 0, 0}, {8, 3, 0, 0},
		{8, 128, 0, 0},
		{9, 0, 0, 0}, {9, 1, 0, 0},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, scenarioByte, shapeByte, valueByte, capacityByte uint8) {
		switch scenarioByte % 10 {
		case 0:
			ipfixFuzzGolden(t, shapeByte, valueByte)
		case 1:
			ipfixFuzzOrdering(t, shapeByte)
		case 2:
			ipfixFuzzVariable(t, shapeByte, valueByte)
		case 3:
			ipfixFuzzFixedStringOctets(t, shapeByte, valueByte)
		case 4:
			ipfixFuzzNTP(t, valueByte)
		case 5:
			ipfixFuzzWidth(t, shapeByte, valueByte)
		case 6:
			ipfixFuzzMetadata(t, shapeByte, valueByte)
		case 7:
			ipfixFuzzCapacity(t, capacityByte)
		case 8:
			ipfixFuzzStreamAtomic(t, shapeByte, valueByte)
		case 9:
			ipfixFuzzStreamLifecycle(t, shapeByte)
		}
	})
}

func ipfixFuzzGolden(t *testing.T, shapeByte, sequenceByte uint8) {
	t.Helper()
	fixtures := [...]string{"canonical-ipv4-v1", "canonical-ipv6-v1", "sampling-ie34-two-distinct-rates-v1"}
	id := fixtures[shapeByte%uint8(len(fixtures))]
	request := fixtureRequest(id)
	request.Header.Sequence = uint32(sequenceByte)
	dst := bytes.Repeat([]byte{0xa5}, 256)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if err != nil {
		t.Fatalf("golden write: %v", err)
	}
	if sequenceByte == 0 {
		assertIndependentPacket(t, dst[:n], request.Shape.Family(), request.Header.ObservationDomainID, len(request.Records))
		if !bytes.Equal(dst[:n], readGolden(t, id+".bin")) {
			t.Fatalf("%s differs from immutable golden", id)
		}
	} else {
		ipfixFuzzAssertPacket(t, dst[:n], request)
	}
	if !bytes.Equal(dst[n:], before[n:]) {
		t.Fatal("golden write changed caller tail")
	}
}

func ipfixFuzzOrdering(t *testing.T, selector uint8) {
	t.Helper()
	base := fixtureRequest("canonical-ipv4-v1").Shape.Fields()
	enterprise, err := wire.NewIPFIXEnterpriseDescriptor("vendor.order", 32473, 100, wire.EncodingUnsigned32, false, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fields []wire.FieldDescriptor
	wantErr := error(nil)
	switch selector % 6 {
	case 0:
		fields = []wire.FieldDescriptor{enterprise}
	case 1:
		fields = []wire.FieldDescriptor{base[0], enterprise}
	case 2:
		fields = []wire.FieldDescriptor{enterprise, base[0]}
		wantErr = wire.ErrInvalidDescriptor
	case 3:
		fields = []wire.FieldDescriptor{base[0], enterprise, base[1]}
		wantErr = wire.ErrInvalidDescriptor
	case 4:
		fields = []wire.FieldDescriptor{base[1], base[3]}
	case 5:
		fields = []wire.FieldDescriptor{base[3], base[1], enterprise}
	}
	shape := ipfixFuzzShape(t, fields, 300)
	recordValues := make([]wire.Value, len(fields))
	for i, field := range fields {
		if field.Enterprise {
			recordValues[i] = wire.UintValue(0x01020304)
		} else {
			recordValues[i] = ipfixFuzzCanonicalValue(field, wire.FamilyIPv4)
		}
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, recordValues)
	if err != nil {
		t.Fatal(err)
	}
	request := wire.PacketRequest{
		Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9},
		Shape:  shape, Records: []wire.WireRecord{record}, TemplateRecords: 1,
		TemplateBytes: shape.TemplateBytes(),
	}
	dst := bytes.Repeat([]byte{0x7e}, 256)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, request)
	if wantErr != nil {
		if n != 0 || gotErr != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("ordering rejection = (%d,%v), want %v, mutated=%v", n, gotErr, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if gotErr != nil {
		t.Fatalf("ordering write: %v", gotErr)
	}
	ipfixFuzzAssertPacket(t, dst[:n], request)
	for i, field := range fields {
		off := 24 + i*4
		if field.Enterprise {
			if got := binary.BigEndian.Uint16(dst[off : off+2]); got != 0x8000|field.ID {
				t.Fatalf("enterprise field %d id = %#x", i, got)
			}
			if got := binary.BigEndian.Uint32(dst[off+4 : off+8]); got != field.PEN {
				t.Fatalf("enterprise field %d PEN = %d", i, got)
			}
		}
	}
}

func ipfixFuzzVariable(t *testing.T, shapeByte, lengthByte uint8) {
	t.Helper()
	lengths := [...]int{0, 1, 254, 255, 256, 65535, 65536}
	length := lengths[lengthByte%uint8(len(lengths))]
	encoding := wire.EncodingOctetArray
	if shapeByte&1 != 0 {
		encoding = wire.EncodingString
	}
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.variable", 32473, 100, encoding, true, 65535, 65535)
	if err != nil {
		t.Fatal(err)
	}
	shape := ipfixFuzzShape(t, []wire.FieldDescriptor{descriptor}, 300)
	payload := bytes.Repeat([]byte{0x5a}, length)
	value := wire.OctetsValue(string(payload))
	if encoding == wire.EncodingString {
		value = wire.StringValue(string(payload))
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
	if err != nil {
		t.Fatal(err)
	}
	request := wire.PacketRequest{
		Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9},
		Shape:  shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes(),
	}
	dst := bytes.Repeat([]byte{0x42}, 65535)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, request)
	if length > 256 {
		if n != 0 || gotErr != wire.ErrBounds || !bytes.Equal(dst, before) {
			t.Fatalf("variable length %d = (%d,%v), want bounds, mutated=%v", length, n, gotErr, !bytes.Equal(dst, before))
		}
		return
	}
	if gotErr != nil {
		t.Fatalf("variable length %d write: %v", length, gotErr)
	}
	ipfixFuzzAssertPacket(t, dst[:n], request)
	data := 16 + int(shape.TemplateBytes()) + 4
	if length < 255 {
		if dst[data] != byte(length) {
			t.Fatalf("variable length %d prefix = %d", length, dst[data])
		}
		data++
	} else if dst[data] != 255 || binary.BigEndian.Uint16(dst[data+1:data+3]) != uint16(length) {
		t.Fatalf("variable length %d extended prefix = %x", length, dst[data:data+3])
	} else {
		data += 3
	}
	if !bytes.Equal(dst[data:data+length], payload) {
		t.Fatalf("variable length %d payload changed", length)
	}
}

func ipfixFuzzFixedStringOctets(t *testing.T, shapeByte, lengthByte uint8) {
	t.Helper()
	lengths := [...]int{1, 254, 255, 256, 4096}
	length := lengths[lengthByte%uint8(len(lengths))]
	encoding := wire.EncodingOctetArray
	if shapeByte&1 != 0 {
		encoding = wire.EncodingString
	}
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.fixed", 32473, 101, encoding, false, uint16(length), 0)
	if err != nil {
		t.Fatal(err)
	}
	shape := ipfixFuzzShape(t, []wire.FieldDescriptor{descriptor}, 301)
	payload := bytes.Repeat([]byte{0x37}, length)
	value := wire.OctetsValue(string(payload))
	if encoding == wire.EncodingString {
		value = wire.StringValue(string(payload))
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
	if err != nil {
		t.Fatal(err)
	}
	request := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
	dst := bytes.Repeat([]byte{0xa5}, 65535)
	n, err := (Writer{}).Write(dst, request)
	if err != nil {
		t.Fatalf("fixed %v length %d write: %v", encoding, length, err)
	}
	ipfixFuzzAssertPacket(t, dst[:n], request)
}

func ipfixFuzzNTP(t *testing.T, selector uint8) {
	t.Helper()
	field := wire.FieldDescriptor{Protocol: wire.ProtocolIPFIX, Field: wire.FieldFlowStart, ID: 156, Length: 8, Encoding: wire.EncodingDateTimeNanoseconds}
	shape := ipfixFuzzShape(t, []wire.FieldDescriptor{field}, 302)
	value := uint64(selector % 8)
	valid := true
	wantErr := error(nil)
	switch selector % 8 {
	case 0:
		value = 0
	case 1:
		value = 1
	case 2:
		value = 1_000_000
	case 3:
		value = 999_999_999
	case 4:
		value = 2_085_978_495_999_999_999
	case 5:
		value = 2_085_978_496_000_000_000
		valid, wantErr = false, wire.ErrTimeOutOfRange
	case 6:
		value = 2_000_000_001
	case 7:
		value = 2_000_000_999
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UnixNanosValue(value)})
	if err != nil {
		t.Fatal(err)
	}
	request := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ExportTimeUnixNanos: 3_000_000_000}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 0}
	dst := bytes.Repeat([]byte{0x91}, 64)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || gotErr != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("NTP case %d = (%d,%v), want %v, mutated=%v", selector%8, n, gotErr, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if gotErr != nil {
		t.Fatalf("NTP case %d: %v", selector%8, gotErr)
	}
	want := [...]uint64{
		0x83aa7e8000000000,
		0x83aa7e8000000004,
		0x83aa7e8000418937,
		0x83aa7e80fffffffc,
		0xfffffffffffffffc,
		0,
		0x83aa7e8200000004,
		0x83aa7e82000010c3,
	}
	if got := binary.BigEndian.Uint64(dst[20:28]); got != want[selector%8] {
		t.Fatalf("NTP case %d = %#x, want %#x", selector%8, got, want[selector%8])
	}
}

func ipfixFuzzWidth(t *testing.T, shapeByte, valueByte uint8) {
	t.Helper()
	fields := [...]struct {
		encoding wire.DescriptorEncoding
		width    uint16
		bits     uint
	}{
		{wire.EncodingUnsigned8, 1, 8}, {wire.EncodingUnsigned16, 2, 16}, {wire.EncodingUnsigned32, 4, 32}, {wire.EncodingUnsigned64, 8, 64},
		{wire.EncodingSigned8, 1, 8}, {wire.EncodingSigned16, 2, 16}, {wire.EncodingSigned32, 4, 32}, {wire.EncodingSigned64, 8, 64},
	}
	field := fields[shapeByte%uint8(len(fields))]
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.scalar", 32473, 200+uint32(shapeByte%8), field.encoding, false, field.width, 0)
	if err != nil {
		t.Fatal(err)
	}
	shape := ipfixFuzzShape(t, []wire.FieldDescriptor{descriptor}, 303)
	value, valid := ipfixFuzzWidthValue(field.encoding, field.bits, valueByte)
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
	if err != nil {
		t.Fatal(err)
	}
	request := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX}, Shape: shape, Records: []wire.WireRecord{record}}
	dst := bytes.Repeat([]byte{0xc3}, 64)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || gotErr != wire.ErrInvalidValue || !bytes.Equal(dst, before) {
			t.Fatalf("width %d case %d = (%d,%v), want invalid value, mutated=%v", field.bits, valueByte%4, n, gotErr, !bytes.Equal(dst, before))
		}
		return
	}
	if gotErr != nil {
		t.Fatalf("width %d case %d: %v", field.bits, valueByte%4, gotErr)
	}
	ipfixFuzzAssertPacket(t, dst[:n], request)
}

func ipfixFuzzMetadata(t *testing.T, shapeByte, valueByte uint8) {
	t.Helper()
	base := fixtureRequest("canonical-ipv4-v1")
	base.TemplateRecords = 0
	base.TemplateBytes = 0
	base.Header.Count = 0
	wantErr := wire.ErrInvalidHeader
	switch shapeByte % 8 {
	case 0:
		base.Header.Protocol = wire.ProtocolV9
		wantErr = wire.ErrInvalidShape
	case 1:
		base.Header.SourceID = 1
	case 2:
		base.Header.Count = 1
	case 3:
		base.DataBytes = 4
		wantErr = wire.ErrBounds
	case 4:
		enterprise, err := wire.NewIPFIXEnterpriseDescriptor("vendor.order", 32473, 300, wire.EncodingUnsigned32, false, 4, 0)
		if err != nil {
			t.Fatal(err)
		}
		fields := []wire.FieldDescriptor{enterprise, base.Shape.Fields()[0]}
		base.Shape = ipfixFuzzShape(t, fields, 304)
		values := []wire.Value{wire.UintValue(uint64(valueByte)), ipfixFuzzCanonicalValue(fields[1], wire.FamilyIPv4)}
		record, err := wire.NewWireRecord(wire.FamilyIPv4, values)
		if err != nil {
			t.Fatal(err)
		}
		base.Records = []wire.WireRecord{record}
		base.TemplateRecords = 1
		base.TemplateBytes = base.Shape.TemplateBytes()
		wantErr = wire.ErrInvalidDescriptor
	case 5:
		base.Header.ExportTimeUnixNanos = (uint64(math.MaxUint32) + 1) * nanosPerSecond
	case 6:
		base.Header.SamplingInterval = 1
	case 7:
		if valueByte&1 == 0 {
			base.Shape = wire.Shape{}
			wantErr = wire.ErrInvalidShape
		} else {
			base.Records = []wire.WireRecord{fixtureRequest("canonical-ipv6-v1").Records[0]}
			wantErr = wire.ErrInvalidFamily
		}
	}
	dst := bytes.Repeat([]byte{0x7e}, 256)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, base)
	if n != 0 || gotErr != wantErr || !bytes.Equal(dst, before) {
		t.Fatalf("metadata case %d = (%d,%v), want %v, mutated=%v", shapeByte%8, n, gotErr, wantErr, !bytes.Equal(dst, before))
	}
}

func ipfixFuzzCapacity(t *testing.T, selector uint8) {
	t.Helper()
	request := fixtureRequest("canonical-ipv4-v1")
	request.TemplateRecords = 0
	request.TemplateBytes = 0
	request.DataBytes = 0
	request.Header.Count = 0
	capacity, budget, valid := 92, uint64(0), true
	wantErr := error(nil)
	switch selector % 8 {
	case 0:
		// Exact data-only canonical IPv4 message: 16-byte header + 4-byte Set + 72-byte record.
	case 1:
		capacity, valid, wantErr = 91, false, wire.ErrShortBuffer
	case 2:
		budget, valid, wantErr = 91, false, wire.ErrBounds
	case 3:
		capacity, budget = 93, 92
	case 4:
		budget, valid, wantErr = 65536, false, wire.ErrBounds
	case 5:
		request.DataBytes, valid, wantErr = 4, false, wire.ErrBounds
	case 6:
		request.Header.Count, valid, wantErr = 1, false, wire.ErrInvalidHeader
	case 7:
		request.TemplateRecords, request.TemplateBytes, capacity = 1, request.Shape.TemplateBytes(), 180
	}
	request.MaxDatagramBytes = budget
	dst := bytes.Repeat([]byte{0xb5}, capacity)
	before := append([]byte(nil), dst...)
	n, gotErr := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || gotErr != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("capacity case %d = (%d,%v), want %v, mutated=%v", selector%8, n, gotErr, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if gotErr != nil {
		t.Fatalf("capacity case %d: %v", selector%8, gotErr)
	}
	ipfixFuzzAssertPacket(t, dst[:n], request)
	if !bytes.Equal(dst[n:], before[n:]) {
		t.Fatalf("capacity case %d changed caller tail", selector%8)
	}
}

func ipfixFuzzStreamAtomic(t *testing.T, shapeByte, valueByte uint8) {
	t.Helper()
	if shapeByte&0x80 != 0 {
		ipfixFuzzStreamVariable(t, valueByte)
		return
	}
	base := fixtureRequest("canonical-ipv4-v1")
	one := base.Records[0]
	second := replaceValue(t, one, 0, wire.UintValue(uint64(valueByte)))
	full := []wire.WireRecord{one, second}
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	request.Header.Count = 0
	request.MaxDatagramBytes = 0
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0x82}, 164)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(one); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	before := append([]byte(nil), dst...)
	selector := shapeByte % 4
	bad := second
	wantErr := wire.ErrInvalidValue
	switch selector {
	case 0:
		bad = replaceValue(t, one, 0, wire.StringValue("bad"))
	case 1:
		other := fixtureRequest("canonical-ipv6-v1")
		bad, wantErr = other.Records[0], wire.ErrInvalidFamily
	case 2:
		request.MaxDatagramBytes = 92
		appender.Reset()
		appender = NewDataPacket()
		if err := appender.Begin(dst, request); err != nil {
			t.Fatalf("budget Begin: %v", err)
		}
		if err := appender.Append(one); err != nil {
			t.Fatalf("budget prefix Append: %v", err)
		}
		before = append([]byte(nil), dst...)
		bad, wantErr = second, wire.ErrBounds
	case 3:
		dst = bytes.Repeat([]byte{0x9a}, 163)
		appender.Reset()
		if err := appender.Begin(dst, request); err != nil {
			t.Fatalf("short Begin: %v", err)
		}
		if err := appender.Append(one); err != nil {
			t.Fatalf("short prefix Append: %v", err)
		}
		before = append([]byte(nil), dst...)
		bad, wantErr = second, wire.ErrShortBuffer
	}
	if err := appender.Append(bad); err != wantErr || !bytes.Equal(dst, before) {
		t.Fatalf("atomic Append case %d = %v, want %v, mutated=%v", selector, err, wantErr, !bytes.Equal(dst, before))
	}
	if selector < 2 {
		if err := appender.Append(second); err != nil {
			t.Fatalf("suffix Append: %v", err)
		}
		n, err := appender.Finish()
		if err != nil || n != 164 {
			t.Fatalf("Finish after rejection = (%d,%v)", n, err)
		}
		ipfixFuzzAssertStreamPacket(t, dst[:n], request.Header, request.Shape, full)
		return
	}
	n, err := appender.Finish()
	if err != nil || n != 92 {
		t.Fatalf("prefix Finish after rejection = (%d,%v)", n, err)
	}
	ipfixFuzzAssertStreamPacket(t, dst[:n], request.Header, request.Shape, full[:1])
	if !bytes.Equal(dst[92:], before[92:]) {
		t.Fatal("late rejection changed unsent suffix")
	}

	// A rejected Begin preserves the active prefix and both caller buffers.
	active := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x93}, 164)
	activeReq := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	if err := active.Begin(oldDst, activeReq); err != nil {
		t.Fatalf("active Begin: %v", err)
	}
	if err := active.Append(one); err != nil {
		t.Fatalf("active prefix: %v", err)
	}
	oldBefore := append([]byte(nil), oldDst...)
	candidate := bytes.Repeat([]byte{0xa4}, 164)
	candidateBefore := append([]byte(nil), candidate...)
	badBegin := activeReq
	badBegin.MaxDatagramBytes = 19
	if err := active.Begin(candidate, badBegin); err != wire.ErrBounds || !bytes.Equal(oldDst, oldBefore) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("rejected Begin = %v, old/candidate mutation", err)
	}
	if err := active.Append(second); err != nil {
		t.Fatalf("old packet after rejected Begin: %v", err)
	}
	if n, err := active.Finish(); err != nil || n != 164 {
		t.Fatalf("old packet Finish = (%d,%v)", n, err)
	}
	ipfixFuzzAssertStreamPacket(t, oldDst, activeReq.Header, activeReq.Shape, full)
}

func ipfixFuzzStreamVariable(t *testing.T, selector uint8) {
	t.Helper()
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.stream", 32473, 305, wire.EncodingOctetArray, true, 65535, 256)
	if err != nil {
		t.Fatal(err)
	}
	shape := ipfixFuzzShape(t, []wire.FieldDescriptor{descriptor}, 305)
	firstLength := 254
	if selector&1 != 0 {
		firstLength = 255
	}
	first, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.OctetsValue(string(bytes.Repeat([]byte{0x51}, firstLength)))})
	if err != nil {
		t.Fatal(err)
	}
	request := wire.DataPacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX}, Shape: shape, MaxRecords: 2}
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0x82}, 600)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("variable Begin: %v", err)
	}
	if err := appender.Append(first); err != nil {
		t.Fatalf("variable first Append: %v", err)
	}
	before := append([]byte(nil), dst...)
	bad := first
	wantErr := wire.ErrBounds
	if selector%4 < 2 {
		bad, err = wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.OctetsValue(string(bytes.Repeat([]byte{0x61}, 257)))})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		firstBytes := 4 + 1 + firstLength
		if firstLength >= 255 {
			firstBytes = 4 + 3 + firstLength
		}
		request.MaxDatagramBytes = uint64(16 + firstBytes)
		appender.Reset()
		appender = NewDataPacket()
		if err := appender.Begin(dst, request); err != nil {
			t.Fatalf("variable budget Begin: %v", err)
		}
		if err := appender.Append(first); err != nil {
			t.Fatalf("variable budget first Append: %v", err)
		}
		before = append([]byte(nil), dst...)
	}
	if err := appender.Append(bad); err != wantErr || !bytes.Equal(dst, before) {
		t.Fatalf("variable late rejection = %v, want %v, mutated=%v", err, wantErr, !bytes.Equal(dst, before))
	}
	n, err := appender.Finish()
	wantLength := 16 + 4 + 1 + firstLength
	if firstLength >= 255 {
		wantLength = 16 + 4 + 3 + firstLength
	}
	if err != nil || n != wantLength {
		t.Fatalf("variable prefix Finish = (%d,%v), want %d", n, err, wantLength)
	}
	ipfixFuzzAssertStreamPacket(t, dst[:n], request.Header, request.Shape, []wire.WireRecord{first})
}

func ipfixFuzzStreamLifecycle(t *testing.T, shapeByte uint8) {
	t.Helper()
	id := "canonical-ipv4-v1"
	if shapeByte&1 != 0 {
		id = "canonical-ipv6-v1"
	}
	base := fixtureRequest(id)
	oneTotal := 92
	if base.Shape.Family() == wire.FamilyIPv6 {
		oneTotal = 116
	}
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0xc6}, oneTotal)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	n, err := appender.Finish()
	if err != nil || n != oneTotal {
		t.Fatalf("Finish = (%d,%v), want %d", n, err, oneTotal)
	}
	ipfixFuzzAssertStreamPacket(t, dst[:n], request.Header, request.Shape, base.Records[:1])
	after := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); err != wire.ErrPacketFinished || !bytes.Equal(dst, after) {
		t.Fatalf("Append after Finish = %v, mutated=%v", err, !bytes.Equal(dst, after))
	}
	if _, err := appender.Finish(); err != wire.ErrPacketFinished || !bytes.Equal(dst, after) {
		t.Fatalf("second Finish = %v", err)
	}
	appender.Reset()
	if err := appender.Append(base.Records[0]); err != wire.ErrPacketNotBegun {
		t.Fatalf("Append after Reset = %v", err)
	}
	if _, err := appender.Finish(); err != wire.ErrPacketNotBegun {
		t.Fatalf("Finish after Reset = %v", err)
	}

	short := NewDataPacket()
	shortRequest := request
	shortRequest.MaxDatagramBytes = uint64(oneTotal - 1)
	shortDst := bytes.Repeat([]byte{0xd7}, oneTotal)
	if err := short.Begin(shortDst, shortRequest); err != nil {
		t.Fatalf("short Begin: %v", err)
	}
	shortBefore := append([]byte(nil), shortDst...)
	if err := short.Append(base.Records[0]); err != wire.ErrBounds || !bytes.Equal(shortDst, shortBefore) {
		t.Fatalf("short Append = %v, mutated=%v", err, !bytes.Equal(shortDst, shortBefore))
	}
	if _, err := short.Finish(); err != wire.ErrPacketEmpty || !bytes.Equal(shortDst, shortBefore) {
		t.Fatalf("short Finish = %v", err)
	}
}

func ipfixFuzzShape(t *testing.T, fields []wire.FieldDescriptor, id uint32) wire.Shape {
	t.Helper()
	var recordLength uint64
	templateBytes := uint64(8)
	for _, field := range fields {
		if field.Variable {
			recordLength++
		} else {
			recordLength += uint64(field.Length)
		}
		templateBytes += 4
		if field.Enterprise {
			templateBytes += 4
		}
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: id, Fields: fields, RecordLength: recordLength, TemplateBytes: templateBytes})
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	return shape
}

func ipfixFuzzCanonicalValue(field wire.FieldDescriptor, family wire.Family) wire.Value {
	switch field.Encoding {
	case wire.EncodingIPv4Address:
		address, _ := netip.ParseAddr("192.0.2.1")
		return wire.IPValue(address)
	case wire.EncodingIPv6Address:
		address, _ := netip.ParseAddr("2001:db8::1")
		return wire.IPValue(address)
	case wire.EncodingMACAddress:
		return wire.MACValue([6]byte{0, 1, 2, 3, 4, 5})
	case wire.EncodingDateTimeNanoseconds:
		return wire.UnixNanosValue(1_500_000_000)
	case wire.EncodingString:
		return wire.StringValue("x")
	case wire.EncodingOctetArray:
		return wire.OctetsValue("x")
	default:
		if field.Encoding >= wire.EncodingSigned8 && field.Encoding <= wire.EncodingSigned64 {
			return wire.IntValue(1)
		}
		if family == wire.FamilyIPv6 {
			return wire.UintValue(1)
		}
		return wire.UintValue(1)
	}
}

func ipfixFuzzWidthValue(encoding wire.DescriptorEncoding, bits uint, selector uint8) (wire.Value, bool) {
	signed := encoding >= wire.EncodingSigned8 && encoding <= wire.EncodingSigned64
	switch selector % 4 {
	case 0:
		if signed {
			return wire.IntValue(0), true
		}
		return wire.UintValue(0), true
	case 1:
		if signed {
			if bits == 64 {
				return wire.IntValue(math.MaxInt64), true
			}
			return wire.IntValue((int64(1) << (bits - 1)) - 1), true
		}
		if bits == 64 {
			return wire.UintValue(math.MaxUint64), true
		}
		return wire.UintValue((uint64(1) << bits) - 1), true
	case 2:
		if signed {
			if bits == 64 {
				return wire.UintValue(1), false
			}
			return wire.IntValue(int64(1) << (bits - 1)), false
		}
		if bits == 64 {
			return wire.IntValue(-1), false
		}
		return wire.UintValue(uint64(1) << bits), false
	default:
		if signed {
			return wire.IntValue(-1), true
		}
		return wire.IntValue(-1), false
	}
}

func ipfixFuzzKnownNTP(unixNanos uint64) (uint64, bool) {
	// Full-word vectors are authored from RFC 7011's NTP epoch and fraction
	// examples. The packet oracle only needs the finite timestamp values used by
	// the immutable fixtures; the boundary grammar above has its own literals.
	switch unixNanos {
	case 1_500_000_000:
		return 0x83aa7e8180000000, true
	case 1_788_220_801_000_000_000:
		return 0xee40940100000000, true
	case 1_788_220_801_001_000_000:
		return 0xee40940100418937, true
	default:
		return 0, false
	}
}

// ipfixFuzzAssertPacket is intentionally test-owned: it computes the complete
// message from descriptor widths and values, including RFC 7011 Set padding.
func ipfixFuzzAssertPacket(t *testing.T, packet []byte, request wire.PacketRequest) {
	t.Helper()
	fields := request.Shape.Fields()
	templateBytes := 0
	if request.TemplateRecords != 0 {
		templateBytes = 8 + 4*len(fields)
		for _, field := range fields {
			if field.Enterprise {
				templateBytes += 4
			}
		}
	}
	recordBytes := 0
	for _, record := range request.Records {
		for i, field := range fields {
			value, ok := record.ValueAt(i)
			if !ok {
				t.Fatalf("record missing field %d", i)
			}
			recordBytes += ipfixFuzzEncodedValueLength(field, value)
		}
	}
	dataBytes := 0
	padding := 0
	if len(request.Records) != 0 {
		dataBytes = 4 + recordBytes
		padding = ipfixFuzzExpectedPadding(fields, recordBytes)
		dataBytes += padding
	}
	total := 16 + int(request.TemplateRecords)*templateBytes + dataBytes
	if len(packet) != total {
		t.Fatalf("packet length = %d, want %d", len(packet), total)
	}
	want := make([]byte, total)
	binary.BigEndian.PutUint16(want[0:2], 10)
	binary.BigEndian.PutUint16(want[2:4], uint16(total))
	binary.BigEndian.PutUint32(want[4:8], uint32(request.Header.ExportTimeUnixNanos/1_000_000_000))
	binary.BigEndian.PutUint32(want[8:12], request.Header.Sequence)
	binary.BigEndian.PutUint32(want[12:16], request.Header.ObservationDomainID)
	offset := 16
	for i := uint64(0); i < request.TemplateRecords; i++ {
		binary.BigEndian.PutUint16(want[offset:offset+2], 2)
		binary.BigEndian.PutUint16(want[offset+2:offset+4], uint16(templateBytes))
		binary.BigEndian.PutUint16(want[offset+4:offset+6], request.Shape.ID())
		binary.BigEndian.PutUint16(want[offset+6:offset+8], uint16(len(fields)))
		offset += 8
		for _, field := range fields {
			id := field.ID
			if field.Enterprise {
				id |= 0x8000
			}
			binary.BigEndian.PutUint16(want[offset:offset+2], id)
			binary.BigEndian.PutUint16(want[offset+2:offset+4], field.Length)
			offset += 4
			if field.Enterprise {
				binary.BigEndian.PutUint32(want[offset:offset+4], field.PEN)
				offset += 4
			}
		}
	}
	if len(request.Records) != 0 {
		binary.BigEndian.PutUint16(want[offset:offset+2], request.Shape.ID())
		binary.BigEndian.PutUint16(want[offset+2:offset+4], uint16(dataBytes))
		offset += 4
		for _, record := range request.Records {
			for i, field := range fields {
				value, _ := record.ValueAt(i)
				ipfixFuzzWriteExpectedValue(want[offset:], field, value)
				offset += ipfixFuzzEncodedValueLength(field, value)
			}
		}
		for i := 0; i < padding; i++ {
			want[offset+i] = 0
		}
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet bytes differ from independent oracle: got %x want %x", packet, want)
	}
}

func ipfixFuzzAssertStreamPacket(t *testing.T, packet []byte, header wire.HeaderMetadata, shape wire.Shape, records []wire.WireRecord) {
	t.Helper()
	request := wire.PacketRequest{Header: header, Shape: shape, Records: records}
	ipfixFuzzAssertPacket(t, packet, request)
}

func ipfixFuzzEncodedValueLength(field wire.FieldDescriptor, value wire.Value) int {
	if field.Variable {
		length := value.ByteLen()
		if field.Encoding == wire.EncodingString {
			length = len(value.Text())
		}
		if length >= 255 {
			return 3 + length
		}
		return 1 + length
	}
	return int(field.Length)
}

func ipfixFuzzWriteExpectedValue(dst []byte, field wire.FieldDescriptor, value wire.Value) {
	if field.Variable {
		length := value.ByteLen()
		if field.Encoding == wire.EncodingString {
			length = len(value.Text())
		}
		if length < 255 {
			dst[0] = byte(length)
			dst = dst[1:]
		} else {
			dst[0] = 255
			binary.BigEndian.PutUint16(dst[1:3], uint16(length))
			dst = dst[3:]
		}
		if field.Encoding == wire.EncodingString {
			copy(dst, value.Text())
		} else {
			for i := 0; i < value.ByteLen(); i++ {
				dst[i] = value.ByteAt(i)
			}
		}
		return
	}
	scalar := value.Uint()
	if value.Kind() == wire.ValueInt {
		scalar = uint64(value.Int())
	}
	switch field.Encoding {
	case wire.EncodingUnsigned8, wire.EncodingSigned8:
		dst[0] = byte(scalar)
	case wire.EncodingUnsigned16, wire.EncodingSigned16:
		binary.BigEndian.PutUint16(dst, uint16(scalar))
	case wire.EncodingUnsigned32, wire.EncodingSigned32:
		binary.BigEndian.PutUint32(dst, uint32(scalar))
	case wire.EncodingUnsigned64, wire.EncodingSigned64:
		binary.BigEndian.PutUint64(dst, scalar)
	case wire.EncodingIPv4Address:
		address := value.IP().As4()
		copy(dst, address[:])
	case wire.EncodingIPv6Address:
		address := value.IP().As16()
		copy(dst, address[:])
	case wire.EncodingMACAddress:
		mac := value.MAC()
		copy(dst, mac[:])
	case wire.EncodingString:
		copy(dst, value.Text())
	case wire.EncodingOctetArray:
		for i := 0; i < value.ByteLen(); i++ {
			dst[i] = value.ByteAt(i)
		}
	case wire.EncodingDateTimeNanoseconds:
		encoded, ok := ipfixFuzzKnownNTP(value.UnixNanos())
		if !ok {
			panic("unreviewed timestamp in IPFIX fuzz oracle")
		}
		binary.BigEndian.PutUint64(dst, encoded)
	}
}

func ipfixFuzzExpectedPadding(fields []wire.FieldDescriptor, recordBytes int) int {
	for _, field := range fields {
		if field.Variable {
			return 0
		}
	}
	// The finite grammar has two accepted odd-width fixed shapes: the
	// canonical {IE 2, IE 5} subset is nine bytes and the reordered
	// {IE 5, IE 2, enterprise} case is thirteen bytes. Fixed text/octet
	// fixtures also cover widths 254 and 255, whose legal padding is two and
	// one bytes respectively. All other accepted grammar cases are already
	// four-byte aligned or use a variable minimum of one byte, so their legal
	// padding is zero.
	switch recordBytes {
	case 9, 13:
		return 3
	case 254:
		return 2
	case 255:
		return 1
	default:
		return 0
	}
}
