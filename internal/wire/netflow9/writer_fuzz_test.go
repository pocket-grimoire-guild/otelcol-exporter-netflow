package netflow9

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// FuzzNetFlow9Writer exercises both v9 writer entry points with a bounded
// scalar grammar. Every input is four uint8 selectors; records, values, and
// output buffers are consequently small and deterministic. The packet oracle
// below computes template/data lengths and every encoded value independently
// of Shape sizing and the writer implementation.
func FuzzNetFlow9Writer(f *testing.F) {
	seeds := [][4]uint8{
		{0, 0, 0, 0}, {0, 1, 0, 0}, {0, 2, 0, 0},
		{1, 0, 0, 0}, {1, 1, 1, 0}, {1, 2, 2, 0}, {1, 3, 3, 0}, {1, 4, 4, 0},
		{2, 0, 0, 0}, {2, 1, 1, 0}, {2, 2, 2, 0}, {2, 3, 3, 0}, {2, 4, 0, 0}, {2, 5, 1, 0},
		{3, 0, 0, 0}, {3, 0, 1, 0}, {3, 0, 2, 0}, {3, 0, 3, 0}, {3, 0, 4, 0}, {3, 0, 5, 0}, {3, 0, 6, 0}, {3, 0, 7, 0},
		{4, 0, 0, 0}, {4, 0, 1, 0}, {4, 0, 2, 0}, {4, 0, 3, 0}, {4, 0, 4, 0}, {4, 0, 5, 0}, {4, 0, 6, 0}, {4, 0, 7, 0},
		{5, 0, 0, 0}, {5, 0, 0, 1}, {5, 0, 0, 2}, {5, 0, 0, 3},
		{6, 0, 0, 0}, {6, 1, 0, 1}, {6, 0, 2, 2}, {6, 1, 3, 3},
		{7, 0, 0, 0}, {7, 1, 1, 1},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, scenarioByte, shapeByte, valueByte, capacityByte uint8) {
		switch scenarioByte % 8 {
		case 0:
			v9FuzzGolden(t, shapeByte, valueByte)
		case 1:
			v9FuzzShapes(t, shapeByte, valueByte)
		case 2:
			v9FuzzWidth(t, shapeByte, valueByte)
		case 3:
			v9FuzzTime(t, valueByte)
		case 4:
			v9FuzzMetadata(t, valueByte)
		case 5:
			v9FuzzCapacity(t, capacityByte)
		case 6:
			v9FuzzStreamAtomic(t, shapeByte, valueByte, capacityByte)
		case 7:
			v9FuzzStreamLifecycle(t, shapeByte, valueByte)
		}
	})
}

func v9FuzzGolden(t *testing.T, shapeByte, sequenceByte uint8) {
	t.Helper()
	fixtures := [...]struct{ id, golden string }{
		{"canonical-ipv4-v1", "canonical-ipv4-v1.bin"},
		{"canonical-ipv6-v1", "canonical-ipv6-v1.bin"},
		{"sampling-ie34-two-distinct-rates-v9-v1", "sampling-ie34-two-distinct-rates-v1.bin"},
	}
	tc := fixtures[shapeByte%uint8(len(fixtures))]
	request := fixtureRequest(t, tc.id)
	request.Header.Sequence = uint32(sequenceByte)
	dst := bytes.Repeat([]byte{0xa5}, 256)
	n, err := (Writer{}).Write(dst, request)
	if err != nil {
		t.Fatalf("golden write: %v", err)
	}
	assertV9FuzzPacket(t, dst[:n], request)
	if sequenceByte == 0 && !bytes.Equal(dst[:n], readGolden(t, tc.golden)) {
		t.Fatalf("%s differs from immutable golden", tc.id)
	}
}

func v9FuzzShapes(t *testing.T, shapeByte, valueByte uint8) {
	t.Helper()
	base := fixtureRequest(t, "canonical-ipv4-v1")
	switch shapeByte % 5 {
	case 0:
		base.Header.Sequence = uint32(valueByte)
		writeAndAssertV9(t, base)
	case 1: // Template-only packet.
		base.Records = nil
		base.Header.Count = 1
		writeAndAssertV9(t, base)
	case 2: // Data-only packet.
		base.TemplateRecords = 0
		base.TemplateBytes = 0
		base.Records = base.Records[:1]
		base.Header.Count = uint16(len(base.Records))
		writeAndAssertV9(t, base)
	case 3: // A fixed one-byte private record exercises the v9 5-byte set edge.
		shape := customByteShape(t)
		record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(uint64(valueByte))})
		if err != nil {
			t.Fatal(err)
		}
		request := privateRequest(shape, record)
		writeAndAssertV9(t, request)
	case 4: // Padding is omitted when it is equal to the smallest record.
		shape := privateScalarShape(t, wire.EncodingUnsigned16, 2, 301)
		record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(uint64(valueByte))})
		if err != nil {
			t.Fatal(err)
		}
		request := privateRequest(shape, record)
		writeAndAssertV9(t, request)
	}
}

func v9FuzzWidth(t *testing.T, shapeByte, valueByte uint8) {
	t.Helper()
	fields := [...]struct {
		encoding wire.DescriptorEncoding
		width    uint16
		bits     uint
	}{
		{wire.EncodingUnsigned8, 1, 8}, {wire.EncodingUnsigned16, 2, 16},
		{wire.EncodingUnsigned32, 4, 32}, {wire.EncodingUnsigned64, 8, 64},
		{wire.EncodingSigned8, 1, 8}, {wire.EncodingSigned16, 2, 16},
		{wire.EncodingSigned32, 4, 32}, {wire.EncodingSigned64, 8, 64},
	}
	field := fields[shapeByte%uint8(len(fields))]
	value, valid := v9WidthValue(field.encoding, field.bits, valueByte)
	shape := privateScalarShape(t, field.encoding, field.width, 40000+uint32(shapeByte%8))
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
	if err != nil {
		t.Fatal(err)
	}
	request := privateRequest(shape, record)
	dst := bytes.Repeat([]byte{0xc3}, 64)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wire.ErrInvalidValue || !bytes.Equal(dst, before) {
			t.Fatalf("width rejection = (%d,%v), mutated=%v", n, err, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil {
		t.Fatalf("width write: %v", err)
	}
	assertV9FuzzPacket(t, dst[:n], request)
}

func v9WidthValue(encoding wire.DescriptorEncoding, bits uint, selector uint8) (wire.Value, bool) {
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
		if signed && bits < 64 {
			return wire.IntValue(int64(1) << (bits - 1)), false
		}
		if !signed && bits < 64 {
			return wire.UintValue(uint64(1) << bits), false
		}
		if signed {
			return wire.UintValue(1), false
		}
		return wire.IntValue(-1), false
	default:
		return wire.IntValue(-1), signed
	}
}

func v9FuzzTime(t *testing.T, selector uint8) {
	t.Helper()
	shape := timestampShape(t,
		wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowStart, ID: 22, Length: 4, Encoding: wire.EncodingUnsigned32},
		wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowEnd, ID: 21, Length: 4, Encoding: wire.EncodingUnsigned32},
	)
	origin := uint64(1_700_000_000) * nanosPerSec
	start, end, export := origin+1234*nanosPerMS, origin+2345*nanosPerMS, origin+3000*nanosPerMS
	valid := true
	wantErr := wire.ErrInvalidValue
	switch selector % 8 {
	case 1:
		start = origin - nanosPerMS
		valid = false
	case 2:
		start = origin + 1
		valid = false
	case 3:
		start, end = origin+2500*nanosPerMS, origin+2000*nanosPerMS
		valid = false
	case 4:
		start = origin + 3001*nanosPerMS
		valid = false
	case 5:
		export = origin + uint64(math.MaxUint32)*nanosPerMS
		start, end = origin+nanosPerMS, origin+2*nanosPerMS
	case 6:
		export = origin + (uint64(math.MaxUint32)+1)*nanosPerMS
		valid = false
		wantErr = wire.ErrInvalidHeader
	case 7:
		valid = false
		wantErr = wire.ErrInvalidHeader
	}
	request := timestampRequest(t, shape, origin, start, end, export)
	if selector%8 == 7 {
		request.Header.HasUptimeOrigin = false
	}
	dst := bytes.Repeat([]byte{0x7e}, 64)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("time case %d = (%d,%v), want %v, mutated=%v", selector%8, n, err, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil {
		t.Fatalf("time write: %v", err)
	}
	assertV9FuzzPacket(t, dst[:n], request)
}

func v9FuzzMetadata(t *testing.T, selector uint8) {
	t.Helper()
	request := fixtureRequest(t, "canonical-ipv4-v1")
	wantErr := wire.ErrInvalidHeader
	switch selector % 8 {
	case 0:
		request.Header.Count++
	case 1:
		request.Header.ObservationDomainID++
	case 2:
		request.Header.HasUptimeOrigin = false
	case 3:
		request.Header.UptimeOriginUnixNanos = request.Header.ExportTimeUnixNanos + 1
	case 4:
		request.Header.ExportTimeUnixNanos = (uint64(math.MaxUint32) + 1) * nanosPerSec
	case 5:
		request.Header.SamplingMode = 1
	case 6:
		request.Header.SamplingInterval = 1
	case 7:
		request.Header.Protocol = wire.ProtocolV5
		wantErr = wire.ErrInvalidShape
	}
	if selector%8 == 0 {
		// Keep the count failure distinct from the observation-domain check.
		request.Header.Count = 1
	}
	if selector%8 == 7 {
		request.Header.Count = 3
	}
	dst := bytes.Repeat([]byte{0x91}, 256)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
		t.Fatalf("metadata case %d = (%d,%v), want %v, mutated=%v", selector%8, n, err, wantErr, !bytes.Equal(dst, before))
	}
}

func v9FuzzCapacity(t *testing.T, selector uint8) {
	t.Helper()
	base := fixtureRequest(t, "canonical-ipv4-v1")
	base.TemplateRecords = 0
	base.TemplateBytes = 0
	base.Records = base.Records[:1]
	base.Header.Count = 1
	base.DataBytes = 0
	capacity, budget, valid := 68, uint64(68), true
	wantErr := wire.ErrBounds
	switch selector % 8 {
	case 1:
		capacity, budget, valid, wantErr = 67, 0, false, wire.ErrShortBuffer
	case 2:
		capacity, budget, valid = 68, 67, false
	case 3:
		capacity, budget = 69, 68
	case 4:
		budget, valid = 65536, false
	case 5:
		base.DataBytes, valid = 49, false
	case 6:
		base.Header.Count, valid, wantErr = 2, false, wire.ErrInvalidHeader
	case 7:
		base.TemplateRecords, base.TemplateBytes = 1, base.Shape.TemplateBytes()
		base.Header.Count, capacity, budget, valid = 2, 148, 0, true
	}
	dst := bytes.Repeat([]byte{0xb5}, capacity)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, func() wire.PacketRequest {
		base.MaxDatagramBytes = budget
		return base
	}())
	if !valid {
		if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("capacity case %d = (%d,%v), want %v, mutated=%v", selector%8, n, err, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil {
		t.Fatalf("capacity case %d: %v", selector%8, err)
	}
	assertV9FuzzPacket(t, dst[:n], base)
	if !bytes.Equal(dst[n:], before[n:]) {
		t.Fatalf("capacity case %d changed caller tail", selector%8)
	}
}

func v9FuzzStreamAtomic(t *testing.T, shapeByte, valueByte, selector uint8) {
	t.Helper()
	baseID := "canonical-ipv4-v1"
	if shapeByte&1 != 0 {
		baseID = "canonical-ipv6-v1"
	}
	base := fixtureRequest(t, baseID)
	one := base.Records[0]
	full := []wire.WireRecord{one, recordWith(t, one, 0, wire.UintValue(uint64(valueByte)))}
	oneTotal := 68
	twoTotal := 112
	if base.Shape.Family() == wire.FamilyIPv6 {
		oneTotal, twoTotal = 92, 160
	}
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	request.Header.Count = 0
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0x82}, twoTotal)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(one); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	before := append([]byte(nil), dst...)
	var bad wire.WireRecord
	wantErr := wire.ErrInvalidValue
	switch selector % 4 {
	case 0:
		bad = recordWith(t, one, 0, wire.UintValue(uint64(math.MaxUint32)+1))
	case 1:
		other := fixtureRequest(t, "canonical-ipv6-v1")
		if base.Shape.Family() == wire.FamilyIPv6 {
			other = fixtureRequest(t, "canonical-ipv4-v1")
		}
		bad, wantErr = other.Records[0], wire.ErrInvalidFamily
	case 2:
		request.MaxDatagramBytes = uint64(oneTotal)
		appender.Reset()
		appender = NewDataPacket()
		if err := appender.Begin(dst, request); err != nil {
			t.Fatalf("budget Begin: %v", err)
		}
		if err := appender.Append(one); err != nil {
			t.Fatalf("budget prefix Append: %v", err)
		}
		before = append([]byte(nil), dst...)
		bad = full[1]
		wantErr = wire.ErrBounds
	case 3:
		request.MaxDatagramBytes = 0
		appender.Reset()
		appender = NewDataPacket()
		short := bytes.Repeat([]byte{0x9a}, twoTotal-1)
		dst = short
		if err := appender.Begin(dst, request); err != nil {
			t.Fatalf("short Begin: %v", err)
		}
		if err := appender.Append(one); err != nil {
			t.Fatalf("short prefix Append: %v", err)
		}
		before = append([]byte(nil), dst...)
		bad = full[1]
		wantErr = wire.ErrShortBuffer
	}
	if selector%4 < 2 {
		if err := appender.Append(bad); err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("atomic Append = %v, want %v, mutated=%v", err, wantErr, !bytes.Equal(dst, before))
		}
		if err := appender.Append(full[1]); err != nil {
			t.Fatalf("suffix Append: %v", err)
		}
		n, err := appender.Finish()
		if err != nil || n != twoTotal {
			t.Fatalf("Finish after rejection = (%d,%v), want (%d,nil)", n, err, twoTotal)
		}
		request.Header.Count = 2
		assertV9FuzzPacket(t, dst[:n], wire.PacketRequest{Header: request.Header, Shape: request.Shape, Records: full})
	} else {
		if err := appender.Append(bad); err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("late Append = %v, want %v, mutated=%v", err, wantErr, !bytes.Equal(dst, before))
		}
		n, err := appender.Finish()
		if err != nil || n != oneTotal {
			t.Fatalf("prefix Finish = (%d,%v), want (%d,nil)", n, err, oneTotal)
		}
		request.Header.Count = 1
		assertV9FuzzPacket(t, dst[:n], wire.PacketRequest{Header: request.Header, Shape: request.Shape, Records: full[:1]})
		if !bytes.Equal(dst[oneTotal:], before[oneTotal:]) {
			t.Fatal("late rejection changed unsent suffix")
		}
	}

	// A rejected Begin preserves the active prefix and both caller buffers.
	active := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x93}, twoTotal)
	activeReq := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	activeReq.Header.Count = 0
	if err := active.Begin(oldDst, activeReq); err != nil {
		t.Fatalf("active Begin: %v", err)
	}
	if err := active.Append(one); err != nil {
		t.Fatalf("active prefix: %v", err)
	}
	oldBefore := append([]byte(nil), oldDst...)
	candidate := bytes.Repeat([]byte{0xa4}, twoTotal)
	candidateBefore := append([]byte(nil), candidate...)
	badBegin := activeReq
	badBegin.MaxDatagramBytes = 23
	if err := active.Begin(candidate, badBegin); err != wire.ErrBounds || !bytes.Equal(oldDst, oldBefore) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("rejected Begin = %v, old/candidate mutation", err)
	}
	if err := active.Append(full[1]); err != nil {
		t.Fatalf("old packet after rejected Begin: %v", err)
	}
	if n, err := active.Finish(); err != nil || n != twoTotal {
		t.Fatalf("old packet Finish = (%d,%v)", n, err)
	}
	activeReq.Header.Count = 2
	assertV9FuzzPacket(t, oldDst, wire.PacketRequest{Header: activeReq.Header, Shape: activeReq.Shape, Records: full})
}

func v9FuzzStreamLifecycle(t *testing.T, shapeByte, sequenceByte uint8) {
	t.Helper()
	id := "canonical-ipv4-v1"
	if shapeByte&1 != 0 {
		id = "canonical-ipv6-v1"
	}
	base := fixtureRequest(t, id)
	oneTotal := 68
	if base.Shape.Family() == wire.FamilyIPv6 {
		oneTotal = 92
	}
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	request.Header.Sequence = uint32(sequenceByte)
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
		t.Fatalf("Finish = (%d,%v)", n, err)
	}
	request.Header.Count = 1
	assertV9FuzzPacket(t, dst, wire.PacketRequest{Header: request.Header, Shape: request.Shape, Records: base.Records[:1]})
	after := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); err != wire.ErrPacketFinished || !bytes.Equal(dst, after) {
		t.Fatalf("Append after Finish = %v, mutated=%v", err, !bytes.Equal(dst, after))
	}
	if _, err := appender.Finish(); err != wire.ErrPacketFinished || !bytes.Equal(dst, after) {
		t.Fatalf("second Finish = %v, mutated=%v", err, !bytes.Equal(dst, after))
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
	shortRequest.Header.Count = 0
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
		t.Fatalf("short Finish = %v, mutated=%v", err, !bytes.Equal(shortDst, shortBefore))
	}
}

func writeAndAssertV9(t *testing.T, request wire.PacketRequest) {
	t.Helper()
	dst := bytes.Repeat([]byte{0xa5}, 256)
	n, err := (Writer{}).Write(dst, request)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	assertV9FuzzPacket(t, dst[:n], request)
}

func privateRequest(shape wire.Shape, record wire.WireRecord) wire.PacketRequest {
	return wire.PacketRequest{
		Header: wire.HeaderMetadata{
			Protocol: wire.ProtocolV9, SourceID: 9, ObservationDomainID: 9, Count: 2,
			ExportTimeUnixNanos: 3 * nanosPerSec, UptimeOriginUnixNanos: 1 * nanosPerSec, HasUptimeOrigin: true,
		},
		Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes(),
	}
}

func privateScalarShape(t *testing.T, encoding wire.DescriptorEncoding, width uint16, id uint32) wire.Shape {
	t.Helper()
	descriptor, err := wire.NewV9PrivateDescriptor("vendor.scalar", id, encoding, width)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: id, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: uint64(width), TemplateBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	return shape
}

// assertV9FuzzPacket is a test-owned byte oracle. It applies RFC 3954's
// padding rule: one to three padding bytes are emitted only when strictly
// shorter than the smallest record. In particular, a fixed one-byte record
// has a five-byte FlowSet with no padding.
func assertV9FuzzPacket(t *testing.T, packet []byte, request wire.PacketRequest) {
	t.Helper()
	fields := request.Shape.Fields()
	templateBytes := 8 + 4*len(fields)
	minRecordBytes := 0
	for _, field := range fields {
		minRecordBytes += int(field.Length)
	}
	recordBytes := 0
	for range request.Records {
		recordBytes += minRecordBytes
	}
	dataBytes := 0
	padding := 0
	if len(request.Records) != 0 {
		dataBytes = 4 + recordBytes
		if remainder := dataBytes % 4; remainder != 0 {
			candidate := 4 - remainder
			if candidate < minRecordBytes {
				padding = candidate
				dataBytes += padding
			}
		}
	}
	total := headerLength + int(request.TemplateRecords)*templateBytes + dataBytes
	if len(packet) != total {
		t.Fatalf("packet length = %d, want %d", len(packet), total)
	}
	want := make([]byte, total)
	binary.BigEndian.PutUint16(want[0:2], 9)
	binary.BigEndian.PutUint16(want[2:4], request.Header.Count)
	binary.BigEndian.PutUint32(want[4:8], uint32((request.Header.ExportTimeUnixNanos-request.Header.UptimeOriginUnixNanos)/nanosPerMS))
	binary.BigEndian.PutUint32(want[8:12], uint32(request.Header.ExportTimeUnixNanos/nanosPerSec))
	binary.BigEndian.PutUint32(want[12:16], request.Header.Sequence)
	binary.BigEndian.PutUint32(want[16:20], request.Header.SourceID)
	offset := headerLength
	for i := uint64(0); i < request.TemplateRecords; i++ {
		binary.BigEndian.PutUint16(want[offset:offset+2], 0)
		binary.BigEndian.PutUint16(want[offset+2:offset+4], uint16(templateBytes))
		binary.BigEndian.PutUint16(want[offset+4:offset+6], request.Shape.ID())
		binary.BigEndian.PutUint16(want[offset+6:offset+8], uint16(len(fields)))
		offset += 8
		for _, field := range fields {
			binary.BigEndian.PutUint16(want[offset:offset+2], field.ID)
			binary.BigEndian.PutUint16(want[offset+2:offset+4], field.Length)
			offset += 4
		}
	}
	if len(request.Records) != 0 {
		binary.BigEndian.PutUint16(want[offset:offset+2], request.Shape.ID())
		binary.BigEndian.PutUint16(want[offset+2:offset+4], uint16(dataBytes))
		offset += 4
		for _, record := range request.Records {
			for index, field := range fields {
				value, ok := record.ValueAt(index)
				if !ok {
					t.Fatalf("record %d missing field %d", len(request.Records), index)
				}
				writeV9ExpectedValue(want[offset:], field, value, request.Header.UptimeOriginUnixNanos)
				offset += int(field.Length)
			}
		}
		for i := 0; i < padding; i++ {
			want[offset+i] = 0
		}
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet bytes differ from independent oracle: got %x want %x", packet, want)
	}
	if request.Shape.FieldCount() == 18 && request.TemplateRecords != 0 {
		assertV9CanonicalTemplate(t, packet, request.Shape.Family())
	}
}

func assertV9CanonicalTemplate(t *testing.T, packet []byte, family wire.Family) {
	t.Helper()
	ids := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60}
	lengths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1}
	if family == wire.FamilyIPv6 {
		ids[6], ids[7], ids[10], ids[11] = 27, 29, 28, 30
		lengths[6], lengths[10] = 16, 16
	}
	for index := range ids {
		offset := headerLength + 8 + index*4
		if got := binary.BigEndian.Uint16(packet[offset : offset+2]); got != ids[index] {
			t.Fatalf("template field %d ID = %d, want %d", index, got, ids[index])
		}
		if got := binary.BigEndian.Uint16(packet[offset+2 : offset+4]); got != lengths[index] {
			t.Fatalf("template field %d length = %d, want %d", index, got, lengths[index])
		}
	}
}

func writeV9ExpectedValue(dst []byte, descriptor wire.FieldDescriptor, value wire.Value, origin uint64) {
	if descriptor.Field == wire.FieldFlowStart || descriptor.Field == wire.FieldFlowEnd {
		binary.BigEndian.PutUint32(dst, uint32((value.UnixNanos()-origin)/nanosPerMS))
		return
	}
	scalar := value.Uint()
	if value.Kind() == wire.ValueInt {
		scalar = uint64(value.Int())
	}
	switch descriptor.Encoding {
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
	}
}
