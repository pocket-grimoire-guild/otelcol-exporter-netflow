package netflow5

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// FuzzNetFlow5Writer exercises the pure v5 writer and streaming appender with
// a small, test-owned scalar grammar. Inputs are all uint8 values, so every
// setup has a fixed finite bound and no external state. The byte oracle below
// uses Cisco's fixed B-3/B-4 offsets independently of the production writer.
func FuzzNetFlow5Writer(f *testing.F) {
	f.Fuzz(func(t *testing.T, scenarioByte, countByte, valueByte, capacityByte uint8) {
		switch scenarioByte % 8 {
		case 0:
			v5FuzzFull(t, countByte)
		case 1:
			v5FuzzWidth(t, valueByte, countByte)
		case 2:
			v5FuzzTime(t, valueByte)
		case 3:
			v5FuzzHeader(t, valueByte)
		case 4:
			v5FuzzAddress(t, valueByte)
		case 5:
			v5FuzzCapacity(t, capacityByte)
		case 6:
			v5FuzzStreamAtomic(t, valueByte)
		case 7:
			v5FuzzStreamLifecycle(t, valueByte)
		}
	})
}

func v5FuzzFull(t *testing.T, countByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	counts := [...]int{1, 30, 0, 31}
	count := counts[countByte%uint8(len(counts))]
	records := make([]wire.WireRecord, count)
	for i := range records {
		records[i] = base.Records[0]
	}
	request := cloneRequest(base)
	request.Header.Count = uint16(count)
	request.Records = records

	// The extra record slot keeps the rejected 31-record case bounded while
	// still proving that the writer rejects the protocol's fixed maximum.
	dst := bytes.Repeat([]byte{0xa5}, headerLength+recordLength*max(1, count))
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if count == 0 || count == 31 {
		if n != 0 || err != wire.ErrBounds || !bytes.Equal(dst, before) {
			t.Fatalf("count %d rejection = (%d,%v), mutated=%v", count, n, err, !bytes.Equal(dst, before))
		}
		return
	}
	want := headerLength + recordLength*count
	if err != nil || n != want {
		t.Fatalf("count %d write = (%d,%v), want (%d,nil)", count, n, err, want)
	}
	assertV5FuzzPacket(t, dst[:n], request)
	if count == 1 && !bytes.Equal(dst[:n], readGolden(t)) {
		t.Fatal("canonical v5 fuzz packet differs from immutable golden")
	}
}

func v5FuzzWidth(t *testing.T, valueByte, fieldByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	// These are the non-address, non-time wire fields in Cisco B-4 order.
	fields := [...]struct {
		index int
		max   uint64
	}{
		{index: 3, max: math.MaxUint16}, {index: 4, max: math.MaxUint16},
		{index: 5, max: math.MaxUint32}, {index: 6, max: math.MaxUint32},
		{index: 9, max: math.MaxUint16}, {index: 10, max: math.MaxUint16},
		{index: 12, max: math.MaxUint8}, {index: 13, max: math.MaxUint8},
		{index: 14, max: math.MaxUint8}, {index: 15, max: math.MaxUint16},
		{index: 16, max: math.MaxUint16}, {index: 17, max: math.MaxUint8},
		{index: 18, max: math.MaxUint8},
	}
	field := fields[fieldByte%uint8(len(fields))]
	if field.index == 17 || field.index == 18 {
		field.max = 32 // v5 IPv4 prefix masks are limited to /32.
	}
	var value wire.Value
	valid := true
	switch valueByte % 4 {
	case 0:
		value = wire.UintValue(0)
	case 1:
		value = wire.UintValue(field.max)
	case 2:
		value = wire.UintValue(field.max + 1)
		valid = false
	default:
		value = wire.IntValue(-1)
		valid = false
	}
	request := cloneRequest(base)
	request.Records[0] = recordWith(t, base.Records[0], field.index, value)
	dst := bytes.Repeat([]byte{0xc3}, headerLength+recordLength)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wire.ErrInvalidValue || !bytes.Equal(dst, before) {
			t.Fatalf("field %d invalid width = (%d,%v), mutated=%v", field.index, n, err, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil || n != len(dst) {
		t.Fatalf("field %d maximum width = (%d,%v), want (%d,nil)", field.index, n, err, len(dst))
	}
	assertV5FuzzPacket(t, dst, request)
}

func v5FuzzTime(t *testing.T, valueByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := cloneRequest(base)
	origin := request.Header.UptimeOriginUnixNanos
	valid := false
	wantErr := wire.ErrInvalidValue
	switch valueByte % 10 {
	case 0:
		request.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(origin-1))
	case 1:
		request.Records[0] = recordWith(t, base.Records[0], 8, wire.UnixNanosValue(origin-1))
	case 2:
		request.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(request.Header.ExportTimeUnixNanos+1_000_000))
	case 3:
		request.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(origin+1))
	case 4:
		request.Records[0] = recordWith(t, base.Records[0], 8, wire.UnixNanosValue(request.Header.ExportTimeUnixNanos+1_000_000))
	case 5:
		request.Header.ExportTimeUnixNanos = origin + uint64(math.MaxUint32)*nanosPerMS
		valid = true
	case 6:
		request.Header.ExportTimeUnixNanos = origin + (uint64(math.MaxUint32)+1)*nanosPerMS
		wantErr = wire.ErrInvalidHeader
	case 7:
		// Keep uptime representable while proving the maximum four-byte
		// export-seconds value and its subsecond remainder.
		request.Header.ExportTimeUnixNanos = uint64(math.MaxUint32)*nanosPerSec + 999*nanosPerMS
		request.Header.UptimeOriginUnixNanos = request.Header.ExportTimeUnixNanos - 1000*nanosPerMS
		request.Records[0] = recordWith(t, base.Records[0], 7, wire.UnixNanosValue(request.Header.UptimeOriginUnixNanos+nanosPerMS), 8, wire.UnixNanosValue(request.Header.UptimeOriginUnixNanos+2*nanosPerMS))
		valid = true
	case 8:
		request.Header.ExportTimeUnixNanos += 123 * nanosPerMS
		valid = true
	default:
		request.Header.UptimeOriginUnixNanos = origin - nanosPerMS
		valid = true
	}
	dst := bytes.Repeat([]byte{0x7e}, headerLength+recordLength)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("time case %d rejection = (%d,%v), want %v, mutated=%v", valueByte%10, n, err, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil || n != len(dst) {
		t.Fatalf("millisecond precision write = (%d,%v)", n, err)
	}
	assertV5FuzzPacket(t, dst, request)
	if valueByte%10 == 8 {
		if got := binary.BigEndian.Uint32(dst[12:16]); got != uint32(123*nanosPerMS) {
			t.Fatalf("unix nanoseconds = %d, want %d", got, 123*nanosPerMS)
		}
	}
}

func v5FuzzHeader(t *testing.T, valueByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := cloneRequest(base)
	valid := false
	wantErr := wire.ErrInvalidHeader
	switch valueByte % 8 {
	case 0:
		request.Header.SamplingMode = (valueByte / 8) % 4
		request.Header.SamplingInterval = uint16((valueByte/8)%16) * 1024
		valid = true
	case 1:
		request.Header.SamplingMode = 4
	case 2:
		request.Header.SamplingInterval = 16384
	case 3:
		request.Header.SourceID = 1
	case 4:
		request.Header.ObservationDomainID = 1
	case 5:
		request.Header.HasUptimeOrigin = false
	case 6:
		request.Header.Protocol = wire.ProtocolV9
		wantErr = wire.ErrInvalidShape
	default:
		request.Shape = wire.BuiltinV9().Shapes()[0]
		wantErr = wire.ErrInvalidShape
	}
	dst := bytes.Repeat([]byte{0x91}, headerLength+recordLength)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("header case %d rejection = (%d,%v), want %v, mutated=%v", valueByte%8, n, err, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil || n != len(dst) {
		t.Fatalf("sampling header write = (%d,%v)", n, err)
	}
	assertV5FuzzPacket(t, dst, request)
	wantSampling := uint16(request.Header.SamplingMode)<<14 | request.Header.SamplingInterval
	if got := binary.BigEndian.Uint16(dst[22:24]); got != wantSampling {
		t.Fatalf("sampling word = %d, want %d", got, wantSampling)
	}
}

func v5FuzzAddress(t *testing.T, valueByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := cloneRequest(base)
	wantErr := wire.ErrInvalidValue
	if valueByte&1 == 0 {
		request.Records[0] = recordWith(t, base.Records[0], 0, wire.StringValue("192.0.2.1"))
	} else {
		request.Records[0] = v5FuzzIPv6Record(t, base.Header)
		wantErr = wire.ErrInvalidFamily
	}
	dst := bytes.Repeat([]byte{0x4d}, headerLength+recordLength)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
		t.Fatalf("address case %d rejection = (%d,%v), want %v, mutated=%v", valueByte&1, n, err, wantErr, !bytes.Equal(dst, before))
	}
}

func v5FuzzIPv6Record(t *testing.T, header wire.HeaderMetadata) wire.WireRecord {
	t.Helper()
	address := wire.IPv6Value(netip.MustParseAddr("2001:db8::1"))
	values := make([]wire.Value, 20)
	values[0], values[1], values[2] = address, address, address
	for index := 3; index < len(values); index++ {
		values[index] = wire.UintValue(0)
	}
	values[7] = wire.UnixNanosValue(header.UptimeOriginUnixNanos + nanosPerMS)
	values[8] = wire.UnixNanosValue(header.UptimeOriginUnixNanos + 2*nanosPerMS)
	return mustWireRecord(t, wire.FamilyIPv6, values)
}

func v5FuzzCapacity(t *testing.T, capacityByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := cloneRequest(base)
	var capacity int
	var budget uint64
	valid := false
	wantErr := wire.ErrBounds
	switch capacityByte % 5 {
	case 0:
		capacity, budget, valid = 72, 72, true
	case 1:
		capacity, budget = 72, 71
	case 2:
		capacity, budget = 71, 0
		wantErr = wire.ErrShortBuffer
	case 3:
		capacity, budget = 72, 65536
	case 4:
		request.Records = append(request.Records, request.Records[0])
		request.Header.Count = 2
		capacity, budget = 120, 72
	}
	request.MaxDatagramBytes = budget
	dst := bytes.Repeat([]byte{0xb5}, capacity)
	before := append([]byte(nil), dst...)
	n, err := (Writer{}).Write(dst, request)
	if !valid {
		if n != 0 || err != wantErr || !bytes.Equal(dst, before) {
			t.Fatalf("capacity case %d rejection = (%d,%v), want %v, mutated=%v", capacityByte%5, n, err, wantErr, !bytes.Equal(dst, before))
		}
		return
	}
	if err != nil || n != capacity {
		t.Fatalf("exact capacity write = (%d,%v), want (%d,nil)", n, err, capacity)
	}
	assertV5FuzzPacket(t, dst[:n], request)
}

func v5FuzzStreamAtomic(t *testing.T, valueByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2, MaxDatagramBytes: 120}
	request.Header.Count = 0
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0x82}, 120)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	before := append([]byte(nil), dst...)
	bad := recordWith(t, base.Records[0], 17, wire.UintValue(33))
	if valueByte%4 == 1 {
		bad = recordWith(t, base.Records[0], 9, wire.UintValue(math.MaxUint16+1))
	}
	if valueByte%4 < 2 {
		if err := appender.Append(bad); err != wire.ErrInvalidValue || !bytes.Equal(dst, before) {
			t.Fatalf("rejected Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
		}
	} else {
		budget := uint64(119)
		destinationBytes := 120
		wantErr := wire.ErrBounds
		if valueByte%4 == 3 {
			budget = 0
			destinationBytes = 119
			wantErr = wire.ErrShortBuffer
		}
		appender.Reset()
		appender = NewDataPacket()
		lateRequest := request
		lateRequest.MaxDatagramBytes = budget
		lateDst := bytes.Repeat([]byte{0x9a}, destinationBytes)
		if err := appender.Begin(lateDst, lateRequest); err != nil {
			t.Fatalf("late capacity Begin: %v", err)
		}
		if err := appender.Append(base.Records[0]); err != nil {
			t.Fatalf("late capacity prefix Append: %v", err)
		}
		lateBefore := append([]byte(nil), lateDst...)
		if err := appender.Append(base.Records[0]); err != wantErr || !bytes.Equal(lateDst, lateBefore) {
			t.Fatalf("late capacity Append = %v, want %v, mutated=%v", err, wantErr, !bytes.Equal(lateDst, lateBefore))
		}
		lateRequest.Header.Count = 1
		if n, err := appender.Finish(); err != nil || n != 72 {
			t.Fatalf("late capacity Finish = (%d,%v)", n, err)
		}
		if !bytes.Equal(lateDst[72:], lateBefore[72:]) {
			t.Fatal("late capacity Finish changed bytes beyond accepted prefix")
		}
		assertV5FuzzPacket(t, lateDst[:72], wire.PacketRequest{Header: lateRequest.Header, Shape: lateRequest.Shape, Records: []wire.WireRecord{base.Records[0]}})
		return
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("suffix Append after rejection (%d): %v", valueByte, err)
	}
	n, err := appender.Finish()
	if err != nil || n != 120 {
		t.Fatalf("Finish after rejected append = (%d,%v)", n, err)
	}
	request.Header.Count = 2
	requestRecords := wire.PacketRequest{Header: request.Header, Shape: request.Shape, Records: []wire.WireRecord{base.Records[0], base.Records[0]}}
	assertV5FuzzPacket(t, dst[:n], requestRecords)

	// A rejected Begin must preserve the active packet and both caller buffers,
	// allowing the old packet to finish through its original state.
	active := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x93}, 120)
	activeRequest := request
	activeRequest.Header.Count = 0
	if err := active.Begin(oldDst, activeRequest); err != nil {
		t.Fatalf("active Begin: %v", err)
	}
	if err := active.Append(base.Records[0]); err != nil {
		t.Fatalf("active prefix Append: %v", err)
	}
	oldBefore := append([]byte(nil), oldDst...)
	candidate := bytes.Repeat([]byte{0xa4}, 120)
	candidateBefore := append([]byte(nil), candidate...)
	badBegin := activeRequest
	badBegin.MaxDatagramBytes = 23
	if err := active.Begin(candidate, badBegin); err != wire.ErrBounds || !bytes.Equal(oldDst, oldBefore) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("rejected Begin = %v, old-mutated=%v candidate-mutated=%v", err, !bytes.Equal(oldDst, oldBefore), !bytes.Equal(candidate, candidateBefore))
	}
	if err := active.Append(base.Records[0]); err != nil {
		t.Fatalf("old packet after rejected Begin: %v", err)
	}
	if n, err := active.Finish(); err != nil || n != 120 {
		t.Fatalf("old packet Finish after rejected Begin = (%d,%v)", n, err)
	}
	request.Header.Count = 2
	if !bytes.Equal(candidate, candidateBefore) {
		t.Fatal("recovery changed rejected Begin candidate")
	}
	assertV5FuzzPacket(t, oldDst, wire.PacketRequest{Header: request.Header, Shape: request.Shape, Records: []wire.WireRecord{base.Records[0], base.Records[0]}})
}

func v5FuzzStreamLifecycle(t *testing.T, valueByte uint8) {
	t.Helper()
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	appender := NewDataPacket()
	dst := bytes.Repeat([]byte{0xc6}, 72)
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	n, err := appender.Finish()
	if err != nil || n != 72 {
		t.Fatalf("Finish = (%d,%v)", n, err)
	}
	assertV5FuzzPacket(t, dst, base)
	afterFinish := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); err != wire.ErrPacketFinished || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("Append after Finish (%d) = %v, mutated=%v", valueByte, err, !bytes.Equal(dst, afterFinish))
	}
	if _, err := appender.Finish(); err != wire.ErrPacketFinished || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("second Finish = %v, mutated=%v", err, !bytes.Equal(dst, afterFinish))
	}
	appender.Reset()
	if err := appender.Append(base.Records[0]); err != wire.ErrPacketNotBegun {
		t.Fatalf("Append after Reset = %v", err)
	}
	if _, err := appender.Finish(); err != wire.ErrPacketNotBegun {
		t.Fatalf("Finish after Reset = %v", err)
	}

	if !bytes.Equal(dst, afterFinish) {
		t.Fatal("Reset or rejected operations changed finished packet")
	}

	// Exact and short streaming capacity are selected by the same bounded
	// scalar, and both rejected appends must retain an empty packet.
	capacity := uint64(72)
	if valueByte&1 != 0 {
		capacity = 71
	}
	capacityAppender := NewDataPacket()
	capacityRequest := request
	capacityRequest.MaxDatagramBytes = capacity
	capacityDst := bytes.Repeat([]byte{0xd7}, 72)
	if err := capacityAppender.Begin(capacityDst, capacityRequest); err != nil {
		t.Fatalf("capacity Begin: %v", err)
	}
	capacityBefore := append([]byte(nil), capacityDst...)
	err = capacityAppender.Append(base.Records[0])
	if capacity == 72 {
		if err != nil {
			t.Fatalf("exact capacity Append: %v", err)
		}
		if n, err := capacityAppender.Finish(); err != nil || n != 72 {
			t.Fatalf("exact capacity Finish: %v", err)
		}
		assertV5FuzzPacket(t, capacityDst, base)
	} else {
		if err != wire.ErrBounds || !bytes.Equal(capacityDst, capacityBefore) {
			t.Fatalf("short budget Append = %v, mutated=%v", err, !bytes.Equal(capacityDst, capacityBefore))
		}
		if _, err := capacityAppender.Finish(); err != wire.ErrPacketEmpty || !bytes.Equal(capacityDst, capacityBefore) {
			t.Fatalf("short budget Finish = %v, mutated=%v", err, !bytes.Equal(capacityDst, capacityBefore))
		}
	}
}

// assertV5FuzzPacket is deliberately independent of netflow5.writeHeader and
// writeRecord. It checks protocol offsets, widths, values, identities, time
// conversion, and reserved bytes for every record in a successful packet.
func assertV5FuzzPacket(t *testing.T, packet []byte, request wire.PacketRequest) {
	t.Helper()
	wantLength := headerLength + recordLength*len(request.Records)
	if len(packet) != wantLength {
		t.Fatalf("packet length = %d, want %d", len(packet), wantLength)
	}
	h := request.Header
	if got := binary.BigEndian.Uint16(packet[0:2]); got != 5 {
		t.Fatalf("version = %d, want 5", got)
	}
	if got := binary.BigEndian.Uint16(packet[2:4]); got != uint16(len(request.Records)) {
		t.Fatalf("count = %d, want %d", got, len(request.Records))
	}
	wantUptime := uint32((h.ExportTimeUnixNanos - h.UptimeOriginUnixNanos) / nanosPerMS)
	if got := binary.BigEndian.Uint32(packet[4:8]); got != wantUptime {
		t.Fatalf("sysUptime = %d, want %d", got, wantUptime)
	}
	if got := binary.BigEndian.Uint32(packet[8:12]); got != uint32(h.ExportTimeUnixNanos/nanosPerSec) {
		t.Fatalf("unix seconds = %d, want %d", got, h.ExportTimeUnixNanos/nanosPerSec)
	}
	if got := binary.BigEndian.Uint32(packet[12:16]); got != uint32(h.ExportTimeUnixNanos%nanosPerSec) {
		t.Fatalf("unix nanoseconds = %d, want %d", got, h.ExportTimeUnixNanos%nanosPerSec)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != h.Sequence {
		t.Fatalf("sequence = %d, want %d", got, h.Sequence)
	}
	if packet[20] != h.EngineType || packet[21] != h.EngineID {
		t.Fatalf("engine identity = %02x%02x, want %02x%02x", packet[20], packet[21], h.EngineType, h.EngineID)
	}
	wantSampling := uint16(h.SamplingMode)<<14 | h.SamplingInterval
	if got := binary.BigEndian.Uint16(packet[22:24]); got != wantSampling {
		t.Fatalf("sampling = %d, want %d", got, wantSampling)
	}
	for recordIndex, record := range request.Records {
		offset := headerLength + recordIndex*recordLength
		values := record.Values()
		if len(values) != 20 {
			t.Fatalf("record %d values = %d, want 20", recordIndex, len(values))
		}
		for index := 0; index < 3; index++ {
			want := values[index].IP().As4()
			if !bytes.Equal(packet[offset+index*4:offset+(index+1)*4], want[:]) {
				t.Fatalf("record %d address %d differs", recordIndex, index)
			}
		}
		if got := binary.BigEndian.Uint16(packet[offset+12 : offset+14]); got != uint16(v5FuzzUint(values[3])) {
			t.Fatalf("record %d input = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint16(packet[offset+14 : offset+16]); got != uint16(v5FuzzUint(values[4])) {
			t.Fatalf("record %d output = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint32(packet[offset+16 : offset+20]); got != uint32(v5FuzzUint(values[5])) {
			t.Fatalf("record %d packets = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint32(packet[offset+20 : offset+24]); got != uint32(v5FuzzUint(values[6])) {
			t.Fatalf("record %d octets = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint32(packet[offset+24 : offset+28]); got != uint32((values[7].UnixNanos()-h.UptimeOriginUnixNanos)/nanosPerMS) {
			t.Fatalf("record %d first = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint32(packet[offset+28 : offset+32]); got != uint32((values[8].UnixNanos()-h.UptimeOriginUnixNanos)/nanosPerMS) {
			t.Fatalf("record %d last = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint16(packet[offset+32 : offset+34]); got != uint16(v5FuzzUint(values[9])) {
			t.Fatalf("record %d source port = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint16(packet[offset+34 : offset+36]); got != uint16(v5FuzzUint(values[10])) {
			t.Fatalf("record %d destination port = %d", recordIndex, got)
		}
		if packet[offset+36] != 0 {
			t.Fatalf("record %d pad1 = %d, want zero", recordIndex, packet[offset+36])
		}
		if packet[offset+37] != byte(v5FuzzUint(values[12])) || packet[offset+38] != byte(v5FuzzUint(values[13])) || packet[offset+39] != byte(v5FuzzUint(values[14])) {
			t.Fatalf("record %d trailing byte fields differ", recordIndex)
		}
		if got := binary.BigEndian.Uint16(packet[offset+40 : offset+42]); got != uint16(v5FuzzUint(values[15])) {
			t.Fatalf("record %d source AS = %d", recordIndex, got)
		}
		if got := binary.BigEndian.Uint16(packet[offset+42 : offset+44]); got != uint16(v5FuzzUint(values[16])) {
			t.Fatalf("record %d destination AS = %d", recordIndex, got)
		}
		if packet[offset+44] != byte(v5FuzzUint(values[17])) || packet[offset+45] != byte(v5FuzzUint(values[18])) {
			t.Fatalf("record %d mask fields differ", recordIndex)
		}
		if packet[offset+46] != 0 || packet[offset+47] != 0 {
			t.Fatalf("record %d pad2 = %x, want zero", recordIndex, packet[offset+46:offset+48])
		}
	}
}

func v5FuzzUint(value wire.Value) uint64 {
	if value.Kind() == wire.ValueInt {
		return uint64(value.Int())
	}
	return value.Uint()
}
