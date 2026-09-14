package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

const (
	canonicalIPv4FixtureID = "canonical-ipv4-v1"
	canonicalIPv6FixtureID = "canonical-ipv6-v1"
)

func assertPreflightReject(t *testing.T, req PacketRequest, capacity int, want error) {
	t.Helper()
	if capacity < 0 {
		t.Fatalf("negative caller capacity %d", capacity)
	}
	buf := bytes.Repeat([]byte{0xd7}, capacity)
	before := append([]byte(nil), buf...)
	n, err := Preflight(buf, req)
	if n != 0 || err == nil {
		t.Fatalf("preflight rejection = (%d,%v), want (0,error)", n, err)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("preflight error = %v, want classification %v", err, want)
	}
	if !bytes.Equal(buf, before) {
		t.Fatal("preflight rejection mutated caller buffer")
	}
}

func TestContract(t *testing.T) {
	catalog := BuiltinV9()
	shape, ok := catalog.ShapeAt(0)
	if !ok {
		t.Fatal("missing built-in v9 IPv4 shape")
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("built-in catalog validation: %v", err)
	}
	// Structural input only; this is not a reproduction of canonical fixture values.
	address, err := ParseIPv4Value("192.0.2.1")
	if err != nil {
		t.Fatalf("structural address: %v", err)
	}
	record, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldSourceAddress, Value: address}})
	if err != nil {
		t.Fatalf("record construction: %v", err)
	}
	if _, ok := record.Lookup(FieldSourceAddress); !ok {
		t.Fatal("record lookup lost source address")
	}
	header := HeaderMetadata{
		Protocol:              ProtocolV9,
		ObservationDomainID:   42,
		SourceID:              42,
		ExportTimeUnixNanos:   1_788_220_803_000_000_000,
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: 1_788_220_800_000_000_000,
	}
	wireRecord := mustWireRecord(t, shape)
	header.Count = 2 // one template record plus one data record
	req := PacketRequest{Header: header, Shape: shape, Records: []WireRecord{wireRecord}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
	dataSet, err := shape.DataSetSize(req.Records)
	if err != nil {
		t.Fatalf("data set sizing: %v", err)
	}
	wantLen := int(20 + shape.TemplateBytes() + dataSet.Length())
	buf := bytes.Repeat([]byte{0xa5}, wantLen)
	n, err := Preflight(buf, req)
	if err != nil || n != wantLen {
		t.Fatalf("preflight = (%d, %v), want (%d, nil)", n, err, wantLen)
	}

	// Contract errors happen before a writer gets access to the buffer.
	assertPreflightReject(t, req, wantLen-1, ErrShortBuffer)
	bad := req
	bad.Header.Protocol = ProtocolIPFIX
	assertPreflightReject(t, bad, wantLen, ErrInvalidShape)

	if n, err := Preflight(buf, req); err != nil || n != wantLen {
		t.Fatalf("repeat preflight = (%d, %v), want (%d, nil)", n, err, wantLen)
	}
	testContractTimeAdmission(t)
	testContractTypedValues(t)
	testContractSamplingAndCounts(t)
	testContractRecordCountBoundary(t)
	testContractZeroAlloc(t)
}

func mustWireRecord(t *testing.T, shape Shape) WireRecord {
	t.Helper()
	// Structural values intentionally stand in for fixture payloads.
	values := make([]Value, len(shape.fields))
	for i, field := range shape.fields {
		if field.Constant {
			values[i] = UintValue(0)
			continue
		}
		switch field.Encoding {
		case EncodingIPv4Address:
			address, err := ParseIPv4Value("192.0.2.1")
			if err != nil {
				t.Fatalf("structural IPv4 value: %v", err)
			}
			values[i] = address
		case EncodingIPv6Address:
			address, err := ParseIPv6Value("2001:db8::1")
			if err != nil {
				t.Fatalf("structural IPv6 value: %v", err)
			}
			values[i] = address
		case EncodingMACAddress:
			mac, err := ParseMACValue("00:11:22:33:44:55")
			if err != nil {
				t.Fatalf("structural MAC value: %v", err)
			}
			values[i] = mac
		case EncodingString:
			values[i] = StringValue("x")
		case EncodingOctetArray:
			values[i] = BytesValue(make([]byte, field.Length))
		case EncodingDateTimeNanoseconds:
			values[i] = UnixNanosValue(1)
		case EncodingSigned8, EncodingSigned16, EncodingSigned32, EncodingSigned64:
			values[i] = IntValue(1)
		default:
			if isAbsoluteTimeField(field.Field) {
				values[i] = UnixNanosValue(1)
			} else {
				values[i] = UintValue(1)
			}
		}
	}
	record, err := NewWireRecord(shape.family, values)
	if err != nil {
		t.Fatalf("wire record construction: %v", err)
	}
	return record
}

func testContractTimeAdmission(t *testing.T) {
	if err := (NormalizedRecord{}).Validate(); err == nil {
		t.Fatal("zero normalized record validated")
	}
	overLimit := bytes.Repeat([]byte{0x01}, MaxNormalizedValueBytes+1)
	if _, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldFlowSrcMAC, Value: BytesValue(overLimit)}}); !errors.Is(err, ErrRecordValueLimit) {
		t.Fatalf("oversized normalized bytes = %v, want %v", err, ErrRecordValueLimit)
	}
	for _, tc := range []struct {
		name string
		h    HeaderMetadata
	}{
		{name: "negative represented as uint overflow", h: HeaderMetadata{Protocol: ProtocolV9, ExportTimeUnixNanos: ^uint64(0)}},
		{name: "origin after export", h: HeaderMetadata{Protocol: ProtocolV9, ExportTimeUnixNanos: 10, HasUptimeOrigin: true, UptimeOriginUnixNanos: 11}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.h.Validate(); err == nil {
				t.Fatal("header unexpectedly accepted")
			}
		})
	}
	maxInt64 := uint64(1<<63 - 1)
	if err := ValidateUnixNanos(maxInt64); err != nil {
		t.Fatalf("MaxInt64 timestamp rejected: %v", err)
	}
	if err := ValidateUnixNanos(maxInt64 + 1); err == nil {
		t.Fatal("MaxInt64+1 timestamp accepted")
	}
	if _, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldFlowStart, Value: IntValue(-1)}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ordinary negative timestamp kind = %v, want %v", err, ErrInvalidValue)
	}
	if _, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldFlowStart, Value: UnixNanosValue(maxInt64 + 1)}}); !errors.Is(err, ErrTimeOutOfRange) {
		t.Fatalf("absolute timestamp over MaxInt64 = %v, want %v", err, ErrTimeOutOfRange)
	}
	bytesIn := []byte{1, 2, 3}
	record, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldFlowSrcMAC, Value: BytesValue(bytesIn)}})
	if err != nil {
		t.Fatalf("bytes record construction: %v", err)
	}
	bytesIn[0] = 9
	value, ok := record.Lookup(FieldFlowSrcMAC)
	if !ok || value.Octets() != string([]byte{1, 2, 3}) {
		t.Fatalf("record retained mutable byte input: %+v", value)
	}
	copyOfBytes := value.BytesCopy()
	copyOfBytes[1] = 8
	valueAgain, _ := record.Lookup(FieldFlowSrcMAC)
	if valueAgain.Octets() != string([]byte{1, 2, 3}) {
		t.Fatal("record lookup exposed mutable byte storage")
	}
}

func testContractTypedValues(t *testing.T) {
	ipv4, err := ParseIPv4Value("192.0.2.1")
	if err != nil || ipv4.Kind() != ValueIP || !ipv4.IP().Is4() {
		t.Fatalf("parsed IPv4 value = (%v,%v)", ipv4, err)
	}
	ipv6, err := ParseIPv6Value("2001:db8::1")
	if err != nil || ipv6.Kind() != ValueIP || !ipv6.IP().Is6() || ipv6.IP().Is4() {
		t.Fatalf("parsed IPv6 value = (%v,%v)", ipv6, err)
	}
	if _, err := ParseIPv4Value("2001:db8::1"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("IPv6 accepted as IPv4: %v", err)
	}
	if _, err := ParseIPv4Value("192.0.2.01"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("noncanonical IPv4 accepted: %v", err)
	}
	if _, err := ParseIPv6Value("2001:DB8::1"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("noncanonical IPv6 accepted: %v", err)
	}
	mac, err := ParseMACValue("00:11:22:33:44:55")
	if err != nil || mac.Kind() != ValueMAC || mac.MAC() != [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("parsed MAC value = (%v,%v)", mac, err)
	}
	if _, err := ParseMACValue("00:11:22:33:44:55:66"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("eight-byte MAC accepted: %v", err)
	}
	if _, err := NewIPValue(netip.Addr{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid parsed IP accepted: %v", err)
	}
	if _, err := NewMACValue([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("short MAC accepted: %v", err)
	}
	macDescriptor := FieldDescriptor{Protocol: ProtocolV9, Field: FieldFlowSrcMAC, ID: 80, Length: 6, Encoding: EncodingMACAddress}
	if got, err := macDescriptor.ValueLength(mac); err != nil || got != 6 {
		t.Fatalf("typed MAC descriptor result = (%d,%v)", got, err)
	}
	if _, err := macDescriptor.ValueLength(StringValue("00:11:22:33:44:55")); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("string masqueraded as typed MAC: %v", err)
	}
	if _, err := NewWireRecord(FamilyIPv4, []Value{ipv6}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("IPv6 value accepted in IPv4 record: %v", err)
	}
	normalized, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldSourceAddress, Value: ipv4}})
	if err != nil {
		t.Fatalf("typed normalized record: %v", err)
	}
	if got, ok := normalized.FieldAt(0); !ok || got.Value.Kind() != ValueIP || got.Value.IP() != ipv4.IP() {
		t.Fatalf("indexed normalized value = (%+v,%v)", got, ok)
	}
	if _, ok := normalized.FieldAt(-1); ok {
		t.Fatal("negative normalized-field index accepted")
	}
	nanos := UnixNanosValue(123)
	if nanos.Kind() != ValueUnixNanos || nanos.UnixNanos() != 123 {
		t.Fatalf("Unix-nanosecond value = %+v", nanos)
	}
	v5Shape, _ := BuiltinV5().ShapeAt(0)
	v5Start, _ := v5Shape.DescriptorAt(7)
	if _, err := v5Start.ValueLength(nanos); err != nil {
		t.Fatalf("v5 semantic time rejected: %v", err)
	}
	if _, err := v5Start.ValueLength(UintValue(123)); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ordinary uint masqueraded as v5 timestamp: %v", err)
	}
	ipfixShape, _ := BuiltinIPFIX().ShapeAt(0)
	ipfixStart, _ := ipfixShape.DescriptorAt(18)
	if _, err := ipfixStart.ValueLength(nanos); err != nil {
		t.Fatalf("IPFIX semantic time rejected: %v", err)
	}
	v9Shape, ok := BuiltinV9().ShapeAt(0)
	if !ok {
		t.Fatal("missing v9 shape for indexed value test")
	}
	wire := mustWireRecord(t, v9Shape)
	if got, ok := wire.ValueAt(0); !ok || got.Kind() != ValueUint || got.Uint() != 1 {
		t.Fatalf("indexed wire value = (%+v,%v)", got, ok)
	}
	if _, ok := wire.ValueAt(-1); ok {
		t.Fatal("negative wire-value index accepted")
	}
	accessAllocs := testing.AllocsPerRun(1000, func() {
		_, _ = v9Shape.DescriptorAt(0)
		_, _ = wire.ValueAt(0)
	})
	if accessAllocs != 0 {
		t.Fatalf("indexed accessor allocations per run = %v, want 0", accessAllocs)
	}
}

func testContractSamplingAndCounts(t *testing.T) {
	v5 := BuiltinV5()
	shape, _ := v5.ShapeAt(0)
	record := mustWireRecord(t, shape)
	for _, tc := range []struct {
		name  string
		count uint16
		mode  uint8
		intv  uint16
		ok    bool
		want  error
	}{
		{"one", 1, 2, 16383, true, nil},
		{"zero", 0, 0, 0, false, ErrBounds},
		{"thirty", 30, 3, 1, true, nil},
		{"thirty-one", 31, 0, 1, false, ErrBounds},
		{"mode-overflow", 1, 4, 1, false, ErrInvalidHeader},
		{"interval-overflow", 1, 0, 16384, false, ErrInvalidHeader},
	} {
		t.Run(canonicalIPv4FixtureID+"/v5/"+tc.name, func(t *testing.T) {
			records := make([]WireRecord, int(tc.count))
			for i := range records {
				records[i] = record
			}
			req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV5, Count: tc.count, SamplingMode: tc.mode, SamplingInterval: tc.intv}, Shape: shape, Records: records}
			if !tc.ok {
				assertPreflightReject(t, req, DefaultMaxMessageBytes, tc.want)
				return
			}
			n, err := Preflight(make([]byte, 65535), req)
			if tc.ok && (err != nil || n == 0) {
				t.Fatalf("accepted case = (%d,%v)", n, err)
			}
		})
	}
	v9, _ := BuiltinV9().ShapeAt(0)
	v9record := mustWireRecord(t, v9)
	valid := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: 2}, Shape: v9, Records: []WireRecord{v9record}, TemplateRecords: 1, TemplateBytes: v9.TemplateBytes()}
	if n, err := Preflight(make([]byte, 65535), valid); err != nil || n == 0 {
		t.Fatalf("v9 template+data count rejected: (%d,%v)", n, err)
	}
	valid.Header.Count = 1
	assertPreflightReject(t, valid, DefaultMaxMessageBytes, ErrInvalidHeader)
	for _, protocol := range []Protocol{ProtocolV9, ProtocolIPFIX} {
		catalog := BuiltinV9()
		if protocol == ProtocolIPFIX {
			catalog = BuiltinIPFIX()
		}
		shape, _ := catalog.ShapeAt(0)
		req := PacketRequest{Header: HeaderMetadata{Protocol: protocol}, Shape: shape}
		want := int(protocolHeaderLength(protocol))
		if n, err := Preflight(make([]byte, want), req); err != nil || n != want {
			t.Fatalf("%s header-only preflight = (%d,%v), want (%d,nil)", protocol, n, err, want)
		}
	}
}

func testContractRecordCountBoundary(t *testing.T) {
	shape, ok := BuiltinV9().ShapeAt(0)
	if !ok {
		t.Fatal("missing v9 shape for record-count boundary")
	}
	record := mustWireRecord(t, shape)
	for _, count := range []int{1024, 1025} {
		name := canonicalIPv4FixtureID + "/v9-records-1024"
		if count == 1025 {
			name = canonicalIPv4FixtureID + "/v9-records-1025"
		}
		t.Run(name, func(t *testing.T) {
			records := make([]WireRecord, count)
			for i := range records {
				records[i] = record
			}
			req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: uint16(count)}, Shape: shape, Records: records}
			dataSet, err := shape.DataSetSize(records)
			if err != nil {
				t.Fatalf("data set sizing: %v", err)
			}
			want := int(protocolV9HeaderBytes + dataSet.Length())
			if n, err := Preflight(make([]byte, want), req); err != nil || n != want {
				t.Fatalf("%d-record preflight = (%d,%v), want (%d,nil)", count, n, err, want)
			}
		})
	}
	// The pure wire contract admits both counts when the 16-bit message fits;
	// destination packetization owns the record-boundary policy.
}

func TestDataSetSizeForEncodedBoundaries(t *testing.T) {
	shape, ok := BuiltinV9().ShapeAt(0)
	if !ok {
		t.Fatal("missing v9 shape")
	}
	for _, tc := range []struct {
		name  string
		bytes uint64
		count uint64
		want  error
	}{
		{name: "positive-bytes-zero-count", bytes: 1, count: 0, want: ErrBounds},
		{name: "zero-bytes-positive-count", bytes: 0, count: 1, want: ErrBounds},
		{name: "below-cumulative-minimum", bytes: 42, count: 1, want: ErrBounds},
		{name: "fixed-width-extra-bytes", bytes: 44, count: 1, want: ErrBounds},
		{name: "one-record", bytes: 43, count: 1},
		{name: "two-records", bytes: 86, count: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := shape.DataSetSizeForEncoded(tc.bytes, tc.count)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || got.Length() != 0 {
					t.Fatalf("size = (%d,%v), want (%v)", got.Length(), err, tc.want)
				}
				return
			}
			if err != nil || got.Length() == 0 {
				t.Fatalf("size = (%d,%v), want success", got.Length(), err)
			}
		})
	}
	v5, ok := BuiltinV5().ShapeAt(0)
	if !ok {
		t.Fatal("missing v5 shape")
	}
	if _, err := v5.DataSetSizeForEncoded(v5.RecordLength()+1, 1); !errors.Is(err, ErrBounds) {
		t.Fatalf("v5 fixed-width extra bytes = %v, want %v", err, ErrBounds)
	}
}

func testContractZeroAlloc(t *testing.T) {
	shape, ok := BuiltinV9().ShapeAt(0)
	if !ok {
		t.Fatal("missing v9 shape for allocation test")
	}
	record := mustWireRecord(t, shape)
	req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: 1}, Shape: shape, Records: []WireRecord{record}}
	dataSet, err := shape.DataSetSize(req.Records)
	if err != nil {
		t.Fatalf("data set sizing: %v", err)
	}
	want := int(protocolV9HeaderBytes + dataSet.Length())
	dst := make([]byte, want)
	allocs := testing.AllocsPerRun(1000, func() {
		n, err := Preflight(dst, req)
		if err != nil || n != want {
			panic("preflight allocation fixture rejected")
		}
	})
	if allocs != 0 {
		t.Fatalf("Preflight allocations per run = %v, want 0", allocs)
	}
	v5Shape, ok := BuiltinV5().ShapeAt(0)
	if !ok {
		t.Fatal("missing v5 shape for allocation test")
	}
	v5Record := mustWireRecord(t, v5Shape)
	v5Req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV5, Count: 1}, Shape: v5Shape, Records: []WireRecord{v5Record}}
	v5Want := int(protocolV5HeaderBytes + v5Shape.RecordLength())
	v5Dst := make([]byte, v5Want)
	v5Allocs := testing.AllocsPerRun(1000, func() {
		n, err := Preflight(v5Dst, v5Req)
		if err != nil || n != v5Want {
			panic("v5 preflight allocation fixture rejected")
		}
	})
	if v5Allocs != 0 {
		t.Fatalf("v5 Preflight allocations per run = %v, want 0", v5Allocs)
	}
}
