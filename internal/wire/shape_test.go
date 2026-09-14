package wire

import "testing"

func TestShape(t *testing.T) {
	t.Run("v5-fixed", func(t *testing.T) {
		shape, ok := BuiltinV5().ShapeAt(0)
		if !ok {
			t.Fatal("missing v5 shape")
		}
		if shape.Protocol() != ProtocolV5 || shape.Family() != FamilyIPv4 || shape.FieldCount() != 20 || shape.RecordLength() != 48 || shape.TemplateBytes() != 0 {
			t.Fatalf("v5 shape = protocol %v family %v fields %d record %d template %d", shape.Protocol(), shape.Family(), shape.FieldCount(), shape.RecordLength(), shape.TemplateBytes())
		}
		fields := shape.Fields()
		want := []struct {
			field      CanonicalField
			id         uint16
			len        uint16
			enc        DescriptorEncoding
			constField bool
		}{
			{FieldSourceAddress, 1, 4, EncodingIPv4Address, false}, {FieldDestinationAddress, 2, 4, EncodingIPv4Address, false}, {FieldFlowNextHop, 3, 4, EncodingIPv4Address, false},
			{FieldFlowInIf, 4, 2, EncodingUnsigned16, false}, {FieldFlowOutIf, 5, 2, EncodingUnsigned16, false}, {FieldFlowIOPackets, 6, 4, EncodingUnsigned32, false}, {FieldFlowIOBytes, 7, 4, EncodingUnsigned32, false},
			{FieldFlowStart, 8, 4, EncodingUnsigned32, false}, {FieldFlowEnd, 9, 4, EncodingUnsigned32, false}, {FieldSourcePort, 10, 2, EncodingUnsigned16, false}, {FieldDestinationPort, 11, 2, EncodingUnsigned16, false},
			{FieldInvalid, 12, 1, EncodingUnsigned8, true}, {FieldFlowTCPFlags, 13, 1, EncodingUnsigned8, false}, {FieldNetworkTransport, 14, 1, EncodingUnsigned8, false}, {FieldFlowIPTOS, 15, 1, EncodingUnsigned8, false},
			{FieldFlowSrcAS, 16, 2, EncodingUnsigned16, false}, {FieldFlowDstAS, 17, 2, EncodingUnsigned16, false}, {FieldFlowSrcNet, 18, 1, EncodingUnsigned8, false}, {FieldFlowDstNet, 19, 1, EncodingUnsigned8, false}, {FieldInvalid, 20, 2, EncodingUnsigned16, true},
		}
		assertShapeFields(t, fields, want)
	})

	t.Run(canonicalIPv4FixtureID+"/v9-family-shapes", func(t *testing.T) {
		catalog := BuiltinV9()
		if catalog.ShapeCount() != 2 {
			t.Fatalf("v9 shape count = %d, want 2", catalog.ShapeCount())
		}
		v4, _ := catalog.ShapeAt(0)
		v6, _ := catalog.ShapeAt(1)
		if v4.ID() != 256 || v6.ID() != 257 || v4.FieldCount() != 18 || v6.FieldCount() != 18 || v4.RecordLength() != 43 || v6.RecordLength() != 67 {
			t.Fatalf("v9 shapes have IDs/count/lengths %d/%d %d/%d %d/%d", v4.ID(), v6.ID(), v4.FieldCount(), v6.FieldCount(), v4.RecordLength(), v6.RecordLength())
		}
		for _, shape := range []Shape{v4, v6} {
			for _, field := range shape.Fields() {
				if field.Enterprise || field.Variable || field.PEN != 0 {
					t.Fatalf("v9 core field unexpectedly enterprise/variable: %+v", field)
				}
			}
		}
		assertV9Fields(t, v4, false)
		assertV9Fields(t, v6, true)
		if got := v4.Fields()[15].ID; got != 34 {
			t.Fatalf("v9 sampling field ID = %d, want ordinary type 34", got)
		}
		if got := v6.Fields()[6].Length; got != 16 {
			t.Fatalf("v9 IPv6 source address width = %d, want 16", got)
		}
	})

	t.Run(canonicalIPv6FixtureID+"/ipfix-family-shapes", func(t *testing.T) {
		catalog := BuiltinIPFIX()
		v4, _ := catalog.ShapeAt(0)
		v6, _ := catalog.ShapeAt(1)
		if catalog.ShapeCount() != 2 || v4.ID() != 256 || v6.ID() != 257 || v4.FieldCount() != 20 || v6.FieldCount() != 20 || v4.RecordLength() != 72 || v6.RecordLength() != 96 {
			t.Fatalf("ipfix shapes have count/IDs/fields/lengths: %d %d/%d %d/%d %d/%d", catalog.ShapeCount(), v4.ID(), v6.ID(), v4.FieldCount(), v6.FieldCount(), v4.RecordLength(), v6.RecordLength())
		}
		for _, shape := range []Shape{v4, v6} {
			fields := shape.Fields()
			if fields[15].ID != 34 || fields[15].Length != 4 || fields[15].Variable || fields[15].Enterprise {
				t.Fatalf("IPFIX ordinary IE 34 is not a fixed four-byte field: %+v", fields[15])
			}
			if fields[18].ID != 156 || fields[19].ID != 157 {
				t.Fatalf("IPFIX timestamps are not final fields: %+v %+v", fields[18], fields[19])
			}
		}
		assertIPFIXFields(t, v4, false)
		assertIPFIXFields(t, v6, true)
		if got := v6.Fields()[6].Length; got != 16 {
			t.Fatalf("IPFIX IPv6 source address width = %d, want 16", got)
		}
	})
	t.Run("ipfix-general-family-shapes", func(t *testing.T) {
		catalog := BuiltinIPFIXGeneral()
		if catalog.ShapeCount() != 2 {
			t.Fatalf("general shape count=%d", catalog.ShapeCount())
		}
		for index, shape := range catalog.Shapes() {
			wantLength := uint64(72)
			if index == 1 {
				wantLength = 96
			}
			if shape.ID() != uint16(256+index) || shape.FieldCount() != 20 || shape.RecordLength() != wantLength || shape.TemplateBytes() != 88 {
				t.Fatalf("general shape %d = id=%d fields=%d record=%d template=%d", index, shape.ID(), shape.FieldCount(), shape.RecordLength(), shape.TemplateBytes())
			}
			fields := shape.Fields()
			if fields[18].ID != 152 || fields[18].Length != 8 || fields[18].Encoding != EncodingDateTimeMilliseconds || fields[19].ID != 153 || fields[19].Length != 8 || fields[19].Encoding != EncodingDateTimeMilliseconds {
				t.Fatalf("general time descriptors=%+v/%+v", fields[18], fields[19])
			}
		}
	})
	testShapeImmutability(t)
	testDescriptorForms(t)
	testShapeFamilyAndIdentityRejections(t)
	testTemplateIDBoundaries(t)
}

func assertShapeFields(t *testing.T, got []FieldDescriptor, want []struct {
	field      CanonicalField
	id         uint16
	len        uint16
	enc        DescriptorEncoding
	constField bool
}) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("field count = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		actual := got[i]
		if actual.Field != expected.field || actual.ID != expected.id || actual.Length != expected.len || actual.Encoding != expected.enc || actual.Constant != expected.constField {
			t.Fatalf("field %d = field %v id %d len %d enc %v const %v, want field %v id %d len %d enc %v const %v", i, actual.Field, actual.ID, actual.Length, actual.Encoding, actual.Constant, expected.field, expected.id, expected.len, expected.enc, expected.constField)
		}
	}
}

func assertV9Fields(t *testing.T, shape Shape, ipv6 bool) {
	t.Helper()
	sourceID, sourceMask, destID, destMask, width := uint16(8), uint16(9), uint16(12), uint16(13), uint16(4)
	if ipv6 {
		sourceID, sourceMask, destID, destMask, width = 27, 29, 28, 30, 16
	}
	want := []struct {
		field   CanonicalField
		id, len uint16
		enc     DescriptorEncoding
	}{
		{FieldFlowIOBytes, 1, 4, EncodingUnsigned32}, {FieldFlowIOPackets, 2, 4, EncodingUnsigned32}, {FieldNetworkTransport, 4, 1, EncodingUnsigned8}, {FieldFlowIPTOS, 5, 1, EncodingUnsigned8},
		{FieldFlowTCPFlags, 6, 1, EncodingUnsigned8}, {FieldSourcePort, 7, 2, EncodingUnsigned16}, {FieldSourceAddress, sourceID, width, mapAddressEncoding(shape.family)}, {FieldFlowSrcNet, sourceMask, 1, EncodingUnsigned8},
		{FieldFlowInIf, 10, 2, EncodingUnsigned16}, {FieldDestinationPort, 11, 2, EncodingUnsigned16}, {FieldDestinationAddress, destID, width, mapAddressEncoding(shape.family)}, {FieldFlowDstNet, destMask, 1, EncodingUnsigned8},
		{FieldFlowOutIf, 14, 2, EncodingUnsigned16}, {FieldFlowSrcAS, 16, 4, EncodingUnsigned32}, {FieldFlowDstAS, 17, 4, EncodingUnsigned32}, {FieldFlowSamplingRate, 34, 4, EncodingUnsigned32}, {FieldFlowIPTTL, 52, 1, EncodingUnsigned8}, {FieldNetworkType, 60, 1, EncodingUnsigned8},
	}
	got := shape.Fields()
	if len(got) != len(want) {
		t.Fatalf("v9 field count = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].Field != expected.field || got[i].ID != expected.id || got[i].Length != expected.len || got[i].Encoding != expected.enc {
			t.Fatalf("v9 field %d mismatch: %+v want %+v", i, got[i], expected)
		}
	}
}

func assertIPFIXFields(t *testing.T, shape Shape, ipv6 bool) {
	t.Helper()
	sourceID, sourceMask, destID, destMask, width, addressEncoding := uint16(8), uint16(9), uint16(12), uint16(13), uint16(4), EncodingIPv4Address
	if ipv6 {
		sourceID, sourceMask, destID, destMask, width, addressEncoding = 27, 29, 28, 30, 16, EncodingIPv6Address
	}
	want := []struct {
		field   CanonicalField
		id, len uint16
		enc     DescriptorEncoding
	}{
		{FieldFlowIOBytes, 1, 8, EncodingUnsigned64}, {FieldFlowIOPackets, 2, 8, EncodingUnsigned64}, {FieldNetworkTransport, 4, 1, EncodingUnsigned8}, {FieldFlowIPTOS, 5, 1, EncodingUnsigned8}, {FieldFlowTCPFlags, 6, 2, EncodingUnsigned16}, {FieldSourcePort, 7, 2, EncodingUnsigned16},
		{FieldSourceAddress, sourceID, width, addressEncoding}, {FieldFlowSrcNet, sourceMask, 1, EncodingUnsigned8}, {FieldFlowInIf, 10, 4, EncodingUnsigned32}, {FieldDestinationPort, 11, 2, EncodingUnsigned16}, {FieldDestinationAddress, destID, width, addressEncoding}, {FieldFlowDstNet, destMask, 1, EncodingUnsigned8},
		{FieldFlowOutIf, 14, 4, EncodingUnsigned32}, {FieldFlowSrcAS, 16, 4, EncodingUnsigned32}, {FieldFlowDstAS, 17, 4, EncodingUnsigned32}, {FieldFlowSamplingRate, 34, 4, EncodingUnsigned32}, {FieldFlowIPTTL, 52, 1, EncodingUnsigned8}, {FieldNetworkType, 60, 1, EncodingUnsigned8}, {FieldFlowStart, 156, 8, EncodingDateTimeNanoseconds}, {FieldFlowEnd, 157, 8, EncodingDateTimeNanoseconds},
	}
	got := shape.Fields()
	if len(got) != len(want) {
		t.Fatalf("ipfix field count = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].Field != expected.field || got[i].ID != expected.id || got[i].Length != expected.len || got[i].Encoding != expected.enc {
			t.Fatalf("ipfix field %d mismatch: %+v want %+v", i, got[i], expected)
		}
	}
}

func testShapeImmutability(t *testing.T) {
	catalog := BuiltinV9()
	shape, _ := catalog.ShapeAt(0)
	fields := shape.Fields()
	fields[0].ID = 99
	fields[0].Length = 1
	if got := shape.Fields()[0].ID; got != 1 {
		t.Fatalf("shape field ID changed through accessor: %d", got)
	}
	shapes := catalog.Shapes()
	shapes[0].fields[0].ID = 100
	if got, ok := catalog.ShapeAt(0); !ok || got.FieldCount() == 0 {
		t.Fatal("unexpected empty shape")
	}
	if got, _ := catalog.ShapeAt(0); got.Fields()[0].ID != 1 {
		t.Fatalf("catalog field ID changed through Shapes accessor: %d", got.Fields()[0].ID)
	}
}

func testDescriptorForms(t *testing.T) {
	v9, err := NewV9PrivateDescriptor("vendor.counter", 40000, EncodingUnsigned32, 4)
	if err != nil {
		t.Fatalf("v9 private descriptor: %v", err)
	}
	if !v9.Custom || !v9.Private || v9.PEN != 0 || v9.Variable {
		t.Fatalf("v9 private identity flags = %+v", v9)
	}
	ipfix, err := NewIPFIXEnterpriseDescriptor("vendor.label", 32473, 100, EncodingString, true, 65535, 4096)
	if err != nil {
		t.Fatalf("IPFIX enterprise descriptor: %v", err)
	}
	if !ipfix.Custom || !ipfix.Enterprise || ipfix.PEN != 32473 || !ipfix.Variable || ipfix.Length != 65535 || ipfix.MaxLength != 4096 {
		t.Fatalf("IPFIX enterprise identity = %+v", ipfix)
	}
	if _, err := NewIPFIXEnterpriseDescriptor("vendor.timestamp", 32473, 101, EncodingDateTimeNanoseconds, false, 8, 0); err == nil {
		t.Fatal("custom IPFIX timestamp descriptor accepted")
	}
	if _, err := NewIPFIXEnterpriseDescriptor("vendor.timestamp", 32473, 152, EncodingUnsigned64, false, 8, 0); err != nil {
		t.Fatalf("enterprise IE 152 rejected: %v", err)
	}
	for _, descriptor := range []FieldDescriptor{
		{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 152, Length: 8, Encoding: EncodingUnsigned64},
		{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 153, Length: 8, Encoding: EncodingDateTimeMilliseconds},
		{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 154, Length: 8, Encoding: EncodingDateTimeMilliseconds},
		{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 152, Length: 4, Encoding: EncodingDateTimeMilliseconds},
	} {
		if err := descriptor.Validate(); err == nil {
			t.Fatalf("invalid general timestamp descriptor accepted: %+v", descriptor)
		}
	}
	if err := (FieldDescriptor{Protocol: ProtocolV9, Field: FieldFlowIPTTL, ID: 52, Length: 1}).Validate(); err == nil {
		t.Fatal("unspecified descriptor encoding accepted")
	}
	if _, err := NewV9PrivateDescriptor("vendor.counter", 255, EncodingUnsigned32, 4); err == nil {
		t.Fatal("v9 registered ID accepted as private")
	}
	if _, err := NewIPFIXEnterpriseDescriptor("vendor.label", 0, 100, EncodingString, true, 65535, 4096); err == nil {
		t.Fatal("zero PEN accepted for enterprise field")
	}
	if _, err := NewV9PrivateDescriptor("source.address", 40000, EncodingUnsigned32, 4); err == nil {
		t.Fatal("custom source colliding with canonical key accepted")
	}
	d, _ := NewV9PrivateDescriptor("vendor.other", 40001, EncodingUnsigned32, 4)
	d.Field = FieldSourceAddress
	if err := d.Validate(); err == nil {
		t.Fatal("custom descriptor carrying a canonical field binding accepted")
	}
	if err := (FieldDescriptor{Protocol: ProtocolV9, Field: FieldInvalid, Constant: true, ID: 1, Length: 1, Encoding: EncodingUnsigned8}).Validate(); err == nil {
		t.Fatal("v9 constant descriptor accepted")
	}
	if _, err := (FieldDescriptor{Protocol: ProtocolV5, Field: FieldInvalid, Constant: true, ID: 12, Length: 1, Encoding: EncodingUnsigned8}).ValueLength(UintValue(1)); err == nil {
		t.Fatal("nonzero fixed-profile pad accepted")
	}
}

func testShapeFamilyAndIdentityRejections(t *testing.T) {
	v4 := FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 8, Length: 4, Encoding: EncodingIPv4Address}
	if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv6, ID: 1, Fields: []FieldDescriptor{v4}, RecordLength: 4, TemplateBytes: 12}); err == nil {
		t.Fatal("IPv4 address descriptor accepted in IPv6 shape")
	}
	if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 1, Fields: []FieldDescriptor{v4}, RecordLength: 4, TemplateBytes: 13}); err == nil {
		t.Fatal("template sum mismatch accepted")
	}
	dup := []FieldDescriptor{
		{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 8, Length: 4, Encoding: EncodingIPv4Address},
		{Protocol: ProtocolV9, Field: FieldDestinationAddress, ID: 8, Length: 4, Encoding: EncodingIPv4Address},
	}
	if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 1, Fields: dup, RecordLength: 8, TemplateBytes: 16}); err == nil {
		t.Fatal("duplicate v9 wire identity accepted")
	}
}

func testTemplateIDBoundaries(t *testing.T) {
	field := FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 1, Length: 1, Encoding: EncodingUnsigned8}
	for _, tc := range []struct {
		name string
		id   uint32
		ok   bool
	}{
		{name: "below-private-base", id: 255},
		{name: "private-base", id: 256, ok: true},
		{name: "maximum", id: 65535, ok: true},
		{name: "narrowing-overflow", id: 65536},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: tc.id, Fields: []FieldDescriptor{field}, RecordLength: 1, TemplateBytes: 12})
			if tc.ok && err != nil {
				t.Fatalf("ID %d rejected: %v", tc.id, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ID %d accepted", tc.id)
			}
		})
	}
	one := ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, Fields: []FieldDescriptor{field}, RecordLength: 1, TemplateBytes: 12}
	one.ID = 65535
	if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 65535, Shapes: []ShapeSpec{one}}); err != nil {
		t.Fatalf("maximum ID base with one shape rejected: %v", err)
	}
	two := []ShapeSpec{one, one}
	two[1].ID = 0
	if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 65535, Shapes: two}); err == nil {
		t.Fatal("ID base plus shape count overflow accepted")
	}
	ipfixField := FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldFlowIOBytes, ID: 1, Length: 8, Encoding: EncodingUnsigned64}
	for _, id := range []uint32{255, 65536} {
		if _, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: id, Fields: []FieldDescriptor{ipfixField}, RecordLength: 8, TemplateBytes: 12}); err == nil {
			t.Fatalf("IPFIX ID %d accepted", id)
		}
	}
}
