package wire

import (
	"bytes"
	"math"
	"testing"
)

func TestBounds(t *testing.T) {
	t.Run("descriptor-IDs-and-lengths", func(t *testing.T) {
		base := FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 1, Length: 1, Encoding: EncodingUnsigned8}
		for _, tc := range []struct {
			name string
			d    FieldDescriptor
			ok   bool
		}{
			{name: "v9-zero", d: FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 0, Length: 1, Encoding: EncodingUnsigned8}},
			{name: "v9-standard-256", d: FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 256, Length: 1, Encoding: EncodingUnsigned8}},
			{name: "v9-private-255", d: FieldDescriptor{Protocol: ProtocolV9, Field: FieldInvalid, Source: "x", Custom: true, Private: true, ID: 255, Length: 1, Encoding: EncodingUnsigned8}},
			{name: "v9-private-256", d: FieldDescriptor{Protocol: ProtocolV9, Field: FieldInvalid, Source: "x", Custom: true, Private: true, ID: 256, Length: 4, Encoding: EncodingUnsigned32}, ok: true},
			{name: "ipfix-standard-32768", d: FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldSourceAddress, ID: 32768, Length: 1, Encoding: EncodingUnsigned8}},
			{name: "ipfix-enterprise-no-pen", d: FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldInvalid, Source: "x", Custom: true, Enterprise: true, ID: 1, Length: 1, Encoding: EncodingUnsigned8}},
			{name: "ipfix-variable-marker", d: FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldInvalid, Source: "x", Custom: true, Enterprise: true, PEN: 1, ID: 1, Variable: true, Length: 65535, MaxLength: 4096, Encoding: EncodingString}, ok: true},
			{name: "ipfix-variable-254", d: FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldInvalid, Source: "x", Custom: true, Enterprise: true, PEN: 1, ID: 1, Variable: true, Length: 254, MaxLength: 4096, Encoding: EncodingString}},
			{name: "ipfix-variable-hard-maximum", d: FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldInvalid, Source: "x", Custom: true, Enterprise: true, PEN: 1, ID: 1, Variable: true, Length: 65535, MaxLength: 65535, Encoding: EncodingString}, ok: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.d.Validate()
				if tc.ok && err != nil {
					t.Fatalf("descriptor rejected: %v", err)
				}
				if !tc.ok && err == nil {
					t.Fatal("invalid descriptor accepted")
				}
			})
		}
		if err := base.Validate(); err != nil {
			t.Fatalf("base standard descriptor rejected: %v", err)
		}
		if _, err := NewIPFIXEnterpriseDescriptor("x", 1, 1, EncodingString, true, 65535, 65536); err == nil {
			t.Fatal("variable maximum 65536 accepted")
		}
	})

	t.Run("shape-count-field-count-and-template", func(t *testing.T) {
		fields := make([]FieldDescriptor, 64)
		for i := range fields {
			fields[i] = FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: uint16(i + 1), Length: 1, Encoding: EncodingUnsigned8}
		}
		if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: fields, RecordLength: 64, TemplateBytes: 264}); err != nil {
			t.Fatalf("64-field shape rejected: %v", err)
		}
		fields = append(fields, FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 65, Length: 1, Encoding: EncodingUnsigned8})
		if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: fields, RecordLength: 65, TemplateBytes: 268}); err == nil {
			t.Fatal("65-field shape accepted")
		}
		tooLarge := make([]FieldDescriptor, 1)
		tooLarge[0] = FieldDescriptor{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: 1, Length: 1, Encoding: EncodingUnsigned8}
		if _, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: tooLarge, RecordLength: 1, TemplateBytes: 4097}); err == nil {
			t.Fatal("4097-byte template accepted")
		}

		one := ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, Fields: tooLarge, RecordLength: 1, TemplateBytes: 12}
		many := make([]ShapeSpec, 16)
		for i := range many {
			many[i] = one
			many[i].ID = uint32(256 + i)
		}
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: many}); err != nil {
			t.Fatalf("16-shape catalog rejected: %v", err)
		}
		many = append(many, one)
		many[16].ID = 272
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: many}); err == nil {
			t.Fatal("17-shape catalog accepted")
		}
	})

	t.Run("custom-count-and-PEN", func(t *testing.T) {
		fields := make([]FieldDescriptor, 32)
		for i := range fields {
			fields[i], _ = NewV9PrivateDescriptor("vendor.same", uint32(40000+i), EncodingUnsigned32, 4)
		}
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: []ShapeSpec{{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: fields, RecordLength: 128, TemplateBytes: 136}}}); err != nil {
			t.Fatalf("32 custom mappings rejected: %v", err)
		}
		fields = append(fields, fields[0])
		fields[32].Source = "vendor.extra"
		fields[32].ID = 40032
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: []ShapeSpec{{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: fields, RecordLength: 132, TemplateBytes: 140}}}); err == nil {
			t.Fatal("33 custom mappings accepted")
		}
		enterprise := make([]FieldDescriptor, 32)
		for i := range enterprise {
			enterprise[i], _ = NewIPFIXEnterpriseDescriptor("vendor.ipfix", uint32(i+1), uint32(i+1), EncodingUnsigned32, false, 4, 0)
		}
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolIPFIX, IDBase: 256, Shapes: []ShapeSpec{{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, Fields: enterprise, RecordLength: 128, TemplateBytes: 264}}}); err != nil {
			t.Fatalf("32 enterprise PENs rejected: %v", err)
		}
		enterprise = append(enterprise, enterprise[0])
		enterprise[32].PEN, enterprise[32].ID = 33, 33
		if _, err := NewCatalog(CatalogSpec{Protocol: ProtocolIPFIX, IDBase: 256, Shapes: []ShapeSpec{{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, Fields: enterprise, RecordLength: 132, TemplateBytes: 272}}}); err == nil {
			t.Fatal("33 enterprise PENs accepted")
		}
	})

	t.Run(canonicalIPv4FixtureID+"/checked-packet-sums-and-capacity", func(t *testing.T) {
		shape, _ := BuiltinV9().ShapeAt(0)
		records := []WireRecord{mustWireRecord(t, shape)}
		req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: 2}, Shape: shape, Records: records, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
		dataSet, err := shape.DataSetSize(records)
		if err != nil {
			t.Fatalf("data set sizing: %v", err)
		}
		need := 20 + int(shape.TemplateBytes()) + int(dataSet.Length())
		for _, tc := range []struct {
			name string
			buf  int
			ok   bool
		}{
			{name: "exact", buf: need, ok: true},
			{name: "one-short", buf: need - 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if !tc.ok {
					assertPreflightReject(t, req, tc.buf, ErrShortBuffer)
					return
				}
				buf := bytes.Repeat([]byte{0xcd}, tc.buf)
				before := append([]byte(nil), buf...)
				n, err := Preflight(buf, req)
				if err != nil || n != need {
					t.Fatalf("exact preflight = (%d, %v), want (%d,nil)", n, err, need)
				}
				if !bytes.Equal(buf, before) {
					t.Fatal("preflight mutated caller bytes")
				}
			})
		}
		if _, ok := checkedMul(math.MaxUint64, 2); ok {
			t.Fatal("checkedMul overflow unexpectedly accepted")
		}
		if _, ok := checkedAdd(math.MaxUint64, 1); ok {
			t.Fatal("checkedAdd overflow unexpectedly accepted")
		}
		v5Shape, _ := BuiltinV5().ShapeAt(0)
		v5Req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV5}, Shape: v5Shape, Records: nil}
		assertPreflightReject(t, v5Req, DefaultMaxMessageBytes, ErrBounds)

		badDescriptor := req
		badDescriptor.Shape.fields = badDescriptor.Shape.Fields()
		badDescriptor.Shape.fields[0].Length = 0
		assertPreflightReject(t, badDescriptor, DefaultMaxMessageBytes, ErrInvalidDescriptor)
		badTemplateSize := req
		badTemplateSize.TemplateBytes = DefaultMaxTemplateBytes + 1
		assertPreflightReject(t, badTemplateSize, DefaultMaxMessageBytes, ErrBounds)
		badDataSum := req
		badDataSum.DataBytes = math.MaxUint64
		assertPreflightReject(t, badDataSum, DefaultMaxMessageBytes, ErrBounds)
		badBudget := req
		badBudget.MaxDatagramBytes = math.MaxUint64
		assertPreflightReject(t, badBudget, DefaultMaxMessageBytes, ErrBounds)
	})

	t.Run(canonicalIPv4FixtureID+"/record-value-rejections", func(t *testing.T) {
		shape, _ := BuiltinV9().ShapeAt(0)
		valid := mustWireRecord(t, shape)
		wrongKind := valid
		wrongKind.values[0] = StringValue("wrong fixed kind")
		invalidRecord := WireRecord{}
		shortRecord := valid
		shortRecord.count = 0
		for _, tc := range []struct {
			name   string
			record WireRecord
			want   error
		}{
			{name: "invalid-record", record: invalidRecord, want: ErrInvalidFamily},
			{name: "wrong-fixed-value-kind", record: wrongKind, want: ErrInvalidValue},
			{name: "record-value-count", record: shortRecord, want: ErrRecordValueLimit},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: 1}, Shape: shape, Records: []WireRecord{tc.record}}
				assertPreflightReject(t, req, DefaultMaxMessageBytes, tc.want)
			})
		}
	})

	t.Run("variable-length-boundaries", func(t *testing.T) {
		descriptor, err := NewIPFIXEnterpriseDescriptor("vendor.label", 32473, 100, EncodingString, true, 65535, 65535)
		if err != nil {
			t.Fatalf("variable descriptor: %v", err)
		}
		for _, length := range []int{0, 1, 253, 254, 255, 65535, 65536} {
			value := StringValue(string(make([]byte, length)))
			got, valueErr := descriptor.ValueLength(value)
			if length == 65536 {
				if valueErr == nil || got != 0 {
					t.Fatalf("length %d accepted: (%d,%v)", length, got, valueErr)
				}
				continue
			}
			if length == 65535 {
				if valueErr == nil || got != 0 {
					t.Fatalf("length %d unexpectedly fits a 16-bit Set: (%d,%v)", length, got, valueErr)
				}
				continue
			}
			want := uint64(length + 1)
			if length >= 255 {
				want = uint64(length + 3)
			}
			if valueErr != nil || got != want {
				t.Fatalf("length %d = (%d,%v), want (%d,nil)", length, got, valueErr, want)
			}
		}
	})

	t.Run("wire-value-union", func(t *testing.T) {
		bad := Value{kind: ValueInt, intValue: 1, octets: "x", octetsSet: true}
		if _, err := NewWireRecord(FamilyIPv4, []Value{bad}); err == nil {
			t.Fatal("inactive byte member retained by integer value")
		}
		if _, err := NewWireRecord(FamilyIPv4, []Value{{kind: ValueInt, intValue: 1, octetsSet: true}}); err == nil {
			t.Fatal("inactive empty byte member retained by integer value")
		}
		if _, err := NewWireRecord(FamilyIPv4, nil); err == nil {
			t.Fatal("empty wire record accepted")
		}
		if _, err := NewWireRecord(FamilyIPv4, []Value{StringValue("invalid IP")}); err != nil {
			t.Fatalf("generic string value rejected before descriptor binding: %v", err)
		}
	})

	t.Run(canonicalIPv6FixtureID+"/caller-budgets", func(t *testing.T) {
		for _, tc := range []struct {
			payload uint64
			budget  uint64
			ok      bool
		}{
			{127, 127, true}, {128, 127, false}, {464, 464, true}, {65507, 65507, true}, {65508, 65507, false},
		} {
			err := ValidatePayloadLength(tc.payload, tc.budget)
			if tc.ok && err != nil {
				t.Fatalf("payload=%d budget=%d rejected: %v", tc.payload, tc.budget, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("payload=%d budget=%d accepted", tc.payload, tc.budget)
			}
		}
		for _, payload := range []uint64{65536, math.MaxUint64} {
			if err := ValidatePayloadLength(payload, 0); err == nil {
				t.Fatalf("payload=%d exceeded 16-bit bound", payload)
			}
		}
		shape, _ := BuiltinV9().ShapeAt(0)
		budgetReq := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9}, Shape: shape, MaxDatagramBytes: 19}
		assertPreflightReject(t, budgetReq, DefaultMaxMessageBytes, ErrBounds)
	})

	t.Run(canonicalIPv4FixtureID+"/set-minima", func(t *testing.T) {
		for _, protocol := range []Protocol{ProtocolV9, ProtocolIPFIX} {
			catalog := BuiltinV9()
			if protocol == ProtocolIPFIX {
				catalog = BuiltinIPFIX()
			}
			shape, _ := catalog.ShapeAt(0)
			req := PacketRequest{Header: HeaderMetadata{Protocol: protocol}, Shape: shape, DataBytes: flowSetHeaderBytes}
			assertPreflightReject(t, req, DefaultMaxMessageBytes, ErrBounds)
		}

		fixedDescriptor := FieldDescriptor{Protocol: ProtocolV9, Field: FieldFlowIPTTL, ID: 52, Length: 1, Encoding: EncodingUnsigned8}
		fixedShape, err := NewShape(ShapeSpec{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, Fields: []FieldDescriptor{fixedDescriptor}, RecordLength: 1, TemplateBytes: 12})
		if err != nil {
			t.Fatalf("fixed one-byte shape: %v", err)
		}
		fixedRecord, err := NewWireRecord(FamilyIPv4, []Value{UintValue(0)})
		if err != nil {
			t.Fatalf("fixed record: %v", err)
		}
		fixedReq := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolV9, Count: 1}, Shape: fixedShape, Records: []WireRecord{fixedRecord}}
		fixedSize, err := fixedShape.DataSetSize(fixedReq.Records)
		if err != nil || fixedSize.Padding() != 0 || fixedSize.Length() != flowSetHeaderBytes+1 {
			t.Fatalf("fixed one-byte data set size = (%+v,%v)", fixedSize, err)
		}
		if n, err := Preflight(make([]byte, int(protocolV9HeaderBytes+flowSetHeaderBytes+1)), fixedReq); err != nil || n != int(protocolV9HeaderBytes+flowSetHeaderBytes+1) {
			t.Fatalf("fixed v9 one-byte preflight = (%d,%v), want (25,nil)", n, err)
		}
		assertPreflightReject(t, fixedReq, int(protocolV9HeaderBytes+flowSetHeaderBytes), ErrShortBuffer)

		ipfixFixedDescriptor, err := NewIPFIXEnterpriseDescriptor("vendor.fixed", 32473, 100, EncodingUnsigned8, false, 1, 0)
		if err != nil {
			t.Fatalf("fixed IPFIX descriptor: %v", err)
		}
		ipfixFixedShape, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, Fields: []FieldDescriptor{ipfixFixedDescriptor}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatalf("fixed IPFIX shape: %v", err)
		}
		ipfixFixedRecord, err := NewWireRecord(FamilyIPv4, []Value{UintValue(0)})
		if err != nil {
			t.Fatalf("fixed IPFIX record: %v", err)
		}
		ipfixFixedReq := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: ipfixFixedShape, Records: []WireRecord{ipfixFixedRecord}, DataBytes: flowSetHeaderBytes + 1}
		ipfixFixedSize, err := ipfixFixedShape.DataSetSize(ipfixFixedReq.Records)
		if err != nil || ipfixFixedSize.Padding() != 0 || ipfixFixedSize.Length() != flowSetHeaderBytes+1 {
			t.Fatalf("fixed IPFIX one-byte data set size = (%+v,%v)", ipfixFixedSize, err)
		}
		if n, err := Preflight(make([]byte, int(protocolIPFIXHeaderBytes+flowSetHeaderBytes+1)), ipfixFixedReq); err != nil || n != int(protocolIPFIXHeaderBytes+flowSetHeaderBytes+1) {
			t.Fatalf("fixed IPFIX one-byte preflight = (%d,%v), want (21,nil)", n, err)
		}
		assertPreflightReject(t, ipfixFixedReq, int(protocolIPFIXHeaderBytes+flowSetHeaderBytes), ErrShortBuffer)

		variableDescriptor, err := NewIPFIXEnterpriseDescriptor("vendor.label", 32473, 100, EncodingString, true, 65535, 4096)
		if err != nil {
			t.Fatalf("variable descriptor: %v", err)
		}
		variableShape, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, Fields: []FieldDescriptor{variableDescriptor}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatalf("variable one-byte shape: %v", err)
		}
		variableRecord, err := NewWireRecord(FamilyIPv4, []Value{StringValue("")})
		if err != nil {
			t.Fatalf("variable record: %v", err)
		}
		variableReq := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: variableShape, Records: []WireRecord{variableRecord}}
		if n, err := Preflight(make([]byte, 65535), variableReq); err != nil || n != int(protocolIPFIXHeaderBytes+flowSetHeaderBytes+1) {
			t.Fatalf("variable five-byte data set = (%d,%v)", n, err)
		}

		variableCases := []struct {
			name      string
			encoding  DescriptorEncoding
			valid     Value
			wrongKind Value
		}{
			{name: "string", encoding: EncodingString, valid: StringValue(""), wrongKind: BytesValue(nil)},
			{name: "octet-array", encoding: EncodingOctetArray, valid: BytesValue(nil), wrongKind: StringValue("")},
		}
		for _, tc := range variableCases {
			t.Run(tc.name+"-wrong-kind", func(t *testing.T) {
				descriptor, err := NewIPFIXEnterpriseDescriptor("vendor."+tc.name, 32473, 100, tc.encoding, true, 65535, 4096)
				if err != nil {
					t.Fatalf("variable descriptor: %v", err)
				}
				shape, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, Fields: []FieldDescriptor{descriptor}, RecordLength: 1, TemplateBytes: 16})
				if err != nil {
					t.Fatalf("variable shape: %v", err)
				}
				validRecord, err := NewWireRecord(FamilyIPv4, []Value{tc.valid})
				if err != nil {
					t.Fatalf("valid record: %v", err)
				}
				validReq := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: shape, Records: []WireRecord{validRecord}}
				if n, err := Preflight(make([]byte, 65535), validReq); err != nil || n != int(protocolIPFIXHeaderBytes+flowSetHeaderBytes+1) {
					t.Fatalf("valid variable data set = (%d,%v)", n, err)
				}
				record, err := NewWireRecord(FamilyIPv4, []Value{tc.wrongKind})
				if err != nil {
					t.Fatalf("wrong-kind record: %v", err)
				}
				req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: shape, Records: []WireRecord{record}}
				assertPreflightReject(t, req, DefaultMaxMessageBytes, ErrInvalidValue)
			})
		}
		tooLongDescriptor, err := NewIPFIXEnterpriseDescriptor("vendor.short", 32473, 102, EncodingString, true, 65535, 4)
		if err != nil {
			t.Fatalf("bounded variable descriptor: %v", err)
		}
		tooLongShape, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 257, Fields: []FieldDescriptor{tooLongDescriptor}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatalf("bounded variable shape: %v", err)
		}
		tooLongRecord, err := NewWireRecord(FamilyIPv4, []Value{StringValue("12345")})
		if err != nil {
			t.Fatalf("too-long record: %v", err)
		}
		assertPreflightReject(t, PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: tooLongShape, Records: []WireRecord{tooLongRecord}}, DefaultMaxMessageBytes, ErrBounds)
	})

	t.Run(canonicalIPv4FixtureID+"/padding-and-size-seam", func(t *testing.T) {
		v9Shape, ok := BuiltinV9().ShapeAt(0)
		if !ok {
			t.Fatal("missing built-in v9 IPv4 shape")
		}
		v9Record := mustWireRecord(t, v9Shape)
		v9Records := []WireRecord{v9Record}
		v9Size, err := v9Shape.DataSetSize(v9Records)
		if err != nil {
			t.Fatalf("built-in v9 data set sizing: %v", err)
		}
		if v9Size.Length() != 48 || v9Size.Padding() != 1 {
			t.Fatalf("built-in v9 one-record set = (length=%d,padding=%d), want (48,1)", v9Size.Length(), v9Size.Padding())
		}
		v9Want := protocolV9HeaderBytes + v9Shape.TemplateBytes() + v9Size.Length()
		v9Req := PacketRequest{
			Header: HeaderMetadata{Protocol: ProtocolV9, Count: 2}, Shape: v9Shape,
			Records: v9Records, TemplateRecords: 1, TemplateBytes: v9Shape.TemplateBytes(), DataBytes: v9Size.Length(),
		}
		if n, err := Preflight(make([]byte, v9Want), v9Req); err != nil || uint64(n) != v9Want {
			t.Fatalf("built-in v9 one-record message = (%d,%v), want (%d,nil)", n, err, v9Want)
		}
		badData := v9Req
		badData.DataBytes--
		assertPreflightReject(t, badData, int(v9Want), ErrBounds)
		budget := v9Req
		budget.MaxDatagramBytes = v9Want - 1
		assertPreflightReject(t, budget, int(v9Want), ErrBounds)
		assertPreflightReject(t, v9Req, int(v9Want-1), ErrShortBuffer)

		fixed, err := NewIPFIXEnterpriseDescriptor("vendor.fixed", 32473, 100, EncodingOctetArray, false, 3, 0)
		if err != nil {
			t.Fatalf("fixed enterprise descriptor: %v", err)
		}
		variable, err := NewIPFIXEnterpriseDescriptor("vendor.label", 32473, 101, EncodingString, true, 65535, 4096)
		if err != nil {
			t.Fatalf("variable enterprise descriptor: %v", err)
		}
		customShape, err := NewShape(ShapeSpec{
			Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256,
			Fields: []FieldDescriptor{fixed, variable}, RecordLength: 4, TemplateBytes: 24,
		})
		if err != nil {
			t.Fatalf("padding vector shape: %v", err)
		}
		for _, tc := range []struct {
			name    string
			payload string
			length  uint64
			padding uint8
		}{
			{name: "aligned", payload: "", length: 8, padding: 0},
			{name: "padding-3", payload: "x", length: 12, padding: 3},
			{name: "padding-2", payload: "xx", length: 12, padding: 2},
			{name: "padding-1", payload: "xxx", length: 12, padding: 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				record, err := NewWireRecord(FamilyIPv4, []Value{BytesValue([]byte{1, 2, 3}), StringValue(tc.payload)})
				if err != nil {
					t.Fatalf("padding vector record: %v", err)
				}
				records := []WireRecord{record}
				size, err := customShape.DataSetSize(records)
				if err != nil {
					t.Fatalf("padding vector sizing: %v", err)
				}
				if size.Length() != tc.length || size.Padding() != tc.padding {
					t.Fatalf("padding vector size = (length=%d,padding=%d), want (%d,%d)", size.Length(), size.Padding(), tc.length, tc.padding)
				}
				req := PacketRequest{Header: HeaderMetadata{Protocol: ProtocolIPFIX}, Shape: customShape, Records: records, DataBytes: size.Length()}
				want := protocolIPFIXHeaderBytes + size.Length()
				if n, err := Preflight(make([]byte, want), req); err != nil || uint64(n) != want {
					t.Fatalf("padding vector preflight = (%d,%v), want (%d,nil)", n, err, want)
				}
				allocs := testing.AllocsPerRun(1000, func() {
					got, err := customShape.DataSetSize(records)
					if err != nil || got != size {
						panic("data set sizing changed")
					}
				})
				if allocs != 0 {
					t.Fatalf("DataSetSize allocations per run = %v, want 0", allocs)
				}
			})
		}

		variableDescriptor, err := NewIPFIXEnterpriseDescriptor("vendor.empty", 32473, 102, EncodingString, true, 65535, 4096)
		if err != nil {
			t.Fatalf("empty variable descriptor: %v", err)
		}
		variableShape, err := NewShape(ShapeSpec{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 257, Fields: []FieldDescriptor{variableDescriptor}, RecordLength: 1, TemplateBytes: 16})
		if err != nil {
			t.Fatalf("empty variable shape: %v", err)
		}
		variableRecord, err := NewWireRecord(FamilyIPv4, []Value{StringValue("")})
		if err != nil {
			t.Fatalf("empty variable record: %v", err)
		}
		variableSize, err := variableShape.DataSetSize([]WireRecord{variableRecord})
		if err != nil || variableSize.Length() != 5 || variableSize.Padding() != 0 {
			t.Fatalf("five-byte empty-variable set = (%+v,%v), want (length=5,padding=0)", variableSize, err)
		}
	})
}
