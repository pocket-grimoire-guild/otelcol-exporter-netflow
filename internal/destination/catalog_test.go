package destination

import (
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestCatalogCompilerOwnership(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			compiled := compiledMapping(t, protocol)
			catalog, err := NewCatalog(compiled)
			if err != nil {
				t.Fatal(err)
			}
			if catalog.Protocol() != protocol || catalog.ShapeCount() != compiled.ShapeCount() {
				t.Fatalf("catalog protocol/count=%v/%d", catalog.Protocol(), catalog.ShapeCount())
			}
			for i, id := range catalog.IDs() {
				shape, ok := compiled.Catalog().ShapeAt(i)
				if !ok || id != shape.ID() {
					t.Fatalf("shape %d id=%d, compiler id=%d/%v", i, id, shape.ID(), ok)
				}
			}
		})
	}
}

func TestCatalogStaticLimitBoundaries(t *testing.T) {
	field := wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, ID: 1, Length: 2, Encoding: wire.EncodingUnsigned16}
	shapeSpec := func(id uint32, fields []wire.FieldDescriptor, record, template uint64) wire.ShapeSpec {
		return wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: id, Fields: fields, RecordLength: record, TemplateBytes: template}
	}
	for _, count := range []int{1, 15, 16} {
		shapes := make([]wire.ShapeSpec, count)
		for i := range shapes {
			f := field
			f.ID = uint16(i + 1)
			shapes[i] = shapeSpec(uint32(256+i), []wire.FieldDescriptor{f}, 2, 12)
		}
		wireCatalog, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: shapes})
		if err != nil {
			t.Fatalf("wire catalog count %d: %v", count, err)
		}
		if _, err := NewCatalogFromWire(wireCatalog); err != nil {
			t.Fatalf("destination catalog count %d: %v", count, err)
		}
	}
	shapes := make([]wire.ShapeSpec, 17)
	for i := range shapes {
		f := field
		f.ID = uint16(i + 1)
		shapes[i] = shapeSpec(uint32(256+i), []wire.FieldDescriptor{f}, 2, 12)
	}
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: shapes}); err == nil {
		t.Fatal("wire accepted 17 shapes")
	}
}

func TestCatalogFieldAndTemplateLimitBoundaries(t *testing.T) {
	base := wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, Length: 2, Encoding: wire.EncodingUnsigned16}
	for _, count := range []int{63, 64} {
		fields := make([]wire.FieldDescriptor, count)
		for i := range fields {
			fields[i] = base
			fields[i].ID = uint16(i + 1)
		}
		valid, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: []wire.ShapeSpec{{
			Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 256, Fields: fields, RecordLength: uint64(2 * count), TemplateBytes: uint64(8 + 4*count),
		}}})
		if err != nil {
			t.Fatalf("%d-field catalog: %v", count, err)
		}
		if _, err := NewCatalogFromWire(valid); err != nil {
			t.Fatalf("destination rejected %d-field catalog: %v", count, err)
		}
	}
	fields := make([]wire.FieldDescriptor, 64)
	for i := range fields {
		fields[i] = base
		fields[i].ID = uint16(i + 1)
	}
	fields = append(fields, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, ID: 65, Length: 2, Encoding: wire.EncodingUnsigned16})
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: []wire.ShapeSpec{{
		Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 256, Fields: fields, RecordLength: 130, TemplateBytes: 268,
	}}}); err == nil {
		t.Fatal("wire accepted 65-field catalog")
	}
	tooLarge := wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 256, Fields: []wire.FieldDescriptor{base}, RecordLength: 2, TemplateBytes: 4097}
	if _, err := wire.NewShape(tooLarge); err == nil {
		t.Fatal("wire accepted template size 4097")
	}
}

func TestCatalogTemplatePolicyBoundary(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, test := range []struct {
			bytes uint64
			valid bool
		}{
			{4095, true}, {4096, true}, {4097, false},
		} {
			err := validateTemplateBytesBudget(protocol, test.bytes)
			if (err == nil) != test.valid {
				t.Fatalf("%s template bytes=%d valid=%v err=%v", protocol, test.bytes, test.valid, err)
			}
		}
	}
	if err := validateTemplateBytesBudget(wire.ProtocolV5, 0); err != nil {
		t.Fatalf("v5 zero template bytes: %v", err)
	}
	if err := validateTemplateBytesBudget(wire.ProtocolV5, 1); err == nil {
		t.Fatal("v5 accepted template bytes")
	}
}
