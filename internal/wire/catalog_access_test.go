package wire

import "testing"

// shapeAtEscapeSink keeps the ShapeAt result observable while the allocation
// test runs. A package-level sink prevents the compiler from deleting the
// lookup as dead code.
var shapeAtEscapeSink Shape

func TestCatalogShapeAccessIsolated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		catalog Catalog
	}{
		{name: "v5", catalog: BuiltinV5()},
		{name: "v9", catalog: BuiltinV9()},
		{name: "ipfix", catalog: BuiltinIPFIX()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := tc.catalog
			for _, index := range []int{-1, catalog.ShapeCount()} {
				if _, ok := catalog.ShapeAt(index); ok {
					t.Fatalf("ShapeAt(%d) reported an out-of-range shape", index)
				}
			}

			spec := catalogAccessSpec(catalog)
			wantFields := make([][]FieldDescriptor, len(spec.Shapes))
			for i := range spec.Shapes {
				wantFields[i] = append([]FieldDescriptor(nil), spec.Shapes[i].Fields...)
			}
			constructed, err := NewCatalog(spec)
			if err != nil {
				t.Fatalf("NewCatalog: %v", err)
			}

			// NewCatalog owns a copy of the constructor descriptors.
			for i := range spec.Shapes {
				spec.Shapes[i].Fields[0].ID++
			}
			assertCatalogFields(t, constructed, wantFields)

			for i := 0; i < constructed.ShapeCount(); i++ {
				shape, ok := constructed.ShapeAt(i)
				if !ok {
					t.Fatalf("ShapeAt(%d) failed", i)
				}

				// Fields returns independent descriptor storage.
				fields := shape.Fields()
				fields[0].ID++
				// DescriptorAt returns a descriptor value, not mutable catalog storage.
				descriptor, ok := shape.DescriptorAt(0)
				if !ok {
					t.Fatalf("DescriptorAt(0) failed for shape %d", i)
				}
				descriptor.ID++

				// Shapes returns independent shape values and descriptor slices.
				shapes := constructed.Shapes()
				shapes[i].fields[0].ID++
				assertCatalogFields(t, constructed, wantFields)
			}
		})
	}
}

func TestCatalogShapeAtZeroAllocations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		catalog Catalog
	}{
		{name: "v5", catalog: BuiltinV5()},
		{name: "v9", catalog: BuiltinV9()},
		{name: "ipfix", catalog: BuiltinIPFIX()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				shape, ok := tc.catalog.ShapeAt(0)
				if !ok {
					panic("missing shape")
				}
				shapeAtEscapeSink = shape
			})
			if allocs != 0 {
				t.Fatalf("ShapeAt allocations = %v, want 0", allocs)
			}
		})
	}
}

func catalogAccessSpec(catalog Catalog) CatalogSpec {
	shapes := catalog.Shapes()
	spec := CatalogSpec{Protocol: catalog.Protocol(), Shapes: make([]ShapeSpec, len(shapes))}
	if catalog.Protocol() != ProtocolV5 {
		spec.IDBase = uint32(shapes[0].ID())
	}
	for i, shape := range shapes {
		spec.Shapes[i] = ShapeSpec{
			Protocol:      shape.Protocol(),
			Family:        shape.Family(),
			ID:            uint32(shape.ID()),
			Fields:        shape.Fields(),
			RecordLength:  shape.RecordLength(),
			TemplateBytes: shape.TemplateBytes(),
		}
	}
	return spec
}

func assertCatalogFields(t *testing.T, catalog Catalog, want [][]FieldDescriptor) {
	t.Helper()
	for i, fields := range want {
		shape, ok := catalog.ShapeAt(i)
		if !ok {
			t.Fatalf("ShapeAt(%d) failed", i)
		}
		got := shape.Fields()
		if len(got) != len(fields) {
			t.Fatalf("shape %d field count = %d, want %d", i, len(got), len(fields))
		}
		for j := range fields {
			if got[j] != fields[j] {
				t.Fatalf("shape %d field %d changed: got %+v, want %+v", i, j, got[j], fields[j])
			}
		}
	}
}
