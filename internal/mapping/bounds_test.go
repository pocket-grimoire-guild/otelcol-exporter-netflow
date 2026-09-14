package mapping

import (
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func testBoundsStatic(t *testing.T) {
	fields := make([]FieldSelection, 65)
	for i := range fields {
		fields[i] = FieldSelection{Canonical: "source.port"}
	}
	if _, err := Compile(explicitConfig(wire.ProtocolV9, fields)); err == nil {
		t.Fatal("65 fields accepted")
	}
	for _, base := range []uint32{255, 65536} {
		config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}})
		config.IDBase = base
		if _, err := Compile(config); err == nil {
			t.Fatalf("ID base %d accepted", base)
		}
	}
	config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}})
	config.IDBase = 65535
	if _, err := Compile(config); err != nil {
		t.Fatalf("single shape at max ID rejected: %v", err)
	}
}
