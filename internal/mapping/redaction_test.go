package mapping

import (
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func testRedactionDecodeBoundary(t *testing.T) {
	if _, err := DecodeJSON([]byte(`{"protocol":3,"fields":[{"canonical":"source.port","secret":"value"}],"loss_policy":"encode_and_count"}`)); err == nil {
		t.Fatal("unknown mapping member accepted")
	}
	if _, err := DecodeJSON([]byte(`{"protocol":3,"fields":[{"canonical":"source.port"}],"loss_policy":"encode_and_count"} trailing`)); err == nil {
		t.Fatal("trailing object accepted")
	}
	config := explicitConfig(3, []FieldSelection{{Canonical: "not-a-canonical-key"}})
	_, err := Compile(config)
	if err == nil || len(err.Error()) > 256 || strings.Contains(err.Error(), "not-a-canonical-key") {
		t.Fatalf("unsafe compiler error: %v", err)
	}
	config = explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.Custom = []CustomField{{Source: "private.secret", PEN: uint32ptr(999999), ElementID: uint32ptr(99999), Encoding: "unsigned64", FixedLength: uint16ptr(8)}}
	_, err = Compile(config)
	if err == nil || strings.Contains(err.Error(), "999999") || strings.Contains(err.Error(), "99999") {
		t.Fatalf("custom identity leaked: %v", err)
	}
	for _, source := range []string{"body.secret", "resource.secret", "scope.secret"} {
		config.Custom[0].Source = source
		if _, err = Compile(config); err == nil {
			t.Fatalf("reserved custom source accepted: %q", source)
		}
	}
}
