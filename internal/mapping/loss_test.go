package mapping

import (
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func testLossRuntime(t *testing.T) {
	config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "network.transport"}})
	config.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "tcp", Number: 6}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldNetworkTransport, Value: wire.StringValue("udp")}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiled.Map(record, nil)
	if err == nil || !errors.Is(err, ErrRuntime) {
		t.Fatalf("map miss=%v", err)
	}
}
