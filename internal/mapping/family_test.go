package mapping

import (
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func testIP(text string) wire.Value {
	address, _ := netip.ParseAddr(text)
	return wire.IPValue(address)
}

func testFamilyRuntime(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.address"}})
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	v4, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourceAddress, Value: testIP("192.0.2.1")}})
	v6, _ := wire.NewRecord(wire.FamilyIPv6, []wire.FieldValue{{Field: wire.FieldSourceAddress, Value: testIP("2001:db8::1")}})
	for _, record := range []wire.NormalizedRecord{v4, v6} {
		bound, err := compiled.Map(record, nil)
		if err != nil || bound.Family() != record.Family() {
			t.Fatalf("family map=%v/%v", bound.Family(), err)
		}
	}
	agnostic, err := Compile(explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}}))
	if err != nil {
		t.Fatal(err)
	}
	v6Port, _ := wire.NewRecord(wire.FamilyIPv6, []wire.FieldValue{
		{Field: wire.FieldSourceAddress, Value: testIP("2001:db8::1")},
		{Field: wire.FieldDestinationAddress, Value: testIP("2001:db8::2")},
		{Field: wire.FieldSourcePort, Value: wire.UintValue(443)},
	})
	mapped, err := agnostic.Map(v6Port, nil)
	if err != nil {
		t.Fatalf("family-agnostic mapping rejected IPv6: %v", err)
	}
	shape, ok := agnostic.Catalog().ShapeAt(0)
	if !ok || mapped.Family() != shape.Family() {
		t.Fatalf("family-agnostic result family=%v shape=%v", mapped.Family(), shape.Family())
	}
	if _, err := shape.DataSetSize([]wire.WireRecord{mapped}); err != nil {
		t.Fatalf("family-agnostic result not packable: %v", err)
	}
	v4Only, err := Compile(explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "flow.fragment_id"}}))
	if err != nil {
		t.Fatal(err)
	}
	v6Fragment, _ := wire.NewRecord(wire.FamilyIPv6, []wire.FieldValue{{Field: wire.FieldFlowFragmentID, Value: wire.UintValue(1)}})
	if _, err := v4Only.Map(v6Fragment, nil); err == nil {
		t.Fatal("IPv4-only mapping accepted IPv6 record")
	}
	customNarrowed := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "flow.icmp_type"}})
	customNarrowed.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "icmp", Number: 1}}
	customNarrowed.Custom = []CustomField{{Source: "vendor.ip", PEN: uint32ptr(7), ElementID: uint32ptr(7), Encoding: "ipv4_address", FixedLength: uint16ptr(4)}}
	narrowed, err := Compile(customNarrowed)
	if err != nil {
		t.Fatalf("family-narrowed ICMP mapping rejected: %v", err)
	}
	if narrowed.ShapeCount() != 1 {
		t.Fatalf("family-narrowed mapping shapes=%d want 1", narrowed.ShapeCount())
	}
}

func testProfileRuntime(t *testing.T) {
	config := Config{Profile: ProfileV9, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}}, NetworkTypeVersions: versionMap(), HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	var mapped wire.WireRecord
	err = normalize.NormalizeEach(testpdata.CanonicalLogs(), func(record wire.NormalizedRecord) error { mapped, err = compiled.Map(record, nil); return err })
	if err != nil {
		t.Fatalf("profile map: %v", err)
	}
	if mapped.Len() != 18 || mapped.Family() != wire.FamilyIPv4 {
		t.Fatalf("mapped=%d/%v", mapped.Len(), mapped.Family())
	}
}

func testV5ProfileRuntime(t *testing.T) {
	config := Config{Profile: ProfileV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}}, InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	var mapped wire.WireRecord
	err = normalize.NormalizeEach(testpdata.CanonicalLogs(), func(record wire.NormalizedRecord) error { mapped, err = compiled.Map(record, nil); return err })
	if err != nil {
		t.Fatalf("v5 map: %v", err)
	}
	if mapped.Len() != 20 || mapped.Family() != wire.FamilyIPv4 {
		t.Fatalf("mapped=%d/%v", mapped.Len(), mapped.Family())
	}
}

func testIPv6ProfileRuntime(t *testing.T) {
	config := Config{Profile: ProfileIPFIX, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}}, NetworkTypeVersions: versionMap()}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	var mapped wire.WireRecord
	err = normalize.NormalizeEach(testpdata.CanonicalIPv6Logs(), func(record wire.NormalizedRecord) error { mapped, err = compiled.Map(record, nil); return err })
	if err != nil {
		t.Fatalf("IPv6 map: %v", err)
	}
	if mapped.Len() != 20 || mapped.Family() != wire.FamilyIPv6 {
		t.Fatalf("mapped=%d/%v", mapped.Len(), mapped.Family())
	}
}
