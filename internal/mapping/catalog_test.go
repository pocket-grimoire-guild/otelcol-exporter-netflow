package mapping

import (
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestCompiledMappingPayloadBudget(t *testing.T) {
	tests := []struct {
		name     string
		payload  uint64
		pathMTU  uint64
		endpoint string
	}{
		{name: "default", payload: 464},
		{name: "explicit-128", payload: 128},
		{name: "explicit-ipv4-484", payload: 484, pathMTU: 512, endpoint: "192.0.2.1:4739"},
		{name: "explicit-ipv4-65507", payload: 65507, pathMTU: 65535, endpoint: "192.0.2.1:4739"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
			config.PathMTU, config.MaxDatagramSize, config.Endpoint = tc.pathMTU, tc.payload, tc.endpoint
			compiled, err := Compile(config)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := compiled.MaxDatagramSize(); got != tc.payload {
				t.Fatalf("compiled payload=%d, want %d", got, tc.payload)
			}
		})
	}
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.MaxDatagramSize = 128
	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("compile immutable baseline: %v", err)
	}
	config.MaxDatagramSize, config.PathMTU, config.Endpoint = 65507, 65535, "192.0.2.1:4739"
	if got := compiled.MaxDatagramSize(); got != 128 {
		t.Fatalf("compiled payload changed after config mutation: %d", got)
	}
	zero := CompiledMapping{}
	if got := zero.MaxDatagramSize(); got != 0 {
		t.Fatalf("zero compiled payload=%d, want 0", got)
	}
}

func TestCompiledMappingOriginContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin uint64
		has    bool
		field  string
	}{
		{name: "present-zero", has: true, field: "flow.start"},
		{name: "present-nonzero", has: true, origin: 1_000_000_000, field: "flow.end"},
		{name: "absent", field: "source.port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: tc.field}})
			config.HasUptimeOrigin, config.UptimeOriginUnixNanos = tc.has, tc.origin
			compiled, err := Compile(config)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			origin, has := compiled.UptimeOrigin()
			if origin != tc.origin || has != tc.has {
				t.Fatalf("origin=(%d,%v), want (%d,%v)", origin, has, tc.origin, tc.has)
			}
		})
	}
}

func testCatalogFieldFamilies(t *testing.T) {
	fields := []FieldSelection{
		{Canonical: "source.address"}, {Canonical: "destination.address"},
		{Canonical: "network.transport"}, {Canonical: "network.type", Target: "ip_version"},
		{Canonical: "flow.io.bytes", Target: "octet_delta_count"}, {Canonical: "flow.io.packets", Target: "packet_delta_count"},
		{Canonical: "flow.fragment_offset"},
		{Canonical: "flow.icmp_type"}, {Canonical: "flow.icmp_code"},
		{Canonical: "flow.src_mac", Target: "source_mac_address"}, {Canonical: "flow.dst_mac", Target: "destination_mac_address"},
		{Canonical: "flow.src_vlan"}, {Canonical: "flow.dst_vlan"},
		{Canonical: "flow.next_hop"}, {Canonical: "flow.bgp_next_hop"},
		{Canonical: "flow.src_net"}, {Canonical: "flow.dst_net"}, {Canonical: "flow.forwarding_status"},
		{Canonical: "flow.observation_point_id"}, {Canonical: "flow.start"}, {Canonical: "flow.end"}, {Canonical: "flow.time_received", Target: "observation_time_nanoseconds"},
	}
	config := explicitConfig(wire.ProtocolIPFIX, fields)
	config.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "icmp", Number: 1}, {Token: "ipv6-icmp", Number: 58}}
	config.NetworkTypeVersions = versionMap()
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.ShapeCount() != 2 {
		t.Fatalf("shape count=%d", compiled.ShapeCount())
	}
	v4, _ := compiled.Catalog().ShapeAt(0)
	v6, _ := compiled.Catalog().ShapeAt(1)
	if v4.Fields()[6].ID != 88 || v6.Fields()[6].ID != 88 {
		t.Fatal("fragment identity changed")
	}
	if v4.Fields()[7].ID != 176 || v6.Fields()[7].ID != 178 {
		t.Fatal("icmp family identity changed")
	}
	if v4.Fields()[19].ID != 156 || v4.Fields()[20].ID != 157 {
		t.Fatal("time identity changed")
	}

	addr4, _ := netip.ParseAddr("192.0.2.1")
	record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{
		{Field: wire.FieldSourceAddress, Value: wire.IPValue(addr4)}, {Field: wire.FieldDestinationAddress, Value: wire.IPValue(addr4)},
		{Field: wire.FieldNetworkTransport, Value: wire.StringValue("icmp")}, {Field: wire.FieldNetworkType, Value: wire.StringValue("ipv4")},
		{Field: wire.FieldFlowIOBytes, Value: wire.UintValue(1)}, {Field: wire.FieldFlowIOPackets, Value: wire.UintValue(1)}, {Field: wire.FieldFlowFragmentOffset, Value: wire.UintValue(1)},
		{Field: wire.FieldFlowICMPType, Value: wire.UintValue(8)}, {Field: wire.FieldFlowICMPCode, Value: wire.UintValue(0)}, {Field: wire.FieldFlowSrcMAC, Value: wire.MACValue([6]byte{})}, {Field: wire.FieldFlowDstMAC, Value: wire.MACValue([6]byte{})}, {Field: wire.FieldFlowSrcVLAN, Value: wire.UintValue(1)}, {Field: wire.FieldFlowDstVLAN, Value: wire.UintValue(1)},
		{Field: wire.FieldFlowVLANID, Value: wire.UintValue(1)}, {Field: wire.FieldFlowNextHop, Value: wire.IPValue(addr4)}, {Field: wire.FieldFlowBGPNextHop, Value: wire.IPValue(addr4)}, {Field: wire.FieldFlowSrcNet, Value: wire.UintValue(24)}, {Field: wire.FieldFlowDstNet, Value: wire.UintValue(24)}, {Field: wire.FieldFlowForwardingStatus, Value: wire.UintValue(0)}, {Field: wire.FieldFlowObservationPointID, Value: wire.UintValue(1)}, {Field: wire.FieldFlowStart, Value: wire.UnixNanosValue(1)}, {Field: wire.FieldFlowEnd, Value: wire.UnixNanosValue(1)}, {Field: wire.FieldFlowTimeReceived, Value: wire.UnixNanosValue(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := compiled.Map(record, nil)
	if err != nil || bound.Len() != len(fields) {
		t.Fatalf("mapped=%d err=%v", bound.Len(), err)
	}
}
