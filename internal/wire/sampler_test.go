package wire

import (
	"net/netip"
	"testing"
)

func TestSamplerAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family Family
		peer   string
	}{
		{"ipv4-flow-ipv6-peer", FamilyIPv4, "2001:db8::fe"},
		{"ipv6-flow-ipv4-peer", FamilyIPv6, "192.0.2.254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := IPValue(netip.MustParseAddr(tc.peer))
			record, err := NewRecord(tc.family, []FieldValue{{Field: FieldFlowSamplerAddress, Value: value}})
			if err != nil {
				t.Fatal(err)
			}
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
			got, ok := record.Lookup(FieldFlowSamplerAddress)
			if !ok || got.IP().String() != tc.peer || record.Family() != tc.family {
				t.Fatal("sampler changed value or flow family")
			}
			for _, field := range []CanonicalField{FieldSourceAddress, FieldDestinationAddress} {
				if _, err := NewRecord(tc.family, []FieldValue{{Field: field, Value: value}}); err == nil {
					t.Fatalf("mismatched flow address %v accepted", field)
				}
				forged := record
				forged.values[0].Field = field
				if forged.Validate() == nil {
					t.Fatalf("Validate accepted mismatched flow address %v", field)
				}
			}
			for _, field := range []CanonicalField{FieldFlowNextHop, FieldFlowBGPNextHop} {
				hop, err := NewRecord(tc.family, []FieldValue{{Field: field, Value: value}})
				if err != nil {
					t.Fatalf("independent next-hop address %v rejected: %v", field, err)
				}
				if err := hop.Validate(); err != nil {
					t.Fatalf("Validate rejected independent next-hop address %v: %v", field, err)
				}
			}
			if _, err := NewWireRecord(tc.family, []Value{value}); err == nil {
				t.Fatal("positional wire record lost its family check")
			}
		})
	}
	for _, value := range []Value{{}, {kind: ValueIP}, IPValue(netip.MustParseAddr("fe80::1%eth0"))} {
		if _, err := NewRecord(FamilyIPv4, []FieldValue{{Field: FieldFlowSamplerAddress, Value: value}}); err == nil {
			t.Fatal("invalid sampler value accepted")
		}
	}
}
