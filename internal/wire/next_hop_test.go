package wire

import (
	"net/netip"
	"testing"
)

func TestNextHopCanonicalFamilies(t *testing.T) {
	cases := []struct {
		name   string
		family Family
		source string
		dest   string
		same   string
		cross  string
	}{
		{name: "ipv4", family: FamilyIPv4, source: "192.0.2.1", dest: "198.51.100.2", same: "192.0.2.254", cross: "2001:db8::fe"},
		{name: "ipv6", family: FamilyIPv6, source: "2001:db8::1", dest: "2001:db8::2", same: "2001:db8::fe", cross: "192.0.2.254"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := IPValue(netip.MustParseAddr(tc.source))
			dest := IPValue(netip.MustParseAddr(tc.dest))
			for _, field := range []CanonicalField{FieldFlowNextHop, FieldFlowBGPNextHop} {
				for _, hop := range []struct {
					name string
					text string
				}{{"same", tc.same}, {"cross", tc.cross}} {
					t.Run(field.CanonicalName()+"/"+hop.name, func(t *testing.T) {
						record, err := NewRecord(tc.family, []FieldValue{
							{Field: FieldSourceAddress, Value: source},
							{Field: FieldDestinationAddress, Value: dest},
							{Field: field, Value: IPValue(netip.MustParseAddr(hop.text))},
						})
						if err != nil {
							t.Fatalf("NewRecord() = %v", err)
						}
						if err := record.Validate(); err != nil {
							t.Fatalf("Validate() = %v", err)
						}
						value, ok := record.Lookup(field)
						if !ok || value.IP().String() != hop.text || record.Family() != tc.family {
							t.Fatalf("hop=(%v,%v) family=%v", value.IP(), ok, record.Family())
						}
					})
				}
			}
			withSampler, err := NewRecord(tc.family, []FieldValue{
				{Field: FieldSourceAddress, Value: source},
				{Field: FieldDestinationAddress, Value: dest},
				{Field: FieldFlowSamplerAddress, Value: IPValue(netip.MustParseAddr(tc.cross))},
				{Field: FieldFlowNextHop, Value: IPValue(netip.MustParseAddr(tc.cross))},
				{Field: FieldFlowBGPNextHop, Value: IPValue(netip.MustParseAddr(tc.same))},
			})
			if err != nil {
				t.Fatalf("independent sampler and hops rejected: %v", err)
			}
			if err := withSampler.Validate(); err != nil {
				t.Fatalf("independent sampler and hops Validate() = %v", err)
			}
			for _, want := range []struct {
				field CanonicalField
				text  string
			}{{FieldFlowSamplerAddress, tc.cross}, {FieldFlowNextHop, tc.cross}, {FieldFlowBGPNextHop, tc.same}} {
				got, ok := withSampler.Lookup(want.field)
				if !ok || got.Kind() != ValueIP || got.IP().String() != want.text || withSampler.Family() != tc.family {
					t.Fatalf("retained %v=(%v,%v) family=%v, want %s/%v", want.field, got.IP(), ok, withSampler.Family(), want.text, tc.family)
				}
			}
			if withSampler.Len() != 5 {
				t.Fatalf("record length=%d, want 5", withSampler.Len())
			}
			omitted, err := NewRecord(tc.family, []FieldValue{{Field: FieldSourceAddress, Value: source}, {Field: FieldDestinationAddress, Value: dest}})
			if err != nil || omitted.Len() != 2 || omitted.Family() != tc.family {
				t.Fatalf("omitted hops = (%d,%v), want 2,nil", omitted.Len(), err)
			}
			if err := omitted.Validate(); err != nil {
				t.Fatalf("omitted hops Validate() = %v", err)
			}
		})
	}
}

func TestNextHopCanonicalValidateBoundaries(t *testing.T) {
	ipv4 := IPValue(netip.MustParseAddr("192.0.2.254"))
	for _, field := range []CanonicalField{FieldFlowNextHop, FieldFlowBGPNextHop} {
		t.Run(field.CanonicalName(), func(t *testing.T) {
			base, err := NewRecord(FamilyIPv4, []FieldValue{{Field: field, Value: ipv4}})
			if err != nil {
				t.Fatal(err)
			}
			zoned := netip.MustParseAddr("fe80::1%eth0")
			for _, bad := range []Value{{}, {kind: ValueIP}, {kind: ValueIP, ip: ipv4.ip, text: "corrupt"}, {kind: ValueIP, ip: zoned}} {
				forged := base
				forged.values[0].Value = bad
				if err := forged.Validate(); err == nil {
					t.Fatalf("Validate accepted bad value %#v", bad)
				}
				if _, err := NewRecord(FamilyIPv4, []FieldValue{{Field: field, Value: bad}}); err == nil {
					t.Fatalf("NewRecord accepted bad value %#v", bad)
				}
			}
			// Canonical construction validates the generic value union. Schema-kind
			// enforcement remains at normalization and mapping boundaries.
			for _, value := range []Value{UintValue(1), StringValue("typed-hop")} {
				record, err := NewRecord(FamilyIPv4, []FieldValue{{Field: field, Value: value}})
				if err != nil {
					t.Fatalf("generic hop value rejected: %v", err)
				}
				if err := record.Validate(); err != nil {
					t.Fatalf("generic hop Validate() rejected: %v", err)
				}
			}
		})
	}
	for _, tc := range []struct {
		family Family
		other  string
	}{
		{FamilyIPv4, "2001:db8::1"},
		{FamilyIPv6, "192.0.2.1"},
	} {
		for _, field := range []CanonicalField{FieldSourceAddress, FieldDestinationAddress} {
			if _, err := NewRecord(tc.family, []FieldValue{{Field: field, Value: IPValue(netip.MustParseAddr(tc.other))}}); err == nil {
				t.Fatalf("NewRecord accepted endpoint %v in %v", field, tc.family)
			}
		}
	}
	for _, tc := range []struct {
		family Family
		value  Value
	}{
		{FamilyIPv4, IPValue(netip.MustParseAddr("2001:db8::1"))},
		{FamilyIPv6, IPValue(netip.MustParseAddr("192.0.2.1"))},
	} {
		if _, err := NewWireRecord(tc.family, []Value{tc.value}); err == nil {
			t.Fatalf("NewWireRecord accepted positional opposite-family value in %v", tc.family)
		}
	}
}
