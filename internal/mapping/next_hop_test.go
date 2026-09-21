package mapping

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestNextHopMapping104Cases(t *testing.T) {
	var total, normalized, mappingSuccess, missing, selectedCross, malformed int
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
			for _, hop := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
				for _, selection := range []struct {
					name   string
					fields []FieldSelection
					pick   bool
				}{{"tuple-only", nextHopTupleSelections(), false}, {"source-port-only", []FieldSelection{{Canonical: "source.port"}}, false}, {"tuple-plus-hop", append(nextHopTupleSelections(), FieldSelection{Canonical: hop}), true}} {
					for _, state := range []struct {
						name string
						text string
					}{
						{"omitted", ""},
						{"same", nextHopAddress(family, true)},
						{"cross", nextHopAddress(family, false)},
						{"malformed", "invalid IP"},
					} {
						name := protocol.String() + "/" + family.String() + "/" + hop + "/" + selection.name + "/" + state.name
						t.Run(name, func(t *testing.T) {
							total++
							logs := nextHopMappingLogs(family, hop, state.text)
							compiled, err := Compile(explicitConfig(protocol, selection.fields))
							if err != nil {
								t.Fatalf("compile: %v", err)
							}
							var record wire.NormalizedRecord
							normalizeErr := normalize.NormalizeEach(logs, func(got wire.NormalizedRecord) error { record = got; return nil })
							if state.name == "malformed" {
								if normalizeErr == nil || record.Len() != 0 {
									t.Fatalf("malformed normalization=(%d,%v), want zero/error", record.Len(), normalizeErr)
								}
								malformed++
								return
							}
							if normalizeErr != nil {
								t.Fatalf("normalize: %v", normalizeErr)
							}
							normalized++
							mapped, mapErr := compiled.Map(record, nil)
							if selection.pick && state.name == "omitted" {
								assertNextHopRuntime(t, mapErr, RuntimeMissingField, 5)
								missing++
								return
							}
							if selection.pick && state.name == "cross" {
								assertNextHopRuntime(t, mapErr, RuntimeValueInvalid, 5)
								selectedCross++
								return
							}
							if mapErr != nil {
								t.Fatalf("map: %v", mapErr)
							}
							if mapped.Len() != len(selection.fields) {
								t.Fatalf("mapped length=%d, want %d", mapped.Len(), len(selection.fields))
							}
							mappingSuccess++
							if !selection.pick && (state.name == "same" || state.name == "cross") {
								baseline := nextHopMustNormalize(t, nextHopMappingLogs(family, hop, ""))
								baselineMapped, baselineErr := compiled.Map(baseline, nil)
								if baselineErr != nil {
									t.Fatalf("omitted baseline map: %v", baselineErr)
								}
								assertNextHopMappedEquivalent(t, mapped, baselineMapped, protocol.String()+"/"+family.String()+"/"+hop+"/"+selection.name+"/"+state.name)
							}
						})
					}
				}
			}
		}
	}

	for _, hop := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
		for _, state := range []struct {
			name string
			text string
		}{{"omitted", ""}, {"same", "192.0.2.254"}, {"cross", "2001:db8::fe"}, {"malformed", "invalid IP"}} {
			t.Run("v5/"+hop+"/"+state.name, func(t *testing.T) {
				total++
				logs := nextHopMappingLogs(wire.FamilyIPv4, hop, state.text)
				if hop == "flow.bgp_next_hop" {
					logs = withValidV5NextHop(logs)
				}
				config := Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
				compiled, err := Compile(config)
				if err != nil {
					t.Fatalf("compile v5: %v", err)
				}
				var record wire.NormalizedRecord
				normalizeErr := normalize.NormalizeEach(logs, func(got wire.NormalizedRecord) error { record = got; return nil })
				if state.name == "malformed" {
					if normalizeErr == nil || record.Len() != 0 {
						t.Fatalf("malformed normalization=(%d,%v)", record.Len(), normalizeErr)
					}
					malformed++
					return
				}
				if normalizeErr != nil {
					t.Fatalf("normalize v5: %v", normalizeErr)
				}
				normalized++
				mapped, mapErr := compiled.Map(record, nil)
				if hop == "flow.next_hop" && state.name == "omitted" {
					assertNextHopRuntime(t, mapErr, RuntimeMissingField, 2)
					missing++
					return
				}
				if hop == "flow.next_hop" && state.name == "cross" {
					assertNextHopRuntime(t, mapErr, RuntimeValueInvalid, 2)
					selectedCross++
					return
				}
				if mapErr != nil {
					t.Fatalf("v5 map=%v, want success", mapErr)
				}
				mappingSuccess++
				if hop == "flow.bgp_next_hop" && (state.name == "same" || state.name == "cross") {
					baseline := nextHopMustNormalize(t, withValidV5NextHop(nextHopMappingLogs(wire.FamilyIPv4, hop, "")))
					baselineMapped, baselineErr := compiled.Map(baseline, nil)
					if baselineErr != nil {
						t.Fatalf("v5 omitted baseline map: %v", baselineErr)
					}
					assertNextHopMappedEquivalent(t, mapped, baselineMapped, "v5/"+hop+"/"+state.name)
				}
			})
		}
	}
	ipv6 := nextHopMappingLogs(wire.FamilyIPv6, "flow.next_hop", "2001:db8::fe")
	var v6Record wire.NormalizedRecord
	if err := normalize.NormalizeEach(ipv6, func(got wire.NormalizedRecord) error { v6Record = got; return nil }); err != nil {
		t.Fatalf("normalize v5 IPv6: %v", err)
	}
	v5, err := Compile(Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v5.Map(v6Record, nil); !errors.Is(err, ErrFamilyMismatch) {
		t.Fatalf("v5 IPv6 map=%v, want family mismatch", err)
	}
	if total != 104 || normalized != 78 || mappingSuccess != 60 || missing != 9 || selectedCross != 9 || malformed != 26 {
		t.Fatalf("totals=%d normalized=%d success=%d missing=%d selected-cross=%d malformed=%d, want 104/78/60/9/9/26", total, normalized, mappingSuccess, missing, selectedCross, malformed)
	}
}

func TestNextHopDescriptorBoundaries(t *testing.T) {
	for _, tc := range []struct {
		protocol wire.Protocol
		field    string
		family   wire.Family
		id       uint16
		length   uint16
		encoding wire.DescriptorEncoding
	}{
		{wire.ProtocolV5, "flow.next_hop", wire.FamilyIPv4, 3, 4, wire.EncodingIPv4Address},
		{wire.ProtocolV9, "flow.next_hop", wire.FamilyIPv4, 15, 4, wire.EncodingIPv4Address},
		{wire.ProtocolV9, "flow.next_hop", wire.FamilyIPv6, 62, 16, wire.EncodingIPv6Address},
		{wire.ProtocolV9, "flow.bgp_next_hop", wire.FamilyIPv4, 18, 4, wire.EncodingIPv4Address},
		{wire.ProtocolV9, "flow.bgp_next_hop", wire.FamilyIPv6, 63, 16, wire.EncodingIPv6Address},
		{wire.ProtocolIPFIX, "flow.next_hop", wire.FamilyIPv4, 15, 4, wire.EncodingIPv4Address},
		{wire.ProtocolIPFIX, "flow.next_hop", wire.FamilyIPv6, 62, 16, wire.EncodingIPv6Address},
		{wire.ProtocolIPFIX, "flow.bgp_next_hop", wire.FamilyIPv4, 18, 4, wire.EncodingIPv4Address},
		{wire.ProtocolIPFIX, "flow.bgp_next_hop", wire.FamilyIPv6, 63, 16, wire.EncodingIPv6Address},
	} {
		t.Run(tc.protocol.String()+"/"+tc.field+"/"+tc.family.String(), func(t *testing.T) {
			descriptor, err := descriptorFor(tc.protocol, nextHopCanonical(tc.field), "", tc.family)
			if err != nil || descriptor.ID != tc.id || descriptor.Length != tc.length || descriptor.Encoding != tc.encoding {
				t.Fatalf("descriptor=%+v, want id=%d length=%d encoding=%v", descriptor, tc.id, tc.length, tc.encoding)
			}
			if got, err := descriptor.ValueLength(wire.IPValue(netip.MustParseAddr(nextHopAddress(tc.family, true)))); err != nil || got != uint64(tc.length) {
				t.Fatalf("same-family ValueLength=(%d,%v), want %d,nil", got, err, tc.length)
			}
			if _, err := descriptor.ValueLength(wire.IPValue(netip.MustParseAddr(nextHopAddress(tc.family, false)))); err == nil {
				t.Fatal("opposite-family ValueLength accepted")
			}
			if _, err := descriptor.ValueLength(wire.UintValue(1)); err == nil {
				t.Fatal("non-IP ValueLength accepted")
			}
			if tc.protocol == wire.ProtocolV5 {
				return
			}
			compiled, err := Compile(explicitConfig(tc.protocol, []FieldSelection{{Canonical: tc.field}}))
			if err != nil {
				t.Fatal(err)
			}
			value := wire.IPValue(netip.MustParseAddr(nextHopAddress(tc.family, true)))
			record, err := wire.NewRecord(tc.family, []wire.FieldValue{{Field: nextHopCanonical(tc.field), Value: value}})
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := compiled.Map(record, nil)
			valueAt, valueOK := mapped.ValueAt(0)
			if err != nil || mapped.Len() != 1 || !valueOK || valueAt.Kind() != wire.ValueIP {
				t.Fatalf("same-family map=(%v,%v)", mapped, err)
			}
			cross := wire.IPValue(netip.MustParseAddr(nextHopAddress(tc.family, false)))
			crossRecord, err := wire.NewRecord(tc.family, []wire.FieldValue{{Field: nextHopCanonical(tc.field), Value: cross}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = compiled.Map(crossRecord, nil)
			assertNextHopRuntime(t, err, RuntimeValueInvalid, 0)
			bad, err := wire.NewRecord(tc.family, []wire.FieldValue{{Field: nextHopCanonical(tc.field), Value: wire.UintValue(1)}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = compiled.Map(bad, nil)
			if !errors.Is(err, ErrFamilyMismatch) {
				t.Fatalf("non-IP selected hop=%v, want family mismatch", err)
			}
		})
	}
}

func TestNextHopUnselectedTypedKindRejected(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
			for _, hop := range []wire.CanonicalField{wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop} {
				compiled, err := Compile(explicitConfig(protocol, []FieldSelection{{Canonical: "source.port"}}))
				if err != nil {
					t.Fatal(err)
				}
				source, destination := "192.0.2.1", "198.51.100.2"
				if family == wire.FamilyIPv6 {
					source, destination = "2001:db8::1", "2001:db8::2"
				}
				fields := []wire.FieldValue{
					{Field: wire.FieldSourceAddress, Value: wire.IPValue(netip.MustParseAddr(source))},
					{Field: wire.FieldDestinationAddress, Value: wire.IPValue(netip.MustParseAddr(destination))},
					{Field: wire.FieldSourcePort, Value: wire.UintValue(12345)},
					{Field: hop, Value: wire.UintValue(7)},
				}
				if hop == wire.FieldFlowNextHop {
					fields = append(fields, wire.FieldValue{Field: wire.FieldFlowBGPNextHop, Value: wire.UintValue(8)})
				} else {
					fields = append(fields, wire.FieldValue{Field: wire.FieldFlowNextHop, Value: wire.IPValue(netip.MustParseAddr(nextHopAddress(family, true)))})
				}
				record, err := wire.NewRecord(family, fields)
				if err != nil {
					t.Fatal(err)
				}
				_, err = compiled.Map(record, nil)
				assertNextHopRuntime(t, err, RuntimeFamilyMismatch, nextHopShapeOrdinal(compiled, family))
			}
		}
	}
	config := Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	v5, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{
		{Field: wire.FieldSourceAddress, Value: wire.IPValue(netip.MustParseAddr("192.0.2.1"))},
		{Field: wire.FieldDestinationAddress, Value: wire.IPValue(netip.MustParseAddr("198.51.100.2"))},
		{Field: wire.FieldFlowNextHop, Value: wire.IPValue(netip.MustParseAddr("192.0.2.254"))},
		{Field: wire.FieldFlowBGPNextHop, Value: wire.UintValue(7)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v5.Map(record, nil)
	assertNextHopRuntime(t, err, RuntimeFamilyMismatch, 0)
}

func TestNextHopJointFamilies(t *testing.T) {
	for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		logs := nextHopMappingLogs(family, "flow.next_hop", nextHopAddress(family, false))
		record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		record.Attributes().PutStr("flow.bgp_next_hop", nextHopAddress(family, true))
		normalized := nextHopMustNormalize(t, logs)
		unselected, err := Compile(explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unselected.Map(normalized, nil); err != nil {
			t.Fatalf("joint unselected %v map=%v", family, err)
		}
		selected, err := Compile(explicitConfig(wire.ProtocolIPFIX, append(nextHopTupleSelections(), FieldSelection{Canonical: "flow.next_hop"})))
		if err != nil {
			t.Fatal(err)
		}
		_, err = selected.Map(normalized, nil)
		assertNextHopRuntime(t, err, RuntimeValueInvalid, 5)
	}
	logs := nextHopMappingLogs(wire.FamilyIPv4, "flow.next_hop", "192.0.2.254")
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr("flow.bgp_next_hop", "2001:db8::fe")
	normalized := nextHopMustNormalize(t, logs)
	config := Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	v5, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v5.Map(normalized, nil); err != nil {
		t.Fatalf("joint v5 map=%v", err)
	}
}

func TestNextHopSelectedPacketBytes(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
			for _, field := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
				text := nextHopAddress(family, true)
				compiled, err := Compile(explicitConfig(protocol, []FieldSelection{{Canonical: field}}))
				if err != nil {
					t.Fatal(err)
				}
				record := nextHopMustNormalize(t, nextHopMappingLogs(family, field, text))
				mapped, err := compiled.Map(record, nil)
				if err != nil {
					t.Fatal(err)
				}
				packet := nextHopPacket(t, protocol, compiled, mapped)
				value := netip.MustParseAddr(text).AsSlice()
				shape, ok := compiled.Catalog().ShapeAt(int(nextHopShapeOrdinal(compiled, family)))
				if !ok {
					t.Fatal("missing selected packet shape")
				}
				wantID := nextHopWireID(protocol, field, family)
				wantWidth := uint16(len(value))
				wantTemplateID := uint16(256 + nextHopShapeOrdinal(compiled, family))
				if shape.ID() != wantTemplateID {
					t.Fatalf("shape template id=%d, want literal %d", shape.ID(), wantTemplateID)
				}
				if protocol == wire.ProtocolV9 {
					if binary.BigEndian.Uint16(packet[24:26]) != wantTemplateID || binary.BigEndian.Uint16(packet[26:28]) != 1 || binary.BigEndian.Uint16(packet[28:30]) != wantID || binary.BigEndian.Uint16(packet[30:32]) != wantWidth || binary.BigEndian.Uint16(packet[32:34]) != wantTemplateID {
						t.Fatalf("v9 template fields=%x, want template=%d id=%d width=%d", packet[24:34], wantTemplateID, wantID, wantWidth)
					}
					if !bytes.Equal(packet[36:36+len(value)], value) {
						t.Fatalf("v9/%s/%s address bytes=%x, want %x", family, field, packet[36:36+len(value)], value)
					}
				} else {
					if binary.BigEndian.Uint16(packet[16:18]) != 2 || binary.BigEndian.Uint16(packet[20:22]) != wantTemplateID || binary.BigEndian.Uint16(packet[22:24]) != 1 || binary.BigEndian.Uint16(packet[24:26]) != wantID || binary.BigEndian.Uint16(packet[26:28]) != wantWidth || binary.BigEndian.Uint16(packet[28:30]) != wantTemplateID {
						t.Fatalf("ipfix template fields=%x, want template=%d id=%d width=%d", packet[16:30], wantTemplateID, wantID, wantWidth)
					}
					if !bytes.Equal(packet[32:32+len(value)], value) {
						t.Fatalf("ipfix/%s/%s address bytes=%x, want %x", family, field, packet[32:32+len(value)], value)
					}
				}
			}
		}
	}
	config := Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	v5, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	shape, ok := v5.Catalog().ShapeAt(0)
	if !ok {
		t.Fatal("missing v5 selected shape")
	}
	var foundV5 bool
	for _, descriptor := range shape.Fields() {
		if descriptor.Field == wire.FieldFlowNextHop {
			foundV5 = true
			if descriptor.ID != 3 || descriptor.Length != 4 || descriptor.Encoding != wire.EncodingIPv4Address {
				t.Fatalf("v5 next-hop descriptor=%+v, want id=3 width=4 IPv4", descriptor)
			}
		}
	}
	if !foundV5 {
		t.Fatal("v5 next-hop descriptor missing")
	}
	record := nextHopMustNormalize(t, nextHopMappingLogs(wire.FamilyIPv4, "flow.next_hop", "192.0.2.254"))
	mapped, err := v5.Map(record, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet := nextHopPacket(t, wire.ProtocolV5, v5, mapped)
	if want := netip.MustParseAddr("192.0.2.254").AsSlice(); !bytes.Equal(packet[32:36], want) {
		t.Fatalf("v5 selected next-hop bytes=%x, want %x", packet[32:36], want)
	}
}

func TestNextHopUnselectedWireEquivalence(t *testing.T) {
	var crossEquivalences, validComparisons int
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
			for _, hop := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
				for _, fields := range [][]FieldSelection{nextHopTupleSelections(), {{Canonical: "source.port"}}} {
					compiled, err := Compile(explicitConfig(protocol, fields))
					if err != nil {
						t.Fatal(err)
					}
					base := nextHopMappingLogs(family, hop, "")
					baseRecord := nextHopMustNormalize(t, base)
					baseMapped, err := compiled.Map(baseRecord, nil)
					if err != nil {
						t.Fatal(err)
					}
					basePacket := nextHopPacket(t, protocol, compiled, baseMapped)
					for _, same := range []bool{true, false} {
						state := nextHopMappingLogs(family, hop, nextHopAddress(family, same))
						stateRecord := nextHopMustNormalize(t, state)
						stateMapped, err := compiled.Map(stateRecord, nil)
						if err != nil {
							t.Fatal(err)
						}
						validComparisons++
						assertNextHopMappedEquivalent(t, stateMapped, baseMapped, protocol.String()+"/"+family.String()+"/"+hop+"/same="+boolString(same))
						statePacket := nextHopPacket(t, protocol, compiled, stateMapped)
						if !bytes.Equal(basePacket, statePacket) {
							t.Fatalf("%s/%s/%s unselected packet changed for same=%v", protocol, family, hop, same)
						}
						if !same {
							crossEquivalences++
						}
					}
				}
			}
		}
	}
	// v5 always selects its IPv4 next-hop slot, while BGP next hop remains
	// unselected. Supply the valid v4 next hop so the BGP comparison is isolated.
	config := Config{Profile: ProfileV5, Protocol: wire.ProtocolV5, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), InputGuarantees: InputGuarantees{FlowIOBytes: "layer3_total_octets"}, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	base := nextHopMustNormalize(t, withValidV5NextHop(nextHopMappingLogs(wire.FamilyIPv4, "flow.bgp_next_hop", "")))
	baseMapped, err := compiled.Map(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	basePacket := nextHopPacket(t, wire.ProtocolV5, compiled, baseMapped)
	for _, same := range []bool{true, false} {
		state := withValidV5NextHop(nextHopMappingLogs(wire.FamilyIPv4, "flow.bgp_next_hop", func() string {
			if same {
				return "192.0.2.254"
			}
			return "2001:db8::fe"
		}()))
		stateRecord := nextHopMustNormalize(t, state)
		stateMapped, err := compiled.Map(stateRecord, nil)
		if err != nil {
			t.Fatal(err)
		}
		validComparisons++
		assertNextHopMappedEquivalent(t, stateMapped, baseMapped, "v5/flow.bgp_next_hop/same="+boolString(same))
		if !bytes.Equal(basePacket, nextHopPacket(t, wire.ProtocolV5, compiled, stateMapped)) {
			t.Fatalf("v5 unselected BGP packet changed for same=%v", same)
		}
		if !same {
			crossEquivalences++
		}
	}
	if validComparisons != 34 || crossEquivalences != 17 {
		t.Fatalf("unselected equivalences valid=%d cross=%d, want 34/17", validComparisons, crossEquivalences)
	}
}

func nextHopTupleSelections() []FieldSelection {
	return []FieldSelection{{Canonical: "source.address"}, {Canonical: "destination.address"}, {Canonical: "source.port"}, {Canonical: "destination.port"}, {Canonical: "network.transport"}}
}

func nextHopCanonical(name string) wire.CanonicalField {
	if name == "flow.next_hop" {
		return wire.FieldFlowNextHop
	}
	return wire.FieldFlowBGPNextHop
}

func nextHopWireID(protocol wire.Protocol, field string, family wire.Family) uint16 {
	if field == "flow.next_hop" {
		if family == wire.FamilyIPv4 {
			return 15
		}
		return 62
	}
	if family == wire.FamilyIPv4 {
		return 18
	}
	return 63
}

func nextHopAddress(family wire.Family, same bool) string {
	if family == wire.FamilyIPv4 {
		if same {
			return "192.0.2.254"
		}
		return "2001:db8::fe"
	}
	if same {
		return "2001:db8::fe"
	}
	return "192.0.2.254"
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func nextHopMappingLogs(family wire.Family, field, text string) (logs plog.Logs) {
	if family == wire.FamilyIPv6 {
		logs = testpdata.CanonicalIPv6Logs()
	} else {
		logs = testpdata.CanonicalLogs()
	}
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().Remove("flow.next_hop")
	record.Attributes().Remove("flow.bgp_next_hop")
	if text != "" {
		record.Attributes().PutStr(field, text)
	}
	return logs
}

func withValidV5NextHop(logs plog.Logs) plog.Logs {
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr("flow.next_hop", "192.0.2.254")
	return logs
}

func nextHopMustNormalize(t *testing.T, logs plog.Logs) wire.NormalizedRecord {
	t.Helper()
	var record wire.NormalizedRecord
	if err := normalize.NormalizeEach(logs, func(got wire.NormalizedRecord) error { record = got; return nil }); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return record
}

func assertNextHopRuntime(t *testing.T, err error, reason RuntimeReason, ordinal uint16) {
	t.Helper()
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != reason || runtimeErr.Ordinal != ordinal {
		t.Fatalf("runtime error=%T/%+v, want reason=%d ordinal=%d", err, runtimeErr, reason, ordinal)
	}
}

func nextHopShapeOrdinal(compiled CompiledMapping, family wire.Family) uint16 {
	if family == wire.FamilyIPv6 && compiled.ShapeCount() > 1 {
		return 1
	}
	return 0
}

func assertNextHopMappedEquivalent(t *testing.T, got, want wire.WireRecord, name string) {
	t.Helper()
	if got.Family() != want.Family() || !reflect.DeepEqual(got.Values(), want.Values()) {
		t.Fatalf("%s mapped=(family=%v,values=%v), omitted=(family=%v,values=%v)", name, got.Family(), got.Values(), want.Family(), want.Values())
	}
}

func assertUnselectedHopAbsentFromOutput(t *testing.T, mapped wire.WireRecord, compiled CompiledMapping, hop string) {
	t.Helper()
	shape, ok := compiled.Catalog().ShapeAt(0)
	if !ok {
		t.Fatal("missing shape")
	}
	for _, descriptor := range shape.Fields() {
		if descriptor.Field == nextHopCanonical(hop) {
			t.Fatalf("unselected hop %s appeared in output", hop)
		}
	}
	if mapped.Len() != shape.FieldCount() {
		t.Fatalf("mapped len=%d, shape fields=%d", mapped.Len(), shape.FieldCount())
	}
}

func nextHopPacket(t *testing.T, protocol wire.Protocol, compiled CompiledMapping, record wire.WireRecord) []byte {
	t.Helper()
	shape, ok := compiled.Catalog().ShapeAt(0)
	if record.Family() == wire.FamilyIPv6 && compiled.ShapeCount() > 1 {
		shape, ok = compiled.Catalog().ShapeAt(1)
	}
	if !ok {
		t.Fatal("missing packet shape")
	}
	data, err := shape.DataSetSize([]wire.WireRecord{record})
	if err != nil {
		t.Fatalf("data set size: %v", err)
	}
	count := uint16(1)
	if protocol == wire.ProtocolV9 {
		count = 2 // one template and one data record
	}
	if protocol == wire.ProtocolIPFIX {
		count = 0 // IPFIX has no message record count field
	}
	header := wire.HeaderMetadata{Protocol: protocol, Count: count, ExportTimeUnixNanos: 1788220803000000000, SourceID: 42, ObservationDomainID: 42, UptimeOriginUnixNanos: 1788220800000000000, HasUptimeOrigin: true}
	request := wire.PacketRequest{Header: header, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes(), DataBytes: data.Length()}
	var size int
	switch protocol {
	case wire.ProtocolV5:
		request.TemplateRecords, request.TemplateBytes = 0, 0
		header.ObservationDomainID, header.SourceID = 0, 0
		header.Protocol = protocol
		request.Header = header
		size = 24 + int(data.Length())
		if size < 72 {
			size = 72
		}
		buf := make([]byte, size)
		n, err := netflow5.Writer{}.Write(buf, request)
		if err != nil {
			t.Fatalf("v5 write: %v", err)
		}
		return buf[:n]
	case wire.ProtocolV9:
		size = 20 + int(shape.TemplateBytes()) + int(data.Length())
		buf := make([]byte, size)
		n, err := netflow9.Writer{}.Write(buf, request)
		if err != nil {
			t.Fatalf("v9 write: %v", err)
		}
		return buf[:n]
	default:
		request.Header.SourceID = 0
		size = 16 + int(shape.TemplateBytes()) + int(data.Length())
		request.Header.ObservationDomainID = 42
		buf := make([]byte, size)
		n, err := ipfix.Writer{}.Write(buf, request)
		if err != nil {
			t.Fatalf("ipfix write: %v", err)
		}
		return buf[:n]
	}
}
