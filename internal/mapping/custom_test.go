package mapping

import (
	"errors"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func testCustomRuntime(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.MaxDatagramSize, config.PathMTU, config.Endpoint = 4200, 4228, "192.0.2.1:4739"
	config.Custom = []CustomField{{Source: "vendor.label", PEN: uint32ptr(32473), ElementID: uint32ptr(100), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(65535)}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(123)}})
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	bound, err := compiled.Map(record, func(source string) (wire.Value, bool) {
		calls++
		if source != "vendor.label" {
			t.Fatal("unexpected lookup source")
		}
		return wire.StringValue("hello"), true
	})
	if err != nil || bound.Len() != 2 || calls != 1 {
		t.Fatalf("map=(%+v,%v), calls=%d", bound, err, calls)
	}
	if value, _ := bound.ValueAt(1); value.Text() != "hello" {
		t.Fatalf("custom value=%q", value.Text())
	}
	_, err = compiled.Map(record, nil)
	if err == nil {
		t.Fatal("missing custom lookup accepted")
	}
	_, err = compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(string(make([]byte, 4096))), true })
	if err != nil {
		t.Fatalf("maximum variable value rejected: %v", err)
	}
	if _, err = compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(string(make([]byte, 4097))), true }); err != nil {
		t.Fatalf("value above the retired 4096-byte default rejected: %v", err)
	}
	var runtimeErr *RuntimeError
	// The packet/path budget is the active bound once descriptor max_length
	// permits a larger value: this exact fit and +1 pair exercises the actual
	// IPFIX header, set prefix, value prefix, and source-port sibling.
	if _, err = compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(strings.Repeat("z", 4175)), true }); err != nil {
		t.Fatalf("record at datagram budget rejected: %v", err)
	}
	_, err = compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(strings.Repeat("z", 4176)), true })
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != RuntimeBudgetExceeded {
		t.Fatalf("record above datagram budget reason=%v err=%v", runtimeErr, err)
	}
	_, err = compiled.Map(record, func(string) (wire.Value, bool) { panic("bridge failure") })
	runtimeErr = nil
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != RuntimeCallbackInvalid {
		t.Fatalf("callback panic reason=%v err=%v", runtimeErr, err)
	}
}

func testCustomAddressRuntime(t *testing.T) {
	config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}})
	config.Custom = []CustomField{{Source: "vendor.ip", FieldType: uint32ptr(40000), Encoding: "ipv4_address", FixedLength: uint16ptr(4), AllowPrivate: boolptr(true)}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
	bound, err := compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue("192.0.2.7"), true })
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := bound.ValueAt(1); value.Kind() != wire.ValueIP || value.IP().String() != "192.0.2.7" {
		t.Fatalf("custom address=%v", value)
	}
}

func testCustomGrammarAndBoundaries(t *testing.T) {
	base := func(entry CustomField) Config {
		config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
		config.Custom = []CustomField{entry}
		return config
	}
	for _, tc := range []struct {
		name   string
		entry  CustomField
		value  wire.Value
		family wire.Family
	}{
		{"unsigned8", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "unsigned8", FixedLength: uint16ptr(1)}, wire.UintValue(255), wire.FamilyIPv4},
		{"unsigned16", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "unsigned16", FixedLength: uint16ptr(2)}, wire.UintValue(65535), wire.FamilyIPv4},
		{"unsigned32", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "unsigned32", FixedLength: uint16ptr(4)}, wire.UintValue(4294967295), wire.FamilyIPv4},
		{"unsigned64", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "unsigned64", FixedLength: uint16ptr(8)}, wire.UintValue(^uint64(0)), wire.FamilyIPv4},
		{"signed8", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "signed8", FixedLength: uint16ptr(1)}, wire.IntValue(-128), wire.FamilyIPv4},
		{"signed16", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "signed16", FixedLength: uint16ptr(2)}, wire.IntValue(-32768), wire.FamilyIPv4},
		{"signed32", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "signed32", FixedLength: uint16ptr(4)}, wire.IntValue(-2147483648), wire.FamilyIPv4},
		{"signed64", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "signed64", FixedLength: uint16ptr(8)}, wire.IntValue(-9223372036854775808), wire.FamilyIPv4},
		{"ipv4", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "ipv4_address", FixedLength: uint16ptr(4)}, wire.StringValue("192.0.2.9"), wire.FamilyIPv4},
		{"ipv6", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "ipv6_address", FixedLength: uint16ptr(16)}, wire.StringValue("2001:db8::9"), wire.FamilyIPv6},
		{"mac", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "mac_address", FixedLength: uint16ptr(6)}, wire.StringValue("00:11:22:33:44:55"), wire.FamilyIPv4},
		{"octets", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "octet_array", FixedLength: uint16ptr(3)}, wire.BytesValue([]byte{1, 2, 3}), wire.FamilyIPv4},
		{"string", CustomField{Source: "vendor.x", PEN: uint32ptr(1), ElementID: uint32ptr(1), Encoding: "string", FixedLength: uint16ptr(3)}, wire.StringValue("abc"), wire.FamilyIPv4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := Compile(base(tc.entry))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			record, err := wire.NewRecord(tc.family, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := compiled.Map(record, func(string) (wire.Value, bool) { return tc.value, true })
			if err != nil || mapped.Len() != 2 {
				t.Fatalf("map len=%d err=%v", mapped.Len(), err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		want wire.Value
		bad  wire.Value
	}{
		{"unsigned8", wire.UintValue(255), wire.UintValue(256)},
		{"unsigned16", wire.UintValue(65535), wire.UintValue(65536)},
		{"unsigned32", wire.UintValue(4294967295), wire.UintValue(4294967296)},
		{"signed8", wire.IntValue(127), wire.IntValue(128)},
		{"signed16", wire.IntValue(32767), wire.IntValue(32768)},
		{"signed32", wire.IntValue(2147483647), wire.IntValue(2147483648)},
	} {
		entry := CustomField{Source: "vendor.n", PEN: uint32ptr(2), ElementID: uint32ptr(2), Encoding: tc.name, FixedLength: uint16ptr(1)}
		switch tc.name {
		case "unsigned16", "signed16":
			entry.FixedLength = uint16ptr(2)
		case "unsigned32", "signed32":
			entry.FixedLength = uint16ptr(4)
		}
		compiled, err := Compile(base(entry))
		if err != nil {
			t.Fatalf("%s compile: %v", tc.name, err)
		}
		record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
		if _, err = compiled.Map(record, func(string) (wire.Value, bool) { return tc.want, true }); err != nil {
			t.Fatalf("%s maximum rejected: %v", tc.name, err)
		}
		if _, err = compiled.Map(record, func(string) (wire.Value, bool) { return tc.bad, true }); err == nil {
			t.Fatalf("%s overflow accepted", tc.name)
		}
	}

	variable := base(CustomField{Source: "vendor.v", PEN: uint32ptr(3), ElementID: uint32ptr(3), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(4096)})
	variable.MaxDatagramSize, variable.PathMTU, variable.Endpoint = 8400, 8428, "192.0.2.1:4739"
	compiled, err := Compile(variable)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
	for _, length := range []int{0, 1, 253, 254, 255, 4096} {
		payload := strings.Repeat("x", length)
		if _, err := compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(payload), true }); err != nil {
			t.Fatalf("variable length %d rejected: %v", length, err)
		}
	}
	for _, length := range []int{65535, 65536} {
		payload := strings.Repeat("x", length)
		if _, err := compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(payload), true }); err == nil {
			t.Fatalf("variable length %d accepted", length)
		}
	}

	var repeated Config = explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	repeated.MaxDatagramSize, repeated.PathMTU, repeated.Endpoint = 8400, 8428, "192.0.2.1:4739"
	repeated.Custom = []CustomField{
		{Source: "vendor.same", PEN: uint32ptr(4), ElementID: uint32ptr(4), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(4096)},
		{Source: "vendor.same", PEN: uint32ptr(5), ElementID: uint32ptr(5), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(4096)},
	}
	compiled, err = Compile(repeated)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, err = compiled.Map(record, func(string) (wire.Value, bool) { calls++; return wire.StringValue(strings.Repeat("y", 4096)), true }); err != nil || calls != 2 {
		t.Fatalf("repeated source map err=%v calls=%d", err, calls)
	}
}

func testCustomPresenceAndIsolation(t *testing.T) {
	const fixed = `{"protocol":3,"fields":[{"canonical":"source.port"}],"loss_policy":"encode_and_count","custom":[{"source":"vendor.x","pen":1,"element_id":1,"encoding":"unsigned32","fixed_length":4}]}`
	for _, tc := range []struct {
		name string
		body string
	}{
		{"variable-false", strings.Replace(fixed, `"fixed_length":4`, `"fixed_length":4,"variable":false`, 1)},
		{"both-lengths", strings.Replace(fixed, `"fixed_length":4`, `"fixed_length":4,"variable":true,"max_length":1`, 1)},
		{"neither-length", strings.Replace(fixed, `,"fixed_length":4`, "", 1)},
		{"max-without-variable", strings.Replace(fixed, `"fixed_length":4`, `"fixed_length":4,"max_length":1`, 1)},
		{"zero-pen", strings.Replace(fixed, `"pen":1`, `"pen":0`, 1)},
		{"zero-element", strings.Replace(fixed, `"element_id":1`, `"element_id":0`, 1)},
		{"forbidden-field-type", strings.Replace(fixed, `"encoding":"unsigned32"`, `"field_type":0,"encoding":"unsigned32"`, 1)},
		{"forbidden-private-opt-in", strings.Replace(fixed, `"encoding":"unsigned32"`, `"allow_private":false,"encoding":"unsigned32"`, 1)},
		{"string-4097", strings.Replace(fixed, `"encoding":"unsigned32","fixed_length":4`, `"encoding":"string","fixed_length":4097`, 1)},
		{"unknown-custom-member", strings.Replace(fixed, `"fixed_length":4`, `"fixed_length":4,"unexpected":1`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := DecodeJSON([]byte(tc.body))
			if err != nil && tc.name == "unknown-custom-member" {
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, err = Compile(config); err == nil {
				t.Fatal("invalid custom presence accepted")
			}
		})
	}

	config, err := DecodeJSON([]byte(fixed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Compile(config); err != nil {
		t.Fatalf("valid fixed presence rejected: %v", err)
	}
	variableJSON := strings.Replace(strings.Replace(fixed, `"encoding":"unsigned32"`, `"encoding":"string"`, 1), `"fixed_length":4`, `"variable":true,"max_length":4096`, 1)
	config, err = DecodeJSON([]byte(variableJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Compile(config); err != nil {
		t.Fatalf("valid variable presence rejected: %v", err)
	}
	directFixed := CustomField{Source: "vendor.direct", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned32", FixedLength: uint16ptr(4)}
	for _, tc := range []struct {
		name   string
		mutate func(*CustomField)
	}{
		{"explicit-variable-false", func(entry *CustomField) { entry.Variable = boolptr(false) }},
		{"zero-pen", func(entry *CustomField) { entry.PEN = uint32ptr(0) }},
		{"zero-element", func(entry *CustomField) { entry.ElementID = uint32ptr(0) }},
		{"forbidden-field-type", func(entry *CustomField) { entry.FieldType = uint32ptr(0) }},
		{"forbidden-allow-private", func(entry *CustomField) { entry.AllowPrivate = boolptr(false) }},
		{"zero-fixed-length", func(entry *CustomField) { entry.FixedLength = uint16ptr(0) }},
		{"neither-length", func(entry *CustomField) { entry.FixedLength = nil }},
		{"both-lengths", func(entry *CustomField) {
			entry.Variable = boolptr(true)
			entry.MaxLength = uint32ptr(4)
			entry.FixedLength = uint16ptr(4)
		}},
	} {
		t.Run("direct-"+tc.name, func(t *testing.T) {
			entry := directFixed
			tc.mutate(&entry)
			if _, err := Compile(baseConfigWithCustom(entry)); err == nil {
				t.Fatal("invalid direct custom presence accepted")
			}
		})
	}

	config = explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.Custom = []CustomField{{Source: "vendor.bytes", PEN: uint32ptr(6), ElementID: uint32ptr(6), Encoding: "octet_array", Variable: boolptr(true), MaxLength: uint32ptr(4)}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
	bytes := []byte{1, 2}
	mapped, err := compiled.Map(record, func(string) (wire.Value, bool) { return wire.BytesValue(bytes), true })
	if err != nil {
		t.Fatal(err)
	}
	bytes[0] = 9
	value, _ := mapped.ValueAt(1)
	if value.Octets() != string([]byte{1, 2}) {
		t.Fatalf("custom octets were not isolated: %v", []byte(value.Octets()))
	}
	stringConfig := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	stringConfig.Custom = []CustomField{{Source: "vendor.string", PEN: uint32ptr(7), ElementID: uint32ptr(7), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(32)}}
	stringConfig.MaxDatagramSize, stringConfig.PathMTU, stringConfig.Endpoint = 4200, 4228, "192.0.2.1:4739"
	stringMapping, err := Compile(stringConfig)
	if err != nil {
		t.Fatal(err)
	}
	accepted := []byte("accepted")
	stringRecord, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(7)}})
	stringBound, err := stringMapping.Map(stringRecord, func(string) (wire.Value, bool) { return wire.StringValue(string(accepted)), true })
	if err != nil {
		t.Fatal(err)
	}
	accepted[0] = 'X'
	stringValue, _ := stringBound.ValueAt(1)
	if stringValue.Text() != "accepted" {
		t.Fatalf("custom string was not isolated: %q", stringValue.Text())
	}
	_, err = compiled.Map(record, func(string) (wire.Value, bool) { return wire.StringValue(string([]byte{0xff})), true })
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != RuntimeCustomInvalid {
		t.Fatalf("invalid UTF-8 reason=%v err=%v", runtimeErr, err)
	}
}

func baseConfigWithCustom(entry CustomField) Config {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.Custom = []CustomField{entry}
	return config
}
