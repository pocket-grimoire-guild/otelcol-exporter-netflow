package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const maxCompileFuzzJSONBytes = 8192

type compileMappingFuzzExpectation struct {
	known      bool
	wantValid  bool
	protocol   wire.Protocol
	shapeCount int
	idBase     uint16
	canary     string
}

type compileMappingFuzzCase struct {
	config Config
	json   []byte
	want   compileMappingFuzzExpectation
}

// FuzzCompileMapping exercises both the strict JSON boundary and a small,
// test-owned configuration grammar. The grammar lane keeps its cases finite
// and reviewed, while the JSON lane still sends arbitrary bounded bytes
// through DecodeJSON. Compile must either return a complete immutable catalog
// or a zero value with a fixed, redacted diagnostic.
func FuzzCompileMapping(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, selector, boundary uint8, number uint64) {
		if len(data) > maxCompileFuzzJSONBytes {
			t.Skip()
		}
		if selector&1 == 0 {
			checkCompileMappingJSON(t, data)
			return
		}
		checkCompileMappingCase(t, compileMappingFuzzCaseFor(selector>>1, boundary, number, data))
	})
}

func TestCompileMappingFuzzGrammar(t *testing.T) {
	for caseID := uint8(0); caseID < 39; caseID++ {
		for boundary := uint8(0); boundary < 3; boundary++ {
			t.Run(strings.Join([]string{"case", strconv.Itoa(int(caseID)), strconv.Itoa(int(boundary))}, "-"), func(t *testing.T) {
				checkCompileMappingCase(t, compileMappingFuzzCaseFor(caseID, boundary, 4096, []byte("grammar-seed")))
			})
		}
	}
}

func checkCompileMappingJSON(t *testing.T, data []byte) {
	t.Helper()
	before := append([]byte(nil), data...)
	config, err := DecodeJSON(data)
	if !bytes.Equal(data, before) {
		t.Fatal("DecodeJSON mutated caller bytes")
	}
	if err != nil {
		want := &compileMappingFuzzExpectation{}
		if bytes.Contains(data, []byte("json-canary")) {
			want.canary = "json-canary"
		}
		assertCompileMappingError(t, err, want)
		_, errAgain := DecodeJSON(data)
		if errAgain == nil || err.Error() != errAgain.Error() {
			t.Fatalf("non-deterministic DecodeJSON error: %v / %v", err, errAgain)
		}
		return
	}
	checkCompileMappingResult(t, config, compileMappingFuzzExpectation{})
}

func checkCompileMappingCase(t *testing.T, tc compileMappingFuzzCase) {
	t.Helper()
	before, err := json.Marshal(tc.config)
	if err != nil {
		t.Fatalf("snapshot config: %v", err)
	}
	checkCompileMappingResult(t, tc.config, tc.want)
	after, err := json.Marshal(tc.config)
	if err != nil {
		t.Fatalf("snapshot config after compile: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Compile mutated caller config")
	}

	data := tc.json
	if data == nil {
		data, err = json.Marshal(tc.config)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
	}
	beforeJSON := append([]byte(nil), data...)
	decoded, err := DecodeJSON(data)
	if err != nil {
		t.Fatalf("DecodeJSON generated invalid grammar case: %v", err)
	}
	if !bytes.Equal(data, beforeJSON) {
		t.Fatal("DecodeJSON mutated generated input bytes")
	}
	checkCompileMappingResult(t, decoded, tc.want)
}

func checkCompileMappingResult(t *testing.T, config Config, want compileMappingFuzzExpectation) {
	t.Helper()
	compiled, err := Compile(config)
	valid := err == nil
	if want.protocol != wire.ProtocolUnknown && compiled.Protocol() != wire.ProtocolUnknown && compiled.Protocol() != want.protocol {
		t.Fatalf("protocol=%v want %v", compiled.Protocol(), want.protocol)
	}
	if want.known && valid != want.wantValid {
		t.Fatalf("Compile valid=%v want %v: %v", valid, want.wantValid, err)
	}
	if err != nil {
		assertCompileMappingError(t, err, &want)
		assertZeroCompiledMapping(t, compiled)
		second, secondErr := Compile(config)
		if secondErr == nil || secondErr.Error() != err.Error() {
			t.Fatalf("non-deterministic Compile error: %v / %v", err, secondErr)
		}
		assertZeroCompiledMapping(t, second)
		return
	}
	if compiled.Catalog().Validate() != nil {
		t.Fatalf("compiled catalog failed validation: %v", compiled.Catalog().Validate())
	}
	if want.shapeCount > 0 && compiled.ShapeCount() != want.shapeCount {
		t.Fatalf("shape count=%d want %d", compiled.ShapeCount(), want.shapeCount)
	}
	if want.idBase != 0 {
		shape, ok := compiled.Catalog().ShapeAt(0)
		if !ok || shape.ID() != want.idBase {
			t.Fatalf("first shape ID=%d/%v want %d", shape.ID(), ok, want.idBase)
		}
	}
	for index := 0; index < compiled.ShapeCount(); index++ {
		shape, ok := compiled.Catalog().ShapeAt(index)
		if !ok || shape.FieldCount() == 0 || shape.FieldCount() > wire.DefaultMaxFieldsPerShape {
			t.Fatalf("invalid shape %d: %+v/%v", index, shape, ok)
		}
		if shape.Protocol() != compiled.Protocol() || shape.TemplateBytes() > wire.DefaultMaxTemplateBytes || shape.RecordLength() > wire.DefaultMaxRecordBytes {
			t.Fatalf("shape %d exceeded catalog bounds: %+v", index, shape)
		}
		if compiled.Protocol() == wire.ProtocolV5 && shape.TemplateBytes() != 0 {
			t.Fatal("v5 shape has template bytes")
		}
		if compiled.Protocol() != wire.ProtocolV5 && shape.TemplateBytes() == 0 {
			t.Fatal("template protocol shape has no template bytes")
		}
	}
	repeat, repeatErr := Compile(config)
	if repeatErr != nil || compiled.Fingerprint() == "" || repeat.Fingerprint() != compiled.Fingerprint() || !reflect.DeepEqual(compiled.Catalog().Shapes(), repeat.Catalog().Shapes()) {
		t.Fatalf("catalog is not deterministic: %q/%q err=%v", compiled.Fingerprint(), repeat.Fingerprint(), repeatErr)
	}
	// Shape and descriptor accessors promise independent copies. Mutating the
	// first copy must leave the compiled catalog and its fingerprint unchanged.
	shape, ok := compiled.Catalog().ShapeAt(0)
	if ok {
		fields := shape.Fields()
		fields[0].ID++
		again, _ := compiled.Catalog().ShapeAt(0)
		if again.Fields()[0].ID == fields[0].ID {
			t.Fatal("catalog accessor exposed mutable descriptor storage")
		}
	}
}

func assertZeroCompiledMapping(t *testing.T, compiled CompiledMapping) {
	t.Helper()
	if !reflect.DeepEqual(compiled, CompiledMapping{}) {
		t.Fatalf("rejected Compile returned partial output: %+v", compiled)
	}
}

func assertCompileMappingError(t *testing.T, err error, want *compileMappingFuzzExpectation) {
	t.Helper()
	if err == nil || len(err.Error()) > 256 || !errors.Is(err, ErrCompile) || Reason(err) != "mapping: configuration rejected" {
		t.Fatalf("unexpected compiler diagnostic: %v", err)
	}
	if want != nil && want.canary != "" && strings.Contains(err.Error(), want.canary) {
		t.Fatalf("compiler diagnostic disclosed canary: %v", err)
	}
}

func compileMappingFuzzCaseFor(selector, boundary uint8, number uint64, data []byte) compileMappingFuzzCase {
	protocol := wire.ProtocolIPFIX
	if boundary&1 != 0 {
		protocol = wire.ProtocolV9
	}
	c := compileMappingFuzzCase{want: compileMappingFuzzExpectation{known: true, protocol: protocol}, config: Config{Protocol: protocol, LossPolicy: LossPolicyEncodeAndCount, Endpoint: string(data)}}
	expectValid := func(shapeCount int) {
		c.want.wantValid, c.want.shapeCount = true, shapeCount
	}
	expectInvalid := func() { c.want.wantValid = false }
	forceIPFIX := func() {
		c.config.Protocol = wire.ProtocolIPFIX
		c.want.protocol = wire.ProtocolIPFIX
	}

	switch selector % 39 {
	case 0: // Each built-in profile is valid with its explicit prerequisites.
		p := boundary % 3
		c.config = profileFuzzConfig(p)
		c.config.Endpoint = string(data)
		c.want.protocol = c.config.Protocol
		expectValid(map[bool]int{true: 1, false: 2}[c.config.Protocol == wire.ProtocolV5])
	case 1: // Exact explicit selectors exercise both template protocols.
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectValid(1)
	case 2: // Ambiguous counters require their documented target.
		if protocol == wire.ProtocolV9 {
			c.config.Fields = []FieldSelection{{Canonical: "source.port"}, {Canonical: "flow.io.bytes", Target: "in_bytes"}}
		} else {
			c.config.Fields = []FieldSelection{{Canonical: "source.port"}, {Canonical: "flow.io.bytes", Target: "octet_delta_count"}}
		}
		expectValid(1)
	case 3: // Profile and explicit selectors are mutually exclusive.
		c.config = profileFuzzConfig(1)
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 4: // Explicit empty presence is distinct from an omitted selector.
		c.config.Protocol, c.config.Fields, c.config.FieldsSet = wire.ProtocolIPFIX, []FieldSelection{}, true
		c.json = []byte(`{"protocol":3,"fields":[],"loss_policy":"encode_and_count"}`)
		expectInvalid()
	case 5: // Neither selector is invalid.
		c.config.Protocol = wire.ProtocolIPFIX
		c.config.Fields = nil
		expectInvalid()
	case 6:
		c.config.Profile = "contrib-netflowreceiver-v0.160.0/unknown-v1"
		expectInvalid()
	case 7:
		c.config.Protocol = wire.Protocol(4)
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 8:
		c.config.LossPolicy = LossPolicy("unknown")
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 9:
		c.config.Fields = []FieldSelection{{Canonical: "flow.io.bytes", Target: "bad-target"}}
		expectInvalid()
	case 10:
		c.config.Fields = []FieldSelection{{Canonical: "flow.src_vlan"}, {Canonical: "flow.vlan_id"}}
		expectInvalid()
	case 11:
		c.config.Fields = []FieldSelection{{Canonical: "network.transport"}, {Canonical: "network.type"}}
		if protocol == wire.ProtocolIPFIX {
			c.config.Fields[1].Target = "ip_version"
		}
		c.config.ProtocolIdentifiers, c.config.NetworkTypeVersions = tokenMap(), versionMap()
		expectValid(1)
	case 12:
		c.config.Fields = []FieldSelection{{Canonical: "network.transport"}}
		c.config.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "tcp", Number: 7}}
		expectInvalid()
	case 13:
		c.config.Fields = []FieldSelection{{Canonical: "network.transport"}}
		c.config.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "tcp", Number: 6}, {Token: "tcp", Number: 6}}
		expectInvalid()
	case 14:
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		c.config.ProtocolIdentifiers = tokenMap()
		expectInvalid()
	case 15:
		c.config.Protocol = wire.ProtocolV9
		c.want.protocol = wire.ProtocolV9
		c.config.Fields = []FieldSelection{{Canonical: "flow.icmp_type_code"}}
		c.config.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "icmp", Number: 1}}
		expectValid(1)
	case 16:
		forceIPFIX()
		c.config.Custom = []CustomField{{Source: "vendor.fixed", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned32", FixedLength: uint16ptr(4)}}
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectValid(1)
	case 17:
		forceIPFIX()
		c.config.Custom = []CustomField{{Source: "vendor.variable", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(uint32(1 + number%4096))}}
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectValid(1)
	case 18, 19: // Both pointer-presence forms must reject without panicking.
		forceIPFIX()
		variable := selector%39 == 18
		c.config.Custom = []CustomField{{Source: "vendor.presence", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "string", Variable: boolptr(variable)}}
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 20:
		forceIPFIX()
		c.config.Custom = []CustomField{{Source: "vendor.both", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "string", FixedLength: uint16ptr(4), Variable: boolptr(true), MaxLength: uint32ptr(4)}}
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 21:
		c.config.Protocol = wire.ProtocolV9
		c.want.protocol = wire.ProtocolV9
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		c.config.Custom = []CustomField{{Source: "vendor.private", FieldType: uint32ptr(300), Encoding: "unsigned8", FixedLength: uint16ptr(1), AllowPrivate: boolptr(true)}}
		expectValid(1)
	case 22:
		c.config = profileFuzzConfig(0)
		c.config.Custom = []CustomField{{Source: "vendor.v5", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned8", FixedLength: uint16ptr(1)}}
		expectInvalid()
	case 23:
		forceIPFIX()
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		c.config.Custom = []CustomField{{Source: "vendor.secret-canary", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned32", FixedLength: uint16ptr(3)}}
		c.want.canary = "vendor.secret-canary"
		expectInvalid()
	case 24:
		c.config.Fields, c.config.IDBase = []FieldSelection{{Canonical: "source.port"}}, 255
		expectInvalid()
	case 25:
		c.config.Fields, c.config.IDBase = []FieldSelection{{Canonical: "source.address"}}, 65535
		expectInvalid()
	case 26:
		c.config.Fields, c.config.IDBase = []FieldSelection{{Canonical: "source.port"}}, 65535
		c.want.idBase = 65535
		expectValid(1)
	case 27:
		c.config.Fields, c.config.MaxDatagramSize = []FieldSelection{{Canonical: "source.port"}}, 465
		expectInvalid()
	case 28:
		c.config.Fields, c.config.PathMTU, c.config.Endpoint = []FieldSelection{{Canonical: "source.port"}}, 511, "192.0.2.1:4739"
		expectInvalid()
	case 29:
		c.config.Fields, c.config.Limits.MaxFieldsPerShape = []FieldSelection{{Canonical: "source.port"}}, 65
		expectInvalid()
	case 30:
		c.config.Fields, c.config.Limits.MaxFieldsPerShape = []FieldSelection{{Canonical: "source.port"}}, 1
		expectValid(1)
	case 31:
		c.config.Fields, c.config.Limits.MaxRecordBytes = []FieldSelection{{Canonical: "source.port"}}, 1
		expectInvalid()
	case 32:
		c.config.Fields, c.config.Limits.MaxTemplateBytes = []FieldSelection{{Canonical: "source.port"}}, 11
		expectInvalid()
	case 33:
		forceIPFIX()
		c.config.Fields, c.config.Limits.MaxCustomMappings = []FieldSelection{{Canonical: "source.port"}}, 1
		c.config.Custom = []CustomField{
			{Source: "vendor.one", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned8", FixedLength: uint16ptr(1)},
			{Source: "vendor.two", PEN: uint32ptr(12), ElementID: uint32ptr(12), Encoding: "unsigned8", FixedLength: uint16ptr(1)},
		}
		expectInvalid()
	case 34:
		forceIPFIX()
		c.config.Fields, c.config.Limits.MaxPENs = []FieldSelection{{Canonical: "source.port"}}, 1
		c.config.Custom = []CustomField{
			{Source: "vendor.one", PEN: uint32ptr(11), ElementID: uint32ptr(11), Encoding: "unsigned8", FixedLength: uint16ptr(1)},
			{Source: "vendor.two", PEN: uint32ptr(12), ElementID: uint32ptr(12), Encoding: "unsigned8", FixedLength: uint16ptr(1)},
		}
		expectInvalid()
	case 35:
		c.config.Fields, c.config.MaxMappedValueBytes = []FieldSelection{{Canonical: "source.port"}}, 65536
		expectInvalid()
	case 36:
		c.config.Fields, c.config.MaxAttributeKeyBytes = []FieldSelection{{Canonical: "source.port"}}, 1025
		expectInvalid()
	case 37:
		c.config.Schema = "unrecognized-schema"
		c.config.Fields = []FieldSelection{{Canonical: "source.port"}}
		expectInvalid()
	case 38:
		c.config.Protocol = wire.ProtocolV5
		c.config.Profile = ProfileV5
		c.config.Fields = nil
		c.config.InputGuarantees = InputGuarantees{FlowIOBytes: "layer3_total_octets"}
		c.config.HasUptimeOrigin = true
		c.config.ProtocolIdentifiers = tokenMap()
		c.config.Custom = nil
		c.config.LossPolicy = LossPolicyEncodeAndCount
		c.want.protocol = wire.ProtocolV5
		expectValid(1)
	}
	return c
}

func profileFuzzConfig(protocol uint8) Config {
	config := Config{LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}}}
	switch protocol % 3 {
	case 0:
		config.Protocol, config.Profile = wire.ProtocolV5, ProfileV5
		config.InputGuarantees = InputGuarantees{FlowIOBytes: "layer3_total_octets"}
		config.HasUptimeOrigin = true
	case 1:
		config.Protocol, config.Profile = wire.ProtocolV9, ProfileV9
		config.NetworkTypeVersions = versionMap()
	case 2:
		config.Protocol, config.Profile = wire.ProtocolIPFIX, ProfileIPFIX
		config.NetworkTypeVersions = versionMap()
	}
	return config
}
