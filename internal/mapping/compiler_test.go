package mapping

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func tokenMap() []ProtocolIdentifier {
	return []ProtocolIdentifier{{Token: "tcp", Number: 6}, {Token: "icmp", Number: 1}}
}

func versionMap() []NetworkTypeVersion {
	return []NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
}

func explicitConfig(protocol wire.Protocol, fields []FieldSelection) Config {
	config := Config{Protocol: protocol, Fields: fields, LossPolicy: LossPolicyEncodeAndCount}
	for _, field := range fields {
		if field.Canonical == "network.transport" || field.Canonical == "flow.icmp_type_code" {
			config.ProtocolIdentifiers = tokenMap()
		}
		if field.Canonical == "network.type" {
			config.NetworkTypeVersions = versionMap()
		}
	}
	return config
}

func TestCompile(t *testing.T) {
	compiled, err := Compile(explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}, {Canonical: "flow.io.bytes", Target: "octet_delta_count"}}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.ShapeCount() != 1 || compiled.Catalog().ShapeCount() != 1 {
		t.Fatalf("shape count = %d", compiled.ShapeCount())
	}
	if compiled.Fingerprint() == "" {
		t.Fatal("empty fingerprint")
	}
	testConcurrentMapper(t)
}

func TestProfile(t *testing.T) {
	for _, tc := range []struct {
		profile  string
		protocol wire.Protocol
	}{{ProfileV5, wire.ProtocolV5}, {ProfileV9, wire.ProtocolV9}, {ProfileIPFIX, wire.ProtocolIPFIX}} {
		config := Config{Profile: tc.profile, Protocol: tc.protocol, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: tokenMap(), HasUptimeOrigin: tc.protocol == wire.ProtocolV5, UptimeOriginUnixNanos: 1}
		if tc.protocol != wire.ProtocolV5 {
			config.NetworkTypeVersions = versionMap()
		}
		if tc.protocol == wire.ProtocolV5 {
			config.InputGuarantees = InputGuarantees{FlowIOBytes: "layer3_total_octets"}
		}
		compiled, err := Compile(config)
		if err != nil {
			t.Fatalf("profile %s: %v", tc.profile, err)
		}
		want := 1
		if tc.protocol != wire.ProtocolV5 {
			want = 2
		}
		if compiled.ShapeCount() != want {
			t.Fatalf("profile %s shapes=%d want %d", tc.profile, compiled.ShapeCount(), want)
		}
	}
	testProfileFingerprints(t)
	testProfileRuntime(t)
	testV5ProfileRuntime(t)
	testIPv6ProfileRuntime(t)
}

func TestCatalog(t *testing.T) {
	if len(protocolNumbers) != 146 || protocolNumbers["sdrp"] != 42 || protocolNumbers["nsh"] != 145 {
		t.Fatalf("frozen token map count=%d", len(protocolNumbers))
	}
	c1, err := Compile(explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}}))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Compile(explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}}))
	if err != nil {
		t.Fatal(err)
	}
	if c1.Fingerprint() != c2.Fingerprint() {
		t.Fatal("non-deterministic catalog fingerprint")
	}
	shape, ok := c1.Catalog().ShapeAt(0)
	if !ok || shape.FieldCount() != 1 || shape.ID() != 256 {
		t.Fatalf("shape=%+v ok=%v", shape, ok)
	}
	testCatalogFieldFamilies(t)
}

func testProfileFingerprints(t *testing.T) {
	for _, profile := range []struct {
		name     string
		protocol wire.Protocol
	}{{ProfileV5, wire.ProtocolV5}, {ProfileV9, wire.ProtocolV9}, {ProfileIPFIX, wire.ProtocolIPFIX}} {
		config := Config{Profile: profile.name, Protocol: profile.protocol, LossPolicy: LossPolicyEncodeAndCount, ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}}, HasUptimeOrigin: profile.protocol == wire.ProtocolV5, UptimeOriginUnixNanos: 1}
		if profile.protocol == wire.ProtocolV5 {
			config.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		} else {
			config.NetworkTypeVersions = versionMap()
		}
		compiled, err := Compile(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s=%s", profile.name, compiled.Fingerprint())
	}
}

func TestCustom(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.Custom = []CustomField{{Source: "vendor.label", PEN: uint32ptr(32473), ElementID: uint32ptr(100), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(4096)}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("custom compile: %v", err)
	}
	shape, _ := compiled.Catalog().ShapeAt(0)
	if !shape.Fields()[1].Custom || !shape.Fields()[1].Enterprise || !shape.Fields()[1].Variable {
		t.Fatalf("custom descriptor=%+v", shape.Fields()[1])
	}
	testCustomRuntime(t)
	testCustomAddressRuntime(t)
	testCustomGrammarAndBoundaries(t)
	testCustomPresenceAndIsolation(t)
}

func TestLoss(t *testing.T) {
	config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "flow.io.bytes", Target: "in_bytes"}})
	config.LossPolicy = LossPolicyReject
	if _, err := Compile(config); err == nil {
		t.Fatal("strict lossy mapping accepted")
	}
	config = explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}})
	config.LossPolicy = LossPolicyReject
	if _, err := Compile(config); err != nil {
		t.Fatalf("strict exact mapping rejected: %v", err)
	}
	testLossRuntime(t)
}

func TestFamily(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.address"}})
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.ShapeCount() != 2 {
		t.Fatalf("family-dependent shape count=%d", compiled.ShapeCount())
	}
	config = explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "flow.icmp_type_code"}})
	compiled, err = Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.ShapeCount() != 1 {
		t.Fatalf("composite shape count=%d", compiled.ShapeCount())
	}
	testFamilyRuntime(t)
}

func TestCollision(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "flow.src_vlan"}, {Canonical: "flow.vlan_id"}})
	if _, err := Compile(config); err == nil {
		t.Fatal("duplicate wire identity accepted")
	}
}

func TestRedaction(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "vendor.secret"}})
	config.Custom = []CustomField{{Source: "secret-value", PEN: uint32ptr(999999), ElementID: uint32ptr(99999), Encoding: "unsigned64", FixedLength: uint16ptr(8)}}
	_, err := Compile(config)
	if err == nil || len(err.Error()) > 256 || strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "999999") {
		t.Fatalf("unsafe error: %v", err)
	}
	testRedactionDecodeBoundary(t)
}

func TestCompileCustomPresenceErrorsDoNotPanic(t *testing.T) {
	valid := func() Config {
		config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
		config.Custom = []CustomField{{
			Source:    "vendor.direct",
			PEN:       uint32ptr(11),
			ElementID: uint32ptr(11),
			Encoding:  "string",
		}}
		return config
	}

	direct := []struct {
		name   string
		mutate func(*CustomField)
	}{
		{"variable-without-max-length", func(entry *CustomField) { entry.Variable = boolptr(true) }},
		{"variable-false-without-max-length", func(entry *CustomField) { entry.Variable = boolptr(false) }},
	}
	for _, tc := range direct {
		t.Run("direct-"+tc.name, func(t *testing.T) {
			config := valid()
			tc.mutate(&config.Custom[0])
			compiled, err := Compile(config)
			if err == nil {
				t.Fatal("invalid custom presence accepted")
			}
			assertCustomPresenceCompileError(t, compiled, err)
		})
	}

	jsonCases := []string{
		`{"protocol":3,"fields":[{"canonical":"source.port"}],"loss_policy":"encode_and_count","custom":[{"source":"vendor.json","pen":11,"element_id":11,"encoding":"string","variable":true}]}`,
		`{"protocol":3,"fields":[{"canonical":"source.port"}],"loss_policy":"encode_and_count","custom":[{"source":"vendor.json","pen":11,"element_id":11,"encoding":"string","variable":false}]}`,
	}
	for i, data := range jsonCases {
		t.Run("json-"+strconv.Itoa(i), func(t *testing.T) {
			config, err := DecodeJSON([]byte(data))
			if err != nil {
				t.Fatalf("DecodeJSON: %v", err)
			}
			compiled, err := Compile(config)
			if err == nil {
				t.Fatal("invalid custom presence accepted")
			}
			assertCustomPresenceCompileError(t, compiled, err)
		})
	}
}

func assertCustomPresenceCompileError(t *testing.T, compiled CompiledMapping, err error) {
	t.Helper()
	var configErr *ConfigError
	if !errors.As(err, &configErr) || configErr.Code != ErrCodeCustom {
		t.Fatalf("custom presence error=%v", err)
	}
	if compiled.ShapeCount() != 0 || compiled.Fingerprint() != "" || compiled.Catalog().ShapeCount() != 0 {
		t.Fatalf("invalid compile exposed partial output: %+v", compiled)
	}
	if configErr.Path != "mapping.custom.max_length" || configErr.Actual != 0 {
		t.Fatalf("missing max length diagnostic=%+v", configErr)
	}
}

func TestBounds(t *testing.T) {
	config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	config.MaxDatagramSize = 465
	if _, err := Compile(config); err == nil {
		t.Fatal("payload above default PMTU accepted")
	}
	config.MaxDatagramSize, config.PathMTU, config.Endpoint = 484, 512, "192.0.2.1:4739"
	if _, err := Compile(config); err != nil {
		t.Fatalf("IPv4 PMTU boundary rejected: %v", err)
	}
	config.MaxDatagramSize = 485
	if _, err := Compile(config); err == nil {
		t.Fatal("IPv4 PMTU overflow accepted")
	}
	if !errors.Is(errSentinel(), ErrCompile) {
		t.Fatal("sentinel sanity")
	}
	testBoundsStatic(t)
	testTokenVocabularyBoundary(t)
	testPMTUBoundary(t)
	testStaticBoundaryMatrix(t)
	testMapperAddressMACTimeAndRangeGates(t)
}

func errSentinel() error {
	return ConfigError{Code: ErrCodeBounds, Protocol: wire.ProtocolIPFIX, Path: "path_mtu"}
}
