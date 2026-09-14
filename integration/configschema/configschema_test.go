package configschema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func repositoryRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func loadSchema(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(), "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	// mdatagen uses the Go module path as a relative $id. Supply an absolute
	// base URI for validators that require URI-normalized identifiers.
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{BaseURI: "https://schema.invalid/"})
	if err != nil {
		t.Fatalf("schema cannot be resolved: %v", err)
	}
	return resolved
}

func loadFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	path := filepath.Join(repositoryRoot(), "integration", "configschema", "testdata", "config-schema", name)
	conf, err := confmaptest.LoadConf(path)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return conf.ToStringMap()
}

func loadFixtureWithScalar(t *testing.T, name, key, value string) map[string]any {
	t.Helper()
	fixturePath := filepath.Join(repositoryRoot(), "integration", "configschema", "testdata", "config-schema", name)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+":") {
			lines[i] = key + ": " + value
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatalf("fixture %s has no top-level %s", name, key)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write temporary YAML: %v", err)
	}
	conf, err := confmaptest.LoadConf(path)
	if err != nil {
		t.Fatalf("load temporary YAML for %s: %v", name, err)
	}
	return conf.ToStringMap()
}

func assertLoadedScalar(t *testing.T, raw map[string]any, key string, wantType reflect.Type, wantValue any) {
	t.Helper()
	got, ok := raw[key]
	if !ok {
		t.Fatalf("loaded YAML has no %s", key)
	}
	if gotType := reflect.TypeOf(got); gotType != wantType {
		t.Fatalf("loaded YAML %s type=%v, want %v (value=%v)", key, gotType, wantType, got)
	}
	if !reflect.DeepEqual(got, wantValue) {
		t.Fatalf("loaded YAML %s value=%v, want %v", key, got, wantValue)
	}
}

func cloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = cloneValue(value)
	}
	return output
}

func cloneValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneMap(value)
	case []any:
		output := make([]any, len(value))
		for i, item := range value {
			output[i] = cloneValue(item)
		}
		return output
	default:
		return value
	}
}

func mapAt(t *testing.T, root map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := root[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object (%T)", key, root[key])
	}
	return value
}

func parseAndValidate(t *testing.T, raw map[string]any) error {
	t.Helper()
	conf := confmap.NewFromStringMap(raw)
	config, ok := netflowexporter.NewFactory().CreateDefaultConfig().(*netflowexporter.Config)
	if !ok {
		return fmt.Errorf("factory returned unexpected config type")
	}
	if err := conf.Unmarshal(config); err != nil {
		return err
	}
	return config.Validate()
}

func assertSchemaAndParser(t *testing.T, resolved *jsonschema.Resolved, name string, raw map[string]any, schemaValid, parserValid bool) {
	t.Helper()
	schemaErr := resolved.Validate(raw)
	parserErr := parseAndValidate(t, raw)
	if (schemaErr == nil) != schemaValid {
		t.Errorf("%s: schema valid=%t, want %t (err=%v)", name, schemaErr == nil, schemaValid, schemaErr)
	}
	if (parserErr == nil) != parserValid {
		t.Errorf("%s: parser valid=%t, want %t (err=%v)", name, parserErr == nil, parserValid, parserErr)
	}
}

func assertNumericBoundaryResults(t *testing.T, resolved *jsonschema.Resolved, raw map[string]any, schemaValid, unmarshalValid, parserValid bool) {
	t.Helper()
	t.Run("schema", func(t *testing.T) {
		err := resolved.Validate(raw)
		if (err == nil) != schemaValid {
			t.Errorf("schema valid=%t, want %t (err=%v)", err == nil, schemaValid, err)
		}
	})
	t.Run("parser", func(t *testing.T) {
		config := netflowexporter.NewFactory().CreateDefaultConfig().(*netflowexporter.Config)
		err := confmap.NewFromStringMap(raw).Unmarshal(config)
		if (err == nil) != unmarshalValid {
			t.Fatalf("Unmarshal valid=%t, want %t (err=%v)", err == nil, unmarshalValid, err)
		}
		if err != nil {
			return
		}
		err = config.Validate()
		if (err == nil) != parserValid {
			t.Errorf("parser valid=%t, want %t (err=%v)", err == nil, parserValid, err)
		}
	})
}

func TestNumericSchemaParserBoundaries(t *testing.T) {
	resolved := loadSchema(t)
	const (
		maxInt64        = uint64(9223372036854775807)
		maxInt64PlusOne = uint64(9223372036854775808)
		aboveSchemaMax  = uint64(9223372036854776001)
	)

	tests := []struct {
		name           string
		fixture        string
		key            string
		directValue    any
		yamlValue      string
		yamlType       reflect.Type
		yamlTypedValue any
		schemaValid    bool
		parserValid    bool
	}{
		{
			name:           "uptime-origin-max-int64",
			fixture:        "valid-v5.yaml",
			key:            "uptime_origin",
			directValue:    maxInt64,
			yamlValue:      "9223372036854775807",
			yamlType:       reflect.TypeOf(int(0)),
			yamlTypedValue: int(maxInt64),
			schemaValid:    true,
			parserValid:    true,
		},
		{
			name:           "uptime-origin-max-int64-plus-one",
			fixture:        "valid-v5.yaml",
			key:            "uptime_origin",
			directValue:    maxInt64PlusOne,
			yamlValue:      "9223372036854775808",
			yamlType:       reflect.TypeOf(uint64(0)),
			yamlTypedValue: maxInt64PlusOne,
			schemaValid:    true,
			parserValid:    false,
		},
		{
			name:           "uptime-origin-above-printed-schema-maximum",
			fixture:        "valid-v5.yaml",
			key:            "uptime_origin",
			directValue:    aboveSchemaMax,
			yamlValue:      "9223372036854776001",
			yamlType:       reflect.TypeOf(uint64(0)),
			yamlTypedValue: aboveSchemaMax,
			schemaValid:    false,
			parserValid:    false,
		},
		{
			name:           "max-datagram-size-integer",
			fixture:        "valid-v9.yaml",
			key:            "max_datagram_size",
			directValue:    int(464),
			yamlValue:      "464",
			yamlType:       reflect.TypeOf(int(0)),
			yamlTypedValue: int(464),
			schemaValid:    true,
			parserValid:    true,
		},
		{
			name:           "max-datagram-size-integral-float",
			fixture:        "valid-v9.yaml",
			key:            "max_datagram_size",
			directValue:    float64(464),
			yamlValue:      "464.0",
			yamlType:       reflect.TypeOf(float64(0)),
			yamlTypedValue: float64(464),
			schemaValid:    true,
			parserValid:    false,
		},
		{
			name:           "max-datagram-size-fractional-float",
			fixture:        "valid-v9.yaml",
			key:            "max_datagram_size",
			directValue:    float64(464.5),
			yamlValue:      "464.5",
			yamlType:       reflect.TypeOf(float64(0)),
			yamlTypedValue: float64(464.5),
			schemaValid:    false,
			parserValid:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Unsigned integer overflow here is semantic: it fits the Go field
			// but exceeds Config.Validate's epoch bound. Floats fail decoding.
			unmarshalValid := tc.yamlType.Kind() != reflect.Float64
			t.Run("map", func(t *testing.T) {
				raw := loadFixture(t, tc.fixture)
				raw[tc.key] = tc.directValue
				assertNumericBoundaryResults(t, resolved, raw, tc.schemaValid, unmarshalValid, tc.parserValid)
			})
			t.Run("yaml", func(t *testing.T) {
				yamlRaw := loadFixtureWithScalar(t, tc.fixture, tc.key, tc.yamlValue)
				assertLoadedScalar(t, yamlRaw, tc.key, tc.yamlType, tc.yamlTypedValue)
				assertNumericBoundaryResults(t, resolved, yamlRaw, tc.schemaValid, unmarshalValid, tc.parserValid)
			})
		})
	}
}

func TestValidProtocolConfigurations(t *testing.T) {
	resolved := loadSchema(t)
	for _, tc := range []struct {
		name string
		file string
	}{
		{name: "v5", file: "valid-v5.yaml"},
		{name: "v9", file: "valid-v9.yaml"},
		{name: "ipfix", file: "valid-ipfix.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSchemaAndParser(t, resolved, tc.name, loadFixture(t, tc.file), true, true)
		})
	}
}

func TestValidExplicitFieldsConfiguration(t *testing.T) {
	resolved := loadSchema(t)
	raw := loadFixture(t, "valid-v9.yaml")
	mapping := mapAt(t, raw, "mapping")
	delete(mapping, "profile")
	delete(mapping, "protocol_identifiers")
	delete(mapping, "network_type_versions")
	mapping["fields"] = []any{map[string]any{"canonical": "source.port", "target": ""}}
	mapping["input_guarantees"] = map[string]any{"flow_io_bytes": ""}
	assertSchemaAndParser(t, resolved, "explicit-fields", raw, true, true)
}

func TestStructuralNegativesRejectAtBothBoundaries(t *testing.T) {
	resolved := loadSchema(t)
	base := loadFixture(t, "valid-v9.yaml")

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name:   "protocol-enum",
			mutate: func(raw map[string]any) { raw["protocol"] = "netflow_v10" },
		},
		{
			name:   "required-loss-policy",
			mutate: func(raw map[string]any) { delete(mapAt(t, raw, "mapping"), "loss_policy") },
		},
		{
			name:   "disabled-queue",
			mutate: func(raw map[string]any) { mapAt(t, raw, "sending_queue")["enabled"] = true },
		},
		{
			name:   "disabled-retry",
			mutate: func(raw map[string]any) { mapAt(t, raw, "retry_on_failure")["enabled"] = true },
		},
		{
			name:   "integer-type",
			mutate: func(raw map[string]any) { raw["max_datagram_size"] = "1200" },
		},
		{
			name:   "fractional-number",
			mutate: func(raw map[string]any) { raw["max_datagram_size"] = 1200.5 },
		},
		{
			name:   "boolean-string",
			mutate: func(raw map[string]any) { mapAt(t, raw, "sending_queue")["enabled"] = "false" },
		},
		{
			name:   "duration-syntax",
			mutate: func(raw map[string]any) { raw["timeout"] = "not-a-duration" },
		},
		{
			name:   "null-identity-pointer",
			mutate: func(raw map[string]any) { mapAt(t, raw, "identity")["source_id"] = nil },
		},
		{
			name:   "empty-identity",
			mutate: func(raw map[string]any) { raw["identity"] = map[string]any{} },
		},
		{
			name: "field-canonical-required",
			mutate: func(raw map[string]any) {
				mapping := mapAt(t, raw, "mapping")
				delete(mapping, "profile")
				mapping["fields"] = []any{map[string]any{"target": "in_bytes"}}
			},
		},
		{
			name: "custom-encoding-enum",
			mutate: func(raw map[string]any) {
				mapping := mapAt(t, raw, "mapping")
				mapping["custom"] = []any{map[string]any{"source": "vendor.x", "field_type": 300, "fixed_length": 1, "allow_private": true, "encoding": "unknown"}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := cloneMap(base)
			tc.mutate(raw)
			assertSchemaAndParser(t, resolved, tc.name, raw, false, false)
		})
	}
}

func TestSemanticParserOnlyCases(t *testing.T) {
	resolved := loadSchema(t)

	tests := []struct {
		name   string
		file   string
		mutate func(map[string]any)
	}{
		{
			name: "profile-and-fields-exclusive",
			file: "valid-v9.yaml",
			mutate: func(raw map[string]any) {
				mapAt(t, raw, "mapping")["fields"] = []any{map[string]any{"canonical": "source.port"}}
			},
		},
		{
			name:   "v9-identity-fields",
			file:   "valid-v9.yaml",
			mutate: func(raw map[string]any) { mapAt(t, raw, "identity")["engine_type"] = 1 },
		},
		{
			name:   "v5-uptime-origin-required",
			file:   "valid-v5.yaml",
			mutate: func(raw map[string]any) { delete(raw, "uptime_origin") },
		},
		{
			name: "timed-v9-uptime-origin-required",
			file: "valid-v9.yaml",
			mutate: func(raw map[string]any) {
				mapAt(t, raw, "mapping")["profile"] = "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1"
				delete(raw, "uptime_origin")
			},
		},
		{
			name:   "protocol-specific-refresh",
			file:   "valid-v9.yaml",
			mutate: func(raw map[string]any) { raw["ipfix"] = map[string]any{"template_refresh_data_packets": 10} },
		},
		{
			name: "dns-stale-after-order",
			file: "valid-v9.yaml",
			mutate: func(raw map[string]any) {
				dns := mapAt(t, raw, "dns")
				dns["refresh_interval"] = "10m"
				dns["stale_after"] = "1m"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := cloneMap(loadFixture(t, tc.file))
			tc.mutate(raw)
			assertSchemaAndParser(t, resolved, tc.name, raw, true, false)
		})
	}
}

func TestKnownGeneratorAndParserBoundaryDifferences(t *testing.T) {
	resolved := loadSchema(t)

	tests := []struct {
		name        string
		file        string
		mutate      func(map[string]any)
		schemaValid bool
		parserValid bool
	}{
		{
			name:        "unknown-root-key-parser-only",
			file:        "valid-v9.yaml",
			mutate:      func(raw map[string]any) { raw["unexpected"] = true },
			schemaValid: true,
			parserValid: false,
		},
		{
			name: "unknown-nested-key-parser-only",
			file: "valid-v9.yaml",
			mutate: func(raw map[string]any) {
				mapAt(t, raw, "mapping")["unexpected"] = true
			},
			schemaValid: true,
			parserValid: false,
		},
		{
			name:        "path-mtu-null-parser-only",
			file:        "valid-ipfix.yaml",
			mutate:      func(raw map[string]any) { raw["path_mtu"] = nil },
			schemaValid: false,
			parserValid: true,
		},
		{
			name: "ipfix-refresh-null-parser-only",
			file: "valid-ipfix.yaml",
			mutate: func(raw map[string]any) {
				mapAt(t, raw, "ipfix")["template_refresh_data_packets"] = nil
			},
			schemaValid: false,
			parserValid: true,
		},
		{
			name:        "duration-scalar-type",
			file:        "valid-v9.yaml",
			mutate:      func(raw map[string]any) { raw["timeout"] = 5 },
			schemaValid: false,
			parserValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := cloneMap(loadFixture(t, tc.file))
			tc.mutate(raw)
			assertSchemaAndParser(t, resolved, tc.name, raw, tc.schemaValid, tc.parserValid)
		})
	}
}

func TestGoDurationSyntax(t *testing.T) {
	resolved := loadSchema(t)
	for _, value := range []string{"+5s", ".5s", "1.s", "500000μs"} {
		t.Run(value, func(t *testing.T) {
			raw := loadFixture(t, "valid-v9.yaml")
			raw["timeout"] = value
			assertSchemaAndParser(t, resolved, value, raw, true, true)
		})
	}
}

var durationType = reflect.TypeOf(time.Duration(0))

func mapstructureFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("mapstructure")
	if tag == "-" {
		return ""
	}
	if name, _, _ := strings.Cut(tag, ","); name != "" {
		return name
	}
	return field.Name
}

func assertSchemaMatchesType(t *testing.T, schema *jsonschema.Schema, typ reflect.Type, path string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == durationType {
		if schema.Type != "string" {
			t.Errorf("%s: duration schema type=%q, want string", path, schema.Type)
		}
		return
	}
	switch typ.Kind() {
	case reflect.Struct:
		if schema.Type != "object" {
			t.Errorf("%s: object schema type=%q", path, schema.Type)
		}
		if schema.Properties == nil {
			t.Errorf("%s: object schema has no properties", path)
			return
		}
		expected := make(map[string]reflect.StructField)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := mapstructureFieldName(field)
			if name != "" {
				expected[name] = field
			}
		}
		for name, field := range expected {
			property, ok := schema.Properties[name]
			if !ok {
				t.Errorf("%s: public field %s missing from schema", path, name)
				continue
			}
			assertSchemaMatchesType(t, property, field.Type, path+"."+name)
		}
		for name := range schema.Properties {
			if _, ok := expected[name]; !ok {
				t.Errorf("%s: schema contains invented property %s", path, name)
			}
		}
	case reflect.Slice, reflect.Array:
		if schema.Type != "array" {
			t.Errorf("%s: slice schema type=%q", path, schema.Type)
			return
		}
		if schema.Items == nil {
			t.Errorf("%s: slice schema has no items", path)
			return
		}
		assertSchemaMatchesType(t, schema.Items, typ.Elem(), path+"[]")
	case reflect.Map:
		if schema.Type != "object" {
			t.Errorf("%s: map schema type=%q", path, schema.Type)
		}
		if schema.AdditionalProperties != nil {
			assertSchemaMatchesType(t, schema.AdditionalProperties, typ.Elem(), path+"{}")
		}
	}
}

func TestSchemaMatchesPublicConfig(t *testing.T) {
	assertSchemaMatchesType(t, loadSchema(t).Schema(), reflect.TypeOf(netflowexporter.Config{}), "Config")
}
