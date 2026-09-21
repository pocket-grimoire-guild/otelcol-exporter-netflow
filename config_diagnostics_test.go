package netflowexporter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter/exportertest"
)

func diagnosticText(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected configuration error")
	}
	text := err.Error()
	if len(text) > 256 {
		t.Fatalf("diagnostic length=%d", len(text))
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			t.Fatalf("diagnostic is not printable ASCII: %q", text)
		}
	}
	return text
}

func assertNoDiagnosticCause(t *testing.T, err error) string {
	t.Helper()
	text := diagnosticText(t, err)
	if errors.Unwrap(err) != nil || errors.Is(err, mapping.ErrCompile) {
		t.Fatalf("configuration diagnostic retained a cause: %q", text)
	}
	var mapped *mapping.ConfigError
	if errors.As(err, &mapped) {
		t.Fatalf("configuration diagnostic exposed ConfigError: %q", text)
	}
	return text
}

func assertPublicDiagnosticBoth(t *testing.T, c *Config, want string, canaries ...string) {
	t.Helper()
	check := func(label string, err error) {
		t.Helper()
		text := assertNoDiagnosticCause(t, err)
		if !strings.HasPrefix(text, "netflow: invalid configuration: "+want+"; ") {
			t.Fatalf("%s diagnostic=%q want token %q", label, text, want)
		}
		for _, canary := range canaries {
			if strings.Contains(text, canary) {
				t.Fatalf("%s diagnostic leaked %q: %q", label, canary, text)
			}
		}
	}
	check("Validate", c.Validate())
	f := NewFactory()
	_, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), c)
	check("CreateLogs", err)
}

func assertPublicValidBoth(t *testing.T, c *Config) {
	t.Helper()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate rejected valid configuration: %v", err)
	}
	f := NewFactory()
	created, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), c)
	if err != nil {
		t.Fatalf("CreateLogs rejected valid configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := created.Shutdown(ctx); err != nil {
		t.Fatalf("successful exporter cleanup failed: %v", err)
	}
}

type hostileDiagnosticError struct{ calls *int }

func (e hostileDiagnosticError) Error() string {
	*e.calls++
	panic("Error must not be called")
}
func (e hostileDiagnosticError) Is(error) bool {
	*e.calls++
	panic("Is must not be called")
}
func (e hostileDiagnosticError) As(any) bool {
	*e.calls++
	panic("As must not be called")
}
func (e hostileDiagnosticError) Unwrap() error {
	*e.calls++
	panic("Unwrap must not be called")
}

func TestPublicConfigDiagnostics(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol+"_valid", func(t *testing.T) {
			if err := validConfig(protocol).Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}

	c := validConfig("ipfix")
	c.Templates.IDBase = 255
	if got := diagnosticText(t, c.Validate()); got != "netflow: invalid configuration: rule=template_id_range path=templates.id_base; expected 256..65535" {
		t.Fatalf("id range diagnostic=%q", got)
	}

	c = validConfig("ipfix")
	if err := c.Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	c.Templates.IDBase = 65535
	if got := diagnosticText(t, c.Validate()); got != "netflow: invalid configuration: rule=template_allocation path=templates.id_base protocol=ipfix; selected templates exceed the ID range" {
		t.Fatalf("allocation diagnostic=%q", got)
	}

	c = validConfig("ipfix")
	c.Mapping.Profile = nil
	c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
	c.Mapping.ProtocolIdentifiers = nil
	c.Mapping.NetworkTypeVersions = nil
	c.Templates.IDBase = 65535
	if err := c.Validate(); err != nil {
		t.Fatalf("one-shape 65535 rejected: %v", err)
	}
	c.Templates.IDBase = 65534
	if err := c.Validate(); err != nil {
		t.Fatalf("one-shape 65534 rejected: %v", err)
	}

	c = validConfig("ipfix")
	c.Mapping.LossPolicy = ptr(mapping.LossPolicyReject)
	if got := diagnosticText(t, c.Validate()); !strings.Contains(got, "rule=compile_policy path=mapping.loss_policy protocol=ipfix") {
		t.Fatalf("policy diagnostic=%q", got)
	}
	c = validConfig("ipfix")
	c.Timeout = 6 * time.Second
	if got := diagnosticText(t, c.Validate()); got != "netflow: invalid configuration: rule=write_timeout_drain path=timeout; must not exceed shutdown_drain_timeout" {
		t.Fatalf("write/drain diagnostic=%q", got)
	}
	c = validConfig("ipfix")
	c.DNS.Timeout = 6 * time.Second
	if got := diagnosticText(t, c.Validate()); got != "netflow: invalid configuration: rule=dns_timeout_drain path=dns.timeout; must not exceed shutdown_drain_timeout" {
		t.Fatalf("dns/drain diagnostic=%q", got)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"queue_before_schema", func(c *Config) { c.SendingQueue.Enabled = true; c.Schema = "canary-schema" }, "rule=queue"},
		{"schema_before_endpoint", func(c *Config) { c.Schema = "canary-schema"; c.Endpoint = "bad-endpoint" }, "rule=schema"},
		{"selector_before_policy", func(c *Config) { c.Mapping.Profile = nil; c.Mapping.LossPolicy = nil }, "rule=mapping path=mapping;"},
		{"policy_before_empty_selector", func(c *Config) { c.Mapping.LossPolicy = nil; c.Mapping.Profile = ptr("") }, "rule=mapping_policy_required"},
		{"timeout_range_before_drain_conflict", func(c *Config) { c.Timeout = 31 * time.Second; c.ShutdownDrainTimeout = 5 * time.Second }, "rule=write_timeout_range"},
		{"write_conflict_before_drain_range", func(c *Config) { c.ShutdownDrainTimeout = 500 * time.Millisecond }, "rule=write_timeout_drain"},
		{"dns_range_before_dns_conflict", func(c *Config) { c.DNS.Timeout = 31 * time.Second; c.ShutdownDrainTimeout = 5 * time.Second }, "rule=dns_timeout_range"},
	} {
		t.Run("overlap_"+tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			tc.mutate(c)
			if got := diagnosticText(t, c.Validate()); !strings.Contains(got, tc.want) {
				t.Fatalf("diagnostic=%q want %q", got, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		config func() *Config
		want   string
		canary []string
	}{
		{"schema", func() *Config {
			c := validConfig("ipfix")
			c.Schema = strings.Repeat("SCHEMA-CANARY\x00", 5000)
			return c
		}, "rule=schema path=schema", []string{"SCHEMA-CANARY"}},
		{"protocol", func() *Config {
			c := validConfig("ipfix")
			c.Protocol = strings.Repeat("PROTOCOL-CANARY\n", 5000)
			return c
		}, "rule=protocol path=protocol", []string{"PROTOCOL-CANARY"}},
		{"profile", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = ptr(strings.Repeat("PROFILE-CANARY", 5000))
			return c
		}, "rule=compile_profile path=mapping.profile protocol=ipfix", []string{"PROFILE-CANARY"}},
		{"token", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.ProtocolIdentifiers[0] = ProtocolIdentifier{Token: "TOKEN-CANARY", Number: 231}
			return c
		}, "rule=compile_token path=mapping.protocol_identifiers protocol=ipfix", []string{"TOKEN-CANARY", "231"}},
		{"selector", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = nil
			c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "SELECTOR-CANARY"}})
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			return c
		}, "rule=compile_selector path=mapping.fields.canonical protocol=ipfix", []string{"SELECTOR-CANARY"}},
		{"custom_source", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Custom = []CustomField{{Source: "body." + strings.Repeat("CUSTOM-SOURCE-CANARY", 4096) + "\x00", Encoding: "octet_array", PEN: ptr(uint32(math.MaxUint32)), ElementID: ptr(uint32(math.MaxUint32)), FixedLength: ptr(uint16(1))}}
			return c
		}, "rule=compile_custom path=mapping.custom.source protocol=ipfix", []string{"CUSTOM-SOURCE-CANARY", "4294967295"}},
		{"provenance", func() *Config {
			c := validConfig("netflow_v9")
			c.Mapping.Profile = ptr(mapping.ProfileV9Timed)
			c.UptimeOrigin = nil
			return c
		}, "rule=compile_provenance path=uptime_origin protocol=v9", []string{"1788220800000000000"}},
		{"collision", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = nil
			c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "flow.start"}, {Canonical: "flow.start"}})
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			return c
		}, "rule=compile_collision path=mapping.fields protocol=ipfix", nil},
		{"bounds", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = nil
			fields := make([]FieldSelection, 223)
			for i := range fields {
				fields[i] = FieldSelection{Canonical: "source.port"}
			}
			c.Mapping.Fields = ptr(fields)
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			return c
		}, "rule=compile_bounds path=mapping.fields protocol=ipfix", []string{"223"}},
		{"pmtu", func() *Config { c := validConfig("ipfix"); c.MaxDatagramSize = 465; return c }, "rule=compile_pmtu path=path_mtu protocol=ipfix", []string{"465", "464"}},
		{"identity", func() *Config {
			c := validConfig("ipfix")
			c.Identity.ObservationDomainID = nil
			c.Identity.SourceID = ptr(uint32(3956874123))
			return c
		}, "rule=identity path=identity", []string{"3956874123"}},
		{"uptime", func() *Config {
			c := validConfig("netflow_v5")
			c.UptimeOrigin = ptr(uint64(math.MaxInt64) + 1)
			return c
		}, "rule=uptime_origin path=uptime_origin", []string{"9223372036854775808"}},
		{"endpoint", func() *Config { c := validConfig("ipfix"); c.Endpoint = "ENDPOINT-CANARY\x00"; return c }, "rule=endpoint path=endpoint", []string{"ENDPOINT-CANARY"}},
		{"endpoint_huge", func() *Config {
			c := validConfig("ipfix")
			c.Endpoint = strings.Repeat("HOST-CANARY", 6554) + ":4739"
			return c
		}, "rule=endpoint path=endpoint", []string{"HOST-CANARY"}},
		{"custom_identity", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Custom = []CustomField{{Source: "CUSTOM-IDENTITY-CANARY", Encoding: "octet_array", PEN: ptr(uint32(3765987654)), ElementID: ptr(uint32(3965987654)), FixedLength: ptr(uint16(1))}}
			return c
		}, "rule=compile_custom path=mapping.custom protocol=ipfix", []string{"CUSTOM-IDENTITY-CANARY", "3765987654", "3965987654"}},
		{"maximum_datagram", func() *Config { c := validConfig("ipfix"); c.MaxDatagramSize = math.MaxUint64; return c }, "rule=max_datagram_size path=max_datagram_size", []string{"18446744073709551615"}},
		{"maximum_template_id", func() *Config { c := validConfig("ipfix"); c.Templates.IDBase = math.MaxUint32; return c }, "rule=template_id_range path=templates.id_base", []string{"4294967295"}},
		{"maximum_path_mtu", func() *Config { c := validConfig("ipfix"); c.PathMTU = ptr(uint64(math.MaxUint64)); return c }, "rule=path_mtu_range path=path_mtu", []string{"18446744073709551615"}},
	} {
		t.Run("public_"+tc.name, func(t *testing.T) {
			assertPublicDiagnosticBoth(t, tc.config(), tc.want, tc.canary...)
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"queue", func(c *Config) { c.SendingQueue.Enabled = true }, "rule=queue path=sending_queue.enabled"},
		{"retry", func(c *Config) { c.RetryOnFailure.Enabled = true }, "rule=retry path=retry_on_failure.enabled"},
		{"endpoint_port", func(c *Config) { c.Endpoint = "endpoint-canary:65536" }, "rule=endpoint path=endpoint"},
		{"sampling_mode", func(c *Config) { c.Identity.SamplingMode = ptr(uint8(4)) }, "rule=identity_sampling_mode path=identity.sampling_mode"},
		{"max_datagram", func(c *Config) { c.MaxDatagramSize = 127 }, "rule=max_datagram_size path=max_datagram_size"},
		{"template_id_range", func(c *Config) { c.Templates.IDBase = 255 }, "rule=template_id_range path=templates.id_base"},
		{"template_copies", func(c *Config) { c.Templates.InitialCopies = 1 }, "rule=template_initial_copies path=templates.initial_copies"},
		{"template_refresh", func(c *Config) { c.Templates.RefreshInterval = 29 * time.Second }, "rule=template_refresh_interval path=templates.refresh_interval"},
		{"write_timeout_range", func(c *Config) { c.Timeout = 50 * time.Millisecond }, "rule=write_timeout_range path=timeout"},
		{"write_timeout_drain", func(c *Config) { c.Timeout = 6 * time.Second }, "rule=write_timeout_drain path=timeout"},
		{"drain_timeout_range", func(c *Config) { c.Timeout = 100 * time.Millisecond; c.ShutdownDrainTimeout = 500 * time.Millisecond }, "rule=drain_timeout_range path=shutdown_drain_timeout"},
		{"dns_timeout_range", func(c *Config) { c.DNS.Timeout = 50 * time.Millisecond }, "rule=dns_timeout_range path=dns.timeout"},
		{"dns_timeout_drain", func(c *Config) { c.DNS.Timeout = 6 * time.Second }, "rule=dns_timeout_drain path=dns.timeout"},
		{"dns_refresh_range", func(c *Config) { c.DNS.RefreshInterval = 500 * time.Millisecond }, "rule=dns_refresh_range path=dns.refresh_interval"},
		{"dns_stale_range", func(c *Config) { c.DNS.StaleAfter = 8 * 24 * time.Hour }, "rule=dns_stale_range path=dns.stale_after"},
		{"dns_stale_refresh", func(c *Config) { c.DNS.StaleAfter = time.Second }, "rule=dns_stale_refresh path=dns.stale_after"},
		{"record_limit", func(c *Config) { c.MaxRecordsPerMessage = ptr(uint16(1025)) }, "rule=record_limit path=max_records_per_message"},
		{"v9_refresh_packets", func(c *Config) { c.NetFlowV9.TemplateRefreshPackets = ptr(uint32(0)) }, "rule=v9_refresh_packets path=netflow_v9.template_refresh_packets"},
		{"ipfix_refresh_packets", func(c *Config) { c.IPFIX.TemplateRefreshDataPackets = ptr(uint32(0)) }, "rule=ipfix_refresh_packets path=ipfix.template_refresh_data_packets"},
		{"path_mtu_range", func(c *Config) { c.PathMTU = ptr(uint64(511)) }, "rule=path_mtu_range path=path_mtu"},
		{"selector_choice", func(c *Config) { c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}}) }, "rule=mapping path=mapping"},
		{"selector_missing", func(c *Config) { c.Mapping.Profile = nil }, "rule=mapping path=mapping"},
		{"selector_empty_profile", func(c *Config) { c.Mapping.Profile = ptr("") }, "rule=mapping path=mapping"},
		{"selector_empty_fields", func(c *Config) { c.Mapping.Profile = nil; c.Mapping.Fields = ptr([]FieldSelection{}) }, "rule=mapping path=mapping"},
		{"policy_required", func(c *Config) { c.Mapping.LossPolicy = nil }, "rule=mapping_policy_required path=mapping.loss_policy"},
	} {
		t.Run("public_direct_"+tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			if tc.name == "sampling_mode" {
				c = validConfig("netflow_v5")
			}
			tc.mutate(c)
			assertPublicDiagnosticBoth(t, c, tc.want, "canary", "65536", "1025")
		})
	}

	for _, tc := range []struct {
		name   string
		config func() *Config
	}{
		{"v5", func() *Config { return validConfig("netflow_v5") }},
		{"v9", func() *Config { return validConfig("netflow_v9") }},
		{"ipfix", func() *Config { return validConfig("ipfix") }},
		{"explicit_mapping", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = nil
			c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			return c
		}},
		{"one_shape_65535", func() *Config {
			c := validConfig("ipfix")
			c.Mapping.Profile = nil
			c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			c.Templates.IDBase = 65535
			return c
		}},
		{"two_shape_65534", func() *Config { c := validConfig("ipfix"); c.Templates.IDBase = 65534; return c }},
		{"timed_v9_origin", func() *Config {
			c := validConfig("netflow_v9")
			c.Mapping.Profile = ptr(mapping.ProfileV9Timed)
			c.UptimeOrigin = ptr(uint64(1788220800000000000))
			return c
		}},
		{"disabled_queue_retry", func() *Config {
			c := validConfig("ipfix")
			c.SendingQueue.Enabled = false
			c.RetryOnFailure.Enabled = false
			return c
		}},
		{"accepted_boundaries", func() *Config {
			c := validConfig("ipfix")
			c.Timeout = 100 * time.Millisecond
			c.DNS.Timeout = 100 * time.Millisecond
			c.ShutdownDrainTimeout = 30 * time.Second
			c.Templates.RefreshInterval = 30 * time.Second
			c.MaxRecordsPerMessage = ptr(uint16(1024))
			return c
		}},
		{"accepted_min_boundaries", func() *Config {
			c := validConfig("ipfix")
			c.Timeout, c.DNS.Timeout = 100*time.Millisecond, 100*time.Millisecond
			c.ShutdownDrainTimeout = time.Second
			c.DNS.RefreshInterval, c.DNS.StaleAfter = time.Second, time.Second
			c.Templates.RefreshInterval = 30 * time.Second
			c.MaxRecordsPerMessage = ptr(uint16(1))
			c.IPFIX.TemplateRefreshDataPackets = ptr(uint32(1))
			return c
		}},
		{"accepted_v5_record_cap", func() *Config { c := validConfig("netflow_v5"); c.MaxRecordsPerMessage = ptr(uint16(30)); return c }},
		{"accepted_v9_packet_min", func() *Config {
			c := validConfig("netflow_v9")
			c.NetFlowV9.TemplateRefreshPackets = ptr(uint32(1))
			return c
		}},
		{"accepted_v9_packet_max", func() *Config {
			c := validConfig("netflow_v9")
			c.NetFlowV9.TemplateRefreshPackets = ptr(uint32(1000))
			return c
		}},
		{"accepted_max_boundaries", func() *Config {
			c := validConfig("ipfix")
			c.Timeout = 30 * time.Second
			c.DNS.Timeout = 30 * time.Second
			c.ShutdownDrainTimeout = 30 * time.Second
			c.Templates.RefreshInterval = 24 * time.Hour
			c.DNS.RefreshInterval = 24 * time.Hour
			c.DNS.StaleAfter = 7 * 24 * time.Hour
			c.MaxRecordsPerMessage = ptr(uint16(1024))
			c.Templates.InitialCopies = 8
			c.IPFIX.TemplateRefreshDataPackets = ptr(uint32(1000))
			return c
		}},
	} {
		t.Run("valid_"+tc.name, func(t *testing.T) { assertPublicValidBoth(t, tc.config()) })
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"queue_schema", func(c *Config) { c.SendingQueue.Enabled = true; c.Schema = "SCHEMA-OVERLAP" }, "rule=queue path=sending_queue.enabled"},
		{"schema_endpoint", func(c *Config) { c.Schema = "SCHEMA-OVERLAP"; c.Endpoint = "ENDPOINT-OVERLAP" }, "rule=schema path=schema"},
		{"selector_policy", func(c *Config) { c.Mapping.Profile = nil; c.Mapping.LossPolicy = nil }, "rule=mapping path=mapping"},
		{"empty_selector_policy", func(c *Config) { c.Mapping.Profile = ptr(""); c.Mapping.LossPolicy = nil }, "rule=mapping_policy_required path=mapping.loss_policy"},
		{"write_range_conflict", func(c *Config) { c.Timeout = 31 * time.Second; c.ShutdownDrainTimeout = 5 * time.Second }, "rule=write_timeout_range path=timeout"},
		{"drain_range_conflict", func(c *Config) { c.ShutdownDrainTimeout = 500 * time.Millisecond }, "rule=write_timeout_drain path=timeout"},
		{"dns_range_conflict", func(c *Config) { c.DNS.Timeout = 31 * time.Second; c.ShutdownDrainTimeout = 5 * time.Second }, "rule=dns_timeout_range path=dns.timeout"},
	} {
		t.Run("public_overlap_"+tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			tc.mutate(c)
			assertPublicDiagnosticBoth(t, c, tc.want, "OVERLAP")
		})
	}

	f := NewFactory()
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"id_range", func(c *Config) { c.Templates.IDBase = 255 }, "rule=template_id_range"},
		{"allocation", func(c *Config) { c.Templates.IDBase = 65535 }, "rule=template_allocation"},
		{"policy", func(c *Config) { c.Mapping.LossPolicy = ptr(mapping.LossPolicyReject) }, "rule=compile_policy"},
		{"write_drain", func(c *Config) { c.Timeout = 6 * time.Second }, "rule=write_timeout_drain"},
		{"dns_drain", func(c *Config) { c.DNS.Timeout = 6 * time.Second }, "rule=dns_timeout_drain"},
	} {
		t.Run("factory_"+tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			tc.mutate(c)
			_, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), c)
			if got := diagnosticText(t, err); !strings.Contains(got, tc.want) {
				t.Fatalf("factory diagnostic=%q want %q", got, tc.want)
			}
		})
	}

	created, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), validConfig("ipfix"))
	if err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := created.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown before start: %v", err)
	}
	var typedNil *Config
	failed, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), typedNil)
	if text := assertNoDiagnosticCause(t, err); text != "netflow: invalid configuration" {
		t.Fatalf("typed-nil factory diagnostic=%q", text)
	}
	_ = failed // Failed creations are deliberately never shut down.
}

func TestConfigDiagnosticProjection(t *testing.T) {
	type tuple struct {
		code       mapping.ErrorCode
		path       string
		wantRule   string
		wantPath   string
		allocation bool
	}
	all := []tuple{
		{mapping.ErrCodeSelector, "mapping.fields", "compile_selector", "mapping.fields", false},
		{mapping.ErrCodeSelector, "mapping.selector", "compile_selector", "mapping.selector", false},
		{mapping.ErrCodeSelector, "mapping.fields.canonical", "compile_selector", "mapping.fields.canonical", false},
		{mapping.ErrCodeSelector, "mapping.fields.target", "compile_selector", "mapping.fields.target", false},
		{mapping.ErrCodeSchema, "mapping.schema", "compile_schema", "schema", false},
		{mapping.ErrCodeProfile, "mapping.profile", "compile_profile", "mapping.profile", false},
		{mapping.ErrCodePolicy, "mapping.loss_policy", "compile_policy", "mapping.loss_policy", false},
		{mapping.ErrCodeToken, "mapping.protocol_identifiers", "compile_token", "mapping.protocol_identifiers", false},
		{mapping.ErrCodeToken, "mapping.network_type_versions", "compile_token", "mapping.network_type_versions", false},
		{mapping.ErrCodeProvenance, "mapping.input_guarantees.flow_io_bytes", "compile_provenance", "mapping.input_guarantees.flow_io_bytes", false},
		{mapping.ErrCodeProvenance, "mapping.protocol_identifiers", "compile_provenance", "mapping.protocol_identifiers", false},
		{mapping.ErrCodeProvenance, "mapping.network_type_versions", "compile_provenance", "mapping.network_type_versions", false},
		{mapping.ErrCodeProvenance, "mapping.uptime_origin", "compile_provenance", "uptime_origin", false},
		{mapping.ErrCodeUnsupported, "mapping.profile", "compile_unsupported", "mapping.profile", false},
		{mapping.ErrCodeUnsupported, "mapping.fields", "compile_unsupported", "mapping.fields", false},
		{mapping.ErrCodeInapplicable, "mapping.fields", "compile_inapplicable", "mapping.fields", false},
		{mapping.ErrCodeCollision, "mapping.fields", "compile_collision", "mapping.fields", false},
		{mapping.ErrCodeCollision, "mapping.custom.source", "compile_collision", "mapping.custom.source", false},
		{mapping.ErrCodeCustom, "mapping.custom", "compile_custom", "mapping.custom", false},
		{mapping.ErrCodeCustom, "mapping.custom.source", "compile_custom", "mapping.custom.source", false},
		{mapping.ErrCodeCustom, "mapping.custom.encoding", "compile_custom", "mapping.custom.encoding", false},
		{mapping.ErrCodeCustom, "mapping.custom.fixed_length", "compile_custom", "mapping.custom.fixed_length", false},
		{mapping.ErrCodeCustom, "mapping.custom.length", "compile_custom", "mapping.custom.length", false},
		{mapping.ErrCodeCustom, "mapping.custom.max_length", "compile_custom", "mapping.custom.max_length", false},
		{mapping.ErrCodeBounds, "mapping.custom", "compile_bounds", "mapping.custom", false},
		{mapping.ErrCodeBounds, "mapping.custom.pen", "compile_bounds", "mapping.custom.pen", false},
		{mapping.ErrCodeBounds, "mapping.fields", "compile_bounds", "mapping.fields", false},
		{mapping.ErrCodeBounds, "mapping.shapes", "compile_bounds", "mapping.shapes", false},
		{mapping.ErrCodeBounds, "mapping.template", "compile_bounds", "mapping.template", false},
		{mapping.ErrCodeBounds, "mapping.record", "compile_bounds", "mapping.record", false},
		{mapping.ErrCodeBounds, "mapping.catalog", "compile_bounds", "mapping.catalog", false},
		{mapping.ErrCodeBounds, "max_datagram_size", "compile_bounds", "max_datagram_size", false},
		{mapping.ErrCodeBounds, "templates.id_base", "template_allocation", "templates.id_base", true},
		{mapping.ErrCodePMTU, "path_mtu", "compile_pmtu", "path_mtu", false},
		{mapping.ErrCodePMTU, "max_datagram_size", "compile_pmtu", "max_datagram_size", false},
	}
	if len(all) != 35 {
		t.Fatalf("projection tuple count=%d, want 35", len(all))
	}
	canaries := []string{strconv.FormatUint(0xBADC0FFEE0DDF00D, 10), strconv.FormatUint(0x13579BDF2468ACE0, 10), strconv.FormatUint(0xFEDCBA9876543210, 10)}
	checkProjection := func(t *testing.T, got error, tc tuple, protocol wire.Protocol) {
		t.Helper()
		text := assertNoDiagnosticCause(t, got)
		if tc.allocation && protocol == wire.ProtocolV5 {
			if text != "netflow: invalid configuration" {
				t.Fatalf("v5 allocation fallback=%q", text)
			}
			return
		}
		prefix := "netflow: invalid configuration: rule=" + tc.wantRule + " path=" + tc.wantPath + " protocol=" + protocol.String() + "; "
		if !strings.HasPrefix(text, prefix) {
			t.Fatalf("projection=%q want prefix %q", text, prefix)
		}
		for _, canary := range canaries {
			if strings.Contains(text, canary) {
				t.Fatalf("projection leaked numeric canary %q: %q", canary, text)
			}
		}
	}
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, tc := range all {
			t.Run(protocol.String()+"/"+tc.path, func(t *testing.T) {
				cause := &mapping.ConfigError{Code: tc.code, Protocol: protocol, Path: tc.path, Ordinal: 0xBADC0FFEE0DDF00D, Actual: 0x13579BDF2468ACE0, Limit: 0xFEDCBA9876543210}
				checkProjection(t, projectCompileError(cause, protocol), tc, protocol)
			})
		}
	}
	maxCause := &mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile", Ordinal: math.MaxUint64, Actual: math.MaxUint64, Limit: math.MaxUint64}
	maxText := assertNoDiagnosticCause(t, projectCompileError(maxCause, wire.ProtocolIPFIX))
	if strings.Contains(maxText, strconv.FormatUint(math.MaxUint64, 10)) {
		t.Fatalf("maximum numeric projection leaked: %q", maxText)
	}

	cause := &mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile", Ordinal: 0xBADC0FFEE0DDF00D}
	got := projectCompileError(cause, wire.ProtocolIPFIX)
	cause.Code, cause.Path, cause.Protocol, cause.Actual = mapping.ErrCodeInvalidConfig, "canary\x00path", wire.ProtocolV5, 0x13579BDF2468ACE0
	if got.Error() != "netflow: invalid configuration: rule=compile_profile path=mapping.profile protocol=ipfix; missing, unknown, or incompatible profile" {
		t.Fatalf("projection was not immutable: %q", got)
	}
	knownAfterMutation := &mapping.ConfigError{Code: mapping.ErrCodeInvalidConfig, Protocol: wire.ProtocolIPFIX, Path: "unknown"}
	knownAfterMutation.Code = mapping.ErrCodeProfile
	knownAfterMutation.Path = "mapping.profile"
	if text := assertNoDiagnosticCause(t, projectCompileError(knownAfterMutation, wire.ProtocolIPFIX)); !strings.Contains(text, "rule=compile_profile path=mapping.profile protocol=ipfix") {
		t.Fatalf("known tuple mutation fallback=%q", text)
	}
	for _, tc := range []struct {
		name  string
		set   func(*mapping.ConfigError)
		value uint64
	}{
		{"ordinal", func(c *mapping.ConfigError) { c.Ordinal = 0xBADC0FFEE0DDF00D }, 0xBADC0FFEE0DDF00D},
		{"actual", func(c *mapping.ConfigError) { c.Actual = 0x13579BDF2468ACE0 }, 0x13579BDF2468ACE0},
		{"limit", func(c *mapping.ConfigError) { c.Limit = 0xFEDCBA9876543210 }, 0xFEDCBA9876543210},
	} {
		t.Run("numeric_"+tc.name, func(t *testing.T) {
			cause := &mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"}
			tc.set(cause)
			text := assertNoDiagnosticCause(t, projectCompileError(cause, wire.ProtocolIPFIX))
			if strings.Contains(text, strconv.FormatUint(tc.value, 10)) {
				t.Fatalf("numeric %s canary leaked: %q", tc.name, text)
			}
		})
	}

	bad := []error{
		nil,
		&mapping.ConfigError{Code: mapping.ErrorCode(255), Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolUnknown, Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile.canary"},
		mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeInvalidConfig, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.fields"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolV9, Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.Protocol(99), Path: "mapping.profile"},
		&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: strings.Repeat("LONG-CONTROL\x00", 65536)},
		errors.New("raw compiler canary"),
		mapping.ErrCompile,
		transport.ErrResolverLookup,
		transport.ErrCandidatePMTU,
		&net.OpError{Op: "dial", Net: "udp", Err: errors.New("socket CANARY")},
		&net.DNSError{Name: "RESOLVER-NAME-CANARY", Err: "LOOKUP-CANARY"},
		&strconv.NumError{Func: "ParseUint", Num: "LIBRARY-CANARY", Err: strconv.ErrSyntax},
		fmt.Errorf("raw wrapper: %w", mapping.ErrCompile),
		fmt.Errorf("WRAPPER-CANARY: %w", &mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"}),
		errors.Join(&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"}, mapping.ErrCompile),
		errors.Join(cause, errors.New("joined canary")),
	}
	hostileCalls := 0
	bad = append(bad, hostileDiagnosticError{calls: &hostileCalls})
	var typedNil *mapping.ConfigError
	bad = append(bad, typedNil)
	for _, err := range bad {
		got := projectCompileError(err, wire.ProtocolIPFIX)
		if got.Error() != "netflow: invalid configuration" {
			t.Fatalf("unsafe projection=%q", got)
		}
		if errors.Unwrap(got) != nil || errors.Is(got, mapping.ErrCompile) {
			t.Fatalf("projection retained a cause: %q", got)
		}
		var mapped *mapping.ConfigError
		if errors.As(got, &mapped) {
			t.Fatalf("projection exposed ConfigError")
		}
	}
	if hostileCalls != 0 {
		t.Fatalf("projection invoked hostile error methods %d times", hostileCalls)
	}

	for _, protocol := range []wire.Protocol{wire.ProtocolUnknown, wire.Protocol(99)} {
		if got := projectCompileError(&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"}, protocol); got.Error() != "netflow: invalid configuration" {
			t.Fatalf("mismatched protocol projection=%q", got)
		}
		if got := projectCompileError(&mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: protocol, Path: "mapping.profile"}, protocol); got.Error() != "netflow: invalid configuration" {
			t.Fatalf("matching unknown protocol projection=%q", got)
		}
	}
	mutated := &mapping.ConfigError{Code: mapping.ErrCodeProfile, Protocol: wire.ProtocolIPFIX, Path: "mapping.profile"}
	mutated.Path = "MUTATED-UNKNOWN-CANARY\n"
	fallback := projectCompileError(mutated, wire.ProtocolIPFIX)
	mutated.Path = "mapping.profile"
	if text := assertNoDiagnosticCause(t, fallback); text != "netflow: invalid configuration" {
		t.Fatalf("fallback changed after input mutation: %q", text)
	}

	longest := 0
	for rule := diagnosticRule(1); rule < diagnosticRuleCount; rule++ {
		for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
			text := assertNoDiagnosticCause(t, renderDiagnostic(rule, protocol))
			if len(text) > longest {
				longest = len(text)
			}
		}
		_ = assertNoDiagnosticCause(t, diagnosticError(rule))
	}
	if longest == 0 || longest > 256 {
		t.Fatalf("renderer longest length=%d", longest)
	}
	t.Logf("projection tuples=%d protocols=%d; renderer variants=%d longest=%d bytes", len(all), 3, int(diagnosticRuleCount)-1, longest)
	if got := renderDiagnostic(diagnosticRuleCount, wire.ProtocolIPFIX); got.Error() != "netflow: invalid configuration" {
		t.Fatalf("unknown rule=%q", got)
	}
	if got := diagnosticError(diagnosticRuleCount); got.Error() != "netflow: invalid configuration" {
		t.Fatalf("unknown diagnostic rule=%q", got)
	}
	if got := renderDiagnostic(diagnosticTemplateAllocation, wire.ProtocolV5); got.Error() != "netflow: invalid configuration" {
		t.Fatalf("v5 allocation renderer=%q", got)
	}
	outer := fmt.Errorf("%s: %w", strings.Repeat("outer-context-", 32), renderDiagnostic(diagnosticCompileProfile, wire.ProtocolIPFIX))
	if len(outer.Error()) <= 256 || errors.Unwrap(outer) == nil {
		t.Fatalf("outer wrapper length/chain=%d/%v", len(outer.Error()), errors.Unwrap(outer))
	}
}

func TestPublicConfigDecodeRedaction(t *testing.T) {
	cases := []map[string]any{
		{"canary_root": "ROOT-CANARY"},
		{"mapping": map[string]any{"canary_nested": "NESTED-CANARY"}},
		{"identity": map[string]any{"source_id": "NUMERIC-CANARY"}},
		{"timeout": "not-a-duration-CANARY"},
	}
	for _, raw := range cases {
		c := validConfig("ipfix")
		err := c.Unmarshal(confmap.NewFromStringMap(raw))
		if err == nil || err.Error() != "netflow: invalid configuration" {
			t.Fatalf("direct decode raw=%#v err=%v", raw, err)
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("direct decode leaked input: %q", err)
		}

		c = validConfig("ipfix")
		err = confmap.NewFromStringMap(raw).Unmarshal(c)
		if err == nil || err.Error() != "'' netflow: invalid configuration" || len(err.Error()) != 33 || strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("Collector decode raw=%#v err=%v", raw, err)
		}
	}
	for _, raw := range []map[string]any{
		{"endpoint": 7},
		{"max_datagram_size": 1.5},
		{"max_datagram_size": -1},
		{"max_datagram_size": "NUMERIC-CANARY"},
		{"max_datagram_size": true},
		{"identity": map[string]any{"source_id": uint64(1) << 32}},
		{"identity": map[string]any{"source_id": -1}},
		{"identity": map[string]any{"source_id": 1.5}},
		{"identity": map[string]any{"source_id": true}},
		{"identity": map[string]any{"source_id": nil}},
		{"identity": nil},
		{"mapping": map[string]any{"profile": nil}},
		{"mapping": map[string]any{"protocol_identifiers": []any{map[string]any{"token": "HOPOPT-CANARY"}}}},
	} {
		c := validConfig("ipfix")
		err := c.Unmarshal(confmap.NewFromStringMap(raw))
		if err == nil || err.Error() != "netflow: invalid configuration" {
			t.Fatalf("strict direct decode raw=%#v err=%v", raw, err)
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("strict direct decode leaked input raw=%#v err=%v", raw, err)
		}
		c = validConfig("ipfix")
		err = confmap.NewFromStringMap(raw).Unmarshal(c)
		if err == nil || err.Error() != "'' netflow: invalid configuration" || len(err.Error()) != 33 {
			t.Fatalf("strict Collector decode raw=%#v err=%v", raw, err)
		}
	}
	var nilConfig *Config
	if err := nilConfig.Unmarshal(nil); err == nil || err.Error() != "netflow: invalid configuration" {
		t.Fatalf("nil direct receiver error=%v", err)
	}
	if err := validConfig("ipfix").Unmarshal(nil); err == nil || err.Error() != "netflow: invalid configuration" {
		t.Fatalf("nil direct conf error=%v", err)
	}
	if err := confmap.NewFromStringMap(map[string]any{}).Unmarshal(nilConfig); err == nil {
		t.Fatalf("nil Collector receiver should fail before component decode: %v", err)
	}

	c := validConfig("ipfix")
	originalEndpoint, originalSchema := c.Endpoint, c.Schema
	if err := c.Unmarshal(confmap.NewFromStringMap(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != originalEndpoint || c.Schema != originalSchema || c.Mapping.LossPolicy == nil {
		t.Fatal("empty valid decode did not preserve defaults/presence")
	}
	if err := confmap.NewFromStringMap(map[string]any{
		"identity": map[string]any{"observation_domain_id": 0},
		"timeout":  "1s",
		"path_mtu": nil,
		"ipfix":    map[string]any{"template_refresh_data_packets": nil},
	}).Unmarshal(c); err != nil {
		t.Fatal(err)
	}
	if c.Identity.ObservationDomainID == nil || *c.Identity.ObservationDomainID != 0 || c.Timeout != time.Second || c.PathMTU != nil || c.IPFIX.TemplateRefreshDataPackets != nil {
		t.Fatal("valid explicit zero/null decode did not preserve presence")
	}
	c = validConfig("ipfix")
	c.PathMTU, c.IPFIX.TemplateRefreshDataPackets = ptr(uint64(1500)), ptr(uint32(20))
	if err := c.Unmarshal(confmap.NewFromStringMap(map[string]any{"path_mtu": nil, "ipfix": map[string]any{"template_refresh_data_packets": nil}})); err != nil {
		t.Fatal(err)
	}
	if c.PathMTU != nil || c.IPFIX.TemplateRefreshDataPackets != nil {
		t.Fatal("direct null controls did not clear populated pointers")
	}
	for _, collector := range []bool{false, true} {
		t.Run(fmt.Sprintf("presence_collector_%t", collector), func(t *testing.T) {
			decode := func(c *Config, raw map[string]any) error {
				conf := confmap.NewFromStringMap(raw)
				if collector {
					return conf.Unmarshal(c)
				}
				return c.Unmarshal(conf)
			}
			c := validConfig("ipfix")
			c.Identity.ObservationDomainID = nil
			if err := decode(c, map[string]any{}); err != nil {
				t.Fatal(err)
			}
			assertPublicDiagnosticBoth(t, c, "rule=identity path=identity")
			c.PathMTU, c.IPFIX.TemplateRefreshDataPackets = ptr(uint64(1500)), ptr(uint32(20))
			if err := decode(c, map[string]any{
				"identity": map[string]any{"observation_domain_id": 0},
				"mapping":  map[string]any{"protocol_identifiers": []any{map[string]any{"token": "hopopt", "number": 0}}},
				"timeout":  "1s", "path_mtu": nil,
				"ipfix": map[string]any{"template_refresh_data_packets": nil},
			}); err != nil {
				t.Fatal(err)
			}
			if c.Identity.ObservationDomainID == nil || *c.Identity.ObservationDomainID != 0 || c.Timeout != time.Second || c.PathMTU != nil || c.IPFIX.TemplateRefreshDataPackets != nil || len(c.Mapping.ProtocolIdentifiers) != 1 || c.Mapping.ProtocolIdentifiers[0].Number != 0 {
				t.Fatal("decoded zero/presence/null controls were not preserved")
			}
			assertPublicValidBoth(t, c)
		})
	}
}

func TestConfigDiagnosticsNoIO(t *testing.T) {
	called := false
	failDial := func(context.Context, netip.AddrPort) (transport.Conn, error) {
		called = true
		return nil, errors.New("dial canary")
	}
	r, err := validConfig("ipfix").newRuntime(testclock.New(1_788_220_802_000_000_000, 0), failDial)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("configuration validation dialed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("runtime cleanup: %v", err)
	}
	hostname := validConfig("ipfix")
	hostname.Endpoint = "collector.example:4739"
	if err := hostname.Validate(); err != nil {
		t.Fatalf("hostname validation performed I/O or rejected construction: %v", err)
	}
	r, err = hostname.newRuntime(testclock.New(1_788_220_802_000_000_000, 0), failDial)
	if err != nil || called {
		t.Fatalf("hostname runtime construction err=%v dialed=%v", err, called)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("hostname runtime cleanup: %v", err)
	}
	cancel()
	if _, err := validConfig("ipfix").newRuntime(nil, failDial); err == nil || err.Error() != "netflow: invalid configuration" {
		t.Fatalf("nil clock late-constructor fallback=%v", err)
	}
	if _, err := validConfig("ipfix").newRuntime(testclock.New(1_788_220_802_000_000_000, 0), nil); err == nil || err.Error() != "netflow: invalid configuration" {
		t.Fatalf("nil dial late-constructor fallback=%v", err)
	}
	f := NewFactory()
	hostExporter, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), hostname)
	if err != nil {
		t.Fatalf("hostname factory construction: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	if err := hostExporter.Shutdown(ctx); err != nil {
		t.Fatalf("hostname factory cleanup: %v", err)
	}
	cancel()
	newTimer := func(time.Duration) transport.Timer {
		t.Fatal("configuration construction started a timer")
		return nil
	}
	logs, err := newLogsExporterWithTimer(context.Background(), exportertest.NewNopSettings(f.Type()), hostname, testclock.New(1_788_220_802_000_000_000, 0), failDial, newTimer)
	if err != nil || called {
		t.Fatalf("hostname exporter construction err=%v dialed=%v", err, called)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	if err := logs.Shutdown(ctx); err != nil {
		t.Fatalf("hostname exporter cleanup: %v", err)
	}
	cancel()

	c := validConfig("ipfix")
	c.Endpoint = "user@host:4739"
	if got := diagnosticText(t, c.Validate()); got != "netflow: invalid configuration" {
		t.Fatalf("late constructor error became specific: %q", got)
	}
}
