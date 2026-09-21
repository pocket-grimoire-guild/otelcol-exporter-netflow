package netflowexporter

import (
	"context"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }
func validConfig(protocol string) *Config {
	c := createDefaultConfig().(*Config)
	c.Endpoint = "127.0.0.1:4739"
	c.Protocol = protocol
	c.Mapping.LossPolicy = ptr(mapping.LossPolicyEncodeAndCount)
	c.Mapping.ProtocolIdentifiers = []ProtocolIdentifier{{Token: "tcp", Number: 6}}
	switch protocol {
	case "netflow_v5":
		c.Mapping.Profile = ptr(mapping.ProfileV5)
		c.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		c.Identity.EngineType = ptr(uint8(0))
		c.Identity.EngineID = ptr(uint8(0))
		c.UptimeOrigin = ptr(uint64(1788220800000000000))
	case "netflow_v9":
		c.Mapping.Profile = ptr(mapping.ProfileV9)
		c.Identity.SourceID = ptr(uint32(0))
	case "ipfix":
		c.Mapping.Profile = ptr(mapping.ProfileIPFIX)
		c.Identity.ObservationDomainID = ptr(uint32(0))
	}
	if protocol != "netflow_v5" {
		c.Mapping.NetworkTypeVersions = []NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	return c
}
func TestConfig(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			if err := validConfig(protocol).Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if createDefaultConfig().(*Config).Validate() == nil {
		t.Fatal("default silently selected a mapping")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"protocol", func(c *Config) { c.Protocol = "sflow" }, "rule=protocol path=protocol"},
		{"schema", func(c *Config) { c.Schema = "latest" }, "rule=schema path=schema"},
		{"identity_absent", func(c *Config) { c.Identity.ObservationDomainID = nil }, "rule=identity path=identity"},
		{"inactive_zero_identity", func(c *Config) { c.Identity.SourceID = ptr(uint32(0)) }, "rule=identity path=identity"},
		{"both_selectors", func(c *Config) { c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}}) }, "rule=mapping path=mapping"},
		{"no_selector", func(c *Config) { c.Mapping.Profile = nil }, "rule=mapping path=mapping"},
		{"empty_profile", func(c *Config) { c.Mapping.Profile = ptr("") }, "rule=mapping path=mapping"},
		{"empty_fields", func(c *Config) { c.Mapping.Profile = nil; c.Mapping.Fields = ptr([]FieldSelection{}) }, "rule=mapping path=mapping"},
		{"wrong_profile", func(c *Config) { c.Mapping.Profile = ptr(mapping.ProfileV9) }, "rule=compile_profile path=mapping.profile protocol=ipfix"},
		{"no_policy", func(c *Config) { c.Mapping.LossPolicy = nil }, "rule=mapping_policy_required path=mapping.loss_policy"},
		{"loss_unacknowledged", func(c *Config) { c.Mapping.LossPolicy = ptr(mapping.LossPolicyReject) }, "rule=compile_policy path=mapping.loss_policy protocol=ipfix"},
		{"token_mismatch", func(c *Config) { c.Mapping.ProtocolIdentifiers[0].Number = 7 }, "rule=compile_token path=mapping.protocol_identifiers protocol=ipfix"},
		{"family_map", func(c *Config) { c.Mapping.NetworkTypeVersions = nil }, "rule=compile_provenance path=mapping.network_type_versions protocol=ipfix"},
		{"queue", func(c *Config) { c.SendingQueue.Enabled = true }, "rule=queue path=sending_queue.enabled"},
		{"retry", func(c *Config) { c.RetryOnFailure.Enabled = true }, "rule=retry path=retry_on_failure.enabled"},
		{"payload_zero", func(c *Config) { c.MaxDatagramSize = 0 }, "rule=max_datagram_size path=max_datagram_size"},
		{"payload_unasserted", func(c *Config) { c.MaxDatagramSize = 465 }, "rule=compile_pmtu path=path_mtu protocol=ipfix"},
		{"payload_max", func(c *Config) { c.MaxDatagramSize = 65508 }, "rule=max_datagram_size path=max_datagram_size"},
		{"mtu_zero", func(c *Config) { c.PathMTU = ptr(uint64(0)) }, "rule=path_mtu_range path=path_mtu"},
		{"hostname_mtu", func(c *Config) {
			c.Endpoint = "collector.example:4739"
			c.PathMTU = ptr(uint64(512))
			c.MaxDatagramSize = 465
		}, "rule=compile_pmtu path=max_datagram_size protocol=ipfix"},
		{"record_zero", func(c *Config) { c.MaxRecordsPerMessage = ptr(uint16(0)) }, "rule=record_limit path=max_records_per_message"},
		{"record_max", func(c *Config) { c.MaxRecordsPerMessage = ptr(uint16(1025)) }, "rule=record_limit path=max_records_per_message"},
		{"template_id", func(c *Config) { c.Templates.IDBase = 65535 }, "rule=template_allocation path=templates.id_base protocol=ipfix"},
		{"copies_zero", func(c *Config) { c.Templates.InitialCopies = 0 }, "rule=template_initial_copies path=templates.initial_copies"},
		{"refresh_zero", func(c *Config) { c.Templates.RefreshInterval = 0 }, "rule=template_refresh_interval path=templates.refresh_interval"},
		{"count_zero", func(c *Config) { c.IPFIX.TemplateRefreshDataPackets = ptr(uint32(0)) }, "rule=ipfix_refresh_packets path=ipfix.template_refresh_data_packets"},
		{"inactive_count", func(c *Config) { c.NetFlowV9.TemplateRefreshPackets = ptr(uint32(20)) }, "rule=v9_refresh_packets path=netflow_v9.template_refresh_packets"},
		{"timeout_zero", func(c *Config) { c.Timeout = 0 }, "rule=write_timeout_range path=timeout"},
		{"timeout_drain", func(c *Config) { c.Timeout = 6 * time.Second }, "rule=write_timeout_drain path=timeout"},
		{"drain_zero", func(c *Config) { c.ShutdownDrainTimeout = 0 }, "rule=write_timeout_drain path=timeout"},
		{"dns_timeout", func(c *Config) { c.DNS.Timeout = 6 * time.Second }, "rule=dns_timeout_drain path=dns.timeout"},
		{"dns_refresh", func(c *Config) { c.DNS.RefreshInterval = 0 }, "rule=dns_refresh_range path=dns.refresh_interval"},
		{"dns_stale", func(c *Config) { c.DNS.StaleAfter = time.Second }, "rule=dns_stale_refresh path=dns.stale_after"},
		{"inactive_uptime", func(c *Config) { c.UptimeOrigin = ptr(uint64(0)) }, "rule=identity path=identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			tc.mutate(c)
			_, err := c.newRuntime(testclock.New(1788220802000000000, 0), func(context.Context, netip.AddrPort) (transport.Conn, error) {
				t.Fatal("validation dialed")
				return nil, nil
			})
			if err == nil {
				t.Fatal("accepted invalid config")
			}
			if !strings.Contains(err.Error(), tc.want+"; ") {
				t.Fatalf("diagnostic=%q want %q", err, tc.want)
			}
		})
	}
	for _, endpoint := range []string{"", "udp://host:4739", "host:0", "host:-1", "host:+1", "host:65536", "host:netflow", "user@host:4739", "host:4739/path", "[fe80::1%eth0]:4739", "127.0.0.1:4739\n"} {
		c := validConfig("ipfix")
		c.Endpoint = endpoint
		if c.Validate() == nil {
			t.Fatalf("endpoint accepted: %q", endpoint)
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Mapping.Custom = []CustomField{} }, func(c *Config) { c.MaxRecordsPerMessage = ptr(uint16(31)) }, func(c *Config) { c.UptimeOrigin = nil }, func(c *Config) { c.Identity.SamplingMode = ptr(uint8(4)) }, func(c *Config) { c.UptimeOrigin = ptr(uint64(math.MaxInt64) + 1) }} {
		c := validConfig("netflow_v5")
		mutate(c)
		if c.Validate() == nil {
			t.Fatal("invalid v5 accepted")
		}
	}
}

func TestTemplateRefreshIntervalBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value time.Duration
		valid bool
	}{
		{"below_minimum", 30*time.Second - time.Nanosecond, false},
		{"minimum", 30 * time.Second, true},
		{"one_minute", time.Minute, true},
		{"default", 10 * time.Minute, true},
		{"maximum", 24 * time.Hour, true},
		{"above_maximum", 24*time.Hour + time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig("ipfix")
			c.Templates.RefreshInterval = tc.value
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("refresh interval %v valid=%v err=%v", tc.value, tc.valid, err)
			}
		})
	}

	defaults := createDefaultConfig().(*Config)
	if defaults.Templates.RefreshInterval != 10*time.Minute {
		t.Fatalf("public default refresh interval=%v, want 10m", defaults.Templates.RefreshInterval)
	}
	zero := validConfig("ipfix")
	zero.Templates.RefreshInterval = 0
	if err := zero.Validate(); err == nil {
		t.Fatal("public zero refresh interval accepted")
	}
}

func TestTimedV9ProfileRequiresOrigin(t *testing.T) {
	configured := validConfig("netflow_v9")
	configured.Mapping.Profile = ptr(mapping.ProfileV9Timed)
	configured.UptimeOrigin = ptr(uint64(1_788_220_800_000_000_000))
	if err := configured.Validate(); err != nil {
		t.Fatalf("timed v9 config rejected: %v", err)
	}
	configured.UptimeOrigin = nil
	if err := configured.Validate(); err == nil {
		t.Fatal("timed v9 config accepted without explicit uptime origin")
	}
	core := validConfig("netflow_v9")
	if err := core.Validate(); err != nil {
		t.Fatalf("time-free v9 core config rejected: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for _, tc := range []map[string]any{
		{"unknown": "secret"}, {"limits": map[string]any{"max_records_per_request": 8192}}, {"identity": map[string]any{"engine_type": 256}}, {"identity": map[string]any{"source_id": uint64(1) << 32}},
		{"identity": map[string]any{"source_id": -1}}, {"identity": map[string]any{"source_id": 1.5}}, {"identity": map[string]any{"source_id": "1"}},
		{"identity": map[string]any{"source_id": nil}}, {"mapping": map[string]any{"profile": nil}}, {"mapping": map[string]any{"fields": nil}},
		{"mapping": map[string]any{"fields": []any{"source.port"}}}, {"mapping": map[string]any{"custom": []any{map[string]any{"pen": nil}}}},
		{"mapping": map[string]any{"protocol_identifiers": []any{map[string]any{"token": "tcp", "number": 262}}}},
		{"mapping": map[string]any{"custom": []any{map[string]any{"field_type": uint64(1) << 32}}}},
		{"mapping": map[string]any{"custom": []any{map[string]any{"fixed_length": 65536}}}},
		{"sending_queue": map[string]any{"enabled": false, "queue_size": 1}}, {"retry_on_failure": map[string]any{"enabled": false, "max_elapsed_time": "1s"}},
		{"batch": map[string]any{}}, {"storage": "secret"}, {"wait_for_result": true}, {"Timeout": "1s"}, {"limits": map[string]any{"max_value_depth": nil}},
	} {
		c := validConfig("ipfix")
		err := confmap.NewFromStringMap(tc).Unmarshal(c)
		if err == nil {
			t.Fatalf("decoded invalid config: %#v", tc)
		}
	}
	c := validConfig("ipfix")
	if err := confmap.NewFromStringMap(map[string]any{"identity": map[string]any{"observation_domain_id": 0}, "timeout": "1s", "path_mtu": nil, "ipfix": map[string]any{"template_refresh_data_packets": nil}}).Unmarshal(c); err != nil {
		t.Fatal(err)
	}
	if c.Identity.ObservationDomainID == nil || *c.Identity.ObservationDomainID != 0 || c.Timeout != time.Second {
		t.Fatal("explicit zero or duration lost")
	}
}
func TestMetadata(t *testing.T) {
	conf, err := confmaptest.LoadConf("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := conf.Sub("tests::config")
	if err != nil {
		t.Fatal(err)
	}
	c := createDefaultConfig().(*Config)
	if err := sub.Unmarshal(c); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigExplicitNullControls(t *testing.T) {
	c := validConfig("ipfix")
	c.PathMTU = ptr(uint64(1500))
	c.IPFIX.TemplateRefreshDataPackets = ptr(uint32(20))
	raw := confmap.NewFromStringMap(map[string]any{"path_mtu": nil, "ipfix": map[string]any{"template_refresh_data_packets": nil}})
	if err := raw.Unmarshal(c); err != nil {
		t.Fatal(err)
	}
	if c.PathMTU != nil || c.IPFIX.TemplateRefreshDataPackets != nil {
		t.Fatal("null did not disable control")
	}
	if err := confmap.NewFromStringMap(map[string]any{"mapping": map[string]any{"protocol_identifiers": []any{map[string]any{"token": "hopopt"}}}}).Unmarshal(c); err == nil {
		t.Fatal("implicit number zero")
	}
}
