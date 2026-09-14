package netflowexporter

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/component"
)

// Config selects one UDP destination and an explicit, immutable mapping.
// Obtain defaults from NewFactory().CreateDefaultConfig() before overriding
// fields. Pointer fields distinguish absence from an explicit zero or empty value.
type Config struct {
	Endpoint             string         `mapstructure:"endpoint"`
	Protocol             string         `mapstructure:"protocol"`
	Schema               string         `mapstructure:"schema"`
	Identity             IdentityConfig `mapstructure:"identity"`
	Mapping              MappingConfig  `mapstructure:"mapping"`
	Templates            TemplateConfig `mapstructure:"templates"`
	NetFlowV9            V9Config       `mapstructure:"netflow_v9"`
	IPFIX                IPFIXConfig    `mapstructure:"ipfix"`
	UptimeOrigin         *uint64        `mapstructure:"uptime_origin"`
	MaxDatagramSize      uint64         `mapstructure:"max_datagram_size"`
	PathMTU              *uint64        `mapstructure:"path_mtu"`
	MaxRecordsPerMessage *uint16        `mapstructure:"max_records_per_message"`
	Timeout              time.Duration  `mapstructure:"timeout"`
	ShutdownDrainTimeout time.Duration  `mapstructure:"shutdown_drain_timeout"`
	DNS                  DNSConfig      `mapstructure:"dns"`
	SendingQueue         DisabledConfig `mapstructure:"sending_queue"`
	RetryOnFailure       DisabledConfig `mapstructure:"retry_on_failure"`
}

type IdentityConfig struct {
	ObservationDomainID *uint32 `mapstructure:"observation_domain_id"`
	SourceID            *uint32 `mapstructure:"source_id"`
	EngineType          *uint8  `mapstructure:"engine_type"`
	EngineID            *uint8  `mapstructure:"engine_id"`
	SamplingMode        *uint8  `mapstructure:"sampling_mode"`
}

type MappingConfig struct {
	Profile             *string              `mapstructure:"profile"`
	Fields              *[]FieldSelection    `mapstructure:"fields"`
	ProtocolIdentifiers []ProtocolIdentifier `mapstructure:"protocol_identifiers"`
	NetworkTypeVersions []NetworkTypeVersion `mapstructure:"network_type_versions"`
	InputGuarantees     InputGuarantees      `mapstructure:"input_guarantees"`
	LossPolicy          *LossPolicy          `mapstructure:"loss_policy"`
	Custom              []CustomField        `mapstructure:"custom"`
}

// These aliases expose the closed compiler grammar to component callers.
type FieldSelection = mapping.FieldSelection
type ProtocolIdentifier = mapping.ProtocolIdentifier
type NetworkTypeVersion = mapping.NetworkTypeVersion
type InputGuarantees = mapping.InputGuarantees
type LossPolicy = mapping.LossPolicy
type CustomField = mapping.CustomField
type TemplateConfig struct {
	IDBase          uint32        `mapstructure:"id_base"`
	InitialCopies   uint8         `mapstructure:"initial_copies"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
}
type V9Config struct {
	TemplateRefreshPackets *uint32 `mapstructure:"template_refresh_packets"`
}
type IPFIXConfig struct {
	TemplateRefreshDataPackets *uint32 `mapstructure:"template_refresh_data_packets"`
}
type DNSConfig struct {
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
	StaleAfter      time.Duration `mapstructure:"stale_after"`
	Timeout         time.Duration `mapstructure:"timeout"`
}

// DisabledConfig deliberately accepts no queue, retry, persistence or batching options.
type DisabledConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Schema:          mapping.SchemaContribNetflowReceiverV0160,
		Templates:       TemplateConfig{IDBase: 256, InitialCopies: 2, RefreshInterval: 10 * time.Minute},
		MaxDatagramSize: 464, Timeout: 5 * time.Second, ShutdownDrainTimeout: 5 * time.Second,
		DNS: DNSConfig{RefreshInterval: 5 * time.Minute, StaleAfter: time.Hour, Timeout: 5 * time.Second},
	}
}

// Validate performs all compilation and cross-field checks without DNS or sockets.
func (c *Config) Validate() error {
	_, err := c.newRuntime(transport.NewClock(), transport.NewDialer("udp", netip.AddrPort{}).Dial)
	return err
}

func configError() error { return errors.New("netflow: invalid configuration") }

func (c *Config) newRuntime(clock transport.Clock, dial transport.NumericDial) (*destination.Runtime, error) {
	return c.newRuntimeWithObserver(clock, dial, nil)
}

func (c *Config) newRuntimeWithObserver(clock transport.Clock, dial transport.NumericDial, observe destination.Observer) (*destination.Runtime, error) {
	if c == nil || c.SendingQueue.Enabled || c.RetryOnFailure.Enabled ||
		c.Schema != mapping.SchemaContribNetflowReceiverV0160 || len(c.Endpoint) < 1 || len(c.Endpoint) > 512 {
		return nil, configError()
	}
	host, portText, err := net.SplitHostPort(c.Endpoint)
	if err != nil || len(portText) == 0 {
		return nil, configError()
	}
	for _, ch := range portText {
		if ch < '0' || ch > '9' {
			return nil, configError()
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, configError()
	}
	var protocol wire.Protocol
	var writer wire.ContractWriter
	switch c.Protocol {
	case "netflow_v5":
		protocol, writer = wire.ProtocolV5, netflow5.NewWriter()
	case "netflow_v9":
		protocol, writer = wire.ProtocolV9, netflow9.NewWriter()
	case "ipfix":
		protocol, writer = wire.ProtocolIPFIX, ipfix.NewWriter()
	default:
		return nil, configError()
	}
	s := destination.DefaultConfig(protocol)
	id := c.Identity
	switch protocol {
	case wire.ProtocolV5:
		if id.EngineType == nil || id.EngineID == nil || id.SourceID != nil || id.ObservationDomainID != nil || c.UptimeOrigin == nil {
			return nil, configError()
		}
		s.EngineType, s.EngineID = *id.EngineType, *id.EngineID
		if id.SamplingMode != nil {
			if *id.SamplingMode > 3 {
				return nil, configError()
			}
			s.SamplingMode = *id.SamplingMode
		}
	case wire.ProtocolV9:
		if id.SourceID == nil || id.ObservationDomainID != nil || id.EngineType != nil || id.EngineID != nil || id.SamplingMode != nil {
			return nil, configError()
		}
		s.SourceID = *id.SourceID
	case wire.ProtocolIPFIX:
		if id.ObservationDomainID == nil || id.SourceID != nil || id.EngineType != nil || id.EngineID != nil || id.SamplingMode != nil || c.UptimeOrigin != nil {
			return nil, configError()
		}
		s.ObservationDomainID = *id.ObservationDomainID
	}
	if c.UptimeOrigin != nil {
		if *c.UptimeOrigin > math.MaxInt64 {
			return nil, configError()
		}
		s.HasUptimeOrigin, s.UptimeOriginUnixNanos = true, *c.UptimeOrigin
	}
	if c.MaxDatagramSize < 128 || c.MaxDatagramSize > 65507 || c.Templates.IDBase < 256 || c.Templates.IDBase > 65535 ||
		c.Templates.InitialCopies < 2 || c.Templates.InitialCopies > 8 || c.Templates.RefreshInterval < 30*time.Second || c.Templates.RefreshInterval > 24*time.Hour ||
		c.Timeout < 100*time.Millisecond || c.Timeout > 30*time.Second || c.Timeout > c.ShutdownDrainTimeout ||
		c.ShutdownDrainTimeout < time.Second || c.ShutdownDrainTimeout > 30*time.Second ||
		c.DNS.Timeout < 100*time.Millisecond || c.DNS.Timeout > 30*time.Second || c.DNS.Timeout > c.ShutdownDrainTimeout ||
		c.DNS.RefreshInterval < time.Second || c.DNS.RefreshInterval > 24*time.Hour || c.DNS.StaleAfter < c.DNS.RefreshInterval || c.DNS.StaleAfter > 7*24*time.Hour {
		return nil, configError()
	}
	if c.MaxRecordsPerMessage != nil {
		if *c.MaxRecordsPerMessage < 1 || *c.MaxRecordsPerMessage > 1024 || (protocol == wire.ProtocolV5 && *c.MaxRecordsPerMessage > 30) {
			return nil, configError()
		}
		s.MaxRecordsPerMessage = *c.MaxRecordsPerMessage
	}
	if n := c.NetFlowV9.TemplateRefreshPackets; n != nil {
		if protocol != wire.ProtocolV9 || *n < 1 || *n > 1000 {
			return nil, configError()
		}
		s.V9RefreshPacketCount = *n
	}
	if n := c.IPFIX.TemplateRefreshDataPackets; n != nil {
		if protocol != wire.ProtocolIPFIX || *n < 1 || *n > 1000 {
			return nil, configError()
		}
		s.IPFIXDataMessageRefreshCount = *n
	}
	m := c.Mapping
	if (m.Profile == nil) == (m.Fields == nil) || m.LossPolicy == nil || (m.Profile != nil && *m.Profile == "") || (m.Fields != nil && len(*m.Fields) == 0) {
		return nil, configError()
	}
	mc := mapping.Config{Schema: c.Schema, Protocol: protocol, ProtocolIdentifiers: m.ProtocolIdentifiers, NetworkTypeVersions: m.NetworkTypeVersions,
		InputGuarantees: m.InputGuarantees, LossPolicy: *m.LossPolicy, Custom: m.Custom, IDBase: c.Templates.IDBase, MaxDatagramSize: c.MaxDatagramSize,
		Endpoint:        c.Endpoint,
		HasUptimeOrigin: s.HasUptimeOrigin, UptimeOriginUnixNanos: s.UptimeOriginUnixNanos}
	if m.Profile != nil {
		mc.Profile = *m.Profile
	}
	if protocol == wire.ProtocolV5 {
		mc.IDBase = 0 // v5 has no template IDs
	}
	if m.Fields != nil {
		mc.Fields = *m.Fields
		mc.FieldsSet = true
	}
	if c.PathMTU != nil {
		if *c.PathMTU < 512 || *c.PathMTU > 65535 {
			return nil, configError()
		}
		mc.PathMTU = *c.PathMTU
	}
	compiled, err := mapping.Compile(mc)
	if err != nil {
		return nil, configError()
	}
	resolver, err := transport.NewResolver("udp", host, c.DNS.Timeout)
	if err != nil {
		return nil, configError()
	}
	dialer, err := transport.NewCandidateDialer(resolver, uint16(port), c.MaxDatagramSize, compiled.MaxDatagramSize(), mc.PathMTU, dial, c.Timeout)
	if err != nil {
		return nil, configError()
	}
	s.MaxDatagramSize, s.InitialCopies, s.RefreshInterval = c.MaxDatagramSize, c.Templates.InitialCopies, c.Templates.RefreshInterval
	if protocol != wire.ProtocolIPFIX && clock != nil {
		clock = millisecondClock{clock: clock, origin: s.UptimeOriginUnixNanos, checkUptime: s.HasUptimeOrigin}
	}
	r, err := destination.NewRuntime(compiled, writer, destination.RuntimeConfig{State: s, DNSRefresh: c.DNS.RefreshInterval, Observe: observe,
		DNSStaleAfter: c.DNS.StaleAfter, ShutdownDrainTimeout: c.ShutdownDrainTimeout}, dialer, clock)
	if err != nil {
		return nil, configError()
	}
	return r, nil
}
