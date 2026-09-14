package mapping

import "github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"

const (
	SchemaContribNetflowReceiverV0160 = "contrib-netflowreceiver-v0.160.0"
	ProfileV5                         = SchemaContribNetflowReceiverV0160 + "/netflow-v5-fixed-v1"
	ProfileV9                         = SchemaContribNetflowReceiverV0160 + "/netflow-v9-core-v1"
	ProfileV9Timed                    = SchemaContribNetflowReceiverV0160 + "/netflow-v9-timed-v1"
	ProfileIPFIX                      = SchemaContribNetflowReceiverV0160 + "/ipfix-core-v1"
	ProfileIPFIXGeneral               = SchemaContribNetflowReceiverV0160 + "/ipfix-general-v1"
)

// LossPolicy controls whether an explicitly documented matrix loss is
// accepted.  Empty is deliberately invalid; there is no implicit policy.
type LossPolicy string

const (
	LossPolicyEncodeAndCount LossPolicy = "encode_and_count"
	LossPolicyReject         LossPolicy = "reject"
)

// FieldSelection is one ordered canonical selector. Canonical is the exact
// receiver key; Target is required only for the ambiguous matrix cells.
type FieldSelection struct {
	Canonical string `mapstructure:"canonical" json:"canonical" yaml:"canonical"`
	Target    string `mapstructure:"target" json:"target,omitempty" yaml:"target,omitempty"`
}

// ProtocolIdentifier is an exact receiver token to protocol-number pair.
type ProtocolIdentifier struct {
	Token  string `mapstructure:"token" json:"token" yaml:"token"`
	Number uint8  `mapstructure:"number" json:"number" yaml:"number"`
}

// NetworkTypeVersion is an exact receiver network.type token to IP-version
// pair. Only ipv4:4 and ipv6:6 are accepted.
type NetworkTypeVersion struct {
	Token   string `mapstructure:"token" json:"token" yaml:"token"`
	Version uint8  `mapstructure:"version" json:"version" yaml:"version"`
}

// InputGuarantees contains assertions about provenance that cannot safely be
// inferred from the canonical receiver value.
type InputGuarantees struct {
	FlowIOBytes string `mapstructure:"flow_io_bytes" json:"flow_io_bytes,omitempty" yaml:"flow_io_bytes,omitempty"`
}

// CustomField is the closed v9-private/IPFIX-enterprise grammar. Its source
// is an exact top-level attribute key and is looked up synchronously per
// record; it is never discovered dynamically. Pointer-valued grammar members
// preserve explicit false/zero values for direct Config callers as well as
// strict object decoders; nil means the member was omitted.
type CustomField struct {
	Source       string  `mapstructure:"source" json:"source" yaml:"source"`
	PEN          *uint32 `mapstructure:"pen" json:"pen,omitempty" yaml:"pen,omitempty"`
	ElementID    *uint32 `mapstructure:"element_id" json:"element_id,omitempty" yaml:"element_id,omitempty"`
	FieldType    *uint32 `mapstructure:"field_type" json:"field_type,omitempty" yaml:"field_type,omitempty"`
	Encoding     string  `mapstructure:"encoding" json:"encoding" yaml:"encoding"`
	FixedLength  *uint16 `mapstructure:"fixed_length" json:"fixed_length,omitempty" yaml:"fixed_length,omitempty"`
	Variable     *bool   `mapstructure:"variable" json:"variable,omitempty" yaml:"variable,omitempty"`
	MaxLength    *uint32 `mapstructure:"max_length" json:"max_length,omitempty" yaml:"max_length,omitempty"`
	AllowPrivate *bool   `mapstructure:"allow_private" json:"allow_private,omitempty" yaml:"allow_private,omitempty"`
}

// Config is the mapping-owned compiler boundary. A nil Fields slice means
// the fields selector is absent; a non-nil empty slice (or FieldsSet) is an
// explicit empty selector and is rejected. Zero-valued optional numeric
// settings select documented defaults.
type Config struct {
	Schema    string           `json:"schema,omitempty" yaml:"schema,omitempty"`
	Protocol  wire.Protocol    `json:"protocol" yaml:"protocol"`
	Profile   string           `json:"profile,omitempty" yaml:"profile,omitempty"`
	Fields    []FieldSelection `json:"fields,omitempty" yaml:"fields,omitempty"`
	FieldsSet bool             `json:"-" yaml:"-"`

	ProtocolIdentifiers []ProtocolIdentifier `json:"protocol_identifiers,omitempty" yaml:"protocol_identifiers,omitempty"`
	NetworkTypeVersions []NetworkTypeVersion `json:"network_type_versions,omitempty" yaml:"network_type_versions,omitempty"`
	InputGuarantees     InputGuarantees      `json:"input_guarantees,omitempty" yaml:"input_guarantees,omitempty"`
	LossPolicy          LossPolicy           `json:"loss_policy" yaml:"loss_policy"`
	Custom              []CustomField        `json:"custom,omitempty" yaml:"custom,omitempty"`

	IDBase               uint32      `json:"id_base,omitempty" yaml:"id_base,omitempty"`
	MaxDatagramSize      uint64      `json:"max_datagram_size,omitempty" yaml:"max_datagram_size,omitempty"`
	PathMTU              uint64      `json:"path_mtu,omitempty" yaml:"path_mtu,omitempty"`
	Endpoint             string      `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	MaxAttributeKeyBytes uint64      `json:"max_attribute_key_bytes,omitempty" yaml:"max_attribute_key_bytes,omitempty"`
	MaxMappedValueBytes  uint64      `json:"max_mapped_value_bytes,omitempty" yaml:"max_mapped_value_bytes,omitempty"`
	Limits               wire.Limits `json:"limits,omitempty" yaml:"limits,omitempty"`

	HasUptimeOrigin       bool   `json:"has_uptime_origin,omitempty" yaml:"has_uptime_origin,omitempty"`
	UptimeOriginUnixNanos uint64 `json:"uptime_origin_unix_nanos,omitempty" yaml:"uptime_origin_unix_nanos,omitempty"`
}

// DefaultConfig returns an intentionally unselectable configuration. The
// caller must supply exactly one profile or nonempty fields and a loss policy.
func DefaultConfig() Config { return Config{Schema: SchemaContribNetflowReceiverV0160} }

// Validate checks the complete static mapping contract without exposing a
// partially compiled value to the caller.
func (config Config) Validate() error {
	_, err := Compile(config)
	return err
}
