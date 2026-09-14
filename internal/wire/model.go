// Package wire contains the protocol-independent boundary shared by the
// focused NetFlow and IPFIX writers.  The package deliberately has no
// Collector, OTel, clock, or transport dependency.
package wire

import (
	"math"
	"net"
	"net/netip"
	"unicode/utf8"
)

// Protocol identifies one of the wire formats supported by the exporter.
type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolV5
	ProtocolV9
	ProtocolIPFIX
)

// Short aliases are convenient at protocol-specific call sites.
const (
	V5    = ProtocolV5
	V9    = ProtocolV9
	IPFIX = ProtocolIPFIX
)

const (
	ProtocolNetFlowV5 = ProtocolV5
	ProtocolNetFlowV9 = ProtocolV9
)

func (p Protocol) String() string {
	switch p {
	case ProtocolV5:
		return "v5"
	case ProtocolV9:
		return "v9"
	case ProtocolIPFIX:
		return "ipfix"
	default:
		return "unknown"
	}
}

// Family is the address family selected during normalization.  It is never
// inferred by a wire writer from a protocol or from a textual token.
type Family uint8

const (
	FamilyUnknown Family = iota
	FamilyIPv4
	FamilyIPv6
)

const (
	IPv4 = FamilyIPv4
	IPv6 = FamilyIPv6
)

func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// CanonicalField names the bounded canonical receiver view.  The first 41
// values mirror the pinned receiver schema; FlowICMPTypeCode is the sole
// virtual selector permitted by the static mapping contract.
type CanonicalField uint8

const FieldInvalid CanonicalField = ^CanonicalField(0)

const (
	FieldSourceAddress CanonicalField = iota
	FieldSourcePort
	FieldDestinationAddress
	FieldDestinationPort
	FieldNetworkTransport
	FieldNetworkType
	FieldFlowIOBytes
	FieldFlowIOPackets
	FieldFlowType
	FieldFlowSequenceNum
	FieldFlowTimeReceived
	FieldFlowStart
	FieldFlowEnd
	FieldFlowSamplingRate
	FieldFlowSamplerAddress
	FieldFlowTCPFlags
	FieldFlowInIf
	FieldFlowOutIf
	FieldFlowIPTOS
	FieldFlowIPTTL
	FieldFlowIPFlags
	FieldFlowFragmentID
	FieldFlowFragmentOffset
	FieldFlowIPv6FlowLabel
	FieldFlowICMPType
	FieldFlowICMPCode
	FieldFlowSrcMAC
	FieldFlowDstMAC
	FieldFlowSrcVLAN
	FieldFlowDstVLAN
	FieldFlowVLANID
	FieldFlowNextHop
	FieldFlowNextHopAS
	FieldFlowSrcAS
	FieldFlowDstAS
	FieldFlowBGPNextHop
	FieldFlowSrcNet
	FieldFlowDstNet
	FieldFlowForwardingStatus
	FieldFlowObservationDomainID
	FieldFlowObservationPointID
	FieldFlowICMPTypeCode
)

const (
	// CanonicalFieldCount is the number of fields in the pinned receiver
	// schema.  The virtual composite is intentionally not included.
	CanonicalFieldCount     = int(FieldFlowObservationPointID) + 1
	MaxNormalizedValues     = 128
	MaxNormalizedValueBytes = 1 << 20
)

var canonicalNames = [...]string{
	"source.address",
	"source.port",
	"destination.address",
	"destination.port",
	"network.transport",
	"network.type",
	"flow.io.bytes",
	"flow.io.packets",
	"flow.type",
	"flow.sequence_num",
	"flow.time_received",
	"flow.start",
	"flow.end",
	"flow.sampling_rate",
	"flow.sampler_address",
	"flow.tcp_flags",
	"flow.in_if",
	"flow.out_if",
	"flow.ip_tos",
	"flow.ip_ttl",
	"flow.ip_flags",
	"flow.fragment_id",
	"flow.fragment_offset",
	"flow.ipv6_flow_label",
	"flow.icmp_type",
	"flow.icmp_code",
	"flow.src_mac",
	"flow.dst_mac",
	"flow.src_vlan",
	"flow.dst_vlan",
	"flow.vlan_id",
	"flow.next_hop",
	"flow.next_hop_as",
	"flow.src_as",
	"flow.dst_as",
	"flow.bgp_next_hop",
	"flow.src_net",
	"flow.dst_net",
	"flow.forwarding_status",
	"flow.observation_domain_id",
	"flow.observation_point_id",
}

// CanonicalName returns the exact pinned receiver key.  Unknown IDs return an
// empty string (the virtual composite is intentionally included).
func (f CanonicalField) CanonicalName() string {
	if int(f) < len(canonicalNames) {
		return canonicalNames[f]
	}
	if f == FieldFlowICMPTypeCode {
		return "flow.icmp_type_code"
	}
	return ""
}

// Valid reports whether f is one of the 41 canonical fields or the virtual
// v9 ICMP composite.
func (f CanonicalField) Valid() bool {
	return int(f) < CanonicalFieldCount || f == FieldFlowICMPTypeCode
}

// ValueKind identifies the representation held in a normalized Value.
type ValueKind uint8

const (
	ValueInvalid ValueKind = iota
	ValueInt
	ValueUint
	ValueString
	ValueBytes
	ValueIP
	ValueMAC
	ValueUnixNanos
)

const (
	ValueIPAddress     = ValueIP
	ValueMACAddress    = ValueMAC
	ValueTimeUnixNanos = ValueUnixNanos
)

// Value is the small, OTel-independent union used by a normalized record.
// Owned payloads are immutable strings; the explicit BorrowedBytesValue path
// instead borrows a stable read-only view for one synchronous mapping/write.
// Parsed IP/MAC values and Unix nanoseconds stay in fixed-size fields. Writer
// accessors allocate no payload and expose no mutable byte slices.
type Value struct {
	kind      ValueKind
	intValue  int64
	uintValue uint64
	text      string
	octets    string
	octetsSet bool
	borrowed  ByteView
	ip        netip.Addr
	mac       [6]byte
}

func IntValue(v int64) Value     { return Value{kind: ValueInt, intValue: v} }
func UintValue(v uint64) Value   { return Value{kind: ValueUint, uintValue: v} }
func StringValue(v string) Value { return Value{kind: ValueString, text: v} }

// BytesValue copies an octet slice into immutable string storage.  The copy is
// intentionally paid once at the mapping/setup boundary, never by Preflight.
func BytesValue(v []byte) Value { return Value{kind: ValueBytes, octets: string(v), octetsSet: true} }

// OctetsValue accepts already-owned immutable octets represented as a string.
func OctetsValue(v string) Value { return Value{kind: ValueBytes, octets: v, octetsSet: true} }

// ByteView is a read-only byte source for synchronous streaming. The caller
// keeps its contents stable until mapping and writing finish. It has no pdata
// dependency; owned BytesValue and OctetsValue retain their snapshot semantics.
type ByteView interface {
	Len() int
	At(int) byte
}

// BorrowedBytesValue borrows a bounded byte view without copying its payload.
// Neither this value nor a record containing it may outlive the source request.
func BorrowedBytesValue(v ByteView) Value {
	return Value{kind: ValueBytes, octetsSet: true, borrowed: v}
}

func (v Value) ByteLen() int {
	if v.borrowed != nil {
		return v.borrowed.Len()
	}
	return len(v.octets)
}
func (v Value) ByteAt(i int) byte {
	if v.borrowed != nil {
		return v.borrowed.At(i)
	}
	return v.octets[i]
}

// IPValue constructs a parsed address value.  Invalid addresses become the
// zero Value and are rejected by record construction; checked constructors
// below return the classified error directly.
func IPValue(v netip.Addr) Value {
	if !v.IsValid() || v.Zone() != "" {
		return Value{}
	}
	return Value{kind: ValueIP, ip: v}
}

func IPv4Value(v netip.Addr) Value {
	if !v.Is4() {
		return Value{}
	}
	return IPValue(v)
}

func IPv6Value(v netip.Addr) Value {
	if !v.Is6() || v.Is4() || v.Zone() != "" {
		return Value{}
	}
	return IPValue(v)
}

func NewIPValue(v netip.Addr) (Value, error) {
	if !v.IsValid() || v.Zone() != "" {
		return Value{}, ErrInvalidValue
	}
	return IPValue(v), nil
}

func NewIPv4Value(v netip.Addr) (Value, error) {
	if !v.Is4() {
		return Value{}, ErrInvalidValue
	}
	return IPv4Value(v), nil
}

func NewIPv6Value(v netip.Addr) (Value, error) {
	if !v.Is6() || v.Is4() || v.Zone() != "" {
		return Value{}, ErrInvalidValue
	}
	return IPv6Value(v), nil
}

func ParseIPValue(text string) (Value, error) {
	address, err := netip.ParseAddr(text)
	if err != nil || address.String() != text || address.Zone() != "" {
		return Value{}, ErrInvalidValue
	}
	return IPValue(address), nil
}

func ParseIPv4Value(text string) (Value, error) {
	address, err := netip.ParseAddr(text)
	if err != nil || address.String() != text || !address.Is4() || address.Zone() != "" {
		return Value{}, ErrInvalidValue
	}
	return IPv4Value(address), nil
}

func ParseIPv6Value(text string) (Value, error) {
	address, err := netip.ParseAddr(text)
	if err != nil || address.String() != text || !address.Is6() || address.Is4() || address.Zone() != "" {
		return Value{}, ErrInvalidValue
	}
	return IPv6Value(address), nil
}

// MACValue stores exactly six octets by value.
func MACValue(v [6]byte) Value { return Value{kind: ValueMAC, mac: v} }

func NewMACValue(v []byte) (Value, error) {
	if len(v) != 6 {
		return Value{}, ErrInvalidValue
	}
	var mac [6]byte
	copy(mac[:], v)
	return MACValue(mac), nil
}

func ParseMACValue(text string) (Value, error) {
	parsed, err := net.ParseMAC(text)
	if err != nil || len(parsed) != 6 || parsed.String() != text {
		return Value{}, ErrInvalidValue
	}
	var mac [6]byte
	copy(mac[:], parsed)
	return MACValue(mac), nil
}

// UnixNanosValue is the semantic absolute-time form.  Range validation is
// repeated at record admission so an out-of-range value cannot cross the
// boundary even when this convenience constructor is used directly.
func UnixNanosValue(v uint64) Value { return Value{kind: ValueUnixNanos, uintValue: v} }

func NewUnixNanosValue(v uint64) (Value, error) {
	if err := ValidateUnixNanos(v); err != nil {
		return Value{}, err
	}
	return UnixNanosValue(v), nil
}

// Kind and scalar accessors are read-only and allocation free.
func (v Value) Kind() ValueKind { return v.kind }
func (v Value) Int() int64      { return v.intValue }
func (v Value) Uint() uint64    { return v.uintValue }
func (v Value) Text() string    { return v.text }
func (v Value) Octets() string {
	if v.borrowed != nil {
		return string(v.BytesCopy())
	}
	return v.octets
}
func (v Value) IP() netip.Addr      { return v.ip }
func (v Value) MAC() [6]byte        { return v.mac }
func (v Value) UnixNanos() uint64   { return v.uintValue }
func (v Value) BytesString() string { return v.Octets() }
func (v Value) TextValue() string   { return v.text }
func (v Value) IPAddr() netip.Addr  { return v.ip }
func (v Value) MACBytes() [6]byte   { return v.mac }
func (v Value) BytesCopy() []byte {
	if !v.octetsSet {
		return nil
	}
	result := make([]byte, v.ByteLen())
	for i := range result {
		result[i] = v.ByteAt(i)
	}
	return result
}

func validateValue(v Value) error {
	switch v.kind {
	case ValueInt:
		if v.uintValue != 0 || v.text != "" || v.octetsSet || v.ip.IsValid() || v.mac != [6]byte{} {
			return ErrInvalidValue
		}
	case ValueUint:
		if v.intValue != 0 || v.text != "" || v.octetsSet || v.ip.IsValid() || v.mac != [6]byte{} {
			return ErrInvalidValue
		}
	case ValueString:
		if v.intValue != 0 || v.uintValue != 0 || v.octetsSet || v.ip.IsValid() || v.mac != [6]byte{} {
			return ErrInvalidValue
		}
		if !utf8.ValidString(v.text) {
			return ErrInvalidValue
		}
		if len(v.text) > MaxNormalizedValueBytes {
			return ErrRecordValueLimit
		}
	case ValueBytes:
		if v.intValue != 0 || v.uintValue != 0 || v.text != "" || v.ip.IsValid() || v.mac != [6]byte{} || !v.octetsSet {
			return ErrInvalidValue
		}
		if v.ByteLen() < 0 || v.ByteLen() > MaxNormalizedValueBytes {
			return ErrRecordValueLimit
		}
	case ValueIP:
		if v.intValue != 0 || v.uintValue != 0 || v.text != "" || v.octetsSet || !v.ip.IsValid() || v.ip.Zone() != "" || v.mac != [6]byte{} {
			return ErrInvalidValue
		}
	case ValueMAC:
		if v.intValue != 0 || v.uintValue != 0 || v.text != "" || v.octetsSet || v.ip.IsValid() {
			return ErrInvalidValue
		}
	case ValueUnixNanos:
		if v.intValue != 0 || v.text != "" || v.octetsSet || v.ip.IsValid() || v.mac != [6]byte{} {
			return ErrInvalidValue
		}
		if err := ValidateUnixNanos(v.uintValue); err != nil {
			return err
		}
	default:
		return ErrInvalidValue
	}
	return nil
}

// ValidateUnixNanos validates the generic absolute-time representation.  The
// admission ceiling is MaxInt64 so later protocol encoders can safely apply
// their own millisecond or NTP-era conversions without signed overflow.
func ValidateUnixNanos(v uint64) error {
	if v > math.MaxInt64 {
		return ErrTimeOutOfRange
	}
	return nil
}

// FieldValue associates one canonical field with one normalized value.
type FieldValue struct {
	Field CanonicalField
	Value Value
}

func validateValueForFamily(v Value, family Family) error {
	if err := validateValue(v); err != nil {
		return err
	}
	if v.kind != ValueIP {
		return nil
	}
	if family == FamilyIPv4 && !v.ip.Is4() {
		return ErrInvalidValue
	}
	if family == FamilyIPv6 && (!v.ip.Is6() || v.ip.Is4()) {
		return ErrInvalidValue
	}
	return nil
}

func validateCanonicalValueForFamily(field FieldValue, family Family) error {
	// The sampler identifies the receiving transport's peer, not an address
	// inside the measured flow. IPv6 flows routinely arrive over IPv4 UDP (and
	// vice versa). Keep generic value validation without imposing flow family.
	if field.Field == FieldFlowSamplerAddress {
		return validateValue(field.Value)
	}
	return validateValueForFamily(field.Value, family)
}

// NormalizedRecord is a bounded, immutable-on-construction value view.  Its
// backing storage is fixed-size; callers cannot add values after construction.
type NormalizedRecord struct {
	family Family

	count  uint16
	values [MaxNormalizedValues]FieldValue
}

// NewRecord validates and copies fields into a bounded record.  Duplicate
// canonical IDs and invalid value kinds are rejected.  Optional receiver
// fields are represented by omission; no sentinel is inserted here.
func NewRecord(family Family, fields []FieldValue) (NormalizedRecord, error) {
	if family != FamilyIPv4 && family != FamilyIPv6 {
		return NormalizedRecord{}, ErrInvalidFamily
	}
	if len(fields) == 0 || len(fields) > MaxNormalizedValues {
		return NormalizedRecord{}, ErrRecordValueLimit
	}
	r := NormalizedRecord{family: family, count: uint16(len(fields))}
	seen := make(map[CanonicalField]struct{}, len(fields))
	for i, f := range fields {
		if !f.Field.Valid() {
			return NormalizedRecord{}, ErrInvalidValue
		}
		if err := validateCanonicalValueForFamily(f, family); err != nil {
			return NormalizedRecord{}, err
		}
		if _, ok := seen[f.Field]; ok {
			return NormalizedRecord{}, ErrDuplicateField
		}
		if isAbsoluteTimeField(f.Field) && f.Value.kind != ValueUnixNanos {
			return NormalizedRecord{}, ErrInvalidValue
		}
		seen[f.Field] = struct{}{}
		r.values[i] = f
	}
	return r, nil
}

// Validate checks a normalized record that crossed an API seam.  The zero
// value is intentionally invalid; callers must use NewRecord so retained byte
// values are copied before a writer or mapping adapter sees them.
func (r NormalizedRecord) Validate() error {
	if r.family != FamilyIPv4 && r.family != FamilyIPv6 {
		return ErrInvalidFamily
	}
	if r.count == 0 || int(r.count) > MaxNormalizedValues {
		return ErrRecordValueLimit
	}
	seen := make(map[CanonicalField]struct{}, r.count)
	for i := 0; i < int(r.count); i++ {
		field := r.values[i]
		if !field.Field.Valid() {
			return ErrInvalidValue
		}
		if err := validateCanonicalValueForFamily(field, r.family); err != nil {
			return err
		}
		if _, ok := seen[field.Field]; ok {
			return ErrDuplicateField
		}
		if isAbsoluteTimeField(field.Field) && field.Value.kind != ValueUnixNanos {
			return ErrInvalidValue
		}
		seen[field.Field] = struct{}{}
	}
	return nil
}

// WireRecord is an ordered value view already bound to a compiled shape.
// It inherits any BorrowedBytesValue lifetime and otherwise owns immutable
// values. The mapping adapter supplies descriptor order, so writers never
// perform canonical-name or custom top-level source lookup.
type WireRecord struct {
	family Family
	count  uint8
	values [MaxRecordFields]Value
}

// NewWireRecord constructs a bounded ordered value view for one data record.
func NewWireRecord(family Family, values []Value) (WireRecord, error) {
	if family != FamilyIPv4 && family != FamilyIPv6 {
		return WireRecord{}, ErrInvalidFamily
	}
	if len(values) == 0 || len(values) > MaxRecordFields {
		return WireRecord{}, ErrRecordValueLimit
	}
	r := WireRecord{family: family, count: uint8(len(values))}
	for i, value := range values {
		if err := validateValueForFamily(value, family); err != nil {
			return WireRecord{}, err
		}
		r.values[i] = value
	}
	return r, nil
}

// Validate checks a wire-bound record, including its immutable family and
// strict value union.  A zero-value WireRecord is intentionally invalid.
func (r WireRecord) Validate() error {
	if r.family != FamilyIPv4 && r.family != FamilyIPv6 {
		return ErrInvalidFamily
	}
	if r.count == 0 || int(r.count) > MaxRecordFields {
		return ErrRecordValueLimit
	}
	for i := 0; i < int(r.count); i++ {
		if err := validateValueForFamily(r.values[i], r.family); err != nil {
			return err
		}
	}
	return nil
}

// Family reports the immutable family selected for this wire record.
func (r WireRecord) Family() Family { return r.family }

// Len reports the number of ordered values.
func (r WireRecord) Len() int { return int(r.count) }

// Values returns an independent ordered copy with deep-copied byte values.
func (r WireRecord) Values() []Value {
	out := make([]Value, r.count)
	copy(out, r.values[:r.count])
	for i := range out {
		if out[i].borrowed != nil {
			out[i] = OctetsValue(out[i].Octets())
		}
	}
	return out
}

// ValueAt returns one ordered value without allocating. A borrowed byte view
// keeps its original lifetime; copying this value does not copy its payload.
func (r WireRecord) ValueAt(index int) (Value, bool) {
	if index < 0 || index >= int(r.count) {
		return Value{}, false
	}
	return r.values[index], true
}

func (r WireRecord) valueAt(index int) (Value, bool) { return r.ValueAt(index) }

func isAbsoluteTimeField(field CanonicalField) bool {
	return field == FieldFlowTimeReceived || field == FieldFlowStart || field == FieldFlowEnd
}

// Record is a concise alias retained for writers and adapters.
type Record = NormalizedRecord

// Len reports the number of values in the record.
func (r NormalizedRecord) Len() int { return int(r.count) }

// Family reports the immutable family selected during normalization.
func (r NormalizedRecord) Family() Family { return r.family }

// Values returns a copy of the ordered values.  Byte values are deep-copied so
// a caller cannot mutate a record through an accessor.
func (r NormalizedRecord) Values() []FieldValue {
	out := make([]FieldValue, r.count)
	copy(out, r.values[:r.count])
	return out
}

// Lookup returns the first (and, by construction, only) value for field.
func (r NormalizedRecord) Lookup(field CanonicalField) (Value, bool) {
	for i := 0; i < int(r.count); i++ {
		if r.values[i].Field == field {
			return r.values[i].Value, true
		}
	}
	return Value{}, false
}

// FieldAt returns one ordered normalized field without allocating.
func (r NormalizedRecord) FieldAt(index int) (FieldValue, bool) {
	if index < 0 || index >= int(r.count) {
		return FieldValue{}, false
	}
	return r.values[index], true
}

// Limits are the checked static-shape and wire arithmetic ceilings.  A zero
// Limits value means the published defaults, which keeps callers from
// accidentally creating an unbounded contract.
type Limits struct {
	MaxShapes         uint64
	MaxFieldsPerShape uint64
	MaxTemplateBytes  uint64
	MaxCustomMappings uint64
	MaxPENs           uint64
	MaxRecords        uint64
	MaxRecordBytes    uint64
	MaxSetBytes       uint64
	MaxMessageBytes   uint64
}

const (
	DefaultMaxShapes         = 16
	DefaultMaxFieldsPerShape = 64
	DefaultMaxTemplateBytes  = 4096
	DefaultMaxCustomMappings = 32
	DefaultMaxPENs           = 32
	DefaultMaxRecords        = 65535
	DefaultMaxRecordBytes    = 65535
	DefaultMaxSetBytes       = 65535
	DefaultMaxMessageBytes   = 65535
	MaxRecordFields          = 64
	// Mapped values use the descriptor and packet/path bounds. The old 4096
	// aggregate default was not a wire requirement.
	DefaultMaxMappedValueBytes = 65535
	HardMaxMappedValueBytes    = 65535
)

// DefaultLimits returns a copy of the published static contract ceilings.
func DefaultLimits() Limits {
	return Limits{
		MaxShapes:         DefaultMaxShapes,
		MaxFieldsPerShape: DefaultMaxFieldsPerShape,
		MaxTemplateBytes:  DefaultMaxTemplateBytes,
		MaxCustomMappings: DefaultMaxCustomMappings,
		MaxPENs:           DefaultMaxPENs,
		MaxRecords:        DefaultMaxRecords,
		MaxRecordBytes:    DefaultMaxRecordBytes,
		MaxSetBytes:       DefaultMaxSetBytes,
		MaxMessageBytes:   DefaultMaxMessageBytes,
	}
}

func (l Limits) withDefaults() Limits {
	if l.MaxShapes == 0 {
		l.MaxShapes = DefaultMaxShapes
	}
	if l.MaxFieldsPerShape == 0 {
		l.MaxFieldsPerShape = DefaultMaxFieldsPerShape
	}
	if l.MaxTemplateBytes == 0 {
		l.MaxTemplateBytes = DefaultMaxTemplateBytes
	}
	if l.MaxCustomMappings == 0 {
		l.MaxCustomMappings = DefaultMaxCustomMappings
	}
	if l.MaxPENs == 0 {
		l.MaxPENs = DefaultMaxPENs
	}
	if l.MaxRecords == 0 {
		l.MaxRecords = DefaultMaxRecords
	}
	if l.MaxRecordBytes == 0 {
		l.MaxRecordBytes = DefaultMaxRecordBytes
	}
	if l.MaxSetBytes == 0 {
		l.MaxSetBytes = DefaultMaxSetBytes
	}
	if l.MaxMessageBytes == 0 {
		l.MaxMessageBytes = DefaultMaxMessageBytes
	}
	return l
}

// DescriptorEncoding is the closed set of descriptor value encodings
// accepted by the static profiles and future custom mapping adapter.
type DescriptorEncoding uint8

const (
	EncodingUnspecified DescriptorEncoding = iota
	EncodingUnsigned8
	EncodingUnsigned16
	EncodingUnsigned32
	EncodingUnsigned64
	EncodingSigned8
	EncodingSigned16
	EncodingSigned32
	EncodingSigned64
	EncodingIPv4Address
	EncodingIPv6Address
	EncodingMACAddress
	EncodingOctetArray
	EncodingString
	EncodingDateTimeNanoseconds
	EncodingDateTimeMilliseconds
)

// FieldDescriptor is a protocol-tagged v9 or IPFIX field identity and wire
// length.  For IPFIX, Enterprise requires a nonzero PEN and IDs are 1..32767;
// variable values use exactly the 65535 marker.  For v9, private IDs are
// explicit and never carry a PEN or variable marker.
type FieldDescriptor struct {
	Protocol Protocol
	Field    CanonicalField
	// Source is non-empty only for an explicitly configured custom mapping.
	// Canonical descriptors use Field and leave Source empty.
	Source     string
	Custom     bool
	Constant   bool
	ID         uint16
	PEN        uint32
	Enterprise bool
	Private    bool
	Length     uint16
	Variable   bool
	MaxLength  uint16
	Encoding   DescriptorEncoding
}

// HeaderMetadata contains destination-owned header identity and generic
// absolute times.  It intentionally carries no inbound sequence or domain
// derivation.  ExportTimeUnixNanos and UptimeOriginUnixNanos use the same
// uint64 Unix-epoch-nanosecond unit as normalized values.
type HeaderMetadata struct {
	Protocol Protocol

	Sequence            uint32
	ObservationDomainID uint32
	SourceID            uint32
	EngineType          uint8
	EngineID            uint8
	SamplingMode        uint8
	SamplingInterval    uint16
	Count               uint16

	ExportTimeUnixNanos   uint64
	UptimeOriginUnixNanos uint64
	HasUptimeOrigin       bool
}

// ContractError is a comparable immutable classified error.  Constant values
// avoid mutable exported error variables while retaining errors.Is support.
type ContractError string

func (e ContractError) Error() string { return string(e) }

const (
	ErrInvalidProtocol   ContractError = "wire: invalid protocol"
	ErrInvalidFamily     ContractError = "wire: invalid family"
	ErrInvalidValue      ContractError = "wire: invalid normalized value"
	ErrDuplicateField    ContractError = "wire: duplicate normalized field"
	ErrRecordValueLimit  ContractError = "wire: normalized value limit exceeded"
	ErrTimeOutOfRange    ContractError = "wire: absolute time out of range"
	ErrInvalidDescriptor ContractError = "wire: invalid field descriptor"
	ErrInvalidHeader     ContractError = "wire: invalid header metadata"
	ErrInvalidShape      ContractError = "wire: invalid shape"
	ErrInvalidCatalog    ContractError = "wire: invalid shape catalog"
	ErrDuplicateIdentity ContractError = "wire: duplicate wire identity"
	ErrBounds            ContractError = "wire: bounds exceeded"
	ErrShortBuffer       ContractError = "wire: caller buffer too short"
)
