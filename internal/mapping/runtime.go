package mapping

import (
	"errors"
	"math"
	"unicode/utf8"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	nanosPerMillisecond = uint64(1_000_000)
	maxIPFIXUnixNanos   = uint64(2_085_978_495_999_999_999)
)

// Lookup is the only runtime extension point. It must synchronously return a
// value for one precompiled custom source key. Mapper never stores the
// callback, key, or returned value after Map returns.
type Lookup func(source string) (wire.Value, bool)

// MappingResult includes bounded loss accounting for a successful record.
// The counters are intentionally small and do not expose source names.
type MappingResult struct {
	Record              wire.WireRecord
	ExporterLosses      uint8
	CanonicalSourceLoss uint8
}

// Map binds one normalized record to the selected precompiled shape. It reads
// canonical values only from record and invokes lookup only for explicit
// custom sources. There is no per-record shape/template allocation.
func (m Mapper) Map(record wire.NormalizedRecord, lookup Lookup) (wire.WireRecord, error) {
	result, err := m.mapResult(record, lookup)
	return result.Record, err
}

// Map maps through a compiled value without exposing its internal mapper.
func (m CompiledMapping) Map(record wire.NormalizedRecord, lookup Lookup) (wire.WireRecord, error) {
	return m.mapper.Map(record, lookup)
}

// MapWithStats is the compiled-value form of Mapper.MapWithStats.
func (m CompiledMapping) MapWithStats(record wire.NormalizedRecord, lookup Lookup) (MappingResult, error) {
	return m.mapper.MapWithStats(record, lookup)
}

// MapWithStats returns bounded loss counters alongside the immutable wire
// record. Canonical-source loss is only counted for matrix-approved mappings;
// unknown/unselected input is never counted.
func (m Mapper) MapWithStats(record wire.NormalizedRecord, lookup Lookup) (MappingResult, error) {
	return m.mapResult(record, lookup)
}

func (m Mapper) mapResult(record wire.NormalizedRecord, lookup Lookup) (MappingResult, error) {
	shapeCount := m.catalog.ShapeCount()
	if shapeCount == 0 || len(m.bindings) != shapeCount {
		return MappingResult{}, runtimeError(RuntimeRecordInvalid, 0)
	}
	shapeIndex := 0
	if shapeCount == 2 {
		if record.Family() == wire.FamilyIPv6 {
			shapeIndex = 1
		} else if record.Family() != wire.FamilyIPv4 {
			return MappingResult{}, runtimeError(RuntimeFamilyMismatch, 0)
		}
	}
	if shapeIndex < 0 || shapeIndex >= len(m.bindings) {
		return MappingResult{}, runtimeError(RuntimeFamilyMismatch, shapeIndex)
	}
	shape, ok := m.catalog.ShapeAt(shapeIndex)
	if !ok || (record.Family() != wire.FamilyIPv4 && record.Family() != wire.FamilyIPv6) || (!m.familyAgnostic && shape.Family() != record.Family()) {
		return MappingResult{}, runtimeError(RuntimeFamilyMismatch, shapeIndex)
	}
	if err := validateCanonicalAddressFamilies(record); err != nil {
		return MappingResult{}, runtimeError(RuntimeFamilyMismatch, shapeIndex)
	}
	bindings := m.bindings[shapeIndex]
	var valueStorage [wire.MaxRecordFields]wire.Value
	values := valueStorage[:0]
	var mappedBytes uint64
	var first, last uint64
	var haveFirst, haveLast bool
	for index, binding := range bindings {
		value, err := m.valueFor(binding, record, lookup)
		if err != nil {
			return MappingResult{}, runtimeError(reasonFor(err), index)
		}
		if binding.descriptor.Field == wire.FieldFlowStart {
			first, haveFirst = value.UnixNanos(), true
		}
		if binding.descriptor.Field == wire.FieldFlowEnd {
			last, haveLast = value.UnixNanos(), true
		}
		length, err := binding.descriptor.ValueLength(value)
		if err != nil {
			reason := reasonFor(err)
			if binding.custom && errors.Is(err, wire.ErrInvalidValue) {
				reason = RuntimeCustomInvalid
			}
			return MappingResult{}, runtimeError(reason, index)
		}
		var fits bool
		mappedBytes, fits = checkedAdd(mappedBytes, length)
		if !fits || mappedBytes > m.limits.MaxRecordBytes || mappedBytes > wire.DefaultMaxRecordBytes {
			return MappingResult{}, runtimeError(RuntimeBudgetExceeded, index)
		}
		packetBytes, fits := mappingDataBytesForMinimum(m.protocol, mappedBytes, shape.MinimumDataRecordLength())
		if !fits || packetBytes > m.maxDatagram {
			return MappingResult{}, runtimeError(RuntimeBudgetExceeded, index)
		}
		values = append(values, value)
	}
	if haveFirst && haveLast && first > last {
		return MappingResult{}, runtimeError(RuntimeTimeInvalid, 0)
	}
	// A family-agnostic mapping intentionally has one structural IPv4 shape.
	// Bind its ordered values to that shape even when the validated source
	// record is IPv6; no family-dependent value can occur in such a shape.
	result, err := wire.NewWireRecord(shape.Family(), values)
	if err != nil {
		return MappingResult{}, runtimeError(RuntimeRecordInvalid, 0)
	}
	var exporterLosses, sourceLoss uint8
	for _, binding := range bindings {
		if binding.class == classLossy || binding.class == classSynthesized {
			exporterLosses++
		}
		if canonicalSourceLoss(binding.descriptor.Protocol, binding.field) {
			sourceLoss++
		}
	}
	return MappingResult{Record: result, ExporterLosses: exporterLosses, CanonicalSourceLoss: sourceLoss}, nil
}

func mappingHeaderBytes(protocol wire.Protocol) uint64 {
	switch protocol {
	case wire.ProtocolV5:
		return 24
	case wire.ProtocolV9:
		return 20
	case wire.ProtocolIPFIX:
		return 16
	default:
		return 0
	}
}

func customValueBytes(descriptor wire.FieldDescriptor, value wire.Value) uint64 {
	if !descriptor.Variable {
		return 0
	}
	if descriptor.Encoding == wire.EncodingString {
		return uint64(len(value.Text()))
	}
	return uint64(value.ByteLen())
}

func canonicalSourceLoss(protocol wire.Protocol, field wire.CanonicalField) bool {
	if field == wire.FieldFlowIOBytes || field == wire.FieldFlowIOPackets {
		return protocol == wire.ProtocolV9 || protocol == wire.ProtocolIPFIX
	}
	if protocol != wire.ProtocolIPFIX {
		return false
	}
	return field == wire.FieldFlowObservationPointID || field == wire.FieldFlowSrcMAC || field == wire.FieldFlowDstMAC
}

func (m Mapper) valueFor(binding shapeBinding, record wire.NormalizedRecord, lookup Lookup) (wire.Value, error) {
	if binding.descriptor.Constant {
		return wire.UintValue(0), nil
	}
	if binding.custom {
		if lookup == nil {
			return wire.Value{}, ErrCustomMissing
		}
		value, ok, panicked := invokeLookup(lookup, binding.descriptor.Source)
		if panicked {
			return wire.Value{}, ErrCallbackInvalid
		}
		if !ok {
			return wire.Value{}, ErrCustomMissing
		}
		value, err := normalizeCustomValue(binding.descriptor, value)
		if err != nil {
			return wire.Value{}, err
		}
		if err := validateCustomValue(binding.descriptor, value); err != nil {
			return wire.Value{}, err
		}
		return value, nil
	}
	if binding.field == wire.FieldFlowICMPTypeCode {
		if record.Family() != wire.FamilyIPv4 {
			return wire.Value{}, ErrFamilyMismatch
		}
		typeValue, ok := record.Lookup(wire.FieldFlowICMPType)
		if !ok {
			return wire.Value{}, ErrMissingField
		}
		codeValue, ok := record.Lookup(wire.FieldFlowICMPCode)
		if !ok {
			return wire.Value{}, ErrMissingField
		}
		transport, ok := record.Lookup(wire.FieldNetworkTransport)
		if !ok || transport.Kind() != wire.ValueString {
			return wire.Value{}, ErrProtocolMismatch
		}
		protocolNumber, ok := m.protocolNumbers[transport.Text()]
		if !ok {
			return wire.Value{}, ErrMapMiss
		}
		typeNumber, typeOK := unsignedValue(typeValue)
		codeNumber, codeOK := unsignedValue(codeValue)
		if protocolNumber != 1 || !typeOK || !codeOK || typeNumber > 255 || codeNumber > 255 {
			return wire.Value{}, ErrProtocolMismatch
		}
		return wire.UintValue(typeNumber<<8 | codeNumber), nil
	}
	if (binding.field == wire.FieldFlowICMPType || binding.field == wire.FieldFlowICMPCode) && binding.descriptor.Protocol == wire.ProtocolIPFIX {
		transport, ok := record.Lookup(wire.FieldNetworkTransport)
		if !ok || transport.Kind() != wire.ValueString {
			return wire.Value{}, ErrProtocolMismatch
		}
		protocolNumber, ok := m.protocolNumbers[transport.Text()]
		if !ok {
			return wire.Value{}, ErrMapMiss
		}
		want := uint8(1)
		if record.Family() == wire.FamilyIPv6 {
			want = 58
		}
		if protocolNumber != want {
			return wire.Value{}, ErrProtocolMismatch
		}
	}
	value, ok := record.Lookup(binding.field)
	if !ok {
		return wire.Value{}, ErrMissingField
	}
	if binding.field == wire.FieldNetworkTransport {
		if value.Kind() != wire.ValueString {
			return wire.Value{}, ErrMapMiss
		}
		number, ok := m.protocolNumbers[value.Text()]
		if !ok {
			return wire.Value{}, ErrMapMiss
		}
		return wire.UintValue(uint64(number)), nil
	}
	if binding.field == wire.FieldNetworkType {
		if value.Kind() != wire.ValueString {
			return wire.Value{}, ErrMapMiss
		}
		version, ok := m.networkVersions[value.Text()]
		if !ok {
			return wire.Value{}, ErrMapMiss
		}
		if (record.Family() == wire.FamilyIPv4 && version != 4) || (record.Family() == wire.FamilyIPv6 && version != 6) {
			return wire.Value{}, ErrFamilyMismatch
		}
		return wire.UintValue(uint64(version)), nil
	}
	if binding.field == wire.FieldFlowIPFlags && binding.descriptor.Protocol == wire.ProtocolIPFIX {
		flowType, ok := record.Lookup(wire.FieldFlowType)
		if !ok || flowType.Kind() != wire.ValueString || flowType.Text() != "ipfix" {
			return wire.Value{}, ErrProtocolMismatch
		}
		number, ok := unsignedValue(value)
		if !ok {
			return wire.Value{}, ErrInvalidValue
		}
		// IE 197 shifts canonical bits into wire bits 7..5; wire bit 7 is
		// reserved, and IPv6 also forbids wire bit 6 (the IPv4-only DF bit).
		limit := uint64(1)
		if record.Family() == wire.FamilyIPv4 {
			limit = 3
		}
		if number > limit {
			return wire.Value{}, ErrInvalidValue
		}
		return wire.UintValue(number << 5), nil
	}
	if binding.field == wire.FieldFlowFragmentOffset || binding.field == wire.FieldFlowIPv6FlowLabel || binding.field == wire.FieldFlowSrcNet || binding.field == wire.FieldFlowDstNet || binding.field == wire.FieldFlowSrcVLAN || binding.field == wire.FieldFlowDstVLAN || binding.field == wire.FieldFlowVLANID || binding.field == wire.FieldFlowObservationPointID {
		number, ok := unsignedValue(value)
		if !ok {
			return wire.Value{}, ErrInvalidValue
		}
		limit := uint64(0xfffff)
		switch binding.field {
		case wire.FieldFlowFragmentOffset:
			limit = 0x1fff
		case wire.FieldFlowSrcNet, wire.FieldFlowDstNet:
			limit = 128
			if record.Family() == wire.FamilyIPv4 {
				limit = 32
			}
		case wire.FieldFlowSrcVLAN, wire.FieldFlowDstVLAN, wire.FieldFlowVLANID:
			limit = 4095
		case wire.FieldFlowObservationPointID:
			limit = math.MaxUint32
		}
		if number > limit {
			return wire.Value{}, ErrInvalidValue
		}
	}
	if binding.field == wire.FieldFlowIPv6FlowLabel && binding.descriptor.Protocol == wire.ProtocolV9 {
		var octets [3]byte
		n, _ := unsignedValue(value)
		octets[0] = byte(n >> 16)
		octets[1] = byte(n >> 8)
		octets[2] = byte(n)
		return wire.BytesValue(octets[:]), nil
	}
	if err := validateMappedTime(m, binding, value); err != nil {
		return wire.Value{}, err
	}
	return value, nil
}

// invokeLookup keeps a faulty bridge from taking down the exporter. The
// callback is still synchronous and is never retained after this call.
func invokeLookup(lookup Lookup, source string) (value wire.Value, ok, panicked bool) {
	defer func() {
		if recover() != nil {
			value, ok, panicked = wire.Value{}, false, true
		}
	}()
	value, ok = lookup(source)
	return value, ok, false
}

func normalizeCustomValue(descriptor wire.FieldDescriptor, value wire.Value) (wire.Value, error) {
	switch descriptor.Encoding {
	case wire.EncodingIPv4Address:
		if value.Kind() == wire.ValueString {
			if len(value.Text()) > 15 {
				return wire.Value{}, ErrCustomInvalid
			}
			parsed, err := wire.ParseIPValue(value.Text())
			if err != nil {
				return wire.Value{}, ErrCustomInvalid
			}
			if !parsed.IP().Is4() {
				return wire.Value{}, ErrFamilyMismatch
			}
			return parsed, nil
		}
		return wire.Value{}, ErrCustomInvalid
	case wire.EncodingIPv6Address:
		if value.Kind() == wire.ValueString {
			if len(value.Text()) > 39 {
				return wire.Value{}, ErrCustomInvalid
			}
			parsed, err := wire.ParseIPValue(value.Text())
			if err != nil {
				return wire.Value{}, ErrCustomInvalid
			}
			if !parsed.IP().Is6() || parsed.IP().Is4() {
				return wire.Value{}, ErrFamilyMismatch
			}
			return parsed, nil
		}
		return wire.Value{}, ErrCustomInvalid
	case wire.EncodingMACAddress:
		if value.Kind() == wire.ValueString {
			if len(value.Text()) > 17 {
				return wire.Value{}, ErrCustomInvalid
			}
			parsed, err := wire.ParseMACValue(value.Text())
			if err != nil {
				return wire.Value{}, ErrCustomInvalid
			}
			return parsed, nil
		}
		return wire.Value{}, ErrCustomInvalid
	case wire.EncodingString:
		if value.Kind() == wire.ValueString {
			if !utf8.ValidString(value.Text()) {
				return wire.Value{}, ErrCustomInvalid
			}
			length := len(value.Text())
			if descriptor.Variable {
				if length > int(descriptor.MaxLength) {
					return wire.Value{}, wire.ErrBounds
				}
			} else if length != int(descriptor.Length) {
				return wire.Value{}, ErrCustomInvalid
			}
			return value, nil
		}
		return wire.Value{}, ErrCustomInvalid
	case wire.EncodingOctetArray:
		if value.Kind() == wire.ValueBytes {
			length := value.ByteLen()
			if descriptor.Variable {
				if length > int(descriptor.MaxLength) {
					return wire.Value{}, wire.ErrBounds
				}
			} else if length != int(descriptor.Length) {
				return wire.Value{}, ErrCustomInvalid
			}
			return value, nil
		}
		return wire.Value{}, ErrCustomInvalid
	case wire.EncodingUnsigned8, wire.EncodingUnsigned16, wire.EncodingUnsigned32, wire.EncodingUnsigned64:
		if value.Kind() != wire.ValueUint && value.Kind() != wire.ValueInt {
			return wire.Value{}, ErrCustomInvalid
		}
		return value, nil
	case wire.EncodingSigned8, wire.EncodingSigned16, wire.EncodingSigned32, wire.EncodingSigned64:
		if value.Kind() != wire.ValueInt {
			return wire.Value{}, ErrCustomInvalid
		}
		return value, nil
	}
	return wire.Value{}, ErrCustomInvalid
}

func validateCustomValue(descriptor wire.FieldDescriptor, value wire.Value) error {
	if descriptor.Encoding == wire.EncodingString && !utf8.ValidString(value.Text()) {
		return ErrCustomInvalid
	}
	return nil
}

func unsignedValue(value wire.Value) (uint64, bool) {
	switch value.Kind() {
	case wire.ValueUint:
		return value.Uint(), true
	case wire.ValueInt:
		if value.Int() >= 0 {
			return uint64(value.Int()), true
		}
	}
	return 0, false
}

func validateMappedTime(m Mapper, binding shapeBinding, value wire.Value) error {
	field := binding.descriptor.Field
	if field != wire.FieldFlowStart && field != wire.FieldFlowEnd && field != wire.FieldFlowTimeReceived {
		return nil
	}
	if value.Kind() != wire.ValueUnixNanos {
		return ErrInvalidValue
	}
	if binding.descriptor.Protocol == wire.ProtocolIPFIX {
		if binding.descriptor.Encoding == wire.EncodingDateTimeMilliseconds {
			return nil
		}
		if value.UnixNanos() > maxIPFIXUnixNanos {
			return ErrTimeInvalid
		}
		return nil
	}
	if !m.hasOrigin || value.UnixNanos() < m.origin {
		return ErrTimeInvalid
	}
	delta := value.UnixNanos() - m.origin
	if delta%nanosPerMillisecond != 0 || delta/nanosPerMillisecond > math.MaxUint32 {
		return ErrTimeInvalid
	}
	return nil
}

func reasonFor(err error) RuntimeReason {
	switch err {
	case ErrMapMiss:
		return RuntimeMapMiss
	case ErrMissingField:
		return RuntimeMissingField
	case ErrCustomMissing:
		return RuntimeCustomMissing
	case ErrCustomInvalid:
		return RuntimeCustomInvalid
	case ErrCallbackInvalid:
		return RuntimeCallbackInvalid
	case ErrFamilyMismatch:
		return RuntimeFamilyMismatch
	case ErrProtocolMismatch:
		return RuntimeProtocolMismatch
	case ErrTimeInvalid:
		return RuntimeTimeInvalid
	case ErrInvalidValue:
		return RuntimeValueInvalid
	case wire.ErrBounds:
		return RuntimeBudgetExceeded
	default:
		return RuntimeValueInvalid
	}
}

var (
	ErrFamilyMismatch   = errors.New("mapping: family mismatch")
	ErrProtocolMismatch = errors.New("mapping: protocol mismatch")
	ErrInvalidValue     = errors.New("mapping: invalid mapped value")
	ErrTimeInvalid      = errors.New("mapping: invalid mapped time")
)

func validateCanonicalAddressFamilies(record wire.NormalizedRecord) error {
	family := record.Family()
	for _, field := range [...]wire.CanonicalField{
		wire.FieldSourceAddress,
		wire.FieldDestinationAddress,
		wire.FieldFlowNextHop,
		wire.FieldFlowBGPNextHop,
	} {
		value, ok := record.Lookup(field)
		if !ok {
			continue
		}
		if value.Kind() != wire.ValueIP {
			return ErrFamilyMismatch
		}
		address := value.IP()
		if (family == wire.FamilyIPv4 && !address.Is4()) || (family == wire.FamilyIPv6 && (!address.Is6() || address.Is4())) {
			return ErrFamilyMismatch
		}
	}
	return nil
}
