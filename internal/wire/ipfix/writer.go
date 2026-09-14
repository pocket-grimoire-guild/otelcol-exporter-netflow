// Package ipfix emits stateless RFC 7011 IPFIX Template and Data Sets for an
// already compiled wire shape.  Destination state (sequence numbers,
// observation identity, and clocks) is supplied by the caller.
package ipfix

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/internal/cursor"
)

const (
	headerLength        = 16
	templateSetID       = 2
	nanosPerMillisecond = uint64(1_000_000)
	nanosPerSecond      = uint64(1_000_000_000)
	ntpEpochOffset      = uint64(2_208_988_800)
	ntpFractionScale    = uint64(4_294_967_296)
	maxUnixNanosIPFIX   = uint64(2_085_978_495_999_999_999)
)

// Writer implements wire.ContractWriter for ordinary IPFIX templates and
// data.  It has no mutable state and its zero value is ready for use.
type Writer struct{}

// NewWriter returns a stateless IPFIX writer.
func NewWriter() Writer { return Writer{} }

var _ wire.ContractWriter = Writer{}
var _ wire.StreamingWriter = Writer{}

// Write validates the complete request before mutating dst.  Every rejection
// returns n=0 and leaves the caller's buffer untouched.
func (Writer) Write(dst []byte, request wire.PacketRequest) (int, error) {
	n, err := wire.Preflight(dst, request)
	if err != nil {
		return 0, err
	}
	if err := validate(request); err != nil {
		return 0, err
	}

	c := cursor.New(dst[:n])
	h := request.Header
	writeHeader(&c, h, uint16(n))

	for i := uint64(0); i < request.TemplateRecords; i++ {
		writeTemplateSet(&c, request.Shape)
	}
	if len(request.Records) != 0 {
		size, _ := request.Shape.DataSetSize(request.Records)
		writeDataSet(&c, request.Shape, request.Records, size)
	}
	return n, nil
}

// Write is also available as a package-level convenience.
func Write(dst []byte, request wire.PacketRequest) (int, error) {
	return Writer{}.Write(dst, request)
}

func writeHeader(c *cursor.Cursor, h wire.HeaderMetadata, length uint16) {
	_ = c.WriteUint16(10)
	_ = c.WriteUint16(length)
	_ = c.WriteUint32(uint32(h.ExportTimeUnixNanos / nanosPerSecond))
	_ = c.WriteUint32(h.Sequence)
	_ = c.WriteUint32(h.ObservationDomainID)
}

func validate(request wire.PacketRequest) error {
	h := request.Header
	if err := validateHeader(h); err != nil {
		return err
	}
	if request.Shape.Protocol() != wire.ProtocolIPFIX {
		return wire.ErrInvalidShape
	}
	if err := validateShapeOrdering(request.Shape); err != nil {
		return err
	}
	for _, record := range request.Records {
		if err := validateRecord(request.Shape, record); err != nil {
			return err
		}
	}
	return nil
}

func validateHeader(h wire.HeaderMetadata) error {
	// IPFIX has Observation Domain ID but no Source ID, engine identity, or
	// sampling header fields.  Rejecting nonzero values prevents silent
	// provenance loss while keeping the wire envelope protocol-specific.
	if h.SourceID != 0 || h.EngineType != 0 || h.EngineID != 0 || h.SamplingMode != 0 || h.SamplingInterval != 0 {
		return wire.ErrInvalidHeader
	}
	if h.ExportTimeUnixNanos/nanosPerSecond > math.MaxUint32 {
		return wire.ErrInvalidHeader
	}
	return nil
}

func validateRecord(shape wire.Shape, record wire.WireRecord) error {
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		value, _ := record.ValueAt(i)
		if descriptor.Encoding == wire.EncodingDateTimeNanoseconds {
			if _, err := ntpTimestamp(value.UnixNanos()); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateShapeOrdering enforces the IPFIX custom append-only grammar.  The
// immutable Shape has already validated descriptor structure, IDs, lengths,
// encodings, family, and wire identity; canonical selector/target semantics
// belong to the mapping compiler rather than this protocol writer.
func validateShapeOrdering(shape wire.Shape) error {
	seenCustom := false
	for i := 0; i < shape.FieldCount(); i++ {
		d, _ := shape.DescriptorAt(i)
		if d.Custom {
			seenCustom = true
			continue
		}
		if seenCustom {
			return wire.ErrInvalidDescriptor
		}
	}
	return nil
}

func writeTemplateSet(c *cursor.Cursor, shape wire.Shape) {
	_ = c.WriteUint16(templateSetID)
	_ = c.WriteUint16(uint16(shape.TemplateBytes()))
	_ = c.WriteUint16(shape.ID())
	_ = c.WriteUint16(uint16(shape.FieldCount()))
	for i := 0; i < shape.FieldCount(); i++ {
		d, _ := shape.DescriptorAt(i)
		id := d.ID
		if d.Enterprise {
			id |= 0x8000
		}
		_ = c.WriteUint16(id)
		_ = c.WriteUint16(d.Length)
		if d.Enterprise {
			_ = c.WriteUint32(d.PEN)
		}
	}
}

func writeDataSet(c *cursor.Cursor, shape wire.Shape, records []wire.WireRecord, size wire.DataSetSize) {
	_ = c.WriteUint16(shape.ID())
	_ = c.WriteUint16(uint16(size.Length()))
	for _, record := range records {
		writeDataRecord(c, shape, record)
	}
	for i := uint8(0); i < size.Padding(); i++ {
		_ = c.WriteUint8(0)
	}
}

func writeDataRecord(c *cursor.Cursor, shape wire.Shape, record wire.WireRecord) {
	for i := 0; i < shape.FieldCount(); i++ {
		d, _ := shape.DescriptorAt(i)
		value, _ := record.ValueAt(i)
		writeValue(c, d, value)
	}
}

func writeValue(c *cursor.Cursor, descriptor wire.FieldDescriptor, value wire.Value) {
	switch descriptor.Encoding {
	case wire.EncodingUnsigned8:
		_ = c.WriteUint8(uint8(valueUint(value)))
	case wire.EncodingUnsigned16:
		_ = c.WriteUint16(uint16(valueUint(value)))
	case wire.EncodingUnsigned32:
		_ = c.WriteUint32(uint32(valueUint(value)))
	case wire.EncodingUnsigned64:
		_ = c.WriteUint64(valueUint(value))
	case wire.EncodingSigned8:
		_ = c.WriteUint8(uint8(value.Int()))
	case wire.EncodingSigned16:
		_ = c.WriteUint16(uint16(value.Int()))
	case wire.EncodingSigned32:
		_ = c.WriteUint32(uint32(value.Int()))
	case wire.EncodingSigned64:
		_ = c.WriteUint64(uint64(value.Int()))
	case wire.EncodingIPv4Address:
		octets := value.IP().As4()
		_ = c.Copy(octets[:])
	case wire.EncodingIPv6Address:
		octets := value.IP().As16()
		_ = c.Copy(octets[:])
	case wire.EncodingMACAddress:
		octets := value.MAC()
		_ = c.Copy(octets[:])
	case wire.EncodingString:
		if descriptor.Variable {
			writeVariable(c, value.Text())
		} else {
			writeString(c, value.Text())
		}
	case wire.EncodingOctetArray:
		if descriptor.Variable {
			length := value.ByteLen()
			if length < 255 {
				_ = c.WriteUint8(uint8(length))
			} else {
				_ = c.WriteUint8(255)
				_ = c.WriteUint16(uint16(length))
			}
		}
		for i := 0; i < value.ByteLen(); i++ {
			_ = c.WriteUint8(value.ByteAt(i))
		}
	case wire.EncodingDateTimeNanoseconds:
		encoded, _ := ntpTimestamp(value.UnixNanos())
		_ = c.WriteUint64(encoded)
	case wire.EncodingDateTimeMilliseconds:
		encoded, _ := unixMilliseconds(value.UnixNanos())
		_ = c.WriteUint64(encoded)
	}
}

func writeString(c *cursor.Cursor, value string) {
	reserved, _ := c.Reserve(len(value))
	copy(reserved, value)
}

func writeVariable(c *cursor.Cursor, value string) {
	length := len(value)
	if length < 255 {
		_ = c.WriteUint8(uint8(length))
	} else {
		_ = c.WriteUint8(255)
		_ = c.WriteUint16(uint16(length))
	}
	writeString(c, value)
}

func valueUint(value wire.Value) uint64 {
	switch value.Kind() {
	case wire.ValueUint, wire.ValueUnixNanos:
		return value.Uint()
	case wire.ValueInt:
		if value.Int() >= 0 {
			return uint64(value.Int())
		}
	}
	return math.MaxUint64
}

// ntpTimestamp converts a nonnegative Unix-nanosecond instant to the RFC 7011
// 64-bit NTP dateTimeNanoseconds representation.  Fraction conversion is
// integer round-to-nearest, with no floating point or truncation.
func ntpTimestamp(unixNanos uint64) (uint64, error) {
	if unixNanos > maxUnixNanosIPFIX {
		return 0, wire.ErrTimeOutOfRange
	}
	seconds := unixNanos / nanosPerSecond
	remainder := unixNanos % nanosPerSecond
	ntpSeconds := seconds + ntpEpochOffset
	fraction := (remainder*ntpFractionScale + 500_000_000) / nanosPerSecond
	if fraction >= ntpFractionScale {
		fraction -= ntpFractionScale
		ntpSeconds++
	}
	if ntpSeconds > math.MaxUint32 {
		return 0, wire.ErrTimeOutOfRange
	}
	return (ntpSeconds << 32) | uint64(uint32(fraction)), nil
}

// unixMilliseconds converts the canonical nonnegative Unix-nanosecond value
// to the RFC 7011 dateTimeMilliseconds representation.  Flooring occurs only
// after the canonical value has passed signed-safe range validation; mapping
// performs flow start/end ordering before this conversion.
func unixMilliseconds(unixNanos uint64) (uint64, error) {
	if err := wire.ValidateUnixNanos(unixNanos); err != nil {
		return 0, err
	}
	return unixNanos / nanosPerMillisecond, nil
}
