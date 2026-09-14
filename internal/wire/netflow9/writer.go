// Package netflow9 emits stateless NetFlow version 9 Template and Data
// FlowSets for an already compiled wire shape.
//
// The writer owns no protocol state.  Destination code supplies the sequence,
// source identity, and reserved logical times; this package validates the
// complete request before writing into the caller-owned datagram buffer.
package netflow9

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/internal/cursor"
)

const (
	headerLength = 20
	nanosPerMS   = uint64(1_000_000)
	nanosPerSec  = uint64(1_000_000_000)
)

// Writer implements wire.ContractWriter for ordinary NetFlow v9 templates
// and data.  Its zero value is ready for use and has no mutable state.
type Writer struct{}

// NewWriter returns a stateless NetFlow v9 writer.
func NewWriter() Writer { return Writer{} }

var _ wire.ContractWriter = Writer{}
var _ wire.StreamingWriter = Writer{}

// Write validates the complete request before mutating dst, then emits one
// NetFlow v9 datagram in network byte order.  A rejected request always
// returns n=0 and leaves every byte in dst untouched.
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
	writeHeader(&c, h, h.Count)

	for i := uint64(0); i < request.TemplateRecords; i++ {
		writeTemplateFlowSet(&c, request.Shape)
	}
	if len(request.Records) != 0 {
		dataSet, _ := request.Shape.DataSetSize(request.Records)
		writeDataFlowSet(&c, request.Shape, request.Records, dataSet, h.UptimeOriginUnixNanos)
	}
	return n, nil
}

// Write is also available as a package-level convenience for callers that do
// not need to retain a Writer value.
func Write(dst []byte, request wire.PacketRequest) (int, error) {
	return Writer{}.Write(dst, request)
}

func writeHeader(c *cursor.Cursor, h wire.HeaderMetadata, count uint16) {
	sysUptime, _ := elapsedMilliseconds(h.ExportTimeUnixNanos, h.UptimeOriginUnixNanos)
	_ = c.WriteUint16(9)
	_ = c.WriteUint16(count)
	_ = c.WriteUint32(uint32(sysUptime))
	_ = c.WriteUint32(uint32(h.ExportTimeUnixNanos / nanosPerSec))
	_ = c.WriteUint32(h.Sequence)
	_ = c.WriteUint32(h.SourceID)
}

func validate(request wire.PacketRequest) error {
	h := request.Header
	if err := validateHeader(h); err != nil {
		return err
	}
	if request.Shape.Protocol() != wire.ProtocolV9 {
		return wire.ErrInvalidShape
	}
	if err := validateShapeBindings(request.Shape); err != nil {
		return err
	}
	sysUptime, _ := elapsedMilliseconds(h.ExportTimeUnixNanos, h.UptimeOriginUnixNanos)
	if err := validateRecordTimes(request.Shape, request.Records, h.UptimeOriginUnixNanos, sysUptime); err != nil {
		return err
	}
	return nil
}

func validateHeader(h wire.HeaderMetadata) error {
	// NetFlow v9 has a single source-id identity.  An observation-domain value
	// may be carried by the shared destination metadata, but when supplied it
	// must agree with the v9 source identity rather than being silently mixed.
	if h.ObservationDomainID != 0 && h.ObservationDomainID != h.SourceID {
		return wire.ErrInvalidHeader
	}
	if !h.HasUptimeOrigin {
		return wire.ErrInvalidHeader
	}
	if h.ExportTimeUnixNanos < h.UptimeOriginUnixNanos {
		return wire.ErrInvalidHeader
	}
	if h.ExportTimeUnixNanos/nanosPerSec > math.MaxUint32 {
		return wire.ErrInvalidHeader
	}
	sysUptime, ok := elapsedMilliseconds(h.ExportTimeUnixNanos, h.UptimeOriginUnixNanos)
	if !ok || sysUptime > math.MaxUint32 {
		return wire.ErrInvalidHeader
	}
	// Sampling mode/interval are v5 header fields.  v9 sampling is the
	// ordinary four-byte type-34 value in each selected Data Template.
	if h.SamplingMode != 0 || h.SamplingInterval != 0 {
		return wire.ErrInvalidHeader
	}
	return nil
}

// validateShapeBindings enforces the only canonical absolute-time mappings
// approved for NetFlow v9.  FieldFlowStart/End are uptime-relative wire
// fields, while the receiver's ingest timestamp has no v9 per-record slot.
func validateShapeBindings(shape wire.Shape) error {
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		switch descriptor.Field {
		case wire.FieldFlowTimeReceived:
			return wire.ErrInvalidShape
		case wire.FieldFlowStart:
			if descriptor.ID != 22 || descriptor.Length != 4 || descriptor.Encoding != wire.EncodingUnsigned32 {
				return wire.ErrInvalidDescriptor
			}
		case wire.FieldFlowEnd:
			if descriptor.ID != 21 || descriptor.Length != 4 || descriptor.Encoding != wire.EncodingUnsigned32 {
				return wire.ErrInvalidDescriptor
			}
		}
	}
	return nil
}

func validateRecordTimes(shape wire.Shape, records []wire.WireRecord, origin, sysUptime uint64) error {
	for _, record := range records {
		if err := validateRecordTime(shape, record, origin, sysUptime); err != nil {
			return err
		}
	}
	return nil
}

func validateRecordTime(shape wire.Shape, record wire.WireRecord, origin, sysUptime uint64) error {
	var first, last uint64
	var hasFirst, hasLast bool
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		if descriptor.Field != wire.FieldFlowStart && descriptor.Field != wire.FieldFlowEnd {
			continue
		}
		value, _ := record.ValueAt(i)
		elapsed, ok := elapsedMilliseconds(value.UnixNanos(), origin)
		if !ok || elapsed > math.MaxUint32 || elapsed > sysUptime {
			return wire.ErrInvalidValue
		}
		if descriptor.Field == wire.FieldFlowStart {
			first, hasFirst = elapsed, true
		} else {
			last, hasLast = elapsed, true
		}
	}
	if hasFirst && hasLast && first > last {
		return wire.ErrInvalidValue
	}
	return nil
}

func elapsedMilliseconds(value, origin uint64) (uint64, bool) {
	if value < origin {
		return 0, false
	}
	delta := value - origin
	if delta%nanosPerMS != 0 {
		return 0, false
	}
	return delta / nanosPerMS, true
}

func writeTemplateFlowSet(c *cursor.Cursor, shape wire.Shape) {
	// Shape validation and preflight fix this length and descriptor order.
	_ = c.WriteUint16(0)
	_ = c.WriteUint16(uint16(shape.TemplateBytes()))
	_ = c.WriteUint16(shape.ID())
	_ = c.WriteUint16(uint16(shape.FieldCount()))
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		_ = c.WriteUint16(descriptor.ID)
		_ = c.WriteUint16(descriptor.Length)
	}
}

func writeDataFlowSet(c *cursor.Cursor, shape wire.Shape, records []wire.WireRecord, size wire.DataSetSize, origin uint64) {
	_ = c.WriteUint16(shape.ID())
	_ = c.WriteUint16(uint16(size.Length()))
	for _, record := range records {
		writeDataRecord(c, shape, record, origin)
	}
	for i := uint8(0); i < size.Padding(); i++ {
		_ = c.WriteUint8(0)
	}
}

func writeDataRecord(c *cursor.Cursor, shape wire.Shape, record wire.WireRecord, origin uint64) {
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		value, _ := record.ValueAt(i)
		writeValue(c, descriptor, value, origin)
	}
}

func writeValue(c *cursor.Cursor, descriptor wire.FieldDescriptor, value wire.Value, origin uint64) {
	if descriptor.Field == wire.FieldFlowStart || descriptor.Field == wire.FieldFlowEnd {
		elapsed, _ := elapsedMilliseconds(value.UnixNanos(), origin)
		_ = c.WriteUint32(uint32(elapsed))
		return
	}
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
		address := value.IP().As4()
		_ = c.Copy(address[:])
	case wire.EncodingIPv6Address:
		address := value.IP().As16()
		_ = c.Copy(address[:])
	case wire.EncodingMACAddress:
		mac := value.MAC()
		_ = c.Copy(mac[:])
	case wire.EncodingString:
		writeString(c, value.Text())
	case wire.EncodingOctetArray:
		for i := 0; i < value.ByteLen(); i++ {
			_ = c.WriteUint8(value.ByteAt(i))
		}
	}
}

func writeString(c *cursor.Cursor, value string) {
	reserved, _ := c.Reserve(len(value))
	copy(reserved, value)
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
