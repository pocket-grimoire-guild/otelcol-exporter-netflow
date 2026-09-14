// Package netflow5 emits the fixed NetFlow version 5 profile.
//
// The writer is intentionally stateless.  Destination state supplies all
// header identity and time values, while this package only checks and emits a
// caller-owned datagram.
package netflow5

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/internal/cursor"
)

const (
	headerLength = 24
	recordLength = 48
	maxRecords   = 30
	nanosPerMS   = uint64(1_000_000)
	nanosPerSec  = uint64(1_000_000_000)
)

// Writer implements wire.ContractWriter for the fixed NetFlow v5 profile.
// It has no mutable state and its zero value is ready for use.
type Writer struct{}

// NewWriter returns a stateless NetFlow v5 writer.
func NewWriter() Writer { return Writer{} }

var _ wire.ContractWriter = Writer{}
var _ wire.StreamingWriter = Writer{}

// Write validates the complete request before mutating dst, then emits one
// NetFlow v5 datagram in network byte order.  A rejected request always
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

	for _, record := range request.Records {
		writeRecord(&c, record, h.UptimeOriginUnixNanos)
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
	_ = c.WriteUint16(5)
	_ = c.WriteUint16(count)
	_ = c.WriteUint32(uint32(sysUptime))
	_ = c.WriteUint32(uint32(h.ExportTimeUnixNanos / nanosPerSec))
	_ = c.WriteUint32(uint32(h.ExportTimeUnixNanos % nanosPerSec))
	_ = c.WriteUint32(h.Sequence)
	_ = c.WriteUint8(h.EngineType)
	_ = c.WriteUint8(h.EngineID)
	_ = c.WriteUint16(uint16(h.SamplingMode)<<14 | h.SamplingInterval)
}

func validate(request wire.PacketRequest) error {
	h := request.Header
	if err := validateHeader(h); err != nil {
		return err
	}
	if len(request.Records) < 1 || len(request.Records) > maxRecords {
		return wire.ErrBounds
	}
	for _, record := range request.Records {
		if err := validateRecord(h, record); err != nil {
			return err
		}
	}
	return nil
}

func validateHeader(h wire.HeaderMetadata) error {
	// Source ID and Observation Domain ID have no v5 wire slots.  Rejecting a
	// nonzero value prevents provenance from being silently discarded.
	if h.SourceID != 0 || h.ObservationDomainID != 0 {
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
	return nil
}

func validateRecord(h wire.HeaderMetadata, record wire.WireRecord) error {
	if record.Family() != wire.FamilyIPv4 || record.Len() != 20 {
		return wire.ErrInvalidShape
	}
	// Cisco's v5 masks are one byte, but this profile only accepts the
	// IPv4 prefix range rather than accepting an out-of-family value.
	srcMask, _ := record.ValueAt(17)
	dstMask, _ := record.ValueAt(18)
	if valueUint(srcMask) > 32 || valueUint(dstMask) > 32 {
		return wire.ErrInvalidValue
	}
	sysUptime, _ := elapsedMilliseconds(h.ExportTimeUnixNanos, h.UptimeOriginUnixNanos)
	start, _ := record.ValueAt(7)
	end, _ := record.ValueAt(8)
	first, ok := elapsedMilliseconds(start.UnixNanos(), h.UptimeOriginUnixNanos)
	if !ok {
		return wire.ErrInvalidValue
	}
	last, ok := elapsedMilliseconds(end.UnixNanos(), h.UptimeOriginUnixNanos)
	if !ok || first > last || last > sysUptime || first > math.MaxUint32 || last > math.MaxUint32 {
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

func valueUint(value wire.Value) uint64 {
	switch value.Kind() {
	case wire.ValueUint:
		return value.Uint()
	case wire.ValueInt:
		if value.Int() >= 0 {
			return uint64(value.Int())
		}
	}
	return math.MaxUint64
}

func writeRecord(c *cursor.Cursor, record wire.WireRecord, origin uint64) {
	// Shape validation fixes this order and all widths.  The ignored cursor
	// errors are safe because wire.Preflight checked the complete capacity.
	value, _ := record.ValueAt(0)
	writeIPv4(c, value)
	value, _ = record.ValueAt(1)
	writeIPv4(c, value)
	value, _ = record.ValueAt(2)
	writeIPv4(c, value)
	value, _ = record.ValueAt(3)
	_ = c.WriteUint16(uint16(valueUint(value)))
	value, _ = record.ValueAt(4)
	_ = c.WriteUint16(uint16(valueUint(value)))
	value, _ = record.ValueAt(5)
	_ = c.WriteUint32(uint32(valueUint(value)))
	value, _ = record.ValueAt(6)
	_ = c.WriteUint32(uint32(valueUint(value)))
	value, _ = record.ValueAt(7)
	first, _ := elapsedMilliseconds(value.UnixNanos(), origin)
	_ = c.WriteUint32(uint32(first))
	value, _ = record.ValueAt(8)
	last, _ := elapsedMilliseconds(value.UnixNanos(), origin)
	_ = c.WriteUint32(uint32(last))
	value, _ = record.ValueAt(9)
	_ = c.WriteUint16(uint16(valueUint(value)))
	value, _ = record.ValueAt(10)
	_ = c.WriteUint16(uint16(valueUint(value)))
	_ = c.WriteUint8(0) // pad1
	value, _ = record.ValueAt(12)
	_ = c.WriteUint8(uint8(valueUint(value)))
	value, _ = record.ValueAt(13)
	_ = c.WriteUint8(uint8(valueUint(value)))
	value, _ = record.ValueAt(14)
	_ = c.WriteUint8(uint8(valueUint(value)))
	value, _ = record.ValueAt(15)
	_ = c.WriteUint16(uint16(valueUint(value)))
	value, _ = record.ValueAt(16)
	_ = c.WriteUint16(uint16(valueUint(value)))
	value, _ = record.ValueAt(17)
	_ = c.WriteUint8(uint8(valueUint(value)))
	value, _ = record.ValueAt(18)
	_ = c.WriteUint8(uint8(valueUint(value)))
	_ = c.WriteUint16(0) // pad2
}

func writeIPv4(c *cursor.Cursor, value wire.Value) {
	octets := value.IP().As4()
	_ = c.Copy(octets[:])
}
