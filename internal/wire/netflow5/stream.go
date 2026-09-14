package netflow5

import (
	"encoding/binary"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/internal/cursor"
)

// NewDataPacket returns a reusable incremental NetFlow v5 data appender.
// Setup allocates the appender's fixed state; packet operations do not retain
// records or allocate per append.
func (Writer) NewDataPacket() wire.DataPacketAppender { return &dataPacketAppender{} }

// NewDataPacket is the package-level streaming factory.
func NewDataPacket() wire.DataPacketAppender { return Writer{}.NewDataPacket() }

type dataPacketAppender struct {
	dst         []byte
	header      wire.HeaderMetadata
	shape       wire.Shape
	budget      uint64
	recordCap   uint64
	records     uint64
	recordBytes uint64
	begun       bool
	done        bool
}

// Reset releases the caller-owned datagram and invalidates the active packet.
func (p *dataPacketAppender) Reset() { *p = dataPacketAppender{} }

func (p *dataPacketAppender) Begin(dst []byte, request wire.DataPacketRequest) error {
	limit, err := request.Validate()
	if err != nil {
		return err
	}
	if request.Shape.Protocol() != wire.ProtocolV5 {
		return wire.ErrInvalidShape
	}
	if err := validateHeader(request.Header); err != nil {
		return err
	}
	if err := wire.ValidatePayloadLength(headerLength, request.MaxDatagramBytes); err != nil {
		return err
	}
	if len(dst) < headerLength {
		return wire.ErrShortBuffer
	}
	c := cursor.New(dst[:headerLength])
	writeHeader(&c, request.Header, 0)

	p.dst = dst
	p.header = request.Header
	p.shape = request.Shape
	p.budget = request.MaxDatagramBytes
	p.recordCap = limit
	p.records = 0
	p.recordBytes = 0
	p.begun = true
	p.done = false
	return nil
}

func (p *dataPacketAppender) Append(record wire.WireRecord) error {
	if !p.begun {
		if p.done {
			return wire.ErrPacketFinished
		}
		return wire.ErrPacketNotBegun
	}
	if p.done {
		return wire.ErrPacketFinished
	}
	if p.records >= p.recordCap {
		return wire.ErrBounds
	}
	recordBytes, err := p.shape.RecordSize(record)
	if err != nil {
		return err
	}
	if err := validateRecord(p.header, record); err != nil {
		return err
	}
	if recordBytes > ^uint64(0)-p.recordBytes {
		return wire.ErrBounds
	}
	cumulativeBytes := p.recordBytes + recordBytes
	cumulativeRecords := p.records + 1
	dataSet, err := p.shape.DataSetSizeForEncoded(cumulativeBytes, cumulativeRecords)
	if err != nil {
		return err
	}
	if uint64(headerLength)+dataSet.Length() < uint64(headerLength) {
		return wire.ErrBounds
	}
	total := uint64(headerLength) + dataSet.Length()
	if err := wire.ValidatePayloadLength(total, p.budget); err != nil {
		return err
	}
	if total > uint64(len(p.dst)) {
		return wire.ErrShortBuffer
	}
	c := cursor.New(p.dst[headerLength+int(p.recordBytes) : headerLength+int(cumulativeBytes)])
	writeRecord(&c, record, p.header.UptimeOriginUnixNanos)
	p.records = cumulativeRecords
	p.recordBytes = cumulativeBytes
	return nil
}

func (p *dataPacketAppender) Finish() (int, error) {
	if !p.begun {
		if p.done {
			return 0, wire.ErrPacketFinished
		}
		return 0, wire.ErrPacketNotBegun
	}
	if p.done {
		return 0, wire.ErrPacketFinished
	}
	if p.records == 0 {
		return 0, wire.ErrPacketEmpty
	}
	dataSet, err := p.shape.DataSetSizeForEncoded(p.recordBytes, p.records)
	if err != nil {
		return 0, err
	}
	total := uint64(headerLength) + dataSet.Length()
	if err := wire.ValidatePayloadLength(total, p.budget); err != nil {
		return 0, err
	}
	if total > uint64(len(p.dst)) {
		return 0, wire.ErrShortBuffer
	}
	// v5 has no set header or set padding.  All checks are complete before
	// these two final state writes, preserving atomic rejection.
	binary.BigEndian.PutUint16(p.dst[2:4], uint16(p.records))
	p.done = true
	return int(total), nil
}
