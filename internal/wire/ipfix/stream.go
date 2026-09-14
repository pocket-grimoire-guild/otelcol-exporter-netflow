package ipfix

import (
	"encoding/binary"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/internal/cursor"
)

// NewDataPacket returns a reusable incremental IPFIX data appender.
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
	dataOffset  int
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
	if request.Shape.Protocol() != wire.ProtocolIPFIX {
		return wire.ErrInvalidShape
	}
	if err := validateHeader(request.Header); err != nil {
		return err
	}
	if err := validateShapeOrdering(request.Shape); err != nil {
		return err
	}
	base := uint64(headerLength + 4)
	if err := wire.ValidatePayloadLength(base, request.MaxDatagramBytes); err != nil {
		return err
	}
	if uint64(len(dst)) < base {
		return wire.ErrShortBuffer
	}
	c := cursor.New(dst[:base])
	writeHeader(&c, request.Header, 0)
	_ = c.WriteUint16(request.Shape.ID())
	_ = c.WriteUint16(0)

	p.dst = dst
	p.header = request.Header
	p.shape = request.Shape
	p.budget = request.MaxDatagramBytes
	p.recordCap = limit
	p.records = 0
	p.recordBytes = 0
	p.dataOffset = headerLength + 4
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
	if err := validateRecord(p.shape, record); err != nil {
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
	total := uint64(headerLength) + dataSet.Length()
	if err := wire.ValidatePayloadLength(total, p.budget); err != nil {
		return err
	}
	if total > uint64(len(p.dst)) {
		return wire.ErrShortBuffer
	}
	c := cursor.New(p.dst[p.dataOffset+int(p.recordBytes) : p.dataOffset+int(cumulativeBytes)])
	writeDataRecord(&c, p.shape, record)
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
	binary.BigEndian.PutUint16(p.dst[2:4], uint16(total))
	binary.BigEndian.PutUint16(p.dst[headerLength+2:headerLength+4], uint16(dataSet.Length()))
	for i := uint8(0); i < dataSet.Padding(); i++ {
		p.dst[p.dataOffset+int(p.recordBytes)+int(i)] = 0
	}
	p.done = true
	return int(total), nil
}
