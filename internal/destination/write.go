package destination

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func (s *State) resetStreamLocked() {
	if s.stream != nil {
		s.stream.Reset()
	}
}

// BeginDataStream reserves a data packet and starts the one setup-time pure
// writer appender in the caller's datagram.  The appender retains no record or
// value views; all subsequent operations are synchronous under State's
// transaction lock.
func (s *State) BeginDataStream(wallUnixNanos, monotonicNanos uint64, shapeIndex int, dst []byte, samplingInterval uint32) (Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stream == nil {
		return Packet{}, ErrStreamingUnsupported
	}
	if s.pending != nil {
		return Packet{}, ErrTransaction
	}
	// A previous terminal path must not leave the shared appender retaining a
	// caller-owned buffer before this transaction starts.
	s.resetStreamLocked()
	if shapeIndex < 0 || shapeIndex >= s.catalog.ShapeCount() {
		return Packet{}, ErrShapeNotInCatalog
	}
	shape, ok := s.catalog.ShapeAt(shapeIndex)
	if !ok {
		return Packet{}, ErrShapeNotInCatalog
	}
	if s.epoch.uptimeExhausted {
		return Packet{}, ErrUptimeExhausted
	}
	if samplingInterval > 16383 || (s.config.Protocol != wire.ProtocolV5 && samplingInterval != 0) {
		return Packet{}, ErrInvalidConfig
	}
	if !s.epoch.ready {
		return Packet{}, ErrNotReady
	}
	s.markRefreshDueLocked(monotonicNanos)
	if s.refreshDue || s.refreshActive {
		return Packet{}, ErrRefreshRequired
	}

	priorRefreshActive, priorRefreshDue := s.refreshActive, s.refreshDue
	priorNextTemplateIndex, priorTemplateRound := s.nextTemplateIndex, s.templateRound
	priorReservedWall, priorHaveReservedWall := s.lastReservedWall, s.haveReservedWall
	priorStartOrigin, priorHasStartOrigin := s.epoch.startOrigin, s.epoch.hasStartOrigin
	instant, err := s.reserveWallLocked(wallUnixNanos)
	if err != nil {
		return Packet{}, err
	}
	header, err := s.headerLocked(instant, uint16(samplingInterval))
	if err != nil {
		s.lastReservedWall, s.haveReservedWall = priorReservedWall, priorHaveReservedWall
		return Packet{}, err
	}
	streamRequest := wire.DataPacketRequest{
		Header: header, Shape: shape, MaxDatagramBytes: s.config.MaxDatagramSize,
		MaxRecords: uint64(s.config.MaxRecordsPerMessage),
	}
	request := wire.PacketRequest{Header: header, Shape: shape, MaxDatagramBytes: s.config.MaxDatagramSize}
	s.nextToken++
	p := Packet{
		state: s, epochID: s.epoch.id, token: s.nextToken, request: request,
		shapeIndex: shapeIndex, monotonicNanos: monotonicNanos,
		logicalInstant:     instant,
		stream:             &streamPacketState{samplingInterval: uint16(samplingInterval), capacity: uint64(len(dst))},
		priorRefreshActive: priorRefreshActive, priorRefreshDue: priorRefreshDue,
		priorNextTemplateIndex: priorNextTemplateIndex, priorTemplateRound: priorTemplateRound,
		priorReservedWall: priorReservedWall, priorHaveReservedWall: priorHaveReservedWall,
		priorStartOrigin: priorStartOrigin, priorHasStartOrigin: priorHasStartOrigin,
	}
	s.pending = &p
	if err := s.stream.Begin(dst, streamRequest); err != nil {
		s.restoreEncodeReservationLocked(*s.pending)
		return Packet{}, err
	}
	return p, nil
}

func (s *State) streamPacketLocked(p *Packet) (*Packet, error) {
	if p == nil || s.pending == nil || p.stream == nil || p.state != s || p.epochID != s.epoch.id || s.pending.token != p.token || s.pending.stream != p.stream {
		return nil, ErrTransaction
	}
	return s.pending, nil
}

// Append validates one mapped record and appends it to the reserved datagram.
// V5 requires the explicit sampling metadata to agree with the packet header
// for every record; non-v5 packets have no destination sampling header and
// therefore accept only zero metadata.
func (p *Packet) Append(record wire.WireRecord, samplingRate uint32) error {
	if p == nil || p.state == nil {
		return ErrTransaction
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, err := s.streamPacketLocked(p)
	if err != nil {
		return err
	}
	if pending.encoded {
		return ErrTransaction
	}
	stream := pending.stream
	if s.config.Protocol == wire.ProtocolV5 {
		if samplingRate > 16383 || uint16(samplingRate) != stream.samplingInterval {
			return ErrInvalidConfig
		}
	} else if samplingRate != 0 {
		return ErrInvalidConfig
	}
	if stream.records >= uint64(s.config.MaxRecordsPerMessage) {
		return wire.ErrBounds
	}
	if s.config.Protocol == wire.ProtocolV5 && stream.records >= 30 {
		return wire.ErrBounds
	}
	shape := pending.request.Shape
	recordBytes, err := shape.RecordSize(record)
	if err != nil {
		return err
	}
	if recordBytes > math.MaxUint64-stream.bytes {
		return wire.ErrBounds
	}
	dataBytes := stream.bytes + recordBytes
	dataRecords := stream.records + 1
	dataSet, err := shape.DataSetSizeForEncoded(dataBytes, dataRecords)
	if err != nil {
		return err
	}
	datagramLength, ok := checkedPacketLength(s.config.Protocol, 0, 0, dataSet.Length())
	if !ok || datagramLength > s.config.MaxDatagramSize {
		return wire.ErrBounds
	}
	if datagramLength > stream.capacity {
		return wire.ErrShortBuffer
	}
	if err := s.stream.Append(record); err != nil {
		return err
	}
	stream.bytes = dataBytes
	stream.records = dataRecords
	pending.dataRecords = dataRecords
	pending.request.DataBytes = dataSet.Length()
	pending.datagramLength = datagramLength
	return nil
}

// Finish finalizes the appender's count, set length, and padding.  It is the
// only operation that makes a streamed Packet eligible for Commit.
func (p *Packet) Finish() (int, error) {
	if p == nil || p.state == nil {
		return 0, ErrTransaction
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, err := s.streamPacketLocked(p)
	if err != nil {
		return 0, err
	}
	if pending.encoded {
		return 0, ErrTransaction
	}
	stream := pending.stream
	if stream.records == 0 {
		_, finishErr := s.stream.Finish()
		s.restoreEncodeReservationLocked(*pending)
		if finishErr == nil {
			return 0, ErrEncoding
		}
		return 0, finishErr
	}
	dataSet, err := pending.request.Shape.DataSetSizeForEncoded(stream.bytes, stream.records)
	if err != nil {
		s.restoreEncodeReservationLocked(*pending)
		return 0, err
	}
	datagramLength, ok := checkedPacketLength(s.config.Protocol, 0, 0, dataSet.Length())
	if !ok || datagramLength > s.config.MaxDatagramSize {
		s.restoreEncodeReservationLocked(*pending)
		return 0, wire.ErrBounds
	}
	if datagramLength > stream.capacity {
		s.restoreEncodeReservationLocked(*pending)
		return 0, wire.ErrShortBuffer
	}
	n, err := s.stream.Finish()
	if err != nil {
		s.restoreEncodeReservationLocked(*pending)
		return 0, err
	}
	if n < 1 || uint64(n) != datagramLength {
		s.restoreEncodeReservationLocked(*pending)
		return 0, ErrEncoding
	}
	s.resetStreamLocked()
	stream.length = datagramLength
	pending.datagramLength = datagramLength
	pending.request.DataBytes = dataSet.Length()
	if s.config.Protocol != wire.ProtocolIPFIX {
		pending.request.Header.Count = uint16(stream.records)
	}
	pending.encoded = true
	return n, nil
}

// Abort releases a reservation before its datagram is handed to transport.
// The existing rollback path restores the reserved logical instant and any
// refresh/bootstrap state captured by Begin.
func (p Packet) Abort() error {
	if p.state == nil {
		return ErrTransaction
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.token != p.token || p.state != s || p.epochID != s.epoch.id {
		return ErrTransaction
	}
	s.restoreEncodeReservationLocked(*s.pending)
	return nil
}
