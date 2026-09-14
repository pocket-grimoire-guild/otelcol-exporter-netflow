package destination

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	defaultMaxDatagramSize      uint64 = 464
	defaultInitialCopies        uint8  = 2
	defaultRefreshInterval             = 10 * time.Minute
	defaultV9RefreshPackets     uint32 = 20
	defaultMaxRecordsPerMessage uint16 = 256
	minMaxDatagramSize          uint64 = 128
	maxMaxDatagramSize          uint64 = 65507
	minInitialCopies            uint8  = 2
	maxInitialCopies            uint8  = 8
	minRefreshInterval                 = 30 * time.Second
	maxRefreshInterval                 = 24 * time.Hour
	minRecordsPerMessage        uint16 = 1
	maxRecordsPerMessage        uint16 = 1024
)

var (
	ErrInvalidConfig        = errors.New("destination: invalid configuration")
	ErrNotReady             = errors.New("destination: template bootstrap incomplete")
	ErrRefreshRequired      = errors.New("destination: template refresh required")
	ErrRefreshNotDue        = errors.New("destination: template refresh not due")
	ErrUptimeExhausted      = errors.New("destination: uptime exhausted")
	ErrTimeNotRepresentable = errors.New("destination: time not representable")
	ErrTransaction          = errors.New("destination: invalid or already committed packet")
	ErrEncoding             = errors.New("destination: packet encoding failed")
	ErrInvalidWrite         = errors.New("destination: invalid write result")
	ErrShapeNotInCatalog    = errors.New("destination: shape is not in catalog")
	ErrTemplateProgress     = errors.New("destination: invalid template progress")
	ErrStreamingUnsupported = errors.New("destination: streaming writer unsupported")
)

// Config contains state-owned protocol identity and bounded state policy.
// Zero-valued policy fields select the documented defaults.  A zero
// IPFIXDataMessageRefreshCount explicitly disables that optional trigger.
// Mapping selection and PMTU family arithmetic remain mapping/packing
// responsibilities; MaxDatagramSize is checked here as the state budget.
type Config struct {
	Protocol              wire.Protocol
	SourceID              uint32
	ObservationDomainID   uint32
	EngineType            uint8
	EngineID              uint8
	SamplingMode          uint8
	HasUptimeOrigin       bool
	UptimeOriginUnixNanos uint64

	MaxDatagramSize              uint64
	MaxRecordsPerMessage         uint16
	InitialCopies                uint8
	RefreshInterval              time.Duration
	V9RefreshPacketCount         uint32
	IPFIXDataMessageRefreshCount uint32
}

// DefaultConfig returns state policy defaults for protocol.  It intentionally
// leaves identity and v5 uptime origin unset for the caller to supply.
func DefaultConfig(protocol wire.Protocol) Config {
	maxRecords := defaultMaxRecordsPerMessage
	if protocol == wire.ProtocolV5 {
		maxRecords = 30
	}
	return Config{
		Protocol:             protocol,
		MaxDatagramSize:      defaultMaxDatagramSize,
		MaxRecordsPerMessage: maxRecords,
		InitialCopies:        defaultInitialCopies,
		RefreshInterval:      defaultRefreshInterval,
		V9RefreshPacketCount: defaultV9RefreshPackets,
	}
}

func (c Config) normalized() (Config, error) {
	if c.Protocol != wire.ProtocolV5 && c.Protocol != wire.ProtocolV9 && c.Protocol != wire.ProtocolIPFIX {
		return Config{}, ErrInvalidConfig
	}
	if c.MaxDatagramSize == 0 {
		c.MaxDatagramSize = defaultMaxDatagramSize
	}
	if c.MaxRecordsPerMessage == 0 {
		c.MaxRecordsPerMessage = defaultMaxRecordsPerMessage
		if c.Protocol == wire.ProtocolV5 {
			c.MaxRecordsPerMessage = 30
		}
	}
	if c.InitialCopies == 0 {
		c.InitialCopies = defaultInitialCopies
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = defaultRefreshInterval
	}
	if c.V9RefreshPacketCount == 0 && c.Protocol == wire.ProtocolV9 {
		c.V9RefreshPacketCount = defaultV9RefreshPackets
	}
	if c.MaxDatagramSize < minMaxDatagramSize || c.MaxDatagramSize > maxMaxDatagramSize {
		return Config{}, ErrInvalidConfig
	}
	if c.MaxRecordsPerMessage < minRecordsPerMessage || c.MaxRecordsPerMessage > maxRecordsPerMessage {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV5 && c.MaxRecordsPerMessage > 30 {
		return Config{}, ErrInvalidConfig
	}
	if c.InitialCopies < minInitialCopies || c.InitialCopies > maxInitialCopies {
		return Config{}, ErrInvalidConfig
	}
	if c.RefreshInterval < minRefreshInterval || c.RefreshInterval > maxRefreshInterval {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV9 && (c.V9RefreshPacketCount < 1 || c.V9RefreshPacketCount > 1000) {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolIPFIX && c.IPFIXDataMessageRefreshCount > 1000 {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV5 && (c.SourceID != 0 || c.ObservationDomainID != 0) {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV9 && c.ObservationDomainID != 0 && c.ObservationDomainID != c.SourceID {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV9 && (c.EngineType != 0 || c.EngineID != 0 || c.SamplingMode != 0) {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolIPFIX && (c.SourceID != 0 || c.EngineType != 0 || c.EngineID != 0 || c.SamplingMode != 0 || c.HasUptimeOrigin) {
		return Config{}, ErrInvalidConfig
	}
	if c.Protocol == wire.ProtocolV5 && !c.HasUptimeOrigin {
		return Config{}, ErrInvalidConfig
	}
	if c.HasUptimeOrigin {
		if c.UptimeOriginUnixNanos > math.MaxInt64 {
			return Config{}, ErrInvalidConfig
		}
	}
	if c.Protocol == wire.ProtocolV5 && c.SamplingMode > 3 {
		return Config{}, ErrInvalidConfig
	}
	return c, nil
}

// State is one destination-local protocol state machine.  It contains no
// package or process globals and is safe for concurrent read/transition calls.
// The caller still owns transport admission and may serialize packet writes;
// State itself rejects a second uncommitted packet transaction.
type State struct {
	mu sync.Mutex

	mapping mapping.CompiledMapping
	catalog Catalog
	writer  wire.ContractWriter
	stream  wire.DataPacketAppender
	config  Config
	epoch   *epochState
	nextID  uint64

	nextTemplateIndex int
	templateRound     uint8
	refreshActive     bool
	refreshDue        bool

	lastRefreshMono  uint64
	haveRefreshMono  bool
	packetCount      uint32
	dataMessageCount uint32

	lastReservedWall uint64
	haveReservedWall bool
	nextToken        uint64
	pending          *Packet
}

// NewState creates a fresh epoch around the compiler-owned catalog and a pure
// writer.  The writer is injected so destination tests can verify state
// transitions independently of bytes/UDP; production callers provide the
// corresponding wire writer.
func NewState(compiled mapping.CompiledMapping, writer wire.ContractWriter, config Config) (*State, error) {
	if config.Protocol == wire.ProtocolUnknown {
		config.Protocol = compiled.Protocol()
	}
	normalized, err := config.normalized()
	if err != nil || normalized.Protocol != compiled.Protocol() {
		return nil, ErrInvalidConfig
	}
	config = normalized
	if config.MaxDatagramSize > compiled.MaxDatagramSize() {
		return nil, ErrInvalidConfig
	}
	if writer == nil {
		return nil, ErrInvalidConfig
	}
	catalog, err := NewCatalog(compiled)
	if err != nil {
		return nil, err
	}
	if config.Protocol != catalog.Protocol() {
		return nil, ErrInvalidConfig
	}
	if err := validateCatalogBudget(catalog, config.MaxDatagramSize); err != nil {
		return nil, err
	}
	if err := validateUptimeOrigin(compiled, catalog, config); err != nil {
		return nil, err
	}
	var stream wire.DataPacketAppender
	if streaming, ok := writer.(wire.StreamingWriter); ok {
		stream = streaming.NewDataPacket()
		if stream == nil {
			return nil, ErrInvalidConfig
		}
	}
	s := &State{mapping: compiled, catalog: catalog, writer: writer, stream: stream, config: config, nextID: 1}
	s.epoch = newEpoch(s.nextID, config.Protocol)
	if config.Protocol == wire.ProtocolV5 {
		s.epoch.ready = true
	}
	return s, nil
}

func validateUptimeOrigin(compiled mapping.CompiledMapping, catalog Catalog, config Config) error {
	if config.Protocol != wire.ProtocolV5 && config.Protocol != wire.ProtocolV9 {
		return nil
	}
	for index := 0; index < catalog.ShapeCount(); index++ {
		shape, ok := catalog.ShapeAt(index)
		if !ok {
			return wire.ErrInvalidCatalog
		}
		for fieldIndex := 0; fieldIndex < shape.FieldCount(); fieldIndex++ {
			descriptor, ok := shape.DescriptorAt(fieldIndex)
			if !ok {
				return wire.ErrInvalidShape
			}
			if descriptor.Field != wire.FieldFlowStart && descriptor.Field != wire.FieldFlowEnd {
				continue
			}
			origin, present := compiled.UptimeOrigin()
			if !present || !config.HasUptimeOrigin || origin != config.UptimeOriginUnixNanos {
				return ErrInvalidConfig
			}
			return nil
		}
	}
	return nil
}

// Mapping returns the immutable compiler result adopted by this state.
func (s *State) Mapping() mapping.CompiledMapping { return s.mapping }

// Catalog returns the immutable catalog adopted by this state.
func (s *State) Catalog() Catalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.catalog
}

// Config returns the normalized state configuration by value.
func (s *State) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

// Epoch reports a consistent read-only state snapshot.
func (s *State) Epoch() EpochSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch.snapshot()
}

// Sequence reports the next sequence value that a packet header will carry.
func (s *State) Sequence() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch.sequence
}

// Ready reports whether this epoch may send data records.
func (s *State) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch.ready && !s.refreshActive && !s.refreshDue && !s.epoch.uptimeExhausted
}

// RefreshDue reports and records whether an interval/count refresh is due at
// monotonic time.  A backwards monotonic value never underflows or creates a
// false due event.
func (s *State) RefreshDue(monotonicNanos uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markRefreshDueLocked(monotonicNanos)
	return s.refreshDue || s.refreshActive
}

// BeginTemplate reserves one ordinary template packet for the next shape in
// the current bootstrap/refresh round.  A round consists of one committed
// template packet for every catalog shape, in compiler order.
func (s *State) BeginTemplate(wallUnixNanos, monotonicNanos uint64, shapeIndex int) (Packet, error) {
	return s.beginPacket(wallUnixNanos, monotonicNanos, shapeIndex, 1, DataRequest{})
}

// DataRequest is the allocation-free input contract for one data packet.
// Records is a bounded borrowed slice: the internal caller must not mutate or
// reuse it until Packet.Encode returns. V5SamplingRates is consumed
// synchronously by BeginData and must contain exactly one value per Records
// entry, with all v5 values agreeing. It is absent for v9 and IPFIX, whose
// selected templates carry any sampling element instead.
type DataRequest struct {
	Records         []wire.WireRecord
	V5SamplingRates []uint32
}

// BeginData reserves one data packet.  Data is unavailable until bootstrap
// and any due refresh complete.
func (s *State) BeginData(wallUnixNanos, monotonicNanos uint64, shapeIndex int, request DataRequest) (Packet, error) {
	return s.beginPacket(wallUnixNanos, monotonicNanos, shapeIndex, 0, request)
}

func validateDataRequest(protocol wire.Protocol, request DataRequest) (uint16, error) {
	if protocol != wire.ProtocolV5 {
		if request.V5SamplingRates != nil {
			return 0, ErrInvalidConfig
		}
		return 0, nil
	}
	if len(request.V5SamplingRates) != len(request.Records) {
		return 0, ErrInvalidConfig
	}
	var common uint32
	for index, rate := range request.V5SamplingRates {
		if rate > 16383 {
			return 0, ErrInvalidConfig
		}
		if index == 0 {
			common = rate
		} else if rate != common {
			return 0, ErrInvalidConfig
		}
	}
	return uint16(common), nil
}

func (s *State) beginPacket(wallUnixNanos, monotonicNanos uint64, shapeIndex int, templateRecords uint64, data DataRequest) (Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return Packet{}, ErrTransaction
	}
	if templateRecords > 1 {
		return Packet{}, ErrTemplateProgress
	}
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
	records := data.Records
	if templateRecords == 0 && len(records) == 0 {
		return Packet{}, ErrInvalidConfig
	}
	if uint64(len(records)) > uint64(s.config.MaxRecordsPerMessage) {
		return Packet{}, ErrInvalidConfig
	}
	if s.config.Protocol == wire.ProtocolV5 && (len(records) == 0 || len(records) > 30) {
		return Packet{}, ErrInvalidConfig
	}
	if s.config.Protocol == wire.ProtocolV9 {
		count := templateRecords + uint64(len(records))
		if count > math.MaxUint16 {
			return Packet{}, ErrInvalidConfig
		}
	}
	samplingInterval, err := validateDataRequest(s.config.Protocol, data)
	if err != nil {
		return Packet{}, err
	}
	dataBytes, err := shape.DataSetSize(records)
	if err != nil {
		return Packet{}, err
	}
	templateBytes := uint64(0)
	if templateRecords != 0 {
		templateBytes = shape.TemplateBytes()
	}
	messageBytes, ok := checkedPacketLength(s.config.Protocol, templateRecords, templateBytes, dataBytes.Length())
	if !ok || messageBytes > s.config.MaxDatagramSize {
		return Packet{}, wire.ErrBounds
	}
	var priorRefreshActive bool
	var priorRefreshDue bool
	var priorNextTemplateIndex int
	var priorTemplateRound uint8
	var priorReservedWall uint64
	var priorHaveReservedWall bool
	var priorStartOrigin uint64
	var priorHasStartOrigin bool
	if templateRecords != 0 {
		if s.config.Protocol == wire.ProtocolV5 {
			return Packet{}, ErrTemplateProgress
		}
		if len(records) != 0 {
			if s.epoch.ready {
				return Packet{}, ErrRefreshRequired
			}
			return Packet{}, ErrNotReady
		}
		if err := s.prepareTemplateLocked(monotonicNanos, shapeIndex); err != nil {
			return Packet{}, err
		}
	} else {
		if !s.epoch.ready {
			return Packet{}, ErrNotReady
		}
		s.markRefreshDueLocked(monotonicNanos)
		if s.refreshDue || s.refreshActive {
			return Packet{}, ErrRefreshRequired
		}
	}
	// For refresh templates, prepareTemplateLocked has now established the
	// authoritative due state. Snapshot immediately before this reservation
	// starts (and before a refresh round is marked active).
	priorRefreshActive, priorRefreshDue = s.refreshActive, s.refreshDue
	priorNextTemplateIndex, priorTemplateRound = s.nextTemplateIndex, s.templateRound
	priorReservedWall, priorHaveReservedWall = s.lastReservedWall, s.haveReservedWall
	priorStartOrigin, priorHasStartOrigin = s.epoch.startOrigin, s.epoch.hasStartOrigin
	instant, err := s.reserveWallLocked(wallUnixNanos)
	if err != nil {
		return Packet{}, err
	}
	if templateRecords != 0 && s.config.Protocol == wire.ProtocolV9 && !s.config.HasUptimeOrigin && !s.epoch.hasStartOrigin {
		// This is the candidate start-origin capture point: no writer or
		// transport operation occurs between reservation and this assignment.
		s.epoch.startOrigin, s.epoch.hasStartOrigin = instant, true
	}
	header, err := s.headerLocked(instant, samplingInterval)
	if err != nil {
		return Packet{}, err
	}
	switch s.config.Protocol {
	case wire.ProtocolV5:
		header.Count = uint16(len(records))
	case wire.ProtocolV9:
		header.Count = uint16(templateRecords + uint64(len(records)))
	}
	request := wire.PacketRequest{
		Header: header, Shape: shape, Records: records,
		TemplateRecords: templateRecords, TemplateBytes: templateRecords * shape.TemplateBytes(),
		DataBytes: dataBytes.Length(), MaxDatagramBytes: s.config.MaxDatagramSize,
	}
	s.nextToken++
	p := Packet{
		state: s, epochID: s.epoch.id, token: s.nextToken, request: request,
		shapeIndex: shapeIndex, templateRecords: templateRecords,
		dataRecords: uint64(len(records)), monotonicNanos: monotonicNanos,
		logicalInstant: instant, datagramLength: messageBytes,
		priorRefreshActive: priorRefreshActive, priorRefreshDue: priorRefreshDue,
		priorNextTemplateIndex: priorNextTemplateIndex, priorTemplateRound: priorTemplateRound,
		priorReservedWall: priorReservedWall, priorHaveReservedWall: priorHaveReservedWall,
		priorStartOrigin: priorStartOrigin, priorHasStartOrigin: priorHasStartOrigin,
	}
	if templateRecords != 0 && s.epoch.ready && !s.refreshActive {
		// Delay beginning a refresh round until every fallible validation above
		// has passed; a rejected packet must not strand the state as active.
		s.refreshActive = true
		s.nextTemplateIndex, s.templateRound = 0, 0
	}
	s.pending = &p
	return p, nil
}

func (s *State) prepareTemplateLocked(monotonicNanos uint64, shapeIndex int) error {
	if s.epoch.ready {
		s.markRefreshDueLocked(monotonicNanos)
		if !s.refreshDue && !s.refreshActive {
			return ErrRefreshNotDue
		}
	}
	if shapeIndex != s.nextTemplateIndex {
		return ErrTemplateProgress
	}
	return nil
}

func (s *State) reserveWallLocked(wall uint64) (uint64, error) {
	if wall > math.MaxInt64 {
		return 0, ErrTimeNotRepresentable
	}
	if s.haveReservedWall && wall < s.lastReservedWall {
		wall = s.lastReservedWall
	}
	if wall/1_000_000_000 > math.MaxUint32 {
		return 0, ErrTimeNotRepresentable
	}
	if s.config.Protocol != wire.ProtocolIPFIX {
		origin, ok := s.uptimeOriginLocked()
		if !ok {
			// A v9 candidate without a configured origin captures its origin
			// immediately before the first bootstrap write, after reservation.
			if s.config.Protocol == wire.ProtocolV9 && !s.epoch.ready && !s.epoch.hasStartOrigin {
				s.lastReservedWall, s.haveReservedWall = wall, true
				return wall, nil
			}
			return 0, ErrTimeNotRepresentable
		}
		if wall < origin {
			return 0, ErrTimeNotRepresentable
		}
		delta := wall - origin
		if delta/1_000_000 > math.MaxUint32 {
			s.epoch.uptimeExhausted = true
			return 0, ErrUptimeExhausted
		}
		if delta%1_000_000 != 0 {
			return 0, ErrTimeNotRepresentable
		}
	}
	s.lastReservedWall, s.haveReservedWall = wall, true
	return wall, nil
}

func (s *State) uptimeOriginLocked() (uint64, bool) {
	if s.config.HasUptimeOrigin {
		return s.config.UptimeOriginUnixNanos, true
	}
	if s.epoch.hasStartOrigin {
		return s.epoch.startOrigin, true
	}
	return 0, false
}

func (s *State) headerLocked(instant uint64, samplingInterval uint16) (wire.HeaderMetadata, error) {
	header := wire.HeaderMetadata{Protocol: s.config.Protocol, Sequence: s.epoch.sequence, SourceID: s.config.SourceID, ObservationDomainID: s.config.ObservationDomainID, EngineType: s.config.EngineType, EngineID: s.config.EngineID, SamplingMode: s.config.SamplingMode, SamplingInterval: samplingInterval, ExportTimeUnixNanos: instant}
	switch s.config.Protocol {
	case wire.ProtocolV5, wire.ProtocolV9:
		origin, ok := s.uptimeOriginLocked()
		if !ok {
			return wire.HeaderMetadata{}, ErrTimeNotRepresentable
		}
		header.HasUptimeOrigin, header.UptimeOriginUnixNanos = true, origin
	}
	return header, header.Validate()
}

func (s *State) markRefreshDueLocked(monotonicNanos uint64) {
	if s.config.Protocol == wire.ProtocolV5 || !s.epoch.ready || s.refreshActive || s.refreshDue {
		return
	}
	if s.haveRefreshMono && monotonicNanos >= s.lastRefreshMono && monotonicNanos-s.lastRefreshMono >= uint64(s.config.RefreshInterval) {
		s.refreshDue = true
		return
	}
	if s.config.Protocol == wire.ProtocolV9 && s.packetCount >= s.config.V9RefreshPacketCount {
		s.refreshDue = true
	}
	if s.config.Protocol == wire.ProtocolIPFIX && s.config.IPFIXDataMessageRefreshCount != 0 && s.dataMessageCount >= s.config.IPFIXDataMessageRefreshCount {
		s.refreshDue = true
	}
}

// Commit applies the write-result boundary for a packet.  Only a full write
// with nil error commits sequence and progress. Legal non-full outcomes are
// ambiguous and leave counters unchanged; an invalid local result is rejected
// and rolls back its reservation wall before candidate cleanup.
func (s *State) Commit(packet Packet, n int, writeErr error) (CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.token != packet.token || packet.state != s || packet.epochID != s.epoch.id {
		return CommitResult{}, ErrTransaction
	}
	pending := s.pending
	if !pending.encoded {
		return CommitResult{}, ErrTransaction
	}
	defer func() { s.pending = nil }()
	datagramLength := pending.datagramLength
	class := ClassifyWrite(n, int(datagramLength), writeErr)
	result := CommitResult{Class: class, SequenceBefore: s.epoch.sequence, LogicalSendInstant: pending.logicalInstant, DatagramLength: datagramLength}
	if class == WriteInvalid {
		s.restoreInvalidWriteReservationLocked(*s.pending)
		s.discardUnpublishedLocked()
		result.SequenceAfter = s.epoch.sequence
		result.Ready = s.epoch.ready
		result.RefreshDue = s.refreshDue || s.refreshActive
		return result, ErrInvalidWrite
	}
	if class != WriteFull {
		s.discardUnpublishedLocked()
		result.Committed = false
		result.SequenceAfter = s.epoch.sequence
		result.Ready = s.epoch.ready
		result.RefreshDue = s.refreshDue || s.refreshActive
		return result, nil
	}

	s.commitSequenceLocked(*pending)
	if pending.templateRecords != 0 {
		s.nextTemplateIndex++
		if s.nextTemplateIndex == s.catalog.ShapeCount() {
			s.nextTemplateIndex = 0
			s.templateRound++
			if !s.epoch.ready {
				if s.templateRound == s.config.InitialCopies {
					s.epoch.ready = true
					s.refreshActive, s.refreshDue = false, false
					s.packetCount, s.dataMessageCount = 0, 0
					s.lastRefreshMono, s.haveRefreshMono = pending.monotonicNanos, true
					s.templateRound = 0
				}
			} else if s.refreshActive && s.templateRound == 1 {
				s.refreshActive, s.refreshDue = false, false
				s.packetCount, s.dataMessageCount = 0, 0
				s.lastRefreshMono, s.haveRefreshMono = pending.monotonicNanos, true
				s.templateRound = 0
			}
		}
	}
	// A successful data-bearing packet may itself cross a count/interval
	// threshold.  Marking here makes the refresh due immediately after the
	// commit, while the completed-round reset above remains authoritative.
	s.markRefreshDueLocked(pending.monotonicNanos)
	result.Committed = true
	result.SequenceAfter = s.epoch.sequence
	result.Ready = s.epoch.ready
	result.RefreshDue = s.refreshDue || s.refreshActive
	return result, nil
}

func (s *State) discardUnpublishedLocked() {
	if s.epoch.ready {
		return
	}
	// An unpublished candidate cannot retain failed v9 origin or partial
	// bootstrap progress. Retry begins from copy/shape zero.
	s.nextTemplateIndex, s.templateRound = 0, 0
	s.epoch.startOrigin, s.epoch.hasStartOrigin = 0, false
	s.epoch.sequence = 0
	s.packetCount, s.dataMessageCount = 0, 0
	s.refreshActive, s.refreshDue = false, false
	s.lastRefreshMono, s.haveRefreshMono = 0, false
}

func (s *State) commitSequenceLocked(packet Packet) {
	switch s.config.Protocol {
	case wire.ProtocolV5:
		s.epoch.sequence += uint32(packet.dataRecords)
	case wire.ProtocolV9:
		s.epoch.sequence++
		s.packetCount++
	case wire.ProtocolIPFIX:
		s.epoch.sequence += uint32(packet.dataRecords)
		if packet.dataRecords != 0 {
			s.dataMessageCount++
		}
	}
}

// Restart discards all state and starts a fresh in-memory endpoint epoch.
// Compiler-assigned catalog IDs remain unchanged; sequence/progress/clock
// state are reset and no prior epoch is persisted or shared.
func (s *State) Restart() EpochSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetStreamLocked()
	s.nextID++
	s.epoch = newEpoch(s.nextID, s.config.Protocol)
	s.nextTemplateIndex, s.templateRound = 0, 0
	s.refreshActive, s.refreshDue = false, false
	s.lastRefreshMono, s.haveRefreshMono = 0, false
	s.packetCount, s.dataMessageCount = 0, 0
	s.lastReservedWall, s.haveReservedWall = 0, false
	s.pending = nil
	return s.epoch.snapshot()
}

// AbortBootstrap discards an unpublished epoch's partial bootstrap.  It is a
// narrow lifecycle hook for candidate setup; published state should use
// Restart when replacing the endpoint.
func (s *State) AbortBootstrap() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch.ready || s.config.Protocol == wire.ProtocolV5 {
		return ErrInvalidConfig
	}
	s.epoch.sequence = 0
	s.epoch.startOrigin, s.epoch.hasStartOrigin = 0, false
	s.nextTemplateIndex, s.templateRound = 0, 0
	s.refreshActive, s.refreshDue = false, false
	s.packetCount, s.dataMessageCount = 0, 0
	s.resetStreamLocked()
	s.pending = nil
	return nil
}

// Packet is an opaque reservation, not a defensive copy of DataRequest. Encode
// or Finish must first complete exactly; then the transport result is reported
// to State.Commit before another packet can be reserved. After encoding,
// Commit relies only on captured scalar state and progress, not record bytes.
type Packet struct {
	state           *State
	epochID         uint64
	token           uint64
	request         wire.PacketRequest
	shapeIndex      int
	templateRecords uint64
	dataRecords     uint64
	monotonicNanos  uint64
	logicalInstant  uint64
	datagramLength  uint64
	encoded         bool
	stream          *streamPacketState

	priorRefreshActive     bool
	priorRefreshDue        bool
	priorNextTemplateIndex int
	priorTemplateRound     uint8
	priorReservedWall      uint64
	priorHaveReservedWall  bool
	priorStartOrigin       uint64
	priorHasStartOrigin    bool
}

// streamPacketState is the single mutable value handle for a streaming
// transaction. Packet values may be copied, but all append/finalization
// counters remain owned by the pending transaction.
type streamPacketState struct {
	samplingInterval uint16
	records          uint64
	bytes            uint64
	capacity         uint64
	length           uint64
}

// Encode invokes the injected pure writer. A successful exact result leaves
// this reservation pending for Commit. Any pure encoding failure restores its
// reservation wall and clears the transaction; unpublished bootstrap failures
// also discard the candidate.
func (p Packet) Encode(dst []byte) (int, error) {
	if p.state == nil {
		return 0, ErrTransaction
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil || s.pending.token != p.token || p.epochID != s.epoch.id || p.state != s {
		return 0, ErrTransaction
	}
	if s.pending.stream != nil || s.pending.encoded {
		return 0, ErrTransaction
	}
	n, err := s.writer.Write(dst, p.request)
	if err != nil || n < 0 || uint64(n) != p.datagramLength {
		s.restoreEncodeReservationLocked(*s.pending)
		return 0, ErrEncoding
	}
	s.pending.encoded = true
	return n, nil
}

func (s *State) restoreEncodeReservationLocked(packet Packet) {
	if packet.stream != nil {
		s.resetStreamLocked()
	}
	s.restoreReservationWallLocked(packet)
	if !s.epoch.ready {
		// A pure writer failure during bootstrap abandons the unpublished
		// candidate; only its pre-reservation logical wall is reusable.
		s.discardUnpublishedLocked()
	} else {
		s.epoch.startOrigin, s.epoch.hasStartOrigin = packet.priorStartOrigin, packet.priorHasStartOrigin
		s.refreshActive, s.refreshDue = packet.priorRefreshActive, packet.priorRefreshDue
		s.nextTemplateIndex, s.templateRound = packet.priorNextTemplateIndex, packet.priorTemplateRound
	}
	s.pending = nil
}

func (s *State) restoreInvalidWriteReservationLocked(packet Packet) {
	// An invalid local result is not an ambiguous UDP handoff. Restore only
	// the reservation's logical wall; candidate cleanup and published refresh
	// retention are shared with every other invalid-write path.
	s.restoreReservationWallLocked(packet)
}

func (s *State) restoreReservationWallLocked(packet Packet) {
	s.lastReservedWall, s.haveReservedWall = packet.priorReservedWall, packet.priorHaveReservedWall
}

func (p Packet) Sequence() uint32           { return p.request.Header.Sequence }
func (p Packet) LogicalSendInstant() uint64 { return p.logicalInstant }
func (p Packet) DatagramLength() uint64 {
	if p.stream != nil && p.state != nil {
		p.state.mu.Lock()
		defer p.state.mu.Unlock()
		return p.stream.length
	}
	return p.datagramLength
}
func (p Packet) ShapeIndex() int         { return p.shapeIndex }
func (p Packet) TemplateRecords() uint64 { return p.templateRecords }
func (p Packet) DataRecords() uint64 {
	if p.stream != nil && p.state != nil {
		p.state.mu.Lock()
		defer p.state.mu.Unlock()
		return p.stream.records
	}
	return p.dataRecords
}

// WriteClass is the complete legal local write-result partition.  FullError
// is intentionally ambiguous even when all bytes were handed to the socket.
type WriteClass uint8

const (
	WriteFull WriteClass = iota + 1
	WriteShortNil
	WriteZeroNil
	WriteShortError
	WriteZeroError
	WriteFullError
	WriteInvalid
)

// ClassifyWrite maps all six {n,error} outcomes to a stable state boundary.
func ClassifyWrite(n, length int, err error) WriteClass {
	if length < 0 || n < 0 || n > length {
		return WriteInvalid
	}
	if n == length && err == nil {
		return WriteFull
	}
	if n == length {
		return WriteFullError
	}
	if n == 0 && err == nil {
		return WriteZeroNil
	}
	if n == 0 {
		return WriteZeroError
	}
	if err == nil {
		return WriteShortNil
	}
	return WriteShortError
}

// CommitResult reports the state boundary without exposing endpoint or raw
// payload details.
type CommitResult struct {
	Class              WriteClass
	Committed          bool
	Ready              bool
	RefreshDue         bool
	SequenceBefore     uint32
	SequenceAfter      uint32
	LogicalSendInstant uint64
	DatagramLength     uint64
}

// ProgressSnapshot exposes bounded template/refresh counters for lifecycle
// coordination and deterministic tests.  It contains no mutable references.
type ProgressSnapshot struct {
	NextShape        int
	CompletedRounds  uint8
	InitialCopies    uint8
	RefreshActive    bool
	RefreshDue       bool
	PacketCount      uint32
	DataMessageCount uint32
	LastRefreshMono  uint64
	HasRefreshMono   bool
}

// Progress reports template and refresh state without permitting mutation.
func (s *State) Progress() ProgressSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ProgressSnapshot{
		NextShape:        s.nextTemplateIndex,
		CompletedRounds:  s.templateRound,
		InitialCopies:    s.config.InitialCopies,
		RefreshActive:    s.refreshActive,
		RefreshDue:       s.refreshDue,
		PacketCount:      s.packetCount,
		DataMessageCount: s.dataMessageCount,
		LastRefreshMono:  s.lastRefreshMono,
		HasRefreshMono:   s.haveRefreshMono,
	}
}

func checkedPacketLength(protocol wire.Protocol, templateRecords, templateBytes, dataBytes uint64) (uint64, bool) {
	var header uint64
	switch protocol {
	case wire.ProtocolV5:
		header = 24
	case wire.ProtocolV9:
		header = 20
	case wire.ProtocolIPFIX:
		header = 16
	default:
		return 0, false
	}
	if templateRecords != 0 {
		if templateBytes > math.MaxUint64/templateRecords {
			return 0, false
		}
		templateBytes *= templateRecords
	}
	if header > math.MaxUint64-templateBytes {
		return 0, false
	}
	total := header + templateBytes
	if total > math.MaxUint64-dataBytes {
		return 0, false
	}
	return total + dataBytes, true
}
