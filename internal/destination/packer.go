package destination

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

// DatagramWrite hands one complete datagram to the destination transport. The
// callback is synchronous and receives the caller context and a borrowed view
// of Packer's one fixed buffer. It returns the bytes handed off and local error;
// Packer classifies that pair through State.Commit and never retains the error.
type DatagramWrite func(context.Context, []byte) (int, error)

// PacketClock returns a wall-clock Unix timestamp in nanoseconds and an
// independent monotonic timestamp in nanoseconds. Packer invokes it once for
// each template or data packet reservation.
type PacketClock func() (wallUnixNanos, monotonicNanos uint64)

// IndexedLookup is the synchronous custom-field bridge. The source ordinal is
// included deliberately: two source records may provide different values for
// the same compiled custom key. Neither the callback nor its returned value is
// retained by Packer.
type IndexedLookup func(sourceOrdinal uint64, source string) (wire.Value, bool)

// PackerConfig supplies the runtime seams needed by the destination-only
// packer. Packet and protocol bounds are enforced by mapping, packetization,
// and the writer.
type PackerConfig struct {
	Observe Observer
	// Available is an optional synchronous gate before packet construction and
	// handoff. False aborts buffered data locally and keeps valid sources unsent.
	Available func() bool
	Write     DatagramWrite
	Clock     PacketClock
}

// PackOutcome is the fixed aggregate result class. It intentionally carries no
// transport or callback text.
type PackOutcome uint8

const (
	PackSucceeded PackOutcome = iota + 1
	PackPermanent
	PackTransient
	PackInternal
)

var (
	// ErrPackerBusy is returned without waiting when one Packer is already
	// processing a request.
	ErrPackerBusy = errors.New("destination: packer busy")
	// ErrPackPermanent reports a request with no successfully confirmed valid
	// record. Invalid source records are represented in the result ledger.
	ErrPackPermanent = errors.New("destination: permanent packet loss")
	// ErrPackTransient reports an ambiguous whole-datagram handoff. The result
	// ledger identifies ambiguous and unsent-valid ordinals without retaining
	// the datagram or source data.
	ErrPackTransient = errors.New("destination: transient packet handoff")
	// ErrPackInternal reports a local state, appender, or write-contract
	// violation. Raw callback errors are intentionally excluded.
	ErrPackInternal = errors.New("destination: internal packet failure")
	// ErrPackAdmission reports a request rejected before indexed callbacks run.
	ErrPackAdmission = errors.New("destination: request admission failed")
)

// PackResult owns the fixed source ledger produced by one request. It contains
// only scalar counters and classifications; no pdata, record, lookup value,
// datagram, or raw error is retained.
type PackResult struct {
	ledger *sourceLedger

	outcome             PackOutcome
	exporterLosses      uint64
	canonicalSourceLoss uint64
	packets             uint64
	confirmedPackets    uint64
	ambiguousPackets    uint64
}

// Outcome reports the fixed aggregate class for this result.
func (r *PackResult) Outcome() PackOutcome {
	if r == nil {
		return PackInternal
	}
	return r.outcome
}

// Error maps the aggregate class to a fixed redacted error. Successful and
// zero-value results have no error.

func (r *PackResult) Error() error {
	if r == nil {
		return ErrPackInternal
	}
	switch r.outcome {
	case PackPermanent:
		return ErrPackPermanent
	case PackTransient:
		return ErrPackTransient
	case PackInternal:
		return ErrPackInternal
	default:
		return nil
	}
}

// Classification returns the result ledger class for one source ordinal.

func (r *PackResult) Classification(ordinal uint64) SourceClass {
	if r == nil || r.ledger == nil {
		return SourceUncovered
	}
	return r.ledger.Classification(ordinal)
}

// Counts returns a value copy of the result ledger counters.
func (r *PackResult) Counts() SourceLedgerCounts {
	if r == nil || r.ledger == nil {
		return SourceLedgerCounts{}
	}
	return r.ledger.Counts()
}

// RejectionCounts returns a value-copy fixed histogram of invalid source
// records. The returned array does not alias the request ledger.
func (r *PackResult) RejectionCounts() RejectionCounts {
	if r == nil || r.ledger == nil {
		return RejectionCounts{}
	}
	return r.ledger.RejectionCounts()
}

// Packet returns a value copy of the final active-packet boundary. A completed
// request normally has no active packet; it is exposed for diagnostic parity
// with sourceLedger and is never a mutable reference.
func (r *PackResult) Packet() SourceLedgerPacket {
	if r == nil || r.ledger == nil {
		return SourceLedgerPacket{}
	}
	return r.ledger.Packet()
}

// ExporterLosses reports bounded mapping-loss events across mapped records.
func (r *PackResult) ExporterLosses() uint64 {
	if r == nil {
		return 0
	}
	return r.exporterLosses
}

// CanonicalSourceLoss reports bounded source-attribute losses across mapped
// records.
func (r *PackResult) CanonicalSourceLoss() uint64 {
	if r == nil {
		return 0
	}
	return r.canonicalSourceLoss
}

// Packets reports the number of data datagrams that reached State.Commit.
func (r *PackResult) Packets() uint64 {
	if r == nil {
		return 0
	}
	return r.packets
}

// ConfirmedPackets and AmbiguousPackets expose only scalar write counts.
func (r *PackResult) ConfirmedPackets() uint64 {
	if r == nil {
		return 0
	}
	return r.confirmedPackets
}
func (r *PackResult) AmbiguousPackets() uint64 {
	if r == nil {
		return 0
	}
	return r.ambiguousPackets
}

// Packer streams one request through one State transaction at a time. Its
// datagram and packet state remain bounded; the source ledger grows compactly
// with the request so valid records are not rejected at an arbitrary count.
type Packer struct {
	state  *State
	config PackerConfig

	datagram   []byte
	validation wire.DataPacketAppender
	ledger     *sourceLedger

	packet       Packet
	packetOpen   bool
	ledgerOpen   bool
	packetShape  int
	packetSample uint32

	stopped   bool
	transient bool
	internal  bool

	previewInstant     uint64
	havePreviewInstant bool

	exporterLosses      uint64
	canonicalSourceLoss uint64
	packets             uint64
	confirmedPackets    uint64
	ambiguousPackets    uint64

	busy uint32
}

// NewPacker requires an already bootstrapped State and allocates the one
// reusable payload buffer. Bootstrap and publication remain lifecycle-owned.
func NewPacker(state *State, config PackerConfig) (*Packer, error) {
	if state == nil || config.Write == nil || config.Clock == nil {
		return nil, ErrInvalidConfig
	}
	state.mu.Lock()
	if state.epoch == nil {
		state.mu.Unlock()
		return nil, ErrNotReady
	}
	epoch := state.epoch.snapshot()
	maxDatagram := state.config.MaxDatagramSize
	streaming := state.stream != nil
	writer := state.writer
	state.mu.Unlock()
	if !epoch.Ready {
		return nil, ErrNotReady
	}
	if epoch.UptimeExhausted {
		return nil, ErrUptimeExhausted
	}
	if !streaming || maxDatagram < minMaxDatagramSize || maxDatagram > maxMaxDatagramSize {
		return nil, ErrInvalidConfig
	}
	if maxDatagram > uint64(int(^uint(0)>>1)) {
		return nil, ErrInvalidConfig
	}
	streamingWriter, ok := writer.(wire.StreamingWriter)
	if !ok {
		return nil, ErrInvalidConfig
	}
	validation := streamingWriter.NewDataPacket()
	if validation == nil {
		return nil, ErrInvalidConfig
	}
	return &Packer{state: state, config: config, datagram: make([]byte, int(maxDatagram)), validation: validation}, nil
}

// Pack consumes one receiver-compatible pdata request synchronously. All
// records are indexed before any per-record result is classified; admission
// failure therefore performs no lookup callbacks or writes. The lookup bridge
// and context are request-local and never stored on Packer or PackResult.
func (p *Packer) Pack(ctx context.Context, logs plog.Logs, lookup IndexedLookup) (*PackResult, error) {
	if p == nil || p.state == nil || ctx == nil {
		return &PackResult{outcome: PackInternal}, ErrPackInternal
	}
	if !atomic.CompareAndSwapUint32(&p.busy, 0, 1) {
		return &PackResult{outcome: PackTransient}, ErrPackerBusy
	}
	defer atomic.StoreUint32(&p.busy, 0)

	var ledger sourceLedger
	p.ledger = &ledger
	defer func() { p.ledger = nil }()
	p.resetRequest()
	normalizeErr := normalize.NormalizeEachIndexed(logs, func(ordinal uint64, normalized wire.NormalizedRecord, normalizeErr error) error {
		return p.consume(ctx, lookup, ordinal, normalized, normalizeErr)
	})
	if normalizeErr != nil && !errors.Is(normalizeErr, normalize.ErrNoRecords) {
		result := p.result(PackPermanent)
		return result, ErrPackAdmission
	}
	if !p.stopped && p.packetOpen {
		p.flushData(ctx)
	}
	if p.internal {
		result := p.result(PackInternal)
		return result, ErrPackInternal
	}
	if p.transient {
		result := p.result(PackTransient)
		return result, ErrPackTransient
	}
	counts := p.ledger.Counts()
	if normalizeErr != nil || counts.Valid == 0 || counts.Confirmed == 0 {
		result := p.result(PackPermanent)
		return result, ErrPackPermanent
	}
	result := p.result(PackSucceeded)
	return result, nil
}

func (p *Packer) resetRequest() {
	if p.validation != nil {
		p.validation.Reset()
	}
	p.packet = Packet{}
	p.packetOpen = false
	p.ledgerOpen = false
	p.packetShape = 0
	p.packetSample = 0
	p.stopped = false
	p.transient = false
	p.internal = false
	p.previewInstant = 0
	p.havePreviewInstant = false
	p.exporterLosses = 0
	p.canonicalSourceLoss = 0
	p.packets = 0
	p.confirmedPackets = 0
	p.ambiguousPackets = 0
}

func (p *Packer) result(outcome PackOutcome) *PackResult {
	return &PackResult{
		ledger:              p.ledger,
		outcome:             outcome,
		exporterLosses:      p.exporterLosses,
		canonicalSourceLoss: p.canonicalSourceLoss,
		packets:             p.packets,
		confirmedPackets:    p.confirmedPackets,
		ambiguousPackets:    p.ambiguousPackets,
	}
}

// consume is the NormalizeEachIndexed callback. It deliberately returns nil
// for every record-local outcome so later ordinals receive validation too.
func (p *Packer) consume(ctx context.Context, lookup IndexedLookup, ordinal uint64, normalized wire.NormalizedRecord, normalizeErr error) error {
	if normalizeErr != nil {
		if err := p.ledger.addSourceReason(ordinal, false, classifyNormalizeError(normalizeErr)); err != nil {
			p.internal = true
			p.stopped = true
		}
		return nil
	}

	mappingLookup := mapping.Lookup(nil)
	if lookup != nil {
		mappingLookup = func(source string) (wire.Value, bool) {
			return lookup(ordinal, source)
		}
	}
	mapped, err := p.state.Mapping().MapWithStats(normalized, mappingLookup)
	if err != nil {
		if addErr := p.ledger.addSourceReason(ordinal, false, classifyMappingError(err)); addErr != nil {
			p.internal = true
			p.stopped = true
		}
		return nil
	}
	if err := p.ledger.addSource(ordinal, true); err != nil {
		p.internal = true
		p.stopped = true
		return nil
	}
	p.exporterLosses += uint64(mapped.ExporterLosses)
	p.canonicalSourceLoss += uint64(mapped.CanonicalSourceLoss)

	shapeIndex, ok := p.shapeIndex(mapped.Record)
	if !ok {
		p.invalidate(ordinal, RejectionFamilyMismatch)
		return nil
	}
	sampling, ok := p.sampling(normalized)
	if !ok {
		p.invalidate(ordinal, RejectionInvalidValue)
		return nil
	}

	if p.stopUnavailable(ctx) || p.stopped {
		p.previewUnsent(ordinal, mapped.Record, shapeIndex, sampling)
		return nil
	}

	config := p.state.Config()
	if p.packetOpen && (shapeIndex != p.packetShape || (config.Protocol == wire.ProtocolV5 && sampling != p.packetSample) || p.packet.DataRecords() >= uint64(config.MaxRecordsPerMessage)) {
		if !p.flushData(ctx) || p.stopped {
			p.previewUnsent(ordinal, mapped.Record, shapeIndex, sampling)
			return nil
		}
	}

	if !p.packetOpen {
		if fits, reason := p.minimumDataPacketFits(mapped.Record, shapeIndex); !fits {
			p.invalidate(ordinal, reason)
			return nil
		}
		if !p.openData(ctx, shapeIndex, sampling) {
			p.previewUnsent(ordinal, mapped.Record, shapeIndex, sampling)
			return nil
		}
	}

	if err := p.append(ordinal, mapped.Record, sampling); err != nil {
		if isAppendBoundary(err) && p.packet.DataRecords() != 0 {
			if !p.flushData(ctx) || p.stopped {
				p.previewUnsent(ordinal, mapped.Record, shapeIndex, sampling)
				return nil
			}
			if fits, reason := p.minimumDataPacketFits(mapped.Record, shapeIndex); !fits {
				p.invalidate(ordinal, reason)
				return nil
			}
			if !p.openData(ctx, shapeIndex, sampling) {
				p.previewUnsent(ordinal, mapped.Record, shapeIndex, sampling)
				return nil
			}
			if err = p.append(ordinal, mapped.Record, sampling); err == nil {
				return nil
			}
		}
		// The appender rejects atomically. A rejected empty packet is aborted so
		// its reservation cannot block the next valid sibling.
		if p.packetOpen && p.packet.DataRecords() == 0 {
			_ = p.packet.Abort()
			p.packetOpen = false
		}
		if isRecordRejection(err) {
			p.invalidate(ordinal, classifyWireError(err))
			return nil
		}
		p.abortDataInternal()
	}
	return nil
}

func (p *Packer) shapeIndex(record wire.WireRecord) (int, bool) {
	catalog := p.state.Catalog()
	if catalog.ShapeCount() == 1 {
		shape, ok := catalog.ShapeAt(0)
		return 0, ok && shape.Family() == record.Family()
	}
	for index := 0; index < catalog.ShapeCount(); index++ {
		shape, ok := catalog.ShapeAt(index)
		if ok && shape.Family() == record.Family() {
			return index, true
		}
	}
	return 0, false
}

func (p *Packer) sampling(record wire.NormalizedRecord) (uint32, bool) {
	if p.state.Config().Protocol != wire.ProtocolV5 {
		return 0, true
	}
	value, ok := record.Lookup(wire.FieldFlowSamplingRate)
	if !ok || value.Kind() != wire.ValueUint || value.Uint() > 16383 {
		return 0, false
	}
	return uint32(value.Uint()), true
}

func (p *Packer) openData(ctx context.Context, shapeIndex int, sampling uint32) bool {
	if p.stopUnavailable(ctx) || p.stopped {
		return false
	}
	drainedRefresh := false
	for attempt := 0; attempt < 2; attempt++ {
		wall, mono := p.clock()
		if p.state.RefreshDue(mono) {
			if drainedRefresh {
				p.transient = true
				p.stopped = true
				return false
			}
			drainedRefresh = true
			if !p.drainRefresh(ctx, wall, mono) || p.stopped {
				return false
			}
			continue
		}
		packet, err := p.state.BeginDataStream(wall, mono, shapeIndex, p.datagram, sampling)
		if errors.Is(err, ErrRefreshRequired) {
			if drainedRefresh {
				p.transient = true
				p.stopped = true
				return false
			}
			drainedRefresh = true
			if !p.drainRefresh(ctx, wall, mono) || p.stopped {
				return false
			}
			continue
		}
		if err != nil {
			p.internal = true
			p.stopped = true
			return false
		}
		p.packet = packet
		p.packetOpen = true
		p.packetShape = shapeIndex
		p.packetSample = sampling
		return true
	}
	p.internal = true
	p.stopped = true
	return false
}

func (p *Packer) append(ordinal uint64, record wire.WireRecord, sampling uint32) error {
	if err := p.packet.Append(record, sampling); err != nil {
		return err
	}
	if !p.ledgerOpen {
		if err := p.ledger.beginPacket(); err != nil {
			_ = p.packet.Abort()
			p.packetOpen = false
			p.internal = true
			p.stopped = true
			return ErrPackInternal
		}
		p.ledgerOpen = true
	}
	if err := p.ledger.addPending(ordinal); err != nil {
		_ = p.ledger.abortPacket()
		p.ledgerOpen = false
		_ = p.packet.Abort()
		p.packetOpen = false
		p.internal = true
		p.stopped = true
		return ErrPackInternal
	}
	return nil
}

func (p *Packer) abortDataInternal() {
	if p.packetOpen {
		_ = p.packet.Abort()
		p.packetOpen = false
	}
	if p.ledgerOpen {
		_ = p.ledger.abortPacket()
		p.ledgerOpen = false
	}
	p.internal = true
	p.stopped = true
}

// stopUnavailable aborts canceled or unavailable work without a transport attempt.
// Continue bounded suffix validation so only valid unsent sources are returned.
// Context is passed down the synchronous call stack, never retained on Packer.
func (p *Packer) stopUnavailable(ctx context.Context) bool {
	if ctx.Err() == nil && (p.config.Available == nil || p.config.Available()) {
		return false
	}
	if p.packetOpen {
		if err := p.packet.Abort(); err != nil {
			p.internal = true
		}
		p.packetOpen = false
	}
	if p.ledgerOpen {
		if err := p.ledger.abortPacket(); err != nil {
			p.internal = true
		}
		p.ledgerOpen = false
	}
	p.transient, p.stopped = true, true
	return true
}

func (p *Packer) flushData(ctx context.Context) bool {
	if p.stopUnavailable(ctx) {
		return false
	}
	if !p.packetOpen {
		return !p.stopped
	}
	if !p.ledgerOpen || p.packet.DataRecords() == 0 {
		_ = p.packet.Abort()
		p.packetOpen = false
		p.ledgerOpen = false
		p.internal = true
		p.stopped = true
		return false
	}
	n, err := p.packet.Finish()
	if err != nil {
		_ = p.ledger.abortPacket()
		p.ledgerOpen = false
		p.packetOpen = false
		p.internal = true
		p.stopped = true
		return false
	}
	p.packets++
	writeN, writeErr := p.write(ctx, p.datagram[:n])
	commit, commitErr := p.state.Commit(p.packet, writeN, writeErr)
	var resolution SourceLedgerResolution
	var ledgerErr error
	if commitErr == nil {
		resolution, ledgerErr = p.ledger.resolvePacket(writeN, n, writeErr)
	} else if p.ledger.Packet().Active {
		// State did not accept the transaction, so its pending source prefix
		// must remain unsent. Resolve only after State.Commit succeeds; this
		// keeps state and ledger transitions coupled on every exit.
		ledgerErr = p.ledger.abortPacket()
	}
	p.packetOpen = false
	p.ledgerOpen = false
	if commitErr != nil || ledgerErr != nil || commit.Class == WriteInvalid || resolution.Class == WriteInvalid {
		if p.ledger.Packet().Active {
			_ = p.ledger.abortPacket()
		}
		p.internal = true
		p.stopped = true
		return false
	}
	p.config.Observe.handoff(ctx, DataConfirmed, DataAmbiguous, commit)
	if commit.Class != WriteFull || resolution.Class != WriteFull {
		p.ambiguousPackets++
		p.transient = true
		p.stopped = true
		return false
	}
	p.confirmedPackets++
	return true
}

// refresh services at most one due catalog round without pdata or a source
// ledger, using the same buffer, availability gates and commits as Pack.
func (p *Packer) refresh(ctx context.Context) error {
	if ctx == nil {
		return ErrPackInternal
	}
	if !atomic.CompareAndSwapUint32(&p.busy, 0, 1) {
		return ErrPackerBusy
	}
	defer atomic.StoreUint32(&p.busy, 0)
	p.resetRequest()
	if !p.stopUnavailable(ctx) {
		wall, mono := p.clock()
		if p.state.RefreshDue(mono) {
			p.drainRefresh(ctx, wall, mono)
		}
	} else {
		p.config.Observe.emit(ctx, RefreshFailed, 0)
	}
	if p.internal {
		return ErrPackInternal
	}
	if p.transient {
		return ErrPackTransient
	}
	return nil
}

func (p *Packer) drainRefresh(ctx context.Context, firstWall, firstMono uint64) (completed bool) {
	defer func() {
		if !completed {
			p.config.Observe.emit(ctx, RefreshFailed, 0)
		}
	}()
	wall, mono := firstWall, firstMono
	first := true
	for {
		if p.stopUnavailable(ctx) || p.stopped {
			return false
		}
		progress := p.state.Progress()
		if !progress.RefreshActive && !progress.RefreshDue {
			return true
		}
		if !first {
			wall, mono = p.clock()
		}
		first = false
		if progress.NextShape < 0 || progress.NextShape >= p.state.Catalog().ShapeCount() {
			p.internal = true
			p.stopped = true
			return false
		}
		template, err := p.state.BeginTemplate(wall, mono, progress.NextShape)
		if err != nil {
			p.internal = true
			p.stopped = true
			return false
		}
		n, err := template.Encode(p.datagram)
		if err != nil {
			p.internal = true
			p.stopped = true
			return false
		}
		if p.stopUnavailable(ctx) {
			_ = template.Abort()
			return false
		}
		writeN, writeErr := p.write(ctx, p.datagram[:n])
		commit, commitErr := p.state.Commit(template, writeN, writeErr)
		if commitErr != nil || commit.Class == WriteInvalid {
			p.internal = true
			p.stopped = true
			return false
		}
		p.config.Observe.handoff(ctx, RefreshConfirmed, RefreshAmbiguous, commit)
		if commit.Class != WriteFull {
			p.transient = true
			p.stopped = true
			return false
		}
		progress = p.state.Progress()
		if !progress.RefreshActive && !progress.RefreshDue {
			return true
		}
	}
}

func (p *Packer) previewUnsent(ordinal uint64, record wire.WireRecord, shapeIndex int, sampling uint32) {
	if p.internal {
		return
	}
	wall := p.previewInstantAt()
	header, ok := p.previewHeader(wall, sampling)
	if !ok || p.validation == nil {
		p.internal = true
		p.stopped = true
		return
	}
	shape, ok := p.state.Catalog().ShapeAt(shapeIndex)
	if !ok {
		p.internal = true
		p.stopped = true
		return
	}
	config := p.state.Config()
	request := wire.DataPacketRequest{
		Header:           header,
		Shape:            shape,
		MaxDatagramBytes: config.MaxDatagramSize,
		MaxRecords:       uint64(config.MaxRecordsPerMessage),
	}
	p.validation.Reset()
	if err := p.validation.Begin(p.datagram, request); err != nil {
		p.validation.Reset()
		p.internal = true
		p.stopped = true
		return
	}
	if err := p.validation.Append(record); err != nil {
		p.validation.Reset()
		if isRecordRejection(err) {
			p.invalidate(ordinal, classifyWireError(err))
			return
		}
		p.internal = true
		p.stopped = true
		return
	}
	if _, err := p.validation.Finish(); err != nil {
		p.validation.Reset()
		p.internal = true
		p.stopped = true
		return
	}
	p.validation.Reset()
}

func (p *Packer) minimumDataPacketFits(record wire.WireRecord, shapeIndex int) (bool, RejectionReason) {
	shape, ok := p.state.Catalog().ShapeAt(shapeIndex)
	if !ok {
		return false, RejectionRecordInvalid
	}
	recordBytes, err := shape.RecordSize(record)
	if err != nil {
		// A direct bounds result from a validated shape is produced only by a
		// descriptor/value byte limit or checked record-length arithmetic. The
		// other trusted record errors describe shape/value validity, not size.
		if sameTrustedError(err, wire.ErrRecordValueLimit) || sameTrustedError(err, wire.ErrBounds) {
			return false, RejectionRecordTooLarge
		}
		return false, RejectionRecordInvalid
	}
	dataSet, err := shape.DataSetSizeForEncoded(recordBytes, 1)
	if err != nil {
		if sameTrustedError(err, wire.ErrBounds) {
			return false, RejectionRecordTooLarge
		}
		return false, RejectionRecordInvalid
	}
	config := p.state.Config()
	total, ok := checkedPacketLength(config.Protocol, 0, 0, dataSet.Length())
	if !ok {
		// An injected or corrupted protocol value makes the arithmetic helper
		// unable to establish a byte-capacity cause.
		return false, RejectionOther
	}
	if total > config.MaxDatagramSize || total > uint64(len(p.datagram)) {
		return false, RejectionRecordTooLarge
	}
	return true, RejectionOther
}

func (p *Packer) previewInstantAt() uint64 {
	if p.havePreviewInstant {
		return p.previewInstant
	}
	// Suffix validation reads the clock in addition to packet reservations.
	// Cache one preview instant per request so several unsent suffix records
	// share a stable pure-appender header while still observing the current
	// wall clock after a failed reservation.
	wall, _ := p.clock()
	p.state.mu.Lock()
	if p.state.haveReservedWall && wall < p.state.lastReservedWall {
		wall = p.state.lastReservedWall
	}
	p.state.mu.Unlock()
	p.previewInstant = wall
	p.havePreviewInstant = true
	return wall
}

func (p *Packer) previewHeader(wall uint64, sampling uint32) (wire.HeaderMetadata, bool) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.haveReservedWall && wall < p.state.lastReservedWall {
		wall = p.state.lastReservedWall
	}
	header, err := p.state.headerLocked(wall, uint16(sampling))
	return header, err == nil
}

func (p *Packer) invalidate(ordinal uint64, reason RejectionReason) {
	if err := p.ledger.invalidate(ordinal, reason); err != nil {
		p.internal = true
		p.stopped = true
	}
}

func (p *Packer) clock() (wall, mono uint64) {
	return p.config.Clock()
}

func (p *Packer) write(ctx context.Context, datagram []byte) (n int, err error) {
	n, err = p.config.Write(ctx, datagram)
	return n, err
}

func isAppendBoundary(err error) bool {
	return errors.Is(err, wire.ErrBounds) || errors.Is(err, wire.ErrShortBuffer)
}

func isRecordRejection(err error) bool {
	return errors.Is(err, wire.ErrInvalidValue) ||
		errors.Is(err, wire.ErrRecordValueLimit) ||
		errors.Is(err, wire.ErrInvalidFamily) ||
		errors.Is(err, wire.ErrBounds) ||
		errors.Is(err, wire.ErrShortBuffer)
}
