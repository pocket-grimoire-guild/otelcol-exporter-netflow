package destination

import (
	"errors"
	"math"
)

const maxPendingValid uint64 = 1024

var (
	ErrLedgerOrdinal  = errors.New("destination: invalid source ordinal")
	ErrLedgerPacket   = errors.New("destination: invalid ledger packet transition")
	ErrLedgerStopped  = errors.New("destination: ledger packet attempts stopped")
	ErrLedgerCapacity = errors.New("destination: ledger packet capacity exceeded")
)

// SourceClass is the externally visible state of one source ordinal. An
// ordinal at or beyond the covered source prefix is SourceUncovered; the
// ledger stores SourceUnsentValid as the zero two-bit value.
type SourceClass uint8

const (
	SourceUncovered SourceClass = iota
	SourceUnsentValid
	SourceConfirmed
	SourceInvalid
	SourceAmbiguous
)

// SourceLedgerCounts is a copy of the scalar ledger counters. Pending valid
// records are included in Unsent and also reported separately in Pending.
type SourceLedgerCounts struct {
	Covered    uint64
	Valid      uint64
	Invalid    uint64
	Unsent     uint64
	Confirmed  uint64
	Ambiguous  uint64
	Pending    uint64
	PacketOpen bool
	Stopped    bool
}

// SourceLedgerPacket is a read-only copy of the active packet boundary. End
// is exclusive. A packet with no pending valid records has Valid equal to zero
// and both ordinal bounds equal to zero.
type SourceLedgerPacket struct {
	Active bool
	Start  uint64
	End    uint64
	Valid  uint64
	Floor  uint64
}

// SourceLedgerResolution reports how the active packet changed the ledger.
// The destination write class is copied from ClassifyWrite's partition; raw
// transport errors are deliberately absent.
type SourceLedgerResolution struct {
	Class     WriteClass
	Confirmed uint64
	Ambiguous uint64
}

const (
	ledgerBitsUnsent    uint8 = 0
	ledgerBitsConfirmed uint8 = 1
	ledgerBitsInvalid   uint8 = 2
	ledgerBitsAmbiguous uint8 = 3
)

// sourceLedger is a dynamically grown compact request ledger. Two bits
// represent each covered ordinal, and the covered prefix distinguishes an
// uncovered ordinal from an unsent valid ordinal. The classification store is
// grown as records arrive, so a request is not rejected at an arbitrary source
// count while packet-local pending state remains bounded.
type sourceLedger struct {
	classes         []byte
	rejectionCounts RejectionCounts

	covered   uint64
	valid     uint64
	invalid   uint64
	confirmed uint64
	ambiguous uint64

	packetOpen  bool
	packetStart uint64
	packetEnd   uint64
	packetValid uint64
	packetFloor uint64
	stopped     bool
}

func newSourceLedger() sourceLedger { return sourceLedger{} }

// Classification returns the final or currently unsent classification of an
// ordinal. Pending valid records remain SourceUnsentValid until resolution.
func (l *sourceLedger) Classification(ordinal uint64) SourceClass {
	if l == nil || ordinal >= l.covered {
		return SourceUncovered
	}
	return l.storedClass(ordinal)
}

// Counts returns scalar counts and packet lifecycle state without exposing the
// classification storage.
func (l *sourceLedger) Counts() SourceLedgerCounts {
	if l == nil {
		return SourceLedgerCounts{}
	}
	return SourceLedgerCounts{
		Covered:    l.covered,
		Valid:      l.valid,
		Invalid:    l.invalid,
		Unsent:     l.valid - l.confirmed - l.ambiguous,
		Confirmed:  l.confirmed,
		Ambiguous:  l.ambiguous,
		Pending:    l.packetValid,
		PacketOpen: l.packetOpen,
		Stopped:    l.stopped,
	}
}

// RejectionCounts returns a value copy of the fixed reason histogram.
func (l *sourceLedger) RejectionCounts() RejectionCounts {
	if l == nil {
		return RejectionCounts{}
	}
	return l.rejectionCounts
}

// Packet returns the active packet's source boundary as a value copy.
func (l *sourceLedger) Packet() SourceLedgerPacket {
	if l == nil {
		return SourceLedgerPacket{}
	}
	return SourceLedgerPacket{
		Active: l.packetOpen,
		Start:  l.packetStart,
		End:    l.packetEnd,
		Valid:  l.packetValid,
		Floor:  l.packetFloor,
	}
}

// addSource appends exactly one source ordinal. The ordinal must extend the
// covered prefix, so gaps and duplicates are rejected before any counter or
// classification mutation.
func (l *sourceLedger) addSource(ordinal uint64, valid bool) error {
	return l.addSourceReason(ordinal, valid, RejectionOther)
}

// addSourceReason appends exactly one source ordinal. Invalid additions use
// the supplied closed cause only after all ordinal/capacity checks succeed.
func (l *sourceLedger) addSourceReason(ordinal uint64, valid bool, reason RejectionReason) error {
	if l == nil || ordinal != l.covered || ordinal == math.MaxUint64 {
		return ErrLedgerOrdinal
	}
	if err := l.ensureOrdinal(ordinal); err != nil {
		return err
	}
	if valid {
		l.valid++
	} else {
		l.invalid++
		l.setStoredClass(ordinal, SourceInvalid)
		l.rejectionCounts[reasonIndex(reason)]++
	}
	l.covered++
	return nil
}

// invalidate performs the only valid-to-invalid transition. It validates the
// exact prior class before changing either scalar counters or the histogram.
func (l *sourceLedger) invalidate(ordinal uint64, reason RejectionReason) error {
	if l == nil || ordinal >= l.covered || l.storedClass(ordinal) != SourceUnsentValid {
		return ErrLedgerOrdinal
	}
	// Pending valid ordinals share the unsent class with the rest of the
	// covered valid prefix. The active interval contains only pending valid
	// ordinals and already-invalid gaps, so reject the former before touching
	// scalar counts, classes, or the reason histogram.
	if l.packetOpen && ordinal >= l.packetStart && ordinal < l.packetEnd {
		return ErrLedgerOrdinal
	}
	l.valid--
	l.invalid++
	l.setStoredClass(ordinal, SourceInvalid)
	l.rejectionCounts[reasonIndex(reason)]++
	return nil
}

func reasonIndex(reason RejectionReason) int {
	if int(reason) < 0 || int(reason) >= RejectionReasonCount {
		return int(RejectionOther)
	}
	return int(reason)
}

func (l *sourceLedger) ensureOrdinal(ordinal uint64) error {
	need := ordinal/4 + 1
	if need > uint64(int(^uint(0)>>1)) {
		return ErrLedgerCapacity
	}
	if need <= uint64(len(l.classes)) {
		return nil
	}
	newLen := int(need)
	if newLen < len(l.classes)*2 {
		newLen = len(l.classes) * 2
		if newLen == 0 {
			newLen = 1
		}
	}
	if uint64(newLen) < need {
		newLen = int(need)
	}
	grown := make([]byte, newLen)
	copy(grown, l.classes)
	l.classes = grown
	return nil
}

// beginPacket starts one packet admission boundary. It is intentionally
// separate from addPending so a caller can reserve the destination packet
// before mapping the first selected source record.
func (l *sourceLedger) beginPacket() error {
	if l == nil {
		return ErrLedgerPacket
	}
	if l.stopped {
		return ErrLedgerStopped
	}
	if l.packetOpen {
		return ErrLedgerPacket
	}
	l.packetOpen = true
	l.packetStart, l.packetEnd, l.packetValid = 0, 0, 0
	return nil
}

// addPending assigns one already-covered unsent valid source ordinal to the
// active packet. Pending valid ordinals must be monotonic from packetFloor.
// Any source gap between adjacent pending records must contain only invalid
// ordinals; this makes packet resolution exact without a per-record pending
// bit.
func (l *sourceLedger) addPending(ordinal uint64) error {
	if l == nil {
		return ErrLedgerPacket
	}
	if l.stopped {
		return ErrLedgerStopped
	}
	if !l.packetOpen {
		return ErrLedgerPacket
	}
	if ordinal >= l.covered || l.storedClass(ordinal) != SourceUnsentValid {
		return ErrLedgerOrdinal
	}
	if l.packetValid >= maxPendingValid || ordinal == math.MaxUint64 {
		return ErrLedgerCapacity
	}
	if l.packetValid == 0 {
		if !l.invalidGap(l.packetFloor, ordinal) {
			return ErrLedgerOrdinal
		}
		l.packetStart, l.packetEnd, l.packetValid = ordinal, ordinal+1, 1
		return nil
	}
	if ordinal < l.packetEnd {
		return ErrLedgerOrdinal
	}
	if !l.invalidGap(l.packetEnd, ordinal) {
		return ErrLedgerOrdinal
	}
	l.packetEnd = ordinal + 1
	l.packetValid++
	return nil
}

// resolvePacket applies the destination's complete local write partition.
// Only WriteFull (the exact length with nil error) confirms. Every other legal
// class marks the packet's pending valid ordinals ambiguous. WriteInvalid is a
// local contract violation and leaves this ledger byte-for-byte unchanged.
func (l *sourceLedger) resolvePacket(n, length int, writeErr error) (SourceLedgerResolution, error) {
	class := ClassifyWrite(n, length, writeErr)
	resolution := SourceLedgerResolution{Class: class}
	if class == WriteInvalid {
		return resolution, ErrInvalidWrite
	}
	if l == nil || !l.packetOpen || l.packetValid == 0 {
		return SourceLedgerResolution{}, ErrLedgerPacket
	}

	if class == WriteFull {
		l.markPending(SourceConfirmed)
		l.confirmed += l.packetValid
		l.packetFloor = l.packetEnd
		resolution.Confirmed = l.packetValid
	} else {
		l.markPending(SourceAmbiguous)
		l.ambiguous += l.packetValid
		l.stopped = true
		resolution.Ambiguous = l.packetValid
	}
	l.packetOpen = false
	l.packetStart, l.packetEnd, l.packetValid = 0, 0, 0
	return resolution, nil
}

// abortPacket leaves all pending valid records in their zero (unsent) class
// and permanently stops packet attempts for this request.
func (l *sourceLedger) abortPacket() error {
	if l == nil || !l.packetOpen {
		return ErrLedgerPacket
	}
	l.packetOpen = false
	l.packetStart, l.packetEnd, l.packetValid = 0, 0, 0
	l.stopped = true
	return nil
}

func (l *sourceLedger) markPending(class SourceClass) {
	for ordinal := l.packetStart; ordinal < l.packetEnd; ordinal++ {
		if l.storedClass(ordinal) == SourceUnsentValid {
			l.setStoredClass(ordinal, class)
		}
	}
}

func (l *sourceLedger) invalidGap(start, end uint64) bool {
	for ordinal := start; ordinal < end; ordinal++ {
		if l.storedClass(ordinal) != SourceInvalid {
			return false
		}
	}
	return true
}

func (l *sourceLedger) storedClass(ordinal uint64) SourceClass {
	slot := ordinal / 4
	if slot >= uint64(len(l.classes)) {
		return SourceUncovered
	}
	shift := (ordinal & 3) << 1
	bits := (l.classes[slot] >> shift) & 3
	switch bits {
	case ledgerBitsConfirmed:
		return SourceConfirmed
	case ledgerBitsInvalid:
		return SourceInvalid
	case ledgerBitsAmbiguous:
		return SourceAmbiguous
	default:
		return SourceUnsentValid
	}
}

func (l *sourceLedger) setStoredClass(ordinal uint64, class SourceClass) {
	slot := ordinal / 4
	shift := (ordinal & 3) << 1
	mask := byte(3 << shift)
	var bits uint8
	switch class {
	case SourceConfirmed:
		bits = ledgerBitsConfirmed
	case SourceInvalid:
		bits = ledgerBitsInvalid
	case SourceAmbiguous:
		bits = ledgerBitsAmbiguous
	default:
		bits = ledgerBitsUnsent
	}
	l.classes[slot] = (l.classes[slot] &^ mask) | byte(bits<<shift)
}
