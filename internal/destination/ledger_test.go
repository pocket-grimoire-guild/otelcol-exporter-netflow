package destination

import (
	"errors"
	"reflect"
	"testing"
)

func ledgerSnapshot(ledger *sourceLedger) sourceLedger {
	snapshot := *ledger
	snapshot.classes = append([]byte(nil), ledger.classes...)
	return snapshot
}

func assertLedgerUnchanged(t *testing.T, before sourceLedger, ledger *sourceLedger) {
	t.Helper()
	if !reflect.DeepEqual(before, *ledger) {
		t.Fatalf("rejected operation mutated ledger: before=%+v after=%+v", before, *ledger)
	}
}

func TestSourceLedgerInterleavedInvalidAndConfirmedPrefix(t *testing.T) {
	ledger := newSourceLedger()
	for ordinal, valid := range []bool{true, false, true, false, true, true} {
		if err := ledger.addSource(uint64(ordinal), valid); err != nil {
			t.Fatalf("addSource(%d): %v", ordinal, err)
		}
	}
	if got := ledger.Classification(6); got != SourceUncovered {
		t.Fatalf("uncovered classification = %v, want %v", got, SourceUncovered)
	}
	if got := ledger.Classification(1); got != SourceInvalid {
		t.Fatalf("invalid classification = %v, want %v", got, SourceInvalid)
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	for _, ordinal := range []uint64{0, 2, 4} {
		if err := ledger.addPending(ordinal); err != nil {
			t.Fatalf("addPending(%d): %v", ordinal, err)
		}
	}
	if got := ledger.Packet(); got != (SourceLedgerPacket{Active: true, Start: 0, End: 5, Valid: 3}) {
		t.Fatalf("packet = %+v", got)
	}
	resolution, err := ledger.resolvePacket(17, 17, nil)
	if err != nil || resolution != (SourceLedgerResolution{Class: WriteFull, Confirmed: 3}) {
		t.Fatalf("resolve = (%+v, %v)", resolution, err)
	}
	for ordinal, want := range []SourceClass{SourceConfirmed, SourceInvalid, SourceConfirmed, SourceInvalid, SourceConfirmed, SourceUnsentValid} {
		if got := ledger.Classification(uint64(ordinal)); got != want {
			t.Errorf("classification[%d] = %v, want %v", ordinal, got, want)
		}
	}
	if got := ledger.Counts(); got != (SourceLedgerCounts{Covered: 6, Valid: 4, Invalid: 2, Unsent: 1, Confirmed: 3}) {
		t.Fatalf("counts = %+v", got)
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(5); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.resolvePacket(19, 19, nil); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Counts(); got.Confirmed != 4 || got.Unsent != 0 || got.Ambiguous != 0 {
		t.Fatalf("final counts = %+v", got)
	}
}

func TestSourceLedgerRejectsGapsDuplicatesAndPendingHoles(t *testing.T) {
	ledger := newSourceLedger()
	if err := ledger.addSource(0, true); err != nil {
		t.Fatal(err)
	}
	for _, ordinal := range []uint64{2, 0} {
		before := ledgerSnapshot(&ledger)
		if err := ledger.addSource(ordinal, true); !errors.Is(err, ErrLedgerOrdinal) {
			t.Fatalf("addSource(%d) = %v, want ordinal error", ordinal, err)
		}
		assertLedgerUnchanged(t, before, &ledger)
	}
	if err := ledger.addSource(1, false); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addSource(2, true); err != nil {
		t.Fatal(err)
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	before := ledgerSnapshot(&ledger)
	if err := ledger.addPending(2); !errors.Is(err, ErrLedgerOrdinal) {
		t.Fatalf("initial skipped valid = %v", err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if err := ledger.addPending(0); err != nil {
		t.Fatal(err)
	}
	before = ledgerSnapshot(&ledger)
	if err := ledger.addPending(0); !errors.Is(err, ErrLedgerOrdinal) {
		t.Fatalf("duplicate pending = %v", err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if err := ledger.addPending(2); err != nil {
		t.Fatal(err)
	}
	before = ledgerSnapshot(&ledger)
	resolution, err := ledger.resolvePacket(1, 0, nil)
	if resolution.Class != WriteInvalid || !errors.Is(err, ErrInvalidWrite) {
		t.Fatalf("invalid packet resolution = (%+v,%v)", resolution, err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if _, err := ledger.resolvePacket(1, 1, nil); err != nil {
		t.Fatal(err)
	}
	if ledger.Classification(0) != SourceConfirmed || ledger.Classification(1) != SourceInvalid || ledger.Classification(2) != SourceConfirmed {
		t.Fatalf("hole resolution classifications = %v,%v,%v", ledger.Classification(0), ledger.Classification(1), ledger.Classification(2))
	}
}

func TestSourceLedgerAmbiguousSuffixAndStoppedPackets(t *testing.T) {
	ledger := newSourceLedger()
	for ordinal, valid := range []bool{true, false, true, true} {
		if err := ledger.addSource(uint64(ordinal), valid); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(0); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(2); err != nil {
		t.Fatal(err)
	}
	resolution, err := ledger.resolvePacket(4, 5, nil)
	if err != nil || resolution != (SourceLedgerResolution{Class: WriteShortNil, Ambiguous: 2}) {
		t.Fatalf("ambiguous resolution = (%+v,%v)", resolution, err)
	}
	if ledger.Classification(0) != SourceAmbiguous || ledger.Classification(1) != SourceInvalid || ledger.Classification(2) != SourceAmbiguous || ledger.Classification(3) != SourceUnsentValid {
		t.Fatalf("ambiguous classifications = %v,%v,%v,%v", ledger.Classification(0), ledger.Classification(1), ledger.Classification(2), ledger.Classification(3))
	}
	if err := ledger.addSource(4, false); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addSource(5, true); err != nil {
		t.Fatal(err)
	}
	if err := ledger.beginPacket(); !errors.Is(err, ErrLedgerStopped) {
		t.Fatalf("begin after ambiguity = %v", err)
	}
	if got := ledger.Counts(); got.Valid != 4 || got.Invalid != 2 || got.Ambiguous != 2 || got.Unsent != 2 || !got.Stopped {
		t.Fatalf("suffix counts = %+v", got)
	}
}

func TestSourceLedgerInvalidResultAndAbortAreNonConfirming(t *testing.T) {
	ledger := newSourceLedger()
	for ordinal, valid := range []bool{true, false, true} {
		if err := ledger.addSource(uint64(ordinal), valid); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(0); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(2); err != nil {
		t.Fatal(err)
	}
	before := ledgerSnapshot(&ledger)
	resolution, err := ledger.resolvePacket(9, 8, nil)
	if resolution.Class != WriteInvalid || !errors.Is(err, ErrInvalidWrite) {
		t.Fatalf("invalid resolution = (%+v,%v)", resolution, err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if got := ledger.Counts(); !got.PacketOpen || got.Confirmed != 0 || got.Ambiguous != 0 || got.Pending != 2 {
		t.Fatalf("invalid result changed ledger = %+v", got)
	}
	if err := ledger.abortPacket(); err != nil {
		t.Fatal(err)
	}
	if ledger.Classification(0) != SourceUnsentValid || ledger.Classification(2) != SourceUnsentValid {
		t.Fatalf("aborted classifications = %v,%v", ledger.Classification(0), ledger.Classification(2))
	}
	if err := ledger.beginPacket(); !errors.Is(err, ErrLedgerStopped) {
		t.Fatalf("begin after abort = %v", err)
	}
}

func TestSourceLedgerPacketFloorPreservesUnsentValidSuffix(t *testing.T) {
	ledger := newSourceLedger()
	for ordinal, valid := range []bool{true, false, true, false, true, true} {
		if err := ledger.addSource(uint64(ordinal), valid); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(0); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(2); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.resolvePacket(4, 4, nil); err != nil {
		t.Fatal(err)
	}
	if ledger.Packet().Floor != 3 {
		t.Fatalf("packet floor = %d, want 3", ledger.Packet().Floor)
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	before := ledgerSnapshot(&ledger)
	if err := ledger.addPending(5); !errors.Is(err, ErrLedgerOrdinal) {
		t.Fatalf("skipped unsent valid = %v, want ordinal error", err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if err := ledger.addPending(4); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addPending(5); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.resolvePacket(8, 8, nil); err != nil {
		t.Fatal(err)
	}
	if ledger.Classification(4) != SourceConfirmed || ledger.Classification(5) != SourceConfirmed {
		t.Fatalf("suffix classifications = %v/%v", ledger.Classification(4), ledger.Classification(5))
	}
}

func TestSourceLedgerPendingLimitAndWideOrdinalStorage(t *testing.T) {
	ledger := newSourceLedger()
	const sourceCount = maxPendingValid + 1
	for ordinal := uint64(0); ordinal < sourceCount; ordinal++ {
		if err := ledger.addSource(ordinal, true); err != nil {
			t.Fatalf("addSource(%d): %v", ordinal, err)
		}
	}
	if err := ledger.beginPacket(); err != nil {
		t.Fatal(err)
	}
	for ordinal := uint64(0); ordinal < maxPendingValid; ordinal++ {
		if err := ledger.addPending(ordinal); err != nil {
			t.Fatalf("addPending(%d): %v", ordinal, err)
		}
	}
	if err := ledger.addPending(maxPendingValid); !errors.Is(err, ErrLedgerCapacity) {
		t.Fatalf("pending ceiling = %v", err)
	}
	if _, err := ledger.resolvePacket(1, 1, nil); err != nil {
		t.Fatal(err)
	}
	if ledger.Classification(maxPendingValid) != SourceUnsentValid {
		t.Fatalf("over-cap source = %v, want unsent", ledger.Classification(maxPendingValid))
	}

	wide := newSourceLedger()
	const boundary = uint64(65_536)
	for ordinal := uint64(0); ordinal <= boundary; ordinal++ {
		if err := wide.addSource(ordinal, ordinal%17 != 0); err != nil {
			t.Fatalf("wide addSource(%d): %v", ordinal, err)
		}
	}
	if wide.Classification(boundary) != SourceUnsentValid || wide.Counts().Covered != boundary+1 {
		t.Fatalf("wide boundary class/count = %v/%d", wide.Classification(boundary), wide.Counts().Covered)
	}
	if wide.Classification(boundary+1) != SourceUncovered {
		t.Fatal("wide uncovered ordinal reported as covered")
	}
}
