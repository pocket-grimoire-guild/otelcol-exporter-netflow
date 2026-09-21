package destination

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func rejectionReasonTotal(counts RejectionCounts) uint64 {
	var total uint64
	for _, count := range counts {
		total += count
	}
	return total
}

func TestPackerRejectionReasonsReconcileCounts(t *testing.T) {
	state := packerState(t)
	logs := appendPackerCopies(t, validPackerLogs(t), 4)
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	records.At(1).Body().SetStr("unsupported body")
	records.At(2).Attributes().PutStr("source.port", "wrong type")
	records.At(3).Attributes().Remove("source.address")
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	counts := result.Counts()
	reasons := result.RejectionCounts()
	if rejectionReasonTotal(reasons) != counts.Invalid {
		t.Fatalf("reason total = %d, invalid = %d, reasons = %v", rejectionReasonTotal(reasons), counts.Invalid, reasons)
	}
	want := RejectionCounts{}
	want[RejectionUnsupportedBody] = 1
	want[RejectionInvalidType] = 1
	want[RejectionMissingField] = 1
	if reasons != want {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
	if counts.Confirmed != 1 || result.Classification(0) != SourceConfirmed {
		t.Fatalf("counts/classes = %+v/%v", counts, result.Classification(0))
	}
}

func TestPackerRejectionReasonsResetAndResultOwnership(t *testing.T) {
	state := packerState(t)
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	firstLogs := validPackerLogs(t)
	firstLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("bad body")
	first, err := packer.Pack(boundedPackerContext(t), firstLogs, nil)
	if !errors.Is(err, ErrPackPermanent) {
		t.Fatalf("first Pack() error = %v, want permanent", err)
	}
	firstReasons := first.RejectionCounts()
	firstCopy := *first
	if firstReasons[RejectionUnsupportedBody] != 1 || rejectionReasonTotal(firstReasons) != 1 {
		t.Fatalf("first reasons = %v", firstReasons)
	}
	firstClass := first.Classification(0)
	firstReasons[RejectionUnsupportedBody] = 99
	second, err := packer.Pack(boundedPackerContext(t), validPackerLogs(t), nil)
	if err != nil {
		t.Fatalf("second Pack() error = %v", err)
	}
	if got := second.RejectionCounts(); got != (RejectionCounts{}) {
		t.Fatalf("second reasons = %v, want zero", got)
	}
	if got := first.RejectionCounts(); got[RejectionUnsupportedBody] != 1 || rejectionReasonTotal(got) != 1 {
		t.Fatalf("first snapshot changed = %v", got)
	}
	if got := first.Classification(0); got != firstClass || got != SourceInvalid {
		t.Fatalf("first classification changed = %v, want invalid", got)
	}
	if got := first.Counts(); got.Invalid != 1 || got.Confirmed != 0 {
		t.Fatalf("first counts changed = %+v", got)
	}
	if firstCopy.RejectionCounts() != first.RejectionCounts() || firstCopy.Classification(0) != SourceInvalid {
		t.Fatal("copied result changed after request reuse")
	}
}

func TestPackerRejectionReasonsExcludeAmbiguousAndUnsent(t *testing.T) {
	state := packerV5State(t, 1, 464)
	logs := appendPackerCopies(t, validPackerLogs(t), 4)
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	records.At(1).Attributes().Remove("source.address")
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if writes == 1 {
				return len(datagram), nil
			}
			return len(datagram) - 1, errors.New("ambiguous handoff")
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackTransient) {
		t.Fatalf("Pack() error = %v, want transient", err)
	}
	counts := result.Counts()
	if counts.Invalid != 1 || counts.Ambiguous != 1 || counts.Unsent != 1 {
		t.Fatalf("counts = %+v", counts)
	}
	if got := rejectionReasonTotal(result.RejectionCounts()); got != counts.Invalid {
		t.Fatalf("reason total = %d, invalid = %d", got, counts.Invalid)
	}
	if got := result.RejectionCounts()[RejectionMissingField]; got != 1 {
		t.Fatalf("missing-field reasons = %d, want one", got)
	}
	if result.Classification(2) != SourceAmbiguous || result.Classification(3) != SourceUnsentValid {
		t.Fatalf("suffix classes = %v/%v", result.Classification(2), result.Classification(3))
	}
}

type hostileRejectionError struct{ payload []byte }

func (hostileRejectionError) Error() string { panic("Error must not be called") }
func (hostileRejectionError) Is(error) bool { panic("Is must not be called") }
func (hostileRejectionError) As(any) bool   { panic("As must not be called") }
func (hostileRejectionError) Unwrap() error { panic("Unwrap must not be called") }

type comparableHostileRejectionError struct{ marker uint64 }

func (comparableHostileRejectionError) Error() string { panic("Error must not be called") }
func (comparableHostileRejectionError) Is(error) bool { panic("Is must not be called") }
func (comparableHostileRejectionError) As(any) bool   { panic("As must not be called") }
func (comparableHostileRejectionError) Unwrap() error { panic("Unwrap must not be called") }

func TestPackerRejectionReasonVocabularyAndRedaction(t *testing.T) {
	wantLabels := []string{
		"other", "unsupported_body", "missing_field", "invalid_type",
		"invalid_value", "map_miss", "family_mismatch", "protocol_mismatch",
		"time_invalid", "custom_unavailable", "custom_invalid",
		"record_too_large", "record_invalid",
	}
	if len(wantLabels) != RejectionReasonCount {
		t.Fatalf("reason count = %d, want %d", RejectionReasonCount, len(wantLabels))
	}
	for index, want := range wantLabels {
		if RejectionReason(index).Label() != want {
			t.Errorf("label[%d] = %q, want %q", index, RejectionReason(index).Label(), want)
		}
	}
	if got := RejectionReason(255).Label(); got != "other" {
		t.Fatalf("unknown label = %q", got)
	}

	for _, test := range []struct {
		name string
		err  error
		want RejectionReason
	}{
		{"unsupported", normalize.ErrUnsupportedBody, RejectionUnsupportedBody},
		{"missing", normalize.ErrMissingRequired, RejectionMissingField},
		{"type", normalize.ErrInvalidType, RejectionInvalidType},
		{"value", normalize.ErrInvalidValue, RejectionInvalidValue},
		{"malformed", normalize.ErrMalformed, RejectionRecordInvalid},
		{"no-records", normalize.ErrNoRecords, RejectionOther},
		{"callback", normalize.ErrInvalidCallback, RejectionOther},
		{"input", normalize.ErrInvalidInput, RejectionOther},
		{"nil", nil, RejectionOther},
		{"text-lookalike", errors.New("normalize: invalid field value"), RejectionOther},
		{"wrapped", fmt.Errorf("wrapped: %w", normalize.ErrInvalidValue), RejectionOther},
		{"hostile", hostileRejectionError{payload: []byte("secret")}, RejectionOther},
		{"comparable-hostile", comparableHostileRejectionError{marker: 1}, RejectionOther},
		{"typed-nil", (*hostileRejectionError)(nil), RejectionOther},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyNormalizeError(test.err); got != test.want {
				t.Fatalf("classify = %v, want %v", got, test.want)
			}
		})
	}

	// These mapper errors are injected at the classifier boundary. In
	// particular, RuntimeValueOverflow has no current production producer.
	for _, test := range []struct {
		reason mapping.RuntimeReason
		want   RejectionReason
	}{
		{mapping.RuntimeMissingField, RejectionMissingField},
		{mapping.RuntimeMapMiss, RejectionMapMiss},
		{mapping.RuntimeFamilyMismatch, RejectionFamilyMismatch},
		{mapping.RuntimeProtocolMismatch, RejectionProtocolMismatch},
		{mapping.RuntimeValueInvalid, RejectionInvalidValue},
		{mapping.RuntimeValueOverflow, RejectionInvalidValue},
		{mapping.RuntimeTimeInvalid, RejectionTimeInvalid},
		{mapping.RuntimeCustomMissing, RejectionCustomUnavailable},
		{mapping.RuntimeCustomInvalid, RejectionCustomInvalid},
		{mapping.RuntimeRecordInvalid, RejectionRecordInvalid},
		{mapping.RuntimeCallbackInvalid, RejectionRecordInvalid},
		{mapping.RuntimeBudgetExceeded, RejectionRecordTooLarge},
		{mapping.RuntimeReason(255), RejectionOther},
	} {
		if got := classifyMappingError(&mapping.RuntimeError{Reason: test.reason}); got != test.want {
			t.Errorf("mapping reason %d = %v, want %v", test.reason, got, test.want)
		}
		if got := classifyMappingError(mapping.RuntimeError{Reason: test.reason}); got != test.want {
			t.Errorf("mapping value reason %d = %v, want %v", test.reason, got, test.want)
		}
	}
	if got := classifyMappingError((*mapping.RuntimeError)(nil)); got != RejectionOther {
		t.Fatalf("typed-nil mapping error = %v", got)
	}
	for name, err := range map[string]error{
		"nil":            nil,
		"text-lookalike": errors.New("mapping runtime reason=1 ordinal=0"),
		"hostile":        hostileRejectionError{payload: []byte("mapping secret")},
	} {
		if got := classifyMappingError(err); got != RejectionOther {
			t.Errorf("mapping %s error = %v, want other", name, got)
		}
	}
	for _, test := range []struct {
		err  error
		want RejectionReason
	}{
		{wire.ErrInvalidValue, RejectionRecordInvalid},
		{wire.ErrRecordValueLimit, RejectionRecordTooLarge},
		{wire.ErrInvalidFamily, RejectionFamilyMismatch},
		{wire.ErrBounds, RejectionRecordTooLarge},
		{wire.ErrShortBuffer, RejectionRecordTooLarge},
		{wire.ErrTimeOutOfRange, RejectionOther},
		{nil, RejectionOther},
		{errors.New(string(wire.ErrInvalidValue)), RejectionOther},
		{fmt.Errorf("wrapped wire: %w", wire.ErrInvalidValue), RejectionOther},
	} {
		if got := classifyWireError(test.err); got != test.want {
			t.Errorf("wire error %v = %v, want %v", test.err, got, test.want)
		}
	}
	if got := classifyWireError(hostileRejectionError{}); got != RejectionOther {
		t.Fatalf("hostile wire error = %v", got)
	}
	if got := classifyWireError(comparableHostileRejectionError{marker: 2}); got != RejectionOther {
		t.Fatalf("comparable hostile wire error = %v", got)
	}
	// Every diagnostic boundary must reject these untrusted error forms
	// without invoking any method, including when the error is comparable.
	for _, err := range []error{
		nil,
		(*hostileRejectionError)(nil),
		hostileRejectionError{payload: []byte("private payload")},
		comparableHostileRejectionError{marker: 3},
		fmt.Errorf("wrapped mapper: %w", &mapping.RuntimeError{Reason: mapping.RuntimeMissingField}),
	} {
		for index, classify := range []func(error) RejectionReason{classifyNormalizeError, classifyMappingError, classifyWireError} {
			if got := classify(err); got != RejectionOther {
				t.Fatalf("untrusted error at classifier %d = %d, want other", index, got)
			}
		}
	}
}

func TestSourceLedgerLegacyFallbackUnknownAndZeroSnapshots(t *testing.T) {
	ledger := newSourceLedger()
	if err := ledger.addSource(0, false); err != nil {
		t.Fatal(err)
	}
	if err := ledger.addSourceReason(1, false, RejectionReason(255)); err != nil {
		t.Fatal(err)
	}
	want := RejectionCounts{}
	want[RejectionOther] = 2
	if got := ledger.RejectionCounts(); got != want {
		t.Fatalf("legacy/unknown reasons = %v, want %v", got, want)
	}
	before := ledgerSnapshot(&ledger)
	if err := ledger.addSource(1, false); !errors.Is(err, ErrLedgerOrdinal) {
		t.Fatalf("duplicate source = %v, want ordinal error", err)
	}
	assertLedgerUnchanged(t, before, &ledger)
	if got := (&PackResult{}).RejectionCounts(); got != (RejectionCounts{}) {
		t.Fatalf("zero result reasons = %v", got)
	}
	var nilResult *PackResult
	if got := nilResult.RejectionCounts(); got != (RejectionCounts{}) {
		t.Fatalf("nil result reasons = %v", got)
	}
}

func TestPackerFirstInvalidReasonWins(t *testing.T) {
	state := packerState(t)
	logs := validPackerLogs(t)
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr("source.port", "wrong type")
	record.Attributes().Remove("source.address")
	packer, err := NewPacker(state, PackerConfig{
		Write: func(context.Context, []byte) (int, error) { t.Fatal("invalid record reached transport"); return 0, nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackPermanent) {
		t.Fatalf("Pack() error = %v, want permanent", err)
	}
	want := RejectionCounts{}
	want[RejectionInvalidType] = 1
	assertPackerRejectionCounts(t, result, want)
}
