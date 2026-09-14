package normalize

import (
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestNormalizeEachIndexedContinuationAndOrder(t *testing.T) {
	logs := plog.NewLogs()
	firstResource := logs.ResourceLogs().AppendEmpty()
	firstResource.ScopeLogs().AppendEmpty()
	appendIndexedRecord(firstResource.ScopeLogs().AppendEmpty(), true)
	secondResource := logs.ResourceLogs().AppendEmpty()
	secondResource.ScopeLogs().AppendEmpty()
	appendIndexedRecord(secondResource.ScopeLogs().AppendEmpty(), false)
	appendIndexedRecord(secondResource.ScopeLogs().AppendEmpty(), true)

	type event struct {
		ordinal uint64
		record  wire.NormalizedRecord
		err     error
	}
	events := make([]event, 0, 3)
	if err := NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		events = append(events, event{ordinal: ordinal, record: record, err: recordErr})
		return nil
	}); err != nil {
		t.Fatalf("NormalizeEachIndexed() error = %v, want nil", err)
	}
	if len(events) != 3 {
		t.Fatalf("callback events = %d, want 3", len(events))
	}
	for index, event := range events {
		if event.ordinal != uint64(index) {
			t.Errorf("event %d ordinal = %d, want %d", index, event.ordinal, index)
		}
	}
	if events[0].err != nil || events[0].record.Len() != wire.CanonicalFieldCount {
		t.Errorf("first event = (len=%d, err=%v), want valid canonical record", events[0].record.Len(), events[0].err)
	}
	if !errors.Is(events[1].err, ErrMissingRequired) || events[1].record.Len() != 0 {
		t.Errorf("invalid event = (len=%d, err=%v), want zero record and missing-required", events[1].record.Len(), events[1].err)
	}
	if events[2].err != nil || events[2].record.Len() != wire.CanonicalFieldCount {
		t.Errorf("last event = (len=%d, err=%v), want valid canonical record", events[2].record.Len(), events[2].err)
	}
}

func TestNormalizeEachIndexedAllInvalidContinues(t *testing.T) {
	callbacks := 0
	var previous uint64
	if err := NormalizeEachIndexed(emptyLogs(3), func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		if ordinal != previous {
			t.Fatalf("ordinal = %d, want %d", ordinal, previous)
		}
		previous++
		callbacks++
		if record.Len() != 0 || !errors.Is(recordErr, ErrMissingRequired) {
			t.Fatalf("event %d = (len=%d, err=%v), want zero/missing-required", ordinal, record.Len(), recordErr)
		}
		return nil
	}); err != nil {
		t.Fatalf("NormalizeEachIndexed() error = %v, want nil", err)
	}
	if callbacks != 3 || previous != 3 {
		t.Fatalf("callbacks/last ordinal = (%d,%d), want (3,3)", callbacks, previous)
	}
}

func TestNormalizeEachIndexedRecordLocalFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(plog.LogRecord)
		want   error
	}{
		{name: "missing", mutate: func(record plog.LogRecord) { record.Attributes().Remove("source.address") }, want: ErrMissingRequired},
		{name: "invalid-type", mutate: func(record plog.LogRecord) { record.Attributes().PutStr("source.port", "123") }, want: ErrInvalidType},
		{name: "invalid-value", mutate: func(record plog.LogRecord) { record.Attributes().PutInt("source.port", -1) }, want: ErrInvalidValue},
		{name: "unsupported-body", mutate: func(record plog.LogRecord) { record.Body().SetStr("raw body") }, want: ErrUnsupportedBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			tc.mutate(logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0))
			callbacks := 0
			if err := NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
				callbacks++
				if ordinal != 0 || record.Len() != 0 || !errors.Is(recordErr, tc.want) {
					t.Fatalf("event = (%d,len=%d,err=%v), want (0,0,%v)", ordinal, record.Len(), recordErr, tc.want)
				}
				return nil
			}); err != nil {
				t.Fatalf("NormalizeEachIndexed() error = %v, want nil", err)
			}
			if callbacks != 1 {
				t.Fatalf("callbacks = %d, want 1", callbacks)
			}
		})
	}
}

func TestNormalizeEachIndexedCallbackErrorStopsAndPropagates(t *testing.T) {
	want := errors.New("indexed callback error")
	t.Run("valid", func(t *testing.T) {
		calls := 0
		got := NormalizeEachIndexed(testpdata.CanonicalLogs(), func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
			calls++
			if ordinal != 0 || record.Len() == 0 || recordErr != nil {
				t.Fatalf("event = (%d,len=%d,err=%v), want valid ordinal zero", ordinal, record.Len(), recordErr)
			}
			return want
		})
		if got != want || calls != 1 {
			t.Fatalf("result/calls = (%v,%d), want callback error and one call", got, calls)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		calls := 0
		got := NormalizeEachIndexed(emptyLogs(2), func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
			calls++
			if ordinal != 0 || record.Len() != 0 || !errors.Is(recordErr, ErrMissingRequired) {
				t.Fatalf("event = (%d,len=%d,err=%v), want invalid ordinal zero", ordinal, record.Len(), recordErr)
			}
			return want
		})
		if got != want || calls != 1 {
			t.Fatalf("result/calls = (%v,%d), want callback error and one call", got, calls)
		}
	})
}

func TestNormalizeEachIndexedCallbackPanicPropagates(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var callbackErr error
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			_ = NormalizeEachIndexed(testpdata.CanonicalLogs(), func(_ uint64, _ wire.NormalizedRecord, recordErr error) error {
				callbackErr = recordErr
				panic("valid callback panic")
			})
		}()
		if !panicked || callbackErr != nil {
			t.Fatalf("panic/error = (%v,%v), want panic and nil record error", panicked, callbackErr)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		var callbackErr error
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			_ = NormalizeEachIndexed(emptyLogs(1), func(_ uint64, record wire.NormalizedRecord, recordErr error) error {
				if record.Len() != 0 {
					t.Fatalf("invalid panic record length = %d, want 0", record.Len())
				}
				callbackErr = recordErr
				panic("invalid callback panic")
			})
		}()
		if !panicked || !errors.Is(callbackErr, ErrMissingRequired) {
			t.Fatalf("panic/error = (%v,%v), want panic and missing-required", panicked, callbackErr)
		}
	})
}

func TestNormalizeEachIndexedVisitsEachSourceRecord(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	calls := 0
	err := NormalizeEachIndexed(logs, func(uint64, wire.NormalizedRecord, error) error {
		calls++
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("result/calls = (%v,%d), want nil and two callbacks", err, calls)
	}
}

func TestNormalizeEachIndexedInputBoundaries(t *testing.T) {
	t.Run("invalid-callback", func(t *testing.T) {
		if err := NormalizeEachIndexed(testpdata.CanonicalLogs(), nil); !errors.Is(err, ErrInvalidCallback) {
			t.Fatalf("nil callback error = %v, want invalid-callback", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		calls := 0
		if err := NormalizeEachIndexed(emptyLogs(0), func(uint64, wire.NormalizedRecord, error) error {
			calls++
			return nil
		}); !errors.Is(err, ErrNoRecords) || calls != 0 {
			t.Fatalf("empty result/calls = (%v,%d), want no-records and zero calls", err, calls)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		var logs plog.Logs
		calls := 0
		if err := NormalizeEachIndexed(logs, func(uint64, wire.NormalizedRecord, error) error {
			calls++
			return nil
		}); !errors.Is(err, ErrMalformed) || calls != 0 {
			t.Fatalf("malformed result/calls = (%v,%d), want malformed and zero calls", err, calls)
		}
	})
}

func TestNormalizeEachIndexedDoesNotRetainPdata(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	source := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	var got wire.NormalizedRecord
	if err := NormalizeEachIndexed(logs, func(_ uint64, record wire.NormalizedRecord, recordErr error) error {
		if recordErr != nil {
			return recordErr
		}
		got = record
		return nil
	}); err != nil {
		t.Fatalf("NormalizeEachIndexed() error = %v, want nil", err)
	}
	source.Attributes().PutStr("source.address", "192.0.2.99")
	value, ok := got.Lookup(wire.FieldSourceAddress)
	if !ok || value.IP().String() != "192.0.2.1" {
		t.Fatalf("normalized source address = (%v,%v), want copied original", value, ok)
	}
}

func TestNormalizeEachIndexedPreservesLegacyFirstError(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	scope := logs.ResourceLogs().At(0).ScopeLogs().At(0)
	bad := scope.LogRecords().AppendEmpty()
	bad.Attributes().PutStr("source.address", "192.0.2.1")
	last := scope.LogRecords().AppendEmpty()
	testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(last)
	calls := 0
	err := NormalizeEach(logs, func(record wire.NormalizedRecord) error {
		calls++
		if record.Len() != wire.CanonicalFieldCount {
			t.Fatalf("legacy record length = %d, want canonical", record.Len())
		}
		return nil
	})
	if !errors.Is(err, ErrMissingRequired) || calls != 1 {
		t.Fatalf("legacy result/calls = (%v,%d), want first record error and one call", err, calls)
	}
}

func TestNormalizeEachIndexedOrdinalBoundary(t *testing.T) {
	const count = 65_537
	logs := emptyLogs(count)
	var next uint64
	if err := NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		if ordinal != next {
			t.Fatalf("ordinal = %d, want %d", ordinal, next)
		}
		if record.Len() != 0 || !errors.Is(recordErr, ErrMissingRequired) {
			t.Fatalf("event %d = (len=%d, err=%v), want zero/missing-required", ordinal, record.Len(), recordErr)
		}
		next++
		return nil
	}); err != nil {
		t.Fatalf("NormalizeEachIndexed() error = %v, want nil", err)
	}
	if next != count || next-1 != count-1 {
		t.Fatalf("visited ordinals through %d, want through %d", next-1, count-1)
	}
}

func appendIndexedRecord(scope plog.ScopeLogs, valid bool) plog.LogRecord {
	record := scope.LogRecords().AppendEmpty()
	testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(record)
	if !valid {
		record.Attributes().Remove("source.address")
	}
	return record
}
