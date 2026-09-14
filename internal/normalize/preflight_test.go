package normalize

import (
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestInspectCountsRecords(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	stats, err := Inspect(logs)
	if err != nil {
		t.Fatalf("canonical inspection: %v", err)
	}
	if stats.Records != 1 {
		t.Fatalf("record count = %d, want 1", stats.Records)
	}
	if err := Preflight(logs); err != nil {
		t.Fatalf("default preflight: %v", err)
	}
}

func TestPreflightIgnoresIrrelevantMetadata(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr("irrelevant.large", string(make([]byte, 65<<20)))
	deep := record.Attributes().PutEmptyMap("irrelevant.deep")
	for i := 0; i < 1024; i++ {
		deep = deep.PutEmptyMap("child")
	}
	wide := record.Attributes().PutEmptyMap("irrelevant.wide")
	for i := 0; i < 4096; i++ {
		wide.PutInt(string(rune('a'+i%26))+string(rune('a'+i/26)), int64(i))
	}
	if err := Preflight(logs); err != nil {
		t.Fatalf("irrelevant metadata rejected: %v", err)
	}
	called := 0
	if err := NormalizeEachIndexed(logs, func(ordinal uint64, normalized wire.NormalizedRecord, recordErr error) error {
		called++
		if ordinal != 0 || recordErr != nil || normalized.Len() != wire.CanonicalFieldCount {
			t.Fatalf("metadata record = (%d,%d,%v)", ordinal, normalized.Len(), recordErr)
		}
		return nil
	}); err != nil {
		t.Fatalf("metadata normalization: %v", err)
	}
	if called != 1 {
		t.Fatalf("callback count = %d, want 1", called)
	}
}

func TestPreflightLargeRecordCount(t *testing.T) {
	const count = 65_537
	logs := emptyLogs(count)
	stats, err := Inspect(logs)
	if err != nil {
		t.Fatalf("%d records rejected: %v", count, err)
	}
	if stats.Records != count {
		t.Fatalf("records = %d, want %d", stats.Records, count)
	}
	var last uint64
	callbacks := 0
	if err := NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		callbacks++
		last = ordinal
		if record.Len() != 0 || !errors.Is(recordErr, ErrMissingRequired) {
			t.Fatalf("record %d = (len=%d, err=%v), want record-local missing-required", ordinal, record.Len(), recordErr)
		}
		return nil
	}); err != nil {
		t.Fatalf("large normalization: %v", err)
	}
	if callbacks != count || last != count-1 {
		t.Fatalf("callbacks/last = (%d,%d), want (%d,%d)", callbacks, last, count, count-1)
	}
}

func TestPreflightMalformedContainerDoesNotPanic(t *testing.T) {
	var zero plog.Logs
	if err := Preflight(zero); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero logs error = %v, want malformed", err)
	}
}

func emptyLogs(count int) plog.Logs {
	logs := plog.NewLogs()
	scope := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for i := 0; i < count; i++ {
		scope.LogRecords().AppendEmpty()
	}
	return logs
}
