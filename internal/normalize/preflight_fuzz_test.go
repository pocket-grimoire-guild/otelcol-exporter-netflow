package normalize

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	preflightMaxData = 256
	preflightMaxWide = 16
	preflightMaxDeep = 16
)

// FuzzPreflight uses a finite, reviewed scenario grammar. Preflight only
// checks the pdata root and counts records; record validation remains a local
// normalization concern and packet limits remain owned by the destination.
func FuzzPreflight(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, scenario, variant uint8) {
		if len(data) > preflightMaxData {
			t.Skip()
		}
		switch scenario % 9 {
		case 0:
			preflightMalformedRoot(t)
		case 1:
			preflightEmptyHierarchy(t)
		case 2:
			preflightCanonical(t, testpdata.CanonicalLogs(), wire.FamilyIPv4)
		case 3:
			preflightCanonical(t, testpdata.CanonicalIPv6Logs(), wire.FamilyIPv6)
		case 4:
			preflightHierarchyOrder(t)
		case 5:
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("ignored.string", fuzzText(data))
			preflightCanonical(t, logs, wire.FamilyIPv4)
		case 6:
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutEmptyBytes("ignored.bytes").FromRaw(fuzzBytes(data))
			preflightCanonical(t, logs, wire.FamilyIPv4)
		case 7:
			logs := testpdata.CanonicalLogs()
			addIrrelevantValues(logs, data, variant)
			preflightCanonical(t, logs, wire.FamilyIPv4)
		case 8:
			logs := testpdata.CanonicalLogs()
			addDeepAlternatingMetadata(logs, data, variant)
			preflightCanonical(t, logs, wire.FamilyIPv4)
		}
	})
}

func preflightMalformedRoot(t *testing.T) {
	t.Helper()
	var logs plog.Logs
	if err := Preflight(logs); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero pdata preflight error = %v, want malformed", err)
	}
	calls := 0
	if err := NormalizeEachIndexed(logs, func(uint64, wire.NormalizedRecord, error) error {
		calls++
		return nil
	}); !errors.Is(err, ErrMalformed) || calls != 0 {
		t.Fatalf("zero pdata normalization = (%v,%d), want malformed and no callback", err, calls)
	}
}

func preflightEmptyHierarchy(t *testing.T) {
	t.Helper()
	logs := plog.NewLogs()
	logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	before := marshalPreflightLogs(t, logs)
	logs.MarkReadOnly()
	if err := Preflight(logs); err != nil {
		t.Fatalf("empty hierarchy preflight error = %v", err)
	}
	stats, err := Inspect(logs)
	if err != nil || stats.Records != 0 {
		t.Fatalf("empty hierarchy inspect = (%+v,%v), want zero records", stats, err)
	}
	calls := 0
	err = NormalizeEachIndexed(logs, func(uint64, wire.NormalizedRecord, error) error {
		calls++
		return nil
	})
	if !errors.Is(err, ErrNoRecords) || calls != 0 {
		t.Fatalf("empty hierarchy normalization = (%v,%d), want no-records and no callback", err, calls)
	}
	if after := marshalPreflightLogs(t, logs); !bytes.Equal(before, after) {
		t.Fatal("empty hierarchy processing mutated pdata")
	}
}

func preflightCanonical(t *testing.T, logs plog.Logs, family wire.Family) {
	t.Helper()
	before := marshalPreflightLogs(t, logs)
	logs.MarkReadOnly()
	stats, err := Inspect(logs)
	if err != nil || stats.Records != 1 {
		t.Fatalf("canonical inspect = (%+v,%v), want one record", stats, err)
	}
	if err := Preflight(logs); err != nil {
		t.Fatalf("canonical preflight error = %v", err)
	}
	calls := 0
	err = NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		if ordinal != uint64(calls) {
			t.Fatalf("canonical ordinal = %d, want %d", ordinal, calls)
		}
		if recordErr != nil || record.Family() != family || record.Len() != wire.CanonicalFieldCount {
			t.Fatalf("canonical output = (family=%v,len=%d,err=%v)", record.Family(), record.Len(), recordErr)
		}
		calls++
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("canonical normalization = (%v,%d), want one successful callback", err, calls)
	}
	if after := marshalPreflightLogs(t, logs); !bytes.Equal(before, after) {
		t.Fatal("canonical processing mutated pdata")
	}
}

func preflightHierarchyOrder(t *testing.T) {
	t.Helper()
	base := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	logs := plog.NewLogs()
	counts := [2][2]int{{1, 2}, {0, 2}}
	want := 0
	for _, scopeCounts := range counts {
		resource := logs.ResourceLogs().AppendEmpty()
		for _, recordCount := range scopeCounts {
			scope := resource.ScopeLogs().AppendEmpty()
			for recordIndex := 0; recordIndex < recordCount; recordIndex++ {
				record := scope.LogRecords().AppendEmpty()
				base.CopyTo(record)
				record.Attributes().PutInt("source.port", int64(41000+want))
				want++
			}
		}
	}
	before := marshalPreflightLogs(t, logs)
	logs.MarkReadOnly()
	stats, err := Inspect(logs)
	if err != nil || stats.Records != uint64(want) {
		t.Fatalf("hierarchy inspect = (%+v,%v), want %d records", stats, err, want)
	}
	calls := 0
	err = NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
		if ordinal != uint64(calls) || recordErr != nil || record.Family() != wire.FamilyIPv4 || record.Len() != wire.CanonicalFieldCount {
			t.Fatalf("hierarchy event = (%d,%d,%v), want ordinal/family/length %d/ipv4/%d", ordinal, record.Len(), recordErr, calls, wire.CanonicalFieldCount)
		}
		value, ok := record.Lookup(wire.FieldSourcePort)
		if !ok || value.Uint() != uint64(41000+calls) {
			t.Fatalf("hierarchy source port = (%v,%v), want %d", value, ok, 41000+calls)
		}
		calls++
		return nil
	})
	if err != nil || calls != want {
		t.Fatalf("hierarchy normalization = (%v,%d), want %d callbacks", err, calls, want)
	}
	if after := marshalPreflightLogs(t, logs); !bytes.Equal(before, after) {
		t.Fatal("hierarchy processing mutated pdata")
	}
}

func addIrrelevantValues(logs plog.Logs, data []byte, variant uint8) {
	attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	text := fuzzText(data)
	attrs.PutEmpty("ignored.empty")
	attrs.PutStr("ignored.string", text)
	attrs.PutInt("ignored.int", int64(variant))
	attrs.PutDouble("ignored.double", float64(variant)+0.5)
	attrs.PutBool("ignored.bool", variant&1 != 0)
	attrs.PutEmptyBytes("ignored.bytes").FromRaw(fuzzBytes(data))
	attrs.PutEmptyMap("ignored.map").PutStr("child", text)
	attrs.PutEmptySlice("ignored.slice").AppendEmpty().SetStr(text)
	for i := 0; i < 1+int(variant)%preflightMaxWide; i++ {
		attrs.PutInt("ignored.wide."+strconv.Itoa(i), int64(i))
	}
}

func addDeepAlternatingMetadata(logs plog.Logs, data []byte, variant uint8) {
	attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	current := attrs.PutEmptyMap("ignored.deep")
	depth := 1 + int(variant)%preflightMaxDeep
	for i := 0; i < depth; i++ {
		next := current.PutEmptySlice("next")
		current = next.AppendEmpty().SetEmptyMap()
	}
	current.PutStr("leaf", fuzzText(data))
}

func fuzzText(data []byte) string {
	if len(data) == 0 {
		return "seed"
	}
	return string(fuzzBytes(data))
}

func fuzzBytes(data []byte) []byte {
	if len(data) > preflightMaxData {
		data = data[:preflightMaxData]
	}
	return append([]byte(nil), data...)
}

func marshalPreflightLogs(t *testing.T, logs plog.Logs) []byte {
	t.Helper()
	data, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	if err != nil {
		t.Fatalf("marshal preflight logs: %v", err)
	}
	return data
}
