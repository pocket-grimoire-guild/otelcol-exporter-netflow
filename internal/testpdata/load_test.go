//go:build integration

package testpdata

import (
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestLoadFixtures(t *testing.T) {
	const ignoredRecords = 7

	if got := CanonicalBatch(100).LogRecordCount(); got != 100 {
		t.Fatalf("canonical batch records=%d, want 100", got)
	}
	ignored := IgnoredMetadataLogs(ignoredRecords)
	if got := ignored.LogRecordCount(); got != ignoredRecords {
		t.Fatalf("ignored-metadata records=%d, want %d", got, ignoredRecords)
	}
	resource := ignored.ResourceLogs().At(0)
	if _, ok := resource.Resource().Attributes().Get("plan005.ignored_resource"); !ok {
		t.Fatal("ignored resource metadata missing")
	}
	if _, ok := resource.ScopeLogs().At(0).Scope().Attributes().Get("plan005.ignored_scope"); !ok {
		t.Fatal("ignored scope metadata missing")
	}
	if _, ok := resource.ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("plan005.ignored_record"); !ok {
		t.Fatal("ignored record metadata missing")
	}

	variable := VariableOctetLogs()
	if got := variable.LogRecordCount(); got != VariableOctetRecordCount {
		t.Fatalf("variable-octet records=%d, want %d", got, VariableOctetRecordCount)
	}
	names := VariableOctetFieldNames()
	if len(names) != VariableOctetFieldCount {
		t.Fatalf("variable-octet fields=%d, want %d", len(names), VariableOctetFieldCount)
	}
	record := variable.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	lengths := make(map[int]bool)
	for _, name := range names {
		value, ok := record.Attributes().Get(name)
		if !ok {
			t.Fatalf("variable-octet field %q missing", name)
		}
		if value.Type() != pcommon.ValueTypeBytes {
			t.Fatalf("variable-octet field %q missing or has type %v", name, value.Type())
		}
		if value.Bytes().Len() <= 255 {
			t.Fatalf("variable-octet field %q length=%d, want >255", name, value.Bytes().Len())
		}
		lengths[value.Bytes().Len()] = true
	}
	if len(lengths) < 2 {
		t.Fatal("variable-octet fields do not exercise varied lengths")
	}
}
