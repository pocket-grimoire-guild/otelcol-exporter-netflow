package testpdata

import (
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestCanonicalLogs(t *testing.T) {
	logs := CanonicalLogs()
	if got := logs.LogRecordCount(); got != 1 {
		t.Fatalf("record count = %d, want 1", got)
	}
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if got := record.Attributes().Len(); got != 41 {
		t.Fatalf("attribute count = %d, want 41", got)
	}
	if got := record.Body().Type(); got != pcommon.ValueTypeEmpty {
		t.Fatalf("body type = %v, want empty", got)
	}
	if got := record.Timestamp(); got != pcommon.Timestamp(1788220801000000000) {
		t.Fatalf("timestamp = %d, want flow.start", got)
	}
	if got := record.ObservedTimestamp(); got != pcommon.Timestamp(1788220802000000000) {
		t.Fatalf("observed timestamp = %d, want flow.time_received", got)
	}
	scope := logs.ResourceLogs().At(0).ScopeLogs().At(0).Scope()
	if scope.Name() != "otelcol/netflowreceiver" {
		t.Fatalf("scope name = %q", scope.Name())
	}
	if got := scope.Attributes().Len(); got != 1 {
		t.Fatalf("scope attributes = %d, want 1", got)
	}
}

func TestCanonicalFamiliesAndOptionalPresence(t *testing.T) {
	for _, tc := range []struct {
		name string
		logs func() interface{ LogRecordCount() int }
	}{
		{name: "ipv4", logs: func() interface{ LogRecordCount() int } { return CanonicalIPv4Logs() }},
		{name: "ipv6", logs: func() interface{ LogRecordCount() int } { return CanonicalIPv6Logs() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.logs().LogRecordCount(); got != 1 {
				t.Fatalf("record count = %d", got)
			}
		})
	}
	without := CanonicalLogsWithoutOptional().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	if _, ok := without.Get("flow.next_hop"); ok {
		t.Fatal("next_hop unexpectedly present")
	}
	if _, ok := without.Get("flow.bgp_next_hop"); ok {
		t.Fatal("bgp_next_hop unexpectedly present")
	}
}
