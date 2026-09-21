package normalize

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestNextHopNormalizationFamiliesAndPresence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family wire.Family
		same   string
		cross  string
	}{
		{name: "ipv4", family: wire.FamilyIPv4, same: "192.0.2.254", cross: "2001:db8::fe"},
		{name: "ipv6", family: wire.FamilyIPv6, same: "2001:db8::fe", cross: "192.0.2.254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
				for _, state := range []struct {
					name string
					text string
				}{{"omitted", ""}, {"same", tc.same}, {"cross", tc.cross}} {
					t.Run(field+"/"+state.name, func(t *testing.T) {
						logs := testpdata.CanonicalLogsWithoutOptional()
						if tc.family == wire.FamilyIPv6 {
							logs = nextHopWithoutOptional(testpdata.CanonicalIPv6Logs())
						}
						if state.text != "" {
							logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr(field, state.text)
						}
						record, err := normalizeNextHopRecord(logs)
						if err != nil {
							t.Fatalf("normalization=(%v,%v), want success", record, err)
						}
						if record.Family() != tc.family {
							t.Fatalf("family=%v, want %v", record.Family(), tc.family)
						}
						if state.text == "" {
							if _, ok := record.Lookup(nextHopField(field)); ok {
								t.Fatalf("omitted %s appeared in normalized record", field)
							}
						} else if got, ok := record.Lookup(nextHopField(field)); !ok || got.IP().String() != state.text {
							t.Fatalf("normalized %s=(%v,%v), want %s", field, got.IP(), ok, state.text)
						}
					})
				}
			}
		})
	}

	for _, tc := range []struct {
		name       string
		logs       plog.Logs
		wantRecord int
		wantAttrs  int
	}{
		{"required-only", testpdata.CanonicalLogsWithoutOptional(), 39, 39},
		{"one-optional", nextHopLogs(testpdata.CanonicalLogsWithoutOptional(), "flow.next_hop", "192.0.2.254"), 40, 40},
		{"both-optionals", testpdata.CanonicalLogs(), 41, 41},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Len()
			if attrs != tc.wantAttrs {
				t.Fatalf("pdata attributes=%d, want %d", attrs, tc.wantAttrs)
			}
			record, err := normalizeNextHopRecord(tc.logs)
			if err != nil || record.Len() != tc.wantRecord {
				t.Fatalf("normalized=(len=%d,err=%v), want (%d,nil)", record.Len(), err, tc.wantRecord)
			}
		})
	}
	missing := testpdata.CanonicalLogsWithoutOptional()
	missing.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Remove("source.port")
	if record, err := normalizeNextHopRecord(missing); !errors.Is(err, ErrMissingRequired) || record.Len() != 0 {
		t.Fatalf("missing required=(len=%d,err=%v), want zero/missing-required", record.Len(), err)
	}
}

func TestNextHopNormalizationMalformedAndTypedBoundaries(t *testing.T) {
	for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		for _, field := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
			for _, text := range []string{"", "invalid IP", "192.000.2.1", "2001:0db8::1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
				t.Run(field+"/"+text, func(t *testing.T) {
					logs := nextHopBase(family)
					logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr(field, text)
					record, err := normalizeNextHopRecord(logs)
					if record.Len() != 0 || !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("malformed %q=(len=%d,err=%v), want zero/invalid-value", text, record.Len(), err)
					}
				})
			}
			logs := nextHopBase(family)
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt(field, 7)
			if record, err := normalizeNextHopRecord(logs); record.Len() != 0 || !errors.Is(err, ErrInvalidType) {
				t.Fatalf("wrong typed %s=(len=%d,err=%v), want zero/invalid-type", field, record.Len(), err)
			}
		}
	}

	for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		logs := nextHopBase(family)
		record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		if family == wire.FamilyIPv4 {
			record.Attributes().PutStr("destination.address", "2001:db8::2")
		} else {
			record.Attributes().PutStr("destination.address", "198.51.100.2")
		}
		got, err := normalizeNextHopRecord(logs)
		if got.Len() != 0 || !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("mixed endpoint family=(len=%d,err=%v), want zero/invalid-value", got.Len(), err)
		}
	}

	// The typed API intentionally preserves a mapped IPv6 representation; the
	// receiver text boundary rejects its textual spelling independently.
	mappedAddress := netip.MustParseAddr("::ffff:192.0.2.1")
	mapped := wire.IPValue(mappedAddress)
	if record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowNextHop, Value: mapped}}); err != nil || record.Validate() != nil {
		t.Fatalf("typed mapped next hop=(%v,%v), want constructor and Validate success", record, err)
	} else if got, ok := record.Lookup(wire.FieldFlowNextHop); !ok || !got.IP().Is4In6() || got.IP() != mappedAddress {
		t.Fatalf("typed mapped next hop lookup=(%v,%v), want exact Is4In6 address %v", got.IP(), ok, mappedAddress)
	}
	if parsed, err := wire.ParseIPValue("::ffff:192.0.2.1"); err != nil || !parsed.IP().Is4In6() || parsed.IP() != mappedAddress {
		t.Fatalf("ParseIPValue mapped=(%v,%v), want exact Is4In6 address", parsed.IP(), err)
	}
	logs := nextHopBase(wire.FamilyIPv4)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("flow.next_hop", "::ffff:192.0.2.1")
	if record, err := normalizeNextHopRecord(logs); record.Len() != 0 || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("textual mapped next hop=(len=%d,err=%v), want zero/invalid-value", record.Len(), err)
	}
}

func TestNextHopNormalizeFuzzOracle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		logs   plog.Logs
		family wire.Family
	}{
		{"ipv4-cross-next", nextHopLogs(testpdata.CanonicalLogsWithoutOptional(), "flow.next_hop", "2001:db8::fe"), wire.FamilyIPv4},
		{"ipv4-cross-bgp", nextHopLogs(testpdata.CanonicalLogsWithoutOptional(), "flow.bgp_next_hop", "2001:db8::3"), wire.FamilyIPv4},
		{"ipv6-cross-next", nextHopLogs(nextHopWithoutOptional(testpdata.CanonicalIPv6Logs()), "flow.next_hop", "192.0.2.254"), wire.FamilyIPv6},
		{"ipv6-cross-bgp", nextHopLogs(nextHopWithoutOptional(testpdata.CanonicalIPv6Logs()), "flow.bgp_next_hop", "192.0.2.1"), wire.FamilyIPv6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := tc.logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			want := normalizeFuzzOracle(source)
			if want.err != nil || want.family != tc.family {
				t.Fatalf("oracle=(family=%v,err=%v), want %v,nil", want.family, want.err, tc.family)
			}
			if _, err := normalizeNextHopRecord(tc.logs); err != nil {
				t.Fatalf("production normalization rejected oracle-valid cross-family hop: %v", err)
			}
		})
	}
	for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		for _, key := range []string{"flow.next_hop", "flow.bgp_next_hop"} {
			malformed := nextHopBase(family)
			malformedRecord := malformed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			malformedRecord.Attributes().PutStr(key, "invalid IP")
			want := normalizeFuzzOracle(malformedRecord)
			if want.err != ErrInvalidValue {
				t.Fatalf("oracle malformed %s/%v=%v, want literal invalid-value", key, family, want.err)
			}
			if got, err := normalizeNextHopRecord(malformed); got.Len() != 0 || err != ErrInvalidValue {
				t.Fatalf("production malformed %s/%v=(len=%d,err=%v), want zero/literal invalid-value", key, family, got.Len(), err)
			}

			wrongType := nextHopBase(family)
			wrongTypeRecord := wrongType.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			wrongTypeRecord.Attributes().PutInt(key, 7)
			want = normalizeFuzzOracle(wrongTypeRecord)
			if want.err != ErrInvalidType {
				t.Fatalf("oracle wrong type %s/%v=%v, want literal invalid-type", key, family, want.err)
			}
			if got, err := normalizeNextHopRecord(wrongType); got.Len() != 0 || err != ErrInvalidType {
				t.Fatalf("production wrong type %s/%v=(len=%d,err=%v), want zero/literal invalid-type", key, family, got.Len(), err)
			}
		}

		endpoint := nextHopBase(family)
		endpointRecord := endpoint.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		if family == wire.FamilyIPv4 {
			endpointRecord.Attributes().PutStr("destination.address", "2001:db8::2")
		} else {
			endpointRecord.Attributes().PutStr("destination.address", "198.51.100.2")
		}
		want := normalizeFuzzOracle(endpointRecord)
		if want.err != ErrInvalidValue {
			t.Fatalf("oracle endpoint mismatch/%v=%v, want literal invalid-value", family, want.err)
		}
		if got, err := normalizeNextHopRecord(endpoint); got.Len() != 0 || err != ErrInvalidValue {
			t.Fatalf("production endpoint mismatch/%v=(len=%d,err=%v), want zero/literal invalid-value", family, got.Len(), err)
		}
	}
}

func nextHopField(name string) wire.CanonicalField {
	if name == "flow.next_hop" {
		return wire.FieldFlowNextHop
	}
	return wire.FieldFlowBGPNextHop
}

func nextHopBase(family wire.Family) plog.Logs {
	if family == wire.FamilyIPv6 {
		return nextHopWithoutOptional(testpdata.CanonicalIPv6Logs())
	}
	return testpdata.CanonicalLogsWithoutOptional()
}

func nextHopLogs(logs plog.Logs, field, text string) plog.Logs {
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr(field, text)
	return logs
}

func normalizeNextHopRecord(logs plog.Logs) (wire.NormalizedRecord, error) {
	var record wire.NormalizedRecord
	err := NormalizeEachIndexed(logs, func(_ uint64, got wire.NormalizedRecord, recordErr error) error {
		record = got
		return recordErr
	})
	return record, err
}

func nextHopWithoutOptional(logs plog.Logs) plog.Logs {
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().Remove("flow.next_hop")
	record.Attributes().Remove("flow.bgp_next_hop")
	return logs
}
