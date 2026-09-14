package normalize

import (
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestSamplerAddressFamily(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		logs := testpdata.CanonicalIPv4Logs()
		peer, family := "2001:db8::fe", wire.FamilyIPv4
		if ipv6 {
			logs = testpdata.CanonicalIPv6Logs()
			peer, family = "192.0.2.254", wire.FamilyIPv6
		}
		r := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		r.Attributes().PutStr("flow.sampler_address", peer)
		logs.MarkReadOnly()
		record, err := normalizeTestRecord(logs)
		if err != nil {
			t.Fatalf("flow family %v: %v", family, err)
		}
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		got, ok := record.Lookup(wire.FieldFlowSamplerAddress)
		if !ok || got.IP().String() != peer || record.Family() != family {
			t.Fatal("sampler changed value or flow family")
		}
	}
}
