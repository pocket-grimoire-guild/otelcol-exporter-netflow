package normalize

import (
	"errors"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestMalformed(t *testing.T) {
	t.Run("numeric-address", TestMalformedNumericAndAddressValues)
	t.Run("types-text", TestMalformedTypesAndCanonicalText)
	t.Run("body-fallbacks", TestMalformedBodyAndUnsupportedFallbacks)
}

func TestMalformedNumericAndAddressValues(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value int64
	}{
		{name: "negative", field: "flow.io.bytes", value: -1},
		{name: "port-one-beyond", field: "source.port", value: 65536},
		{name: "tcp-flags-one-beyond", field: "flow.tcp_flags", value: 65536},
		{name: "byte-one-beyond", field: "flow.ip_tos", value: 256},
		{name: "vlan-one-beyond", field: "flow.vlan_id", value: 4096},
		{name: "flow-label-one-beyond", field: "flow.ipv6_flow_label", value: 0x100000},
		{name: "prefix-one-beyond-ipv4", field: "flow.src_net", value: 33},
		{name: "signed-overflow-decoded", field: "flow.io.packets", value: math.MinInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutInt(tc.field, tc.value)
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want invalid-value", err)
			}
		})
	}

	for _, text := range []string{"invalid IP", "192.000.2.1", "192.0.2.1/32", "::ffff:192.0.2.1"} {
		t.Run("address-"+text, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutStr("source.address", text)
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("address %q error = %v", text, err)
			}
		})
	}
}

func TestMalformedTypesAndCanonicalText(t *testing.T) {
	t.Run("numeric-as-string", func(t *testing.T) {
		logs := testpdata.CanonicalLogs()
		record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		record.Attributes().PutStr("source.port", "12345")
		if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidType) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("string-as-int", func(t *testing.T) {
		logs := testpdata.CanonicalLogs()
		record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		record.Attributes().PutInt("network.transport", 6)
		if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidType) {
			t.Fatalf("error = %v", err)
		}
	})
	for _, tc := range []struct {
		field string
		text  string
	}{
		{"flow.src_mac", "00:11:22:33:44:FF"},
		{"flow.src_mac", "00-11-22-33-44-55"},
		{"flow.dst_mac", "00:11:22:33:44"},
		{"network.transport", "TCP"},
		{"network.type", "ethernet"},
		{"flow.type", "netflow-v9"},
		{"source.address", string([]byte{0xff, 0xfe})},
	} {
		t.Run(tc.field, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutStr(tc.field, tc.text)
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("%s=%q error = %v", tc.field, tc.text, err)
			}
		})
	}
}

func TestMalformedBodyAndUnsupportedFallbacks(t *testing.T) {
	for _, name := range []string{"empty-string", "bytes", "map", "slice"} {
		t.Run(name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			switch name {
			case "empty-string":
				record.Body().SetStr("")
			case "bytes":
				record.Body().SetEmptyBytes().FromRaw([]byte("formatted"))
			case "map":
				record.Body().SetEmptyMap().PutStr("body", "formatted")
			case "slice":
				record.Body().SetEmptySlice().AppendEmpty().SetStr("formatted")
			}
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrUnsupportedBody) {
				t.Fatalf("body error = %v", err)
			}
		})
	}

	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().Remove("flow.start")
	record.SetObservedTimestamp(pcommon.Timestamp(1788220801000000000))
	if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrMissingRequired) {
		t.Fatalf("observed timestamp fallback error = %v", err)
	}
}
