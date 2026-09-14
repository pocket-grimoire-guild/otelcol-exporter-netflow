package normalize

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// FuzzNormalize mutates one of all 41 canonical keys between valid siblings.
// Independent schema/vocabulary literals own acceptance and exact values; the
// production normalizer and wire validators are never used to derive expectations.
func FuzzNormalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, field, mutation uint8, integer int64, text string, ipv6 bool) {
		if len(text) > 4096 {
			t.Skip()
		}
		logs := testpdata.CanonicalLogs()
		middle := logs.ResourceLogs().At(0).ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		base := testpdata.CanonicalLogs()
		if ipv6 {
			base = testpdata.CanonicalIPv6Logs()
		}
		base.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(middle)
		last := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(last)

		key := canonicalSchemaVectors[int(field)%len(canonicalSchemaVectors)].name
		attrs := middle.Attributes()
		switch mutation % 13 {
		case 0: // Canonical fixture; keep every original value.
		case 1:
			attrs.PutInt(key, integer)
		case 2:
			attrs.PutStr(key, text)
		case 3:
			attrs.Remove(key)
		case 4:
			attrs.PutEmpty(key)
		case 5:
			attrs.PutBool(key, integer != 0)
		case 6:
			attrs.PutDouble(key, float64(integer))
		case 7:
			attrs.PutEmptyBytes(key).FromRaw([]byte(text))
		case 8:
			attrs.PutEmptyMap(key).PutStr("private-key-canary", text)
		case 9:
			attrs.PutEmptySlice(key).AppendEmpty().SetStr(text)
		case 10:
			// Every nonempty OTel body type is unsupported, including a typed
			// empty string/map/slice/bytes value. TypeEmpty remains parsed mode.
			setNormalizeFuzzBody(middle.Body(), field%8, integer, text)
		case 11:
			// Unknown attributes and provenance must survive in caller pdata,
			// while contributing no fields or fallbacks to the canonical view.
			attrs.PutEmptyMap("unknown-key-canary").PutStr("private", text)
		case 12:
			attrs.Remove(key)
			logs.ResourceLogs().At(0).Resource().Attributes().PutStr(key, text)
			logs.ResourceLogs().At(0).ScopeLogs().At(1).Scope().Attributes().PutStr(key, text)
			middle.SetTimestamp(pcommon.Timestamp(uint64(integer)))
			middle.SetObservedTimestamp(pcommon.Timestamp(uint64(integer)))
		}
		middle.SetSeverityText("severity-canary")
		middle.SetEventName("event-canary")
		middle.SetTraceID(pcommon.TraceID{1})
		middle.SetSpanID(pcommon.SpanID{1})

		sources := [3]plog.LogRecord{logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0), middle, last}
		var want [3]normalizeFuzzExpectation
		for i, source := range sources {
			want[i] = normalizeFuzzOracle(source)
		}
		before := fuzzPdataSnapshot(t, logs)
		var retained [3]wire.NormalizedRecord
		var fingerprints [3]string
		calls := 0
		err := NormalizeEachIndexed(logs, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
			if calls >= len(want) || ordinal != uint64(calls) {
				t.Fatal("indexed normalization lost source order or cardinality")
			}
			assertNormalizeFuzzRecord(t, record, recordErr, want[calls])
			retained[calls] = record
			fingerprints[calls] = normalizedRecordFingerprint(record)
			calls++
			return nil
		})
		assertFuzzError(t, err, nil)
		if calls != len(want) {
			t.Fatal("indexed normalization skipped a source record")
		}
		// The legacy path stops at the first invalid record, after a valid prefix.
		calls = 0
		err = NormalizeEach(logs, func(record wire.NormalizedRecord) error {
			if calls >= len(want) {
				t.Fatal("legacy normalization emitted extra records")
			}
			assertNormalizeFuzzRecord(t, record, nil, want[calls])
			calls++
			return nil
		})
		assertFuzzError(t, err, want[1].err)
		expectedCalls := 3
		if want[1].err != nil {
			expectedCalls = 1
		}
		if calls != expectedCalls {
			t.Fatal("legacy normalization continued after a record error")
		}
		// Callback errors must stop even on the invalid middle record. Repeat
		// against read-only pdata to catch attempted mutation hidden by recover.
		frozen := plog.NewLogs()
		logs.CopyTo(frozen)
		frozen.MarkReadOnly()
		stop := errors.New("test callback stop")
		calls = 0
		err = NormalizeEachIndexed(frozen, func(ordinal uint64, record wire.NormalizedRecord, recordErr error) error {
			if calls >= 2 || ordinal != uint64(calls) {
				t.Fatal("callback error did not stop traversal")
			}
			assertNormalizeFuzzRecord(t, record, recordErr, want[calls])
			calls++
			if ordinal == 1 {
				return stop
			}
			return nil
		})
		if err != stop || calls != 2 {
			t.Fatal("callback error was swallowed or replaced")
		}
		if !bytes.Equal(before, fuzzPdataSnapshot(t, logs)) || !bytes.Equal(before, fuzzPdataSnapshot(t, frozen)) {
			t.Fatal("normalization mutated caller pdata")
		}
		for i, source := range sources {
			source.Attributes().Clear()
			source.Body().SetStr("replaced-after-normalization")
			if normalizedRecordFingerprint(retained[i]) != fingerprints[i] {
				t.Fatal("normalized output retained mutable pdata storage")
			}
		}
	})
}

func setNormalizeFuzzBody(v pcommon.Value, kind uint8, integer int64, text string) {
	switch kind {
	case 1:
		v.SetStr(text)
	case 2:
		v.SetInt(integer)
	case 3:
		v.SetDouble(float64(integer))
	case 4:
		v.SetBool(integer != 0)
	case 5:
		v.SetEmptyMap()
	case 6:
		v.SetEmptySlice()
	case 7:
		v.SetEmptyBytes().FromRaw([]byte(text))
	}
}

type normalizeFuzzExpectation struct {
	values []wire.FieldValue
	family wire.Family
	err    error
}

func normalizeFuzzOracle(record plog.LogRecord) normalizeFuzzExpectation {
	reject := func(err error) normalizeFuzzExpectation { return normalizeFuzzExpectation{err: err} }
	if record.Body().Type() != pcommon.ValueTypeEmpty {
		return reject(ErrUnsupportedBody)
	}
	want := normalizeFuzzExpectation{family: wire.FamilyIPv4}
	for _, schema := range canonicalSchemaVectors {
		value, exists := record.Attributes().Get(schema.name)
		if !exists {
			if schema.optional {
				continue
			}
			return reject(ErrMissingRequired)
		}
		if value.Type() != schema.pdata {
			return reject(ErrInvalidType)
		}
		var converted wire.Value
		if schema.numeric {
			ceiling := schema.max
			if (schema.name == "flow.src_net" || schema.name == "flow.dst_net") && want.family == wire.FamilyIPv4 {
				ceiling = 32
			}
			if value.Int() < 0 || uint64(value.Int()) > ceiling {
				return reject(ErrInvalidValue)
			}
			converted = wire.UintValue(uint64(value.Int()))
			if schema.kind == wire.ValueUnixNanos {
				converted = wire.UnixNanosValue(uint64(value.Int()))
			}
		} else {
			text := value.Str()
			if !utf8.ValidString(text) {
				return reject(ErrInvalidValue)
			}
			switch schema.kind {
			case wire.ValueIP:
				ip, err := netip.ParseAddr(text)
				if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != text {
					return reject(ErrInvalidValue)
				}
				if schema.name == "source.address" && ip.Is6() {
					want.family = wire.FamilyIPv6
				}
				if schema.name != "flow.sampler_address" && ip.Is4() != (want.family == wire.FamilyIPv4) {
					return reject(ErrInvalidValue)
				}
				if ip.Is4() {
					converted = wire.IPv4Value(ip)
				} else {
					converted = wire.IPv6Value(ip)
				}
			case wire.ValueMAC:
				mac, err := net.ParseMAC(text)
				if err != nil || len(mac) != 6 || mac.String() != text {
					return reject(ErrInvalidValue)
				}
				converted = wire.MACValue([6]byte(mac))
			case wire.ValueString:
				var tokens []string
				switch schema.name {
				case "network.transport":
					tokens = testNetworkTransportTokens[:]
				case "network.type":
					tokens = testNetworkTypeTokens[:]
				case "flow.type":
					tokens = testFlowTypeTokens[:]
				}
				if !slices.Contains(tokens, text) {
					return reject(ErrInvalidValue)
				}
				converted = wire.StringValue(text)
			}
		}
		want.values = append(want.values, wire.FieldValue{Field: schema.field, Value: converted})
	}
	return want
}

func assertNormalizeFuzzRecord(t *testing.T, got wire.NormalizedRecord, err error, want normalizeFuzzExpectation) {
	t.Helper()
	assertFuzzError(t, err, want.err)
	if err != nil {
		if got.Len() != 0 || got.Family() != wire.FamilyUnknown {
			t.Fatal("invalid record exposed partial normalized output")
		}
		return
	}
	if got.Family() != want.family || !reflect.DeepEqual(got.Values(), want.values) {
		t.Fatal("normalized fields differ from the independent schema oracle")
	}
}

func fuzzPdataSnapshot(t *testing.T, logs plog.Logs) []byte {
	t.Helper()
	data, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	if err != nil {
		t.Fatal("cannot snapshot test pdata")
	}
	return data
}

func assertFuzzError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	if got != nil && want != nil && got.Error() != want.Error() {
		t.Fatalf("error text = %q, want %q", got.Error(), want.Error())
	}
}
