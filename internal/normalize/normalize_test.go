package normalize

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestNormalize(t *testing.T) {
	t.Run("canonical", TestNormalizeCanonical)
	t.Run("fingerprint", TestNormalizeCanonicalFingerprint)
	t.Run("ipv6-optional", TestNormalizeIPv6AndOptionalAbsence)
	t.Run("non-retention", TestNormalizeDoesNotRetainOrMutatePdata)
	t.Run("concurrent-calls", TestNormalizeConcurrentCalls)
	t.Run("zero-no-fallback", TestNormalizeZeroAndNoFallbacks)
	t.Run("rejects", TestNormalizeRejectsTypeAddressBodyAndProvenanceFallback)
	t.Run("unselected-metadata", TestNormalizeEachIgnoresUnselectedMetadata)
	t.Run("rejection-callback-zero", TestNormalizeRejectionCallbackZero)
	t.Run("callback-error-returned", TestNormalizeCallbackErrorReturned)
	t.Run("callback-panic-propagates", TestNormalizeCallbackPanicPropagates)
	t.Run("malformed-boundary", TestNormalizeMalformedPdataBoundary)
}

func TestNormalizeCanonical(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	got, err := normalizeTestRecord(logs)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got.Family() != wire.FamilyIPv4 || got.Len() != 41 {
		t.Fatalf("normalized family/length = %v/%d, want ipv4/41", got.Family(), got.Len())
	}
	if value, ok := got.Lookup(wire.FieldSourceAddress); !ok || value.Kind() != wire.ValueIP || value.IP().String() != "192.0.2.1" {
		t.Fatalf("source address = (%v,%v)", value, ok)
	}
	if value, ok := got.Lookup(wire.FieldFlowStart); !ok || value.Kind() != wire.ValueUnixNanos || value.UnixNanos() != 1788220801000000000 {
		t.Fatalf("flow.start = (%v,%v)", value, ok)
	}
	if value, ok := got.Lookup(wire.FieldFlowSrcMAC); !ok || value.Kind() != wire.ValueMAC || value.MAC() != [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("source MAC = (%v,%v)", value, ok)
	}
	if value, ok := got.Lookup(wire.FieldFlowNextHop); !ok || value.IP().String() != "192.0.2.254" {
		t.Fatalf("next hop = (%v,%v)", value, ok)
	}
}

func TestNormalizeCanonicalFingerprint(t *testing.T) {
	got, err := normalizeTestRecord(testpdata.CanonicalLogs())
	if err != nil {
		t.Fatalf("canonical normalization: %v", err)
	}
	if got.Len() != wire.CanonicalFieldCount {
		t.Fatalf("canonical field count = %d, want %d", got.Len(), wire.CanonicalFieldCount)
	}
	for index := 0; index < wire.CanonicalFieldCount; index++ {
		field, ok := got.FieldAt(index)
		if !ok || field.Field != wire.CanonicalField(index) {
			t.Fatalf("canonical field at %d = (%v,%v), want %v", index, field.Field, ok, index)
		}
	}
	actual := normalizedRecordFingerprint(got)
	t.Logf("canonical normalized-record fingerprint = %s", actual)
	const want = "cfb800c180267b161d4b075d1b2f9bdc264d287b14fa9a42225a26d90aa48bcc"
	if actual != want {
		t.Fatalf("canonical normalized-record fingerprint = %s, want %s", actual, want)
	}

	// Envelope metadata and identity fields are deliberately not canonical
	// values. Changing them must not change the complete normalized fingerprint.
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.SetTimestamp(pcommon.Timestamp(1))
	record.SetObservedTimestamp(pcommon.Timestamp(2))
	record.SetSeverityText("unselected severity")
	record.SetEventName("unselected event")
	record.SetSeverityNumber(plog.SeverityNumber(255))
	record.SetFlags(plog.LogRecordFlags(0xffff))
	record.SetDroppedAttributesCount(^uint32(0))
	record.SetTraceID(pcommon.TraceID{1})
	record.SetSpanID(pcommon.SpanID{1})
	withEnvelope, err := normalizeTestRecord(logs)
	if err != nil {
		t.Fatalf("metadata normalization: %v", err)
	}
	if gotEnvelope := normalizedRecordFingerprint(withEnvelope); gotEnvelope != actual {
		t.Fatalf("identity envelope changed fingerprint: got %s, want %s", gotEnvelope, actual)
	}
}

// normalizedRecordFingerprint is a test-owned binary framing oracle. It does
// not use fmt output, map order, pointers, or production serialization.
func normalizedRecordFingerprint(record wire.NormalizedRecord) string {
	hasher := sha256.New()
	write := func(bytes []byte) { _, _ = hasher.Write(bytes) }
	var fixed [8]byte
	write([]byte("otel-netflow-normalized-record-v1"))
	write([]byte{byte(record.Family())})
	binary.BigEndian.PutUint16(fixed[:2], uint16(record.Len()))
	write(fixed[:2])
	for index := 0; index < record.Len(); index++ {
		field, ok := record.FieldAt(index)
		if !ok {
			panic("missing normalized field")
		}
		binary.BigEndian.PutUint16(fixed[:2], uint16(field.Field))
		write(fixed[:2])
		write([]byte{byte(field.Value.Kind())})
		switch field.Value.Kind() {
		case wire.ValueInt:
			binary.BigEndian.PutUint64(fixed[:], uint64(field.Value.Int()))
			write(fixed[:])
		case wire.ValueUint, wire.ValueUnixNanos:
			binary.BigEndian.PutUint64(fixed[:], field.Value.Uint())
			write(fixed[:])
		case wire.ValueString:
			text := field.Value.Text()
			binary.BigEndian.PutUint32(fixed[:4], uint32(len(text)))
			write(fixed[:4])
			write([]byte(text))
		case wire.ValueBytes:
			octets := field.Value.Octets()
			binary.BigEndian.PutUint32(fixed[:4], uint32(len(octets)))
			write(fixed[:4])
			write([]byte(octets))
		case wire.ValueIP:
			ip := field.Value.IP()
			if ip.Is4() {
				write([]byte{4})
				bytes := ip.As4()
				write(bytes[:])
			} else if ip.Is6() && !ip.Is4() {
				write([]byte{6})
				bytes := ip.As16()
				write(bytes[:])
			} else {
				panic("invalid normalized IP")
			}
		case wire.ValueMAC:
			bytes := field.Value.MAC()
			write(bytes[:])
		default:
			panic("invalid normalized value kind")
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func TestNormalizeIPv6AndOptionalAbsence(t *testing.T) {
	logs := testpdata.CanonicalIPv6Logs()
	got, err := normalizeTestRecord(logs)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got.Family() != wire.FamilyIPv6 {
		t.Fatalf("family = %v, want ipv6", got.Family())
	}
	got, err = normalizeTestRecord(testpdata.CanonicalLogsWithoutOptional())
	if err != nil {
		t.Fatalf("optional absence rejected: %v", err)
	}
	if got.Len() != 39 {
		t.Fatalf("optional absence length = %d, want 39", got.Len())
	}
	if _, ok := got.Lookup(wire.FieldFlowNextHop); ok {
		t.Fatal("absent next hop copied")
	}
}

func TestNormalizeDoesNotRetainOrMutatePdata(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	got, err := normalizeTestRecord(logs)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	attrs := record.Attributes()
	attrs.PutStr("source.address", "192.0.2.99")
	attrs.PutStr("network.transport", "udp")
	attrs.PutStr("flow.src_mac", "ff:ff:ff:ff:ff:ff")
	if value, _ := got.Lookup(wire.FieldSourceAddress); value.IP().String() != "192.0.2.1" {
		t.Fatalf("normalized address changed after pdata mutation: %s", value.IP())
	}
	if value, _ := got.Lookup(wire.FieldNetworkTransport); value.Text() != "tcp" {
		t.Fatalf("normalized transport changed after pdata mutation: %q", value.Text())
	}
	if value, _ := got.Lookup(wire.FieldFlowSrcMAC); value.MAC() != [6]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("normalized MAC changed after pdata mutation: %v", value.MAC())
	}
	values := got.Values()
	values[0].Value = wire.StringValue("tampered")
	if value, _ := got.Lookup(wire.FieldSourceAddress); value.IP().String() != "192.0.2.1" {
		t.Fatalf("public value slice bypassed immutable record: %s", value.IP())
	}
}

func TestNormalizeConcurrentCalls(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	const workers = 8
	results := make([]string, workers)
	errorsByWorker := make([]error, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer wait.Done()
			record, err := normalizeTestRecord(logs)
			if err != nil {
				errorsByWorker[index] = err
				return
			}
			results[index] = normalizedRecordFingerprint(record)
		}()
	}
	wait.Wait()
	const want = "cfb800c180267b161d4b075d1b2f9bdc264d287b14fa9a42225a26d90aa48bcc"
	for index := range results {
		if errorsByWorker[index] != nil || results[index] != want {
			t.Fatalf("worker %d result = (%v,%s), want (%v,%s)", index, errorsByWorker[index], results[index], nil, want)
		}
	}
}

func TestNormalizeZeroAndNoFallbacks(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := record.Attributes()
	attrs.PutStr("source.address", "0.0.0.0")
	attrs.PutStr("destination.address", "0.0.0.0")
	attrs.PutStr("flow.sampler_address", "0.0.0.0")
	attrs.PutStr("flow.next_hop", "0.0.0.0")
	attrs.PutStr("flow.bgp_next_hop", "0.0.0.0")
	attrs.PutStr("flow.src_mac", "00:00:00:00:00:00")
	attrs.PutStr("flow.dst_mac", "00:00:00:00:00:00")
	for _, key := range []string{"source.port", "destination.port", "flow.io.bytes", "flow.io.packets", "flow.sequence_num", "flow.time_received", "flow.start", "flow.end", "flow.sampling_rate", "flow.tcp_flags", "flow.in_if", "flow.out_if", "flow.ip_tos", "flow.ip_ttl", "flow.ip_flags", "flow.fragment_id", "flow.fragment_offset", "flow.ipv6_flow_label", "flow.icmp_type", "flow.icmp_code", "flow.src_vlan", "flow.dst_vlan", "flow.vlan_id", "flow.next_hop_as", "flow.src_as", "flow.dst_as", "flow.src_net", "flow.dst_net", "flow.forwarding_status", "flow.observation_domain_id", "flow.observation_point_id"} {
		attrs.PutInt(key, 0)
	}
	attrs.PutStr("network.transport", "unknown")
	attrs.PutStr("network.type", "unknown")
	attrs.PutStr("flow.type", "unknown")
	got, err := normalizeTestRecord(logs)
	if err != nil {
		t.Fatalf("explicit zero values rejected: %v", err)
	}
	if value, ok := got.Lookup(wire.FieldFlowIOBytes); !ok || value.Kind() != wire.ValueUint || value.Uint() != 0 {
		t.Fatalf("zero bytes = (%v,%v)", value, ok)
	}
	if _, ok := got.Lookup(wire.FieldFlowStart); !ok {
		t.Fatal("zero timestamp was omitted")
	}

	attrs.Remove("flow.start")
	record.SetTimestamp(pcommon.Timestamp(1788220801000000000))
	if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrMissingRequired) {
		t.Fatalf("timestamp fallback error = %v, want missing-required", err)
	}
}

func TestNormalizeRejectsTypeAddressBodyAndProvenanceFallback(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(plog.LogRecord)
		want   error
	}{
		{name: "wrong-type", mutate: func(record plog.LogRecord) { value, _ := record.Attributes().Get("source.port"); value.SetStr("123") }, want: ErrInvalidType},
		{name: "noncanonical-address", mutate: func(record plog.LogRecord) { record.Attributes().PutStr("source.address", "192.000.2.1") }, want: ErrInvalidValue},
		{name: "formatted-body", mutate: func(record plog.LogRecord) { record.Body().SetStr("ProtoProducerMessage{secret}") }, want: ErrUnsupportedBody},
		{name: "resource-fallback", mutate: func(record plog.LogRecord) { record.Attributes().Remove("source.address") }, want: ErrMissingRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			if tc.name == "resource-fallback" {
				logs.ResourceLogs().At(0).Resource().Attributes().PutStr("source.address", "192.0.2.1")
			}
			tc.mutate(record)
			if _, err := normalizeTestRecord(logs); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNormalizeEachIgnoresUnselectedMetadata(t *testing.T) {
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	record.Attributes().PutStr("unselected", string(make([]byte, 65<<20)))
	var calls int
	err := NormalizeEach(logs, func(wire.NormalizedRecord) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("admitted request rejected: %v", err)
	}
	if calls != 1 {
		t.Fatalf("consumer calls = %d, want 1", calls)
	}
}

func TestNormalizeRejectionCallbackZero(t *testing.T) {
	cases := []struct {
		name string
		logs func() plog.Logs
		want error
	}{
		{name: "missing", logs: func() plog.Logs {
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Remove("source.address")
			return logs
		}, want: ErrMissingRequired},
		{name: "invalid-type", logs: func() plog.Logs {
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("source.port", "123")
			return logs
		}, want: ErrInvalidType},
		{name: "invalid-value", logs: func() plog.Logs {
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("source.port", -1)
			return logs
		}, want: ErrInvalidValue},
		{name: "unsupported-body", logs: func() plog.Logs {
			logs := testpdata.CanonicalLogs()
			logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("raw secret")
			return logs
		}, want: ErrUnsupportedBody},
		{name: "no-records", logs: func() plog.Logs { return emptyLogs(0) }, want: ErrNoRecords},
		{name: "malformed", logs: func() plog.Logs { var logs plog.Logs; return logs }, want: ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := tc.logs()
			calls := 0
			before := wire.NormalizedRecord{}
			err := NormalizeEach(logs, func(record wire.NormalizedRecord) error {
				calls++
				before = record
				return nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if calls != 0 || before.Len() != 0 {
				t.Fatalf("rejected request invoked callback/state = (%d,%d)", calls, before.Len())
			}
			if Reason(err) != Reason(tc.want) {
				t.Fatalf("reason = %q, want %q", Reason(err), Reason(tc.want))
			}
		})
	}
}

func TestNormalizeCallbackPanicPropagates(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("callback panic was recovered")
		}
	}()
	_ = NormalizeEach(testpdata.CanonicalLogs(), func(wire.NormalizedRecord) error {
		panic("consumer panic")
	})
}

func TestNormalizeCallbackErrorReturned(t *testing.T) {
	want := errors.New("consumer error")
	if err := NormalizeEach(testpdata.CanonicalLogs(), func(wire.NormalizedRecord) error {
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("callback error = %v, want %v", err, want)
	}
}

func TestNormalizeMalformedPdataBoundary(t *testing.T) {
	var logs plog.Logs
	if err := NormalizeEach(logs, func(wire.NormalizedRecord) error {
		t.Fatal("consumer called for malformed pdata")
		return nil
	}); !errors.Is(err, ErrMalformed) || Reason(err) != ErrMalformed.Error() {
		t.Fatalf("malformed pdata error = %v, reason = %q", err, Reason(err))
	}
}

func normalizeTestRecord(logs plog.Logs) (wire.NormalizedRecord, error) {
	var result wire.NormalizedRecord
	count := 0
	err := NormalizeEach(logs, func(record wire.NormalizedRecord) error {
		result = record
		count++
		return nil
	})
	if err != nil {
		return wire.NormalizedRecord{}, err
	}
	if count != 1 {
		return wire.NormalizedRecord{}, ErrInvalidInput
	}
	return result, nil
}
