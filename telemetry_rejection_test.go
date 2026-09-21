package netflowexporter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const rejectionOrigin = uint64(1788220800000000000)

type publicTelemetryFixture struct {
	exporter exporter.Logs
	listener *net.UDPConn
	reader   *sdkmetric.ManualReader
	observed *observer.ObservedLogs
}

func newPublicTelemetryFixture(t *testing.T, protocol, name string, configure func(*Config)) publicTelemetryFixture {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	c := validConfig(protocol)
	c.Endpoint = listener.LocalAddr().String()
	if protocol == "netflow_v5" {
		c.UptimeOrigin = ptr(rejectionOrigin)
	}
	if configure != nil {
		configure(c)
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	settings := exportertest.NewNopSettings(NewFactory().Type())
	settings.ID = component.NewIDWithName(NewFactory().Type(), name)
	settings.MeterProvider = provider
	core, observed := observer.New(zap.DebugLevel)
	settings.Logger = zap.New(core)
	createCtx, createCancel := context.WithTimeout(context.Background(), 2*time.Second)
	e, err := NewFactory().CreateLogs(createCtx, settings, c)
	createCancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := boundedShutdown(t, e); err != nil {
			t.Errorf("cleanup shutdown: %v", err)
		}
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = e.Start(startCtx, componenttest.NewNopHost())
	startCancel()
	if err != nil {
		t.Fatal(err)
	}
	return publicTelemetryFixture{exporter: e, listener: listener, reader: reader, observed: observed}
}

func boundedConsume(t *testing.T, e exporter.Logs, logs plog.Logs) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return e.ConsumeLogs(ctx, logs)
}

func boundedPush(t *testing.T, e *logsExporter, logs plog.Logs) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return e.pushLogs(ctx, logs)
}

func boundedShutdown(t *testing.T, e exporter.Logs) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return e.Shutdown(ctx)
}

func rejectionLogs(t *testing.T, mutators ...func(plog.LogRecord)) plog.Logs {
	t.Helper()
	base := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	logs := plog.NewLogs()
	for _, mutate := range mutators {
		record := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		base.CopyTo(record)
		if mutate != nil {
			mutate(record)
		}
	}
	logs.MarkReadOnly()
	return logs
}

func collectMetric(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	metrics := localMetrics(t, reader)
	acceptanceAssertLocalVocabulary(t, metrics)
	for key := range metrics {
		if strings.HasPrefix(key, "rejected_records|") {
			assertRejectedSDKContract(t, reader)
			break
		}
	}
	return metrics
}

func helperSentRecords(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "otelcol_exporter_sent_log_records" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("helper sent metric type=%T", metric.Data)
			}
			for _, point := range sum.DataPoints {
				total += point.Value
			}
		}
	}
	return total
}

func helperFailedRecords(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "otelcol_exporter_send_failed_log_records" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("helper failed metric type=%T", metric.Data)
			}
			for _, point := range sum.DataPoints {
				total += point.Value
			}
		}
	}
	return total
}

func metricDelta(after, before map[string]int64) map[string]int64 {
	delta := make(map[string]int64)
	for key, value := range after {
		delta[key] = value - before[key]
	}
	for key, value := range before {
		if _, ok := after[key]; !ok {
			delta[key] = -value
		}
	}
	return delta
}

func rejectionReasonDelta(metrics map[string]int64, exporterName string) map[string]int64 {
	result := make(map[string]int64)
	for key, value := range metrics {
		parts := strings.Split(key, "|")
		if len(parts) != 3 || parts[0] != "rejected_records" || parts[1] != "exporter="+exporterName {
			continue
		}
		result[strings.TrimPrefix(parts[2], "rejection_reason=")] = value
	}
	return result
}

func assertRejectionDeltaEqualsInvalid(t *testing.T, metrics map[string]int64, exporterName string) {
	t.Helper()
	total := int64(0)
	for _, count := range rejectionReasonDelta(metrics, exporterName) {
		total += count
	}
	invalid := metrics[metricKey("records", "exporter="+exporterName, "outcome=invalid")]
	if total != invalid {
		t.Fatalf("rejected_records=%d records.invalid=%d", total, invalid)
	}
}

func validateRejectedMetricKey(key string) error {
	parts := strings.Split(key, "|")
	if len(parts) != 3 || parts[0] != "rejected_records" {
		return errors.New("rejected_records must have exactly three fields")
	}
	if parts[1] == "" || !strings.HasPrefix(parts[1], "exporter=") || parts[1] == "exporter=" {
		return errors.New("rejected_records exporter identity missing")
	}
	if !strings.HasPrefix(parts[2], "rejection_reason=") || parts[2] == "rejection_reason=" {
		return errors.New("rejection_reason missing")
	}
	if _, ok := acceptanceMetricValues["rejected_records"]["rejection_reason"][strings.TrimPrefix(parts[2], "rejection_reason=")]; !ok {
		return errors.New("unknown rejection_reason")
	}
	return nil
}

func assertRejectedSDKContract(t *testing.T, reader *sdkmetric.ManualReader) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "otelcol_netflow.exporter.rejected_records" {
				continue
			}
			found = true
			if metric.Unit != "{record}" {
				t.Fatalf("rejected_records unit=%q want {record}", metric.Unit)
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok || !sum.IsMonotonic || sum.Temporality != metricdata.CumulativeTemporality {
				t.Fatalf("rejected_records data=%T monotonic=%v temporality=%v", metric.Data, ok && sum.IsMonotonic, sum.Temporality)
			}
			for _, point := range sum.DataPoints {
				attrs := point.Attributes.ToSlice()
				if len(attrs) != 2 {
					t.Fatalf("rejected_records attributes=%v want exporter/rejection_reason", attrs)
				}
				keys := map[string]bool{}
				for _, attr := range attrs {
					if attr.Value.Type() != attribute.STRING {
						t.Fatalf("rejected_records attribute %q type=%v want string", attr.Key, attr.Value.Type())
					}
					keys[string(attr.Key)] = true
				}
				if !keys["exporter"] || !keys["rejection_reason"] {
					t.Fatalf("rejected_records attributes=%v want exporter/rejection_reason", attrs)
				}
			}
		}
	}
	if !found {
		t.Fatal("rejected_records SDK instrument was not captured")
	}
}

func readUDPPackets(t *testing.T, listener *net.UDPConn, want int) [][]byte {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packets := make([][]byte, 0, want)
	for len(packets) < want {
		buffer := make([]byte, 65507)
		n, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("read UDP packet %d/%d: %v", len(packets)+1, want, err)
		}
		packets = append(packets, append([]byte(nil), buffer[:n]...))
	}
	return packets
}

func assertUDPQuiet(t *testing.T, listener *net.UDPConn) {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	_, _, err := listener.ReadFromUDP(buffer[:])
	if err == nil {
		t.Fatal("unexpected UDP retry or extra datagram")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("UDP quiet check = %v, want bounded timeout", err)
	}
}

func TestTelemetryRejectionPublicMixedReasons(t *testing.T) {
	t.Run("netflow_v5", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "netflow_v5", "rejection-v5", nil)
		if err := boundedConsume(t, fixture.exporter, testpdata.CanonicalLogs()); err != nil {
			t.Fatalf("good-only control = %v", err)
		}
		goodPackets := readUDPPackets(t, fixture.listener, 1)
		assertUDPQuiet(t, fixture.listener)
		golden, err := os.ReadFile("integration/testdata/golden/v5/canonical-ipv4-v1.bin")
		if err != nil {
			t.Fatal(err)
		}
		if len(goodPackets[0]) < 24 {
			t.Fatalf("good-only packet length=%d, want at least 24", len(goodPackets[0]))
		}
		if len(golden) < 24 {
			t.Fatalf("golden packet length=%d, want at least 24", len(golden))
		}
		if !bytes.Equal(goodPackets[0][24:], golden[24:]) {
			t.Fatalf("good-only valid bytes changed: got %x want %x", goodPackets[0][24:], golden[24:])
		}
		goodMetrics := collectMetric(t, fixture.reader)
		requireMetric(t, goodMetrics, "records", 1, "exporter=netflow/rejection-v5", "outcome=confirmed")
		if got := helperSentRecords(t, fixture.reader); got != 1 {
			t.Fatalf("good-only helper sent records=%d want 1", got)
		}
		assertRejectionDeltaEqualsInvalid(t, goodMetrics, "netflow/rejection-v5")
		if len(rejectionReasonDelta(goodMetrics, "netflow/rejection-v5")) != 0 {
			t.Fatal("good-only v5 control emitted a rejection point")
		}

		mutators := []func(plog.LogRecord){
			nil,
			func(record plog.LogRecord) {
				record.Body().SetStr("unsupported body")
				record.Attributes().PutStr("flow.io.bytes", "also wrong")
			},
			func(record plog.LogRecord) { record.Attributes().PutStr("flow.io.bytes", "wrong type") },
			func(record plog.LogRecord) { record.Attributes().Remove("flow.io.bytes") },
			func(record plog.LogRecord) { record.Attributes().PutStr("network.transport", "udp") },
			func(record plog.LogRecord) {
				record.Attributes().PutStr("network.type", "ipv6")
				record.Attributes().PutStr("source.address", "2001:db8::1")
				record.Attributes().PutStr("destination.address", "2001:db8::2")
				record.Attributes().PutStr("flow.sampler_address", "2001:db8::fe")
			},
			func(record plog.LogRecord) { record.Attributes().PutInt("flow.start", int64(rejectionOrigin-1)) },
		}
		if err := boundedConsume(t, fixture.exporter, rejectionLogs(t, mutators...)); err != nil {
			t.Fatalf("mixed request = %v", err)
		}
		packets := readUDPPackets(t, fixture.listener, 1)
		assertUDPQuiet(t, fixture.listener)
		if len(packets[0]) < 24 {
			t.Fatalf("mixed packet length=%d, want at least 24", len(packets[0]))
		}
		if !bytes.Equal(packets[0][24:], golden[24:]) {
			t.Fatalf("valid sibling wire bytes changed: got %x want %x", packets[0][24:], golden[24:])
		}
		metrics := collectMetric(t, fixture.reader)
		delta := metricDelta(metrics, goodMetrics)
		if delta[metricKey("records", "exporter=netflow/rejection-v5", "outcome=confirmed")] != 1 || delta[metricKey("records", "exporter=netflow/rejection-v5", "outcome=invalid")] != 6 {
			t.Fatalf("mixed records delta=%v", delta)
		}
		want := map[string]int64{
			"unsupported_body": 1,
			"invalid_type":     1,
			"missing_field":    1,
			"map_miss":         1,
			"family_mismatch":  1,
			"time_invalid":     1,
		}
		got := rejectionReasonDelta(delta, "netflow/rejection-v5")
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("rejection reasons=%v want %v", got, want)
		}
		assertRejectionDeltaEqualsInvalid(t, delta, "netflow/rejection-v5")
		if got := helperSentRecords(t, fixture.reader); got != 8 {
			t.Fatalf("helper sent records=%d want 8 after control and mixed request", got)
		}
		before := metrics
		if err := boundedConsume(t, fixture.exporter, testpdata.CanonicalLogs()); err != nil {
			t.Fatal(err)
		}
		readUDPPackets(t, fixture.listener, 1)
		assertUDPQuiet(t, fixture.listener)
		nextDelta := metricDelta(collectMetric(t, fixture.reader), before)
		for key, value := range nextDelta {
			if strings.HasPrefix(key, "rejected_records|") && value != 0 {
				t.Fatalf("valid-only request emitted rejected-record delta %s=%d", key, value)
			}
		}
		if nextDelta[metricKey("records", "exporter=netflow/rejection-v5", "outcome=confirmed")] != 1 {
			t.Fatalf("valid-only records delta=%v", nextDelta)
		}
		assertRejectionDeltaEqualsInvalid(t, nextDelta, "netflow/rejection-v5")
		if got := helperSentRecords(t, fixture.reader); got != 9 {
			t.Fatalf("helper sent records=%d want 9 after valid-only request", got)
		}
		if fixture.observed.Len() != 0 {
			t.Fatalf("mixed public flow emitted %d warning/error logs", fixture.observed.Len())
		}
		if err := boundedShutdown(t, fixture.exporter); err != nil {
			t.Fatalf("shutdown = %v", err)
		}
	})

	t.Run("ipfix_custom", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "ipfix", "rejection-ipfix", func(c *Config) {
			c.Mapping.Profile = nil
			c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
			c.Mapping.ProtocolIdentifiers = nil
			c.Mapping.NetworkTypeVersions = nil
			c.Mapping.Custom = []CustomField{{
				Source: "vendor.bytes", PEN: ptr(uint32(32473)), ElementID: ptr(uint32(1)),
				Encoding: "octet_array", Variable: ptr(true), MaxLength: ptr(uint32(3)),
			}}
		})
		if err := boundedConsume(t, fixture.exporter, rejectionLogs(t, func(record plog.LogRecord) {
			bytes := record.Attributes().PutEmptyBytes("vendor.bytes")
			bytes.Append(1, 2, 3)
		})); err != nil {
			t.Fatalf("IPFIX good-only control = %v", err)
		}
		goodPackets := readUDPPackets(t, fixture.listener, 3)
		assertUDPQuiet(t, fixture.listener)
		goodData := goodPackets[len(goodPackets)-1]
		if len(goodData) < 16 {
			t.Fatalf("IPFIX good-only data length=%d, want at least 16", len(goodData))
		}
		goodMetrics := collectMetric(t, fixture.reader)
		requireMetric(t, goodMetrics, "records", 1, "exporter=netflow/rejection-ipfix", "outcome=confirmed")
		assertRejectionDeltaEqualsInvalid(t, goodMetrics, "netflow/rejection-ipfix")
		if len(rejectionReasonDelta(goodMetrics, "netflow/rejection-ipfix")) != 0 {
			t.Fatal("good-only IPFIX control emitted a rejection point")
		}
		if got := helperSentRecords(t, fixture.reader); got != 1 {
			t.Fatalf("IPFIX good-only helper sent records=%d want 1", got)
		}
		mutators := []func(plog.LogRecord){
			func(record plog.LogRecord) {
				bytes := record.Attributes().PutEmptyBytes("vendor.bytes")
				bytes.Append(1, 2, 3)
			},
			func(record plog.LogRecord) {},
			func(record plog.LogRecord) { record.Attributes().PutStr("vendor.bytes", "wrong descriptor value") },
			func(record plog.LogRecord) {
				bytes := record.Attributes().PutEmptyBytes("vendor.bytes")
				bytes.Append(1, 2, 3, 4)
			},
			func(record plog.LogRecord) { record.Attributes().PutBool("vendor.bytes", true) },
			func(record plog.LogRecord) { record.Attributes().PutDouble("vendor.bytes", 1.25) },
			func(record plog.LogRecord) { record.Attributes().PutEmptyMap("vendor.bytes") },
			func(record plog.LogRecord) { record.Attributes().PutEmptySlice("vendor.bytes") },
			func(record plog.LogRecord) { record.Attributes().PutEmpty("vendor.bytes") },
		}
		if err := boundedConsume(t, fixture.exporter, rejectionLogs(t, mutators...)); err != nil {
			t.Fatalf("IPFIX custom mixed request = %v", err)
		}
		packets := readUDPPackets(t, fixture.listener, 1)
		assertUDPQuiet(t, fixture.listener)
		for _, packet := range packets {
			if len(packet) < 16 || packet[0] != 0 || packet[1] != 10 {
				t.Fatalf("unexpected IPFIX packet header: %x", packet)
			}
		}
		metrics := collectMetric(t, fixture.reader)
		delta := metricDelta(metrics, goodMetrics)
		if delta[metricKey("records", "exporter=netflow/rejection-ipfix", "outcome=confirmed")] != 1 || delta[metricKey("records", "exporter=netflow/rejection-ipfix", "outcome=invalid")] != 8 {
			t.Fatalf("IPFIX mixed records delta=%v", delta)
		}
		for reason, want := range map[string]int64{"custom_unavailable": 6, "custom_invalid": 1, "record_too_large": 1} {
			if got := delta[metricKey("rejected_records", "exporter=netflow/rejection-ipfix", "rejection_reason="+reason)]; got != want {
				t.Fatalf("IPFIX %s delta=%d want %d", reason, got, want)
			}
		}
		assertRejectionDeltaEqualsInvalid(t, delta, "netflow/rejection-ipfix")
		if !bytes.Equal(packets[0][16:], goodData[16:]) {
			t.Fatalf("IPFIX valid payload changed: got %x want %x", packets[0][16:], goodData[16:])
		}
		if got := helperSentRecords(t, fixture.reader); got != 10 {
			t.Fatalf("IPFIX helper sent records=%d want 10 after control and mixed request", got)
		}
		before := metrics
		if err := boundedConsume(t, fixture.exporter, rejectionLogs(t, func(record plog.LogRecord) {
			bytes := record.Attributes().PutEmptyBytes("vendor.bytes")
			bytes.Append(1, 2, 3)
		})); err != nil {
			t.Fatalf("IPFIX valid-only request = %v", err)
		}
		readUDPPackets(t, fixture.listener, 1)
		assertUDPQuiet(t, fixture.listener)
		nextDelta := metricDelta(collectMetric(t, fixture.reader), before)
		if nextDelta[metricKey("records", "exporter=netflow/rejection-ipfix", "outcome=confirmed")] != 1 {
			t.Fatalf("IPFIX valid-only records delta=%v", nextDelta)
		}
		assertRejectionDeltaEqualsInvalid(t, nextDelta, "netflow/rejection-ipfix")
		for key, value := range nextDelta {
			if strings.HasPrefix(key, "rejected_records|") && value != 0 {
				t.Fatalf("IPFIX valid-only rejected-record delta %s=%d", key, value)
			}
		}
		if got := helperSentRecords(t, fixture.reader); got != 11 {
			t.Fatalf("IPFIX helper sent records=%d want 11 after valid-only request", got)
		}
		if fixture.observed.Len() != 0 {
			t.Fatalf("IPFIX mixed public flow emitted %d warning/error logs", fixture.observed.Len())
		}
		if err := boundedShutdown(t, fixture.exporter); err != nil {
			t.Fatalf("IPFIX shutdown = %v", err)
		}
	})
}

func TestTelemetryRejectionAllInvalidAndPartialFailure(t *testing.T) {
	t.Run("all_invalid_public", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "netflow_v5", "rejection-all-invalid", nil)
		invalid := rejectionLogs(t, func(record plog.LogRecord) { record.Body().SetStr("all invalid") })
		err := boundedConsume(t, fixture.exporter, invalid)
		if !consumererror.IsPermanent(err) {
			t.Fatalf("all-invalid error=%v", err)
		}
		assertUDPQuiet(t, fixture.listener)
		metrics := collectMetric(t, fixture.reader)
		requireMetric(t, metrics, "records", 1, "exporter=netflow/rejection-all-invalid", "outcome=invalid")
		requireMetric(t, metrics, "rejected_records", 1, "exporter=netflow/rejection-all-invalid", "rejection_reason=unsupported_body")
		assertRejectionDeltaEqualsInvalid(t, metrics, "netflow/rejection-all-invalid")
		if got := helperSentRecords(t, fixture.reader); got != 0 {
			t.Fatalf("all-invalid helper sent records=%d want 0", got)
		}
		if got := helperFailedRecords(t, fixture.reader); got != 1 {
			t.Fatalf("all-invalid helper failed records=%d want 1", got)
		}
		if fixture.observed.Len() == 0 {
			t.Fatal("all-invalid helper error log was not captured")
		}
		if err := boundedShutdown(t, fixture.exporter); err != nil {
			t.Fatalf("all-invalid shutdown = %v", err)
		}
	})

	t.Run("write_variants_and_suffix", func(t *testing.T) {
		tests := []struct {
			name       string
			writeN     func(int) int
			writeErr   error
			wantWrites int
			wantOK     bool
		}{
			{name: "full-nil", writeN: func(length int) int { return length }, wantWrites: 4, wantOK: true},
			{name: "zero-nil", writeN: func(int) int { return 0 }, wantWrites: 2},
			{name: "zero-error", writeN: func(int) int { return 0 }, writeErr: errors.New("zero write error"), wantWrites: 2},
			{name: "short-nil", writeN: func(length int) int { return length - 1 }, wantWrites: 2},
			{name: "short-error", writeN: func(length int) int { return length - 1 }, writeErr: errors.New("short write"), wantWrites: 2},
			{name: "full-error", writeN: func(length int) int { return length }, writeErr: errors.New("full write error"), wantWrites: 2},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				c := validConfig("netflow_v5")
				c.MaxRecordsPerMessage = ptr(uint16(1))
				reader := sdkmetric.NewManualReader()
				provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
				t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
				settings := exportertest.NewNopSettings(NewFactory().Type())
				settings.ID = component.NewIDWithName(NewFactory().Type(), "write-variant-"+test.name)
				settings.MeterProvider = provider
				steps := []testtransport.WriteStep{{N: 72}, {N: test.writeN(72), Err: test.writeErr}}
				if test.wantOK {
					steps = append(steps, testtransport.WriteStep{N: 72}, testtransport.WriteStep{N: 72})
				}
				conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint), steps...)
				e, err := newLogsExporter(context.Background(), settings, c, testclock.New(rejectionOrigin+2_000_000_000, 0), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
				startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Second)
				err = e.Start(startCtx, componenttest.NewNopHost())
				startCancel()
				if err != nil {
					t.Fatal(err)
				}
				resultErr := boundedConsume(t, e, mixedLogs())
				if test.wantOK {
					if resultErr != nil {
						t.Fatalf("full write error=%v", resultErr)
					}
				} else if resultErr == nil || consumererror.IsPermanent(resultErr) {
					t.Fatalf("partial error=%v", resultErr)
				}
				if got := len(conn.Writes()); got != test.wantWrites {
					t.Fatalf("writes=%d want %d", got, test.wantWrites)
				}
				metrics := collectMetric(t, reader)
				id := "netflow/write-variant-" + test.name
				if test.wantOK {
					requireMetric(t, metrics, "records", 4, "exporter="+id, "outcome=confirmed")
					requireMetric(t, metrics, "records", 2, "exporter="+id, "outcome=invalid")
					if got := helperFailedRecords(t, reader); got != 0 {
						t.Fatalf("successful helper failed records=%d", got)
					}
					if got := helperSentRecords(t, reader); got != 6 {
						t.Fatalf("successful helper sent records=%d want 6", got)
					}
				} else {
					subset, ok := errors.AsType[consumererror.Logs](resultErr)
					if !ok {
						t.Fatalf("partial result type=%T", resultErr)
					}
					assertReturnedRejectionSubset(t, subset.Data())
					requireMetric(t, metrics, "records", 1, "exporter="+id, "outcome=confirmed")
					requireMetric(t, metrics, "records", 2, "exporter="+id, "outcome=invalid")
					requireMetric(t, metrics, "records", 1, "exporter="+id, "outcome=ambiguous")
					requireMetric(t, metrics, "records", 2, "exporter="+id, "outcome=unsent")
					if got := helperFailedRecords(t, reader); got != 6 {
						t.Fatalf("partial helper failed records=%d want 6", got)
					}
					if got := helperSentRecords(t, reader); got != 0 {
						t.Fatalf("partial helper sent records=%d want 0", got)
					}
				}
				requireMetric(t, metrics, "rejected_records", 2, "exporter="+id, "rejection_reason=unsupported_body")
				assertRejectionDeltaEqualsInvalid(t, metrics, id)
				if err := boundedShutdown(t, e); err != nil {
					t.Fatalf("shutdown = %v", err)
				}
			})
		}
	})
}

func assertReturnedRejectionSubset(t *testing.T, logs plog.Logs) {
	t.Helper()
	if logs.LogRecordCount() != 3 || logs.ResourceLogs().Len() != 2 {
		t.Fatalf("subset records/resources=%d/%d, want 3/2", logs.LogRecordCount(), logs.ResourceLogs().Len())
	}
	wantResources := []struct {
		resource int64
		scopes   [][]int64
	}{{resource: 1, scopes: [][]int64{{2}}}, {resource: 2, scopes: [][]int64{{4}, {5}}}}
	for index, want := range wantResources {
		resource := logs.ResourceLogs().At(index)
		if resource.SchemaUrl() != "resource-schema" {
			t.Fatal("returned resource schema changed")
		}
		value, ok := resource.Resource().Attributes().Get("resource")
		if !ok || value.Int() != want.resource {
			t.Fatalf("subset resource %d grouping/identity invalid: present=%v value=%v scopes=%d", index, ok, value, resource.ScopeLogs().Len())
		}
		if resource.ScopeLogs().Len() != len(want.scopes) {
			t.Fatalf("subset resource %d scopes=%d want %d", index, resource.ScopeLogs().Len(), len(want.scopes))
		}
		for scopeIndex, wantRecords := range want.scopes {
			scope := resource.ScopeLogs().At(scopeIndex)
			if scope.SchemaUrl() != "scope-schema" || scope.Scope().Name() != "scope" || scope.Scope().Version() != "version" {
				t.Fatal("returned scope identity changed")
			}
			records := scope.LogRecords()
			if records.Len() != len(wantRecords) {
				t.Fatalf("subset resource %d scope %d records=%d want %d", index, scopeIndex, records.Len(), len(wantRecords))
			}
			for recordIndex, ordinal := range wantRecords {
				value, ok := records.At(recordIndex).Attributes().Get("ordinal")
				if !ok || value.Int() != ordinal {
					t.Fatalf("subset ordinal[%d,%d,%d]=%v want %d", index, scopeIndex, recordIndex, value, ordinal)
				}
			}
		}
	}
}

func TestTelemetryRejectionRefreshFailureWithInvalidSuffix(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	refreshFailed := make(chan struct{})
	var refreshOnce sync.Once
	steps := conditionalFullSteps("netflow_v9")
	steps = append(steps,
		testtransport.WriteStep{N: 1, Err: errors.New("refresh handoff failure")},
		testtransport.WriteStep{N: packetLength("netflow_v9")},
	)
	e, fixture := conditionalExporterWithHook(t, provider, "netflow_v9", "refresh-invalid-suffix", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: steps}}, func(event destination.Event) {
		if event == destination.RefreshFailed {
			refreshOnce.Do(func() { close(refreshFailed) })
		}
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := e.Start(startCtx, componenttest.NewNopHost()); err != nil {
		startCancel()
		t.Fatal(err)
	}
	startCancel()
	waitConditionalTimer(t, fixture.timers[0])
	fixture.clock.Advance(0, uint64(30*time.Second))
	if !fixture.timers[0].Fire() {
		t.Fatal("refresh timer did not fire")
	}
	waitConditionalDone(t, refreshFailed)
	logs := rejectionLogs(t,
		func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 0) },
		func(record plog.LogRecord) {
			record.Attributes().PutInt("ordinal", 1)
			record.Body().SetStr("invalid suffix")
		},
	)
	err := boundedConsume(t, e, logs)
	subset, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) {
		t.Fatalf("refresh failure must return a transient subset: %v", err)
	}
	returned := subset.Data()
	if returned.LogRecordCount() != 1 || returned.ResourceLogs().Len() != 1 || returned.ResourceLogs().At(0).ScopeLogs().Len() != 1 {
		t.Fatal("refresh failure subset lost grouping or retained an invalid source")
	}
	ordinal, ok := returned.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("ordinal")
	if !ok || ordinal.Int() != 0 {
		t.Fatal("refresh failure subset did not retain only the valid-unsent ordinal")
	}
	metrics := collectMetric(t, reader)
	id := "netflow/refresh-invalid-suffix"
	requireMetric(t, metrics, "records", 1, "exporter="+id, "outcome=invalid")
	requireMetric(t, metrics, "records", 1, "exporter="+id, "outcome=unsent")
	requireMetric(t, metrics, "rejected_records", 1, "exporter="+id, "rejection_reason=unsupported_body")
	assertRejectionDeltaEqualsInvalid(t, metrics, id)
	if got := helperSentRecords(t, reader); got != 0 {
		t.Fatalf("refresh failure helper sent records=%d want 0", got)
	}
	if got := helperFailedRecords(t, reader); got != 2 {
		t.Fatalf("refresh failure helper failed records=%d want 2", got)
	}
	if got := len(fixture.dialer.conns[0].Writes()); got != len(steps) {
		t.Fatalf("refresh failure writes=%d want %d, retry occurred", got, len(steps))
	}
	if err := boundedShutdown(t, e); err != nil {
		t.Fatalf("refresh failure shutdown = %v", err)
	}
}

func TestTelemetryRejectionIPFIXEmptyPacketFit(t *testing.T) {
	// The mapping is compiled with the normal maximum while the destination
	// state receives a smaller wire budget. This trusted private seam reaches
	// the empty-packet fit branch after mapping succeeds; public config
	// validation rejects the same inconsistent budgets earlier.
	variable, maxLength := true, uint32(256)
	pen, elementID := uint32(32473), uint32(101)
	compiled, err := mapping.Compile(mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507, PathMTU: 65535, Endpoint: "192.0.2.1:4739",
		Custom: []mapping.CustomField{{Source: "vendor.oversized", PEN: &pen, ElementID: &elementID, Encoding: "string", Variable: &variable, MaxLength: &maxLength}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stateConfig := destination.DefaultConfig(wire.ProtocolIPFIX)
	stateConfig.ObservationDomainID = 42
	stateConfig.MaxDatagramSize = 128
	state, err := destination.NewState(compiled, ipfix.NewWriter(), stateConfig)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < int(state.Config().InitialCopies); round++ {
		for shape := 0; shape < state.Catalog().ShapeCount(); shape++ {
			packet, beginErr := state.BeginTemplate(rejectionOrigin, uint64(round+1), shape)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			buffer := make([]byte, 128)
			n, encodeErr := packet.Encode(buffer)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			commit, commitErr := state.Commit(packet, n, nil)
			if commitErr != nil || !commit.Committed {
				t.Fatalf("template commit=%+v err=%v", commit, commitErr)
			}
		}
	}
	packer, err := destination.NewPacker(state, destination.PackerConfig{
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("empty-packet fit rejection reached UDP handoff")
			return 0, nil
		},
		Clock: func() (uint64, uint64) { return rejectionOrigin, 10 },
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := testpdata.CanonicalLogs()
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutStr("vendor.oversized", strings.Repeat("x", 123))
	result, err := packer.Pack(context.Background(), logs, func(_ uint64, key string) (wire.Value, bool) {
		if key != "vendor.oversized" {
			return wire.Value{}, false
		}
		return wire.StringValue(strings.Repeat("x", 123)), true
	})
	if !errors.Is(err, destination.ErrPackPermanent) || result == nil || result.Counts().Invalid != 1 || result.RejectionCounts()[destination.RejectionRecordTooLarge] != 1 {
		t.Fatalf("empty-packet fit result=(%v,%v,%+v)", result, err, result.Counts())
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	settings := exportertest.NewNopSettings(NewFactory().Type())
	settings.MeterProvider = provider
	builder, err := metadata.NewTelemetryBuilder(settings.TelemetrySettings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(builder.Shutdown)
	telemetry{builder: builder, instance: attribute.String("exporter", "netflow/ipfix-empty-fit")}.record(context.Background(), result)
	metrics := collectMetric(t, reader)
	requireMetric(t, metrics, "records", 1, "exporter=netflow/ipfix-empty-fit", "outcome=invalid")
	requireMetric(t, metrics, "rejected_records", 1, "exporter=netflow/ipfix-empty-fit", "rejection_reason=record_too_large")
	assertRejectionDeltaEqualsInvalid(t, metrics, "netflow/ipfix-empty-fit")
}

func TestTelemetryRejectionVocabularyAndRedaction(t *testing.T) {
	wantLabels := []string{
		"other", "unsupported_body", "missing_field", "invalid_type", "invalid_value",
		"map_miss", "family_mismatch", "protocol_mismatch", "time_invalid",
		"custom_unavailable", "custom_invalid", "record_too_large", "record_invalid",
	}
	labels := make([]string, 0, destination.RejectionReasonCount)
	for i := 0; i < destination.RejectionReasonCount; i++ {
		labels = append(labels, destination.RejectionReason(i).Label())
	}
	if !reflect.DeepEqual(labels, wantLabels) {
		t.Fatalf("closed rejection vocabulary=%v want %v", labels, wantLabels)
	}
	if len(acceptanceMetricValues["rejected_records"]["rejection_reason"]) != len(wantLabels) {
		t.Fatal("acceptance vocabulary does not contain exactly thirteen labels")
	}
	for _, invalid := range []string{
		"rejected_records|exporter=netflow/test",
		"rejected_records|exporter=netflow/test|rejection_reason=unknown",
		"rejected_records|exporter=netflow/test|rejection_reason=",
	} {
		if err := validateRejectedMetricKey(invalid); err == nil {
			t.Fatalf("invalid rejection metric key accepted: %q", invalid)
		}
	}
	operationReasons := acceptanceSet("accepted", "busy", "closed", "preflight", "invalid_context", "unavailable", "internal", "candidate", "bootstrap", "refresh")
	if len(operationReasons) != acceptanceMaxReasons {
		t.Fatalf("operation/admission vocabulary=%d want %d", len(operationReasons), acceptanceMaxReasons)
	}
	if got := destination.RejectionReason(255).Label(); got != "other" {
		t.Fatalf("unknown rejection reason=%q", got)
	}
	if got := destination.RejectionReason(0).Label(); got != "other" {
		t.Fatalf("zero rejection reason=%q", got)
	}

	reader := sdkmetric.NewManualReader()
	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	c := validConfig("netflow_v5")
	c.Endpoint = "203.0.113.77:4739"
	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
	e := acceptanceExporter(t, c, "rejection-redaction", reader, tracerProvider, logger, testtransport.WriteStep{N: packetLength("netflow_v5")})
	startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := e.Start(startCtx, componenttest.NewNopHost()); err != nil {
		startCancel()
		t.Fatal(err)
	}
	startCancel()
	canary := "body=raw.secret key=custom.secret value=address.secret endpoint=203.0.113.77 wrapper=" + acceptanceWrapper
	invalid := acceptanceCanaryLogs(canary)
	if err := boundedPush(t, e, invalid); !consumererror.IsPermanent(err) {
		t.Fatalf("redaction rejection=%v", err)
	}
	metrics := collectMetric(t, reader)
	assertRejectedSDKContract(t, reader)
	acceptanceAssertLocalVocabulary(t, metrics)
	requireMetric(t, metrics, "rejected_records", 1, "exporter=netflow/rejection-redaction", "rejection_reason=unsupported_body")
	assertRejectionDeltaEqualsInvalid(t, metrics, "netflow/rejection-redaction")
	if next := collectMetric(t, reader); !reflect.DeepEqual(next, metrics) {
		t.Fatalf("rejected_records is not cumulative: first=%v second=%v", metrics, next)
	}
	acceptanceCheckAllMetricsForCanaries(t, reader)
	if observed.Len() != 0 {
		t.Fatalf("telemetry rejection emitted %d warning/error logs", observed.Len())
	}
	if err := boundedShutdown(t, e); err != nil {
		t.Fatalf("redaction shutdown = %v", err)
	}
}
