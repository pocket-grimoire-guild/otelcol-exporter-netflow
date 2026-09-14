package netflowexporter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const (
	acceptanceMaxReasons = 16
	acceptanceMaxSeries  = 96
)

var acceptanceMetricAttributes = map[string]map[string]struct{}{
	"admission":       {"exporter": {}, "reason": {}},
	"bytes":           {"exporter": {}, "message_kind": {}, "outcome": {}},
	"data_messages":   {"exporter": {}, "outcome": {}},
	"dns":             {"exporter": {}, "outcome": {}},
	"endpoint_epochs": {"exporter": {}},
	"failures":        {"exporter": {}, "reason": {}},
	"losses":          {"exporter": {}, "loss_class": {}},
	"records":         {"exporter": {}, "outcome": {}},
	"templates":       {"exporter": {}, "message_kind": {}, "outcome": {}},
}

var acceptanceMetricValues = map[string]map[string]map[string]struct{}{
	"admission": {"reason": acceptanceSet("accepted", "busy", "closed", "preflight", "invalid_context")},
	"bytes": {
		"message_kind": acceptanceSet("data", "bootstrap", "refresh"),
		"outcome":      acceptanceSet("confirmed", "ambiguous"),
	},
	"data_messages": {"outcome": acceptanceSet("confirmed", "ambiguous")},
	"dns":           {"outcome": acceptanceSet("succeeded", "failed")},
	"failures":      {"reason": acceptanceSet("busy", "closed", "unavailable", "internal", "candidate", "bootstrap", "refresh")},
	"losses":        {"loss_class": acceptanceSet("exporter", "canonical_source")},
	"records":       {"outcome": acceptanceSet("confirmed", "invalid", "ambiguous", "unsent")},
	"templates": {
		"message_kind": acceptanceSet("bootstrap", "refresh"),
		"outcome":      acceptanceSet("confirmed", "ambiguous"),
	},
}

func acceptanceSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

type acceptanceClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *acceptanceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *acceptanceClock) NewTicker(d time.Duration) *time.Ticker { return time.NewTicker(d) }

func (c *acceptanceClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func acceptanceExporter(t *testing.T, c *Config, id string, reader *sdkmetric.ManualReader, tracer *sdktrace.TracerProvider, logger *zap.Logger, steps ...testtransport.WriteStep) *logsExporter {
	t.Helper()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), id)
	set.Logger = logger
	set.MeterProvider = provider
	set.TracerProvider = tracer
	remote := netip.MustParseAddrPort(c.Endpoint)
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), remote, steps...)
	e, err := newLogsExporter(context.Background(), set, c, testclockForAcceptance(), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e
}

// testclockForAcceptance keeps the helper fixture's packet timestamps stable
// without sharing mutable state with the logger clock.
func testclockForAcceptance() transport.Clock {
	return testclock.New(1788220802000000000, 0)
}

const (
	acceptanceEndpoint  = "203.0.113.77:4739"
	acceptanceSourceIP  = "203.0.113.77"
	acceptanceDestIP    = "198.51.100.77"
	acceptanceSourceMAC = "de:ad:be:ef:ca:fe"
	acceptanceDestMAC   = "de:ad:be:ef:ca:ff"
	acceptanceSecretKey = "telemetry.secret.key"
	acceptanceSecretVal = "telemetry.secret.value"
	acceptanceBody      = "telemetry.body.secret"
	acceptancePayload   = "telemetry.payload.secret"
	acceptanceRawError  = "telemetry.raw.error.secret"
	acceptancePoison    = "endpoint=203.0.113.77 ip6=2001:db8::77 mac=de:ad:be:ef:ca:fe key=telemetry.secret.key value=telemetry.secret.value PEN=424242 template=65535 body=telemetry.body.secret payload=telemetry.payload.secret raw=telemetry.raw.error.secret"
)

func acceptanceCanaryLogs(body string) plog.Logs {
	logs := testpdata.CanonicalLogs()
	resource := logs.ResourceLogs().At(0)
	record := resource.ScopeLogs().At(0).LogRecords().At(0)
	resource.Resource().Attributes().PutStr(acceptanceSecretKey, acceptanceSecretVal)
	attrs := record.Attributes()
	attrs.PutStr("source.address", acceptanceSourceIP)
	attrs.PutStr("destination.address", acceptanceDestIP)
	attrs.PutStr("flow.src_mac", acceptanceSourceMAC)
	attrs.PutStr("flow.dst_mac", acceptanceDestMAC)
	attrs.PutStr(acceptanceSecretKey, acceptanceSecretVal)
	if body != "" {
		record.Body().SetStr(body)
	}
	return logs
}

func acceptanceAssertLocalVocabulary(t *testing.T, metrics map[string]int64) {
	t.Helper()
	if len(metrics) == 0 {
		t.Fatal("no local telemetry was recorded")
	}
	instances := map[string]map[string]struct{}{}
	reasons := map[string]struct{}{}
	for key := range metrics {
		parts := strings.Split(key, "|")
		name := parts[0]
		allowedAttrs, ok := acceptanceMetricAttributes[name]
		if !ok {
			t.Fatalf("unknown local metric %q", name)
		}
		seen := make(map[string]string, len(parts)-1)
		instance := ""
		for _, raw := range parts[1:] {
			pair := strings.SplitN(raw, "=", 2)
			if len(pair) != 2 {
				t.Fatalf("malformed local metric labels %q", key)
			}
			if _, ok := allowedAttrs[pair[0]]; !ok {
				t.Fatalf("unexpected %q attribute %q", name, pair[0])
			}
			if _, exists := seen[pair[0]]; exists {
				t.Fatalf("duplicate %q attribute %q", name, pair[0])
			}
			seen[pair[0]] = pair[1]
			if values, ok := acceptanceMetricValues[name][pair[0]]; ok {
				if _, allowed := values[pair[1]]; !allowed {
					t.Fatalf("unexpected %q value %q=%q", name, pair[0], pair[1])
				}
			}
			if pair[0] == "reason" {
				reasons[pair[1]] = struct{}{}
			}
			if pair[0] == "exporter" {
				instance = pair[1]
			}
		}
		if len(seen) != len(allowedAttrs) || instance == "" {
			t.Fatalf("%q labels=%v, want exactly %v and trusted instance", name, seen, allowedAttrs)
		}
		if instances[instance] == nil {
			instances[instance] = map[string]struct{}{}
		}
		instances[instance][key] = struct{}{}
	}
	if len(reasons) > acceptanceMaxReasons {
		t.Fatalf("fixed reason vocabulary grew to %d", len(reasons))
	}
	for instance, series := range instances {
		if len(series) > acceptanceMaxSeries {
			t.Fatalf("instance %q has %d local series, limit %d", instance, len(series), acceptanceMaxSeries)
		}
	}
}

func acceptanceAssertNoCanary(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		for _, canary := range []string{acceptanceEndpoint, acceptanceSourceIP, acceptanceDestIP, "2001:db8::77", acceptanceSourceMAC, acceptanceDestMAC, acceptanceSecretKey, acceptanceSecretVal, "PEN=424242", "template=65535", acceptanceBody, acceptancePayload, acceptanceRawError} {
			if strings.Contains(value, canary) {
				t.Fatalf("diagnostic contains canary %q: %q", canary, value)
			}
		}
	}
}

func acceptanceAttributeTexts(attrs []attribute.KeyValue) []string {
	result := make([]string, 0, len(attrs)*2)
	for _, attr := range attrs {
		result = append(result, string(attr.Key))
		if attr.Value.Type() == attribute.STRING {
			result = append(result, attr.Value.AsString())
		}
	}
	return result
}

func acceptanceCheckAllMetricsForCanaries(t *testing.T, reader *sdkmetric.ManualReader) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			acceptanceAssertNoCanary(t, metric.Name)
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, point := range sum.DataPoints {
				acceptanceAssertNoCanary(t, acceptanceAttributeTexts(point.Attributes.ToSlice())...)
			}
		}
	}
}

func TestTelemetryAcceptancePublicCanariesAllProtocols(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			recorder := tracetest.NewSpanRecorder()
			tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
			t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
			core, observed := observer.New(zap.DebugLevel)
			logger := zap.New(core)
			c := validConfig(protocol)
			c.Endpoint = acceptanceEndpoint
			steps := append([]testtransport.WriteStep{}, bootstrapSteps(protocol)...)
			steps = append(steps, testtransport.WriteStep{N: packetLength(protocol)}, testtransport.WriteStep{N: 0, Err: errors.New(acceptancePoison)})
			e := acceptanceExporter(t, c, "telemetry-canary", reader, tracerProvider, logger, steps...)
			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			validErr := e.ConsumeLogs(context.Background(), acceptanceCanaryLogs(""))
			failureErr := e.ConsumeLogs(context.Background(), acceptanceCanaryLogs(""))
			invalidErr := e.ConsumeLogs(context.Background(), acceptanceCanaryLogs(acceptanceBody))
			if validErr != nil || !consumererror.IsPermanent(invalidErr) || failureErr == nil {
				t.Fatalf("valid=%v invalid=%v send=%v", validErr, invalidErr, failureErr)
			}
			for _, err := range []error{validErr, invalidErr, failureErr} {
				if err != nil {
					acceptanceAssertNoCanary(t, err.Error())
				}
			}
			if observed.Len() == 0 {
				t.Fatal("helper transport-failure log was not captured")
			}
			for _, entry := range observed.All() {
				acceptanceAssertNoCanary(t, entry.Message)
				for _, field := range entry.Context {
					acceptanceAssertNoCanary(t, field.Key, field.String, fmt.Sprint(field.Interface))
				}
			}
			spans := recorder.Ended()
			if len(spans) != 3 {
				t.Fatalf("helper emitted %d spans, want 3", len(spans))
			}
			for i, span := range spans {
				acceptanceAssertNoCanary(t, span.Name(), span.Status().Description)
				wantStatus := codes.Error
				if i == 0 {
					wantStatus = codes.Unset
				}
				if span.Status().Code != wantStatus {
					t.Fatalf("span %d status=%v, want %v", i, span.Status().Code, wantStatus)
				}
				for _, value := range acceptanceAttributeTexts(span.Attributes()) {
					acceptanceAssertNoCanary(t, value)
				}
				for _, event := range span.Events() {
					acceptanceAssertNoCanary(t, event.Name)
					for _, value := range acceptanceAttributeTexts(event.Attributes) {
						acceptanceAssertNoCanary(t, value)
					}
				}
			}
			metrics := localMetrics(t, reader)
			acceptanceAssertLocalVocabulary(t, metrics)
			requireMetric(t, metrics, "admission", 3, "exporter=netflow/telemetry-canary", "reason=accepted")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/telemetry-canary", "outcome=confirmed")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/telemetry-canary", "outcome=invalid")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/telemetry-canary", "outcome=ambiguous")
			requireMetric(t, metrics, "data_messages", 1, "exporter=netflow/telemetry-canary", "outcome=confirmed")
			requireMetric(t, metrics, "data_messages", 1, "exporter=netflow/telemetry-canary", "outcome=ambiguous")
			requireMetric(t, metrics, "bytes", int64(packetLength(protocol)), "exporter=netflow/telemetry-canary", "message_kind=data", "outcome=confirmed")
			requireMetric(t, metrics, "bytes", int64(packetLength(protocol)), "exporter=netflow/telemetry-canary", "message_kind=data", "outcome=ambiguous")
			if protocol != "netflow_v5" {
				bootstrapBytes := int64(0)
				for _, step := range bootstrapSteps(protocol) {
					bootstrapBytes += int64(step.N)
				}
				requireMetric(t, metrics, "templates", 4, "exporter=netflow/telemetry-canary", "message_kind=bootstrap", "outcome=confirmed")
				requireMetric(t, metrics, "bytes", bootstrapBytes, "exporter=netflow/telemetry-canary", "message_kind=bootstrap", "outcome=confirmed")
			}
			acceptanceCheckAllMetricsForCanaries(t, reader)
		})
	}
}

func TestTelemetryAcceptanceRateLimitClock(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
	clock := &acceptanceClock{now: time.Unix(1788220802, 0)}
	core, observed := observer.New(zap.DebugLevel)
	supplied := zap.New(core, zap.WithClock(clock))
	c := validConfig("netflow_v5")
	c.Endpoint = acceptanceEndpoint
	e := acceptanceExporter(t, c, "telemetry-rate", reader, tracerProvider, supplied, testtransport.WriteStep{N: packetLength("netflow_v5")})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	invalid := acceptanceCanaryLogs(acceptanceBody)
	for range 10000 {
		err := e.ConsumeLogs(context.Background(), invalid)
		if !consumererror.IsPermanent(err) {
			t.Fatalf("repeated invalid request error=%v", err)
		}
		acceptanceAssertNoCanary(t, err.Error())
	}
	if got := observed.Len(); got != 1 {
		t.Fatalf("first sampler window logged %d events, want 1", got)
	}
	clock.Advance(time.Minute)
	if err := e.ConsumeLogs(context.Background(), invalid); !consumererror.IsPermanent(err) {
		t.Fatalf("post-window invalid request error=%v", err)
	}
	if got := observed.Len(); got != 2 {
		t.Fatalf("second sampler window logged %d events, want 2 total", got)
	}
	if err := e.ConsumeLogs(context.Background(), invalid); !consumererror.IsPermanent(err) {
		t.Fatalf("same-window invalid request error=%v", err)
	}
	if got := observed.Len(); got != 2 {
		t.Fatalf("same-window failure was not suppressed: %d events", got)
	}
	// The settings logger remains the caller's unsampled logger. This also
	// verifies that wrapping the core did not mutate the supplied logger.
	supplied.Error("Exporting failed. Rejecting data.")
	supplied.Error("Exporting failed. Rejecting data.")
	if got := observed.Len(); got != 4 {
		t.Fatalf("caller logger was unexpectedly sampled: %d events", got)
	}
	for _, entry := range observed.All() {
		acceptanceAssertNoCanary(t, entry.Message)
		for _, field := range entry.Context {
			acceptanceAssertNoCanary(t, field.Key, field.String, fmt.Sprint(field.Interface))
		}
	}
	acceptanceAssertLocalVocabulary(t, localMetrics(t, reader))
	acceptanceCheckAllMetricsForCanaries(t, reader)
}
