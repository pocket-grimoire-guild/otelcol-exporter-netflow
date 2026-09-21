package netflowexporter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func telemetryExporter(t *testing.T, c *Config, reader *sdkmetric.ManualReader, name string, steps ...testtransport.WriteStep) *logsExporter {
	t.Helper()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), name)
	set.MeterProvider = provider
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint), steps...)
	e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e
}
func metricKey(name string, labels ...string) string {
	sort.Strings(labels)
	return name + "|" + strings.Join(labels, "|")
}
func localMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	result := map[string]int64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			const prefix = "otelcol_netflow.exporter."
			if !strings.HasPrefix(m.Name, prefix) {
				continue
			}
			var points []metricdata.DataPoint[int64]
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if !data.IsMonotonic {
					t.Fatalf("non-counter %s", m.Name)
				}
				points = data.DataPoints
			case metricdata.Gauge[int64]:
				if m.Name != "otelcol_netflow.exporter.uptime_exhausted" || m.Unit != "1" {
					t.Fatalf("unexpected int gauge %s unit=%q", m.Name, m.Unit)
				}
				for _, dp := range data.DataPoints {
					if dp.Value != 0 && dp.Value != 1 {
						t.Fatalf("invalid exhausted gauge value=%d", dp.Value)
					}
				}
				continue
			case metricdata.Gauge[float64]:
				if m.Name != "otelcol_netflow.exporter.uptime_remaining" || m.Unit != "s" {
					t.Fatalf("unexpected float gauge %s unit=%q", m.Name, m.Unit)
				}
				for _, dp := range data.DataPoints {
					if math.IsNaN(dp.Value) || math.IsInf(dp.Value, 0) || dp.Value < 0 {
						t.Fatalf("invalid remaining gauge value=%v", dp.Value)
					}
				}
				continue
			default:
				t.Fatalf("unknown local metric %s type=%T", m.Name, m.Data)
			}
			for _, dp := range points {
				var labels []string
				for _, a := range dp.Attributes.ToSlice() {
					labels = append(labels, string(a.Key)+"="+a.Value.AsString())
				}
				result[metricKey(strings.TrimPrefix(m.Name, prefix), labels...)] += dp.Value
			}
		}
	}
	return result
}
func requireMetric(t *testing.T, metrics map[string]int64, name string, want int64, labels ...string) {
	t.Helper()
	key := metricKey(name, labels...)
	if metrics[key] != want {
		t.Fatalf("%s=%d, want %d; metrics=%v", key, metrics[key], want, metrics)
	}
}
func TestTelemetry(t *testing.T) {
	t.Run("admission", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		e := telemetryExporter(t, validConfig("netflow_v5"), reader, "admission", testtransport.WriteStep{N: 72})
		helper := &countHelper{Logs: e.helper}
		e.helper = helper
		// Rejections must not traverse even malformed pdata or enter the helper.
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- e.runtime.Consume(context.Background(), func(context.Context) error { close(entered); <-release; return nil })
		}()
		<-entered
		err := e.ConsumeLogs(context.Background(), plog.Logs{})
		close(release)
		<-done
		if !errors.Is(err, destination.ErrRuntimeBusy) {
			t.Fatal(err)
		}
		if err = e.ConsumeLogs(nil, plog.Logs{}); !errors.Is(err, transport.ErrInvalidContext) {
			t.Fatal(err)
		}
		if err = e.ConsumeLogs(context.Background(), plog.Logs{}); !consumererror.IsPermanent(err) {
			t.Fatal(err)
		}
		if helper.consumes.Load() != 0 {
			t.Fatal("rejected request entered helper")
		}
		// An admitted pre-Start request fails availability separately from admission.
		if err = e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); !errors.Is(err, destination.ErrRuntimeUnavailable) {
			t.Fatal(err)
		}
		if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		if err = e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
			t.Fatal(err)
		}
		if err = e.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err = e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeClosed) {
			t.Fatal(err)
		}
		metrics := localMetrics(t, reader)
		for reason, want := range map[string]int64{"accepted": 2, "preflight": 1, "busy": 1, "invalid_context": 1, "closed": 1} {
			requireMetric(t, metrics, "admission", want, "exporter=netflow/admission", "reason="+reason)
		}
		requireMetric(t, metrics, "failures", 1, "exporter=netflow/admission", "reason=unavailable")
		requireMetric(t, metrics, "endpoint_epochs", 1, "exporter=netflow/admission")
		if helper.consumes.Load() != 2 {
			t.Fatal("helper accounting included admission failures")
		}
	})
	t.Run("handoffs", func(t *testing.T) {
		for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
			size := packetLength(protocol)
			for _, failure := range []struct {
				name string
				n    int
				err  error
			}{
				{"full", size, nil}, {"short", 1, nil}, {"zero", 0, nil}, {"short_error", 1, errors.New("secret")},
				{"zero_error", 0, errors.New("secret")}, {"full_error", size, errors.New("secret")}, {"invalid", size + 1, nil},
			} {
				t.Run(fmt.Sprintf("%s/%s", protocol, failure.name), func(t *testing.T) {
					reader := sdkmetric.NewManualReader()
					steps := append(bootstrapSteps(protocol), testtransport.WriteStep{N: failure.n, Err: failure.err})
					e := telemetryExporter(t, validConfig(protocol), reader, "packets", steps...)
					if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
						t.Fatal(err)
					}
					err := e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs())
					if (err == nil) != (failure.name == "full") {
						t.Fatal(err)
					}
					metrics := localMetrics(t, reader)
					outcome := "ambiguous"
					if failure.name == "full" {
						outcome = "confirmed"
					}
					want := int64(size)
					if failure.name == "invalid" {
						want = 0
					}
					requireMetric(t, metrics, "bytes", want, "exporter=netflow/packets", "message_kind=data", "outcome="+outcome)
					messages := int64(1)
					if failure.name == "invalid" {
						messages = 0
					}
					requireMetric(t, metrics, "data_messages", messages, "exporter=netflow/packets", "outcome="+outcome)
					if protocol != "netflow_v5" {
						requireMetric(t, metrics, "templates", 4, "exporter=netflow/packets", "message_kind=bootstrap", "outcome=confirmed")
						requireMetric(t, metrics, "bytes", int64(4*steps[0].N), "exporter=netflow/packets", "message_kind=bootstrap", "outcome=confirmed")
					}
					for key := range metrics {
						if strings.HasPrefix(key, "dns|") {
							t.Fatal("literal endpoint counted as DNS")
						}
					}
				})
			}
		}
	})
}

func TestRate(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	c := validConfig("ipfix")
	c.MaxRecordsPerMessage = ptr(uint16(1))
	e := telemetryExporter(t, c, reader, "bounded", append(bootstrapSteps("ipfix"), testtransport.WriteStep{N: 92}, testtransport.WriteStep{N: 1})...)
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if e.ConsumeLogs(context.Background(), mixedLogs()) == nil {
		t.Fatal("expected mixed failure")
	}
	// Exhaust the fixed telemetry vocabulary, then submit 10,000 changing hostile
	// labels/event values. Repetition must count exactly without adding any series.
	for range 10000 {
		for _, reason := range []string{"accepted", "busy", "closed", "preflight", "invalid_context"} {
			e.telemetry.admission(context.Background(), reason)
		}
		for _, reason := range []string{"busy", "closed", "unavailable", "internal"} {
			e.telemetry.failure(context.Background(), reason)
		}
		for event := destination.DataConfirmed; event <= destination.RefreshFailed; event++ {
			e.telemetry.observe(context.Background(), event, 128)
		}
	}
	before := localMetrics(t, reader)
	for i := range 10000 {
		poison := fmt.Sprintf("secret 192.0.2.%d PEN key body", i)
		e.telemetry.admission(context.Background(), poison)
		e.telemetry.failure(context.Background(), poison)
		e.telemetry.observe(context.Background(), destination.Event(255), uint64(i))
		e.telemetry.observe(context.Background(), destination.DataConfirmed, ^uint64(0))
	}
	after := localMetrics(t, reader)
	acceptanceAssertLocalVocabulary(t, after)
	// The original 33 series plus this fixture's one rejected-record reason.
	// The closed thirteen-reason vocabulary plus two lifetime gauges raises the
	// overall bound to 48; this counter-only helper still sees 34 populated
	// counter series in this fixture.
	if len(before) != 34 || len(after) != 34 {
		t.Fatalf("local series before=%d after=%d: %v", len(before), len(after), before)
	}
	requireMetric(t, after, "rejected_records", 2, "exporter=netflow/bounded", "rejection_reason=unsupported_body")
	for key, value := range before {
		if after[key] != value || strings.Contains(key, "secret") {
			t.Fatalf("unbounded labels or counts: %s", key)
		}
	}
	requireMetric(t, after, "dns", 10000, "exporter=netflow/bounded", "outcome=failed")
	requireMetric(t, after, "templates", 10000, "exporter=netflow/bounded", "message_kind=refresh", "outcome=ambiguous")
	requireMetric(t, after, "bytes", 1280000, "exporter=netflow/bounded", "message_kind=refresh", "outcome=ambiguous")
}

func TestIsolation(t *testing.T) {
	t.Run("records", testRecordIsolation)
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			defer provider.Shutdown(context.Background())
			for _, name := range []string{"healthy", "failed"} {
				c := validConfig(protocol)
				set := exportertest.NewNopSettings(NewFactory().Type())
				set.ID = component.NewIDWithName(NewFactory().Type(), name)
				set.MeterProvider = provider
				steps := append(bootstrapSteps(protocol), testtransport.WriteStep{N: packetLength(protocol)})
				if name == "failed" {
					steps[1] = testtransport.WriteStep{N: 0, Err: errors.New("secret bootstrap")}
				}
				conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint), steps...)
				e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
				err = e.Start(context.Background(), componenttest.NewNopHost())
				if (err == nil) != (name == "healthy") {
					t.Fatal(err)
				}
				if name == "healthy" {
					if err = e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
						t.Fatal(err)
					}
				}
				if err = e.Shutdown(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			metrics := localMetrics(t, reader)
			requireMetric(t, metrics, "endpoint_epochs", 1, "exporter=netflow/healthy")
			requireMetric(t, metrics, "endpoint_epochs", 0, "exporter=netflow/failed")
			requireMetric(t, metrics, "templates", 4, "exporter=netflow/healthy", "message_kind=bootstrap", "outcome=confirmed")
			requireMetric(t, metrics, "templates", 1, "exporter=netflow/failed", "message_kind=bootstrap", "outcome=confirmed")
			requireMetric(t, metrics, "templates", 1, "exporter=netflow/failed", "message_kind=bootstrap", "outcome=ambiguous")
			requireMetric(t, metrics, "failures", 1, "exporter=netflow/failed", "reason=bootstrap")
			requireMetric(t, metrics, "failures", 0, "exporter=netflow/healthy", "reason=bootstrap")
		})
	}
}
