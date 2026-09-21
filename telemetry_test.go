package netflowexporter

import (
	"context"
	"errors"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countHelper struct {
	exporter.Logs
	consumes, shutdowns atomic.Int32
}

func (c *countHelper) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	c.consumes.Add(1)
	return c.Logs.ConsumeLogs(ctx, logs)
}
func (c *countHelper) Shutdown(ctx context.Context) error {
	c.shutdowns.Add(1)
	return c.Logs.Shutdown(ctx)
}
func TestShutdown(t *testing.T) {
	e, _ := fakeExporter(t, validConfig("netflow_v5"))
	counter := &countHelper{Logs: e.helper}
	e.helper = counter
	entered := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- e.runtime.Consume(context.Background(), func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return ctx.Err()
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := e.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded shutdown %v", err)
	}
	<-canceled
	if err := e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatal(err)
	}
	if err := e.Start(context.Background(), componenttest.NewNopHost()); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatal(err)
	}
	close(release)
	<-done
	for range 3 {
		if err := e.Shutdown(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	if counter.shutdowns.Load() != 1 {
		t.Fatal("helper shutdown repeated")
	}
}
func TestHelperAccounting(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	c := validConfig("netflow_v5")
	c.MaxRecordsPerMessage = ptr(uint16(1))
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.MeterProvider = provider
	remote := netip.MustParseAddrPort(c.Endpoint)
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), remote, testtransport.WriteStep{N: 72}, testtransport.WriteStep{N: 1})
	e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 0), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown(context.Background())
	if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err = e.ConsumeLogs(context.Background(), mixedLogs()); err == nil {
		t.Fatal("expected partial failure")
	}
	var rm metricdata.ResourceMetrics
	if err = reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	failed := int64(0)
	outcomes := map[string]int64{}
	rejections := map[string]int64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				switch m.Name {
				case "otelcol_exporter_send_failed_log_records":
					failed += dp.Value
				case "otelcol_netflow.exporter.records":
					v, _ := dp.Attributes.Value("outcome")
					outcomes[v.AsString()] += dp.Value
				case "otelcol_netflow.exporter.rejected_records":
					v, _ := dp.Attributes.Value("rejection_reason")
					rejections[v.AsString()] += dp.Value
				}
			}
		}
	}
	if failed != 6 || outcomes["confirmed"] != 1 || outcomes["invalid"] != 2 || outcomes["ambiguous"] != 1 || outcomes["unsent"] != 2 {
		t.Fatalf("helper=%d local=%v", failed, outcomes)
	}
	if rejections["unsupported_body"] != 2 {
		t.Fatalf("rejected records=%v", rejections)
	}
}
func testRecordIsolation(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	for _, name := range []string{"healthy", "failed"} {
		c := validConfig("netflow_v5")
		set := exportertest.NewNopSettings(NewFactory().Type())
		set.ID = component.NewIDWithName(NewFactory().Type(), name)
		set.MeterProvider = provider
		n := 72
		if name == "failed" {
			n = 1
		}
		remote := netip.MustParseAddrPort(c.Endpoint)
		conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), remote, testtransport.WriteStep{N: n})
		e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 0), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		err = e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs())
		if (err == nil) != (name == "healthy") {
			t.Fatal(err)
		}
		if err = e.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]string{}
	for _, s := range rm.ScopeMetrics {
		for _, m := range s.Metrics {
			if m.Name == "otelcol_netflow.exporter.records" {
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					id, _ := dp.Attributes.Value("exporter")
					outcome, _ := dp.Attributes.Value("outcome")
					outcomes[id.AsString()] = outcome.AsString()
				}
			}
		}
	}
	if outcomes["netflow/healthy"] != "confirmed" || outcomes["netflow/failed"] != "ambiguous" {
		t.Fatal(outcomes)
	}
}
func TestRedaction(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.Logger = zap.New(core)
	c := validConfig("netflow_v5")
	remote := netip.MustParseAddrPort(c.Endpoint)
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), remote, testtransport.WriteStep{Err: errors.New("secret endpoint 192.0.2.1 PEN 999")})
	e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 0), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown(context.Background())
	if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	err = e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs())
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	invalid := plog.NewLogs()
	invalid.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetStr("secret")
	// Every request still reaches helper accounting, while its routine logger is
	// capped at one event per minute. No request-derived sampling key is retained.
	for range 10000 {
		_ = e.ConsumeLogs(context.Background(), invalid)
	}
	if observed.Len() != 1 {
		t.Fatalf("unbounded helper logging: %d", observed.Len())
	}
	for _, entry := range observed.All() {
		if strings.Contains(entry.Message, "secret") {
			t.Fatal("message leak")
		}
		for _, f := range entry.Context {
			if strings.Contains(f.String, "secret") {
				t.Fatal("field leak")
			}
			if f.Interface != nil && strings.Contains(f.Interface.(error).Error(), "secret") {
				t.Fatal("error leak")
			}
		}
	}
}
