package netflowexporter

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const lifetimeOrigin uint64 = 1_788_220_800_000_000_000

type lifetimeValues struct {
	remaining  []metricdata.DataPoint[float64]
	exhausted  []metricdata.DataPoint[int64]
	remainingU string
	exhaustedU string
}

// lifetimeFixture owns every resource used by a root SDK test.  The
// constructor is deliberately injected: boundary tests can set the wall
// sample independently of source timestamps, inspect the exact scripted UDP
// datagrams, and still exercise the production wrapper/callback seam.
type lifetimeFixture struct {
	e        *logsExporter
	conn     *testtransport.Conn
	clock    *testclock.Clock
	reader   *sdkmetric.ManualReader
	provider *sdkmetric.MeterProvider
	config   *Config
	origin   uint64
}

func newLifetimeFixture(t *testing.T, protocol, profile, name string, configuredOrigin *uint64) *lifetimeFixture {
	t.Helper()
	origin := lifetimeOrigin
	if configuredOrigin != nil {
		origin = *configuredOrigin
	}
	clock := testclock.New(origin+1_000_000_000, 1)
	c := validConfig(protocol)
	if profile != "" {
		c.Mapping.Profile = ptr(profile)
	}
	if configuredOrigin != nil {
		c.UptimeOrigin = ptr(*configuredOrigin)
	}
	if protocol == "netflow_v9" && profile == mapping.ProfileV9 && configuredOrigin == nil {
		c.UptimeOrigin = nil
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), name)
	set.MeterProvider = provider
	steps := bootstrapSteps(protocol)
	if protocol == "netflow_v9" && profile == mapping.ProfileV9Timed {
		// Timed v9's full profile has a larger template than the core v9
		// profile. The scripted transport records every byte for independent
		// wire assertions below.
		steps = []testtransport.WriteStep{{N: 108}, {N: 108}, {N: 108}, {N: 108}}
	}
	dataLength := packetLength(protocol)
	if protocol == "netflow_v9" && profile == mapping.ProfileV9Timed {
		dataLength = 76
	}
	for i := 0; i < 16; i++ {
		steps = append(steps, testtransport.WriteStep{N: dataLength})
	}
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:40000"),
		netip.MustParseAddrPort(c.Endpoint), steps...,
	)
	e, err := newLogsExporter(context.Background(), set, c, clock, func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &lifetimeFixture{e: e, conn: conn, clock: clock, reader: reader, provider: provider, config: c, origin: origin}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return fixture
}

func (f *lifetimeFixture) start(t *testing.T) {
	t.Helper()
	if err := f.e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if f.config.Protocol == "netflow_v9" && f.config.UptimeOrigin == nil {
		wall, _ := f.clock.Now()
		// millisecondClock rounds the implicit publication sample down before
		// State captures it as the epoch origin.
		f.origin = wall - wall%1_000_000
	}
}

func lifetimeLogs(origin uint64) plog.Logs {
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	start := origin + 1_000_000_000
	end := start + 1_000_000
	received := origin + 2_000_000_000
	record.Attributes().PutInt("flow.start", int64(start))
	record.Attributes().PutInt("flow.end", int64(end))
	record.Attributes().PutInt("flow.time_received", int64(received))
	record.SetTimestamp(pcommon.Timestamp(start))
	record.SetObservedTimestamp(pcommon.Timestamp(received))
	return logs
}

func lifetimeWritePayloads(conn *testtransport.Conn) [][]byte {
	var payloads [][]byte
	for _, event := range conn.Writes() {
		if event.N == len(event.Payload) && event.N > 0 {
			payloads = append(payloads, event.Payload)
		}
	}
	return payloads
}

func lifetimeDataPayloads(protocol string, conn *testtransport.Conn) [][]byte {
	var payloads [][]byte
	for _, payload := range lifetimeWritePayloads(conn) {
		if protocol == "netflow_v5" {
			payloads = append(payloads, payload)
			continue
		}
		if protocol == "netflow_v9" && len(payload) >= 24 && binary.BigEndian.Uint16(payload[20:22]) >= 256 {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

func assertLifetimeWire(t *testing.T, protocol string, payloads [][]byte, wantUptime []uint32) {
	t.Helper()
	if len(payloads) != len(wantUptime) {
		t.Fatalf("%s data packets=%d want %d (all writes=%d)", protocol, len(payloads), len(wantUptime), len(payloads))
	}
	var firstSequence uint32
	for i, payload := range payloads {
		if len(payload) < 24 {
			t.Fatalf("%s packet %d length=%d", protocol, i, len(payload))
		}
		var uptime, sequence uint32
		switch protocol {
		case "netflow_v5":
			if got := binary.BigEndian.Uint16(payload[2:4]); got != 1 {
				t.Fatalf("v5 packet %d record count=%d want 1", i, got)
			}
			uptime = binary.BigEndian.Uint32(payload[4:8])
			sequence = binary.BigEndian.Uint32(payload[16:20])
		case "netflow_v9":
			if got := binary.BigEndian.Uint16(payload[2:4]); got != 1 {
				t.Fatalf("v9 packet %d record count=%d want 1", i, got)
			}
			uptime = binary.BigEndian.Uint32(payload[4:8])
			sequence = binary.BigEndian.Uint32(payload[12:16])
		default:
			t.Fatalf("wire assertion called for %s", protocol)
		}
		if uptime != wantUptime[i] {
			t.Fatalf("%s packet %d uptime=%d want %d", protocol, i, uptime, wantUptime[i])
		}
		if i == 0 {
			firstSequence = sequence
		} else if sequence != firstSequence+uint32(i) {
			t.Fatalf("%s packet %d sequence=%d want %d", protocol, i, sequence, firstSequence+uint32(i))
		}
	}
}

func collectLifetime(t *testing.T, reader *sdkmetric.ManualReader) lifetimeValues {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	return lifetimeValuesFromResourceMetrics(t, &rm)
}

func lifetimeValuesFromResourceMetrics(t *testing.T, rm *metricdata.ResourceMetrics) lifetimeValues {
	t.Helper()
	got := lifetimeValues{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch m.Name {
			case "otelcol_netflow.exporter.uptime_remaining":
				data, ok := m.Data.(metricdata.Gauge[float64])
				if !ok {
					t.Fatalf("remaining data type=%T", m.Data)
				}
				got.remainingU = m.Unit
				got.remaining = data.DataPoints
			case "otelcol_netflow.exporter.uptime_exhausted":
				data, ok := m.Data.(metricdata.Gauge[int64])
				if !ok {
					t.Fatalf("exhausted data type=%T", m.Data)
				}
				got.exhaustedU = m.Unit
				got.exhausted = data.DataPoints
			}
		}
	}
	return got
}

func lifetimeExporterWithRegistration(t *testing.T, protocol, name string, clock transport.Clock, reader *sdkmetric.ManualReader) (*logsExporter, *lifetimeMeter) {
	t.Helper()
	c := validConfig(protocol)
	if protocol == "netflow_v9" {
		c.Mapping.Profile = ptr(mapping.ProfileV9Timed)
		c.UptimeOrigin = ptr(lifetimeOrigin)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), name)
	meter := &lifetimeMeter{
		Meter: provider.Meter("test-registration"), registration: &lifetimeRegistration{},
	}
	set.MeterProvider = &lifetimeProvider{MeterProvider: provider, meter: meter}
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint), append(bootstrapSteps(protocol), testtransport.WriteStep{N: packetLength(protocol)})...)
	e, err := newLogsExporter(context.Background(), set, c, clock, func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e, meter
}

type lifetimeBarrierClock struct {
	base    *testclock.Clock
	blocked atomic.Bool
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *lifetimeBarrierClock) Now() (uint64, uint64) {
	c.calls.Add(1)
	if c.blocked.Load() {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.base.Now()
}

func waitLifecycleError(t *testing.T, name string, result <-chan error) error {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		t.Fatalf("%s did not complete before deadline", name)
		return nil
	}
}

func requireLifetimePoint(t *testing.T, got lifetimeValues, remaining float64, exhausted int64) {
	t.Helper()
	if len(got.remaining) != 1 || got.remaining[0].Value != remaining {
		t.Fatalf("remaining=%v, want one point %v", got.remaining, remaining)
	}
	if len(got.exhausted) != 1 || got.exhausted[0].Value != exhausted {
		t.Fatalf("exhausted=%v, want one point %d", got.exhausted, exhausted)
	}
	if got.remainingU != "s" || got.exhaustedU != "1" {
		t.Fatalf("units remaining=%q exhausted=%q", got.remainingU, got.exhaustedU)
	}
	for _, attrs := range []attributeSet{attributesToSet(got.remaining[0].Attributes), attributesToSet(got.exhausted[0].Attributes)} {
		if len(attrs) != 1 || attrs["exporter"] == "" {
			t.Fatalf("attributes=%v, want only trusted exporter", attrs)
		}
	}
}

func requireLifetimeIdentity(t *testing.T, got lifetimeValues, expected string) {
	t.Helper()
	for _, pointAttrs := range []attribute.Set{got.remaining[0].Attributes, got.exhausted[0].Attributes} {
		attrs := attributesToSet(pointAttrs)
		if len(attrs) != 1 || attrs["exporter"] != expected {
			t.Fatalf("lifetime identity=%v want exporter=%q", attrs, expected)
		}
	}
}

type attributeSet map[string]string

func attributesToSet(attrs attribute.Set) attributeSet {
	result := make(attributeSet, len(attrs.ToSlice()))
	for _, kv := range attrs.ToSlice() {
		result[string(kv.Key)] = kv.Value.AsString()
	}
	return result
}

func requireLifetimeSubsetOrdinals(t *testing.T, logs plog.Logs, want []int64) {
	t.Helper()
	if logs.LogRecordCount() != len(want) {
		t.Fatalf("subset records=%d want %d", logs.LogRecordCount(), len(want))
	}
	cursor := logCursor{logs: logs}
	for index, expected := range want {
		record, ok := cursor.at(uint64(index))
		if !ok {
			t.Fatalf("subset lost ordinal at index %d", index)
		}
		ordinal, ok := record.Attributes().Get("ordinal")
		if !ok || ordinal.Int() != expected {
			t.Fatalf("subset ordinal[%d]=%v want %d", index, ordinal, expected)
		}
	}
}

func TestTelemetryLifetimeBoundaries(t *testing.T) {
	const limitMS = uint64(math.MaxUint32) + 1
	profiles := []struct {
		name    string
		proto   string
		profile string
		origin  *uint64
	}{
		{name: "v5", proto: "netflow_v5", profile: mapping.ProfileV5, origin: ptr(lifetimeOrigin)},
		{name: "timed-v9", proto: "netflow_v9", profile: mapping.ProfileV9Timed, origin: ptr(lifetimeOrigin + 123_456)},
		{name: "implicit-v9", proto: "netflow_v9", profile: mapping.ProfileV9},
		{name: "ipfix-absence", proto: "ipfix", profile: mapping.ProfileIPFIX},
	}
	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newLifetimeFixture(t, tc.proto, tc.profile, "boundaries-"+tc.name, tc.origin)
			if tc.proto == "ipfix" {
				fixture.origin = lifetimeOrigin
			}
			if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
				t.Fatalf("pre-start points=%+v", got)
			}
			fixture.start(t)
			logs := lifetimeLogs(fixture.origin)
			if tc.proto == "ipfix" {
				// IPFIX has no uptime window. Run the same finite edge vector
				// to prove absence at every instant while datagrams continue.
				for i, delta := range []uint64{(limitMS - 2) * 1_000_000, (limitMS - 1) * 1_000_000, (limitMS-1)*1_000_000 + 999_999, limitMS * 1_000_000, 1_000_000_000} {
					fixture.clock.Set(fixture.origin+delta, uint64(i+2))
					if err := fixture.e.ConsumeLogs(context.Background(), logs); err != nil {
						t.Fatalf("IPFIX edge %d consume=%v", i, err)
					}
					if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
						t.Fatalf("IPFIX edge %d lifetime=%+v", i, got)
					}
				}
				if got := helperSentRecords(t, fixture.reader); got != 5 {
					t.Fatalf("IPFIX sent records=%d want 5", got)
				}
				if got := len(lifetimeDataPayloads(tc.proto, fixture.conn)); got != 0 {
					t.Fatalf("IPFIX data classifier unexpectedly found %d v5/v9 packets", got)
				}
				if got := len(lifetimeWritePayloads(fixture.conn)); got != 9 {
					t.Fatalf("IPFIX writes=%d want four bootstrap plus five data", got)
				}
				return
			}

			initial := collectLifetime(t, fixture.reader)
			if len(initial.remaining) != 1 || initial.exhausted[0].Value != 0 {
				t.Fatalf("post-start initial point=%+v", initial)
			}
			requireLifetimeIdentity(t, initial, "netflow/boundaries-"+tc.name)
			wantUptime := []uint32{}
			edges := []struct {
				name   string
				delta  uint64
				remain float64
			}{
				{name: "max-minus-one", delta: (limitMS - 2) * 1_000_000, remain: 0.002},
				{name: "exact-max", delta: (limitMS - 1) * 1_000_000, remain: 0.001},
				// The millisecond adapter intentionally rounds this final
				// fractional source sample down to the exact maximum uptime.
				{name: "final-fractional-ms", delta: (limitMS-1)*1_000_000 + 999_999, remain: 0.001},
			}
			for index, edge := range edges {
				t.Run(edge.name, func(t *testing.T) {
					fixture.clock.Set(fixture.origin+edge.delta, uint64(index+2))
					requireLifetimePoint(t, collectLifetime(t, fixture.reader), edge.remain, 0)
					if err := fixture.e.ConsumeLogs(context.Background(), logs); err != nil {
						t.Fatalf("legal edge consume=%v", err)
					}
					if tc.proto == "netflow_v5" {
						wantUptime = append(wantUptime, uint32(edge.delta/1_000_000))
					} else {
						wantUptime = append(wantUptime, uint32(edge.delta/1_000_000))
					}
				})
			}
			// Repeat a legal final sample and then rewind. Both operations
			// must send and advance sequence/accounting while the quiet
			// projection remains unlatched.
			fixture.clock.Set(fixture.origin+(limitMS-1)*1_000_000, 9)
			requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0.001, 0)
			if err := fixture.e.ConsumeLogs(context.Background(), logs); err != nil {
				t.Fatalf("repeated legal sample=%v", err)
			}
			wantUptime = append(wantUptime, math.MaxUint32)
			fixture.clock.Set(fixture.origin+1_000_000_000, 10)
			got := collectLifetime(t, fixture.reader)
			if len(got.remaining) != 1 || got.remaining[0].Value <= 0 || got.exhausted[0].Value != 0 {
				t.Fatalf("rewound quiet projection=%+v", got)
			}
			if err := fixture.e.ConsumeLogs(context.Background(), logs); err != nil {
				t.Fatalf("rewound legal sample=%v", err)
			}
			// State's prior-wall reservation floor keeps a rewind from
			// emitting a smaller protocol uptime; the wire sample therefore
			// remains at the last legal maximum even though the projection is
			// still quiet and unlatched.
			wantUptime = append(wantUptime, math.MaxUint32)

			// Projection at the first exhausted millisecond is quiet zero.
			// Only the failed data operation latches the published State.
			fixture.clock.Set(fixture.origin+limitMS*1_000_000, 11)
			requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 0)
			writesBefore := len(lifetimeDataPayloads(tc.proto, fixture.conn))
			if err := fixture.e.ConsumeLogs(context.Background(), logs); err == nil {
				t.Fatal("first exhausted operation unexpectedly succeeded")
			} else if !consumererror.IsPermanent(err) {
				t.Fatalf("first exhausted error=%v, want permanent", err)
			}
			requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 1)
			fixture.clock.Set(fixture.origin+1_000_000_000, 12)
			requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 1)
			if err := fixture.e.ConsumeLogs(context.Background(), logs); err == nil {
				t.Fatal("latched rewind unexpectedly succeeded")
			}
			if got := len(lifetimeDataPayloads(tc.proto, fixture.conn)); got != writesBefore {
				t.Fatalf("latched rewind wrote data=%d want %d", got, writesBefore)
			}
			assertLifetimeWire(t, tc.proto, lifetimeDataPayloads(tc.proto, fixture.conn), wantUptime)
			if got := helperSentRecords(t, fixture.reader); got != int64(len(wantUptime)) {
				t.Fatalf("%s helper sent=%d want %d", tc.proto, got, len(wantUptime))
			}
		})
	}
}

func TestTelemetryLifetimeLifecycle(t *testing.T) {
	const limitMS = uint64(math.MaxUint32) + 1
	t.Run("v5-expired-start-then-data", func(t *testing.T) {
		fixture := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "lifecycle-v5", ptr(lifetimeOrigin))
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("constructed exporter published points=%+v", got)
		}
		fixture.start(t)
		fixture.clock.Set(lifetimeOrigin+limitMS*1_000_000, 2)
		// Quiet observation sees the representable zero without changing the
		// State latch or reserving a packet wall.
		requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 0)
		err := fixture.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin))
		if err == nil || !consumererror.IsPermanent(err) || err.Error() != "Permanent error: netflow: records rejected" {
			t.Fatalf("expired v5 data=%v, want permanent uptime error", err)
		}
		requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 1)
		fixture.clock.Set(lifetimeOrigin+1_000_000_000, 3)
		requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 1)
		if err := fixture.e.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("post-shutdown points=%+v", got)
		}
	})

	t.Run("timed-v9-expired-start-fails-before-publication", func(t *testing.T) {
		fixture := newLifetimeFixture(t, "netflow_v9", mapping.ProfileV9Timed, "lifecycle-expired-timed", ptr(lifetimeOrigin))
		fixture.clock.Set(lifetimeOrigin+limitMS*1_000_000, 1)
		err := fixture.e.Start(context.Background(), componenttest.NewNopHost())
		if err != destination.ErrUptimeExhausted {
			t.Fatalf("timed expired Start=%v, want existing uptime sentinel", err)
		}
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("failed candidate points=%+v", got)
		}
		metrics := localMetrics(t, fixture.reader)
		if metrics["failures|exporter=netflow/lifecycle-expired-timed|reason=bootstrap"] != 1 {
			t.Fatalf("bootstrap failure metrics=%v", metrics)
		}
	})

	t.Run("refresh-latches-published-epoch", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
		refreshFailed := make(chan struct{})
		var refreshOnce sync.Once
		e, fixture := conditionalExporterWithHook(t, provider, "netflow_v9", "lifecycle-refresh", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: conditionalFullSteps("netflow_v9")}}, func(event destination.Event) {
			if event == destination.RefreshFailed {
				refreshOnce.Do(func() { close(refreshFailed) })
			}
		})
		if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		if got := collectLifetime(t, reader); len(got.remaining) != 1 || len(got.exhausted) != 1 || got.exhausted[0].Value != 0 {
			t.Fatalf("published v9 before refresh=%+v", got)
		}
		waitConditionalTimer(t, fixture.timers[0])
		wall, _ := fixture.clock.Now()
		fixture.clock.Set(wall+limitMS*1_000_000, uint64(30*time.Second))
		if !fixture.timers[0].Fire() {
			t.Fatal("refresh timer did not fire")
		}
		waitConditionalDone(t, refreshFailed)
		got := collectLifetime(t, reader)
		requireLifetimePoint(t, got, 0, 1)
		if metrics := localMetrics(t, reader); metrics[metricKey("failures", "exporter=netflow/lifecycle-refresh", "reason=refresh")] != 1 {
			t.Fatalf("refresh failure metrics=%v", metrics)
		}
	})

	t.Run("failed-candidate-retains-old-latch", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
		candidateFailed := make(chan struct{})
		var candidateOnce sync.Once
		lookup := testtransport.NewResolver(
			testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
			testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.11")}},
		)
		e, fixture := conditionalExporterWithHook(t, provider, "netflow_v5", "lifecycle-replacement", "collector.example", lookup, []conditionalDialPlan{{}, {err: errors.New("candidate private failure")}}, func(event destination.Event) {
			if event == destination.CandidateFailed {
				candidateOnce.Do(func() { close(candidateFailed) })
			}
		})
		if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		fixture.clock.Set(rejectionOrigin+limitMS*1_000_000, 2)
		if err := e.pushLogs(context.Background(), lifetimeLogs(rejectionOrigin)); err == nil {
			t.Fatal("old expired epoch unexpectedly accepted data")
		}
		requireLifetimePoint(t, collectLifetime(t, reader), 0, 1)
		waitConditionalTimer(t, fixture.timers[0])
		fixture.clock.Advance(0, uint64(time.Second))
		if !fixture.timers[0].Fire() {
			t.Fatal("DNS replacement timer did not fire")
		}
		waitConditionalDone(t, candidateFailed)
		// Candidate failure leaves the old published latch and identity intact.
		requireLifetimePoint(t, collectLifetime(t, reader), 0, 1)
		if metrics := localMetrics(t, reader); metrics[metricKey("failures", "exporter=netflow/lifecycle-replacement", "reason=candidate")] != 1 {
			t.Fatalf("candidate failure metrics=%v", metrics)
		}
	})

	t.Run("instances-do-not-share-latch", func(t *testing.T) {
		left := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "lifecycle-left", ptr(lifetimeOrigin))
		right := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "lifecycle-right", ptr(lifetimeOrigin))
		left.start(t)
		right.start(t)
		left.clock.Set(lifetimeOrigin+limitMS*1_000_000, 2)
		if err := left.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin)); err == nil {
			t.Fatal("left expired data unexpectedly succeeded")
		}
		requireLifetimePoint(t, collectLifetime(t, left.reader), 0, 1)
		right.clock.Set(lifetimeOrigin+3_000_000_000, 2)
		if err := right.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin)); err != nil {
			t.Fatalf("independent right data=%v", err)
		}
		if got := collectLifetime(t, right.reader); len(got.remaining) != 1 || got.remaining[0].Value <= 0 || got.exhausted[0].Value != 0 {
			t.Fatalf("right instance inherited latch=%+v", got)
		}
	})
}

func TestTelemetryLifetimeAccounting(t *testing.T) {
	const exporterName = "netflow/accounting-mixed"
	t.Run("successful-mixed-valid-invalid", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "netflow_v5", "accounting-mixed", nil)
		before := collectMetric(t, fixture.reader)
		sentBefore := helperSentRecords(t, fixture.reader)
		failedBefore := helperFailedRecords(t, fixture.reader)
		logs := rejectionLogs(t,
			func(record plog.LogRecord) {},
			func(record plog.LogRecord) { record.Body().SetStr(acceptanceBody) },
			func(record plog.LogRecord) { record.Attributes().PutStr("flow.io.bytes", "wrong type") },
			func(record plog.LogRecord) {},
		)
		if err := boundedConsume(t, fixture.exporter, logs); err != nil {
			t.Fatalf("mixed valid/invalid consume=%v", err)
		}
		after := collectMetric(t, fixture.reader)
		delta := metricDelta(after, before)
		if delta[metricKey("records", "exporter="+exporterName, "outcome=confirmed")] != 2 || delta[metricKey("records", "exporter="+exporterName, "outcome=invalid")] != 2 {
			t.Fatalf("mixed record delta=%v", delta)
		}
		if got := delta[metricKey("rejected_records", "exporter="+exporterName, "rejection_reason=unsupported_body")] + delta[metricKey("rejected_records", "exporter="+exporterName, "rejection_reason=invalid_type")]; got != 2 {
			t.Fatalf("mixed rejection delta=%v", delta)
		}
		assertRejectionDeltaEqualsInvalid(t, delta, exporterName)
		if got := helperSentRecords(t, fixture.reader) - sentBefore; got != 4 {
			t.Fatalf("mixed helper sent delta=%d want all four admitted records", got)
		}
		if got := helperFailedRecords(t, fixture.reader) - failedBefore; got != 0 {
			t.Fatalf("mixed helper failed delta=%d want 0", got)
		}
		acceptanceCheckAllMetricsForCanaries(t, fixture.reader)
		for _, entry := range fixture.observed.All() {
			acceptanceAssertNoCanary(t, entry.Message)
		}
	})

	t.Run("all-invalid-repeat-and-latch", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "netflow_v5", "accounting-all-invalid", nil)
		invalid := rejectionLogs(t,
			func(record plog.LogRecord) { record.Body().SetStr(acceptanceBody) },
			func(record plog.LogRecord) { record.Body().SetStr("second invalid body") },
		)
		before := collectMetric(t, fixture.reader)
		sentBefore := helperSentRecords(t, fixture.reader)
		failedBefore := helperFailedRecords(t, fixture.reader)
		for i := 0; i < 2; i++ {
			err := boundedConsume(t, fixture.exporter, invalid)
			if !consumererror.IsPermanent(err) || err.Error() != "Permanent error: netflow: records rejected" {
				t.Fatalf("all-invalid call %d error=%v", i, err)
			}
			acceptanceAssertNoCanary(t, err.Error())
			assertUDPQuiet(t, fixture.listener)
		}
		after := collectMetric(t, fixture.reader)
		delta := metricDelta(after, before)
		if delta[metricKey("records", "exporter=netflow/accounting-all-invalid", "outcome=invalid")] != 4 {
			t.Fatalf("all-invalid records delta=%v", delta)
		}
		assertRejectionDeltaEqualsInvalid(t, delta, "netflow/accounting-all-invalid")
		if got := helperSentRecords(t, fixture.reader) - sentBefore; got != 0 {
			t.Fatalf("all-invalid helper sent delta=%d", got)
		}
		if got := helperFailedRecords(t, fixture.reader) - failedBefore; got != 4 {
			t.Fatalf("all-invalid helper failed delta=%d want 4 records across two calls", got)
		}
		acceptanceCheckAllMetricsForCanaries(t, fixture.reader)
		if fixture.observed.Len() == 0 {
			t.Fatal("all-invalid helper error log was not captured")
		}
		for _, entry := range fixture.observed.All() {
			acceptanceAssertNoCanary(t, entry.Message)
		}

		// An already-latched runtime still validates sibling records. Invalid
		// records are rejected exactly once; the valid sibling remains unsent
		// and cannot manufacture a rejection reason or a UDP write.
		latched := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "accounting-latched", ptr(lifetimeOrigin))
		latched.start(t)
		limitMS := uint64(math.MaxUint32) + 1
		latched.clock.Set(lifetimeOrigin+limitMS*1_000_000, 2)
		if err := latched.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin)); err == nil {
			t.Fatal("latch setup unexpectedly succeeded")
		}
		latched.clock.Set(lifetimeOrigin+3_000_000_000, 3)
		beforeLatch := collectMetric(t, latched.reader)
		writesBefore := len(lifetimeDataPayloads("netflow_v5", latched.conn))
		sentLatchBefore := helperSentRecords(t, latched.reader)
		failedLatchBefore := helperFailedRecords(t, latched.reader)
		mixed := rejectionLogs(t,
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 0) },
			func(record plog.LogRecord) {
				record.Attributes().PutInt("ordinal", 1)
				record.Body().SetStr("latched invalid")
			},
		)
		err := latched.e.ConsumeLogs(context.Background(), mixed)
		if !consumererror.IsPermanent(err) || err.Error() != "Permanent error: netflow: records rejected" {
			t.Fatalf("latched mixed error=%v", err)
		}
		deltaLatch := metricDelta(collectMetric(t, latched.reader), beforeLatch)
		if deltaLatch[metricKey("records", "exporter=netflow/accounting-latched", "outcome=invalid")] != 1 ||
			deltaLatch[metricKey("records", "exporter=netflow/accounting-latched", "outcome=unsent")] != 1 {
			t.Fatalf("latched invalid delta=%v", deltaLatch)
		}
		assertRejectionDeltaEqualsInvalid(t, deltaLatch, "netflow/accounting-latched")
		if got := helperSentRecords(t, latched.reader) - sentLatchBefore; got != 0 {
			t.Fatalf("latched mixed helper sent delta=%d want 0", got)
		}
		if got := helperFailedRecords(t, latched.reader) - failedLatchBefore; got != 2 {
			t.Fatalf("latched mixed helper failed delta=%d want 2", got)
		}
		if got := len(lifetimeDataPayloads("netflow_v5", latched.conn)); got != writesBefore {
			t.Fatalf("latched mixed wrote data=%d want %d", got, writesBefore)
		}
		requireLifetimePoint(t, collectLifetime(t, latched.reader), 0, 1)
	})

	t.Run("transport-failed-subset", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
		c := validConfig("netflow_v5")
		c.Endpoint = "127.0.0.1:4739"
		c.UptimeOrigin = ptr(rejectionOrigin)
		c.MaxRecordsPerMessage = ptr(uint16(1))
		set := exportertest.NewNopSettings(NewFactory().Type())
		set.ID = component.NewIDWithName(NewFactory().Type(), "accounting-failed-subset")
		set.MeterProvider = provider
		conn := testtransport.NewConn(
			netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint),
			testtransport.WriteStep{N: 72},
			testtransport.WriteStep{N: 1, Err: errors.New("transport private error")},
		)
		e, err := newLogsExporter(context.Background(), set, c, testclock.New(rejectionOrigin+3_000_000_000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
		if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		logs := rejectionLogs(t,
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 0) },
			func(record plog.LogRecord) {
				record.Attributes().PutInt("ordinal", 1)
				record.Body().SetStr("failed-subset invalid")
			},
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 2) },
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 3) },
		)
		before := collectMetric(t, reader)
		err = e.ConsumeLogs(context.Background(), logs)
		if err == nil || consumererror.IsPermanent(err) || err.Error() != "netflow: transient packet handoff" {
			t.Fatalf("failed-subset error=%v", err)
		}
		subset, ok := errors.AsType[consumererror.Logs](err)
		if !ok {
			t.Fatalf("failed-subset error type=%T", err)
		}
		requireLifetimeSubsetOrdinals(t, subset.Data(), []int64{2, 3})
		acceptanceAssertNoCanary(t, err.Error())
		delta := metricDelta(collectMetric(t, reader), before)
		if delta[metricKey("records", "exporter=netflow/accounting-failed-subset", "outcome=confirmed")] != 1 ||
			delta[metricKey("records", "exporter=netflow/accounting-failed-subset", "outcome=invalid")] != 1 ||
			delta[metricKey("records", "exporter=netflow/accounting-failed-subset", "outcome=ambiguous")] != 1 ||
			delta[metricKey("records", "exporter=netflow/accounting-failed-subset", "outcome=unsent")] != 1 {
			t.Fatalf("failed-subset records delta=%v", delta)
		}
		assertRejectionDeltaEqualsInvalid(t, delta, "netflow/accounting-failed-subset")
		if got := len(conn.Writes()); got != 2 {
			t.Fatalf("failed-subset writes=%d want 2", got)
		}
		if got := helperSentRecords(t, reader); got != 0 {
			t.Fatalf("failed-subset helper sent=%d want 0", got)
		}
		if got := helperFailedRecords(t, reader); got != 4 {
			t.Fatalf("failed-subset helper failed=%d want 4", got)
		}
	})

	t.Run("non-lifetime-header-seconds-recovery", func(t *testing.T) {
		fixture := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "accounting-header-seconds", ptr(lifetimeOrigin))
		fixture.start(t)
		fixture.clock.Set((uint64(math.MaxUint32)+1)*1_000_000_000, 2)
		headerErr := fixture.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin))
		if headerErr == nil || headerErr.Error() != "Permanent error: netflow: records rejected" {
			t.Fatal("invalid header-seconds Consume unexpectedly succeeded")
		}
		headerErrText := headerErr.Error()
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 1 || got.exhausted[0].Value != 0 {
			t.Fatalf("invalid header-seconds projection=%+v", got)
		}
		failed := localMetrics(t, fixture.reader)
		_ = collectLifetime(t, fixture.reader)
		if afterCollect := localMetrics(t, fixture.reader); !reflect.DeepEqual(failed, afterCollect) {
			t.Fatalf("collection changed non-lifetime counters before=%v after=%v", failed, afterCollect)
		}
		if headerErr.Error() != headerErrText {
			t.Fatalf("collection changed header error from %q to %q", headerErrText, headerErr)
		}
		// The non-lifetime header check is a source-data failure. It must leave
		// the lifetime projection quiet and recover on the next valid-time call;
		// the test above also proves observation itself has no counter side effect.
		fixture.clock.Set(lifetimeOrigin+3_000_000_000, 3)
		if err := fixture.e.ConsumeLogs(context.Background(), lifetimeLogs(lifetimeOrigin)); err != nil {
			t.Fatalf("valid-time recovery=%v", err)
		}
		got := collectLifetime(t, fixture.reader)
		if len(got.remaining) != 1 || got.remaining[0].Value <= 0 || got.exhausted[0].Value != 0 {
			t.Fatalf("valid-time recovery projection=%+v", got)
		}
	})

}

func TestTelemetryLifetimePublicFactory(t *testing.T) {
	const limitMS = uint64(math.MaxUint32) + 1
	const maxLifetimeSeconds = float64(limitMS) / 1000
	// Keep the real loopback listeners open from CreateLogs through shutdown.
	// The source timestamps are tied to a recent origin, so this exercises the
	// public factory with live wall time without asserting exact real-time ms.
	liveOrigin := uint64(time.Now().Add(-10 * time.Second).Truncate(time.Millisecond).UnixNano())
	for _, tc := range []struct {
		name string
		id   string
	}{
		{name: "live-a", id: "public-lifetime-live-a"},
		{name: "live-b", id: "public-lifetime-live-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newPublicTelemetryFixture(t, "netflow_v5", tc.id, func(c *Config) {
				c.UptimeOrigin = ptr(liveOrigin)
			})
			if err := boundedConsume(t, fixture.exporter, lifetimeLogs(liveOrigin)); err != nil {
				t.Fatalf("live public consume=%v", err)
			}
			packets := readUDPPackets(t, fixture.listener, 1)
			if len(packets[0]) < 24 || binary.BigEndian.Uint16(packets[0][:2]) != 5 {
				t.Fatalf("live packet header=%x", packets[0][:min(len(packets[0]), 24)])
			}
			got := collectLifetime(t, fixture.reader)
			if len(got.remaining) != 1 || got.remaining[0].Value <= 24*60*60 || got.remaining[0].Value > maxLifetimeSeconds {
				t.Fatalf("live remaining=%v, want >24h and <=%v seconds", got.remaining, maxLifetimeSeconds)
			}
			requireLifetimePoint(t, got, got.remaining[0].Value, 0)
			for _, point := range []attribute.Set{got.remaining[0].Attributes, got.exhausted[0].Attributes} {
				attrs := attributesToSet(point)
				if attrs["exporter"] != "netflow/"+tc.id {
					t.Fatalf("public trusted identity=%v want netflow/%s", attrs, tc.id)
				}
			}
			if err := boundedShutdown(t, fixture.exporter); err != nil {
				t.Fatal(err)
			}
			if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
				t.Fatalf("post-shutdown live points=%+v", got)
			}
		})
	}

	t.Run("expired-origin-v5", func(t *testing.T) {
		expiredBy := time.Duration(limitMS)*time.Millisecond + 10*time.Second
		expiredOrigin := uint64(time.Now().Add(-expiredBy).UnixNano())
		fixture := newPublicTelemetryFixture(t, "netflow_v5", "public-lifetime-expired", func(c *Config) {
			c.UptimeOrigin = ptr(expiredOrigin)
		})
		requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 0)
		err := boundedConsume(t, fixture.exporter, lifetimeLogs(expiredOrigin))
		if err == nil || !consumererror.IsPermanent(err) || err.Error() != "Permanent error: netflow: records rejected" {
			t.Fatalf("expired public v5 consume=%v, want permanent", err)
		}
		assertUDPQuiet(t, fixture.listener)
		requireLifetimePoint(t, collectLifetime(t, fixture.reader), 0, 1)
		if err := boundedShutdown(t, fixture.exporter); err != nil {
			t.Fatal(err)
		}
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("post-shutdown expired points=%+v", got)
		}
	})

	t.Run("ipfix-absence", func(t *testing.T) {
		fixture := newPublicTelemetryFixture(t, "ipfix", "public-lifetime-ipfix", nil)
		if err := boundedConsume(t, fixture.exporter, lifetimeLogs(liveOrigin)); err != nil {
			t.Fatalf("public IPFIX consume=%v", err)
		}
		packets := readUDPPackets(t, fixture.listener, 5)
		for i, packet := range packets {
			if len(packet) < 16 || binary.BigEndian.Uint16(packet[:2]) != 10 {
				t.Fatalf("IPFIX packet %d header=%x", i, packet[:min(len(packet), 16)])
			}
		}
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("public IPFIX published lifetime=%+v", got)
		}
		if err := boundedShutdown(t, fixture.exporter); err != nil {
			t.Fatal(err)
		}
		if got := collectLifetime(t, fixture.reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
			t.Fatalf("post-shutdown IPFIX points=%+v", got)
		}
	})
}

type lifetimeRegistration struct {
	metric.Registration
	unregisters    atomic.Int32
	err            error
	skipUnderlying bool
}

func (r *lifetimeRegistration) Unregister() error {
	r.unregisters.Add(1)
	var wrappedErr error
	if !r.skipUnderlying && r.Registration != nil {
		wrappedErr = r.Registration.Unregister()
	}
	if r.err != nil {
		return r.err
	}
	return wrappedErr
}

func cleanupLifetimeRegistration(t *testing.T, registration *lifetimeRegistration) {
	t.Helper()
	if registration == nil || registration.Registration == nil {
		return
	}
	if err := registration.Registration.Unregister(); err != nil {
		t.Fatalf("underlying registration cleanup=%v", err)
	}
	registration.Registration = nil
}

type lifetimeMeter struct {
	metric.Meter
	registration    *lifetimeRegistration
	registerErr     error
	registers       atomic.Int32
	observables     atomic.Int32
	returnNil       bool
	callbackEnter   chan struct{}
	callbackRelease <-chan struct{}
	callbackOnce    sync.Once
	observerEnter   chan struct{}
	observerRelease <-chan struct{}
	observerOnce    sync.Once
}

type lifetimeObserverBarrier struct {
	metric.Observer
	entered chan struct{}
	release <-chan struct{}
	once    *sync.Once
}

func (o *lifetimeObserverBarrier) ObserveFloat64(instrument metric.Float64Observable, value float64, opts ...metric.ObserveOption) {
	o.once.Do(func() { close(o.entered) })
	<-o.release
	o.Observer.ObserveFloat64(instrument, value, opts...)
}

func (m *lifetimeMeter) RegisterCallback(callback metric.Callback, observables ...metric.Observable) (metric.Registration, error) {
	m.registers.Add(1)
	m.observables.Store(int32(len(observables)))
	if m.observerEnter != nil && m.observerRelease != nil {
		original := callback
		callback = func(ctx context.Context, observer metric.Observer) error {
			observer = &lifetimeObserverBarrier{
				Observer: observer,
				entered:  m.observerEnter,
				release:  m.observerRelease,
				once:     &m.observerOnce,
			}
			return original(ctx, observer)
		}
	}
	if m.callbackEnter != nil && m.callbackRelease != nil {
		original := callback
		callback = func(ctx context.Context, observer metric.Observer) error {
			m.callbackOnce.Do(func() { close(m.callbackEnter) })
			<-m.callbackRelease
			return original(ctx, observer)
		}
	}
	registration, err := m.Meter.RegisterCallback(callback, observables...)
	if m.returnNil {
		if m.registration != nil {
			m.registration.Registration = registration
		}
		return nil, m.registerErr
	}
	if m.registration != nil {
		m.registration.Registration = registration
		if m.registerErr != nil {
			return m.registration, m.registerErr
		}
		return m.registration, err
	}
	if m.registerErr != nil {
		return registration, m.registerErr
	}
	return registration, err
}

func installLifetimeCallbackBarrier(t *testing.T, e *logsExporter, provider *sdkmetric.MeterProvider, entered chan struct{}, release <-chan struct{}) *lifetimeMeter {
	t.Helper()
	if e.telemetry.lifetimeReg != nil {
		if err := e.telemetry.lifetimeReg.Unregister(); err != nil {
			t.Fatalf("replace lifetime registration=%v", err)
		}
	}
	meter := &lifetimeMeter{
		Meter:           provider.Meter(metadata.ScopeName),
		registration:    &lifetimeRegistration{},
		callbackEnter:   entered,
		callbackRelease: release,
	}
	registration, err := e.telemetry.registerLifetime(meter, e.runtime)
	if err != nil {
		t.Fatalf("barrier lifetime registration=%v", err)
	}
	e.telemetry.lifetimeReg = registration
	return meter
}

func installLifetimeObserverBarrier(t *testing.T, e *logsExporter, provider *sdkmetric.MeterProvider, entered chan struct{}, release <-chan struct{}) *lifetimeMeter {
	t.Helper()
	if e.telemetry.lifetimeReg != nil {
		if err := e.telemetry.lifetimeReg.Unregister(); err != nil {
			t.Fatalf("replace lifetime registration=%v", err)
		}
	}
	meter := &lifetimeMeter{
		Meter:           provider.Meter(metadata.ScopeName),
		registration:    &lifetimeRegistration{},
		observerEnter:   entered,
		observerRelease: release,
	}
	registration, err := e.telemetry.registerLifetime(meter, e.runtime)
	if err != nil {
		t.Fatalf("observer barrier lifetime registration=%v", err)
	}
	e.telemetry.lifetimeReg = registration
	return meter
}

type lifetimeProvider struct {
	metric.MeterProvider
	meter metric.Meter
}

func (p *lifetimeProvider) Meter(string, ...metric.MeterOption) metric.Meter { return p.meter }

func TestTelemetryLifetimeConcurrentShutdown(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	clock := &lifetimeBarrierClock{
		base:    testclock.New(lifetimeOrigin+1_000_000_000, 1),
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	e, registrationMeter := lifetimeExporterWithRegistration(t, "netflow_v5", "concurrent", clock, reader)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(clock.release) }) }
	// Register this after lifetimeExporter so cleanup releases the callback
	// before the exporter cleanup can attempt its terminal shutdown.
	t.Cleanup(release)
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if got := registrationMeter.registers.Load(); got != 1 || registrationMeter.observables.Load() != 2 {
		t.Fatalf("lifetime registration calls=%d instruments=%d want one/two", got, registrationMeter.observables.Load())
	}
	clock.calls.Store(0)
	clock.blocked.Store(true)
	collectDone := make(chan struct{})
	go func() {
		var rm metricdata.ResourceMetrics
		_ = reader.Collect(context.Background(), &rm)
		close(collectDone)
	}()
	waitLifecycleSignal(t, clock.entered)
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- e.Shutdown(context.Background()) }()
	secondShutdownDone := make(chan error, 1)
	go func() { secondShutdownDone <- e.Shutdown(context.Background()) }()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before the registered callback released")
	case <-time.After(100 * time.Millisecond):
	}
	if got := clock.calls.Load(); got != 1 {
		t.Fatalf("lifetime callback clock samples=%d want one", got)
	}
	release()
	waitLifecycleSignal(t, collectDone)
	shutdownErr := waitLifecycleError(t, "shutdown after callback release", shutdownDone)
	if shutdownErr != nil {
		t.Fatal(shutdownErr)
	}
	if secondErr := waitLifecycleError(t, "concurrent shutdown completion", secondShutdownDone); secondErr != nil {
		t.Fatal(secondErr)
	}
	if got := collectLifetime(t, reader); len(got.remaining) != 0 || len(got.exhausted) != 0 {
		t.Fatalf("callback survived successful shutdown=%+v", got)
	}
	if got := clock.calls.Load(); got != 1 {
		t.Fatalf("post-shutdown collection invoked callback clock samples=%d", got)
	}
	if got := registrationMeter.registration.unregisters.Load(); got != 1 {
		t.Fatalf("successful shutdown unregister calls=%d want one", got)
	}

	partial := &lifetimeRegistration{skipUnderlying: true}
	baseProvider := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = baseProvider.Shutdown(context.Background()) })
	failingMeter := &lifetimeMeter{Meter: baseProvider.Meter("test-failing"), registration: partial, registerErr: errors.New("provider secret")}
	provider := &lifetimeProvider{MeterProvider: baseProvider, meter: failingMeter}
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.MeterProvider = provider
	_, err := newLogsExporter(context.Background(), set, validConfig("netflow_v5"), testclock.New(lifetimeOrigin, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:4739")), nil
	})
	if err == nil || err.Error() != "netflow: telemetry initialization failed" || partial.unregisters.Load() != 1 {
		t.Fatalf("registration failure err=%v unregisters=%d", err, partial.unregisters.Load())
	}
	if partial.Registration == nil {
		t.Fatal("registration failure unexpectedly removed the underlying SDK handle")
	}
	cleanupLifetimeRegistration(t, partial)

	nilRegistration := &lifetimeRegistration{}
	// Keep the constructor's Meter real: metadata.NewTelemetryBuilder uses it
	// before registerLifetime. This fake controls only the nil registration and
	// registration error returned by the SDK boundary.
	nilRegistrationMeter := &lifetimeMeter{Meter: baseProvider.Meter("test-nil"), registration: nilRegistration, registerErr: errors.New("provider nil"), returnNil: true}
	nilProvider := &lifetimeProvider{MeterProvider: baseProvider, meter: nilRegistrationMeter}
	set.MeterProvider = nilProvider
	if _, err := newLogsExporter(context.Background(), set, validConfig("netflow_v5"), testclock.New(lifetimeOrigin, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:4739")), nil
	}); err == nil || err.Error() != "netflow: telemetry initialization failed" {
		t.Fatalf("nil registration error=%v", err)
	}
	if nilRegistration.unregisters.Load() != 0 {
		t.Fatalf("nil registration unexpectedly invoked wrapper unregister=%d", nilRegistration.unregisters.Load())
	}
	cleanupLifetimeRegistration(t, nilRegistration)
	// Exercise the defensive nil-meter guard directly on a built exporter;
	// the constructor path above always supplies a real Meter and only
	// controls the returned registration/error contract.
	nilMeterFixture := newLifetimeFixture(t, "netflow_v5", mapping.ProfileV5, "nil-meter-guard", ptr(lifetimeOrigin))
	if _, err := nilMeterFixture.e.telemetry.registerLifetime(nil, nilMeterFixture.e.runtime); err != errLifetimeTelemetryInit {
		t.Fatalf("nil meter guard error=%v", err)
	}

	cleanupReg := &lifetimeRegistration{err: errors.New("provider secret"), skipUnderlying: true}
	cleanupMeter := &lifetimeMeter{Meter: baseProvider.Meter("test-cleanup"), registration: cleanupReg}
	cleanupProvider := &lifetimeProvider{MeterProvider: baseProvider, meter: cleanupMeter}
	set.MeterProvider = cleanupProvider
	cleanup, err := newLogsExporter(context.Background(), set, validConfig("netflow_v5"), testclock.New(lifetimeOrigin, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:4739")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup.Shutdown(context.Background()) })
	if err := cleanup.Shutdown(context.Background()); err == nil || err.Error() != "netflow: shutdown failed" || cleanupReg.unregisters.Load() != 1 {
		t.Fatalf("unregister failure err=%v calls=%d", err, cleanupReg.unregisters.Load())
	}
	if cleanupReg.Registration == nil {
		t.Fatal("failed unregister control claimed successful underlying removal")
	}
	cleanupLifetimeRegistration(t, cleanupReg)

	// The runtime drain timeout remains the primary shutdown result while the
	// wrapper still unregisters the callback after the admitted call releases.
	timeoutReader := sdkmetric.NewManualReader()
	timeoutProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(timeoutReader))
	t.Cleanup(func() { _ = timeoutProvider.Shutdown(context.Background()) })
	timeoutReg := &lifetimeRegistration{err: errors.New("provider timeout"), skipUnderlying: true}
	timeoutMeter := &lifetimeMeter{Meter: timeoutProvider.Meter("test-timeout"), registration: timeoutReg}
	timeoutProviderWrapper := &lifetimeProvider{MeterProvider: timeoutProvider, meter: timeoutMeter}
	timeoutSet := exportertest.NewNopSettings(NewFactory().Type())
	timeoutSet.ID = component.NewIDWithName(NewFactory().Type(), "runtime-timeout")
	timeoutSet.MeterProvider = timeoutProviderWrapper
	timeoutConfig := validConfig("netflow_v5")
	timeoutConn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(timeoutConfig.Endpoint), bootstrapSteps("netflow_v5")...)
	timeout, err := newLogsExporter(context.Background(), timeoutSet, timeoutConfig, testclock.New(lifetimeOrigin+1_000_000_000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return timeoutConn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = timeout.Shutdown(context.Background()) })
	if err := timeout.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	canceledCtx, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	if err := timeout.ConsumeLogs(canceledCtx, testpdata.CanonicalLogs()); err == nil || (!errors.Is(err, context.Canceled) && !errors.Is(err, destination.ErrRuntimeUnavailable)) {
		t.Fatalf("canceled request=%v", err)
	}
	entered, admittedRelease, consumeDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var admittedReleaseOnce sync.Once
	releaseAdmitted := func() { admittedReleaseOnce.Do(func() { close(admittedRelease) }) }
	// This cleanup is registered after the exporter cleanup above, so LIFO
	// ordering releases an admitted call before terminal Shutdown can drain it.
	t.Cleanup(releaseAdmitted)
	go func() {
		consumeDone <- timeout.runtime.Consume(context.Background(), func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			<-admittedRelease
			return ctx.Err()
		})
	}()
	waitLifecycleSignal(t, entered)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = timeout.Shutdown(shutdownCtx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runtime timeout=%v", err)
	}
	if got := timeoutReg.unregisters.Load(); got != 1 {
		t.Fatalf("timeout unregister calls=%d want one before admitted drain", got)
	}
	releaseAdmitted()
	if err := waitLifecycleError(t, "admitted Consume cancellation", consumeDone); err == nil {
		t.Fatal("canceled admitted call unexpectedly succeeded")
	}
	shutdownResults := make(chan error, 2)
	go func() { shutdownResults <- timeout.Shutdown(context.Background()) }()
	go func() { shutdownResults <- timeout.Shutdown(context.Background()) }()
	for i := 0; i < 2; i++ {
		if err := waitLifecycleError(t, "post-drain concurrent shutdown", shutdownResults); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout result changed after drain=%v", err)
		}
	}
	cleanupLifetimeRegistration(t, timeoutReg)

	// Cancellation must interrupt a real writer while observation remains
	// independent, and the returned subset must preserve ambiguous/unsent
	// accounting without adding a rejection for the valid unsent sibling.
	t.Run("blocked-send-cancellation-and-subset", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
		c := validConfig("netflow_v5")
		c.Endpoint = "127.0.0.1:4739"
		c.UptimeOrigin = ptr(rejectionOrigin)
		c.MaxRecordsPerMessage = ptr(uint16(1))
		set := exportertest.NewNopSettings(NewFactory().Type())
		set.ID = component.NewIDWithName(NewFactory().Type(), "concurrent-blocked-send")
		set.MeterProvider = provider
		writeStarted := make(chan struct{})
		writeRelease := make(chan struct{})
		conn := testtransport.NewConn(
			netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint),
			append(bootstrapSteps("netflow_v5"), testtransport.WriteStep{Started: writeStarted, Wait: writeRelease})...,
		)
		e, err := newLogsExporter(context.Background(), set, c, testclock.New(rejectionOrigin+3_000_000_000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(writeRelease) }) }
		t.Cleanup(release)
		if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		logs := rejectionLogs(t,
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 0) },
			func(record plog.LogRecord) {
				record.Attributes().PutInt("ordinal", 1)
				record.Body().SetStr("blocked invalid")
			},
			func(record plog.LogRecord) { record.Attributes().PutInt("ordinal", 2) },
		)
		before := collectMetric(t, reader)
		sentBefore := helperSentRecords(t, reader)
		failedBefore := helperFailedRecords(t, reader)
		consumeCtx, cancelConsume := context.WithCancel(context.Background())
		consumeDone := make(chan error, 1)
		go func() { consumeDone <- e.ConsumeLogs(consumeCtx, logs) }()
		select {
		case <-writeStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("blocked writer did not start")
		}
		observationDone := make(chan error, 1)
		go func() {
			var rm metricdata.ResourceMetrics
			observationDone <- reader.Collect(context.Background(), &rm)
		}()
		select {
		case err := <-observationDone:
			if err != nil {
				t.Fatalf("observation while send blocked=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("observation waited behind blocked send")
		}
		cancelConsume()
		var consumeErr error
		select {
		case consumeErr = <-consumeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("canceled blocked consume did not finish")
		}
		if consumeErr == nil {
			t.Fatal("canceled blocked consume unexpectedly succeeded")
		}
		subset, ok := errors.AsType[consumererror.Logs](consumeErr)
		if !ok {
			t.Fatalf("blocked cancellation error type=%T", consumeErr)
		}
		if subset.Data().LogRecordCount() != 2 {
			t.Fatalf("blocked cancellation subset records=%d want ambiguous plus valid unsent", subset.Data().LogRecordCount())
		}
		requireLifetimeSubsetOrdinals(t, subset.Data(), []int64{0, 2})
		delta := metricDelta(collectMetric(t, reader), before)
		if delta[metricKey("records", "exporter=netflow/concurrent-blocked-send", "outcome=ambiguous")] != 1 ||
			delta[metricKey("records", "exporter=netflow/concurrent-blocked-send", "outcome=invalid")] != 1 ||
			delta[metricKey("records", "exporter=netflow/concurrent-blocked-send", "outcome=unsent")] != 1 {
			t.Fatalf("blocked cancellation record delta=%v", delta)
		}
		if got := rejectionReasonDelta(delta, "netflow/concurrent-blocked-send"); len(got) != 1 || got["unsupported_body"] != 1 {
			t.Fatalf("rejection accounting=%v, want only the invalid sibling", got)
		}
		if got := helperSentRecords(t, reader) - sentBefore; got != 0 {
			t.Fatalf("blocked cancellation helper sent delta=%d want 0", got)
		}
		if got := helperFailedRecords(t, reader) - failedBefore; got != 3 {
			t.Fatalf("blocked cancellation helper failed delta=%d want 3", got)
		}
		release()
		cancelConsume()
		if err := e.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("collection-barrier-refresh-and-replacement", func(t *testing.T) {
		const limitMS = uint64(math.MaxUint32) + 1
		t.Run("observer-coherent-successful-replacement", func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
				testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.11")}},
			)
			var published atomic.Int32
			secondPublished := make(chan struct{})
			var secondOnce sync.Once
			e, fixture := conditionalExporterWithHook(t, provider, "netflow_v5", "concurrent-observer-replacement", "collector.example", lookup, []conditionalDialPlan{
				{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}}},
				{},
			}, func(event destination.Event) {
				if event == destination.EpochPublished && published.Add(1) == 2 {
					secondOnce.Do(func() { close(secondPublished) })
				}
			})
			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			if got := published.Load(); got != 1 {
				t.Fatalf("initial published epochs=%d want 1", got)
			}
			limitWall := rejectionOrigin + limitMS*1_000_000
			fixture.clock.Set(limitWall-1_000_000, 0)
			if err := e.pushLogs(context.Background(), lifetimeLogs(rejectionOrigin)); err != nil {
				t.Fatalf("old epoch legal edge=%v", err)
			}
			fixture.clock.Set(limitWall, 0)
			if err := e.pushLogs(context.Background(), lifetimeLogs(rejectionOrigin)); err == nil {
				t.Fatal("old published epoch did not latch at uptime limit")
			}
			// Keep the replacement sample at the exhausted wall. The old
			// endpoint remains latched while the candidate gets a fresh epoch.
			fixture.clock.Set(limitWall, uint64(time.Second))
			waitConditionalTimer(t, fixture.timers[0])

			observerEntered := make(chan struct{})
			observerRelease := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(observerRelease) }) }
			// Release is registered after the exporter cleanup from the
			// conditional fixture, so a failure cannot strand its callback.
			t.Cleanup(release)
			installLifetimeObserverBarrier(t, e, provider, observerEntered, observerRelease)

			collectionDone := make(chan error, 1)
			var captured metricdata.ResourceMetrics
			go func() { collectionDone <- reader.Collect(context.Background(), &captured) }()
			waitLifecycleSignal(t, observerEntered)
			if !fixture.timers[0].Fire() {
				t.Fatal("successful replacement timer did not fire")
			}
			waitLifecycleSignal(t, secondPublished)
			release()
			if err := waitLifecycleError(t, "observer-barrier collection", collectionDone); err != nil {
				t.Fatal(err)
			}

			// Runtime.Lifetime was copied before the callback reached its first
			// observation. Even though publication changed while blocked, the
			// released Int64 point belongs to the old latched snapshot.
			first := lifetimeValuesFromResourceMetrics(t, &captured)
			requireLifetimePoint(t, first, 0, 1)
			requireLifetimeIdentity(t, first, "netflow/concurrent-observer-replacement")
			if got := published.Load(); got != 2 {
				t.Fatalf("successful replacement published epochs=%d want 2", got)
			}
			fixture.dialer.mu.Lock()
			connectionCount := len(fixture.dialer.conns)
			fixture.dialer.mu.Unlock()
			if connectionCount != 2 {
				t.Fatalf("successful replacement connections=%d want 2", connectionCount)
			}

			// A subsequent collection reads the new candidate's fresh state:
			// the old latch did not cross the epoch seam, so the same expired
			// wall projects as quiet 0/0 instead of exhausted 0/1.
			next := collectLifetime(t, reader)
			requireLifetimePoint(t, next, 0, 0)
			// The old state had reserved the final legal wall before latching.
			// Rewinding the new epoch into its valid window proves that
			// reservation floor was private to the retired state.
			fixture.clock.Set(rejectionOrigin+3_000_000_000, 2*uint64(time.Second))
			fresh := collectLifetime(t, reader)
			if len(fresh.remaining) != 1 || fresh.remaining[0].Value <= 0 || len(fresh.exhausted) != 1 || fresh.exhausted[0].Value != 0 {
				t.Fatalf("new replacement lifetime=%+v", fresh)
			}
			requireLifetimeIdentity(t, next, "netflow/concurrent-observer-replacement")
			requireLifetimeIdentity(t, fresh, "netflow/concurrent-observer-replacement")
		})

		t.Run("refresh", func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			refreshFailed := make(chan struct{})
			var refreshOnce sync.Once
			e, fixture := conditionalExporterWithHook(t, provider, "netflow_v9", "concurrent-refresh", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: conditionalFullSteps("netflow_v9")}}, func(event destination.Event) {
				if event == destination.RefreshFailed {
					refreshOnce.Do(func() { close(refreshFailed) })
				}
			})
			callbackEntered := make(chan struct{})
			callbackRelease := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(callbackRelease) }) }
			// Register release before any callback registration can fail, and
			// keep it after exporter cleanup so LIFO cleanup cannot deadlock.
			t.Cleanup(release)
			installLifetimeCallbackBarrier(t, e, provider, callbackEntered, callbackRelease)
			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			waitConditionalTimer(t, fixture.timers[0])
			collectionDone := make(chan error, 1)
			go func() {
				var rm metricdata.ResourceMetrics
				collectionDone <- reader.Collect(context.Background(), &rm)
			}()
			select {
			case <-callbackEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("refresh collection did not enter callback barrier")
			}
			wall, mono := fixture.clock.Now()
			fixture.clock.Set(wall+limitMS*1_000_000, mono+uint64(30*time.Second))
			if !fixture.timers[0].Fire() {
				t.Fatal("refresh timer did not fire")
			}
			waitConditionalDone(t, refreshFailed)
			release()
			select {
			case err := <-collectionDone:
				if err != nil {
					t.Fatalf("refresh collection=%v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("refresh collection did not finish after release")
			}
			requireLifetimePoint(t, collectLifetime(t, reader), 0, 1)
			if metrics := localMetrics(t, reader); metrics[metricKey("failures", "exporter=netflow/concurrent-refresh", "reason=refresh")] != 1 {
				t.Fatalf("concurrent refresh metrics=%v", metrics)
			}
		})

		t.Run("replacement", func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			candidateFailed := make(chan struct{})
			var candidateOnce sync.Once
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
				testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.11")}},
			)
			initialSteps := append(conditionalFullSteps("netflow_v5"), testtransport.WriteStep{N: packetLength("netflow_v5")})
			e, fixture := conditionalExporterWithHook(t, provider, "netflow_v5", "concurrent-replacement", "collector.example", lookup, []conditionalDialPlan{{steps: initialSteps}, {err: errors.New("replacement private failure")}}, func(event destination.Event) {
				if event == destination.CandidateFailed {
					candidateOnce.Do(func() { close(candidateFailed) })
				}
			})
			callbackEntered := make(chan struct{})
			callbackRelease := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(callbackRelease) }) }
			// Register release before any callback registration can fail, and
			// keep it after exporter cleanup so LIFO cleanup cannot deadlock.
			t.Cleanup(release)
			installLifetimeCallbackBarrier(t, e, provider, callbackEntered, callbackRelease)
			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			limitWall := rejectionOrigin + limitMS*1_000_000
			fixture.clock.Set(limitWall, 2)
			if err := e.pushLogs(context.Background(), lifetimeLogs(rejectionOrigin)); err == nil {
				t.Fatal("published replacement baseline did not latch old state")
			}
			waitConditionalTimer(t, fixture.timers[0])
			collectionDone := make(chan error, 1)
			go func() {
				var rm metricdata.ResourceMetrics
				collectionDone <- reader.Collect(context.Background(), &rm)
			}()
			select {
			case <-callbackEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("replacement collection did not enter callback barrier")
			}
			fixture.clock.Advance(0, uint64(time.Second))
			if !fixture.timers[0].Fire() {
				t.Fatal("replacement timer did not fire")
			}
			waitConditionalDone(t, candidateFailed)
			release()
			select {
			case err := <-collectionDone:
				if err != nil {
					t.Fatalf("replacement collection=%v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("replacement collection did not finish after release")
			}
			requireLifetimePoint(t, collectLifetime(t, reader), 0, 1)
			if metrics := localMetrics(t, reader); metrics[metricKey("failures", "exporter=netflow/concurrent-replacement", "reason=candidate")] != 1 {
				t.Fatalf("concurrent replacement metrics=%v", metrics)
			}
		})
	})

	// A disabled provider is still a valid wrapper construction and cleanup
	// path; it simply yields no SDK observations.
	noopSet := exportertest.NewNopSettings(NewFactory().Type())
	noopSet.MeterProvider = metricnoop.NewMeterProvider()
	noop, err := newLogsExporter(context.Background(), noopSet, validConfig("netflow_v5"), testclock.New(lifetimeOrigin, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:4739")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noop.Shutdown(context.Background()) })
	if err := noop.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err := noop.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
