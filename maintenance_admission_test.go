package netflowexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
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
)

type maintenanceFixture struct {
	exporter *logsExporter
	conn     *testtransport.Conn
	clock    *testclock.Clock
	timer    *testclock.Timer
	helper   *countHelper
	reader   *sdkmetric.ManualReader
	release  func()
}

func newMaintenanceFixture(t *testing.T, protocol string, release chan struct{}, steps ...testtransport.WriteStep) *maintenanceFixture {
	return newMaintenanceFixtureConfig(t, protocol, validConfig(protocol), release, steps...)
}

func newMaintenanceFixtureConfig(t *testing.T, protocol string, c *Config, release chan struct{}, steps ...testtransport.WriteStep) *maintenanceFixture {
	t.Helper()
	c.Templates.RefreshInterval = 30 * time.Second
	clock := testclock.New(1788220802000000000, 1)
	timer := testclock.NewTimer()
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint), steps...)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), "maintenance")
	set.MeterProvider = provider
	e, err := newLogsExporterWithTimer(context.Background(), set, c, clock,
		func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil },
		func(time.Duration) transport.Timer { return timer })
	if err != nil {
		t.Fatal(err)
	}
	helper := &countHelper{Logs: e.helper}
	e.helper = helper
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseGate()
		_ = e.Shutdown(context.Background())
		_ = provider.Shutdown(context.Background())
	})
	return &maintenanceFixture{exporter: e, conn: conn, clock: clock, timer: timer, helper: helper, reader: reader, release: releaseGate}
}

func maintenanceTemplateLength(protocol string) int {
	if protocol == "netflow_v9" {
		return 100
	}
	return 104
}

func maintenanceDataLength(protocol string) int {
	if protocol == "netflow_v9" {
		return 68
	}
	return 92
}

func maintenanceBootstrapSteps(protocol string) []testtransport.WriteStep {
	step := maintenanceTemplateLength(protocol)
	return []testtransport.WriteStep{{N: step}, {N: step}, {N: step}, {N: step}}
}

func (f *maintenanceFixture) start(t *testing.T) {
	t.Helper()
	if err := f.exporter.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	maintenanceWaitTimer(t, f.timer, 1)
}

func maintenanceWaitTimer(t *testing.T, timer *testclock.Timer, count int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		delays, stopped, changed := timer.Snapshot()
		if stopped && len(delays) != 0 {
			t.Fatalf("maintenance timer stopped before reset %d", count)
		}
		if len(delays) >= count {
			if len(delays) != count {
				t.Fatalf("unexpected timer resets %v", delays)
			}
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("maintenance timer did not reset %d", count)
		}
	}
}

func (f *maintenanceFixture) gateRefresh(t *testing.T, entered chan struct{}) {
	t.Helper()
	f.clock.Advance(0, uint64(30*time.Second))
	if !f.timer.Fire() {
		t.Fatal("maintenance timer was not armed")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not reach write gate")
	}
}

func maintenanceWaitHelper(t *testing.T, helper *countHelper) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for helper.consumes.Load() == 0 {
		select {
		case <-deadline.C:
			t.Fatal("public caller did not enter helper")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func maintenanceAssertPending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("admitted caller returned while maintenance was gated: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func maintenanceWaitDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("public caller did not complete")
		return nil
	}
}

func maintenanceCleanupCall(t *testing.T, release func(), done <-chan error, joined *bool) {
	t.Helper()
	t.Cleanup(func() {
		release()
		if *joined {
			return
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("public caller did not join during cleanup")
		}
	})
}

func maintenanceDataWrites(conn *testtransport.Conn) []testtransport.Event {
	return conn.Writes()
}

func TestMaintenanceAdmissionWait(t *testing.T) {
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			template, data := maintenanceTemplateLength(protocol), maintenanceDataLength(protocol)
			entered := make(chan struct{})
			release := make(chan struct{})
			steps := maintenanceBootstrapSteps(protocol)
			steps = append(steps, testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
			f := newMaintenanceFixture(t, protocol, release, steps...)
			f.start(t)
			f.clock.Advance(0, uint64(30*time.Second))
			if !f.timer.Fire() {
				t.Fatal("maintenance timer was not armed")
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("refresh did not reach write gate")
			}
			logs := testpdata.CanonicalLogs()
			before, err := normalize.Inspect(logs)
			if err != nil {
				t.Fatal(err)
			}
			logs.MarkReadOnly()
			done := make(chan error, 1)
			joined := false
			go func() {
				defer close(done)
				done <- f.exporter.ConsumeLogs(context.Background(), logs)
			}()
			maintenanceCleanupCall(t, f.release, done, &joined)
			maintenanceWaitHelper(t, f.helper)
			maintenanceAssertPending(t, done)
			if err := f.exporter.ConsumeLogs(context.Background(), nilLogs()); !errors.Is(err, destination.ErrRuntimeBusy) {
				t.Fatalf("second public call = %v", err)
			}
			f.release()
			if err := maintenanceWaitDone(t, done); err != nil {
				t.Fatal(err)
			}
			joined = true
			if f.helper.consumes.Load() != 1 {
				t.Fatalf("helper calls=%d, want one admitted call", f.helper.consumes.Load())
			}
			after, err := normalize.Inspect(logs)
			if err != nil || after != before {
				t.Fatalf("input changed: before=%+v after=%+v err=%v", before, after, err)
			}
			writes := maintenanceDataWrites(f.conn)
			if len(writes) != 7 {
				t.Fatalf("writes=%d, want four bootstrap, two refresh, one data", len(writes))
			}
			if protocol == "netflow_v9" {
				for i, want := range []uint32{0, 1, 2, 3, 4, 5, 6} {
					if got := binary.BigEndian.Uint32(writes[i].Payload[12:16]); got != want {
						t.Fatalf("v9 write %d sequence=%d, want %d", i, got, want)
					}
				}
			} else {
				for i, packet := range writes {
					if got := binary.BigEndian.Uint32(packet.Payload[8:12]); got != 0 {
						t.Fatalf("IPFIX write %d sequence=%d, want 0", i, got)
					}
				}
			}
			header := 20
			if protocol == "ipfix" {
				header = 16
			}
			if !bytes.Equal(writes[0].Payload[header:], writes[4].Payload[header:]) || !bytes.Equal(writes[1].Payload[header:], writes[5].Payload[header:]) {
				t.Fatal("refresh template IDs or shapes changed")
			}
			wantSetID := uint16(0)
			if protocol == "ipfix" {
				wantSetID = 2
			}
			for i, wantTemplateID := range []uint16{256, 257} {
				if got := binary.BigEndian.Uint16(writes[i].Payload[header : header+2]); got != wantSetID {
					t.Fatalf("template %d set ID=%d, want %d", i, got, wantSetID)
				}
				if got := binary.BigEndian.Uint16(writes[i].Payload[header+4 : header+6]); got != wantTemplateID {
					t.Fatalf("template %d ID=%d, want %d", i, got, wantTemplateID)
				}
			}
			if got := binary.BigEndian.Uint16(writes[6].Payload[header : header+2]); got != 256 {
				t.Fatalf("data Set ID=%d, want template 256", got)
			}
			metrics := localMetrics(t, f.reader)
			requireMetric(t, metrics, "admission", 1, "exporter=netflow/maintenance", "reason=accepted")
			requireMetric(t, metrics, "admission", 1, "exporter=netflow/maintenance", "reason=busy")
			requireMetric(t, metrics, "admission", 0, "exporter=netflow/maintenance", "reason=preflight")
			requireMetric(t, metrics, "failures", 0, "exporter=netflow/maintenance", "reason=busy")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/maintenance", "outcome=confirmed")
			requireMetric(t, metrics, "data_messages", 1, "exporter=netflow/maintenance", "outcome=confirmed")
		})
	}
}

func nilLogs() plog.Logs { return plog.Logs{} }

func maintenanceAmbiguousLogs() plog.Logs {
	logs := plog.NewLogs()
	canonical := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	records := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for ordinal := 0; ordinal < 3; ordinal++ {
		record := records.AppendEmpty()
		canonical.CopyTo(record)
		record.Attributes().PutInt("ordinal", int64(ordinal))
		if ordinal == 1 {
			record.Body().SetStr("unsupported raw secret")
		}
	}
	return logs
}

func TestMaintenanceAdmissionCancel(t *testing.T) {
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			template, data := maintenanceTemplateLength(protocol), maintenanceDataLength(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			steps := append(maintenanceBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
			f := newMaintenanceFixture(t, protocol, release, steps...)
			f.start(t)
			f.clock.Advance(0, uint64(30*time.Second))
			if !f.timer.Fire() {
				t.Fatal("maintenance timer was not armed")
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("refresh did not reach write gate")
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			joined := false
			go func() {
				defer close(done)
				done <- f.exporter.ConsumeLogs(ctx, testpdata.CanonicalLogs())
			}()
			maintenanceCleanupCall(t, f.release, done, &joined)
			maintenanceWaitHelper(t, f.helper)
			cancel()
			if err := maintenanceWaitDone(t, done); !errors.Is(err, destination.ErrRuntimeUnavailable) {
				t.Fatalf("canceled public call = %v", err)
			}
			joined = true
			metrics := localMetrics(t, f.reader)
			requireMetric(t, metrics, "failures", 1, "exporter=netflow/maintenance", "reason=unavailable")
			f.release()
			maintenanceWaitTimer(t, f.timer, 2)
			if writes := len(maintenanceDataWrites(f.conn)); writes != 6 {
				t.Fatalf("canceled call wrote %d datagrams, want bootstrap plus refresh", writes)
			}
			if err := f.exporter.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
				t.Fatalf("later call after cancellation = %v", err)
			}
			if writes := len(maintenanceDataWrites(f.conn)); writes != 7 {
				t.Fatalf("later call wrote %d datagrams, want one data packet", writes)
			}
		})
	}
}

func TestMaintenanceAdmissionShutdown(t *testing.T) {
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			template, data := maintenanceTemplateLength(protocol), maintenanceDataLength(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			steps := append(maintenanceBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
			f := newMaintenanceFixture(t, protocol, release, steps...)
			f.start(t)
			f.clock.Advance(0, uint64(30*time.Second))
			if !f.timer.Fire() {
				t.Fatal("maintenance timer was not armed")
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("refresh did not reach write gate")
			}
			done := make(chan error, 1)
			doneJoined := false
			go func() {
				defer close(done)
				done <- f.exporter.ConsumeLogs(context.Background(), testpdata.CanonicalLogs())
			}()
			maintenanceWaitHelper(t, f.helper)
			shutdown := make(chan error, 1)
			shutdownJoined := false
			go func() {
				defer close(shutdown)
				shutdown <- f.exporter.Shutdown(context.Background())
			}()
			t.Cleanup(func() {
				f.release()
				if !doneJoined {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Errorf("public shutdown caller did not join during cleanup")
					}
				}
				if !shutdownJoined {
					select {
					case <-shutdown:
					case <-time.After(2 * time.Second):
						t.Errorf("public shutdown did not join during cleanup")
					}
				}
			})
			if err := maintenanceWaitDone(t, done); !errors.Is(err, destination.ErrRuntimeClosed) {
				t.Fatalf("shutdown public call = %v", err)
			}
			doneJoined = true
			if err := maintenanceWaitDone(t, shutdown); err != nil {
				t.Fatal(err)
			}
			shutdownJoined = true
			f.release()
			if writes := len(maintenanceDataWrites(f.conn)); writes != 5 {
				t.Fatalf("shutdown wrote %d datagrams, want close before second refresh/data", writes)
			}
			if err := f.exporter.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); !errors.Is(err, destination.ErrRuntimeClosed) {
				t.Fatalf("post-shutdown call = %v", err)
			}
		})
	}
}

func TestMaintenanceAdmissionAmbiguousHandoff(t *testing.T) {
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			template, data := maintenanceTemplateLength(protocol), maintenanceDataLength(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			steps := append(maintenanceBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: 1, Err: errors.New("ambiguous")})
			c := validConfig(protocol)
			c.MaxRecordsPerMessage = ptr(uint16(1))
			f := newMaintenanceFixtureConfig(t, protocol, c, release, steps...)
			f.start(t)
			f.clock.Advance(0, uint64(30*time.Second))
			if !f.timer.Fire() {
				t.Fatal("maintenance timer was not armed")
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("refresh did not reach write gate")
			}
			done := make(chan error, 1)
			joined := false
			logs := maintenanceAmbiguousLogs()
			go func() {
				defer close(done)
				done <- f.exporter.ConsumeLogs(context.Background(), logs)
			}()
			maintenanceCleanupCall(t, f.release, done, &joined)
			maintenanceWaitHelper(t, f.helper)
			f.release()
			err := maintenanceWaitDone(t, done)
			joined = true
			subset, ok := errors.AsType[consumererror.Logs](err)
			if !ok {
				t.Fatalf("ambiguous handoff type=%T error=%v", err, err)
			}
			if consumererror.IsPermanent(err) {
				t.Fatalf("ambiguous handoff unexpectedly permanent: %v", err)
			}
			if subset.Data().LogRecordCount() != 2 {
				t.Fatalf("ambiguous handoff = %v, subset records=%d", err, subset.Data().LogRecordCount())
			}
			cursor := logCursor{logs: subset.Data()}
			for index, want := range []int64{0, 2} {
				record, ok := cursor.at(uint64(index))
				if !ok {
					t.Fatalf("ambiguous subset lost retained record %d", index)
				}
				ordinal, ok := record.Attributes().Get("ordinal")
				if !ok || ordinal.Int() != want {
					t.Fatalf("ambiguous subset ordinal=%v, want %d", ordinal, want)
				}
			}
			metrics := localMetrics(t, f.reader)
			requireMetric(t, metrics, "records", 0, "exporter=netflow/maintenance", "outcome=confirmed")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/maintenance", "outcome=invalid")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/maintenance", "outcome=ambiguous")
			requireMetric(t, metrics, "records", 1, "exporter=netflow/maintenance", "outcome=unsent")
			requireMetric(t, metrics, "admission", 1, "exporter=netflow/maintenance", "reason=accepted")
			requireMetric(t, metrics, "admission", 0, "exporter=netflow/maintenance", "reason=preflight")
			writes := maintenanceDataWrites(f.conn)
			if len(writes) != 7 {
				t.Fatalf("ambiguous handoff wrote %d datagrams, want no retry", len(writes))
			}
			dataHeader := 12
			if protocol == "ipfix" {
				dataHeader = 8
			}
			firstSequence := binary.BigEndian.Uint32(writes[6].Payload[dataHeader : dataHeader+4])
			if err := f.conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
				t.Fatal(err)
			}
			if err := f.exporter.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
				t.Fatalf("later valid handoff = %v", err)
			}
			writes = maintenanceDataWrites(f.conn)
			if len(writes) != 8 {
				t.Fatalf("later valid handoff wrote %d datagrams, want one additional data packet", len(writes))
			}
			secondSequence := binary.BigEndian.Uint32(writes[7].Payload[dataHeader : dataHeader+4])
			if secondSequence != firstSequence {
				t.Fatalf("ambiguous sequence advanced: first=%d later=%d", firstSequence, secondSequence)
			}
		})
	}
}
