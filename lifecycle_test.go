package netflowexporter

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
)

// lifecycleGateHelper is installed around the already constructed Collector
// helper. It keeps the test at the public exporter boundary while providing a
// deterministic point before the inner helper traverses pdata. Shutdown
// records whether the admitted call has completely returned before helper
// shutdown begins.
type lifecycleGateHelper struct {
	exporter.Logs

	entered     chan struct{}
	release     chan struct{}
	done        chan struct{}
	postEntered chan struct{}
	postRelease chan struct{}

	enterOnce             sync.Once
	releaseOnce           sync.Once
	doneOnce              sync.Once
	postEnteredOnce       sync.Once
	postReleaseOnce       sync.Once
	entries               atomic.Int32
	shutdowns             atomic.Int32
	shutdownBeforeConsume atomic.Bool
}

func (h *lifecycleGateHelper) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	h.entries.Add(1)
	h.enterOnce.Do(func() { close(h.entered) })
	select {
	case <-h.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer h.doneOnce.Do(func() { close(h.done) })
	err := h.Logs.ConsumeLogs(ctx, logs)
	if h.postRelease != nil {
		h.postEnteredOnce.Do(func() { close(h.postEntered) })
		<-h.postRelease
	}
	return err
}

func (h *lifecycleGateHelper) Shutdown(ctx context.Context) error {
	h.shutdowns.Add(1)
	select {
	case <-h.done:
	default:
		h.shutdownBeforeConsume.Store(true)
	}
	return h.Logs.Shutdown(ctx)
}

func (h *lifecycleGateHelper) releaseNow() {
	h.releaseOnce.Do(func() { close(h.release) })
}

func (h *lifecycleGateHelper) releasePostNow() {
	if h.postRelease != nil {
		h.postReleaseOnce.Do(func() { close(h.postRelease) })
	}
}

func (h *lifecycleGateHelper) releaseAll() {
	h.releaseNow()
	h.releasePostNow()
}

func waitLifecycleSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle signal did not arrive")
	}
}

func lifecycleCall(t *testing.T, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle call did not return")
		return nil
	}
}

func lifecycleSteps(protocol string, data int) []testtransport.WriteStep {
	steps := append([]testtransport.WriteStep(nil), bootstrapSteps(protocol)...)
	steps = append(steps, testtransport.WriteStep{N: data})
	return steps
}

func sequenceOffset(protocol string) int {
	switch protocol {
	case "netflow_v5":
		return 16
	case "netflow_v9":
		return 12
	default:
		return 8
	}
}

func assertDataSequence(t *testing.T, protocol string, conn *countedConn, want int) {
	t.Helper()
	writes := conn.Writes()
	bootstrap := len(bootstrapSteps(protocol))
	if len(writes) != bootstrap+want {
		t.Fatalf("%s writes = %d, want %d", protocol, len(writes), bootstrap+want)
	}
	offset := sequenceOffset(protocol)
	wantFirst := uint32(0)
	if protocol == "netflow_v9" {
		wantFirst = uint32(bootstrap)
	}
	var first uint32
	for i := 0; i < want; i++ {
		payload := writes[bootstrap+i].Payload
		if len(payload) < offset+4 {
			t.Fatalf("%s data packet %d is too short: %d", protocol, i, len(payload))
		}
		sequence := binary.BigEndian.Uint32(payload[offset : offset+4])
		if i == 0 {
			first = sequence
			if first != wantFirst {
				t.Fatalf("%s data packet %d sequence = %d, want %d", protocol, i, sequence, wantFirst)
			}
		} else if sequence != first+uint32(i) {
			t.Fatalf("%s data packet %d sequence = %d, want %d", protocol, i, sequence, first+uint32(i))
		}
	}
}

func assertClosedExporter(t *testing.T, e *logsExporter, helper *lifecycleGateHelper, conn *countedConn, writes int) {
	t.Helper()
	if err := lifecycleCall(t, func() error { return e.ConsumeLogs(context.Background(), plog.Logs{}) }); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatalf("post-shutdown consume = %v", err)
	}
	if got := helper.entries.Load(); got != 1 {
		t.Fatalf("post-shutdown helper entries = %d, want 1", got)
	}
	if got := len(conn.Writes()); got != writes {
		t.Fatalf("post-shutdown writes = %d, want %d", got, writes)
	}
}

func TestConcurrent(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			firstConfig := validConfig(protocol)
			secondConfig := validConfig(protocol)
			first, firstConn := fakeExporter(t, firstConfig, lifecycleSteps(protocol, packetLength(protocol))...)
			second, secondConn := fakeExporter(t, secondConfig, append(lifecycleSteps(protocol, packetLength(protocol)), testtransport.WriteStep{N: packetLength(protocol)})...)

			gate := &lifecycleGateHelper{
				Logs:    first.helper,
				entered: make(chan struct{}),
				release: make(chan struct{}),
				done:    make(chan struct{}),
			}
			first.helper = gate
			t.Cleanup(gate.releaseAll)

			if err := first.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			if err := second.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}

			firstDone := make(chan error, 1)
			go func() { firstDone <- first.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()) }()
			waitLifecycleSignal(t, gate.entered)
			if got := gate.entries.Load(); got != 1 {
				t.Fatalf("admitted helper entries = %d, want 1", got)
			}

			// Admission is the sole whole-request slot and is checked before the
			// helper can inspect even malformed pdata.
			if err := lifecycleCall(t, func() error { return first.ConsumeLogs(context.Background(), plog.Logs{}) }); !errors.Is(err, destination.ErrRuntimeBusy) {
				t.Fatalf("competing consume = %v", err)
			}
			if got := gate.entries.Load(); got != 1 {
				t.Fatalf("competing call entered helper: %d", got)
			}

			// The second instance has its own lifecycle gate, socket and sequence;
			// it remains usable while the first admitted request is held.
			if err := second.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
				t.Fatalf("independent consume while held = %v", err)
			}

			gate.releaseNow()
			select {
			case err := <-firstDone:
				if err != nil {
					t.Fatalf("admitted consume = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("admitted consume did not return")
			}
			if gate.entries.Load() != 1 {
				t.Fatal("admitted helper call was duplicated")
			}
			if got := len(firstConn.Writes()); got != len(bootstrapSteps(protocol))+1 {
				t.Fatalf("first instance writes = %d, want %d", got, len(bootstrapSteps(protocol))+1)
			}

			if err := first.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := second.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err != nil {
				t.Fatalf("independent consume after shutdown = %v", err)
			}
			assertDataSequence(t, protocol, secondConn, 2)
			if err := second.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if gate.shutdowns.Load() != 1 {
				t.Fatalf("helper shutdowns = %d, want 1", gate.shutdowns.Load())
			}
			if firstConn.closes.Load() != 1 || secondConn.closes.Load() != 1 {
				t.Fatalf("socket closes = %d/%d, want 1/1", firstConn.closes.Load(), secondConn.closes.Load())
			}
			assertClosedExporter(t, first, gate, firstConn, len(firstConn.Writes()))
		})
	}
}

func TestShutdownConcurrent(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			config := validConfig(protocol)
			config.MaxRecordsPerMessage = ptr(uint16(1))
			writeStarted := make(chan struct{})
			writeWait := make(chan struct{})
			steps := append([]testtransport.WriteStep(nil), bootstrapSteps(protocol)...)
			steps = append(steps, testtransport.WriteStep{N: packetLength(protocol), Started: writeStarted, Wait: writeWait})
			e, conn := fakeExporter(t, config, steps...)
			t.Cleanup(func() { close(writeWait) })
			gate := &lifecycleGateHelper{
				Logs:        e.helper,
				entered:     make(chan struct{}),
				release:     make(chan struct{}),
				done:        make(chan struct{}),
				postEntered: make(chan struct{}),
				postRelease: make(chan struct{}),
			}
			e.helper = gate
			t.Cleanup(gate.releaseAll)

			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			consumeDone := make(chan error, 1)
			go func() { consumeDone <- e.ConsumeLogs(context.Background(), mixedLogs()) }()
			waitLifecycleSignal(t, gate.entered)
			if err := lifecycleCall(t, func() error { return e.ConsumeLogs(context.Background(), plog.Logs{}) }); !errors.Is(err, destination.ErrRuntimeBusy) {
				t.Fatalf("competing consume = %v", err)
			}
			gate.releaseNow()
			waitLifecycleSignal(t, writeStarted)

			const callers = 4
			ready := make(chan struct{}, callers)
			startShutdown := make(chan struct{})
			releaseShutdown := sync.OnceFunc(func() { close(startShutdown) })
			t.Cleanup(releaseShutdown)
			results := make(chan error, callers)
			for i := 0; i < callers; i++ {
				go func() {
					ready <- struct{}{}
					<-startShutdown
					results <- e.Shutdown(context.Background())
				}()
			}
			for i := 0; i < callers; i++ {
				waitLifecycleSignal(t, ready)
			}
			releaseShutdown()
			waitLifecycleSignal(t, gate.postEntered)
			select {
			case err := <-results:
				t.Fatalf("shutdown returned before helper consume: %v", err)
			default:
			}
			if gate.shutdowns.Load() != 0 {
				t.Fatal("helper shutdown began before post-pusher barrier release")
			}
			if got := len(conn.Writes()); got != len(bootstrapSteps(protocol))+1 {
				t.Fatalf("shutdown attempted %d writes, want %d", got, len(bootstrapSteps(protocol))+1)
			}
			gate.releasePostNow()

			var firstErr error
			for i := 0; i < callers; i++ {
				select {
				case err := <-results:
					if i == 0 {
						firstErr = err
					} else if err != firstErr {
						t.Fatalf("shutdown result %v differs from %v", err, firstErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("concurrent shutdown did not return")
				}
			}
			if firstErr != nil {
				t.Fatalf("shutdown = %v", firstErr)
			}

			select {
			case err := <-consumeDone:
				subsetErr, ok := errors.AsType[consumererror.Logs](err)
				if !ok || consumererror.IsPermanent(err) {
					t.Fatalf("interrupted consume = %v", err)
				}
				subset := subsetErr.Data()
				if subset.LogRecordCount() != 4 {
					t.Fatalf("interrupted subset records = %d, want 4", subset.LogRecordCount())
				}
				cursor := logCursor{logs: subset}
				for i, want := range []int64{0, 2, 4, 5} {
					record, ok := cursor.at(uint64(i))
					if !ok {
						t.Fatalf("missing subset record %d", i)
					}
					got, ok := record.Attributes().Get("ordinal")
					if !ok || got.Int() != want {
						t.Fatalf("subset ordinal %d = %v, want %d", i, got, want)
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatal("interrupted consume did not return")
			}
			if gate.shutdownBeforeConsume.Load() {
				t.Fatal("helper shutdown began before admitted consume returned")
			}
			if gate.shutdowns.Load() != 1 {
				t.Fatalf("helper shutdowns = %d, want 1", gate.shutdowns.Load())
			}
			if conn.closes.Load() != 1 {
				t.Fatalf("socket closes = %d, want 1", conn.closes.Load())
			}
			writes := len(conn.Writes())
			assertClosedExporter(t, e, gate, conn, writes)
		})
	}
}
