package destination

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// resourceRuntimeFixture owns every manually controlled timer returned to a
// Runtime. Keeping the timers here prevents a successful test from proving
// cleanup for only the timer it happened to retain locally.
type resourceRuntimeFixture struct {
	r      *Runtime
	clock  *testclock.Clock
	lookup *testtransport.Resolver
	conn   *runtimeConn
	timers []*testclock.Timer
}

func newResourceRuntime(t *testing.T, protocol wire.Protocol, lookup *testtransport.Resolver, conn *runtimeConn) *resourceRuntimeFixture {
	t.Helper()
	compiled, writer, config := runtimeConfig(t, protocol)
	config.State.RefreshInterval = time.Minute
	resolver, err := transport.NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &resourceRuntimeFixture{
		clock:  testclock.New(4_000_000_000, 1),
		lookup: lookup,
		conn:   conn,
	}
	dialer, err := transport.NewCandidateDialer(
		resolver, runtimeRemote.Port(), 464, compiled.MaxDatagramSize(), 0,
		func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil },
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	config.NewTimer = func(time.Duration) transport.Timer {
		timer := testclock.NewTimer()
		fixture.timers = append(fixture.timers, timer)
		return timer
	}
	fixture.r, err = NewRuntime(compiled, writer, config, dialer, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func resourceTimerCount(protocol wire.Protocol) int {
	if protocol == wire.ProtocolV5 {
		return 1
	}
	return 2
}

func shutdownResourceRuntime(t *testing.T, r *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
}

func assertResourceRuntimeClosed(t *testing.T, fixture *resourceRuntimeFixture, wantCloses int32) {
	t.Helper()
	r := fixture.r
	r.lifecycle.Lock()
	closing := r.closing
	closedPublished := r.published == nil
	attempt := r.attempt
	activeCalls, activeWrites := r.activeCalls, r.activeWrites
	packCancel, requestCancel := r.packCancel, r.requestCancel
	dnsCancel, refreshCancel := r.dnsCancel, r.refreshCancel
	drained, shutdownDone := r.drained, r.shutdownDone
	r.lifecycle.Unlock()
	if !closing || !closedPublished || attempt != nil || activeCalls != 0 || activeWrites != 0 ||
		packCancel != nil || requestCancel != nil || dnsCancel != nil || refreshCancel != nil {
		t.Fatalf("closed runtime retained lifecycle state: closing=%v published=%v attempt=%v calls=%d writes=%d pack=%v request=%v dns=%v refresh=%v", closing, !closedPublished, attempt != nil, activeCalls, activeWrites, packCancel != nil, requestCancel != nil, dnsCancel != nil, refreshCancel != nil)
	}
	select {
	case <-drained:
	default:
		t.Fatal("shutdown returned before drained closed")
	}
	select {
	case <-shutdownDone:
	default:
		t.Fatal("shutdown returned before shutdownDone closed")
	}
	assertRuntimeIdle(t, r, false)
	if len(fixture.timers) != resourceTimerCount(r.config.State.Protocol) {
		t.Fatalf("created timers = %d, want %d", len(fixture.timers), resourceTimerCount(r.config.State.Protocol))
	}
	for index, timer := range fixture.timers {
		delays, stopped, _ := timer.Snapshot()
		if (len(delays) == 0 && wantCloses != 0) || !stopped {
			t.Fatalf("timer %d delays=%v stopped=%v after shutdown", index, delays, stopped)
		}
		if timer.Fire() {
			t.Fatalf("timer %d remained fireable after shutdown", index)
		}
	}
	if got := fixture.conn.closes.Load(); got != wantCloses {
		t.Fatalf("Conn.Close calls = %d, want %d", got, wantCloses)
	}
	writes := fixture.conn.Writes()
	closeEvents := 0
	for _, event := range fixture.conn.Events() {
		if event.Kind == testtransport.EventClose {
			closeEvents++
		}
	}
	if closeEvents != int(wantCloses) {
		t.Fatalf("fake close events = %d, want %d", closeEvents, wantCloses)
	}
	if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Pack after shutdown = %v", err)
	}
	if err := r.Start(context.Background()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Start after shutdown = %v", err)
	}
	if got := len(fixture.conn.Writes()); got != len(writes) {
		t.Fatalf("post-shutdown operations wrote %d packets, want %d", got, len(writes))
	}
}

func assertResourceRuntimeStartFailed(t *testing.T, fixture *resourceRuntimeFixture) {
	t.Helper()
	r := fixture.r
	r.lifecycle.Lock()
	closing := r.closing
	published := r.published != nil
	attempt := r.attempt
	activeCalls, activeWrites := r.activeCalls, r.activeWrites
	packCancel, requestCancel := r.packCancel, r.requestCancel
	dnsCancel, refreshCancel := r.dnsCancel, r.refreshCancel
	r.lifecycle.Unlock()
	if closing || published || attempt != nil || activeCalls != 0 || activeWrites != 0 ||
		packCancel != nil || requestCancel != nil || dnsCancel != nil || refreshCancel != nil {
		t.Fatalf("failed Start retained lifecycle state: closing=%v published=%v attempt=%v calls=%d writes=%d pack=%v request=%v dns=%v refresh=%v", closing, published, attempt != nil, activeCalls, activeWrites, packCancel != nil, requestCancel != nil, dnsCancel != nil, refreshCancel != nil)
	}
	assertRuntimeIdle(t, r, false)
	if len(fixture.timers) != resourceTimerCount(r.config.State.Protocol) {
		t.Fatalf("failed Start created timers = %d, want %d", len(fixture.timers), resourceTimerCount(r.config.State.Protocol))
	}
	for index, timer := range fixture.timers {
		delays, stopped, _ := timer.Snapshot()
		if len(delays) != 0 || !stopped {
			t.Fatalf("failed Start timer %d delays=%v stopped=%v", index, delays, stopped)
		}
		if timer.Fire() {
			t.Fatalf("failed Start timer %d remained fireable", index)
		}
	}
	if got := fixture.conn.closes.Load(); got != 0 {
		t.Fatalf("failed Start Conn.Close calls = %d, want 0", got)
	}
	if writes := len(fixture.conn.Writes()); writes != 0 {
		t.Fatalf("failed Start wrote %d packets", writes)
	}
}

func TestRuntimeResourceLifecycleCycles(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			for cycle := 0; cycle < 100; cycle++ {
				t.Run(fmt.Sprintf("cycle-%03d", cycle), func(t *testing.T) {
					lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
					_, dataLength := runtimeLengths(protocol)
					steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: dataLength})
					conn := newRuntimeConn(steps...)
					fixture := newResourceRuntime(t, protocol, lookup, conn)
					defer fixture.r.Close()
					if err := fixture.r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					result, err := fixture.r.Pack(context.Background(), validPackerLogs(t), nil)
					if err != nil || result.Counts().Confirmed != 1 {
						t.Fatalf("Pack = %+v, %v", result, err)
					}
					shutdownResourceRuntime(t, fixture.r)
					assertResourceRuntimeClosed(t, fixture, 1)
				})
			}
		})
	}
}

func TestRuntimeResourceCoalescesThousandDNSTriggers(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}, Started: entered, Wait: release},
			)
			conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			fixture := newResourceRuntime(t, protocol, lookup, conn)
			defer fixture.r.Close()
			if err := fixture.r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			dnsTimer := fixture.timers[0]
			waitDNSReset(t, dnsTimer, 1)
			fixture.clock.Advance(0, uint64(time.Second))
			if !dnsTimer.Fire() {
				t.Fatal("DNS timer was not armed")
			}
			waitRuntimeSignal(t, entered)
			for range 1000 {
				fixture.r.triggerDNS()
			}
			if len(fixture.r.dnsWake) != 1 {
				t.Fatalf("DNS pending wake slots = %d, want 1", len(fixture.r.dnsWake))
			}
			if events := lookup.Events(); len(events) != 1 {
				t.Fatalf("lookup rounds while barrier held = %d, want 1", len(events))
			}
			close(release)
			waitDNSReset(t, dnsTimer, 2)
			if !dnsTimer.Fire() {
				t.Fatal("DNS timer was not rearmed after lookup")
			}
			waitDNSReset(t, dnsTimer, 3)
			if events := lookup.Events(); len(events) != 2 {
				t.Fatalf("lookup rounds after coalesced triggers = %d, want 2 total", len(events))
			}
			shutdownResourceRuntime(t, fixture.r)
			assertResourceRuntimeClosed(t, fixture, 1)
		})
	}
}

func TestRuntimeResourceCoalescesThousandTemplateTriggers(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			templateLength, _ := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
			steps := append(runtimeBootstrapSteps(protocol),
				testtransport.WriteStep{N: templateLength, Started: entered, Wait: release},
				testtransport.WriteStep{N: templateLength},
			)
			conn := newRuntimeConn(steps...)
			fixture := newResourceRuntime(t, protocol, lookup, conn)
			defer fixture.r.Close()
			if err := fixture.r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, fixture.timers[0], 1)
			refreshTimer := fixture.timers[1]
			waitRefreshReset(t, refreshTimer, 1)
			fixture.clock.Advance(0, uint64(time.Minute))
			if !refreshTimer.Fire() {
				t.Fatal("template timer was not armed")
			}
			waitRuntimeSignal(t, entered)
			for range 1000 {
				fixture.r.triggerRefresh()
			}
			if len(fixture.r.refreshWake) != 1 {
				t.Fatalf("template pending wake slots = %d, want 1", len(fixture.r.refreshWake))
			}
			if writes := len(conn.Writes()); writes != len(runtimeBootstrapSteps(protocol)) {
				t.Fatalf("writes while refresh barrier held = %d, want bootstrap %d", writes, len(runtimeBootstrapSteps(protocol)))
			}
			close(release)
			waitRefreshReset(t, refreshTimer, 3)
			if writes := len(conn.Writes()); writes != len(runtimeBootstrapSteps(protocol))+2 {
				t.Fatalf("refresh writes after coalesced triggers = %d, want %d", writes, len(runtimeBootstrapSteps(protocol))+2)
			}
			shutdownResourceRuntime(t, fixture.r)
			assertResourceRuntimeClosed(t, fixture, 1)
		})
	}
}

func TestRuntimeResourceShutdownDuringHeldLookup(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}, Started: entered, Wait: release},
			)
			conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			fixture := newResourceRuntime(t, protocol, lookup, conn)
			defer fixture.r.Close()
			if err := fixture.r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, fixture.timers[0], 1)
			fixture.clock.Advance(0, uint64(time.Second))
			if !fixture.timers[0].Fire() {
				t.Fatal("DNS timer was not armed")
			}
			waitRuntimeSignal(t, entered)
			shutdownResourceRuntime(t, fixture.r)
			if events := lookup.Events(); len(events) != 2 || !events[1].Canceled {
				t.Fatalf("held lookup trace = %+v", events)
			}
			assertResourceRuntimeClosed(t, fixture, 1)
		})
	}
}

func TestRuntimeResourceShutdownDuringHeldRefresh(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			templateLength, _ := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: templateLength, Started: entered, Wait: release})
			conn := newRuntimeConn(steps...)
			fixture := newResourceRuntime(t, protocol, lookup, conn)
			defer fixture.r.Close()
			if err := fixture.r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, fixture.timers[0], 1)
			refreshTimer := fixture.timers[1]
			waitRefreshReset(t, refreshTimer, 1)
			fixture.clock.Advance(0, uint64(time.Minute))
			if !refreshTimer.Fire() {
				t.Fatal("template timer was not armed")
			}
			waitRuntimeSignal(t, entered)
			shutdownResourceRuntime(t, fixture.r)
			assertResourceRuntimeClosed(t, fixture, 1)
		})
	}
}

func TestRuntimeResourceFailedStartStopsAllTimers(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Err: errors.New("lookup failed")})
			conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			fixture := newResourceRuntime(t, protocol, lookup, conn)
			defer fixture.r.Close()
			if err := fixture.r.Start(context.Background()); err == nil {
				t.Fatal("failed lookup unexpectedly started runtime")
			}
			assertResourceRuntimeStartFailed(t, fixture)
			shutdownResourceRuntime(t, fixture.r)
			assertResourceRuntimeClosed(t, fixture, 0)
		})
	}
}
