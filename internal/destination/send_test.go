package destination

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

type packAttempt struct {
	result *PackResult
	err    error
}

type closeObservedConn struct {
	*runtimeConn
	closed      chan struct{}
	once        sync.Once
	beforeClose func()
}

func (c *closeObservedConn) Close() error {
	if c.beforeClose != nil {
		c.beforeClose()
	}
	err := c.runtimeConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type orderedEvents struct {
	mu     sync.Mutex
	events []Event
}

type retirementEvidence struct {
	sequence uint32
	dataSeen bool
}

func (o *orderedEvents) observe(_ context.Context, event Event, _ uint64) {
	o.mu.Lock()
	o.events = append(o.events, event)
	o.mu.Unlock()
}

func (o *orderedEvents) snapshot() []Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Event(nil), o.events...)
}

func waitObservedEvent(t *testing.T, observed *orderedEvents, want Event, occurrence int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if eventOccurrence(observed.snapshot(), want, occurrence) >= 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("event %d occurrence %d was not observed", want, occurrence)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func acquirePermitWithin(t *testing.T, permit *sendPermit) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !permit.acquire(ctx) {
		t.Fatal("permit acquisition did not complete within the bound")
	}
}

func takeTestPermit(t *testing.T, r *Runtime) func() {
	t.Helper()
	select {
	case <-r.send.token:
	case <-time.After(2 * time.Second):
		t.Fatal("test-owned send permit was unavailable")
	}
	var once sync.Once
	return func() { once.Do(r.send.release) }
}

func waitStartPublicationPending(t *testing.T, r *Runtime) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		r.lifecycle.Lock()
		pending := r.attempt != nil && r.attempt.candidate != nil && r.published == nil
		r.lifecycle.Unlock()
		if pending {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("Start candidate did not remain registered while waiting to publish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func waitRefreshTimerConsumed(t *testing.T, timer *testclock.Timer) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if len(timer.C()) == 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("refresh worker did not consume the due timer signal")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func waitRefreshPermitPending(t *testing.T, r *Runtime, timer *testclock.Timer, conn *runtimeConn) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		delays, stopped, _ := timer.Snapshot()
		r.lifecycle.Lock()
		worker := r.refreshCancel != nil
		r.lifecycle.Unlock()
		permitHeld := len(r.send.token) == 0
		if worker && !stopped && len(delays) == 1 && permitHeld && len(dnsPackets(conn)) == 4 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("refresh was not observed pending: worker=%v stopped=%v resets=%v permit_held=%v writes=%d", worker, stopped, delays, permitHeld, len(dnsPackets(conn)))
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func completedDatagrams(conn *runtimeConn) int {
	count := 0
	for _, event := range conn.Writes() {
		if event.Err == nil && event.N == len(event.Payload) {
			count++
		}
	}
	return count
}

func eventOccurrence(events []Event, want Event, occurrence int) int {
	seen := 0
	for index, event := range events {
		if event != want {
			continue
		}
		if seen == occurrence {
			return index
		}
		seen++
	}
	return -1
}

func waitPackAttempt(t *testing.T, done <-chan packAttempt) packAttempt {
	t.Helper()
	select {
	case attempt := <-done:
		return attempt
	case <-time.After(2 * time.Second):
		t.Fatal("Pack operation did not complete")
		return packAttempt{}
	}
}

func assertPermitReleased(t *testing.T, r *Runtime) {
	t.Helper()
	r.lifecycle.Lock()
	packRegistered := r.packCancel != nil
	permitAvailable := false
	select {
	case <-r.send.token:
		permitAvailable = true
	default:
	}
	if permitAvailable {
		r.send.release()
	}
	r.lifecycle.Unlock()
	if packRegistered || !permitAvailable {
		t.Fatalf("Pack cleanup: registered=%v permit_available=%v", packRegistered, permitAvailable)
	}
}

func cleanupPackGate(t *testing.T, release func(), done <-chan packAttempt, joined *bool) {
	t.Helper()
	t.Cleanup(func() {
		release()
		if *joined {
			return
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("Pack waiter did not join during cleanup")
		}
	})
}

func cleanupErrorGate(t *testing.T, release func(), done <-chan error, joined *bool) {
	t.Helper()
	t.Cleanup(func() {
		release()
		if *joined {
			return
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("error waiter did not join during cleanup")
		}
	})
}

func waitPublicationPending(t *testing.T, r *Runtime) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		r.lifecycle.Lock()
		pending := r.attempt != nil && r.attempt.candidate != nil && r.published != nil
		r.lifecycle.Unlock()
		if pending {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("candidate did not remain registered while waiting to publish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestSendPermitCancellationReturnsOwnedToken(t *testing.T) {
	permit := newSendPermit()
	select {
	case <-permit.token:
	default:
		t.Fatal("fresh permit was unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if permit.acquire(ctx) {
		t.Fatal("canceled wait acquired the permit")
	}
	permit.release()
	acquirePermitWithin(t, &permit)
	permit.release()
}

func TestSendPermitCancellationAndReleaseRace(t *testing.T) {
	for range 100 {
		permit := newSendPermit()
		acquirePermitWithin(t, &permit)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool, 1)
		go func() {
			defer close(done)
			done <- permit.acquire(ctx)
		}()
		cancel()
		permit.release()
		select {
		case acquired := <-done:
			if acquired {
				t.Fatal("canceled waiter acquired a released permit")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("canceled waiter did not join")
		}
		acquirePermitWithin(t, &permit)
		permit.release()
	}
}

func TestPublicationWaitCancellationWhileSendHeld(t *testing.T) {
	for _, action := range []string{"cancel", "shutdown"} {
		for _, protocol := range templateProtocols {
			t.Run(fmt.Sprintf("%s/%s", action, protocol), func(t *testing.T) {
				conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
				r, _, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
					return conn, nil
				})
				var observed orderedEvents
				r.config.Observe = observed.observe
				releasePermit := takeTestPermit(t, r)
				t.Cleanup(releasePermit)
				t.Cleanup(func() { _ = r.Shutdown(context.Background()) })
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				started := make(chan error, 1)
				go func() {
					started <- r.Start(ctx)
					close(started)
				}()

				// Four observer events prove that the candidate completed every
				// bootstrap commit before publication tried to take send.
				waitObservedEvent(t, &observed, BootstrapConfirmed, 3)
				waitStartPublicationPending(t, r)
				if len(dnsPackets(conn)) != 4 {
					t.Fatalf("candidate writes=%d, want four bootstrap datagrams", len(dnsPackets(conn)))
				}
				if action == "cancel" {
					cancel()
				} else if err := r.Shutdown(context.Background()); err != nil {
					t.Fatalf("Shutdown = %v", err)
				}
				if err := waitRuntimeError(t, started); !errors.Is(err, ErrRuntimeUnavailable) {
					t.Fatalf("Start while publication waited = %v, want unavailable", err)
				}
				assertRuntimeIdle(t, r, false)
				if conn.closes.Load() != 1 {
					t.Fatalf("candidate Close calls=%d, want one", conn.closes.Load())
				}
				if len(dnsPackets(conn)) != 4 {
					t.Fatalf("canceled publication wrote %d datagrams, want four bootstrap datagrams", len(dnsPackets(conn)))
				}
				events := observed.snapshot()
				if eventOccurrence(events, DataConfirmed, 0) >= 0 || eventOccurrence(events, EpochPublished, 0) >= 0 {
					t.Fatalf("canceled publication emitted data/publication events: %v", events)
				}
				_, stopped, _ := timer.Snapshot()
				if !stopped || timer.Fire() {
					t.Fatal("publication cancellation did not stop the refresh timer")
				}
				select {
				case <-r.send.token:
					t.Fatal("publication waiter released the test-held permit")
				default:
				}
				releasePermit()
				acquirePermitWithin(t, &r.send)
				r.send.release()
				if action == "shutdown" {
					if err := r.Start(context.Background()); !errors.Is(err, ErrRuntimeClosed) {
						t.Fatalf("Start after closing = %v, want closed", err)
					}
				}
			})
		}
	}
}

func TestRefreshWorkerWaitCancellationWhileSendHeld(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			base := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			conn := &shutdownConn{runtimeConn: base, closed: make(chan struct{})}
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
				return conn, nil
			})
			var observed orderedEvents
			r.config.Observe = observed.observe
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			releasePermit := takeTestPermit(t, r)
			t.Cleanup(releasePermit)
			t.Cleanup(func() { _ = r.Shutdown(context.Background()) })
			clock.Advance(0, uint64(30*time.Second))
			if !timer.Fire() {
				t.Fatal("refresh timer was not armed")
			}
			// The timer channel is the worker's dispatch boundary. Once its
			// fired value is consumed, the due worker is blocked in send.acquire.
			waitRefreshTimerConsumed(t, timer)
			waitRefreshPermitPending(t, r, timer, base)

			shutdownDone := make(chan error, 1)
			go func() {
				shutdownDone <- r.Shutdown(context.Background())
				close(shutdownDone)
			}()
			waitRuntimeSignal(t, conn.closed)
			if err := waitRuntimeError(t, shutdownDone); err != nil {
				t.Fatalf("Shutdown = %v", err)
			}
			assertRuntimeIdle(t, r, false)
			if base.closes.Load() != 1 {
				t.Fatalf("refresh shutdown Close calls=%d, want one", base.closes.Load())
			}
			if completedDatagrams(base) != 4 {
				t.Fatalf("canceled refresh completed %d datagrams, want four bootstrap datagrams", completedDatagrams(base))
			}
			events := observed.snapshot()
			if eventOccurrence(events, RefreshConfirmed, 0) >= 0 || eventOccurrence(events, DataConfirmed, 0) >= 0 {
				t.Fatalf("canceled refresh emitted maintenance/data events: %v", events)
			}
			_, stopped, _ := timer.Snapshot()
			if !stopped || timer.Fire() {
				t.Fatal("refresh shutdown did not stop its timer")
			}
			select {
			case <-r.send.token:
				t.Fatal("refresh worker released a permit it never acquired")
			default:
			}
			releasePermit()
			acquirePermitWithin(t, &r.send)
			r.send.release()
		})
	}
}

func TestPackWaitAdmission(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(fmt.Sprint(protocol), func(t *testing.T) {
			template, data := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
			conn := newRuntimeConn(steps...)
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			clock.Advance(0, uint64(30*time.Second))
			fireRefresh(t, timer)
			waitRuntimeSignal(t, entered)
			first := make(chan packAttempt, 1)
			joined := false
			go func() {
				defer close(first)
				result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
				first <- packAttempt{result: result, err: err}
			}()
			cleanupPackGate(t, releaseGate, first, &joined)
			waitPackRegistration(t, r)
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); !errors.Is(err, ErrRuntimeBusy) {
				t.Fatalf("second direct Pack = %v", err)
			}
			select {
			case attempt := <-first:
				t.Fatalf("waiting Pack completed: %+v", attempt)
			default:
			}
			releaseGate()
			attempt := waitPackAttempt(t, first)
			joined = true
			if attempt.err != nil || attempt.result == nil || attempt.result.Counts().Confirmed != 1 {
				t.Fatalf("waiting Pack = %+v, want one confirmed record", attempt)
			}
			state := currentEndpoint(r).state
			if !state.Ready() || state.pending != nil || state.Progress().NextShape != 0 || len(dnsPackets(conn)) != 7 {
				t.Fatalf("final maintenance state=%+v pending=%v writes=%d", state.Progress(), state.pending != nil, len(dnsPackets(conn)))
			}
			wantSequence := uint32(1)
			if protocol == wire.ProtocolV9 {
				wantSequence = 7
			}
			if state.Sequence() != wantSequence {
				t.Fatalf("final sequence=%d, want %d", state.Sequence(), wantSequence)
			}
			assertRuntimeIdle(t, r, true)
			assertPermitReleased(t, r)
			if err := conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
				t.Fatal(err)
			}
			reused, err := r.Pack(context.Background(), validPackerLogs(t), nil)
			if err != nil || reused == nil || reused.Counts().Confirmed != 1 {
				t.Fatalf("permit reuse Pack = %+v, %v", reused, err)
			}
		})
	}
}

func TestPackWaitAdmissionShutdownRegistered(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(fmt.Sprint(protocol), func(t *testing.T) {
			template, data := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			base := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})...)
			conn := &shutdownConn{runtimeConn: base, closed: make(chan struct{})}
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			clock.Advance(0, uint64(30*time.Second))
			fireRefresh(t, timer)
			waitRuntimeSignal(t, entered)
			packed := make(chan packAttempt, 1)
			packedJoined := false
			go func() {
				defer close(packed)
				result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
				packed <- packAttempt{result: result, err: err}
			}()
			waitPackRegistration(t, r)
			cleanupPackGate(t, releaseGate, packed, &packedJoined)
			shutdown := make(chan error, 1)
			shutdownJoined := false
			go func() {
				defer close(shutdown)
				shutdown <- r.Shutdown(context.Background())
			}()
			t.Cleanup(func() {
				releaseGate()
				if shutdownJoined {
					return
				}
				select {
				case <-shutdown:
				case <-time.After(2 * time.Second):
					t.Errorf("shutdown waiter did not join during cleanup")
				}
			})
			waitRuntimeSignal(t, conn.closed)
			attempt := waitPackAttempt(t, packed)
			packedJoined = true
			if attempt.result != nil || !errors.Is(attempt.err, ErrRuntimeClosed) {
				t.Fatalf("shutdown Pack = %+v, want nil/closed", attempt)
			}
			if err := waitRuntimeError(t, shutdown); err != nil {
				t.Fatal(err)
			}
			shutdownJoined = true
			assertRuntimeIdle(t, r, false)
			assertPermitReleased(t, r)
			_, stopped, _ := timer.Snapshot()
			if !stopped || timer.Fire() {
				t.Fatal("shutdown did not stop the refresh timer")
			}
		})
	}
}

func TestPackWaitAdmissionShutdownRace(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		for iteration := range 8 {
			t.Run(fmt.Sprintf("%s/%02d", protocol, iteration), func(t *testing.T) {
				template, data := runtimeLengths(protocol)
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
				base := newRuntimeConn(append(runtimeBootstrapSteps(protocol),
					testtransport.WriteStep{N: template, Started: entered, Wait: release},
					testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})...)
				conn := &shutdownConn{runtimeConn: base, closed: make(chan struct{})}
				r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
					return conn, nil
				})
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitRefreshReset(t, timer, 1)
				clock.Advance(0, uint64(30*time.Second))
				if !timer.Fire() {
					t.Fatal("refresh timer was not armed")
				}
				waitRuntimeSignal(t, entered)

				start := make(chan struct{})
				packed := make(chan packAttempt, 1)
				shutdown := make(chan error, 1)
				packCall := func() {
					<-start
					result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
					packed <- packAttempt{result: result, err: err}
					close(packed)
				}
				shutdownCall := func() {
					<-start
					shutdown <- r.Shutdown(context.Background())
					close(shutdown)
				}
				if iteration%2 == 0 {
					go packCall()
					go shutdownCall()
				} else {
					go shutdownCall()
					go packCall()
				}
				// Register release and both joins before opening the shared start
				// barrier. No Pack registration observation is used to order Shutdown.
				t.Cleanup(func() {
					releaseGate()
					select {
					case <-packed:
					case <-time.After(2 * time.Second):
						t.Errorf("racing Pack did not join during cleanup")
					}
					select {
					case <-shutdown:
					case <-time.After(2 * time.Second):
						t.Errorf("racing Shutdown did not join during cleanup")
					}
				})
				close(start)
				waitRuntimeSignal(t, conn.closed)
				if err := waitRuntimeError(t, shutdown); err != nil {
					t.Fatalf("racing Shutdown = %v", err)
				}
				attempt := waitPackAttempt(t, packed)
				if attempt.result != nil || !errors.Is(attempt.err, ErrRuntimeClosed) {
					t.Fatalf("racing Pack = %+v, want nil/closed", attempt)
				}
				if conn.closes.Load() != 1 {
					t.Fatalf("racing shutdown Close calls=%d, want one", conn.closes.Load())
				}
				if completedDatagrams(base) != 4 {
					t.Fatalf("racing shutdown completed %d datagrams, want four bootstrap datagrams", completedDatagrams(base))
				}
				assertRuntimeIdle(t, r, false)
				assertPermitReleased(t, r)
				_, stopped, _ := timer.Snapshot()
				if !stopped || timer.Fire() {
					t.Fatal("racing shutdown did not stop the refresh timer")
				}
			})
		}
	}
}

func TestPackWaitCancellation(t *testing.T) {
	for _, scenario := range []string{"already_canceled", "cancel_wait", "cancel_release"} {
		for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
			t.Run(fmt.Sprintf("%s/%s", scenario, protocol), func(t *testing.T) {
				template, data := runtimeLengths(protocol)
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
				conn := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})...)
				r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitRefreshReset(t, timer, 1)
				clock.Advance(0, uint64(30*time.Second))
				fireRefresh(t, timer)
				waitRuntimeSignal(t, entered)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if scenario == "already_canceled" {
					cancel()
					result, err := r.Pack(ctx, validPackerLogs(t), nil)
					if result != nil || !errors.Is(err, ErrRuntimeUnavailable) {
						t.Fatalf("already-canceled Pack = (%+v,%v), want nil/unavailable", result, err)
					}
					assertRuntimeIdleAfterRefreshWait(t, r, releaseGate, timer, conn)
					if err := conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
						t.Fatal(err)
					}
					if result, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil || result == nil || result.Counts().Confirmed != 1 {
						t.Fatalf("Pack after already-canceled wait = %+v, %v", result, err)
					}
					return
				}
				packed := make(chan packAttempt, 1)
				joined := false
				go func() {
					defer close(packed)
					result, err := r.Pack(ctx, validPackerLogs(t), nil)
					packed <- packAttempt{result: result, err: err}
				}()
				waitPackRegistration(t, r)
				cleanupPackGate(t, releaseGate, packed, &joined)
				var cancelReleaseDone <-chan struct{}
				if scenario == "cancel_wait" {
					cancel()
				} else {
					done := make(chan struct{})
					cancelReleaseDone = done
					t.Cleanup(func() {
						releaseGate()
						cancel()
						select {
						case <-done:
						case <-time.After(2 * time.Second):
							t.Errorf("cancel/release helper did not join during cleanup")
						}
					})
					go func() {
						releaseGate()
						cancel()
						close(done)
					}()
				}
				attempt := waitPackAttempt(t, packed)
				joined = true
				if cancelReleaseDone != nil {
					select {
					case <-cancelReleaseDone:
					case <-time.After(2 * time.Second):
						t.Fatal("cancel/release helper did not join")
					}
				}
				if scenario == "cancel_wait" {
					if attempt.result != nil || !errors.Is(attempt.err, ErrRuntimeUnavailable) {
						t.Fatalf("canceled waiting Pack = %+v, want nil/unavailable", attempt)
					}
					assertRuntimeIdleAfterRefreshWait(t, r, releaseGate, timer, conn)
					if err := conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
						t.Fatal(err)
					}
					if result, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil || result == nil || result.Counts().Confirmed != 1 {
						t.Fatalf("Pack after canceled wait = %+v, %v", result, err)
					}
					return
				}
				// Cancellation racing permit release may either win before packet
				// work (nil/unavailable) or lose after packet work begins. Both
				// outcomes must leave the registration and permit reusable.
				if attempt.result == nil && !errors.Is(attempt.err, ErrRuntimeUnavailable) {
					t.Fatalf("release/cancel race = %+v, want unavailable or a Pack result", attempt)
				}
				if attempt.result != nil && attempt.err != nil && !errors.Is(attempt.err, ErrPackTransient) {
					t.Fatalf("release/cancel race returned unexpected Pack error: %+v", attempt)
				}
				if len(dnsPackets(conn)) > 7 {
					t.Fatalf("release/cancel race wrote %d datagrams", len(dnsPackets(conn)))
				}
				waitRefreshReset(t, timer, 2)
				assertRuntimeIdle(t, r, true)
				assertPermitReleased(t, r)
				if err := conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
					t.Fatal(err)
				}
				if result, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil || result == nil || result.Counts().Confirmed != 1 {
					t.Fatalf("Pack after release/cancel race = %+v, %v", result, err)
				}
			})
		}
	}
}

func TestPackWaitAmbiguousLedger(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(fmt.Sprint(protocol), func(t *testing.T) {
			template, data := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: 1, Err: errors.New("ambiguous")})
			conn := newRuntimeConn(steps...)
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			clock.Advance(0, uint64(30*time.Second))
			fireRefresh(t, timer)
			waitRuntimeSignal(t, entered)
			packed := make(chan packAttempt, 1)
			joined := false
			go func() {
				defer close(packed)
				result, err := r.Pack(context.Background(), maintenanceMixedLogs(), nil)
				packed <- packAttempt{result: result, err: err}
			}()
			waitPackRegistration(t, r)
			cleanupPackGate(t, releaseGate, packed, &joined)
			releaseGate()
			attempt := waitPackAttempt(t, packed)
			joined = true
			if attempt.result == nil || !errors.Is(attempt.err, ErrPackTransient) {
				t.Fatalf("ambiguous Pack = %+v, want transient result", attempt)
			}
			if got := attempt.result.Counts(); got.Confirmed != 0 || got.Invalid != 1 || got.Ambiguous != 1 || got.Unsent != 1 {
				t.Fatalf("ambiguous counts=%+v, want confirmed=0 invalid=1 ambiguous=1 unsent=1", got)
			}
			for ordinal, want := range []SourceClass{SourceAmbiguous, SourceInvalid, SourceUnsentValid} {
				if got := attempt.result.Classification(uint64(ordinal)); got != want {
					t.Fatalf("source %d class=%v, want %v", ordinal, got, want)
				}
			}
			waitRefreshReset(t, timer, 2)
			assertRuntimeIdle(t, r, true)
			assertPermitReleased(t, r)
			writes := dnsPackets(conn)
			if len(writes) != 7 {
				t.Fatalf("ambiguous writes=%d, want bootstrap plus refresh plus one data attempt", len(writes))
			}
			dataHeader := 12
			if protocol == wire.ProtocolIPFIX {
				dataHeader = 8
			}
			firstSequence := binary.BigEndian.Uint32(writes[6][dataHeader : dataHeader+4])
			if err := conn.AddStep(testtransport.WriteStep{N: data}); err != nil {
				t.Fatal(err)
			}
			result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
			if err != nil || result == nil || result.Counts().Confirmed != 1 {
				t.Fatalf("later valid Pack = %+v, %v", result, err)
			}
			writes = dnsPackets(conn)
			secondSequence := binary.BigEndian.Uint32(writes[7][dataHeader : dataHeader+4])
			if firstSequence != secondSequence {
				t.Fatalf("ambiguous write advanced sequence: first=%d later=%d", firstSequence, secondSequence)
			}
			wantSequence := uint32(1)
			if protocol == wire.ProtocolV9 {
				wantSequence = 7
			}
			if currentEndpoint(r).state.Sequence() != wantSequence {
				t.Fatalf("final sequence=%d, want %d", currentEndpoint(r).state.Sequence(), wantSequence)
			}
		})
	}
}

func maintenanceMixedLogs() plog.Logs {
	logs := plog.NewLogs()
	canonical := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	records := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for ordinal := 0; ordinal < 3; ordinal++ {
		record := records.AppendEmpty()
		canonical.CopyTo(record)
		if ordinal == 1 {
			record.Body().SetStr("unsupported raw secret")
		}
	}
	return logs
}

func assertRuntimeIdleAfterRefreshWait(t *testing.T, r *Runtime, release func(), timer *testclock.Timer, conn *runtimeConn) {
	t.Helper()
	release()
	waitRefreshReset(t, timer, 2)
	assertRuntimeIdle(t, r, true)
	assertPermitReleased(t, r)
	if len(dnsPackets(conn)) != 6 {
		t.Fatalf("canceled wait wrote %d datagrams, want bootstrap plus refresh", len(dnsPackets(conn)))
	}
}

func TestPackWaitPublication(t *testing.T) {
	t.Run("publication_first", func(t *testing.T) {
		for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
			t.Run(fmt.Sprint(protocol), func(t *testing.T) {
				template, data := runtimeLengths(protocol)
				entered, release, bootstrapped := make(chan struct{}), make(chan struct{}), make(chan struct{})
				oldBase := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
				oldClosed := make(chan struct{})
				old := &closeObservedConn{runtimeConn: oldBase, closed: oldClosed}
				nextSteps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
				nextSteps[3].OnWrite = func() { close(bootstrapped) }
				next := newReplacementConn(nextSteps...)
				lookup := testtransport.NewResolver(
					testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
					testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
				)
				r, clock, dnsTimer, refreshTimer := newIdleDNSRuntime(t, protocol, lookup, func(_ context.Context, remote netip.AddrPort) (transport.Conn, error) {
					if remote == runtimeRemote {
						return old, nil
					}
					return next, nil
				})
				var observed orderedEvents
				r.config.Observe = observed.observe
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				oldEpoch := currentEndpoint(r)
				waitDNSReset(t, dnsTimer, 1)
				waitRefreshReset(t, refreshTimer, 1)
				clock.Advance(0, uint64(time.Second))
				if !dnsTimer.Fire() {
					t.Fatal("DNS timer was not armed")
				}
				waitRuntimeSignal(t, bootstrapped)
				waitDNSReset(t, dnsTimer, 2)
				previous := currentEndpoint(r)
				if previous == nil || previous.candidate.RemoteAddr() != next.RemoteAddr() {
					t.Fatal("replacement did not publish before Pack")
				}
				oldProgress, oldSequence := oldEpoch.state.Progress(), oldEpoch.state.Sequence()
				clock.Advance(0, uint64(30*time.Second))
				if !refreshTimer.Fire() {
					t.Fatal("refresh timer was not armed")
				}
				waitRuntimeSignal(t, entered)
				packed := make(chan error, 1)
				joined := false
				var releaseOnce sync.Once
				releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
				go func() {
					defer close(packed)
					_, err := r.Pack(context.Background(), validPackerLogs(t), nil)
					packed <- err
				}()
				waitPackRegistration(t, r)
				cleanupErrorGate(t, releaseGate, packed, &joined)
				select {
				case err := <-packed:
					t.Fatalf("Pack crossed gated replacement refresh: %v", err)
				default:
				}
				releaseGate()
				if err := waitRuntimeError(t, packed); err != nil {
					t.Fatal(err)
				}
				joined = true
				if currentEndpoint(r).candidate.RemoteAddr() != next.RemoteAddr() {
					t.Fatal("Pack did not use the published replacement")
				}
				if oldEpoch.state.Progress() != oldProgress || oldEpoch.state.Sequence() != oldSequence {
					t.Fatal("published old epoch changed during replacement refresh")
				}
				select {
				case <-oldClosed:
				case <-time.After(2 * time.Second):
					t.Fatal("retired old endpoint did not close")
				}
				if len(dnsPackets(oldBase)) != 4 || len(dnsPackets(next)) != 7 {
					t.Fatalf("old/new datagrams=%d/%d, want 4/7", len(dnsPackets(oldBase)), len(dnsPackets(next)))
				}
			})
		}
	})

	t.Run("pack_first", func(t *testing.T) {
		for _, protocol := range runtimeProtocols {
			t.Run(fmt.Sprint(protocol), func(t *testing.T) {
				_, data := runtimeLengths(protocol)
				entered, release, bootstrapped := make(chan struct{}), make(chan struct{}), make(chan struct{})
				oldBase := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: data})...)
				oldClosed := make(chan struct{})
				old := &closeObservedConn{runtimeConn: oldBase, closed: oldClosed}
				deadlineCall := 10
				if protocol == wire.ProtocolV5 {
					deadlineCall = 2
				}
				oldBase.BlockDeadlineCall(deadlineCall, release, entered)
				nextSteps := runtimeBootstrapSteps(protocol)
				next := newReplacementConn(nextSteps...)
				lookup := testtransport.NewResolver(
					testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
					testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
				)
				r, clock, dnsTimer, refreshTimer := newIdleDNSRuntime(t, protocol, lookup, func(_ context.Context, remote netip.AddrPort) (transport.Conn, error) {
					if remote == runtimeRemote {
						return old, nil
					}
					if protocol == wire.ProtocolV5 {
						close(bootstrapped)
					}
					return next, nil
				})
				var observed orderedEvents
				r.config.Observe = observed.observe
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				oldEndpoint := currentEndpoint(r)
				oldProgress := oldEndpoint.state.Progress()
				wantSequence := uint32(1)
				if protocol == wire.ProtocolV9 {
					wantSequence = 5
				}
				var retired retirementEvidence
				old.beforeClose = func() {
					retired.sequence = oldEndpoint.state.Sequence()
					retired.dataSeen = eventOccurrence(observed.snapshot(), DataConfirmed, 0) >= 0
				}
				waitDNSReset(t, dnsTimer, 1)
				if protocol != wire.ProtocolV5 {
					waitRefreshReset(t, refreshTimer, 1)
				}
				packed := make(chan error, 1)
				joined := false
				var releaseOnce sync.Once
				releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
				cleanupErrorGate(t, releaseGate, packed, &joined)
				go func() {
					defer close(packed)
					_, err := r.Pack(context.Background(), validPackerLogs(t), nil)
					packed <- err
				}()
				waitRuntimeSignal(t, entered)
				clock.Advance(0, uint64(time.Second))
				if !dnsTimer.Fire() {
					t.Fatal("DNS timer was not armed")
				}
				if protocol == wire.ProtocolV5 {
					waitRuntimeSignal(t, bootstrapped)
				} else {
					// Observer delivery follows each bootstrap State.Commit. The
					// initial epoch contributes four events; this waits for all four
					// replacement commits while Pack still owns send.
					waitObservedEvent(t, &observed, BootstrapConfirmed, 7)
				}
				waitPublicationPending(t, r)
				if currentEndpoint(r) != oldEndpoint {
					t.Fatal("candidate published before Pack committed")
				}
				r.lifecycle.Lock()
				candidateAttached := r.attempt != nil && r.attempt.candidate != nil
				candidateRemote := netip.AddrPort{}
				if candidateAttached {
					candidateRemote = r.attempt.candidate.RemoteAddr()
				}
				r.lifecycle.Unlock()
				if !candidateAttached || candidateRemote != next.RemoteAddr() {
					t.Fatalf("replacement candidate not retained while Pack was gated: attached=%v remote=%v", candidateAttached, candidateRemote)
				}
				select {
				case <-oldClosed:
					t.Fatal("old endpoint retired before Pack committed")
				default:
				}
				releaseGate()
				if err := waitRuntimeError(t, packed); err != nil {
					t.Fatal(err)
				}
				joined = true
				waitDNSReset(t, dnsTimer, 2)
				select {
				case <-oldClosed:
				case <-time.After(2 * time.Second):
					t.Fatal("retired old endpoint did not close")
				}
				if retired.sequence != wantSequence || !retired.dataSeen {
					t.Fatalf("old retirement preceded committed data: sequence=%d want=%d data_seen=%v", retired.sequence, wantSequence, retired.dataSeen)
				}
				if oldBase.closes.Load() != 1 {
					t.Fatalf("old endpoint Close calls=%d, want one retirement", oldBase.closes.Load())
				}
				if currentEndpoint(r).candidate.RemoteAddr() != next.RemoteAddr() {
					t.Fatal("publication did not follow the Pack commit")
				}
				wantOldWrites, wantNextWrites := 5, 4
				if protocol == wire.ProtocolV5 {
					wantOldWrites, wantNextWrites = 1, 0
				}
				progressChanged := oldEndpoint.state.Progress() != oldProgress
				if protocol == wire.ProtocolV5 {
					progressChanged = true
				}
				if !progressChanged || oldEndpoint.state.pending != nil || oldEndpoint.state.Sequence() != wantSequence || len(dnsPackets(oldBase)) != wantOldWrites || len(dnsPackets(next)) != wantNextWrites {
					t.Fatalf("Pack commit or replacement bootstrap was lost: old sequence=%d writes=%d/%d want=%d/%d", oldEndpoint.state.Sequence(), len(dnsPackets(oldBase)), len(dnsPackets(next)), wantOldWrites, wantNextWrites)
				}
				events := observed.snapshot()
				dataIndex := eventOccurrence(events, DataConfirmed, 0)
				publishIndex := eventOccurrence(events, EpochPublished, 1)
				if dataIndex < 0 || publishIndex < 0 || dataIndex >= publishIndex {
					t.Fatalf("commit/publication event order=%v, data=%d publication=%d", events, dataIndex, publishIndex)
				}
				_ = refreshTimer
			})
		}
	})
}
