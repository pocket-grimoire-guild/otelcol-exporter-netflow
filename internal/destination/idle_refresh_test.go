package destination

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

var templateProtocols = []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX}

func newIdleRuntime(t *testing.T, protocol wire.Protocol, remote netip.AddrPort, dial transport.NumericDial) (*Runtime, *testclock.Clock, *testclock.Timer) {
	t.Helper()
	clock, timer := testclock.New(4_000_000_000, 1), testclock.NewTimer()
	r := newRuntimeForTest(t, protocol, remote, dial, clock)
	r.config.State.RefreshInterval = 30 * time.Second
	r.config.NewTimer = func(time.Duration) transport.Timer { return timer }
	return r, clock, timer
}

func waitRefreshReset(t *testing.T, timer *testclock.Timer, count int) time.Duration {
	t.Helper()
	for {
		delays, stopped, changed := timer.Snapshot()
		if len(delays) >= count {
			if stopped || len(delays) != count {
				t.Fatalf("template timer resets=%v stopped=%v, want %d resets", delays, stopped, count)
			}
			for _, delay := range delays {
				if delay <= 0 || delay > time.Minute {
					t.Fatalf("unbounded template delay: %v", delay)
				}
			}
			return delays[len(delays)-1]
		}
		waitRuntimeSignal(t, changed)
	}
}

func fireRefresh(t *testing.T, timer *testclock.Timer) {
	t.Helper()
	if !timer.Fire() {
		t.Fatal("template timer not armed")
	}
}

// These ordinary templates use independently authored literal bytes, not
// destination/writer decoding. Wall time stays at four seconds; only elapsed
// time advances, so v9 uptime remains zero throughout the idle tests.
func assertIdleTemplate(t *testing.T, protocol wire.Protocol, packet []byte, shape int, sequence uint32) {
	t.Helper()
	var encoded string
	if protocol == wire.ProtocolV9 {
		encoded = "000900010000000000000004000000000000002a0000000c0100000100080004"
		if shape == 1 {
			encoded = "000900010000000000000004000000000000002a0000000c01010001001b0010"
		}
	} else {
		encoded = "000a001c00000004000000000000002a0002000c0100000100080004"
		if shape == 1 {
			encoded = "000a001c00000004000000000000002a0002000c01010001001b0010"
		}
	}
	want, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == wire.ProtocolV9 {
		binary.BigEndian.PutUint32(want[12:16], sequence)
	} else {
		binary.BigEndian.PutUint32(want[8:12], sequence)
	}
	if !bytes.Equal(packet, want) {
		t.Fatalf("idle template:\n got %x\nwant %x", packet, want)
	}
}

func TestRefreshIdleLiteralUDP(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			r, clock, timer := newIdleRuntime(t, protocol, listener.LocalAddr().(*net.UDPAddr).AddrPort(), transport.NewDialer("udp4", netip.AddrPort{}).Dial)
			ctx, cancel := context.WithCancel(context.Background())
			if err := r.Start(ctx); err != nil {
				t.Fatal(err)
			}
			cancel() // successful startup context does not own idle maintenance
			waitRefreshReset(t, timer, 1)
			if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for i := range 4 { // two bootstrap copies, one packet per family
				buffer := make([]byte, 464)
				n, _, err := listener.ReadFromUDP(buffer)
				if err != nil {
					t.Fatal(err)
				}
				var sequence uint32
				if protocol == wire.ProtocolV9 {
					sequence = uint32(i)
				}
				assertIdleTemplate(t, protocol, buffer[:n], i%2, sequence)
			}
			clock.Advance(0, uint64(29*time.Second))
			fireRefresh(t, timer)
			if delay := waitRefreshReset(t, timer, 2); delay != time.Second {
				t.Fatalf("early refresh remainder=%v, want 1s", delay)
			}
			if err := listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var early [464]byte
			if _, _, err := listener.ReadFromUDP(early[:]); err == nil {
				t.Fatal("early refresh emitted a template before 30s")
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("early refresh read: %v", err)
			}
			clock.Advance(0, uint64(time.Second))
			fireRefresh(t, timer)
			waitRefreshReset(t, timer, 3)
			if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for i := range 2 { // due refresh sends the complete two-shape catalog
				buffer := make([]byte, 464)
				n, _, err := listener.ReadFromUDP(buffer)
				if err != nil {
					t.Fatal(err)
				}
				var sequence uint32
				if protocol == wire.ProtocolV9 {
					sequence = uint32(4 + i)
				}
				assertIdleTemplate(t, protocol, buffer[:n], i%2, sequence)
			}
			state := currentEndpoint(r).state
			if !state.Ready() || state.Progress().LastRefreshMono != uint64(30*time.Second)+1 {
				t.Fatal("idle round did not commit")
			}
			if err := r.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertRuntimeIdle(t, r, false)
			_, stopped, _ := timer.Snapshot()
			if !stopped || timer.Fire() {
				t.Fatal("idle timer survived shutdown")
			}
		})
	}
}

func TestRefreshIdleClocksAndCountWake(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			template, data := runtimeLengths(protocol)
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: data})
			for range 4 {
				steps = append(steps, testtransport.WriteStep{N: template})
			}
			conn := newRuntimeConn(steps...)
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			r.config.State.V9RefreshPacketCount, r.config.State.IPFIXDataMessageRefreshCount = 1, 1
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			clock.SetWall(90_000_000_000)
			fireRefresh(t, timer)
			waitRefreshReset(t, timer, 2)
			clock.Set(4_000_000_000, 0) // backward monotonic sample does not underflow
			fireRefresh(t, timer)
			waitRefreshReset(t, timer, 3)
			if len(dnsPackets(conn)) != 4 {
				t.Fatal("wall step or backward monotonic time refreshed templates")
			}
			clock.SetMonotonic(uint64(15*time.Second) + 1)
			result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
			if err != nil || result.Counts().Confirmed != 1 {
				t.Fatalf("Pack=%v, %v", result, err)
			}
			waitRefreshReset(t, timer, 4) // count wake sends without a timer fire
			if len(dnsPackets(conn)) != 7 || !currentEndpoint(r).state.Ready() {
				t.Fatal("final data packet did not trigger one idle round")
			}
			clock.Advance(0, uint64(15*time.Second))
			fireRefresh(t, timer)
			if delay := waitRefreshReset(t, timer, 5); delay != 15*time.Second || len(dnsPackets(conn)) != 7 {
				t.Fatalf("early timer duplicated round or drifted deadline: %v", delay)
			}
			clock.Advance(0, uint64(15*time.Second))
			fireRefresh(t, timer)
			waitRefreshReset(t, timer, 6)
			packets := dnsPackets(conn)
			if len(packets) != 9 {
				t.Fatalf("next interval packets=%d", len(packets))
			}
			for i := 5; i < 9; i++ {
				sequence := uint32(1) // templates do not advance IPFIX data sequence
				if protocol == wire.ProtocolV9 {
					sequence = uint32(i)
				}
				assertIdleTemplate(t, protocol, packets[i], (i-5)%2, sequence)
			}
		})
	}
}

func TestRefreshIdleFailureProgress(t *testing.T) {
	for _, protocol := range templateProtocols {
		template, _ := runtimeLengths(protocol)
		for _, failure := range []struct {
			name string
			n    int
			err  error
		}{
			{"short_nil", 1, nil}, {"zero_nil", 0, nil},
			{"short_error", 1, errors.New("private failure")}, {"zero_error", 0, errors.New("private failure")},
			{"full_error", template, errors.New("private failure")}, {"invalid", template + 1, nil},
		} {
			for failedShape := range 2 {
				t.Run(fmt.Sprintf("%s/%s/shape%d", protocol, failure.name, failedShape), func(t *testing.T) {
					steps := runtimeBootstrapSteps(protocol)
					for range failedShape {
						steps = append(steps, testtransport.WriteStep{N: template})
					}
					steps = append(steps, testtransport.WriteStep{N: failure.n, Err: failure.err})
					for i := failedShape; i < 2; i++ {
						steps = append(steps, testtransport.WriteStep{N: template})
					}
					conn := newRuntimeConn(steps...)
					r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					waitRefreshReset(t, timer, 1)
					state := currentEndpoint(r).state
					clock.Advance(0, uint64(30*time.Second))
					fireRefresh(t, timer)
					if delay := waitRefreshReset(t, timer, 2); delay != 30*time.Second {
						t.Fatalf("failed refresh retry delay=%v, want 30s", delay)
					}
					progress := state.Progress()
					wantSequence := uint32(0)
					if protocol == wire.ProtocolV9 {
						wantSequence = uint32(4 + failedShape)
					}
					if progress.NextShape != failedShape || !progress.RefreshDue || progress.LastRefreshMono != 1 || state.Sequence() != wantSequence || state.Ready() {
						t.Fatalf("failure committed/forgot progress: %+v seq=%d", progress, state.Sequence())
					}
					// Timer is armed for a full interval, with no immediate pending
					// attempt; successful prefixes are retained for the next tick.
					if len(dnsPackets(conn)) != 5+failedShape {
						t.Fatal("failed refresh immediately retried")
					}
					clock.Advance(0, uint64(30*time.Second))
					fireRefresh(t, timer)
					waitRefreshReset(t, timer, 3)
					if !state.Ready() || state.Progress().NextShape != 0 || state.Progress().LastRefreshMono != uint64(60*time.Second)+1 {
						t.Fatal("next interval failed to finish retained round")
					}
					packets := dnsPackets(conn)
					if len(packets) != 7 {
						t.Fatalf("replayed completed prefix: %d packets", len(packets))
					}
					for i := failedShape; i < 2; i++ {
						sequence := uint32(0)
						if protocol == wire.ProtocolV9 {
							sequence = uint32(4 + i)
						}
						assertIdleTemplate(t, protocol, packets[5+i], i, sequence)
					}
				})
			}
		}
	}
}

func TestShutdownJoinsIdleRefresh(t *testing.T) {
	for _, protocol := range templateProtocols {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%v", protocol, full), func(t *testing.T) {
				template, _ := runtimeLengths(protocol)
				entered, release := make(chan struct{}), make(chan struct{})
				defer close(release)
				step := testtransport.WriteStep{Started: entered, Wait: release}
				if full {
					step = testtransport.WriteStep{N: template}
				}
				conn := &shutdownConn{runtimeConn: newRuntimeConn(append(runtimeBootstrapSteps(protocol), step)...), closed: make(chan struct{})}
				r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitRefreshReset(t, timer, 1)
				state := currentEndpoint(r).state
				sequence := state.Sequence()
				if full {
					conn.BlockDeadlineCall(10, release, entered) // fifth write's cleanup, before commit
				}
				clock.Advance(0, uint64(30*time.Second))
				fireRefresh(t, timer)
				waitRuntimeSignal(t, entered)
				if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != ErrRuntimeBusy {
					t.Fatalf("Pack during idle write = %v", err)
				}
				done := make(chan error, 1)
				go func() { done <- r.Shutdown(context.Background()) }()
				waitRuntimeSignal(t, conn.closed)
				if full {
					select {
					case <-r.drained:
						t.Fatal("worker drained before full-write commit")
					default:
					}
					release <- struct{}{}
				}
				if err := waitRuntimeError(t, done); err != nil {
					t.Fatal(err)
				}
				assertRuntimeIdle(t, r, false)
				wantShape := 0
				if full {
					wantShape = 1
					if protocol == wire.ProtocolV9 {
						sequence++
					}
				}
				if state.Progress().NextShape != wantShape || state.Sequence() != sequence || state.pending != nil || len(dnsPackets(conn.runtimeConn)) != 5 || conn.closes.Load() != 1 {
					t.Fatal("shutdown lost full-write boundary or sent another shape")
				}
				_, stopped, _ := timer.Snapshot()
				if !stopped || timer.Fire() {
					t.Fatal("shutdown did not stop template timer")
				}
			})
		}
	}
}

func TestCandidateRuntimeInvalidRefreshTimer(t *testing.T) {
	for _, protocol := range templateProtocols {
		for _, mode := range []string{"nil_timer", "nil_channel", "shared_dns_timer"} {
			t.Run(fmt.Sprintf("%s/%s", protocol, mode), func(t *testing.T) {
				lookup := testtransport.NewResolver()
				dial := func(context.Context, netip.AddrPort) (transport.Conn, error) {
					t.Error("invalid refresh timer reached dial")
					return nil, nil
				}
				var r *Runtime
				var dnsTimer *testclock.Timer
				if mode == "shared_dns_timer" {
					r, _, dnsTimer = newDNSRuntime(t, protocol, 4739, lookup, dial)
					r.config.NewTimer = func(time.Duration) transport.Timer { return dnsTimer }
				} else {
					r, _, _ = newIdleRuntime(t, protocol, runtimeRemote, dial)
				}
				invalid := &nilChannelTimer{}
				if mode != "shared_dns_timer" {
					r.config.NewTimer = func(time.Duration) transport.Timer {
						if mode == "nil_timer" {
							return nil
						}
						return invalid
					}
				}
				if err := r.Start(context.Background()); err != ErrInvalidConfig {
					t.Fatalf("Start = %v", err)
				}
				assertRuntimeIdle(t, r, false)
				if len(lookup.Events()) != 0 || (mode == "nil_channel" && !invalid.stopped) {
					t.Fatal("invalid timer not cleaned/rejected before lookup")
				}
				if dnsTimer != nil {
					_, stopped, _ := dnsTimer.Snapshot()
					if !stopped {
						t.Fatal("shared timer not stopped")
					}
				}
			})
		}
	}
}

func TestRefreshIdleCoalescesWithConsume(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			template, data := runtimeLengths(protocol)
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			steps := append(runtimeBootstrapSteps(protocol),
				testtransport.WriteStep{N: template, Started: entered, Wait: release},
				testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
			conn := newRuntimeConn(steps...)
			r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			var observed eventCounts
			r.config.Observe = observed.observe
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitRefreshReset(t, timer, 1)
			clock.Advance(0, uint64(30*time.Second))
			packed := make(chan error, 1)
			logs := validPackerLogs(t)
			go func() {
				_, err := r.Pack(context.Background(), logs, nil)
				packed <- err
			}()
			waitRuntimeSignal(t, entered)
			fireRefresh(t, timer) // the idle worker must share the data sender's round
			for range 20 {
				r.triggerRefresh() // all rechecks coalesce into the one fixed slot
			}
			release <- struct{}{}
			if err := waitRuntimeError(t, packed); err != nil {
				t.Fatal(err)
			}
			// If the worker saw the completed round before taking send, it may
			// consume the queued recheck separately, but neither recheck writes.
			for {
				delays, _, changed := timer.Snapshot()
				if len(delays) >= 2 {
					break
				}
				waitRuntimeSignal(t, changed)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if len(dnsPackets(conn)) != 7 || conn.closes.Load() != 1 {
				t.Fatal("timer/Consume rechecks duplicated a refresh round")
			}
			observed.require(t, RefreshConfirmed, 2, uint64(2*template))
			observed.require(t, RefreshAmbiguous, 0, 0)
			observed.require(t, DataConfirmed, 1, uint64(data))
			assertRuntimeIdle(t, r, false)
		})
	}
}

type gatedRefreshClock struct {
	transport.Clock
	armed            atomic.Bool
	entered, release chan struct{}
}

func (c *gatedRefreshClock) Now() (uint64, uint64) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return c.Clock.Now()
}

func newIdleDNSRuntime(t *testing.T, protocol wire.Protocol, lookup transport.LookupNetIP, dial transport.NumericDial) (*Runtime, *testclock.Clock, *testclock.Timer, *testclock.Timer) {
	t.Helper()
	compiled, writer, config := runtimeConfig(t, protocol)
	clock := testclock.New(4_000_000_000, 1)
	dnsTimer, refreshTimer := testclock.NewTimer(), testclock.NewTimer()
	config.State.RefreshInterval, config.DNSStaleAfter = 30*time.Second, 2*time.Minute
	timerCalls := 0
	config.NewTimer = func(time.Duration) transport.Timer {
		timerCalls++
		if timerCalls == 1 {
			return dnsTimer
		}
		return refreshTimer
	}
	resolver, err := transport.NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := transport.NewCandidateDialer(resolver, 4739, 464, compiled.MaxDatagramSize(), 0, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRuntime(compiled, writer, config, dialer, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, clock, dnsTimer, refreshTimer
}

func TestRefreshIdleDNSPublicationOrdering(t *testing.T) {
	for _, protocol := range templateProtocols {
		for _, order := range []string{"refresh_first", "publication_first"} {
			t.Run(fmt.Sprintf("%s/%s", protocol, order), func(t *testing.T) {
				template, _ := runtimeLengths(protocol)
				entered, release, bootstrapped := make(chan struct{}), make(chan struct{}), make(chan struct{})
				defer close(release)
				oldSteps := runtimeBootstrapSteps(protocol)
				if order == "refresh_first" {
					oldSteps = append(oldSteps, testtransport.WriteStep{N: template, Started: entered, Wait: release}, testtransport.WriteStep{N: template})
				}
				old := newRuntimeConn(oldSteps...)
				nextSteps := runtimeBootstrapSteps(protocol)
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
				gate := &gatedRefreshClock{Clock: clock, entered: entered, release: release}
				if order == "publication_first" {
					r.clock = gate
				}
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitDNSReset(t, dnsTimer, 1)
				waitRefreshReset(t, refreshTimer, 1)
				previous := currentEndpoint(r)
				clock.Advance(0, uint64(30*time.Second))
				if order == "publication_first" {
					gate.armed.Store(true) // pause after capturing old endpoint, before send
				}
				fireRefresh(t, refreshTimer)
				waitRuntimeSignal(t, entered)
				fireRefresh(t, dnsTimer)
				waitRuntimeSignal(t, bootstrapped)
				if order == "refresh_first" {
					if currentEndpoint(r) != previous || old.closes.Load() != 0 {
						t.Fatal("publication crossed an in-flight old-epoch refresh")
					}
					release <- struct{}{}
					waitDNSReset(t, dnsTimer, 2)
				} else {
					waitDNSReset(t, dnsTimer, 2)
					release <- struct{}{}
				}
				waitRefreshReset(t, refreshTimer, 2)
				published := currentEndpoint(r)
				if published == previous || len(dnsPackets(next)) != 4 || old.closes.Load() != 1 {
					t.Fatal("replacement lost fresh bootstrap or old handle ownership")
				}
				wantOld := 4
				if order == "refresh_first" {
					wantOld = 6
				}
				if len(dnsPackets(old)) != wantOld || !published.state.Ready() || published.state.Progress().LastRefreshMono != uint64(30*time.Second)+1 {
					t.Fatal("pending idle work used wrong epoch or duplicated fresh templates")
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				assertRuntimeIdle(t, r, false)
				for _, timer := range []*testclock.Timer{dnsTimer, refreshTimer} {
					_, stopped, _ := timer.Snapshot()
					if !stopped || timer.Fire() {
						t.Fatal("hostname shutdown failed to stop both timers")
					}
				}
			})
		}
	}
}

func TestRefreshIdleRejectsExpiredDNS(t *testing.T) {
	for _, protocol := range templateProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Err: errors.New("DNS failure")},
			)
			r, clock, dnsTimer, refreshTimer := newIdleDNSRuntime(t, protocol, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
			var observed eventCounts
			r.config.Observe = observed.observe
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, dnsTimer, 1)
			waitRefreshReset(t, refreshTimer, 1)
			tickDNS(t, clock, dnsTimer, 2) // failure begins the finite stale window
			state := currentEndpoint(r).state
			before, sequence := state.Progress(), state.Sequence()
			clock.Advance(0, uint64(3*time.Minute))
			fireRefresh(t, refreshTimer)
			waitRefreshReset(t, refreshTimer, 2)
			observed.require(t, RefreshFailed, 1, 0)
			observed.require(t, RefreshConfirmed, 0, 0)
			observed.require(t, DNSFailed, 1, 0)
			if r.resolver.Snapshot().Available || len(dnsPackets(conn)) != 4 || state.Progress() != before || state.Sequence() != sequence {
				t.Fatal("expired DNS constructed/committed an idle template")
			}
		})
	}
}
