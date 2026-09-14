package destination

import (
	"context"
	"errors"
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

var replacementRemote = netip.MustParseAddrPort("[::1]:4739")

func newDNSRuntime(t *testing.T, protocol wire.Protocol, port uint16, lookup transport.LookupNetIP, dial transport.NumericDial) (*Runtime, *testclock.Clock, *testclock.Timer) {
	t.Helper()
	compiled, writer, config := runtimeConfig(t, protocol)
	clock, timer := testclock.New(4_000_000_000, 1), testclock.NewTimer()
	config.DNSStaleAfter = 3 * time.Second
	timerCalls := 0
	config.NewTimer = func(time.Duration) transport.Timer {
		timerCalls++
		if timerCalls%2 == 1 || protocol == wire.ProtocolV5 {
			return timer
		}
		return testclock.NewTimer()
	}
	resolver, err := transport.NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := transport.NewCandidateDialer(resolver, port, 464, compiled.MaxDatagramSize(), 0, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRuntime(compiled, writer, config, dialer, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, clock, timer
}

func waitDNSReset(t *testing.T, timer *testclock.Timer, count int) {
	t.Helper()
	for {
		delays, stopped, changed := timer.Snapshot()
		if stopped && len(delays) != 0 {
			t.Fatal("DNS timer stopped before expected reset")
		}
		if len(delays) >= count {
			if len(delays) != count {
				t.Fatalf("unexpected DNS timer resets: %v", delays)
			}
			for _, delay := range delays {
				if delay != time.Second {
					t.Fatalf("unbounded DNS retry interval: %v", delay)
				}
			}
			return
		}
		waitRuntimeSignal(t, changed)
	}
}

func tickDNS(t *testing.T, clock *testclock.Clock, timer *testclock.Timer, reset int) {
	t.Helper()
	clock.Advance(0, uint64(time.Second))
	if !timer.Fire() {
		t.Fatal("DNS timer not armed")
	}
	waitDNSReset(t, timer, reset)
}

func currentEndpoint(r *Runtime) *endpoint {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	return r.published
}

func dnsPackets(conn *runtimeConn) [][]byte {
	var packets [][]byte
	for _, event := range conn.Events() {
		if event.Kind == testtransport.EventWrite {
			packets = append(packets, event.Payload)
		}
	}
	return packets
}

func newReplacementConn(steps ...testtransport.WriteStep) *runtimeConn {
	return &runtimeConn{Conn: testtransport.NewConn(netip.MustParseAddrPort("[::1]:40001"), replacementRemote, steps...)}
}

func TestDNSRuntimeRetainsEpoch(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			_, data := runtimeLengths(protocol)
			conn := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: data})...)
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr(), runtimeRemote.Addr(), runtimeRemote.Addr()}},
			)
			var dials atomic.Int32
			r, clock, timer := newDNSRuntime(t, protocol, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
				dials.Add(1)
				return conn, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			if err := r.Start(ctx); err != nil {
				t.Fatal(err)
			}
			cancel() // the successful Start caller does not own worker lifetime
			waitDNSReset(t, timer, 1)
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatal(err)
			}
			old := currentEndpoint(r)
			before, packets := old.state.Progress(), len(dnsPackets(conn))
			clock.SetWall(90_000_000_000) // wall jumps do not make DNS due
			if !timer.Fire() {
				t.Fatal("timer not armed")
			}
			waitDNSReset(t, timer, 2)
			if len(lookup.Events()) != 1 {
				t.Fatal("wall clock caused DNS lookup")
			}
			tickDNS(t, clock, timer, 3)
			if currentEndpoint(r) != old || old.state.Progress() != before || dials.Load() != 1 || conn.closes.Load() != 0 || len(dnsPackets(conn)) != packets {
				t.Fatal("same-address refresh replaced or changed the epoch")
			}
			if len(lookup.Events()) != 2 || r.resolver.Snapshot().Stale || !r.resolver.Snapshot().Available {
				t.Fatal("same-address DNS metadata not refreshed")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			_, stopped, _ := timer.Snapshot()
			if !stopped || timer.Fire() || conn.closes.Load() != 1 {
				t.Fatal("shutdown did not join timer and close once")
			}
			assertRuntimeIdle(t, r, false)
		})
	}
}

func TestDNSRuntimeReplacement(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			_, data := runtimeLengths(protocol)
			old := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: data})...)
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			steps := runtimeBootstrapSteps(protocol)
			if len(steps) != 0 {
				steps[0].Started, steps[0].Wait = entered, release
			}
			next := newReplacementConn(append(steps, testtransport.WriteStep{N: data})...)
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
			)
			r, clock, timer := newDNSRuntime(t, protocol, 4739, lookup, func(ctx context.Context, remote netip.AddrPort) (transport.Conn, error) {
				if remote == runtimeRemote {
					return old, nil
				}
				if protocol == wire.ProtocolV5 {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return next, nil
			})
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, timer, 1)
			previous := currentEndpoint(r)
			clock.Advance(0, uint64(time.Second))
			if !timer.Fire() {
				t.Fatal("timer not armed")
			}
			waitRuntimeSignal(t, entered)
			r.lifecycle.Lock()
			registered := r.attempt != nil && r.attempt.previous == previous
			attached := registered && r.attempt.candidate != nil
			r.lifecycle.Unlock()
			if !registered || (protocol != wire.ProtocolV5 && !attached) || currentEndpoint(r) != previous || old.closes.Load() != 0 {
				t.Fatal("candidate not registered/attached, or published before bootstrap")
			}
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatalf("old endpoint unusable during candidate setup: %v", err)
			}
			oldProgress := previous.state.Progress()
			close(release)
			waitDNSReset(t, timer, 2)
			published := currentEndpoint(r)
			wantSequence := uint32(0)
			if protocol == wire.ProtocolV9 {
				wantSequence = 4
			}
			if published == previous || published.candidate.RemoteAddr() != replacementRemote || published.state.Sequence() != wantSequence || old.closes.Load() != 1 || next.closes.Load() != 0 || previous.state.Progress() != oldProgress {
				t.Fatal("replacement did not atomically install a fresh epoch and retire old")
			}
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatal(err)
			}
			for index, packet := range dnsPackets(next) {
				assertRuntimeDatagram(t, protocol, index, packet)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if old.closes.Load() != 1 || next.closes.Load() != 1 {
				t.Fatal("handle closed more than once")
			}
		})
	}
}

func TestDNSRuntimeFailureExpiryAndRecovery(t *testing.T) {
	for _, mode := range []string{"lookup", "dial", "bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			protocol := wire.ProtocolIPFIX
			old := newRuntimeConn(append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: 24})...)
			failed := newReplacementConn(testtransport.WriteStep{N: 1})
			recovered := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
			failure := testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}}
			if mode == "lookup" {
				failure = testtransport.ResolverStep{Err: errors.New("sensitive DNS error")}
			}
			if err := lookup.AddStep(failure); err != nil {
				t.Fatal(err)
			}
			// A later failure must not extend the first stale origin.
			if err := lookup.AddStep(testtransport.ResolverStep{Err: errors.New("second failure")}); err != nil {
				t.Fatal(err)
			}
			recoveryEntered, recoveryRelease := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-recoveryRelease:
				default:
					close(recoveryRelease)
				}
			}()
			if err := lookup.AddStep(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}, Started: recoveryEntered, Wait: recoveryRelease}); err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			r, clock, timer := newDNSRuntime(t, protocol, 4739, lookup, func(_ context.Context, remote netip.AddrPort) (transport.Conn, error) {
				call := dials.Add(1)
				if call == 1 {
					return old, nil
				}
				if remote == runtimeRemote {
					return recovered, nil
				}
				if mode == "dial" {
					return failed, errors.New("sensitive dial error")
				}
				return failed, nil
			})
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, timer, 1)
			previous := currentEndpoint(r)
			tickDNS(t, clock, timer, 2)
			stale := r.resolver.Snapshot()
			if !stale.Stale || !stale.Available || currentEndpoint(r) != previous || old.closes.Load() != 0 {
				t.Fatal("failure discarded usable old endpoint")
			}
			if mode != "lookup" && failed.closes.Load() != 1 {
				t.Fatal("failed candidate not closed once")
			}
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatal(err)
			}
			tickDNS(t, clock, timer, 3)
			if r.resolver.Snapshot().StaleSince != stale.StaleSince {
				t.Fatal("failure extended stale retention")
			}
			clock.Advance(0, uint64(2*time.Second)) // exact first-failure + stale_after
			before, events := previous.state.Progress(), len(old.Events())
			if n, err := r.writePublished(context.Background(), previous.candidate, []byte{1}); n != 0 || err != ErrRuntimeUnavailable || len(old.Events()) != events {
				t.Fatal("registered handoff did not recheck stale expiry")
			}
			result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
			if result != nil || err != ErrRuntimeUnavailable || !r.resolver.Snapshot().StaleExpired || previous.state.Progress() != before || len(old.Events()) != events {
				t.Fatal("expired destination constructed, wrote or advanced state")
			}
			waitRuntimeSignal(t, recoveryEntered) // Consume also wakes due maintenance
			close(recoveryRelease)
			waitDNSReset(t, timer, 4)
			if currentEndpoint(r) == previous || currentEndpoint(r).candidate.RemoteAddr() != runtimeRemote || currentEndpoint(r).state.Sequence() != 0 || old.closes.Load() != 1 || !r.resolver.Snapshot().Available {
				t.Fatal("expired same-address recovery reused the stale epoch")
			}
			for index, packet := range dnsPackets(recovered) {
				assertRuntimeDatagram(t, protocol, index, packet)
			}
		})
	}
}

func TestDNSRuntimeCoalescesConsumeAndTimer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	lookup := testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
		testtransport.ResolverStep{Err: errors.New("DNS failure"), Started: entered, Wait: release},
		testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
	)
	steps := make([]testtransport.WriteStep, 32)
	for i := range steps {
		steps[i].N = 72
	}
	conn := newRuntimeConn(steps...)
	var dials atomic.Int32
	r, clock, timer := newDNSRuntime(t, wire.ProtocolV5, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
		dials.Add(1)
		return conn, nil
	})
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDNSReset(t, timer, 1)
	clock.Advance(0, uint64(time.Second))
	if !timer.Fire() {
		t.Fatal("timer not armed")
	}
	waitRuntimeSignal(t, entered)
	logs := validPackerLogs(t)
	for range 32 {
		if _, err := r.Pack(context.Background(), logs, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.dnsWake) != 1 || len(lookup.Events()) != 1 || dials.Load() != 1 {
		t.Fatal("Consume triggers did not coalesce behind one lookup")
	}
	close(release)
	waitDNSReset(t, timer, 2)
	// An early timer tick also rechecks monotonic freshness; neither it nor
	// the queued Consume wake can turn a failure into an immediate retry.
	if !timer.Fire() {
		t.Fatal("timer not rearmed after failure")
	}
	waitDNSReset(t, timer, 3)
	if len(lookup.Events()) != 2 || dials.Load() != 1 {
		t.Fatal("tight retry after DNS failure")
	}
	tickDNS(t, clock, timer, 4)
	if len(lookup.Events()) != 3 || dials.Load() != 1 || r.resolver.Snapshot().Stale {
		t.Fatal("next interval did not recover retained address")
	}
}

func TestDNSRuntimeLiteralHasNoWorker(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		conn := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
		r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
		r.config.NewTimer = func(delay time.Duration) transport.Timer {
			if protocol == wire.ProtocolV5 || delay != r.config.State.RefreshInterval {
				t.Fatal("literal endpoint created a DNS timer")
			}
			return testclock.NewTimer()
		}
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertRuntimeIdle(t, r, true)
		r.lifecycle.Lock()
		hasDNS := r.dnsCancel != nil
		r.lifecycle.Unlock()
		if hasDNS {
			t.Fatal("literal endpoint registered worker")
		}
	}
}

type nilChannelTimer struct{ stopped bool }

func (*nilChannelTimer) C() <-chan time.Time { return nil }
func (*nilChannelTimer) Reset(time.Duration) {}
func (t *nilChannelTimer) Stop()             { t.stopped = true }

func TestCandidateRuntimeInvalidDNSTimer(t *testing.T) {
	for _, mode := range []string{"nil_timer", "nil_channel"} {
		t.Run(mode, func(t *testing.T) {
			lookup := testtransport.NewResolver()
			r, _, _ := newDNSRuntime(t, wire.ProtocolV5, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
				t.Fatal("invalid timer dialed")
				return nil, nil
			})
			invalid := &nilChannelTimer{}
			r.config.NewTimer = func(time.Duration) transport.Timer {
				if mode == "nil_timer" {
					return nil
				}
				return invalid
			}
			if err := r.Start(context.Background()); err != ErrInvalidConfig {
				t.Fatalf("Start = %v", err)
			}
			assertRuntimeIdle(t, r, false)
			if len(lookup.Events()) != 0 || (mode == "nil_channel" && !invalid.stopped) {
				t.Fatal("invalid timer was not rejected/cleaned before lookup")
			}
		})
	}
}

func TestCandidateRuntimeFailedStartStopsDNSTimer(t *testing.T) {
	for _, mode := range []string{"lookup", "dial", "bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			answer := testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}}
			if mode == "lookup" {
				answer = testtransport.ResolverStep{Err: errors.New("lookup failure")}
			}
			lookup := testtransport.NewResolver(answer)
			conn := newRuntimeConn(testtransport.WriteStep{N: 1})
			var dials int
			r, _, timer := newDNSRuntime(t, wire.ProtocolIPFIX, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
				dials++
				if mode == "dial" {
					return conn, errors.New("dial failure")
				}
				return conn, nil
			})
			refreshTimer := testclock.NewTimer()
			timerCalls := 0
			r.config.NewTimer = func(delay time.Duration) transport.Timer {
				selected := timer
				timerCalls++
				if timerCalls == 2 {
					selected = refreshTimer
				}
				selected.Reset(delay)
				return selected
			}
			if err := r.Start(context.Background()); err == nil {
				t.Fatal("initial failure accepted")
			}
			assertRuntimeIdle(t, r, false)
			delays, stopped, _ := timer.Snapshot()
			wantDials := 1
			if mode == "lookup" {
				wantDials = 0
			}
			if !stopped || len(delays) != 1 || timer.Fire() || r.dnsCancel != nil || dials != wantDials || conn.closes.Load() != int32(wantDials) {
				t.Fatal("failed Start leaked timer, worker or candidate")
			}
			delays, stopped, _ = refreshTimer.Snapshot()
			if !stopped || len(delays) != 1 || refreshTimer.Fire() || r.refreshCancel != nil {
				t.Fatal("failed Start leaked template timer or worker")
			}
		})
	}
}

func TestShutdownDNSWorker(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		for _, mode := range []string{"lookup", "dial", "bootstrap"} {
			if mode == "bootstrap" && protocol == wire.ProtocolV5 {
				continue
			}
			t.Run(protocol.String()+"/"+mode, func(t *testing.T) {
				entered, blocked := make(chan struct{}), make(chan struct{})
				old := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
				steps := runtimeBootstrapSteps(protocol)
				if mode == "bootstrap" {
					steps[0].Started, steps[0].Wait = entered, blocked
				}
				next := newReplacementConn(steps...)
				answer := testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}}
				if mode == "lookup" {
					answer.Started, answer.Wait = entered, blocked
				}
				lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}}, answer)
				r, clock, timer := newDNSRuntime(t, protocol, 4739, lookup, func(ctx context.Context, remote netip.AddrPort) (transport.Conn, error) {
					if remote == runtimeRemote {
						return old, nil
					}
					if mode == "dial" {
						close(entered)
						<-ctx.Done()
					}
					return next, nil // a late successful dial still closes before attachment
				})
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitDNSReset(t, timer, 1)
				clock.Advance(0, uint64(time.Second))
				if !timer.Fire() {
					t.Fatal("timer not armed")
				}
				waitRuntimeSignal(t, entered)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := r.Shutdown(ctx); err != nil {
					t.Fatal(err)
				}
				assertRuntimeIdle(t, r, false)
				_, stopped, _ := timer.Snapshot()
				wantNextCloses := int32(1)
				if mode == "lookup" {
					wantNextCloses = 0
				}
				if !stopped || timer.Fire() || old.closes.Load() != 1 || next.closes.Load() != wantNextCloses {
					t.Fatal("shutdown leaked timer, candidate or worker")
				}
				assertShutdownRejectsCalls(t, r)
			})
		}
	}
}

// Actual IPv4 -> IPv6 delivery uses the same numeric port and compares the new
// epoch's captured datagrams with literal protocol bytes, not a self-decoder.
func TestDNSRuntimeIPv6LoopbackReplacement(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer v4.Close()
			port := v4.LocalAddr().(*net.UDPAddr).Port
			v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
			if err != nil {
				t.Fatal(err)
			}
			defer v6.Close()
			lookup := testtransport.NewResolver(
				testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
				testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
			)
			r, clock, timer := newDNSRuntime(t, protocol, uint16(port), lookup, transport.NewDialer("udp", netip.AddrPort{}).Dial)
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitDNSReset(t, timer, 1)
			tickDNS(t, clock, timer, 2)
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatal(err)
			}
			count := 5
			if protocol == wire.ProtocolV5 {
				count = 1
			}
			if err := v6.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < count; index++ {
				buffer := make([]byte, 512)
				n, sender, err := v6.ReadFromUDPAddrPort(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if sender != currentEndpoint(r).candidate.LocalAddr() {
					t.Fatal("replacement source identity mismatch")
				}
				assertRuntimeDatagram(t, protocol, index, buffer[:n])
			}
		})
	}
}
