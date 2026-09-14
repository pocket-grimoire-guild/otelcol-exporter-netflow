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
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
)

func TestShutdownConfigBounds(t *testing.T) {
	for _, dialer := range []*transport.CandidateDialer{nil, {}} {
		compiled, writer, config := runtimeConfig(t, wire.ProtocolV5)
		if r, err := NewRuntime(compiled, writer, config, dialer, testclock.New(4_000_000_000, 1)); r != nil || err != ErrInvalidConfig {
			t.Fatalf("empty dialer = %v, %v", r, err)
		}
	}
	for _, tc := range []struct {
		name              string
		drain, dns, write time.Duration
		want              time.Duration
	}{
		{"default", 0, time.Second, time.Second, 5 * time.Second},
		{"negative", -1, time.Second, time.Second, 0},
		{"below_min", time.Second - 1, time.Second, time.Second, 0},
		{"min_equal", time.Second, time.Second, time.Second, time.Second},
		{"max_equal", 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second},
		{"above_max", 30*time.Second + 1, time.Second, time.Second, 0},
		{"dns_above_drain", time.Second, time.Second + 1, time.Second, 0},
		{"write_above_drain", time.Second, time.Second, time.Second + 1, 0},
		{"dns_above_default", 0, 5*time.Second + 1, time.Second, 0},
		{"write_above_default", 0, time.Second, 5*time.Second + 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, writer, config := runtimeConfig(t, wire.ProtocolV5)
			config.ShutdownDrainTimeout = tc.drain
			resolver, err := transport.NewResolver("udp4", "127.0.0.1", tc.dns)
			if err != nil {
				t.Fatal(err)
			}
			dialer, err := transport.NewCandidateDialer(resolver, 4739, 464, compiled.MaxDatagramSize(), 0,
				func(context.Context, netip.AddrPort) (transport.Conn, error) {
					t.Fatal("validation dialed a socket")
					return nil, nil
				}, tc.write)
			if err != nil {
				t.Fatal(err)
			}
			r, err := NewRuntime(compiled, writer, config, dialer, testclock.New(4_000_000_000, 1))
			if tc.want == 0 {
				if r != nil || !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("NewRuntime = %v, %v", r, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.config.ShutdownDrainTimeout != tc.want {
				t.Fatalf("drain = %v", r.config.ShutdownDrainTimeout)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Closure signals follow the real fake close, so barriers prove sockets have
// stopped accepting writes without requiring a scheduler-dependent sleep.
type shutdownConn struct {
	*runtimeConn
	closed chan struct{}
	err    error
}

func (c *shutdownConn) Close() error {
	err := c.runtimeConn.Close()
	close(c.closed)
	if c.err != nil {
		return c.err
	}
	return err
}

func TestShutdownBeforeStartAndConcurrentClose(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		for _, mode := range []string{"before_start", "published", "close_error"} {
			t.Run(fmt.Sprintf("%s/%s", protocol, mode), func(t *testing.T) {
				conn := &shutdownConn{runtimeConn: newRuntimeConn(runtimeBootstrapSteps(protocol)...), closed: make(chan struct{})}
				var want error
				if mode == "close_error" {
					conn.err = errors.New("sensitive endpoint close failure")
					want = transport.ErrClosed
				}
				r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
				if err := r.Shutdown(nil); !errors.Is(err, transport.ErrInvalidContext) {
					t.Fatalf("nil context = %v", err)
				}
				if mode != "before_start" {
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 12)
				for i := range 12 {
					go func() {
						if i%2 == 0 {
							done <- r.Close()
						} else {
							done <- r.Shutdown(context.Background())
						}
					}()
				}
				for range 12 {
					if err := waitRuntimeError(t, done); err != want {
						t.Fatalf("shared shutdown result = %v, want %v", err, want)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := r.Shutdown(ctx); err != want {
					t.Fatalf("stored result = %v", err)
				}
				assertRuntimeIdle(t, r, false)
				assertShutdownRejectsCalls(t, r)
				wantCloses := int32(1)
				if mode == "before_start" {
					wantCloses = 0
				}
				if conn.closes.Load() != wantCloses {
					t.Fatalf("close count = %d", conn.closes.Load())
				}
			})
		}
	}
}

func assertShutdownRejectsCalls(t *testing.T, r *Runtime) {
	t.Helper()
	if err := r.Start(context.Background()); err != ErrRuntimeClosed {
		t.Fatalf("Start after shutdown = %v", err)
	}
	if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != ErrRuntimeClosed {
		t.Fatalf("Pack after shutdown = %v", err)
	}
}

func TestShutdownJoinsStalledWrites(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		for _, phase := range []string{"bootstrap", "data"} {
			if protocol == wire.ProtocolV5 && phase == "bootstrap" {
				continue // v5 has no bootstrap write; its startup dial is covered below.
			}
			t.Run(fmt.Sprintf("%s/%s", protocol, phase), func(t *testing.T) {
				started := make(chan struct{})
				steps := runtimeBootstrapSteps(protocol)
				blocked := testtransport.WriteStep{Wait: make(chan struct{}), Started: started}
				if phase == "bootstrap" {
					steps = []testtransport.WriteStep{blocked}
				} else {
					steps = append(steps, blocked)
				}
				conn := newRuntimeConn(steps...)
				r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
				done := make(chan error, 1)
				if phase == "bootstrap" {
					go func() { done <- r.Start(context.Background()) }()
				} else {
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					logs := appendPackerCopies(t, validPackerLogs(t), 2)
					go func() {
						result, err := r.Pack(context.Background(), logs, nil)
						if result.Classification(0) != SourceAmbiguous || result.Classification(1) != SourceUnsentValid {
							done <- fmt.Errorf("shutdown ledger: %+v", result.Counts())
							return
						}
						done <- err
					}()
				}
				waitRuntimeSignal(t, started)
				if err := r.Shutdown(context.Background()); err != nil {
					t.Fatal(err)
				}
				// Inspect registration before joining the test goroutine: Shutdown
				// itself must have drained state commits and cleanup.
				assertRuntimeIdle(t, r, false)
				if err := waitRuntimeError(t, done); !errors.Is(err, ErrPackTransient) {
					t.Fatalf("interrupted operation = %v", err)
				}
				assertShutdownRejectsCalls(t, r)
				if conn.closes.Load() != 1 {
					t.Fatalf("close count = %d", conn.closes.Load())
				}
			})
		}
	}
}

func TestShutdownJoinsDNS(t *testing.T) {
	started := make(chan struct{})
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Wait: make(chan struct{}), Started: started})
	resolver, err := transport.NewResolverWithLookup("udp4", "flows.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	compiled, writer, config := runtimeConfig(t, wire.ProtocolV9)
	dialer, err := transport.NewCandidateDialer(resolver, 4739, 464, compiled.MaxDatagramSize(), 0,
		func(context.Context, netip.AddrPort) (transport.Conn, error) {
			t.Error("canceled DNS reached dial")
			return nil, nil
		}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRuntime(compiled, writer, config, dialer, testclock.New(4_000_000_000, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background()) }()
	waitRuntimeSignal(t, started)
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRuntimeIdle(t, r, false)
	if err := waitRuntimeError(t, done); err != transport.ErrResolverCanceled {
		t.Fatalf("Start = %v", err)
	}
	if events := lookup.Events(); len(events) != 1 || !events[0].Canceled {
		t.Fatalf("DNS trace = %+v", events)
	}
}

func TestShutdownBoundAndLateDial(t *testing.T) {
	for _, mode := range []string{"cooperative", "caller_deadline", "caller_cancel", "configured_drain"} {
		t.Run(mode, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			conn := newRuntimeConn()
			r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(ctx context.Context, _ netip.AddrPort) (transport.Conn, error) {
				close(started)
				if mode == "cooperative" {
					<-ctx.Done()
				} else {
					<-release // intentionally noncooperative, but eventually joined below
				}
				return conn, nil
			}, testclock.New(4_000_000_000, 1))
			r.config.ShutdownDrainTimeout = time.Second
			done := make(chan error, 1)
			go func() { done <- r.Start(context.Background()) }()
			waitRuntimeSignal(t, started)
			ctx := context.Background()
			var want error
			switch mode {
			case "caller_deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
				want = context.DeadlineExceeded
			case "caller_cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "configured_drain":
				want = context.DeadlineExceeded
			}
			before := time.Now()
			if err := r.Shutdown(ctx); err != want {
				t.Fatalf("Shutdown = %v, want %v", err, want)
			}
			elapsed := time.Since(before)
			if elapsed > 2*time.Second || (mode == "configured_drain" && elapsed < 900*time.Millisecond) || (mode == "caller_deadline" && elapsed > 500*time.Millisecond) {
				t.Fatalf("shutdown bound: %v", elapsed)
			}
			assertShutdownRejectsCalls(t, r)
			if mode != "cooperative" {
				// Release without closing twice; the deferred close is the cleanup
				// fallback when a preceding assertion fails.
				release <- struct{}{}
			}
			if err := waitRuntimeError(t, done); err == nil {
				t.Fatal("late dial published")
			}
			assertRuntimeIdle(t, r, false)
			if conn.closes.Load() != 1 || len(conn.Writes()) != 0 {
				t.Fatal("late dial was written or not closed exactly once")
			}
			if err := r.Close(); err != want {
				t.Fatalf("stored result changed after drain: %v", err)
			}
		})
	}
}

func TestShutdownConcurrentDeadlineAndLateLookup(t *testing.T) {
	state := customPackerState(t, false, 464, 0, 2)
	// The custom shape has one ordinary and one enterprise descriptor: two
	// 36-byte IPFIX bootstrap datagrams. Data stays buffered before shutdown.
	conn := &shutdownConn{runtimeConn: newRuntimeConn(testtransport.WriteStep{N: 36}, testtransport.WriteStep{N: 36}), closed: make(chan struct{})}
	resolver, err := transport.NewResolver("udp4", "127.0.0.1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := transport.NewCandidateDialer(resolver, 4739, 464, state.Mapping().MaxDatagramSize(), 0,
		func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRuntime(state.Mapping(), ipfix.Writer{}, RuntimeConfig{State: state.Config(), DNSRefresh: time.Second, DNSStaleAfter: time.Minute}, dialer, testclock.New(4_000_000_000, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	published := r.published
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	packed := make(chan error, 1)
	logs := appendPackerCopies(t, validPackerLogs(t), 2)
	go func() {
		result, err := r.Pack(context.Background(), logs, func(ordinal uint64, _ string) (wire.Value, bool) {
			if ordinal == 1 {
				close(entered)
				<-release
			}
			return wire.UintValue(7), true
		})
		if result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceUnsentValid {
			packed <- fmt.Errorf("late lookup ledger: %+v", result.Counts())
			return
		}
		packed <- err
	}()
	waitRuntimeSignal(t, entered)
	first := make(chan error, 1)
	go func() { first <- r.Shutdown(context.Background()) }()
	waitRuntimeSignal(t, conn.closed)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := r.Shutdown(ctx); err != context.DeadlineExceeded {
		t.Fatalf("shorter concurrent deadline = %v", err)
	}
	if err := waitRuntimeError(t, first); err != context.DeadlineExceeded {
		t.Fatalf("first caller did not share deadline result: %v", err)
	}
	assertShutdownRejectsCalls(t, r) // closed wins even though Pack still owns send
	eventCount := len(conn.Events())
	release <- struct{}{}
	if err := waitRuntimeError(t, packed); err != ErrPackTransient {
		t.Fatalf("Pack = %v", err)
	}
	assertRuntimeIdle(t, r, false)
	if len(conn.Events()) != eventCount || published.state.Sequence() != 0 || published.state.pending != nil || conn.closes.Load() != 1 {
		t.Fatal("late callback wrote, committed, retained a packet or closed twice")
	}
	if err := r.Close(); err != context.DeadlineExceeded {
		t.Fatalf("stored timeout = %v", err)
	}
}

func TestShutdownJoinsFullWriteCommit(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			_, dataLength := runtimeLengths(protocol)
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: dataLength})
			conn := &shutdownConn{runtimeConn: newRuntimeConn(steps...), closed: make(chan struct{})}
			r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			published := r.published
			sequence := published.state.Sequence()
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			// Pause deadline cleanup after the full Write returned, before its
			// State/ledger commit. Close still interrupts the socket promptly.
			conn.BlockDeadlineCall(2*len(steps), release, entered)
			packed := make(chan error, 1)
			logs := validPackerLogs(t)
			go func() {
				result, err := r.Pack(context.Background(), logs, nil)
				if result.Counts().Confirmed != 1 {
					packed <- fmt.Errorf("lost full-write commit: %+v", result.Counts())
					return
				}
				packed <- err
			}()
			waitRuntimeSignal(t, entered)
			done := make(chan error, 1)
			go func() { done <- r.Shutdown(context.Background()) }()
			waitRuntimeSignal(t, conn.closed)
			select {
			case <-r.drained:
				t.Fatal("shutdown drained before full-write commit")
			default:
			}
			release <- struct{}{}
			if err := waitRuntimeError(t, done); err != nil {
				t.Fatal(err)
			}
			assertRuntimeIdle(t, r, false)
			if published.state.Sequence() != sequence+1 || published.state.pending != nil {
				t.Fatal("shutdown returned before exact full-write commit")
			}
			if err := waitRuntimeError(t, packed); err != nil {
				t.Fatal(err)
			}
		})
	}
}
