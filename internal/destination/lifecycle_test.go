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

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
)

var runtimeProtocols = []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX}

func runtimeConfig(t *testing.T, protocol wire.Protocol) (mapping.CompiledMapping, wire.ContractWriter, RuntimeConfig) {
	t.Helper()
	config := RuntimeConfig{State: DefaultConfig(protocol), DNSRefresh: time.Second, DNSStaleAfter: time.Minute}
	config.State.MaxRecordsPerMessage = 1
	if protocol == wire.ProtocolV5 {
		config.State.HasUptimeOrigin = true
		return compiledMapping(t, protocol), netflow5.Writer{}, config
	}
	compiled, err := mapping.Compile(mapping.Config{
		Protocol: protocol, Fields: []mapping.FieldSelection{{Canonical: "source.address"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 464, Endpoint: "127.0.0.1:4739",
	})
	if err != nil {
		t.Fatal(err)
	}
	if protocol == wire.ProtocolV9 {
		config.State.SourceID = 42
		return compiled, netflow9.Writer{}, config
	}
	config.State.ObservationDomainID = 42
	return compiled, ipfix.Writer{}, config
}

func newRuntimeForTest(t *testing.T, protocol wire.Protocol, remote netip.AddrPort, dial transport.NumericDial, clock transport.Clock) *Runtime {
	t.Helper()
	compiled, writer, config := runtimeConfig(t, protocol)
	resolver, err := transport.NewResolver("udp4", remote.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := transport.NewCandidateDialer(resolver, remote.Port(), 464, compiled.MaxDatagramSize(), 0, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRuntime(compiled, writer, config, dialer, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// Count calls outside the fake's own sync.Once, so duplicate ownership would
// fail even if the underlying transport silently made Close idempotent.
type runtimeConn struct {
	*testtransport.Conn
	closes atomic.Int32
}

func (c *runtimeConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

var runtimeRemote = netip.MustParseAddrPort("127.0.0.1:4739")

func newRuntimeConn(steps ...testtransport.WriteStep) *runtimeConn {
	return &runtimeConn{Conn: testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), runtimeRemote, steps...)}
}

func runtimeLengths(protocol wire.Protocol) (template, data int) {
	switch protocol {
	case wire.ProtocolV5:
		return 0, 72
	case wire.ProtocolV9:
		return 32, 28
	default:
		return 28, 24
	}
}

func runtimeBootstrapSteps(protocol wire.Protocol) []testtransport.WriteStep {
	template, _ := runtimeLengths(protocol)
	if template == 0 {
		return nil
	}
	return []testtransport.WriteStep{{N: template}, {N: template}, {N: template}, {N: template}}
}

func assertRuntimeIdle(t *testing.T, r *Runtime, published bool) {
	t.Helper()
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	var workers uint32
	if published && r.dnsCancel != nil {
		workers++
	}
	if published && r.refreshCancel != nil {
		workers++
	}
	if r.attempt != nil || r.activeCalls != workers || r.activeWrites != 0 || r.packCancel != nil || (r.published != nil) != published {
		t.Fatalf("attempt=%v calls=%d writes=%d published=%v", r.attempt != nil, r.activeCalls, r.activeWrites, r.published != nil)
	}
	token, err := r.maintenance.Begin()
	if err != nil {
		t.Fatalf("maintenance token leaked: %v", err)
	}
	if pending, err := r.maintenance.End(token); err != nil || pending {
		t.Fatalf("End = %v, %v", pending, err)
	}
}

// Captures come from actual numeric connected UDP writes. Expected templates
// and data below are literal protocol bytes, independent of the Go encoders.
func TestPublication(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			dialer := transport.NewDialer("udp4", netip.AddrPort{})
			r := newRuntimeForTest(t, protocol, listener.LocalAddr().(*net.UDPAddr).AddrPort(), dialer.Dial, testclock.New(4_000_000_000, 1))
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertRuntimeIdle(t, r, true)
			logs := validPackerLogs(t)
			if protocol == wire.ProtocolV5 {
				appendPackerCopies(t, logs, 2)
			} else {
				testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).CopyTo(logs.ResourceLogs().AppendEmpty())
			}
			result, err := r.Pack(context.Background(), logs, nil)
			if err != nil || result.Counts().Confirmed != 2 {
				t.Fatalf("Pack = %+v, %v", result, err)
			}
			count := 6
			if protocol == wire.ProtocolV5 {
				count = 2
			}
			if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < count; index++ {
				buffer := make([]byte, 512)
				n, sender, err := listener.ReadFromUDPAddrPort(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if sender != r.published.candidate.LocalAddr() {
					t.Fatalf("datagram %d changed source socket", index)
				}
				assertRuntimeDatagram(t, protocol, index, buffer[:n])
			}
			wantSeq := uint32(2)
			if protocol == wire.ProtocolV9 {
				wantSeq = 6
			}
			if r.published.state.Sequence() != wantSeq {
				t.Fatalf("sequence = %d, want %d", r.published.state.Sequence(), wantSeq)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Pack(context.Background(), logs, nil); !errors.Is(err, ErrRuntimeClosed) {
				t.Fatalf("Pack after Close = %v", err)
			}
			// Detect unexpected extra bootstrap/data datagrams after cleanup.
			_ = listener.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, _, err := listener.ReadFromUDPAddrPort(make([]byte, 512)); err == nil {
				t.Fatal("unexpected extra datagram")
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal(err)
			}
		})
	}
}

func assertRuntimeDatagram(t *testing.T, protocol wire.Protocol, index int, packet []byte) {
	t.Helper()
	if protocol == wire.ProtocolV5 {
		if len(packet) != 72 || binary.BigEndian.Uint16(packet[:2]) != 5 || binary.BigEndian.Uint16(packet[2:4]) != 1 || binary.BigEndian.Uint32(packet[4:8]) != 4000 || binary.BigEndian.Uint32(packet[8:12]) != 4 || binary.BigEndian.Uint32(packet[12:16]) != 0 || binary.BigEndian.Uint32(packet[16:20]) != uint32(index) || binary.BigEndian.Uint16(packet[22:24]) != 1000 {
			t.Fatalf("v5 header: %x", packet)
		}
		if !bytes.Equal(packet[24:36], []byte{192, 0, 2, 1, 198, 51, 100, 2, 192, 0, 2, 254}) || binary.BigEndian.Uint32(packet[40:44]) != 1234 || binary.BigEndian.Uint32(packet[44:48]) != 56789 || binary.BigEndian.Uint32(packet[48:52]) != 3000 || binary.BigEndian.Uint32(packet[52:56]) != 3000 || binary.BigEndian.Uint16(packet[56:58]) != 12345 || binary.BigEndian.Uint16(packet[58:60]) != 443 || packet[60] != 0 || packet[70] != 0 || packet[71] != 0 {
			t.Fatalf("v5 record: %x", packet[24:])
		}
		return
	}
	var expected string
	if protocol == wire.ProtocolV9 {
		if index < 4 {
			expected = "000900010000000000000004000000000000002a0000000c0100000100080004"
			if index%2 == 1 {
				expected = "000900010000000000000004000000000000002a0000000c01010001001b0010"
			}
		} else if index == 4 {
			expected = "000900010000000000000004000000000000002a01000008c0000201"
		} else {
			expected = "000900010000000000000004000000000000002a0101001420010db8000000000000000000000001"
		}
	} else if index < 4 {
		expected = "000a001c00000004000000000000002a0002000c0100000100080004"
		if index%2 == 1 {
			expected = "000a001c00000004000000000000002a0002000c01010001001b0010"
		}
	} else if index == 4 {
		expected = "000a001800000004000000000000002a01000008c0000201"
	} else {
		expected = "000a002400000004000000010000002a0101001420010db8000000000000000000000001"
	}
	golden, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == wire.ProtocolV9 {
		binary.BigEndian.PutUint32(golden[12:16], uint32(index))
	}
	if !bytes.Equal(packet, golden) {
		t.Fatalf("datagram %d:\n got %x\nwant %x", index, packet, golden)
	}
}

func TestPublicationRegistrationAndCommits(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			_, dataLength := runtimeLengths(protocol)
			steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: dataLength})
			var r *Runtime
			var ledger []string
			for index := range steps {
				steps[index].OnWrite = func() {
					r.lifecycle.Lock()
					defer r.lifecycle.Unlock()
					if r.activeWrites != 1 {
						t.Fatal("write not registered")
					}
					if r.published == nil {
						if r.attempt == nil || r.attempt.candidate == nil {
							t.Fatal("bootstrap before attachment")
						}
						ledger = append(ledger, "template")
					} else {
						want := uint32(0)
						if protocol == wire.ProtocolV9 {
							want = 4
						}
						if r.published.state.Sequence() != want {
							t.Fatal("data committed before full write")
						}
						ledger = append(ledger, "data")
					}
				}
			}
			conn := newRuntimeConn(steps...)
			r = newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
				r.lifecycle.Lock()
				defer r.lifecycle.Unlock()
				sendAvailable := false
				select {
				case <-r.send.token:
					sendAvailable = true
				default:
				}
				if r.attempt == nil || r.attempt.candidate != nil || r.published != nil || !sendAvailable {
					t.Fatal("dial was not registered outside send")
				}
				r.send.release()
				ledger = append(ledger, "dial")
				return conn, nil
			}, testclock.New(4_000_000_000, 1))
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); !errors.Is(err, ErrRuntimeUnavailable) {
				t.Fatalf("Pack before Start = %v", err)
			}
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ledger = append(ledger, "publish")
			if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
				t.Fatal(err)
			}
			assertRuntimeIdle(t, r, true)
			if err := r.Start(context.Background()); err != nil { // no second dial
				t.Fatal(err)
			}
			_ = r.Close()
			_ = r.Close()
			if conn.closes.Load() != 1 {
				t.Fatalf("Close calls = %d", conn.closes.Load())
			}
			want := "[dial template template template template publish data]"
			if protocol == wire.ProtocolV5 {
				want = "[dial publish data]"
			}
			if fmt.Sprint(ledger) != want {
				t.Fatalf("ledger = %v, want %s", ledger, want)
			}
		})
	}
}

func TestPublicationBootstrapFailureAndFreshRetry(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		templateLength, _ := runtimeLengths(protocol)
		for failedAt := range 4 {
			for _, outcome := range []struct {
				name string
				n    int
				err  error
			}{{"short_nil", 1, nil}, {"zero_nil", 0, nil}, {"short_error", 1, errors.New("private")}, {"zero_error", 0, errors.New("private")}, {"full_error", templateLength, errors.New("private")}, {"invalid", templateLength + 1, nil}} {
				t.Run(fmt.Sprintf("%s/%d/%s", protocol, failedAt, outcome.name), func(t *testing.T) {
					steps := runtimeBootstrapSteps(protocol)
					steps[failedAt] = testtransport.WriteStep{N: outcome.n, Err: outcome.err}
					failed, fresh := newRuntimeConn(steps...), newRuntimeConn(runtimeBootstrapSteps(protocol)...)
					calls := 0
					r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
						calls++
						if calls == 1 {
							return failed, nil
						}
						return fresh, nil
					}, testclock.New(4_000_000_000, 1))
					if err := r.Start(context.Background()); err == nil {
						t.Fatal("failed bootstrap published")
					}
					assertRuntimeIdle(t, r, false)
					if r.resolver.Snapshot().Available || len(failed.Writes()) != failedAt+1 || failed.closes.Load() != 1 {
						t.Fatalf("failed epoch retained: writes=%d closes=%d", len(failed.Writes()), failed.closes.Load())
					}
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					assertRuntimeIdle(t, r, true)
					for i, event := range fresh.Writes() {
						assertRuntimeDatagram(t, protocol, i, event.Payload)
					}
					_ = r.Close()
					if failed.closes.Load() != 1 || fresh.closes.Load() != 1 {
						t.Fatal("candidate ownership duplicated")
					}
				})
			}
		}
	}
}

func TestPublicationCancelAndClose(t *testing.T) {
	for _, action := range []string{"cancel", "close"} {
		t.Run(action+"_bootstrap", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{}, 1)
			conn := newRuntimeConn(testtransport.WriteStep{Wait: make(chan struct{}), Started: started})
			r := newRuntimeForTest(t, wire.ProtocolV9, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
			done := make(chan error, 1)
			go func() { done <- r.Start(ctx) }()
			waitRuntimeSignal(t, started)
			if err := r.Start(ctx); !errors.Is(err, ErrRuntimeBusy) {
				t.Fatalf("concurrent Start = %v", err)
			}
			if action == "cancel" {
				cancel()
			} else if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := waitRuntimeError(t, done); !errors.Is(err, ErrPackTransient) {
				t.Fatalf("Start = %v", err)
			}
			assertRuntimeIdle(t, r, false)
			if conn.closes.Load() != 1 || len(conn.Writes()) != 1 || r.resolver.Snapshot().Available {
				t.Fatal("failed startup not cleaned up")
			}
			_ = r.Close()
			if conn.closes.Load() != 1 {
				t.Fatal("second Close")
			}
		})
	}
	t.Run("close_dial", func(t *testing.T) {
		started := make(chan struct{}, 1)
		conn := newRuntimeConn()
		r := newRuntimeForTest(t, wire.ProtocolV9, runtimeRemote, func(ctx context.Context, _ netip.AddrPort) (transport.Conn, error) {
			started <- struct{}{}
			<-ctx.Done()
			return conn, nil // deliberately late successful dial
		}, testclock.New(4_000_000_000, 1))
		done := make(chan error, 1)
		go func() { done <- r.Start(context.Background()) }()
		waitRuntimeSignal(t, started)
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := waitRuntimeError(t, done); err == nil {
			t.Fatal("closed dial published")
		}
		assertRuntimeIdle(t, r, false)
		if conn.closes.Load() != 1 || len(conn.Events()) != 1 || conn.Events()[0].Kind != testtransport.EventClose {
			t.Fatal("late dial was written or not closed exactly once")
		}
	})
	t.Run("already_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			t.Fatal("dial after caller cancellation")
			return nil, nil
		}, testclock.New(4_000_000_000, 1))
		if err := r.Start(ctx); err == nil {
			t.Fatal("canceled Start succeeded")
		}
		assertRuntimeIdle(t, r, false)
		_ = r.Close()
		if err := r.Start(context.Background()); !errors.Is(err, ErrRuntimeClosed) {
			t.Fatalf("Start after Close = %v", err)
		}
	})
}

func TestPublicationRechecksBeforeCommit(t *testing.T) {
	for _, failure := range []string{"cancel", "close", "clock", "generation"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := testclock.New(4_000_000_000, 10)
			var r *Runtime
			steps := runtimeBootstrapSteps(wire.ProtocolV9)
			steps[3].OnWrite = func() {
				switch failure {
				case "cancel":
					cancel()
				case "close":
					// Inject closure at the publication boundary. A terminal
					// Shutdown here would try to join its own Start callback.
					r.closeHandles()
				case "clock":
					clock.SetMonotonic(9)
				case "generation":
					// Fault injection: give the runtime fresh resolver metadata
					// while its already attached candidate carries the old generation.
					other := transport.NewMaintenance()
					state, err := transport.NewResolverState(clock, other, time.Second, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					r.resolver = state
				}
			}
			conn := newRuntimeConn(steps...)
			r = newRuntimeForTest(t, wire.ProtocolV9, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, clock)
			if err := r.Start(ctx); err == nil {
				t.Fatal("candidate published after final revalidation failure")
			}
			assertRuntimeIdle(t, r, false)
			if len(conn.Writes()) != 4 || conn.closes.Load() != 1 || r.resolver.Snapshot().Available {
				t.Fatal("complete but unpublished bootstrap retained")
			}
		})
	}
}

func TestCandidateRuntimeBudgetBeforeDial(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		t.Run(protocol.String(), func(t *testing.T) {
			compiled, writer, config := runtimeConfig(t, protocol)
			resolver, err := transport.NewResolver("udp", "flow.example", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			dial := func(context.Context, netip.AddrPort) (transport.Conn, error) {
				t.Fatal("invalid budget dialed")
				return nil, nil
			}
			if _, err := transport.NewCandidateDialer(resolver, 4739, 465, 465, 512, dial, time.Second); !errors.Is(err, transport.ErrCandidatePMTU) {
				t.Fatalf("hostname PMTU = %v", err)
			}
			dialer, err := transport.NewCandidateDialer(resolver, 4739, 128, compiled.MaxDatagramSize(), 512, dial, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewRuntime(compiled, writer, config, dialer, testclock.New(4_000_000_000, 1)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("mismatched packer/transport budget = %v", err)
			}
		})
	}
}

func TestPacking(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		_, dataLength := runtimeLengths(protocol)
		for _, outcome := range []struct {
			name string
			n    int
			err  error
		}{{"full", dataLength, nil}, {"short_nil", 1, nil}, {"zero_nil", 0, nil}, {"short_error", 1, errors.New("private endpoint")}, {"zero_error", 0, errors.New("private endpoint")}, {"full_error", dataLength, errors.New("private endpoint")}, {"invalid", -1, nil}} {
			t.Run(fmt.Sprintf("%s/%s", protocol, outcome.name), func(t *testing.T) {
				steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: dataLength}, testtransport.WriteStep{N: outcome.n, Err: outcome.err}, testtransport.WriteStep{N: dataLength})
				conn := newRuntimeConn(steps...)
				r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				logs := appendPackerCopies(t, validPackerLogs(t), 5)
				records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
				records.At(1).Attributes().Remove("source.address")
				records.At(4).Attributes().Remove("source.address")
				result, err := r.Pack(context.Background(), logs, nil)
				classes := []SourceClass{SourceConfirmed, SourceInvalid, SourceAmbiguous, SourceUnsentValid, SourceInvalid}
				wantSeq := uint32(1)
				wantWrites := 2
				switch outcome.name {
				case "full":
					if err != nil {
						t.Fatal(err)
					}
					classes[2], classes[3] = SourceConfirmed, SourceConfirmed
					wantSeq, wantWrites = 3, 3
				case "invalid":
					if !errors.Is(err, ErrPackInternal) {
						t.Fatalf("Pack = %v", err)
					}
					classes[2] = SourceUnsentValid
				default:
					if !errors.Is(err, ErrPackTransient) {
						t.Fatalf("Pack = %v", err)
					}
				}
				for i, want := range classes {
					if got := result.Classification(uint64(i)); got != want {
						t.Fatalf("source %d class = %v, want %v", i, got, want)
					}
				}
				if protocol == wire.ProtocolV9 {
					wantSeq += 4
				}
				if protocol != wire.ProtocolV5 {
					wantWrites += 4
				}
				if r.published.state.Sequence() != wantSeq || len(conn.Writes()) != wantWrites {
					t.Fatalf("sequence/writes = %d/%d, want %d/%d", r.published.state.Sequence(), len(conn.Writes()), wantSeq, wantWrites)
				}
				if result.Counts().Invalid != 2 || result.Counts().Valid != 3 {
					t.Fatalf("counts = %+v", result.Counts())
				}
				assertRuntimeIdle(t, r, true)
			})
		}
	}
}

func TestPackingRuntimeCancellationAndClose(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		for _, action := range []string{"cancel", "close"} {
			t.Run(fmt.Sprintf("%s/%s", protocol, action), func(t *testing.T) {
				_, dataLength := runtimeLengths(protocol)
				started := make(chan struct{}, 1)
				steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{Wait: make(chan struct{}), Started: started}, testtransport.WriteStep{N: dataLength})
				conn := newRuntimeConn(steps...)
				r := newRuntimeForTest(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil }, testclock.New(4_000_000_000, 1))
				startCtx, startCancel := context.WithCancel(context.Background())
				if err := r.Start(startCtx); err != nil {
					t.Fatal(err)
				}
				startCancel() // published writes must not retain Start's context
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					result, err := r.Pack(ctx, appendPackerCopies(t, validPackerLogs(t), 2), nil)
					if result.Classification(0) != SourceAmbiguous || result.Classification(1) != SourceUnsentValid {
						done <- fmt.Errorf("bad canceled-write ledger: %+v", result.Counts())
						return
					}
					done <- err
				}()
				waitRuntimeSignal(t, started)
				if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); !errors.Is(err, ErrRuntimeBusy) {
					t.Fatalf("concurrent Pack = %v", err)
				}
				if action == "cancel" {
					cancel()
				} else {
					_ = r.Close()
				}
				if err := waitRuntimeError(t, done); !errors.Is(err, ErrPackTransient) {
					t.Fatal(err)
				}
				assertRuntimeIdle(t, r, action == "cancel")
				if action == "cancel" {
					// This new request has its own context and cleared deadlines.
					result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
					if err != nil || result.Counts().Confirmed != 1 {
						t.Fatalf("next request = %+v, %v", result, err)
					}
				}
				_ = r.Close()
				if conn.closes.Load() != 1 {
					t.Fatalf("Close calls = %d", conn.closes.Load())
				}
			})
		}
	}
}

func waitRuntimeSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime operation did not reach barrier")
	}
}

func waitRuntimeError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("runtime operation did not complete")
		return nil
	}
}

func TestCandidateRuntimeLookupAndDialFailure(t *testing.T) {
	for _, protocol := range runtimeProtocols {
		for _, failure := range []string{"lookup", "dial"} {
			t.Run(fmt.Sprintf("%s/%s", protocol, failure), func(t *testing.T) {
				compiled, writer, config := runtimeConfig(t, protocol)
				step := testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}}
				if failure == "lookup" {
					step.Err = errors.New("private hostname")
				}
				resolver, err := transport.NewResolverWithLookup("udp4", "flow.example", time.Second, testtransport.NewResolver(step))
				if err != nil {
					t.Fatal(err)
				}
				conn := newRuntimeConn()
				dialer, err := transport.NewCandidateDialer(resolver, runtimeRemote.Port(), 464, compiled.MaxDatagramSize(), 0, func(context.Context, netip.AddrPort) (transport.Conn, error) {
					if failure == "lookup" {
						t.Fatal("failed lookup reached dial")
					}
					return conn, errors.New("private endpoint")
				}, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				r, err := NewRuntime(compiled, writer, config, dialer, testclock.New(4_000_000_000, 1))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				wantErr := transport.ErrResolverLookup
				wantCloses := int32(0)
				if failure == "dial" {
					wantErr, wantCloses = transport.ErrDial, 1
				}
				if err := r.Start(context.Background()); !errors.Is(err, wantErr) {
					t.Fatalf("Start = %v, want fixed %v", err, wantErr)
				}
				assertRuntimeIdle(t, r, false)
				if conn.closes.Load() != wantCloses || len(conn.Writes()) != 0 {
					t.Fatal("failed setup retained or wrote a socket")
				}
			})
		}
	}
}
