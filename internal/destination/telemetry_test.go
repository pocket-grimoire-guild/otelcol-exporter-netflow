package destination

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

type eventCounts struct {
	mu     sync.Mutex
	counts [RefreshFailed + 1]uint64
	bytes  [RefreshFailed + 1]uint64
}

func (c *eventCounts) observe(_ context.Context, event Event, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[event]++
	c.bytes[event] += bytes
}
func (c *eventCounts) require(t *testing.T, event Event, count, bytes uint64) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[event] != count || c.bytes[event] != bytes {
		t.Fatalf("event %d: count=%d bytes=%d; want %d/%d", event, c.counts[event], c.bytes[event], count, bytes)
	}
}
func TestTelemetry(t *testing.T) {
	t.Run("bootstrap_failure", func(t *testing.T) {
		for _, protocol := range templateProtocols {
			t.Run(protocol.String(), func(t *testing.T) {
				length, _ := runtimeLengths(protocol)
				conn := newRuntimeConn(testtransport.WriteStep{N: length}, testtransport.WriteStep{N: length, Err: errors.New("private endpoint template failure")})
				r, _, _ := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				var events eventCounts
				r.config.Observe = events.observe
				if r.Start(context.Background()) == nil {
					t.Fatal("failed bootstrap published")
				}
				events.require(t, BootstrapConfirmed, 1, uint64(length))
				events.require(t, BootstrapAmbiguous, 1, uint64(length))
				events.require(t, BootstrapFailed, 1, 0)
				events.require(t, EpochPublished, 0, 0)
				events.require(t, DNSSucceeded, 0, 0)
				if currentEndpoint(r) != nil || conn.closes.Load() != 1 {
					t.Fatal("candidate survived failure")
				}
			})
		}
	})
	t.Run("idle_refresh_resume", func(t *testing.T) {
		for _, protocol := range templateProtocols {
			length, _ := runtimeLengths(protocol)
			for _, failure := range []struct {
				name string
				n    int
				err  error
			}{
				{"short", 1, nil}, {"zero", 0, nil}, {"short_error", 1, errors.New("private")},
				{"zero_error", 0, errors.New("private")}, {"full_error", length, errors.New("private")}, {"invalid", length + 1, nil},
			} {
				t.Run(fmt.Sprintf("%s/%s", protocol, failure.name), func(t *testing.T) {
					steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: length}, testtransport.WriteStep{N: failure.n, Err: failure.err}, testtransport.WriteStep{N: length})
					conn := newRuntimeConn(steps...)
					r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
					var events eventCounts
					r.config.Observe = events.observe
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					waitRefreshReset(t, timer, 1)
					clock.Advance(0, uint64(time.Minute))
					fireRefresh(t, timer)
					waitRefreshReset(t, timer, 2)
					events.require(t, BootstrapConfirmed, 4, uint64(4*length))
					events.require(t, RefreshConfirmed, 1, uint64(length))
					ambiguous := uint64(1)
					if failure.name == "invalid" {
						ambiguous = 0
					}
					events.require(t, RefreshAmbiguous, ambiguous, ambiguous*uint64(length))
					events.require(t, RefreshFailed, 1, 0)
					// One full interval resumes only the failed shape; completed prefixes are
					// neither resent nor counted again, including after an illegal Write result.
					clock.Advance(0, uint64(time.Minute))
					fireRefresh(t, timer)
					waitRefreshReset(t, timer, 3)
					events.require(t, RefreshConfirmed, 2, uint64(2*length))
					events.require(t, EpochPublished, 1, 0)
					events.require(t, DataConfirmed, 0, 0)
					if err := r.Close(); err != nil {
						t.Fatal(err)
					}
					events.require(t, RefreshConfirmed, 2, uint64(2*length))
					if timer.Fire() {
						t.Fatal("post-shutdown maintenance")
					}
				})
			}
		}
	})
	t.Run("request_refresh", func(t *testing.T) {
		for _, protocol := range templateProtocols {
			t.Run(protocol.String(), func(t *testing.T) {
				template, data := runtimeLengths(protocol)
				steps := append(runtimeBootstrapSteps(protocol), testtransport.WriteStep{N: template}, testtransport.WriteStep{N: 0}, testtransport.WriteStep{N: template}, testtransport.WriteStep{N: data})
				conn := newRuntimeConn(steps...)
				r, clock, timer := newIdleRuntime(t, protocol, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
				var events eventCounts
				r.config.Observe = events.observe
				if err := r.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				waitRefreshReset(t, timer, 1)
				clock.Advance(0, uint64(time.Minute))
				result, err := r.Pack(context.Background(), validPackerLogs(t), nil)
				if err != ErrPackTransient || result.Counts().Unsent != 1 {
					t.Fatalf("result=%v err=%v", result, err)
				}
				events.require(t, RefreshConfirmed, 1, uint64(template))
				events.require(t, RefreshAmbiguous, 1, uint64(template))
				events.require(t, DataConfirmed, 0, 0)
				if _, err = r.Pack(context.Background(), validPackerLogs(t), nil); err != nil {
					t.Fatal(err)
				}
				events.require(t, RefreshConfirmed, 2, uint64(2*template))
				events.require(t, DataConfirmed, 1, uint64(data))
			})
		}
	})
	t.Run("dns_and_publication", func(t *testing.T) {
		for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
			for _, failure := range []string{"lookup", "answer_limit", "dial", "bootstrap", "unchanged", "none"} {
				if protocol == wire.ProtocolV5 && failure == "bootstrap" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s", protocol, failure), func(t *testing.T) {
					answer := testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}}
					switch failure {
					case "lookup":
						answer = testtransport.ResolverStep{Err: errors.New("secret DNS address")}
					case "answer_limit":
						for i := 1; i < 9; i++ {
							answer.Answers = append(answer.Answers, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
						}
					case "unchanged":
						answer.Answers = []netip.Addr{runtimeRemote.Addr()}
					}
					lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}}, answer)
					old := newRuntimeConn(runtimeBootstrapSteps(protocol)...)
					nextSteps := runtimeBootstrapSteps(protocol)
					if failure == "bootstrap" {
						nextSteps[1] = testtransport.WriteStep{N: 0, Err: errors.New("secret template")}
					}
					next := newReplacementConn(nextSteps...)
					r, clock, timer := newDNSRuntime(t, protocol, 4739, lookup, func(_ context.Context, remote netip.AddrPort) (transport.Conn, error) {
						if remote == runtimeRemote {
							return old, nil
						}
						if failure == "dial" {
							return nil, errors.New("secret dial address")
						}
						return next, nil
					})
					var events eventCounts
					r.config.Observe = events.observe
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					waitDNSReset(t, timer, 1)
					tickDNS(t, clock, timer, 2)
					success, failed, epochs := uint64(2), uint64(0), uint64(1)
					if failure == "lookup" || failure == "answer_limit" {
						success, failed = 1, 1
					}
					if failure == "none" {
						epochs = 2
					}
					events.require(t, DNSSucceeded, success, 0)
					events.require(t, DNSFailed, failed, 0)
					events.require(t, EpochPublished, epochs, 0)
					if failure == "bootstrap" {
						events.require(t, BootstrapFailed, 1, 0)
					}
					if failure == "dial" {
						events.require(t, CandidateFailed, 1, 0)
					} else {
						events.require(t, CandidateFailed, 0, 0)
					}
					// Duplicate Start and data-independent early wakes must not count lookup
					// or publication again; shutdown joins all observer calls.
					if err := r.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
					if err := r.Close(); err != nil {
						t.Fatal(err)
					}
					events.require(t, EpochPublished, epochs, 0)
					events.require(t, DNSSucceeded, success, 0)
				})
			}
		}
	})
}
