package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestDNSCandidatePMTUBoundariesAndCompiledHandoff(t *testing.T) {
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	hostResolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		payload  uint64
		compiled uint64
		pathMTU  uint64
		want     error
	}{
		{name: "default-boundary", payload: 464, want: nil},
		{name: "default-over", payload: 465, want: ErrCandidateInvalidPayload},
		{name: "zero-effective", payload: 0, compiled: 65507, want: ErrCandidateInvalidPayload},
		{name: "zero-compiled", payload: 128, compiled: 0, want: ErrCandidateInvalidCompiled},
		{name: "effective-overflow", payload: ^uint64(0), compiled: 65507, want: ErrCandidateInvalidPayload},
		{name: "compiled-overflow", payload: 128, compiled: ^uint64(0), want: ErrCandidateInvalidCompiled},
		{name: "hostname-pmtu-boundary", payload: 464, pathMTU: 512, want: nil},
		{name: "hostname-pmtu-over", payload: 465, pathMTU: 512, want: ErrCandidatePMTU},
		{name: "large-hostname-boundary", payload: 65487, pathMTU: 65535, want: nil},
		{name: "large-hostname-over", payload: 65488, pathMTU: 65535, want: ErrCandidatePMTU},
		{name: "pmtu-low", payload: 464, pathMTU: 511, want: ErrCandidateInvalidPathMTU},
		{name: "pmtu-high", payload: 464, pathMTU: 65536, want: ErrCandidateInvalidPathMTU},
		{name: "pmtu-overflow", payload: 464, pathMTU: ^uint64(0), want: ErrCandidateInvalidPathMTU},
		{name: "payload-low", payload: 127, pathMTU: 512, want: ErrCandidateInvalidPayload},
		{name: "payload-high", payload: 65508, pathMTU: 65535, want: ErrCandidateInvalidPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dial := func(context.Context, netip.AddrPort) (Conn, error) { return nil, ErrDial }
			compiled := tc.compiled
			if compiled == 0 && tc.payload != 128 {
				compiled = 65507
			}
			_, got := NewCandidateDialer(hostResolver, 4739, tc.payload, compiled, tc.pathMTU, dial, time.Second)
			if !errors.Is(got, tc.want) {
				t.Fatalf("constructor error = %v, want %v", got, tc.want)
			}
		})
	}

	// A real compiler cap can be higher than the effective destination cap;
	// the candidate enforces the normalized lower value supplied by state.
	config := mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 484,
		PathMTU:         512,
		Endpoint:        "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(config)
	if err != nil || compiled.MaxDatagramSize() != 484 {
		t.Fatalf("compiled IPv4 handoff = (%d,%v)", compiled.MaxDatagramSize(), err)
	}
	literalResolver, err := NewResolver("udp4", "192.0.2.1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		payload uint64
		pathMTU uint64
		want    error
	}{{payload: 128, pathMTU: 512}, {payload: 484, pathMTU: 512}, {payload: 485, pathMTU: 512, want: ErrCandidatePMTU}, {payload: 65507, pathMTU: 65535}, {payload: 65508, pathMTU: 65535, want: ErrCandidateInvalidPayload}} {
		_, got := NewCandidateDialer(literalResolver, 4739, tc.payload, 65507, tc.pathMTU, func(context.Context, netip.AddrPort) (Conn, error) {
			return nil, ErrDial
		}, time.Second)
		if !errors.Is(got, tc.want) {
			t.Fatalf("literal IPv4 payload %d error = %v, want %v", tc.payload, got, tc.want)
		}
	}
	if _, err := NewCandidateDialer(literalResolver, 4739, 465, 464, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return nil, ErrDial
	}, time.Second); !errors.Is(err, ErrCandidatePayloadExceeded) {
		t.Fatalf("effective payload over compiler cap = %v", err)
	}
	ipv6Resolver, err := NewResolver("udp6", "2001:db8::1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		payload  uint64
		compiled uint64
		want     error
	}{{payload: 65487, compiled: 65487}, {payload: 65488, compiled: 65507, want: ErrCandidatePMTU}} {
		_, got := NewCandidateDialer(ipv6Resolver, 4739, tc.payload, tc.compiled, 65535, func(context.Context, netip.AddrPort) (Conn, error) {
			return nil, ErrDial
		}, time.Second)
		if !errors.Is(got, tc.want) {
			t.Fatalf("literal IPv6 payload %d error = %v, want %v", tc.payload, got, tc.want)
		}
	}
	if _, err := NewCandidateDialer(literalResolver, 4739, compiled.MaxDatagramSize(), compiled.MaxDatagramSize(), config.PathMTU, func(context.Context, netip.AddrPort) (Conn, error) {
		return nil, ErrDial
	}, time.Second); err != nil {
		t.Fatalf("compiled IPv4 payload handoff rejected: %v", err)
	}
	if _, err := NewCandidateDialer(hostResolver, 4739, 464, 484, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return nil, ErrDial
	}, time.Second); err != nil {
		t.Fatalf("lower effective hostname cap rejected: %v", err)
	}
}

func TestDNSCandidateSelectsAndRetainsResolverAddress(t *testing.T) {
	firstAddress := netip.MustParseAddr("192.0.2.10")
	sortedFirst := netip.MustParseAddr("192.0.2.1")
	lookup := testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{firstAddress}},
		testtransport.ResolverStep{Answers: []netip.Addr{sortedFirst, firstAddress}},
		testtransport.ResolverStep{Err: fmt.Errorf("resolver secret: %w", errors.New("upstream failure"))},
	)
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connections := []*testtransport.Conn{
		testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3000"), netip.AddrPortFrom(firstAddress, 4739)),
		testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3001"), netip.AddrPortFrom(firstAddress, 4739)),
	}
	index := 0
	dialer, err := NewCandidateDialer(resolver, 4739, 464, 464, 512, func(_ context.Context, remote netip.AddrPort) (Conn, error) {
		if index >= len(connections) {
			return nil, ErrDial
		}
		if remote.Addr() != firstAddress {
			t.Fatalf("selected remote = %v, want %v", remote, firstAddress)
		}
		conn := connections[index]
		index++
		return conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := dialer.Dial(context.Background(), state, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := candidate.RemoteAddr(); got != netip.AddrPortFrom(firstAddress, 4739) {
		t.Fatalf("candidate remote = %v", got)
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = dialer.Dial(context.Background(), state, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := candidate.RemoteAddr(); got != netip.AddrPortFrom(firstAddress, 4739) {
		t.Fatalf("retained remote = %v, want %v", got, netip.AddrPortFrom(firstAddress, 4739))
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := func() error {
		_, err := dialer.Dial(context.Background(), state, token)
		return err
	}(); !errors.Is(err, ErrResolverLookup) {
		t.Fatalf("failed refresh = %v, want resolver lookup error", err)
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("resolver error leaked raw text: %v", err)
	}
	if len(connections[1].Events()) != 0 {
		t.Fatalf("failed refresh changed prior handle = %+v", connections[1].Events())
	}
	if index != 2 {
		t.Fatalf("failed refresh dial count = %d, want 2", index)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCandidateHostnameReserveSurvivesFamilyChange(t *testing.T) {
	lookup := testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.20")}},
		testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("2001:db8::20")}},
	)
	resolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewCandidateDialer(resolver, 4739, 464, 464, 512, func(_ context.Context, remote netip.AddrPort) (Conn, error) {
		local := netip.MustParseAddrPort("192.0.2.100:3000")
		if remote.Addr().Is6() {
			local = netip.MustParseAddrPort("[2001:db8::100]:3000")
		}
		return testtransport.NewConn(local, remote), nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if dialer.PMTUReserve() != ipv6UDPReserve {
		t.Fatalf("hostname reserve = %d, want %d", dialer.PMTUReserve(), ipv6UDPReserve)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8::20")} {
		token, err := maintenance.Begin()
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := dialer.Dial(context.Background(), state, token)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.RemoteAddr().Addr() != want {
			t.Fatalf("family candidate = %v, want %v", candidate.RemoteAddr().Addr(), want)
		}
		if err := candidate.Close(); err != nil {
			t.Fatal(err)
		}
		if err := state.CommitPublishedCandidate(token); err != nil {
			t.Fatal(err)
		}
		if _, err := maintenance.End(token); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDNSCandidateLiteralBypassesLookupAndRejectsIdentity(t *testing.T) {
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.30")}})
	resolver, err := NewResolverWithLookup("udp4", "127.0.0.1", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3000"), netip.MustParseAddrPort("127.0.0.2:4739"))
	dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 0, func(context.Context, netip.AddrPort) (Conn, error) {
		return conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.Dial(context.Background(), state, token); !errors.Is(err, ErrCandidateIdentity) {
		t.Fatalf("identity error = %v", err)
	}
	if len(conn.Events()) != 1 || conn.Events()[0].Kind != testtransport.EventClose {
		t.Fatalf("rejected connection events = %+v", conn.Events())
	}
	if len(lookup.Events()) != 0 {
		t.Fatal("literal candidate called DNS")
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	v6Address := netip.MustParseAddr("2001:db8::30")
	v6Lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{v6Address}})
	v6Resolver, err := NewResolverWithLookup("udp6", "collector.example", time.Second, v6Lookup)
	if err != nil {
		t.Fatal(err)
	}
	v6Maintenance := NewMaintenance()
	v6State, err := NewResolverState(clock, v6Maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v6Conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3001"), netip.AddrPortFrom(v6Address, 4739))
	v6Dialer, err := NewCandidateDialer(v6Resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return v6Conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v6Token, err := v6Maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v6Dialer.Dial(context.Background(), v6State, v6Token); !errors.Is(err, ErrCandidateIdentity) {
		t.Fatalf("family identity error = %v", err)
	}
	if events := v6Conn.Events(); len(events) != 1 || events[0].Kind != testtransport.EventClose {
		t.Fatalf("family rejection cleanup = %+v", events)
	}
	if _, err := v6Maintenance.End(v6Token); err != nil {
		t.Fatal(err)
	}
}

func TestUDPCandidateCancellationAndConnectionOwnership(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.40")
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3000"), netip.AddrPortFrom(address, 4739))
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	dialErr := errors.New("dial secret")
	dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return conn, dialErr
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.Dial(context.Background(), state, token); !errors.Is(err, ErrDial) {
		t.Fatalf("connection-plus-error = %v", err)
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("dial error leaked raw text: %v", err)
	}
	if len(conn.Events()) != 1 || conn.Events()[0].Kind != testtransport.EventClose {
		t.Fatalf("connection-plus-error events = %+v", conn.Events())
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	wrappedLookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
	wrappedResolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, wrappedLookup)
	if err != nil {
		t.Fatal(err)
	}
	wrappedMaintenance := NewMaintenance()
	wrappedState, err := NewResolverState(clock, wrappedMaintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wrappedConn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3002"), netip.AddrPortFrom(address, 4739))
	wrappedDialer, err := NewCandidateDialer(wrappedResolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return wrappedConn, fmt.Errorf("dial secret: %w", ErrWrite)
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wrappedToken, err := wrappedMaintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrappedDialer.Dial(context.Background(), wrappedState, wrappedToken); !errors.Is(err, ErrWrite) {
		t.Fatalf("wrapped dial error = %v", err)
	} else if strings.Contains(err.Error(), "secret") {
		t.Fatalf("wrapped dial error leaked raw text: %v", err)
	}
	if events := wrappedConn.Events(); len(events) != 1 || events[0].Kind != testtransport.EventClose {
		t.Fatalf("wrapped dial cleanup = %+v", events)
	}
	if _, err := wrappedMaintenance.End(wrappedToken); err != nil {
		t.Fatal(err)
	}

	lookupStarted := make(chan struct{})
	lateLookup := &lateCandidateLookup{address: address, started: lookupStarted}
	resolver, err = NewResolverWithLookup("udp4", "collector.example", time.Second, lateLookup)
	if err != nil {
		t.Fatal(err)
	}
	maintenance = NewMaintenance()
	state, err = NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dialCalls := 0
	dialer, err = NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		dialCalls++
		return conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := dialer.Dial(ctx, state, token)
		done <- err
	}()
	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("late lookup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrResolverCanceled) {
			t.Fatalf("canceled candidate = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled candidate did not return")
	}
	if dialCalls != 0 {
		t.Fatalf("canceled candidate dial calls = %d", dialCalls)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
}

func TestUDPCandidatePostDialCancellationAndTokenEndCloseOnce(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		address := netip.MustParseAddr("192.0.2.70")
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
		resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
		if err != nil {
			t.Fatal(err)
		}
		clock := testclock.New(1, 1)
		maintenance := NewMaintenance()
		state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3070"), netip.AddrPortFrom(address, 4739))
		ctx, cancel := context.WithCancel(context.Background())
		dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
			cancel()
			return conn, nil
		}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		token, err := maintenance.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dialer.Dial(ctx, state, token); !errors.Is(err, ErrWriteCanceled) {
			t.Fatalf("post-dial cancellation = %v", err)
		}
		if events := conn.Events(); len(events) != 1 || events[0].Kind != testtransport.EventClose {
			t.Fatalf("post-dial cancellation cleanup = %+v", events)
		}
		if _, err := maintenance.End(token); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("token-end", func(t *testing.T) {
		address := netip.MustParseAddr("192.0.2.71")
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
		resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
		if err != nil {
			t.Fatal(err)
		}
		clock := testclock.New(1, 1)
		maintenance := NewMaintenance()
		state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3071"), netip.AddrPortFrom(address, 4739))
		token, err := maintenance.Begin()
		if err != nil {
			t.Fatal(err)
		}
		dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
			if _, err := maintenance.End(token); err != nil {
				t.Fatalf("dial-time token end = %v", err)
			}
			return conn, nil
		}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dialer.Dial(context.Background(), state, token); !errors.Is(err, ErrResolverMaintenanceToken) {
			t.Fatalf("ended-token candidate = %v", err)
		}
		if events := conn.Events(); len(events) != 1 || events[0].Kind != testtransport.EventClose {
			t.Fatalf("ended-token cleanup = %+v", events)
		}
	})
}

func TestUDPCandidateCloseRedactsAndClosesOnce(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.72")
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := &candidateErrorConn{
		local: netip.MustParseAddrPort("192.0.2.100:3072"), remote: netip.AddrPortFrom(address, 4739),
		closeErr: fmt.Errorf("close secret: %w", ErrClosed),
	}
	dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := dialer.Dial(context.Background(), state, token)
	if err != nil {
		t.Fatal(err)
	}
	closeErr := candidate.Close()
	if !errors.Is(closeErr, ErrClosed) || strings.Contains(closeErr.Error(), "secret") {
		t.Fatalf("close error = %v", closeErr)
	}
	if !errors.Is(candidate.Close(), ErrClosed) || conn.closes != 1 {
		t.Fatalf("close count/error = %d/%v", conn.closes, closeErr)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
}

func TestUDPCandidateCapPrecedesWriterAndLoopbackDelivery(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote := server.LocalAddr().(*net.UDPAddr).AddrPort()
	resolver, err := NewResolver("udp4", remote.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewCandidateDialer(resolver, remote.Port(), 128, 128, 512, NewDialer("udp4", netip.AddrPort{}).Dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := dialer.Dial(context.Background(), state, token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = candidate.Close()
		_, _ = maintenance.End(token)
	}()
	if _, err := candidate.Write(context.Background(), make([]byte, 129)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversize candidate write = %v", err)
	}
	if _, err := candidate.Write(context.Background(), []byte("candidate")); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "candidate" {
		t.Fatalf("loopback payload = %q", buf[:n])
	}
}

func TestUDPCandidateWriteOutcomeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		step testtransport.WriteStep
		n    int
		err  error
	}{
		{name: "full-nil", step: testtransport.WriteStep{N: 4}, n: 4},
		{name: "short-nil", step: testtransport.WriteStep{N: 3}, n: 3},
		{name: "zero-nil", step: testtransport.WriteStep{N: 0}, n: 0},
		{name: "short-error", step: testtransport.WriteStep{N: 3, Err: errors.New("write secret")}, n: 3, err: ErrWrite},
		{name: "zero-wrapped-error", step: testtransport.WriteStep{N: 0, Err: fmt.Errorf("write secret: %w", ErrWrite)}, n: 0, err: ErrWrite},
		{name: "full-error", step: testtransport.WriteStep{N: 4, Err: errors.New("write secret")}, n: 4, err: ErrWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := netip.MustParseAddr("192.0.2.60")
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
			resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
			if err != nil {
				t.Fatal(err)
			}
			clock := testclock.New(1, 1)
			maintenance := NewMaintenance()
			state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3060"), netip.AddrPortFrom(address, 4739), tc.step)
			dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
				return conn, nil
			}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			token, err := maintenance.Begin()
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := dialer.Dial(context.Background(), state, token)
			if err != nil {
				t.Fatal(err)
			}
			gotN, gotErr := candidate.Write(context.Background(), []byte("data"))
			if gotN != tc.n || !errors.Is(gotErr, tc.err) {
				t.Fatalf("write = (%d,%v), want (%d,%v)", gotN, gotErr, tc.n, tc.err)
			}
			if gotErr != nil && strings.Contains(gotErr.Error(), "secret") {
				t.Fatalf("write error leaked raw text: %v", gotErr)
			}
			if err := candidate.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := maintenance.End(token); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPCandidateOversizeSkipsDeadlineAndWrite(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.61")
	lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{address}})
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1, 1)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := testtransport.NewConn(netip.MustParseAddrPort("192.0.2.100:3061"), netip.AddrPortFrom(address, 4739))
	dialer, err := NewCandidateDialer(resolver, 4739, 128, 128, 512, func(context.Context, netip.AddrPort) (Conn, error) {
		return conn, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := dialer.Dial(context.Background(), state, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write(context.Background(), make([]byte, 129)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversize write = %v", err)
	}
	if events := conn.Events(); len(events) != 0 {
		t.Fatalf("oversize write touched connection: %+v", events)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
}

type candidateErrorConn struct {
	local    netip.AddrPort
	remote   netip.AddrPort
	closeErr error
	closes   int
}

func (c *candidateErrorConn) LocalAddr() netip.AddrPort  { return c.local }
func (c *candidateErrorConn) RemoteAddr() netip.AddrPort { return c.remote }
func (c *candidateErrorConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *candidateErrorConn) Write(payload []byte) (int, error) {
	return len(payload), nil
}
func (c *candidateErrorConn) Close() error {
	c.closes++
	return c.closeErr
}

type lateCandidateLookup struct {
	address netip.Addr
	started chan<- struct{}
}

func (l *lateCandidateLookup) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	if l.started != nil {
		close(l.started)
	}
	<-ctx.Done()
	return []netip.Addr{l.address}, nil
}
