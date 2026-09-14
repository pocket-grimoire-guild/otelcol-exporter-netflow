package transport

// This file joins the bounded resolver state to the numeric connected-UDP
// seam. It deliberately stops before candidate publication: the lifecycle
// owner keeps the maintenance token live while it bootstraps and publishes a
// returned candidate.

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync"
	"time"
)

const (
	minCandidatePayload     = 128
	maxCandidatePayload     = 65507
	defaultCandidatePayload = 464
	minCandidatePathMTU     = 512
	maxCandidatePathMTU     = 65535
	ipv4UDPReserve          = 28
	ipv6UDPReserve          = 48
)

var (
	ErrCandidateInvalidResolver = errors.New("transport: invalid candidate resolver")
	ErrCandidateInvalidPort     = errors.New("transport: invalid candidate port")
	ErrCandidateInvalidPayload  = errors.New("transport: invalid candidate payload")
	ErrCandidateInvalidCompiled = errors.New("transport: invalid compiled payload cap")
	ErrCandidatePayloadExceeded = errors.New("transport: candidate payload exceeds compiled cap")
	ErrCandidateInvalidPathMTU  = errors.New("transport: invalid candidate path MTU")
	ErrCandidatePMTU            = errors.New("transport: candidate exceeds path MTU budget")
	ErrCandidateInvalidDial     = errors.New("transport: invalid candidate dial function")
	ErrCandidateIdentity        = errors.New("transport: candidate connection identity mismatch")
	ErrCandidateUnavailable     = errors.New("transport: candidate unavailable")
)

// NumericDial is the injected numeric-only connected UDP operation. The
// endpoint has already been selected and includes the configured destination
// port; a dial implementation must not resolve names.
type NumericDial func(context.Context, netip.AddrPort) (Conn, error)

// CandidateDialer binds one immutable resolver and transport budget to the
// operation that creates a candidate connection. payload is the normalized
// effective cap and compiledPayload is the separate immutable compiler cap.
// A zero pathMTU means that no operator assertion was supplied; it still
// enforces the conservative 464 byte payload cap. Defaults belong to
// configuration normalization, not this transport seam.
type CandidateDialer struct {
	resolver     *Resolver
	port         uint16
	payload      uint64
	compiled     uint64
	pathMTU      uint64
	reserve      uint64
	dial         NumericDial
	writeTimeout time.Duration
}

// NewCandidateDialer constructs a resolver-bound candidate dialer. The
// resolver's configured host determines the reserve: literal IPv4 uses 28
// bytes, while literal IPv6 and every hostname use 48 bytes. A hostname keeps
// the 48-byte reserve even when its current answer is IPv4 so a later DNS
// generation may safely select IPv6. All cap and PMTU checks happen before
// lookup or socket activity.
func NewCandidateDialer(resolver *Resolver, port uint16, payload, compiledPayload, pathMTU uint64, dial NumericDial, writeTimeout time.Duration) (*CandidateDialer, error) {
	if resolver == nil {
		return nil, ErrCandidateInvalidResolver
	}
	if port == 0 {
		return nil, ErrCandidateInvalidPort
	}
	if compiledPayload < minCandidatePayload || compiledPayload > maxCandidatePayload {
		return nil, ErrCandidateInvalidCompiled
	}
	if payload < minCandidatePayload || payload > maxCandidatePayload {
		return nil, ErrCandidateInvalidPayload
	}
	if payload > compiledPayload {
		return nil, ErrCandidatePayloadExceeded
	}
	if pathMTU == 0 {
		if payload > defaultCandidatePayload {
			return nil, ErrCandidateInvalidPayload
		}
	} else {
		if pathMTU < minCandidatePathMTU || pathMTU > maxCandidatePathMTU {
			return nil, ErrCandidateInvalidPathMTU
		}
	}
	if dial == nil {
		return nil, ErrCandidateInvalidDial
	}
	if err := ValidateWriteTimeout(writeTimeout); err != nil {
		return nil, err
	}

	reserve := uint64(ipv6UDPReserve)
	if resolver.literal.IsValid() && resolver.literal.Is4() {
		reserve = ipv4UDPReserve
	}
	if payload > math.MaxUint64-reserve {
		return nil, ErrCandidatePMTU
	}
	if pathMTU != 0 && payload+reserve > pathMTU {
		return nil, ErrCandidatePMTU
	}
	return &CandidateDialer{
		resolver: resolver, port: port, payload: payload, compiled: compiledPayload, pathMTU: pathMTU,
		reserve: reserve, dial: dial, writeTimeout: writeTimeout,
	}, nil
}

// PayloadCap returns the immutable payload cap enforced before every write.
func (d *CandidateDialer) PayloadCap() uint64 {
	if d == nil {
		return 0
	}
	return d.payload
}

// CompiledPayloadCap reports the immutable compiler-validated upper bound.
func (d *CandidateDialer) CompiledPayloadCap() uint64 {
	if d == nil {
		return 0
	}
	return d.compiled
}

// WriteTimeout and ResolverTimeout expose immutable operation limits so the
// lifecycle owner can reject a drain shorter than either configured timeout.
func (d *CandidateDialer) WriteTimeout() time.Duration {
	if d == nil {
		return 0
	}
	return d.writeTimeout
}

func (d *CandidateDialer) ResolverTimeout() time.Duration {
	if d == nil || d.resolver == nil {
		return 0
	}
	return d.resolver.timeout
}

// UsesDNS reports whether periodic hostname resolution is needed. Numeric
// endpoints retain their epoch without a maintenance worker.
func (d *CandidateDialer) UsesDNS() bool {
	return d != nil && d.resolver != nil && !d.resolver.literal.IsValid()
}

// PathMTU returns the optional trusted path-MTU assertion. Zero means absent.
func (d *CandidateDialer) PathMTU() uint64 {
	if d == nil {
		return 0
	}
	return d.pathMTU
}

// PMTUReserve returns the fixed outer-header reserve selected from the
// configured resolver host, independent of the current DNS answer.
func (d *CandidateDialer) PMTUReserve() uint64 {
	if d == nil {
		return 0
	}
	return d.reserve
}

// Dial resolves and selects one candidate, applies the result to resolver
// metadata, then creates a numeric connected socket. The maintenance token
// remains live on return; the lifecycle owner must End it after candidate
// bootstrap/publication or failure. This method never commits publication and
// never ends the token itself.
func (d *CandidateDialer) Dial(ctx context.Context, state *ResolverState, token MaintenanceToken) (*Candidate, error) {
	return d.dialCandidate(ctx, state, token, nil)
}

// DialReplacement refreshes DNS and returns nil, nil when the currently
// published address remains available and selected. That case preserves the
// socket and protocol epoch. An expired address requires a fresh candidate,
// even if it reappears. The lifecycle owner keeps current open and the token
// live through candidate bootstrap/publication or failure, just as for Dial.
func (d *CandidateDialer) DialReplacement(ctx context.Context, state *ResolverState, token MaintenanceToken, current *Candidate) (*Candidate, error) {
	return d.dialCandidate(ctx, state, token, current)
}

func (d *CandidateDialer) dialCandidate(ctx context.Context, state *ResolverState, token MaintenanceToken, current *Candidate) (*Candidate, error) {
	if d == nil || d.resolver == nil {
		return nil, ErrCandidateInvalidResolver
	}
	if ctx == nil {
		return nil, ErrInvalidContext
	}
	if state == nil {
		return nil, ErrCandidateUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyContextError(err)
	}

	answers, lookupErr := d.resolver.ResolveFor(ctx, token)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The lookup may have returned a successful answer concurrently with
		// cancellation. Apply the cancellation through the existing stale/error
		// path and never permit that late answer to become usable.
		answers = AnswerSet{}
		lookupErr = classifyResolverContext(ctxErr)
	}
	if applyErr := state.ApplyLookup(token, answers, lookupErr); applyErr != nil {
		// ApplyLookup returns the canonical lookup class for an ordinary DNS
		// failure. Preserve any distinct token/clock failure instead of
		// treating it as a stale-answer path.
		if lookupErr == nil || !errors.Is(applyErr, lookupErr) {
			return nil, applyErr
		}
	}
	if lookupErr != nil {
		return nil, lookupErr
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, classifyContextError(ctxErr)
	}
	snapshot := state.Snapshot()
	if snapshot.TimeFault {
		return nil, ErrResolverClock
	}
	selected := snapshot.Selected
	if !selected.IsValid() || snapshot.Generation != token.Generation() || !answers.Contains(selected) {
		return nil, ErrCandidateUnavailable
	}
	if current != nil && snapshot.Available && snapshot.Current == selected &&
		current.RemoteAddr() == netip.AddrPortFrom(selected, d.port) {
		return nil, nil
	}
	return d.dialSelected(ctx, state, token, selected, snapshot.Generation)
}

func (d *CandidateDialer) dialSelected(ctx context.Context, state *ResolverState, token MaintenanceToken, address netip.Addr, generation uint64) (*Candidate, error) {
	if ctx == nil {
		return nil, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyContextError(err)
	}
	if !token.valid(nil) {
		return nil, ErrResolverMaintenanceToken
	}
	if !address.IsValid() || address.Zone() != "" || !resolverFamilyCompatible(d.resolver.network, address) {
		return nil, ErrCandidateIdentity
	}
	snapshot := state.Snapshot()
	if snapshot.TimeFault {
		return nil, ErrResolverClock
	}
	if snapshot.Generation != generation || !snapshot.answersContain(address, d.resolver.network) {
		return nil, ErrCandidateUnavailable
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, classifyContextError(ctxErr)
	}
	if !token.valid(nil) {
		return nil, ErrResolverMaintenanceToken
	}
	remote := netip.AddrPortFrom(address, d.port)
	conn, dialErr := d.dial(ctx, remote)
	if dialErr != nil {
		if conn != nil {
			_ = conn.Close()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, classifyContextError(ctxErr)
		}
		if fixed := fixedTransportError(dialErr); fixed != nil {
			return nil, fixed
		}
		return nil, ErrDial
	}
	if conn == nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, classifyContextError(ctxErr)
		}
		return nil, ErrDial
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = conn.Close()
		return nil, classifyContextError(ctxErr)
	}
	if !token.valid(nil) {
		_ = conn.Close()
		return nil, ErrResolverMaintenanceToken
	}
	if err := validateCandidateIdentity(conn, remote, d.resolver.network); err != nil {
		_ = conn.Close()
		return nil, err
	}
	writer, err := NewWriter(conn, d.writeTimeout)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = conn.Close()
		return nil, classifyContextError(ctxErr)
	}
	return &Candidate{conn: conn, writer: writer, remote: remote, generation: generation, payload: d.payload}, nil
}

func validateCandidateIdentity(conn Conn, remote netip.AddrPort, network string) error {
	if conn == nil || !remote.IsValid() || remote.Port() == 0 {
		return ErrCandidateIdentity
	}
	local := conn.LocalAddr()
	actualRemote := conn.RemoteAddr()
	if !local.IsValid() || local.Port() == 0 || local.Addr().Zone() != "" || !resolverFamilyCompatible(network, local.Addr()) {
		return ErrCandidateIdentity
	}
	if actualRemote != remote || actualRemote.Addr().Zone() != "" || !resolverFamilyCompatible(network, actualRemote.Addr()) || local.Addr().Is4() != actualRemote.Addr().Is4() {
		return ErrCandidateIdentity
	}
	return nil
}

// Candidate owns a successfully dialed connection until Close. Its Writer
// does not own closure, and Write enforces the configured candidate cap before
// invoking any deadline or underlying socket operation.
type Candidate struct {
	conn       Conn
	writer     *Writer
	remote     netip.AddrPort
	generation uint64
	payload    uint64
	closeOnce  sync.Once
	closeErr   error
}

func (c *Candidate) LocalAddr() netip.AddrPort {
	if c == nil || c.conn == nil {
		return netip.AddrPort{}
	}
	return c.conn.LocalAddr()
}

func (c *Candidate) RemoteAddr() netip.AddrPort {
	if c == nil {
		return netip.AddrPort{}
	}
	return c.remote
}

func (c *Candidate) Generation() uint64 {
	if c == nil {
		return 0
	}
	return c.generation
}

func (c *Candidate) Write(ctx context.Context, payload []byte) (int, error) {
	if c == nil || c.writer == nil {
		return 0, ErrClosed
	}
	if uint64(len(payload)) > c.payload {
		return 0, ErrDatagramTooLarge
	}
	return c.writer.Write(ctx, payload)
}

func (c *Candidate) Close() error {
	if c == nil || c.conn == nil {
		return ErrClosed
	}
	c.closeOnce.Do(func() {
		if err := c.conn.Close(); err != nil {
			c.closeErr = classifyCloseError(err)
		}
	})
	return c.closeErr
}

// answersContain checks an immutable resolver snapshot without exposing its
// internal fixed array as mutable state.
func (s ResolverSnapshot) answersContain(address netip.Addr, network string) bool {
	if !address.IsValid() || !resolverFamilyCompatible(network, address) {
		return false
	}
	for index := 0; index < int(s.AnswerCount); index++ {
		if s.Answers[index] == address {
			return true
		}
	}
	return false
}
