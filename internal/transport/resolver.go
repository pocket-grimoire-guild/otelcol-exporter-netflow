package transport

// This file contains the bounded DNS answer and maintenance state seam.  It
// deliberately stops before socket creation and endpoint publication: the
// future lifecycle wrapper owns candidate bootstrap, the send/lifecycle lock
// order, and the atomic socket/epoch publication transition.

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	MinResolverTimeout = 100 * time.Millisecond
	MaxResolverTimeout = 30 * time.Second
	MinDNSRefresh      = time.Second
	MaxDNSRefresh      = 24 * time.Hour
	MaxDNSStale        = 7 * 24 * time.Hour

	// Resolver answers are retained in this fixed array.  Raw answers are
	// inspected only up to MaxResolverRawAnswers before any element is read.
	MaxResolverAnswers    = 8
	MaxResolverRawAnswers = 64
	MaxResolverHostBytes  = 253
)

var (
	ErrResolverInvalidContext       = errors.New("transport: invalid resolver context")
	ErrResolverInvalidNetwork       = errors.New("transport: invalid resolver network")
	ErrResolverInvalidHost          = errors.New("transport: invalid resolver host")
	ErrResolverInvalidTimeout       = errors.New("transport: invalid resolver timeout")
	ErrResolverInvalidLookup        = errors.New("transport: invalid resolver lookup")
	ErrResolverLookup               = errors.New("transport: resolver lookup failed")
	ErrResolverCanceled             = errors.New("transport: resolver lookup canceled")
	ErrResolverTimeout              = errors.New("transport: resolver lookup timed out")
	ErrResolverNoAnswers            = errors.New("transport: resolver returned no answers")
	ErrResolverTooManyRawAnswers    = errors.New("transport: resolver answer inspection limit exceeded")
	ErrResolverTooManyAnswers       = errors.New("transport: resolver answer limit exceeded")
	ErrResolverInvalidAnswer        = errors.New("transport: resolver returned an invalid answer")
	ErrResolverClock                = errors.New("transport: resolver monotonic clock invalid")
	ErrResolverGenerationExhausted  = errors.New("transport: resolver generation exhausted")
	ErrResolverMaintenancePending   = errors.New("transport: resolver maintenance already active")
	ErrResolverMaintenanceToken     = errors.New("transport: invalid resolver maintenance token")
	ErrResolverLookupAlreadyStarted = errors.New("transport: resolver lookup already started")
	ErrResolverLookupInFlight       = errors.New("transport: resolver lookup still in flight")
	ErrResolverLookupApplied        = errors.New("transport: resolver result already applied")
	ErrResolverCandidateCommitted   = errors.New("transport: resolver candidate already committed")
	ErrResolverNoCandidate          = errors.New("transport: no resolver candidate available")
	ErrResolverUnavailable          = errors.New("transport: resolver destination unavailable")
)

// LookupNetIP is the only production resolver dependency.  Its method is the
// standard library net.Resolver.LookupNetIP shape so tests can inject a
// bounded implementation without retaining standard-library answer slices.
type LookupNetIP interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// AnswerSet is an owned, sorted DNS answer snapshot.  The array is part of
// the value, so callers cannot mutate resolver state or retain a lookup slice.
// Addresses are normalized with Addr.Unmap; IPv4-mapped IPv6 answers are
// therefore consistently treated as IPv4.  Compare supplies numeric lexical
// order, independent of resolver answer order.
type AnswerSet struct {
	addresses  [MaxResolverAnswers]netip.Addr
	count      uint8
	selected   netip.Addr
	generation uint64
	origin     *maintenanceTokenState
}

func (a AnswerSet) Count() int { return int(a.count) }

func (a AnswerSet) At(index int) (netip.Addr, bool) {
	if index < 0 || index >= int(a.count) {
		return netip.Addr{}, false
	}
	return a.addresses[index], true
}

func (a AnswerSet) Selected() (netip.Addr, bool) {
	if !a.selected.IsValid() {
		return netip.Addr{}, false
	}
	return a.selected, true
}

func (a AnswerSet) Contains(address netip.Addr) bool {
	address = normalizeResolverAddress(address)
	if !address.IsValid() {
		return false
	}
	for index := 0; index < int(a.count); index++ {
		if a.addresses[index] == address {
			return true
		}
	}
	return false
}

// Resolver performs one bounded A/AAAA lookup.  A numeric literal is stored
// at construction and Resolve returns it without calling DNS.  Hostnames are
// trusted operator configuration, never record data; their validation is
// bounded before any standard-library call.
type Resolver struct {
	network string
	host    string
	timeout time.Duration
	lookup  LookupNetIP
	literal netip.Addr
}

func NewResolver(network, host string, timeout time.Duration) (*Resolver, error) {
	return NewResolverWithLookup(network, host, timeout, net.DefaultResolver)
}

func NewResolverWithLookup(network, host string, timeout time.Duration, lookup LookupNetIP) (*Resolver, error) {
	if !validResolverNetwork(network) {
		return nil, ErrResolverInvalidNetwork
	}
	if timeout < MinResolverTimeout || timeout > MaxResolverTimeout {
		return nil, ErrResolverInvalidTimeout
	}
	if lookup == nil {
		return nil, ErrResolverInvalidLookup
	}
	literal, err := parseResolverLiteral(host)
	if err != nil {
		return nil, err
	}
	if !literal.IsValid() && !validResolverHostname(host) {
		return nil, ErrResolverInvalidHost
	}
	if literal.IsValid() && !resolverFamilyCompatible(network, literal) {
		return nil, ErrResolverInvalidAnswer
	}
	return &Resolver{network: network, host: host, timeout: timeout, lookup: lookup, literal: literal}, nil
}

// Resolve executes one lookup.  The timeout context is layered on the caller
// context, so an earlier caller deadline wins.  Only fixed error classes leave
// this method; raw hostnames, DNS messages, and endpoint text never escape.
func (r *Resolver) Resolve(ctx context.Context) (AnswerSet, error) {
	if r == nil || r.lookup == nil {
		return AnswerSet{}, ErrResolverInvalidLookup
	}
	if ctx == nil {
		return AnswerSet{}, ErrResolverInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return AnswerSet{}, classifyResolverContext(err)
	}
	if r.literal.IsValid() {
		return makeAnswerSet(r.literal, 0), nil
	}
	lookupContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	answers, err := r.lookup.LookupNetIP(lookupContext, resolverLookupNetwork(r.network), r.host)
	if err != nil {
		return AnswerSet{}, classifyResolverLookupError(lookupContext, err)
	}
	if contextErr := lookupContext.Err(); contextErr != nil {
		return AnswerSet{}, classifyResolverContext(contextErr)
	}
	set, err := normalizeResolverAnswers(r.network, answers)
	if err != nil {
		return AnswerSet{}, err
	}
	return set, nil
}

// ResolveFor is the lifecycle-facing variant.  The token is checked before
// and after the blocking lookup; a token that was canceled/ended while DNS
// was in flight cannot produce an applicable result.  Candidate publication
// still requires ResolverState.CommitPublishedCandidate.
func (r *Resolver) ResolveFor(ctx context.Context, token MaintenanceToken) (result AnswerSet, resultErr error) {
	if !token.valid(nil) {
		return AnswerSet{}, ErrResolverMaintenanceToken
	}
	if !token.claimLookup() {
		if !token.valid(nil) {
			return AnswerSet{}, ErrResolverMaintenanceToken
		}
		return AnswerSet{}, ErrResolverLookupAlreadyStarted
	}
	defer func() {
		outcome := LookupNotAttempted
		if r != nil && !r.literal.IsValid() {
			outcome = LookupSucceeded
			if resultErr != nil {
				outcome = LookupFailed
			}
		}
		token.finishLookup(outcome)
	}()
	set, err := r.Resolve(ctx)
	if err != nil {
		return AnswerSet{}, err
	}
	if !token.valid(nil) {
		return AnswerSet{}, ErrResolverMaintenanceToken
	}
	set.generation = token.generation()
	set.origin = token.state
	return set, nil
}

func parseResolverLiteral(host string) (netip.Addr, error) {
	if host == "" || len(host) > MaxResolverHostBytes {
		return netip.Addr{}, ErrResolverInvalidHost
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, nil
	}
	if address.Zone() != "" {
		return netip.Addr{}, ErrResolverInvalidAnswer
	}
	return normalizeResolverAddress(address), nil
}

func validResolverNetwork(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

func resolverLookupNetwork(network string) string {
	switch network {
	case "udp4":
		return "ip4"
	case "udp6":
		return "ip6"
	default:
		return "ip"
	}
}

func resolverFamilyCompatible(network string, address netip.Addr) bool {
	address = normalizeResolverAddress(address)
	switch network {
	case "udp4":
		return address.Is4()
	case "udp6":
		return address.Is6()
	default:
		return address.Is4() || address.Is6()
	}
}

func validResolverHostname(host string) bool {
	if host == "" || len(host) > MaxResolverHostBytes {
		return false
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" || len(host) > MaxResolverHostBytes {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeResolverAddress(address netip.Addr) netip.Addr {
	if !address.IsValid() || address.Zone() != "" {
		return netip.Addr{}
	}
	return address.Unmap()
}

func normalizeResolverAnswers(network string, answers []netip.Addr) (AnswerSet, error) {
	if len(answers) > MaxResolverRawAnswers {
		return AnswerSet{}, ErrResolverTooManyRawAnswers
	}
	if len(answers) == 0 {
		return AnswerSet{}, ErrResolverNoAnswers
	}
	var set AnswerSet
	for _, answer := range answers {
		answer = normalizeResolverAddress(answer)
		if !answer.IsValid() {
			return AnswerSet{}, ErrResolverInvalidAnswer
		}
		// LookupNetIP is requested with ip/ip4/ip6, so a production resolver
		// normally returns only matching families.  Filtering an incompatible
		// valid answer keeps this boundary defensive and makes mixed scripted
		// answers deterministic without treating a valid address as malformed.
		if !resolverFamilyCompatible(network, answer) {
			continue
		}
		duplicate := false
		for index := 0; index < int(set.count); index++ {
			if set.addresses[index] == answer {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if set.count == MaxResolverAnswers {
			return AnswerSet{}, ErrResolverTooManyAnswers
		}
		set.addresses[set.count] = answer
		set.count++
	}
	if set.count == 0 {
		return AnswerSet{}, ErrResolverNoAnswers
	}
	for index := 1; index < int(set.count); index++ {
		candidate := set.addresses[index]
		position := index
		for position > 0 && set.addresses[position-1].Compare(candidate) > 0 {
			set.addresses[position] = set.addresses[position-1]
			position--
		}
		set.addresses[position] = candidate
	}
	set.selected = set.addresses[0]
	return set, nil
}

func makeAnswerSet(address netip.Addr, generation uint64) AnswerSet {
	var set AnswerSet
	set.addresses[0] = normalizeResolverAddress(address)
	set.count = 1
	set.selected = set.addresses[0]
	set.generation = generation
	return set
}

func classifyResolverContext(err error) error {
	if errors.Is(err, context.Canceled) {
		return ErrResolverCanceled
	}
	return ErrResolverTimeout
}

func classifyResolverLookupError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return classifyResolverContext(contextErr)
	}
	if errors.Is(err, context.Canceled) {
		return ErrResolverCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return ErrResolverTimeout
	}
	return ErrResolverLookup
}

// Maintenance is one per destination instance.  It permits one active run
// and one coalesced pending bit.  It does not spawn goroutines, queue work, or
// register lifecycle operations; the future root wrapper owns that authority
// and must defer End on every cancellation, failure, and close path.
type Maintenance struct {
	mu      sync.Mutex
	active  *maintenanceTokenState
	pending bool
	next    uint64
}

type maintenanceTokenState struct {
	gate               *Maintenance
	generation         uint64
	consumed           bool
	lookupStarted      bool
	lookupInFlight     bool
	lookupApplied      bool
	lookupOutcome      LookupOutcome
	candidateCommitted bool
}

// MaintenanceToken is copy-safe for rejection: all copies refer to one
// consumed marker, so ending one copy invalidates every copied/foreign use.
type MaintenanceToken struct{ state *maintenanceTokenState }

func NewMaintenance() *Maintenance { return &Maintenance{} }

// Begin either owns a new run or records one coalesced trigger while a run is
// active.  ErrResolverMaintenancePending is not a failure of the trigger;
// the active owner receives pending=true from End and schedules one follow-up.
func (m *Maintenance) Begin() (MaintenanceToken, error) {
	if m == nil {
		return MaintenanceToken{}, ErrResolverMaintenanceToken
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != nil {
		m.pending = true
		return MaintenanceToken{}, ErrResolverMaintenancePending
	}
	if m.next == math.MaxUint64 {
		return MaintenanceToken{}, ErrResolverGenerationExhausted
	}
	m.next++
	state := &maintenanceTokenState{gate: m, generation: m.next}
	m.active = state
	return MaintenanceToken{state: state}, nil
}

// End consumes the live owner and reports whether one pending trigger was
// coalesced during the run.  It never silently accepts a stale, foreign, or
// copied-consumed token.
func (m *Maintenance) End(token MaintenanceToken) (bool, error) {
	if m == nil {
		return false, ErrResolverMaintenanceToken
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.validLocked(token) {
		return false, ErrResolverMaintenanceToken
	}
	if token.state.lookupInFlight {
		return false, ErrResolverLookupInFlight
	}
	pending := m.pending
	m.pending = false
	token.state.consumed = true
	m.active = nil
	return pending, nil
}

func (m *Maintenance) valid(token MaintenanceToken) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.validLocked(token)
}

func (m *Maintenance) validLocked(token MaintenanceToken) bool {
	return token.state != nil && token.state.gate == m && !token.state.consumed && m.active == token.state
}

func (t MaintenanceToken) valid(gate *Maintenance) bool {
	if t.state == nil {
		return false
	}
	if gate != nil {
		return gate.valid(t)
	}
	return t.state.gate != nil && t.state.gate.valid(t)
}

func (t MaintenanceToken) generation() uint64 {
	if t.state == nil {
		return 0
	}
	return t.state.generation
}

func (t MaintenanceToken) claimLookup() bool {
	if t.state == nil || t.state.gate == nil {
		return false
	}
	m := t.state.gate
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.validLocked(t) || t.state.lookupStarted {
		return false
	}
	t.state.lookupStarted = true
	t.state.lookupInFlight = true
	return true
}

func (t MaintenanceToken) finishLookup(outcome LookupOutcome) {
	if t.state == nil || t.state.gate == nil {
		return
	}
	m := t.state.gate
	m.mu.Lock()
	if t.state.gate == m && m.active == t.state {
		t.state.lookupInFlight = false
		t.state.lookupOutcome = outcome
	}
	m.mu.Unlock()
}

// LookupOutcome classifies one token's hostname resolution attempt, including
// answer validation and cancellation. Literals and unclaimed lookups are absent.
// It describes resolution independently of later clock, dial or bootstrap work.
type LookupOutcome uint8

const (
	LookupNotAttempted LookupOutcome = iota
	LookupSucceeded
	LookupFailed
)

// LookupOutcome returns a fixed result without sampling the clock or exposing
// DNS answers. The result remains readable after End and is zero while in flight.
func (t MaintenanceToken) LookupOutcome() LookupOutcome {
	if t.state == nil || t.state.gate == nil {
		return LookupNotAttempted
	}
	t.state.gate.mu.Lock()
	defer t.state.gate.mu.Unlock()
	return t.state.lookupOutcome
}

func (t MaintenanceToken) Generation() uint64 { return t.generation() }

// ResolverSnapshot is an immutable value copy.  Its fixed answer array avoids
// mutable backing storage and keeps the retained candidate set bounded.
type ResolverSnapshot struct {
	Current      netip.Addr
	Selected     netip.Addr
	Available    bool
	Generation   uint64
	Due          bool
	Stale        bool
	StaleExpired bool
	TimeFault    bool
	StaleSince   uint64
	AnswerCount  uint8
	Answers      [MaxResolverAnswers]netip.Addr
}

func (s ResolverSnapshot) Answer(index int) (netip.Addr, bool) {
	if index < 0 || index >= int(s.AnswerCount) {
		return netip.Addr{}, false
	}
	return s.Answers[index], true
}

// ResolverState tracks metadata and freshness only.  CommitPublishedCandidate
// is intentionally named for its caller: the future lifecycle wrapper invokes
// this fallible metadata step inside atomic publication under send -> lifecycle
// locks, before the infallible socket/epoch swap.  This state object never owns
// or closes a socket and cannot make a DNS answer usable by itself.
type ResolverState struct {
	mu          sync.Mutex
	clock       Clock
	maintenance *Maintenance
	refresh     uint64
	staleAfter  uint64

	answers            [MaxResolverAnswers]netip.Addr
	answerCount        uint8
	current            netip.Addr
	selected           netip.Addr
	currentSet         bool
	selectedSet        bool
	selectedGeneration uint64
	available          bool
	stale              bool
	staleExpired       bool
	staleSince         uint64
	generation         uint64

	lastSample  uint64
	hasSample   bool
	lastRefresh uint64
	hasRefresh  bool
	timeFault   bool
}

func NewResolverState(clock Clock, maintenance *Maintenance, refresh, staleAfter time.Duration) (*ResolverState, error) {
	if clock == nil || maintenance == nil {
		return nil, ErrResolverClock
	}
	if refresh < MinDNSRefresh || refresh > MaxDNSRefresh || staleAfter < refresh || staleAfter > MaxDNSStale {
		return nil, ErrResolverInvalidTimeout
	}
	return &ResolverState{
		clock: clock, maintenance: maintenance,
		refresh: uint64(refresh), staleAfter: uint64(staleAfter),
	}, nil
}

// ApplyLookup records an answer/error observation under the live run token.
// It may update selected/stale metadata, but it never makes a new candidate
// available.  A successful answer containing a still-usable current address
// can clear staleness; after expiry, even that same address requires the
// explicit publication commit transition.
func (s *ResolverState) ApplyLookup(token MaintenanceToken, answers AnswerSet, lookupErr error) error {
	m, err := s.lockMaintenance(token)
	if err != nil {
		return err
	}
	defer m.mu.Unlock()
	defer s.mu.Unlock()
	if token.state.lookupApplied {
		return ErrResolverLookupApplied
	}
	if lookupErr == nil && (answers.origin != token.state || answers.generation != token.generation() || !validAnswerSet(answers)) {
		return ErrResolverMaintenanceToken
	}
	lookupErr = canonicalResolverApplyError(lookupErr)
	now, err := s.sampleLocked()
	if err != nil {
		return err
	}
	if lookupErr == nil {
		s.copyAnswersLocked(answers)
		s.selected = answers.selected
		if s.currentSet && answers.Contains(s.current) {
			s.selected = s.current
		}
		s.selectedSet = answers.selected.IsValid()
		s.selectedGeneration = token.generation()
	}
	token.state.lookupApplied = true
	s.generation = token.generation()
	s.lastRefresh = now
	s.hasRefresh = true
	if lookupErr != nil {
		s.beginStaleLocked(now)
		s.evaluateAvailabilityLocked(now)
		return lookupErr
	}
	// Latch stale expiry before considering whether this answer still contains
	// current.  A lookup that arrives after the retention boundary cannot
	// revive an address merely because the answer repeats it.
	s.evaluateAvailabilityLocked(now)
	if s.currentSet && answers.Contains(s.current) && !s.staleExpired {
		s.stale = false
		s.staleSince = 0
		s.available = true
	} else if s.currentSet {
		s.beginStaleLocked(now)
		s.evaluateAvailabilityLocked(now)
	} else {
		// Initial lookup success stores a candidate but remains unavailable until
		// the future lifecycle commits a fully bootstrapped candidate.
		s.available = false
	}
	return nil
}

// CommitPublishedCandidate is the fallible metadata step inside the future
// lifecycle's atomic publication operation.  The wrapper calls it under its
// send -> lifecycle lock order before the infallible socket/epoch swap; a
// validation error therefore aborts publication.  This state object still
// owns no socket and never performs that swap itself.
func (s *ResolverState) CommitPublishedCandidate(token MaintenanceToken) error {
	m, err := s.lockMaintenance(token)
	if err != nil {
		return err
	}
	defer m.mu.Unlock()
	defer s.mu.Unlock()
	if token.state.candidateCommitted {
		return ErrResolverCandidateCommitted
	}
	if _, err := s.sampleLocked(); err != nil {
		return err
	}
	s.evaluateAvailabilityLocked(s.lastSample)
	if !s.selectedSet || !s.selected.IsValid() || s.selectedGeneration != token.generation() {
		return ErrResolverNoCandidate
	}
	s.current = s.selected
	s.currentSet = true
	s.available = true
	s.stale = false
	s.staleExpired = false
	s.staleSince = 0
	token.state.candidateCommitted = true
	return nil
}

func (s *ResolverState) Snapshot() ResolverSnapshot {
	if s == nil {
		return ResolverSnapshot{TimeFault: true, Due: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, err := s.sampleLocked(); err == nil {
		s.evaluateAvailabilityLocked(now)
	} else {
		s.available = false
		s.timeFault = true
	}
	var snapshot ResolverSnapshot
	snapshot.Current = s.current
	snapshot.Selected = s.selected
	snapshot.Available = s.available
	snapshot.Generation = s.generation
	snapshot.Due = s.dueLocked()
	snapshot.Stale = s.stale
	snapshot.StaleExpired = s.staleExpired
	snapshot.TimeFault = s.timeFault
	snapshot.StaleSince = s.staleSince
	snapshot.AnswerCount = s.answerCount
	snapshot.Answers = s.answers
	return snapshot
}

func (s *ResolverState) lockMaintenance(token MaintenanceToken) (*Maintenance, error) {
	if s == nil || s.maintenance == nil {
		return nil, ErrResolverMaintenanceToken
	}
	m := s.maintenance
	m.mu.Lock()
	if !m.validLocked(token) {
		m.mu.Unlock()
		return nil, ErrResolverMaintenanceToken
	}
	s.mu.Lock()
	return m, nil
}

func (s *ResolverState) copyAnswersLocked(answers AnswerSet) {
	s.answers = answers.addresses
	s.answerCount = answers.count
}

func (s *ResolverState) beginStaleLocked(now uint64) {
	if !s.currentSet || s.stale {
		return
	}
	s.stale = true
	s.staleSince = now
	s.staleExpired = false
}

func (s *ResolverState) sampleLocked() (uint64, error) {
	_, now := s.clock.Now()
	if now == math.MaxUint64 {
		s.timeFault = true
		s.available = false
		return 0, ErrResolverClock
	}
	if s.hasSample && now < s.lastSample {
		// Retain the high-water sample and stale origin.  A later sample at or
		// above this value may resume evaluation, but expiry remains latched.
		s.timeFault = true
		s.available = false
		return 0, ErrResolverClock
	}
	s.lastSample = now
	s.hasSample = true
	if s.timeFault {
		s.timeFault = false
	}
	return now, nil
}

func (s *ResolverState) evaluateAvailabilityLocked(now uint64) {
	if !s.currentSet || s.timeFault {
		s.available = false
		return
	}
	if s.stale && !s.staleExpired {
		if now >= s.staleSince && now-s.staleSince >= s.staleAfter {
			s.staleExpired = true
		}
	}
	if s.staleExpired {
		s.available = false
		return
	}
	s.available = true
}

func (s *ResolverState) dueLocked() bool {
	if s.timeFault || !s.hasRefresh {
		return true
	}
	if !s.hasSample || s.lastSample < s.lastRefresh {
		return true
	}
	return s.lastSample-s.lastRefresh >= s.refresh
}

func validAnswerSet(answers AnswerSet) bool {
	if answers.count == 0 || answers.count > MaxResolverAnswers || !answers.selected.IsValid() {
		return false
	}
	for index := 0; index < int(answers.count); index++ {
		address := answers.addresses[index]
		if !address.IsValid() || address.Zone() != "" {
			return false
		}
		if index > 0 && answers.addresses[index-1].Compare(address) >= 0 {
			return false
		}
	}
	return answers.selected == answers.addresses[0]
}

func canonicalResolverApplyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ErrResolverCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrResolverTimeout
	}
	for _, fixed := range []error{
		ErrResolverClock,
		ErrResolverCanceled,
		ErrResolverTimeout,
		ErrResolverNoAnswers,
		ErrResolverTooManyRawAnswers,
		ErrResolverTooManyAnswers,
		ErrResolverInvalidAnswer,
		ErrResolverLookup,
	} {
		if errors.Is(err, fixed) {
			return fixed
		}
	}
	return ErrResolverLookup
}
