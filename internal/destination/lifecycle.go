package destination

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

var (
	ErrRuntimeClosed      = errors.New("destination: runtime closed")
	ErrRuntimeBusy        = errors.New("destination: runtime busy")
	ErrRuntimeUnavailable = errors.New("destination: runtime unavailable")
)

// RuntimeConfig joins the existing state and DNS freshness policies.
// DNS durations must already be normalized to the transport bounds.
type RuntimeConfig struct {
	Observe       Observer
	State         Config
	DNSRefresh    time.Duration
	DNSStaleAfter time.Duration
	// NewTimer defaults to the standard-library monotonic timer. Start checks
	// each returned timer/channel before lookup. Each call must return a fresh
	// timer: DNS and template maintenance have independent, single-owner timers.
	NewTimer transport.TimerFactory
	// ShutdownDrainTimeout defaults to five seconds; the accepted range is
	// one to thirty seconds, and it must cover DNS and write timeouts.
	ShutdownDrainTimeout time.Duration
}

// Runtime owns one connected endpoint epoch. Start registers, dials and
// bootstraps a candidate; Pack synchronously sends on the published epoch.
// One hostname worker refreshes DNS and replaces endpoints; one v9/IPFIX
// worker refreshes idle templates, including on literal endpoints. There is
// no data queue or retry.
//
// The future Collector wrapper must reuse this lifecycle authority for its
// admission and shutdown integration, rather than introduce a second handle
// owner. send is always taken before lifecycle; Shutdown never waits for send.
type Runtime struct {
	send      sendPermit
	lifecycle sync.Mutex

	compiled    mapping.CompiledMapping
	writer      wire.ContractWriter
	config      RuntimeConfig
	dialer      *transport.CandidateDialer
	clock       transport.Clock
	maintenance *transport.Maintenance
	resolver    *transport.ResolverState

	closing       bool
	attempt       *candidateAttempt
	published     *endpoint
	activeWrites  uint32
	activeCalls   uint32
	packCancel    context.CancelFunc
	requestCancel context.CancelFunc
	dnsCancel     context.CancelFunc
	dnsWake       chan struct{} // one coalesced pending trigger, never a work queue
	refreshCancel context.CancelFunc
	refreshWake   chan struct{} // one coalesced template trigger
	drained       chan struct{}
	closeOnce     sync.Once
	closeErr      error
	shutdownOnce  sync.Once
	shutdownDone  chan struct{}
	shutdownErr   error
}

type candidateAttempt struct {
	cancel    context.CancelFunc
	candidate *transport.Candidate // attached under lifecycle before any Write
	previous  *endpoint            // publication must still replace this endpoint
}

type endpoint struct {
	candidate *transport.Candidate
	state     *State
	packer    *Packer
}

// NewRuntime validates the compiled/state/transport cap handoff before any
// lookup or socket operation. The injected writer and clock are the same ones
// used for both bootstrap and request packing. All mutable epoch and resolver
// state belongs to this runtime alone.
func NewRuntime(compiled mapping.CompiledMapping, writer wire.ContractWriter, config RuntimeConfig, dialer *transport.CandidateDialer, clock transport.Clock) (*Runtime, error) {
	if dialer == nil || clock == nil {
		return nil, ErrInvalidConfig
	}
	if config.ShutdownDrainTimeout == 0 {
		config.ShutdownDrainTimeout = 5 * time.Second
	}
	if config.NewTimer == nil {
		config.NewTimer = transport.NewTimer
	}
	if config.ShutdownDrainTimeout < time.Second || config.ShutdownDrainTimeout > 30*time.Second ||
		dialer.WriteTimeout() > config.ShutdownDrainTimeout || dialer.ResolverTimeout() > config.ShutdownDrainTimeout {
		return nil, ErrInvalidConfig
	}
	state, err := NewState(compiled, writer, config.State)
	if err != nil {
		return nil, err
	}
	config.State = state.Config()
	if state.stream == nil || dialer.PayloadCap() != config.State.MaxDatagramSize || dialer.CompiledPayloadCap() != compiled.MaxDatagramSize() {
		return nil, ErrInvalidConfig
	}
	maintenance := transport.NewMaintenance()
	resolver, err := transport.NewResolverState(clock, maintenance, config.DNSRefresh, config.DNSStaleAfter)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		compiled: compiled, writer: writer, config: config, dialer: dialer,
		clock: clock, maintenance: maintenance, resolver: resolver,
		send:    newSendPermit(),
		drained: make(chan struct{}), shutdownDone: make(chan struct{}), dnsWake: make(chan struct{}, 1),
		refreshWake: make(chan struct{}, 1),
	}, nil
}

// Start publishes one fully bootstrapped initial epoch. An unsuccessful call
// leaves no owned socket or live maintenance token; a later explicit Start may
// try a fresh epoch from copy/shape/sequence zero. A concurrent Start is busy.
func (r *Runtime) Start(ctx context.Context) error {
	if ctx == nil {
		return transport.ErrInvalidContext
	}
	r.lifecycle.Lock()
	if r.closing {
		r.lifecycle.Unlock()
		return ErrRuntimeClosed
	}
	if r.published != nil {
		r.lifecycle.Unlock()
		return nil
	}
	if r.attempt != nil {
		r.lifecycle.Unlock()
		return ErrRuntimeBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	attempt := &candidateAttempt{cancel: cancel}
	r.attempt = attempt // register before maintenance, resolution or dial
	r.activeCalls++
	r.lifecycle.Unlock()
	var timer, refreshTimer transport.Timer
	started := false
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if refreshTimer != nil {
			refreshTimer.Stop()
		}
		r.finishAttempt(attempt)
		if started {
			r.startDNSWorker(timer)
			r.startRefreshWorker(refreshTimer)
		}
	}()
	if r.dialer.UsesDNS() {
		timer = r.config.NewTimer(r.config.DNSRefresh)
		if timer == nil || timer.C() == nil {
			return ErrInvalidConfig
		}
	}
	if r.config.State.Protocol != wire.ProtocolV5 {
		refreshTimer = r.config.NewTimer(r.config.State.RefreshInterval)
		if refreshTimer == nil || refreshTimer.C() == nil || (timer != nil && timer.C() == refreshTimer.C()) {
			return ErrInvalidConfig
		}
	}

	token, err := r.maintenance.Begin()
	if err != nil {
		return err
	}
	// Dial is synchronous and joins its lookup before returning, so End cannot
	// overlap that lookup. End precedes unregistering this attempt.
	defer r.maintenance.End(token)
	candidate, err := r.dialer.Dial(ctx, r.resolver, token)
	r.observeDNS(ctx, token)
	if err != nil {
		if token.LookupOutcome() != transport.LookupFailed {
			r.config.Observe.emit(ctx, CandidateFailed, 0)
		}
		return err
	}
	err = r.prepareCandidate(ctx, attempt, token, candidate)
	started = err == nil
	return err
}

// prepareCandidate is shared by initial Start and scheduled DNS replacement.
// The caller has already registered the attempt and owns a live token.
func (r *Runtime) prepareCandidate(ctx context.Context, attempt *candidateAttempt, token transport.MaintenanceToken, candidate *transport.Candidate) error {
	r.lifecycle.Lock()
	if r.closing || ctx.Err() != nil {
		r.lifecycle.Unlock()
		_ = candidate.Close()
		return ErrRuntimeUnavailable
	}
	attempt.candidate = candidate
	r.lifecycle.Unlock()

	state, err := NewState(r.compiled, r.writer, r.config.State)
	if err != nil {
		return err
	}
	if err := r.bootstrap(ctx, attempt, state); err != nil {
		r.config.Observe.emit(ctx, BootstrapFailed, 0)
		return err
	}
	// Finish every fallible construction step before publication. This private
	// packer cannot write data until writePublished sees the published handle.
	packer, err := NewPacker(state, PackerConfig{
		Clock: r.clock.Now, Observe: r.config.Observe,
		Available: func() bool { return r.resolver.Snapshot().Available },
		Write: func(ctx context.Context, payload []byte) (int, error) {
			return r.writePublished(ctx, candidate, payload)
		},
	})
	if err != nil {
		return err
	}
	err = r.publish(ctx, attempt, token, &endpoint{candidate: candidate, state: state, packer: packer})
	if err == nil {
		r.config.Observe.emit(ctx, EpochPublished, 0)
	} else {
		r.config.Observe.emit(ctx, CandidateFailed, 0)
	}
	return err
}

func (r *Runtime) finishAttempt(attempt *candidateAttempt) {
	r.lifecycle.Lock()
	candidate := attempt.candidate
	attempt.candidate = nil
	r.lifecycle.Unlock()
	attempt.cancel()
	if candidate != nil {
		_ = candidate.Close()
	}
	// Keep this operation registered until cleanup finishes, so another Start
	// cannot accumulate candidates behind a slow Close.
	r.lifecycle.Lock()
	if r.attempt == attempt {
		r.attempt = nil
	}
	r.endCallLocked()
	r.lifecycle.Unlock()
}

// Pack registers one operation before waiting for send. The permit covers the
// complete packer call and its state/ledger commits; the transport callback
// takes only lifecycle.
func (r *Runtime) Pack(ctx context.Context, logs plog.Logs, lookup IndexedLookup) (*PackResult, error) {
	if ctx == nil {
		return nil, transport.ErrInvalidContext
	}
	r.lifecycle.Lock()
	if r.closing {
		r.lifecycle.Unlock()
		return nil, ErrRuntimeClosed
	}
	if r.packCancel != nil {
		r.lifecycle.Unlock()
		return nil, ErrRuntimeBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	r.packCancel = cancel
	r.activeCalls++
	r.lifecycle.Unlock()
	acquired := r.send.acquire(ctx)
	defer r.finishPack(cancel, acquired)
	if !acquired {
		r.lifecycle.Lock()
		closing := r.closing
		r.lifecycle.Unlock()
		if closing {
			return nil, ErrRuntimeClosed
		}
		return nil, ErrRuntimeUnavailable
	}
	r.lifecycle.Lock()
	current, closing := r.published, r.closing
	canceled := ctx.Err() != nil
	r.lifecycle.Unlock()
	if closing {
		return nil, ErrRuntimeClosed
	}
	if canceled {
		return nil, ErrRuntimeUnavailable
	}
	if current == nil {
		return nil, ErrRuntimeUnavailable
	}
	snapshot := r.resolver.Snapshot()
	if snapshot.Due {
		r.triggerDNS()
	}
	if !snapshot.Available || ctx.Err() != nil {
		return nil, ErrRuntimeUnavailable
	}
	result, err := current.packer.Pack(ctx, logs, lookup)
	// A final successful data packet can cross the count threshold with no
	// next packet to drain it. Queue under send so the worker can consume all
	// preceding wakes before its attempt. Failed requests never trigger retries.
	if err == nil && current.state.Progress().RefreshDue {
		r.triggerRefresh()
	}
	return result, err
}

func (r *Runtime) finishPack(cancel context.CancelFunc, acquired bool) {
	cancel()
	r.lifecycle.Lock()
	// Release send before completing admission. A new caller must still pass
	// lifecycle before registering; shutdown observes all state cleanup done.
	if acquired {
		r.send.release()
	}
	r.packCancel = nil
	r.endCallLocked()
	r.lifecycle.Unlock()
}

func (r *Runtime) endCallLocked() {
	r.activeCalls--
	if r.closing && r.activeCalls == 0 {
		close(r.drained)
	}
}

func (r *Runtime) writePublished(ctx context.Context, candidate *transport.Candidate, payload []byte) (int, error) {
	r.lifecycle.Lock()
	if r.closing || r.published == nil || r.published.candidate != candidate || !r.resolver.Snapshot().Available {
		r.lifecycle.Unlock()
		return 0, ErrRuntimeUnavailable
	}
	r.activeWrites++
	r.lifecycle.Unlock()
	defer r.endWrite()
	return candidate.Write(ctx, payload)
}

func (r *Runtime) endWrite() {
	r.lifecycle.Lock()
	r.activeWrites--
	r.lifecycle.Unlock()
}

// closeHandles closes admission and sockets without waiting behind send or
// admitted calls. Conn.Close must promptly interrupt writes, as required by
// the injected connected-UDP contract. No socket cleanup runs under lifecycle.
func (r *Runtime) closeHandles() {
	r.closeOnce.Do(func() {
		r.lifecycle.Lock()
		r.closing = true
		current, attempt := r.published, r.attempt
		r.published = nil
		packCancel := r.packCancel
		requestCancel := r.requestCancel
		dnsCancel := r.dnsCancel
		refreshCancel := r.refreshCancel
		var candidate *transport.Candidate
		if attempt != nil {
			candidate, attempt.candidate = attempt.candidate, nil
		}
		if r.activeCalls == 0 {
			close(r.drained)
		}
		r.lifecycle.Unlock()
		if packCancel != nil {
			packCancel()
		}
		if requestCancel != nil {
			requestCancel()
		}
		if dnsCancel != nil {
			dnsCancel()
		}
		if refreshCancel != nil {
			refreshCancel()
		}
		if attempt != nil {
			attempt.cancel()
		}
		if candidate != nil {
			r.closeErr = candidate.Close()
		}
		if current != nil {
			if err := current.candidate.Close(); r.closeErr == nil {
				r.closeErr = err
			}
		}
	})
}

// Shutdown is terminal, idempotent and safe before Start. It closes admission,
// cancels operations, closes sockets, then joins admitted calls and maintenance.
// The earlier of each caller's context and the configured drain bounds its
// wait. The first completed drain or expired/canceled caller stores the shared
// result; an earlier concurrent deadline therefore ends the wait for everyone.
// Later calls return that result even if their own context is canceled.
//
// A timed-out call can leave an injected callback or lookup finishing cleanup,
// but it cannot publish or send: admission and owned sockets are already closed,
// and a late dial result is canceled and closed before attachment. No additional
// goroutine is created to wait for calls. The future Collector wrapper must
// extend this admission boundary through helper processing and subset copying.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return transport.ErrInvalidContext
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.ShutdownDrainTimeout)
	defer cancel()
	r.closeHandles()
	select {
	case <-r.shutdownDone:
		return r.shutdownErr
	default:
	}
	select {
	case <-r.drained:
		r.finishShutdown(r.closeErr)
	case <-ctx.Done():
		r.finishShutdown(ctx.Err())
	case <-r.shutdownDone:
	}
	return r.shutdownErr
}

func (r *Runtime) finishShutdown(err error) {
	r.shutdownOnce.Do(func() {
		r.shutdownErr = err
		close(r.shutdownDone)
	})
}

// Close is Shutdown with the configured drain timeout and no earlier caller
// deadline. Like Shutdown, it must not be called from an admitted callback.
func (r *Runtime) Close() error { return r.Shutdown(context.Background()) }
