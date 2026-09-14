package destination

import (
	"context"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// startDNSWorker runs only after initial token and attempt cleanup. Register
// before launching, under the same authority that closes admission and drains
// calls. A successful Start context does not own this component-lifetime work.
func (r *Runtime) startDNSWorker(timer transport.Timer) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closing || r.published == nil || r.dnsCancel != nil || timer == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.dnsCancel = cancel
	r.activeCalls++
	go r.runDNS(ctx, timer)
}

func (r *Runtime) triggerDNS() {
	if !r.dialer.UsesDNS() {
		return
	}
	select {
	case r.dnsWake <- struct{}{}:
	default:
	}
}

func (r *Runtime) runDNS(ctx context.Context, timer transport.Timer) {
	defer func() {
		r.lifecycle.Lock()
		r.dnsCancel = nil
		r.endCallLocked()
		r.lifecycle.Unlock()
	}()
	defer timer.Stop()
	timer.Reset(r.config.DNSRefresh)
	for {
		timed := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C():
			timed = true
		case <-r.dnsWake:
		}
		if ctx.Err() != nil {
			return
		}
		snapshot := r.resolver.Snapshot()
		// A queued Consume trigger is only a request to recheck freshness.
		// Lookup completion sets the next due interval even on DNS failure.
		// Clock faults may be retried on timer ticks, never a Consume hot loop.
		if snapshot.Due && (timed || !snapshot.TimeFault) {
			_ = r.maintainDNS(ctx)
			timer.Reset(r.config.DNSRefresh)
		} else if timed {
			timer.Reset(r.config.DNSRefresh)
		}
	}
}

func (r *Runtime) maintainDNS(ctx context.Context) error {
	r.lifecycle.Lock()
	if r.closing || ctx.Err() != nil || r.published == nil || r.attempt != nil {
		r.lifecycle.Unlock()
		return ErrRuntimeUnavailable
	}
	ctx, cancel := context.WithCancel(ctx)
	attempt := &candidateAttempt{cancel: cancel, previous: r.published}
	r.attempt = attempt // registration precedes lookup and numeric dial
	r.activeCalls++
	r.lifecycle.Unlock()
	defer r.finishAttempt(attempt)

	token, err := r.maintenance.Begin()
	if err != nil {
		return err
	}
	defer r.maintenance.End(token) // synchronous lookup is joined before End
	candidate, err := r.dialer.DialReplacement(ctx, r.resolver, token, attempt.previous.candidate)
	r.observeDNS(ctx, token)
	if err != nil && token.LookupOutcome() != transport.LookupFailed {
		r.config.Observe.emit(ctx, CandidateFailed, 0)
	}
	if err != nil || candidate == nil {
		return err // unchanged available address retains its entire epoch
	}
	return r.prepareCandidate(ctx, attempt, token, candidate)
}
