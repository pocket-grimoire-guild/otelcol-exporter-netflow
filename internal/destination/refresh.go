package destination

import (
	"context"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// Like DNS work, template maintenance belongs to the component lifetime and
// is registered before launch. Start has already validated/stopped the timer.
func (r *Runtime) startRefreshWorker(timer transport.Timer) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closing || r.published == nil || r.refreshCancel != nil || timer == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.refreshCancel = cancel
	r.activeCalls++
	go r.runRefresh(ctx, timer)
}

func (r *Runtime) triggerRefresh() {
	select {
	case r.refreshWake <- struct{}{}:
	default:
	}
}

func (r *Runtime) runRefresh(ctx context.Context, timer transport.Timer) {
	defer func() {
		r.lifecycle.Lock()
		r.refreshCancel = nil
		r.endCallLocked()
		r.lifecycle.Unlock()
	}()
	defer timer.Stop()
	timer.Reset(r.refreshTemplates(ctx))
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C():
		case <-r.refreshWake:
		}
		if ctx.Err() != nil {
			return
		}
		timer.Reset(r.refreshTemplates(ctx))
	}
}

// refreshTemplates first checks without send to avoid making data admission
// busy for an early timer. Only a due round waits for send; this one registered
// worker is the sole template waiter, and Shutdown never waits behind send.
func (r *Runtime) refreshTemplates(ctx context.Context) time.Duration {
	interval := r.config.State.RefreshInterval
	r.lifecycle.Lock()
	current, closing := r.published, r.closing
	r.lifecycle.Unlock()
	if closing || current == nil || ctx.Err() != nil {
		return interval
	}
	_, mono := r.clock.Now()
	if delay := refreshRemaining(current.state.Progress(), mono, interval); delay > 0 {
		return delay
	}
	r.send.Lock()
	defer r.send.Unlock()
	// Consume wakes were queued under send. Discard the pending recheck, not
	// a second round, before attempting any write; failure then waits a full
	// interval instead of immediately retrying a queued timer/Consume trigger.
	select {
	case <-r.refreshWake:
	default:
	}
	r.lifecycle.Lock()
	current, closing = r.published, r.closing
	r.lifecycle.Unlock()
	if closing || current == nil || ctx.Err() != nil {
		return interval
	}
	if !r.resolver.Snapshot().Available {
		r.config.Observe.emit(ctx, RefreshFailed, 0)
		return interval
	}
	if err := current.packer.refresh(ctx); err != nil {
		return interval // partial progress stays due; no automatic immediate retry
	}
	_, mono = r.clock.Now()
	if delay := refreshRemaining(current.state.Progress(), mono, interval); delay > 0 {
		return delay
	}
	return interval // clock jumps must not turn maintenance into a hot loop
}

// Use subtraction only after ordering, avoiding unsigned clock underflow and
// deadline addition overflow. A successful Consume refresh shifts the next
// deadline; early ticks rearm only its remaining interval, not a fresh one.
func refreshRemaining(progress ProgressSnapshot, mono uint64, interval time.Duration) time.Duration {
	if progress.RefreshDue || progress.RefreshActive {
		return 0
	}
	if !progress.HasRefreshMono || mono < progress.LastRefreshMono {
		return interval
	}
	elapsed := mono - progress.LastRefreshMono
	if elapsed >= uint64(interval) {
		return 0
	}
	return interval - time.Duration(elapsed)
}
