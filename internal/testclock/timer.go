package testclock

import (
	"sync"
	"time"
)

// Timer is a manually fired, single-slot timer with a bounded reset trace.
// Firing never advances Clock: tests explicitly control both sources. Reset
// drops an unread expiry, as does a standard-library Go 1.26 channel timer.
type Timer struct {
	mu      sync.Mutex
	wake    chan time.Time
	armed   bool
	stopped bool
	delays  []time.Duration
	changed chan struct{}
}

func NewTimer() *Timer {
	return &Timer{wake: make(chan time.Time, 1), changed: make(chan struct{})}
}

func (t *Timer) C() <-chan time.Time { return t.wake }

func (t *Timer) Reset(delay time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.delays) == 256 {
		panic("testclock: timer reset trace exhausted")
	}
	select {
	case <-t.wake:
	default:
	}
	t.armed, t.stopped = true, false
	t.delays = append(t.delays, delay)
	t.notifyLocked()
}

func (t *Timer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.armed, t.stopped = false, true
	select {
	case <-t.wake:
	default:
	}
	t.notifyLocked()
}

func (t *Timer) Fire() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.armed {
		return false
	}
	t.armed = false
	t.wake <- time.Time{}
	return true
}

// Snapshot and its change channel allow barrier-based assertions without
// sleeps or polling. The caller must take a new snapshot after each change.
func (t *Timer) Snapshot() (delays []time.Duration, stopped bool, changed <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]time.Duration(nil), t.delays...), t.stopped, t.changed
}

func (t *Timer) notifyLocked() {
	close(t.changed)
	t.changed = make(chan struct{})
}
