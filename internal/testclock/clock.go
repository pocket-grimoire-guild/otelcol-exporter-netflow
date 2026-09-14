// Package testclock provides bounded, concurrency-safe clock seams for
// deterministic transport and destination tests.
package testclock

import "sync"

// Clock is a manually controlled pair of wall and elapsed values.  Wall and
// monotonic values can be changed independently to exercise wall-clock steps
// without changing refresh/timer time.
type Clock struct {
	mu sync.RWMutex

	wallUnixNanos  uint64
	monotonicNanos uint64
}

// New constructs a clock at the supplied values.
func New(wallUnixNanos, monotonicNanos uint64) *Clock {
	return &Clock{wallUnixNanos: wallUnixNanos, monotonicNanos: monotonicNanos}
}

// Now returns the current deterministic pair.
func (c *Clock) Now() (wallUnixNanos, monotonicNanos uint64) {
	if c == nil {
		return ^uint64(0), ^uint64(0)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.wallUnixNanos, c.monotonicNanos
}

// Set replaces both values atomically.  Tests may intentionally set a wall
// value outside the protocol range; production State owns rejection of it.
func (c *Clock) Set(wallUnixNanos, monotonicNanos uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.wallUnixNanos, c.monotonicNanos = wallUnixNanos, monotonicNanos
	c.mu.Unlock()
}

// SetWall changes only the UTC wall value.
func (c *Clock) SetWall(wallUnixNanos uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.wallUnixNanos = wallUnixNanos
	c.mu.Unlock()
}

// SetMonotonic changes only the elapsed value.  Callers are responsible for
// preserving monotonic ordering when modeling a valid timer source.
func (c *Clock) SetMonotonic(monotonicNanos uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.monotonicNanos = monotonicNanos
	c.mu.Unlock()
}

// Advance moves wall and elapsed values independently by unsigned amounts.
// It is useful for stepping the refresh source while keeping a stable wall
// timestamp, or vice versa.  Overflow is intentionally checked by callers
// that need a bounded vector; this helper wraps like ordinary uint64 math.
func (c *Clock) Advance(wallDelta, monotonicDelta uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.wallUnixNanos += wallDelta
	c.monotonicNanos += monotonicDelta
	c.mu.Unlock()
}
