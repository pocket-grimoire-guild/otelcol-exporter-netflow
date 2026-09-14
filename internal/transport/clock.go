// Package transport contains the internal clock and connected UDP seams used
// by the destination lifecycle.  The seams are deliberately small so that
// destination state remains the owner of logical send-time reservation.
package transport

import (
	"math"
	"time"
)

const invalidClockValue = math.MaxUint64

// Clock returns the UTC wall-clock timestamp and an independent elapsed value
// in nanoseconds.  The two values have different jobs: wall is serialized in
// protocol headers, while elapsed is used only for refresh and timer policy.
//
// Wall values use the uint64 shape required by destination.PacketClock.  A
// wall value outside the representable protocol range is reported as
// invalidClockValue, which State rejects; it is never converted into a valid
// timestamp by overflow or clamping.
type Clock interface {
	Now() (wallUnixNanos, monotonicNanos uint64)
}

// systemClock is intentionally private: callers must use NewClock and cannot
// construct a zero-origin clock that could silently produce invalid elapsed
// values.
type systemClock struct {
	origin time.Time
}

// NewClock constructs a production clock. time.Now supplies a monotonic
// reading when available; Time.Sub therefore does not follow wall-clock
// adjustments. The returned interface has no exported concrete zero value.
func NewClock() Clock { return &systemClock{origin: time.Now()} }

// Now implements Clock.
func (c *systemClock) Now() (wallUnixNanos, monotonicNanos uint64) {
	if c == nil {
		return invalidClockValue, invalidClockValue
	}
	now := time.Now()
	var ok bool
	wallUnixNanos, ok = checkedWallUnixNanos(now)
	if !ok {
		return invalidClockValue, invalidClockValue
	}
	elapsed := now.Sub(c.origin)
	if elapsed < 0 {
		// Unsupported backward elapsed samples fail closed instead of resetting
		// the refresh clock to zero.
		return invalidClockValue, invalidClockValue
	}
	return wallUnixNanos, uint64(elapsed)
}

func checkedWallUnixNanos(now time.Time) (uint64, bool) {
	seconds := now.Unix()
	nanos := int64(now.Nanosecond())
	maxSeconds := int64(math.MaxInt64 / int64(time.Second))
	maxNanos := int64(math.MaxInt64 % int64(time.Second))
	if seconds < 0 || seconds > maxSeconds || (seconds == maxSeconds && nanos > maxNanos) {
		return invalidClockValue, false
	}
	return uint64(seconds)*uint64(time.Second) + uint64(nanos), true
}
