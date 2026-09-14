package transport

import "time"

// Timer is a single-owner, resettable monotonic wakeup. Its channel carries no
// policy timestamp: consumers sample Clock for DNS or template freshness. Stop prevents
// future delivery; Reset discards a previous unread expiry, matching Go 1.26
// time.Timer. Implementations must not create a goroutine per reset.
type Timer interface {
	C() <-chan time.Time
	Reset(time.Duration)
	Stop()
}

type TimerFactory func(time.Duration) Timer

type systemTimer struct{ timer *time.Timer }

func NewTimer(delay time.Duration) Timer { return &systemTimer{timer: time.NewTimer(delay)} }

func (t *systemTimer) C() <-chan time.Time   { return t.timer.C }
func (t *systemTimer) Reset(d time.Duration) { t.timer.Reset(d) }
func (t *systemTimer) Stop()                 { t.timer.Stop() }
