package transport

import (
	"testing"
	"time"
)

func TestDNSTimerResetAndStop(t *testing.T) {
	timer := NewTimer(0)
	defer timer.Stop()
	select {
	case <-timer.C():
	case <-time.After(time.Second):
		t.Fatal("immediate timer failed to wake")
	}
	timer.Reset(time.Hour)
	select {
	case <-timer.C():
		t.Fatal("reset delivered a stale expiry")
	default:
	}
	timer.Stop()
	timer.Reset(0)
	select {
	case <-timer.C():
	case <-time.After(time.Second):
		t.Fatal("stopped timer failed to reset")
	}
}
