// Package testtransport provides bounded scripted transport seams for
// deterministic destination tests.  It is never used by production code.
package testtransport

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

const (
	// MaxScriptSteps and MaxEvents keep accidental test scripts bounded.
	MaxScriptSteps = 256
	MaxEvents      = 512
	maxPayload     = 65507
)

var ErrScriptExhausted = errors.New("testtransport: scripted write outcomes exhausted")

// EventKind identifies one bounded fake-connection event.
type EventKind uint8

const (
	EventWrite EventKind = iota + 1
	EventDeadline
	EventClose
)

// Event is a copy-safe trace record.  Payload is retained only for the
// bounded test fake and is never produced by the production transport.
type Event struct {
	Kind     EventKind
	Payload  []byte
	N        int
	Err      error
	Deadline time.Time
}

// WriteStep is one scripted Write outcome.  If Wait is non-nil, Write waits
// synchronously until Wait is closed, its deadline changes, or Close runs.
// This lets cancellation tests exercise an outstanding write without adding a
// per-datagram goroutine to the production seam.
type WriteStep struct {
	N       int
	Err     error
	Wait    <-chan struct{}
	Started chan<- struct{}
	OnWrite func()
}

// Conn is a deterministic connected-UDP fake implementing transport.Conn.
// The package avoids importing production Writer so it can be used to test
// both the connection and writer layers independently.
type Conn struct {
	mu sync.Mutex

	local  netip.AddrPort
	remote netip.AddrPort
	steps  []WriteStep
	events []Event

	deadlineErr        error
	deadlineErrors     map[int]error
	deadlineBlockCall  int
	deadlineBlock      <-chan struct{}
	deadlineBlockEntry chan<- struct{}
	deadlineCalls      int
	deadline           time.Time
	deadlineWake       chan struct{}
	closed             chan struct{}
	closeOnce          sync.Once
	closedFlag         bool
}

// NewConn constructs a bounded scripted connection. Supplying more than
// MaxScriptSteps is test-programmer misuse and panics instead of truncating
// evidence silently.
func NewConn(local, remote netip.AddrPort, steps ...WriteStep) *Conn {
	if len(steps) > MaxScriptSteps {
		panic("testtransport: script exceeds MaxScriptSteps")
	}
	copied := append([]WriteStep(nil), steps...)
	return &Conn{
		local: local, remote: remote, steps: copied, deadlineErrors: make(map[int]error),
		deadlineWake: make(chan struct{}), closed: make(chan struct{}),
		events: make([]Event, 0, MaxEvents),
	}
}

func (c *Conn) LocalAddr() netip.AddrPort {
	if c == nil {
		return netip.AddrPort{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.local
}

func (c *Conn) RemoteAddr() netip.AddrPort {
	if c == nil {
		return netip.AddrPort{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

// SetDeadlineError injects one fixed error for all subsequent deadline setup
// calls.  Passing nil restores successful setup.
func (c *Conn) SetDeadlineError(err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.deadlineErr = err
	c.mu.Unlock()
}

// SetDeadlineErrorOnCall injects one error on a particular deadline call.
func (c *Conn) SetDeadlineErrorOnCall(call int, err error) {
	if c == nil || call <= 0 {
		panic("testtransport: invalid deadline call")
	}
	c.mu.Lock()
	c.deadlineErrors[call] = err
	c.mu.Unlock()
}

// BlockDeadlineCall signals entry and delays one deadline operation until wait
// is closed. It proves that cancellation cleanup is joined before the next
// write even when the underlying write has already returned.
func (c *Conn) BlockDeadlineCall(call int, wait <-chan struct{}, entered chan<- struct{}) {
	if c == nil || call <= 0 || wait == nil || entered == nil {
		panic("testtransport: invalid deadline block")
	}
	c.mu.Lock()
	c.deadlineBlockCall, c.deadlineBlock, c.deadlineBlockEntry = call, wait, entered
	c.mu.Unlock()
}

// AddStep appends one bounded scripted result and reports a capacity error.
func (c *Conn) AddStep(step WriteStep) error {
	if c == nil {
		return ErrScriptExhausted
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.steps) >= MaxScriptSteps {
		return ErrScriptExhausted
	}
	c.steps = append(c.steps, step)
	return nil
}

func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	if c == nil {
		return net.ErrClosed
	}
	c.mu.Lock()
	if c.closedFlag {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.deadlineCalls++
	call := c.deadlineCalls
	event := Event{Kind: EventDeadline, Deadline: deadline}
	err := c.deadlineErr
	if callErr, ok := c.deadlineErrors[call]; ok {
		err = callErr
	}
	if err != nil {
		event.Err = err
		c.appendEventLocked(event)
		c.mu.Unlock()
		return err
	}
	block := c.deadlineBlock
	entry := c.deadlineBlockEntry
	if call != c.deadlineBlockCall {
		block, entry = nil, nil
	}
	c.appendEventLocked(event)
	c.mu.Unlock()
	if block != nil {
		close(entry)
		<-block
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedFlag {
		return net.ErrClosed
	}
	previous := c.deadlineWake
	c.deadline = deadline
	c.deadlineWake = make(chan struct{})
	close(previous)
	return nil
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	if len(payload) > maxPayload {
		return 0, errors.New("testtransport: datagram too large")
	}
	c.mu.Lock()
	if c.closedFlag {
		c.mu.Unlock()
		return c.finishWrite(payload, 0, net.ErrClosed)
	}
	step := WriteStep{N: len(payload)}
	if len(c.steps) == 0 {
		c.mu.Unlock()
		return c.finishWrite(payload, 0, ErrScriptExhausted)
	}
	step = c.steps[0]
	c.steps = c.steps[1:]
	wake := c.deadlineWake
	deadline := c.deadline
	closed := c.closed
	c.mu.Unlock()
	if step.Started != nil {
		close(step.Started)
	}

	if step.Wait != nil {
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return c.finishWrite(payload, step.N, deadlineError(step.Err))
			}
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
		select {
		case <-step.Wait:
			if timer != nil {
				timer.Stop()
			}
			if c.isClosed() {
				return c.finishWrite(payload, 0, net.ErrClosed)
			}
			return c.finishWrite(payload, step.N, step.Err)
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
			if c.isClosed() {
				return c.finishWrite(payload, 0, net.ErrClosed)
			}
			return c.finishWrite(payload, step.N, deadlineError(step.Err))
		case <-timerC:
			if c.isClosed() {
				return c.finishWrite(payload, 0, net.ErrClosed)
			}
			return c.finishWrite(payload, step.N, deadlineError(step.Err))
		case <-closed:
			if timer != nil {
				timer.Stop()
			}
			return c.finishWrite(payload, 0, net.ErrClosed)
		}
	}
	if step.OnWrite != nil {
		step.OnWrite()
	}
	return c.finishWrite(payload, step.N, step.Err)
}

func deadlineError(scripted error) error {
	if scripted != nil {
		return scripted
	}
	return os.ErrDeadlineExceeded
}

func (c *Conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closedFlag
}

func (c *Conn) finishWrite(payload []byte, n int, err error) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := append([]byte(nil), payload...)
	c.appendEventLocked(Event{Kind: EventWrite, Payload: copied, N: n, Err: err})
	return n, err
}

func (c *Conn) Close() error {
	if c == nil {
		return net.ErrClosed
	}
	var closeErr error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closedFlag = true
		close(c.closed)
		close(c.deadlineWake)
		c.appendEventLocked(Event{Kind: EventClose})
		c.mu.Unlock()
	})
	return closeErr
}

// Events returns an independent bounded trace copy.
func (c *Conn) Events() []Event {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]Event, len(c.events))
	for i, event := range c.events {
		result[i] = event
		result[i].Payload = append([]byte(nil), event.Payload...)
	}
	return result
}

// Writes returns only write events, preserving event order and payload copies.
func (c *Conn) Writes() []Event {
	events := c.Events()
	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		if event.Kind == EventWrite {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func (c *Conn) appendEventLocked(event Event) {
	if len(c.events) >= MaxEvents {
		panic("testtransport: event trace exceeds MaxEvents")
	}
	c.events = append(c.events, event)
}
