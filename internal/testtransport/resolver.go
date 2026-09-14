// Package testtransport provides bounded scripted transport seams for
// deterministic destination tests.  It is never used by production code.
package testtransport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

const (
	MaxResolverScript = 256
	MaxResolverTrace  = 512
	MaxResolverRaw    = 128
)

var (
	ErrResolverScriptExhausted = errors.New("testtransport: resolver script capacity exhausted")
	ErrResolverTraceExhausted  = errors.New("testtransport: resolver trace capacity exhausted")
)

// ResolverStep is one bounded LookupNetIP outcome.  Wait and Started are
// test-owned synchronization channels; the fake never creates a goroutine or
// timer to control them.
type ResolverStep struct {
	Answers []netip.Addr
	Err     error
	Wait    <-chan struct{}
	Started chan<- struct{}
}

// ResolverEvent is a bounded, redacted trace entry.  It deliberately omits
// hostname and raw errors so a test cannot accidentally retain endpoint text.
type ResolverEvent struct {
	Network     string
	AnswerCount int
	HadError    bool
	Canceled    bool
	TimedOut    bool
}

type Resolver struct {
	mu     sync.Mutex
	steps  []ResolverStep
	events []ResolverEvent
}

func NewResolver(steps ...ResolverStep) *Resolver {
	if len(steps) > MaxResolverScript {
		panic("testtransport: resolver script exceeds MaxResolverScript")
	}
	resolver := &Resolver{steps: make([]ResolverStep, 0, MaxResolverScript), events: make([]ResolverEvent, 0, MaxResolverTrace)}
	for _, step := range steps {
		if len(step.Answers) > MaxResolverRaw {
			panic("testtransport: resolver step exceeds MaxResolverRaw")
		}
		step.Answers = append([]netip.Addr(nil), step.Answers...)
		resolver.steps = append(resolver.steps, step)
	}
	return resolver
}

func (r *Resolver) AddStep(step ResolverStep) error {
	if r == nil || len(step.Answers) > MaxResolverRaw {
		return ErrResolverScriptExhausted
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.steps) >= MaxResolverScript {
		return ErrResolverScriptExhausted
	}
	step.Answers = append([]netip.Addr(nil), step.Answers...)
	r.steps = append(r.steps, step)
	return nil
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, _ string) ([]netip.Addr, error) {
	if r == nil || ctx == nil {
		return nil, net.ErrClosed
	}
	r.mu.Lock()
	if len(r.steps) == 0 {
		r.mu.Unlock()
		return nil, ErrResolverScriptExhausted
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	r.mu.Unlock()
	if step.Started != nil {
		close(step.Started)
	}
	if step.Wait != nil {
		select {
		case <-step.Wait:
		case <-ctx.Done():
			err := ctx.Err()
			if !r.record(network, 0, err) {
				return nil, ErrResolverTraceExhausted
			}
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		if !r.record(network, 0, err) {
			return nil, ErrResolverTraceExhausted
		}
		return nil, err
	}
	answers := append([]netip.Addr(nil), step.Answers...)
	if !r.record(network, len(answers), step.Err) {
		return nil, ErrResolverTraceExhausted
	}
	return answers, step.Err
}

func (r *Resolver) record(network string, answerCount int, err error) bool {
	if r == nil {
		return false
	}
	switch network {
	case "ip", "ip4", "ip6":
	default:
		network = ""
	}
	event := ResolverEvent{Network: network, AnswerCount: answerCount, HadError: err != nil}
	if errors.Is(err, context.Canceled) {
		event.Canceled = true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		event.TimedOut = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) >= MaxResolverTrace {
		return false
	}
	r.events = append(r.events, event)
	return true
}

func (r *Resolver) Events() []ResolverEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ResolverEvent(nil), r.events...)
}
