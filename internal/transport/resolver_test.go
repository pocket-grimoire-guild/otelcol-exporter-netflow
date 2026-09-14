package transport

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
)

func mustAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("parse address %q: %v", text, err)
	}
	return address
}

func tokenAnswerSet(address netip.Addr, token MaintenanceToken) AnswerSet {
	answers := makeAnswerSet(address, token.Generation())
	answers.origin = token.state
	return answers
}

type resolverBarrierClock struct {
	mu      sync.Mutex
	wall    uint64
	mono    uint64
	entered chan struct{}
	release <-chan struct{}
}

func (c *resolverBarrierClock) Now() (uint64, uint64) {
	c.mu.Lock()
	wall, mono := c.wall, c.mono
	entered, release := c.entered, c.release
	c.entered, c.release = nil, nil
	c.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	return wall, mono
}

func (c *resolverBarrierClock) BlockNext(entered chan struct{}, release <-chan struct{}) {
	c.mu.Lock()
	c.entered, c.release = entered, release
	c.mu.Unlock()
}

type lateSuccessLookup struct {
	started chan<- struct{}
	answers []netip.Addr
}

func (l *lateSuccessLookup) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	close(l.started)
	<-ctx.Done()
	return append([]netip.Addr(nil), l.answers...), nil
}

func TestResolverLiteralBypassesDNSAndChecksFamily(t *testing.T) {
	fake := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{mustAddr(t, "192.0.2.1")}})
	resolver, err := NewResolverWithLookup("udp4", "192.0.2.1", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	answers, err := resolver.Resolve(context.Background())
	_, selected := answers.Selected()
	if err != nil || answers.Count() != 1 || !selected {
		t.Fatalf("literal resolve = (%+v,%v)", answers, err)
	}
	if len(fake.Events()) != 0 {
		t.Fatal("numeric literal called DNS")
	}
	if _, err := NewResolverWithLookup("udp6", "192.0.2.1", time.Second, fake); !errors.Is(err, ErrResolverInvalidAnswer) {
		t.Fatalf("udp6 IPv4 literal error = %v, want family rejection", err)
	}
	if _, err := NewResolverWithLookup("udp", "fe80::1%eth0", time.Second, fake); !errors.Is(err, ErrResolverInvalidAnswer) {
		t.Fatalf("zoned literal error = %v, want ErrResolverInvalidAnswer", err)
	}
}

func TestResolverSortsDeduplicatesMapsAndFiltersFamilies(t *testing.T) {
	v4 := mustAddr(t, "192.0.2.2")
	mapped := mustAddr(t, "::ffff:192.0.2.1")
	v6 := mustAddr(t, "2001:db8::1")
	fake := testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{v6, v4, mapped, v4}},
		testtransport.ResolverStep{Answers: []netip.Addr{v6, v4, mapped}},
		testtransport.ResolverStep{Answers: []netip.Addr{v6, v4, mapped}},
	)
	resolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	answers, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if answers.Count() != 3 {
		t.Fatalf("answer count = %d, want 3", answers.Count())
	}
	want := []netip.Addr{mustAddr(t, "192.0.2.1"), v4, v6}
	for index, expected := range want {
		got, ok := answers.At(index)
		if !ok || got != expected {
			t.Fatalf("answer %d = (%v,%t), want %v", index, got, ok, expected)
		}
	}
	resolver, err = NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	answers, err = resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if answers.Count() != 2 || answers.Contains(v6) {
		t.Fatalf("udp4 filtered answers = %+v, want only IPv4", answers)
	}
	resolver, err = NewResolverWithLookup("udp6", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	answers, err = resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if answers.Count() != 1 || !answers.Contains(v6) {
		t.Fatalf("udp6 filtered answers = %+v, want only IPv6", answers)
	}
}

func TestResolverFakeCopiesBoundedScriptInputs(t *testing.T) {
	original := mustAddr(t, "192.0.2.30")
	replacement := mustAddr(t, "192.0.2.31")
	answers := []netip.Addr{original}
	fake := testtransport.NewResolver(testtransport.ResolverStep{Answers: answers})
	answers[0] = replacement
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	set, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := set.At(0); got != original {
		t.Fatalf("fake retained caller answer backing storage: %v", got)
	}
	for index := 0; index < testtransport.MaxResolverScript; index++ {
		if err := fake.AddStep(testtransport.ResolverStep{}); err != nil {
			t.Fatalf("bounded script add %d: %v", index, err)
		}
	}
	if err := fake.AddStep(testtransport.ResolverStep{}); !errors.Is(err, testtransport.ErrResolverScriptExhausted) {
		t.Fatalf("script overflow = %v", err)
	}
}

func TestResolverRejectsAnswerBoundsAndMalformedValues(t *testing.T) {
	addresses := make([]netip.Addr, 0, MaxResolverAnswers+1)
	for index := 0; index < MaxResolverAnswers+1; index++ {
		addresses = append(addresses, netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}))
	}
	fake := testtransport.NewResolver(testtransport.ResolverStep{Answers: addresses})
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background()); !errors.Is(err, ErrResolverTooManyAnswers) {
		t.Fatalf("9 unique answers error = %v", err)
	}
	tooManyRaw := make([]netip.Addr, MaxResolverRawAnswers+1)
	for index := range tooManyRaw {
		tooManyRaw[index] = netip.MustParseAddr("192.0.2.1")
	}
	fake = testtransport.NewResolver(testtransport.ResolverStep{Answers: tooManyRaw})
	resolver, err = NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background()); !errors.Is(err, ErrResolverTooManyRawAnswers) {
		t.Fatalf("65 raw answers error = %v", err)
	}
	for name, step := range map[string]testtransport.ResolverStep{
		"empty":   {},
		"invalid": {Answers: []netip.Addr{{}}},
		"zoned":   {Answers: []netip.Addr{mustAddr(t, "fe80::1%eth0")}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := testtransport.NewResolver(step)
			resolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, fake)
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.Resolve(context.Background())
			if name == "empty" && !errors.Is(err, ErrResolverNoAnswers) {
				t.Fatalf("empty error = %v", err)
			}
			if name != "empty" && !errors.Is(err, ErrResolverInvalidAnswer) {
				t.Fatalf("%s error = %v", name, err)
			}
		})
	}
}

func TestResolverTimeoutCancellationAndRedaction(t *testing.T) {
	started := make(chan struct{})
	wait := make(chan struct{})
	fake := testtransport.NewResolver(testtransport.ResolverStep{Wait: wait, Started: started})
	resolver, err := NewResolverWithLookup("udp", "collector.example", 100*time.Millisecond, fake)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(ctx)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrResolverCanceled) {
			t.Fatalf("canceled lookup error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled lookup did not return")
	}
	if events := fake.Events(); len(events) != 1 || !events[0].Canceled {
		t.Fatalf("cancel trace = %+v", events)
	}

	started = make(chan struct{})
	wait = make(chan struct{})
	fake = testtransport.NewResolver(testtransport.ResolverStep{Wait: wait, Started: started})
	resolver, err = NewResolverWithLookup("udp", "collector.example", 100*time.Millisecond, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background())
	if !errors.Is(err, ErrResolverTimeout) {
		t.Fatalf("timeout lookup error = %v", err)
	}

	canary := errors.New("sensitive.example.invalid:53")
	fake = testtransport.NewResolver(testtransport.ResolverStep{Err: canary})
	resolver, err = NewResolverWithLookup("udp", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background())
	if !errors.Is(err, ErrResolverLookup) || stringsContains(err.Error(), "sensitive.example.invalid") {
		t.Fatalf("redacted resolver error = %v", err)
	}
}

func TestResolverMaintenanceSingleflightTokensAndGeneration(t *testing.T) {
	maintenance := NewMaintenance()
	first, err := maintenance.Begin()
	if err != nil || first.Generation() != 1 {
		t.Fatalf("first begin = (%+v,%v)", first, err)
	}
	if _, err := maintenance.Begin(); !errors.Is(err, ErrResolverMaintenancePending) {
		t.Fatalf("second begin = %v, want pending", err)
	}
	copyToken := first
	pending, err := maintenance.End(first)
	if err != nil || !pending {
		t.Fatalf("end = (%t,%v), want pending", pending, err)
	}
	if _, err := maintenance.End(copyToken); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("copied consumed token = %v", err)
	}
	second, err := maintenance.Begin()
	if err != nil || second.Generation() != 2 {
		t.Fatalf("second generation = (%d,%v)", second.Generation(), err)
	}
	foreign := NewMaintenance()
	foreignToken, err := foreign.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(foreignToken); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("foreign token = %v", err)
	}
	if _, err := foreign.End(foreignToken); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(second); err != nil {
		t.Fatal(err)
	}
	maintenance.next = math.MaxUint64
	if _, err := maintenance.Begin(); !errors.Is(err, ErrResolverGenerationExhausted) {
		t.Fatalf("generation exhaustion = %v", err)
	}
}

func TestResolverRunAllowsOneLookup(t *testing.T) {
	fake := testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{mustAddr(t, "192.0.2.40")}},
		testtransport.ResolverStep{Answers: []netip.Addr{mustAddr(t, "192.0.2.41")}},
	)
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	maintenance := NewMaintenance()
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveFor(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveFor(context.Background(), token); !errors.Is(err, ErrResolverLookupAlreadyStarted) {
		t.Fatalf("second lookup = %v", err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
}

func TestResolverLateLookupSuccessHonorsCancellation(t *testing.T) {
	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
		"cancel": func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		},
		"deadline": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Millisecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			started := make(chan struct{})
			lookup := &lateSuccessLookup{
				started: started,
				answers: []netip.Addr{mustAddr(t, "192.0.2.50")},
			}
			resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, lookup)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := makeContext()
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := resolver.Resolve(ctx)
				done <- err
			}()
			<-started
			if name == "cancel" {
				cancel()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("context did not terminate")
			}
			select {
			case err := <-done:
				want := ErrResolverTimeout
				if name == "cancel" {
					want = ErrResolverCanceled
				}
				if err != want {
					t.Fatalf("late success error = %v, want exact %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("late lookup did not return")
			}
		})
	}
}

func TestResolverApplyCanonicalizesWrappedErrors(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{name: "cancel", in: ErrResolverCanceled, want: ErrResolverCanceled},
		{name: "timeout", in: ErrResolverTimeout, want: ErrResolverTimeout},
		{name: "empty", in: ErrResolverNoAnswers, want: ErrResolverNoAnswers},
		{name: "raw-bound", in: ErrResolverTooManyRawAnswers, want: ErrResolverTooManyRawAnswers},
		{name: "unique-bound", in: ErrResolverTooManyAnswers, want: ErrResolverTooManyAnswers},
		{name: "invalid", in: ErrResolverInvalidAnswer, want: ErrResolverInvalidAnswer},
		{name: "lookup", in: ErrResolverLookup, want: ErrResolverLookup},
		{name: "clock", in: ErrResolverClock, want: ErrResolverClock},
		{name: "unknown", in: errors.New("raw endpoint canary"), want: ErrResolverLookup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := testclock.New(0, 0)
			maintenance := NewMaintenance()
			state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			token, err := maintenance.Begin()
			if err != nil {
				t.Fatal(err)
			}
			wrapped := fmt.Errorf("sensitive.example.invalid: %w", tc.in)
			got := state.ApplyLookup(token, AnswerSet{}, wrapped)
			if got != tc.want || stringsContains(got.Error(), "sensitive.example.invalid") {
				t.Fatalf("canonical error = %v, want exact %v", got, tc.want)
			}
			if _, err := maintenance.End(token); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResolverRunResultIdentityAndSingleUse(t *testing.T) {
	clock := testclock.New(0, 0)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	firstAnswers := tokenAnswerSet(mustAddr(t, "192.0.2.60"), first)
	if err := state.ApplyLookup(first, firstAnswers, nil); err != nil {
		t.Fatal(err)
	}
	beforeDuplicate := state.Snapshot()
	if err := state.ApplyLookup(first, firstAnswers, nil); !errors.Is(err, ErrResolverLookupApplied) {
		t.Fatalf("duplicate apply = %v", err)
	}
	if after := state.Snapshot(); !reflect.DeepEqual(beforeDuplicate, after) {
		t.Fatalf("duplicate apply changed snapshot: before=%+v after=%+v", beforeDuplicate, after)
	}
	if err := state.CommitPublishedCandidate(first); err != nil {
		t.Fatal(err)
	}
	beforeCommit := state.Snapshot()
	if err := state.CommitPublishedCandidate(first); !errors.Is(err, ErrResolverCandidateCommitted) {
		t.Fatalf("duplicate commit = %v", err)
	}
	if after := state.Snapshot(); !reflect.DeepEqual(beforeCommit, after) {
		t.Fatalf("duplicate commit changed snapshot: before=%+v after=%+v", beforeCommit, after)
	}
	if _, err := maintenance.End(first); err != nil {
		t.Fatal(err)
	}

	foreignGate := NewMaintenance()
	foreign, err := foreignGate.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Generation() != first.Generation() {
		t.Fatalf("foreign generation = %d, want equal %d", foreign.Generation(), first.Generation())
	}
	foreignState, err := NewResolverState(clock, foreignGate, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreignState.ApplyLookup(foreign, firstAnswers, nil); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("equal-generation foreign result = %v", err)
	}
	if _, err := foreignGate.End(foreign); err != nil {
		t.Fatal(err)
	}
}

func TestResolverStateRejectsEndRacingApplyAndCommit(t *testing.T) {
	clock := &resolverBarrierClock{wall: 0, mono: 0}
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	answers := tokenAnswerSet(mustAddr(t, "192.0.2.70"), token)
	entered := make(chan struct{})
	release := make(chan struct{})
	clock.BlockNext(entered, release)
	applyDone := make(chan error, 1)
	go func() { applyDone <- state.ApplyLookup(token, answers, nil) }()
	<-entered
	if maintenance.mu.TryLock() {
		maintenance.mu.Unlock()
		close(release)
		if err := <-applyDone; err != nil {
			t.Fatalf("ownership probe cleanup apply = %v", err)
		}
		t.Fatal("maintenance mutex was available while ApplyLookup was paused")
	}
	endDone := make(chan error, 1)
	go func() {
		_, err := maintenance.End(token)
		endDone <- err
	}()
	close(release)
	if err := <-applyDone; err != nil {
		t.Fatalf("transition-first apply = %v", err)
	}
	if err := <-endDone; err != nil {
		t.Fatalf("transition-first end = %v", err)
	}

	endFirst, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(endFirst); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyLookup(endFirst, tokenAnswerSet(mustAddr(t, "192.0.2.71"), endFirst), nil); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("end-first apply = %v", err)
	}

	commitToken, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	commitAnswers := tokenAnswerSet(mustAddr(t, "192.0.2.72"), commitToken)
	if err := state.ApplyLookup(commitToken, commitAnswers, nil); err != nil {
		t.Fatal(err)
	}
	entered = make(chan struct{})
	release = make(chan struct{})
	clock.BlockNext(entered, release)
	commitDone := make(chan error, 1)
	go func() { commitDone <- state.CommitPublishedCandidate(commitToken) }()
	<-entered
	if maintenance.mu.TryLock() {
		maintenance.mu.Unlock()
		close(release)
		if err := <-commitDone; err != nil {
			t.Fatalf("ownership probe cleanup commit = %v", err)
		}
		t.Fatal("maintenance mutex was available while CommitPublishedCandidate was paused")
	}
	endDone = make(chan error, 1)
	go func() { _, err := maintenance.End(commitToken); endDone <- err }()
	close(release)
	if err := <-commitDone; err != nil {
		t.Fatalf("transition-first commit = %v", err)
	}
	if err := <-endDone; err != nil {
		t.Fatalf("transition-first commit end = %v", err)
	}
	if err := state.CommitPublishedCandidate(commitToken); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("end-first commit = %v", err)
	}
}

func TestResolverEndWaitsForLookupJoinBeforeNextRun(t *testing.T) {
	started := make(chan struct{})
	wait := make(chan struct{})
	fake := testtransport.NewResolver(testtransport.ResolverStep{Wait: wait, Started: started})
	resolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	maintenance := NewMaintenance()
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	lookupContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	lookupDone := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveFor(lookupContext, token)
		lookupDone <- err
	}()
	<-started
	if _, err := maintenance.End(token); !errors.Is(err, ErrResolverLookupInFlight) {
		t.Fatalf("end during lookup = %v", err)
	}
	if _, err := maintenance.Begin(); !errors.Is(err, ErrResolverMaintenancePending) {
		t.Fatalf("begin during lookup = %v", err)
	}
	cancel()
	// The owner cancels and joins the blocked lookup before the final End.
	if err := <-lookupDone; !errors.Is(err, ErrResolverCanceled) {
		t.Fatalf("joined lookup = %v", err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	next, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(next); err != nil {
		t.Fatal(err)
	}
}

func TestResolverStateRequiresPublishedCandidateAndRetainsStaleOrigin(t *testing.T) {
	clock := testclock.New(100, uint64(10*time.Second))
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fake := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{mustAddr(t, "192.0.2.10")}})
	resolver, err := NewResolverWithLookup("udp4", "collector.example", time.Second, fake)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	answers, err := resolver.ResolveFor(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyLookup(token, answers, nil); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	if snapshot.Available || snapshot.Current.IsValid() || snapshot.Selected != mustAddr(t, "192.0.2.10") || snapshot.Generation != 1 {
		t.Fatalf("pre-publication snapshot = %+v", snapshot)
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	snapshot = state.Snapshot()
	if !snapshot.Available || snapshot.Current != mustAddr(t, "192.0.2.10") {
		t.Fatalf("published snapshot = %+v", snapshot)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	// A successful answer excluding current starts staleness but leaves the
	// old endpoint usable until the monotonic stale-after boundary.
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	other := tokenAnswerSet(mustAddr(t, "192.0.2.11"), token)
	if err := state.ApplyLookup(token, other, nil); err != nil {
		t.Fatal(err)
	}
	stale := state.Snapshot()
	if !stale.Stale || !stale.Available || stale.StaleSince != uint64(10*time.Second) || stale.Selected != mustAddr(t, "192.0.2.11") {
		t.Fatalf("stale-start snapshot = %+v", stale)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	clock.SetWall(1)
	clock.SetMonotonic(uint64(12 * time.Second))
	if !state.Snapshot().Available {
		t.Fatal("wall-clock step changed availability")
	}
	// A successful answer that still contains current clears staleness before
	// the retention boundary, without needing candidate publication.
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	currentAnswer := tokenAnswerSet(mustAddr(t, "192.0.2.10"), token)
	if err := state.ApplyLookup(token, currentAnswer, nil); err != nil {
		t.Fatal(err)
	}
	cleared := state.Snapshot()
	if cleared.Stale || !cleared.Available {
		t.Fatalf("current-containing answer did not clear stale state: %+v", cleared)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	// A repeated failure does not move the stale origin.
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyLookup(token, AnswerSet{}, ErrResolverLookup); !errors.Is(err, ErrResolverLookup) {
		t.Fatalf("lookup failure = %v", err)
	}
	if got := state.Snapshot().StaleSince; got != uint64(12*time.Second) {
		t.Fatalf("repeated failure stale origin = %d, want %d", got, uint64(12*time.Second))
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	clock.SetMonotonic(uint64(15 * time.Second))
	if !state.Snapshot().StaleExpired || state.Snapshot().Available {
		t.Fatalf("expired snapshot = %+v", state.Snapshot())
	}

	// Even the same current address cannot recover after expiry until the
	// lifecycle's explicit publication commit transition.
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	recovery := tokenAnswerSet(mustAddr(t, "192.0.2.10"), token)
	if err := state.ApplyLookup(token, recovery, nil); err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().Available {
		t.Fatal("lookup alone restored expired availability")
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	if !state.Snapshot().Available {
		t.Fatal("published recovery remained unavailable")
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyLookup(token, recovery, nil); !errors.Is(err, ErrResolverMaintenanceToken) {
		t.Fatalf("stale token apply = %v", err)
	}
}

func TestResolverStateClockFaultHighWaterAndOverflowFailClosed(t *testing.T) {
	clock := testclock.New(0, 100)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	answers := tokenAnswerSet(mustAddr(t, "192.0.2.20"), token)
	if err := state.ApplyLookup(token, answers, nil); err != nil {
		t.Fatal(err)
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	clock.SetMonotonic(99)
	fault := state.Snapshot()
	if fault.Available || !fault.TimeFault || fault.StaleSince != 0 {
		t.Fatalf("backward snapshot = %+v", fault)
	}
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	answers = tokenAnswerSet(mustAddr(t, "192.0.2.20"), token)
	if err := state.ApplyLookup(token, answers, nil); !errors.Is(err, ErrResolverClock) {
		t.Fatalf("backward apply = %v", err)
	}
	if err := state.CommitPublishedCandidate(token); !errors.Is(err, ErrResolverClock) {
		t.Fatalf("backward commit = %v", err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
	clock.SetMonotonic(100)
	resumed := state.Snapshot()
	if resumed.TimeFault || !resumed.Available {
		t.Fatalf("high-water recovery = %+v", resumed)
	}

	overflowClock := testclock.New(0, math.MaxUint64-1)
	overflowMaintenance := NewMaintenance()
	overflowState, err := NewResolverState(overflowClock, overflowMaintenance, time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Advance wraps the test source; State detects the backwards sample and
	// does not reset its high-water value.
	if _, err := overflowMaintenance.Begin(); err != nil {
		t.Fatal(err)
	}
	first := overflowState.Snapshot()
	if first.TimeFault {
		t.Fatal("initial high-water sample unexpectedly faulted")
	}
	overflowClock.Advance(0, 2)
	second := overflowState.Snapshot()
	if !second.TimeFault || !second.Due {
		t.Fatalf("wrapped monotonic snapshot = %+v", second)
	}
}

func TestResolverStateClockRecoveryKeepsStaleWindowAndExpiryLatch(t *testing.T) {
	clock := testclock.New(0, uint64(10*time.Second))
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	current := tokenAnswerSet(mustAddr(t, "192.0.2.80"), token)
	if err := state.ApplyLookup(token, current, nil); err != nil {
		t.Fatal(err)
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	// Exclusion starts finite staleness at the high-water sample.
	clock.SetMonotonic(uint64(10 * time.Second))
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ApplyLookup(token, tokenAnswerSet(mustAddr(t, "192.0.2.81"), token), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}

	clock.SetMonotonic(uint64(9 * time.Second))
	fault := state.Snapshot()
	if fault.Available || !fault.TimeFault || fault.StaleSince != uint64(10*time.Second) {
		t.Fatalf("backward stale snapshot = %+v", fault)
	}
	clock.SetMonotonic(uint64(11 * time.Second))
	resumed := state.Snapshot()
	if !resumed.Available || resumed.TimeFault || !resumed.Stale || resumed.StaleExpired {
		t.Fatalf("unexpired recovery snapshot = %+v", resumed)
	}
	clock.SetMonotonic(uint64(13 * time.Second))
	expired := state.Snapshot()
	if expired.Available || !expired.StaleExpired {
		t.Fatalf("expiry snapshot = %+v", expired)
	}

	// A repeated address at/after expiry remains unavailable until the explicit
	// publication commit, even though the clock itself is valid again.
	token, err = maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	recovery := tokenAnswerSet(mustAddr(t, "192.0.2.80"), token)
	if err := state.ApplyLookup(token, recovery, nil); err != nil {
		t.Fatal(err)
	}
	if state.Snapshot().Available {
		t.Fatal("post-expiry lookup restored availability")
	}
	if err := state.CommitPublishedCandidate(token); err != nil {
		t.Fatal(err)
	}
	if !state.Snapshot().Available {
		t.Fatal("publication commit did not restore availability")
	}
	if _, err := maintenance.End(token); err != nil {
		t.Fatal(err)
	}
}

func TestResolverStateSnapshotsConcurrentWithMaintenanceTriggers(t *testing.T) {
	clock := testclock.New(0, 0)
	maintenance := NewMaintenance()
	state, err := NewResolverState(clock, maintenance, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, err := maintenance.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for index := 0; index < 8; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for count := 0; count < 100; count++ {
				_ = state.Snapshot()
				_, _ = maintenance.Begin()
			}
		}()
	}
	wg.Wait()
	pending, err := maintenance.End(first)
	if err != nil || !pending {
		t.Fatalf("concurrent trigger end = (%t,%v)", pending, err)
	}
}

func stringsContains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
