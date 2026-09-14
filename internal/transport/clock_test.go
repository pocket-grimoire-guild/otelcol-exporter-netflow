package transport

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
)

func TestClockSystemSeparatesWallAndMonotonic(t *testing.T) {
	clock := NewClock()
	wall1, mono1 := clock.Now()
	wall2, mono2 := clock.Now()
	if wall1 == 0 || wall2 == 0 {
		t.Fatalf("system wall clock returned zero: %d, %d", wall1, wall2)
	}
	if mono2 < mono1 {
		t.Fatalf("monotonic clock moved backwards: %d -> %d", mono1, mono2)
	}
}

func TestClockWallRepresentabilityFailsClosed(t *testing.T) {
	if invalidClockValue <= uint64(math.MaxInt64) {
		t.Fatalf("invalid sentinel = %d, want above State's MaxInt64 gate", uint64(invalidClockValue))
	}
	maxSeconds := int64(math.MaxInt64 / int64(time.Second))
	maxNanos := int64(math.MaxInt64 % int64(time.Second))
	cases := []struct {
		name string
		when time.Time
		ok   bool
	}{
		{name: "before epoch", when: time.Unix(-1, 0), ok: false},
		{name: "representable upper bound", when: time.Unix(maxSeconds, maxNanos), ok: true},
		{name: "one nanosecond beyond bound", when: time.Unix(maxSeconds, maxNanos+1), ok: false},
		{name: "far future", when: time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC), ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := checkedWallUnixNanos(tc.when)
			if ok != tc.ok {
				t.Fatalf("checked wall = (%d,%t), want valid=%t", got, ok, tc.ok)
			}
			if !tc.ok && got != invalidClockValue {
				t.Fatalf("invalid wall = %d, want invalid sentinel %d", got, uint64(invalidClockValue))
			}
		})
	}
	var nilClock *systemClock
	wall, mono := nilClock.Now()
	if wall != invalidClockValue || mono != invalidClockValue {
		t.Fatalf("nil clock = (%d,%d), want invalid sentinels", wall, mono)
	}
	backward := &systemClock{origin: time.Now().Add(time.Hour)}
	wall, mono = backward.Now()
	if wall != invalidClockValue || mono != invalidClockValue {
		t.Fatalf("backward elapsed sample = (%d,%d), want invalid sentinels", wall, mono)
	}
}

func TestClockDeterministicSteps(t *testing.T) {
	zero := testclock.New(0, 0)
	if wall, mono := zero.Now(); wall != 0 || mono != 0 {
		t.Fatalf("zero deterministic sample = (%d,%d), want (0,0)", wall, mono)
	}
	clock := testclock.New(100, 20)
	wall, mono := clock.Now()
	if wall != 100 || mono != 20 {
		t.Fatalf("initial clock = (%d,%d), want (100,20)", wall, mono)
	}
	clock.SetWall(90)
	clock.SetMonotonic(30)
	wall, mono = clock.Now()
	if wall != 90 || mono != 30 {
		t.Fatalf("independent step = (%d,%d), want (90,30)", wall, mono)
	}
	clock.Advance(10, 0)
	wall, mono = clock.Now()
	if wall != 100 || mono != 30 {
		t.Fatalf("wall-only advance = (%d,%d), want (100,30)", wall, mono)
	}
	clock.Set(^uint64(0), 40)
	wall, mono = clock.Now()
	if wall != ^uint64(0) || mono != 40 {
		t.Fatalf("out-of-range wall was changed: (%d,%d)", wall, mono)
	}
	var nilFake *testclock.Clock
	wall, mono = nilFake.Now()
	if wall != ^uint64(0) || mono != ^uint64(0) {
		t.Fatalf("nil fake = (%d,%d), want invalid sentinels", wall, mono)
	}
}

func TestClockDeterministicConcurrentReadsAndWrites(t *testing.T) {
	clock := testclock.New(1, 2)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				clock.SetWall(uint64(i*200 + j))
				clock.SetMonotonic(uint64(j))
				_, _ = clock.Now()
			}
		}(i)
	}
	wg.Wait()
}
