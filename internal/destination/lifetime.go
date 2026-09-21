package destination

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// LifetimeSnapshot is a value-only observation of the published NetFlow
// uptime window. Applicable is false for an inactive, closing, or IPFIX
// runtime. When Applicable is true, RemainingKnown says whether
// RemainingSeconds is usable; known zero can precede the State latch.
// Exhausted reports only that existing State latch. The result deliberately
// carries no state, endpoint, origin, or epoch handle, so taking a snapshot
// cannot retain or mutate a destination.
type LifetimeSnapshot struct {
	Applicable       bool
	RemainingKnown   bool
	RemainingSeconds float64
	Exhausted        bool
}

const lifetimeLimitMilliseconds = uint64(math.MaxUint32) + 1

// Lifetime returns a coherent scalar snapshot of the currently published
// v5/v9 epoch.  The clock sample is taken before either destination lock, then
// lifecycle and State fields are copied under their established lock order.
// Projection is performed after both locks have been released.
func (r *Runtime) Lifetime() LifetimeSnapshot {
	if r == nil || r.clock == nil {
		return LifetimeSnapshot{}
	}

	// Keep this sample before the lifecycle/State copy.  A concurrent rewind
	// can otherwise be paired with a reservation floor copied from an earlier
	// instant and falsely report extra remaining time.
	wall, _ := r.clock.Now()

	r.lifecycle.Lock()
	if r.closing || r.published == nil {
		r.lifecycle.Unlock()
		return LifetimeSnapshot{}
	}
	state := r.published.state
	if state == nil {
		r.lifecycle.Unlock()
		return LifetimeSnapshot{}
	}

	// State owns all of these fields.  Copy them as one observation point while
	// lifecycle remains held, preserving lifecycle -> State lock order.
	state.mu.Lock()
	protocol := state.config.Protocol
	configuredOrigin, hasConfiguredOrigin := state.config.UptimeOriginUnixNanos, state.config.HasUptimeOrigin
	origin, hasOrigin := state.epoch.startOrigin, state.epoch.hasStartOrigin
	latched := state.epoch.uptimeExhausted
	reservedWall, haveReservedWall := state.lastReservedWall, state.haveReservedWall
	state.mu.Unlock()
	r.lifecycle.Unlock()

	if protocol != wire.ProtocolV5 && protocol != wire.ProtocolV9 {
		return LifetimeSnapshot{}
	}

	result := LifetimeSnapshot{Applicable: true, Exhausted: latched}
	if latched {
		result.RemainingKnown = true
		return result
	}
	if hasConfiguredOrigin {
		origin, hasOrigin = configuredOrigin, true
	}
	if !hasOrigin {
		return result
	}

	// Match State.reserveWallLocked's signed-safe order.  In particular, do
	// not clamp an invalid raw sample to an older reservation floor.
	if wall > math.MaxInt64 {
		return result
	}
	if haveReservedWall && wall < reservedWall {
		wall = reservedWall
	}
	if wall/1_000_000_000 > math.MaxUint32 || wall < origin {
		return result
	}
	delta := wall - origin
	elapsed := delta / 1_000_000
	// Preserve State's overflow-before-alignment branch order.  A fractional
	// sample at or beyond the first exhausted millisecond is still known zero.
	if elapsed >= lifetimeLimitMilliseconds {
		result.RemainingKnown = true
		return result
	}
	if delta%1_000_000 != 0 {
		return result
	}
	result.RemainingKnown = true
	result.RemainingSeconds = float64(lifetimeLimitMilliseconds-elapsed) / 1000
	return result
}
