package netflowexporter

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// millisecondClock presents the wall clock at the resolution of v5/v9 uptime,
// relative to the configured origin (or Unix epoch for v9's startup sample).
// This controls only header send-time resolution, never source timestamps.
// Invalid/future-origin/exhausted samples pass through to the existing state
// checks; monotonic DNS/refresh scheduling keeps its full resolution.
type millisecondClock struct {
	clock       transport.Clock
	origin      uint64
	checkUptime bool
}

func (c millisecondClock) Now() (uint64, uint64) {
	wall, mono := c.clock.Now()
	if wall > math.MaxInt64 || wall/1_000_000_000 > math.MaxUint32 || wall < c.origin || (c.checkUptime && (wall-c.origin)/1_000_000 > math.MaxUint32) {
		return wall, mono
	}
	return wall - (wall-c.origin)%1_000_000, mono
}
