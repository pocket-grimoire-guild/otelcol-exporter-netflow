package normalize

import (
	"math"

	"go.opentelemetry.io/collector/pdata/plog"
)

// PreflightStats contains the only useful whole-request observation: the
// number of source records. Packet and mapping bounds are enforced where the
// corresponding wire object is built.
type PreflightStats struct {
	Records uint64
}

// Preflight performs only the small structural check needed to distinguish a
// zero or malformed pdata root from a request containing records. It does not
// inspect arbitrary metadata, copy values, or reject a request by aggregate
// count/byte/depth/map/key/scalar measurements.
func Preflight(logs plog.Logs) error {
	_, err := Inspect(logs)
	return err
}

// Inspect returns a value-only record count. The old recursive metadata walk
// was an admission policy and made irrelevant attributes capable of rejecting
// valid wire records; callers must not use this snapshot as a bounds oracle.
func Inspect(logs plog.Logs) (stats PreflightStats, err error) {
	defer func() {
		if recover() != nil {
			stats = PreflightStats{}
			err = ErrMalformed
		}
	}()
	resources := logs.ResourceLogs()
	for resourceIndex := 0; resourceIndex < resources.Len(); resourceIndex++ {
		scopes := resources.At(resourceIndex).ScopeLogs()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			count := uint64(scopes.At(scopeIndex).LogRecords().Len())
			if count > math.MaxUint64-stats.Records {
				return PreflightStats{}, ErrMalformed
			}
			stats.Records += count
		}
	}
	return stats, nil
}
