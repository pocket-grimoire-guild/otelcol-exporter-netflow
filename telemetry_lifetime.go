package netflowexporter

import (
	"context"
	"errors"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"go.opentelemetry.io/otel/metric"
)

var errLifetimeTelemetryInit = errors.New("netflow: telemetry initialization failed")

// registerLifetime installs one callback for the two lifetime gauges. The
// callback takes exactly one immutable runtime snapshot per collection so the
// pair cannot describe different epochs or clock samples.
func (t *telemetry) registerLifetime(meter metric.Meter, runtime *destination.Runtime) (metric.Registration, error) {
	if t == nil || t.builder == nil || meter == nil || runtime == nil {
		return nil, errLifetimeTelemetryInit
	}
	return meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		snapshot := runtime.Lifetime()
		if !snapshot.Applicable {
			return nil
		}
		attrs := metric.WithAttributes(t.instance)
		if snapshot.RemainingKnown {
			observer.ObserveFloat64(t.builder.NetflowExporterUptimeRemaining, snapshot.RemainingSeconds, attrs)
		}
		exhausted := int64(0)
		if snapshot.Exhausted {
			exhausted = 1
		}
		observer.ObserveInt64(t.builder.NetflowExporterUptimeExhausted, exhausted, attrs)
		return nil
	}, t.builder.NetflowExporterUptimeRemaining, t.builder.NetflowExporterUptimeExhausted)
}
