package netflowexporter

import (
	"context"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// At most 33 local series per instance: the original eight result/loss series,
// five admission reasons, six byte series, four template series, two DNS results,
// one publication counter and seven failure reasons. The union has ten fixed
// reasons. Instance IDs come only from trusted Collector configuration.
type telemetry struct {
	builder  *metadata.TelemetryBuilder
	instance attribute.KeyValue
}

func (t telemetry) record(ctx context.Context, r *destination.PackResult) {
	if t.builder == nil || r == nil {
		return
	}
	counts := r.Counts()
	for _, entry := range []struct {
		outcome string
		value   uint64
	}{
		{"confirmed", counts.Confirmed}, {"invalid", counts.Invalid}, {"ambiguous", counts.Ambiguous}, {"unsent", counts.Unsent},
	} {
		if entry.value > 0 {
			t.builder.NetflowExporterRecords.Add(ctx, int64(entry.value), metric.WithAttributes(t.instance, attribute.String("outcome", entry.outcome)))
		}
	}
	for _, entry := range []struct {
		outcome string
		value   uint64
	}{{"confirmed", r.ConfirmedPackets()}, {"ambiguous", r.AmbiguousPackets()}} {
		if entry.value > 0 {
			t.builder.NetflowExporterDataMessages.Add(ctx, int64(entry.value), metric.WithAttributes(t.instance, attribute.String("outcome", entry.outcome)))
		}
	}
	for _, entry := range []struct {
		class string
		value uint64
	}{{"exporter", r.ExporterLosses()}, {"canonical_source", r.CanonicalSourceLoss()}} {
		if entry.value > 0 {
			t.builder.NetflowExporterLosses.Add(ctx, int64(entry.value), metric.WithAttributes(t.instance, attribute.String("loss_class", entry.class)))
		}
	}
}

// admission counts one whole request before helper entry. Accepted means the
// sole request slot and preflight succeeded; it does not promise a packet write.
func (t telemetry) admission(ctx context.Context, reason string) {
	if t.builder == nil {
		return
	}
	switch reason {
	case "accepted", "busy", "closed", "preflight", "invalid_context":
		t.builder.NetflowExporterAdmission.Add(ctx, 1, metric.WithAttributes(t.instance, attribute.String("reason", reason)))
	}
}

func (t telemetry) failure(ctx context.Context, reason string) {
	if t.builder == nil {
		return
	}
	switch reason {
	case "busy", "closed", "unavailable", "internal", "candidate", "bootstrap", "refresh":
		t.builder.NetflowExporterFailures.Add(ctx, 1, metric.WithAttributes(t.instance, attribute.String("reason", reason)))
	}
}

func (t telemetry) observe(ctx context.Context, event destination.Event, bytes uint64) {
	if t.builder == nil {
		return
	}
	kind, outcome := "", "confirmed"
	switch event {
	case destination.DataConfirmed, destination.DataAmbiguous:
		kind = "data"
	case destination.BootstrapConfirmed, destination.BootstrapAmbiguous:
		kind = "bootstrap"
	case destination.RefreshConfirmed, destination.RefreshAmbiguous:
		kind = "refresh"
	case destination.DNSSucceeded, destination.DNSFailed:
		outcome = "succeeded"
		if event == destination.DNSFailed {
			outcome = "failed"
		}
		t.builder.NetflowExporterDNS.Add(ctx, 1, metric.WithAttributes(t.instance, attribute.String("outcome", outcome)))
		return
	case destination.EpochPublished:
		t.builder.NetflowExporterEndpointEpochs.Add(ctx, 1, metric.WithAttributes(t.instance))
		return
	case destination.CandidateFailed:
		t.failure(ctx, "candidate")
		return
	case destination.BootstrapFailed:
		t.failure(ctx, "bootstrap")
		return
	case destination.RefreshFailed:
		t.failure(ctx, "refresh")
		return
	default:
		return
	}
	// Check the scalar even though production CommitResult already guarantees
	// the UDP bound. Unknown events/values cannot create a new series or overflow.
	if bytes == 0 || bytes > 65507 {
		return
	}
	if event == destination.DataAmbiguous || event == destination.BootstrapAmbiguous || event == destination.RefreshAmbiguous {
		outcome = "ambiguous"
	}
	attrs := metric.WithAttributes(t.instance, attribute.String("message_kind", kind), attribute.String("outcome", outcome))
	t.builder.NetflowExporterBytes.Add(ctx, int64(bytes), attrs)
	if kind != "data" {
		t.builder.NetflowExporterTemplates.Add(ctx, 1, attrs)
	}
}
