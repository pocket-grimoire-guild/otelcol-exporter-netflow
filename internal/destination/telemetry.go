package destination

import (
	"context"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// Event is a closed, value-only telemetry vocabulary. No caller data, endpoint,
// template identity, or error text crosses the observation boundary.
type Event uint8

const (
	DataConfirmed Event = iota + 1
	DataAmbiguous
	BootstrapConfirmed
	BootstrapAmbiguous
	RefreshConfirmed
	RefreshAmbiguous
	DNSSucceeded
	DNSFailed
	EpochPublished
	CandidateFailed
	BootstrapFailed
	RefreshFailed
)

// Observer runs synchronously after the observed state transition, outside
// lifecycle/state locks. It must be concurrency-safe, prompt, and must not
// reenter Runtime or Packer (the sender may still own send). Bytes is the full
// intended UDP payload length for handoff events, including ambiguous writes;
// it is zero for other events. An observer must not retain the context.
type Observer func(ctx context.Context, event Event, bytes uint64)

func (o Observer) emit(ctx context.Context, event Event, bytes uint64) {
	if o != nil {
		o(ctx, event, bytes)
	}
}

func (o Observer) handoff(ctx context.Context, full, ambiguous Event, commit CommitResult) {
	switch commit.Class {
	case WriteFull:
		if commit.Committed {
			o.emit(ctx, full, commit.DatagramLength)
		}
	case WriteShortNil, WriteZeroNil, WriteShortError, WriteZeroError, WriteFullError:
		o.emit(ctx, ambiguous, commit.DatagramLength)
	}
}

func (r *Runtime) observeDNS(ctx context.Context, token transport.MaintenanceToken) {
	switch token.LookupOutcome() {
	case transport.LookupSucceeded:
		r.config.Observe.emit(ctx, DNSSucceeded, 0)
	case transport.LookupFailed:
		r.config.Observe.emit(ctx, DNSFailed, 0)
	}
}
