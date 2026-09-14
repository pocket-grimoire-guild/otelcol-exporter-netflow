package destination

import "github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"

// EpochSnapshot is a read-only description of the destination-local protocol
// epoch.  A restart creates a new number; no sequence or template progress is
// carried across that boundary.
type EpochSnapshot struct {
	ID              uint64
	Protocol        wire.Protocol
	Sequence        uint32
	Ready           bool
	UptimeExhausted bool
	StartOrigin     uint64
	HasStartOrigin  bool
}

type epochState struct {
	id       uint64
	protocol wire.Protocol

	sequence uint32
	ready    bool

	// startOrigin is used only by a v9 candidate without a configured uptime
	// origin.  It is assigned immediately before the first bootstrap write and
	// becomes durable only when bootstrap completes.
	startOrigin    uint64
	hasStartOrigin bool

	uptimeExhausted bool
}

func newEpoch(id uint64, protocol wire.Protocol) *epochState {
	return &epochState{id: id, protocol: protocol, ready: protocol == wire.ProtocolV5}
}

func (e *epochState) snapshot() EpochSnapshot {
	return EpochSnapshot{
		ID:              e.id,
		Protocol:        e.protocol,
		Sequence:        e.sequence,
		Ready:           e.ready,
		UptimeExhausted: e.uptimeExhausted,
		StartOrigin:     e.startOrigin,
		HasStartOrigin:  e.hasStartOrigin,
	}
}
