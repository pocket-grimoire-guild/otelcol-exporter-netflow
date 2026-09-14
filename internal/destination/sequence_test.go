package destination

import (
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestSequenceProtocolChargesAndWrap(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			state, _ := stateFor(t, protocol, func(config *Config) {
				config.MaxDatagramSize = 65507
				config.MaxRecordsPerMessage = 30
			})
			if protocol != wire.ProtocolV5 {
				bootstrap(t, state, 3_000_000_000, 1)
			}
			shape, _ := state.Catalog().ShapeAt(0)
			record := testRecord(t, shape, 3_000_000_000)
			state.mu.Lock()
			state.epoch.sequence = math.MaxUint32
			state.mu.Unlock()
			request := DataRequest{Records: []wire.WireRecord{record, record}}
			if protocol == wire.ProtocolV5 {
				request.V5SamplingRates = []uint32{0, 0}
			}
			packet, err := state.BeginData(3_000_000_000, 2, 0, request)
			if err != nil {
				t.Fatal(err)
			}
			if packet.Sequence() != math.MaxUint32 {
				t.Fatalf("header sequence=%d", packet.Sequence())
			}
			result := commitFull(t, state, packet)
			want := uint32(0)
			if protocol == wire.ProtocolV5 || protocol == wire.ProtocolIPFIX {
				want = 1
			}
			if result.SequenceAfter != want {
				t.Fatalf("sequence after=%d want %d result=%+v", result.SequenceAfter, want, result)
			}
		})
	}
}

func TestSequenceV9CountsTemplatePackets(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) {
		config.InitialCopies = 2
		config.MaxDatagramSize = 65507
	})
	bootstrap(t, state, 3_000_000_000, 1)
	// Two family shapes and two copies make four successful Export Packets.
	if got := state.Sequence(); got != 4 {
		t.Fatalf("bootstrap sequence=%d want 4", got)
	}
	shape, _ := state.Catalog().ShapeAt(0)
	record := testRecord(t, shape, 3_000_000_000)
	packet, err := state.BeginData(3_001_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	if packet.Sequence() != 4 {
		t.Fatalf("data sequence=%d want 4", packet.Sequence())
	}
	commitFull(t, state, packet)
	if got := state.Sequence(); got != 5 {
		t.Fatalf("data sequence after=%d want 5", got)
	}
}
