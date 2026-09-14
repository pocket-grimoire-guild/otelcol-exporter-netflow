package destination

import (
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestTemplateCopiesBoundsAndCompleteBootstrap(t *testing.T) {
	for _, copies := range []uint8{1, 9} {
		_, err := NewState(compiledMapping(t, wire.ProtocolV9), &recordingWriter{}, Config{Protocol: wire.ProtocolV9, InitialCopies: copies})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("initial copies %d err=%v", copies, err)
		}
	}
	for _, copies := range []uint8{2, 8} {
		state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.InitialCopies = copies; config.MaxDatagramSize = 65507 })
		bootstrap(t, state, 3_000_000_000, 1)
		if !state.Ready() || state.Epoch().Sequence != uint32(int(copies)*2) {
			t.Fatalf("copies=%d ready=%v epoch=%+v", copies, state.Ready(), state.Epoch())
		}
		if got := state.Catalog().IDs(); len(got) != 2 || got[0] != 256 || got[1] != 257 {
			t.Fatalf("compiler IDs=%v", got)
		}
	}
}

func TestTemplateProgressOrderFailureAndNoOptions(t *testing.T) {
	state, writer := stateFor(t, wire.ProtocolV9, func(config *Config) {
		config.MaxDatagramSize = 65507
	})
	if _, err := state.BeginTemplate(3_000_000_000, 1, 1); !errors.Is(err, ErrTemplateProgress) {
		t.Fatalf("out-of-order template err=%v", err)
	}
	first, err := state.BeginTemplate(3_000_000_000, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.request.TemplateRecords != 1 || first.request.TemplateBytes != first.request.Shape.TemplateBytes() || first.request.Records != nil {
		t.Fatalf("template request=%+v", first.request)
	}
	if first.request.Header.Count != 1 {
		t.Fatalf("v9 template count=%d", first.request.Header.Count)
	}
	n, err := encodePacket(t, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Commit(first, n-1, nil); err != nil {
		t.Fatal(err)
	}
	if state.Epoch().HasStartOrigin {
		t.Fatalf("failed candidate retained start origin: %+v", state.Epoch())
	}
	if _, err := state.BeginTemplate(3_000_000_000, 2, 0); err != nil {
		t.Fatalf("retry first template: %v", err)
	}
	if len(writer.requests) != 1 {
		t.Fatalf("explicit encode invocation count=%d", len(writer.requests))
	}
}

func TestTemplateIPFIXChargesZeroDataRecords(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolIPFIX, func(config *Config) { config.MaxDatagramSize = 65507 })
	packet, err := state.BeginTemplate(3_000_000_000, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if packet.request.Header.Count != 0 || packet.DataRecords() != 0 {
		t.Fatalf("ipfix template header/data count=%d/%d", packet.request.Header.Count, packet.DataRecords())
	}
	commitFull(t, state, packet)
	if state.Sequence() != 0 {
		t.Fatalf("ipfix template advanced sequence=%d", state.Sequence())
	}
}
