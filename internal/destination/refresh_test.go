package destination

import (
	"errors"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestRefreshV9PacketCountAndPartialRound(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.V9RefreshPacketCount = 2
	})
	bootstrap(t, state, 3_000_000_000, 0)
	shape, _ := state.Catalog().ShapeAt(0)
	record := testRecord(t, shape, 3_000_000_000)
	for i := 0; i < 2; i++ {
		packet, err := state.BeginData(3_000_000_000, uint64(i+1), 0, DataRequest{Records: []wire.WireRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
	}
	if !state.RefreshDue(3) {
		t.Fatal("v9 packet-count refresh not due")
	}
	if _, err := state.BeginData(3_000_000_000, 3, 0, DataRequest{Records: []wire.WireRecord{record}}); !errors.Is(err, ErrRefreshRequired) {
		t.Fatalf("data while refresh due err=%v", err)
	}
	first, err := state.BeginTemplate(3_000_000_000, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	failed, err := state.BeginTemplate(3_000_000_000, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	n, err := encodePacket(t, failed)
	if err != nil {
		t.Fatal(err)
	}
	result, err := state.Commit(failed, n-1, errors.New("short"))
	if err != nil || result.Committed || result.Class != WriteShortError {
		t.Fatalf("failed refresh result=%+v err=%v", result, err)
	}
	if !state.RefreshDue(5) || state.Ready() {
		t.Fatalf("partial refresh state ready=%v due=%v", state.Ready(), state.RefreshDue(5))
	}
	retry, err := state.BeginTemplate(3_000_000_000, 6, 1)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, retry)
	if !state.Ready() || state.RefreshDue(6) {
		t.Fatalf("refresh completion ready=%v due=%v", state.Ready(), state.RefreshDue(6))
	}
}

func TestRefreshIntervalAndBackwardMonotonicValue(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolIPFIX, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.RefreshInterval = 30 * time.Second
	})
	bootstrap(t, state, 3_000_000_000, 100)
	if state.RefreshDue(99) {
		t.Fatal("backward monotonic value created a due refresh")
	}
	if state.RefreshDue(100 + uint64(30*time.Second) - 1) {
		t.Fatal("refresh became due one nanosecond early")
	}
	if !state.RefreshDue(100 + uint64(30*time.Second)) {
		t.Fatal("interval refresh not due")
	}
	if _, err := state.BeginData(3_000_000_000, 100+uint64(30*time.Second), 0, DataRequest{Records: []wire.WireRecord{testRecord(t, mustShape(t, state, 0), 3_000_000_000)}}); !errors.Is(err, ErrRefreshRequired) {
		t.Fatalf("data after interval err=%v", err)
	}
}

func TestRefreshIPFIXOptionalDataMessageCount(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolIPFIX, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.IPFIXDataMessageRefreshCount = 2
	})
	bootstrap(t, state, 3_000_000_000, 0)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	for i := 0; i < 2; i++ {
		packet, err := state.BeginData(3_000_000_000, uint64(i+1), 0, DataRequest{Records: []wire.WireRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
	}
	if !state.RefreshDue(3) {
		t.Fatal("ipfix data-message refresh not due")
	}
}

func TestRefreshInvalidCommitRetainsPublishedProgress(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.V9RefreshPacketCount = 2
	})
	bootstrap(t, state, 3_000_000_000, 0)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	for i := 0; i < 2; i++ {
		packet, err := state.BeginData(3_000_000_000, uint64(i+1), 0, DataRequest{Records: []wire.WireRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
	}
	if !state.RefreshDue(3) {
		t.Fatal("refresh was not due")
	}
	packet, err := state.BeginTemplate(4_000_000_000, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encodePacket(t, packet); err != nil {
		t.Fatal(err)
	}
	sequence := state.Sequence()
	progressBefore := state.Progress()
	if _, err := state.Commit(packet, -1, nil); !errors.Is(err, ErrInvalidWrite) {
		t.Fatalf("invalid published refresh err=%v", err)
	}
	progressAfter := state.Progress()
	if state.Sequence() != sequence || progressAfter.NextShape != progressBefore.NextShape || !progressAfter.RefreshActive || !progressAfter.RefreshDue || progressAfter.PacketCount != progressBefore.PacketCount {
		t.Fatalf("invalid refresh changed state sequence=%d/%d progress=%+v/%+v", state.Sequence(), sequence, progressAfter, progressBefore)
	}
	state.mu.Lock()
	wall, haveWall := state.lastReservedWall, state.haveReservedWall
	state.mu.Unlock()
	if !haveWall || wall != 3_000_000_000 {
		t.Fatalf("invalid refresh changed wall=%v/%d", haveWall, wall)
	}
	retry, err := state.BeginTemplate(3_500_000_000, 4, 0)
	if err != nil || retry.LogicalSendInstant() != 3_500_000_000 {
		t.Fatalf("invalid refresh retry=(%+v,%v)", retry, err)
	}
	commitFull(t, state, retry)
}

func TestRefreshFirstEncodeFailureRetainsDue(t *testing.T) {
	t.Run("v9-count", func(t *testing.T) {
		state, writer := stateFor(t, wire.ProtocolV9, func(config *Config) {
			config.MaxDatagramSize = 65507
			config.V9RefreshPacketCount = 1
		})
		bootstrap(t, state, 3_000_000_000, 0)
		shape := mustShape(t, state, 0)
		record := testRecord(t, shape, 3_000_000_000)
		packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{record}})
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
		if !state.RefreshDue(2) {
			t.Fatal("v9 count refresh not due")
		}
		writer.writeErr = errors.New("encode")
		candidate, err := state.BeginTemplate(4_000_000_000, 2, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := candidate.Encode(make([]byte, candidate.DatagramLength())); !errors.Is(err, ErrEncoding) {
			t.Fatalf("first refresh encode err=%v", err)
		}
		progress := state.Progress()
		if !progress.RefreshDue || progress.RefreshActive || progress.NextShape != 0 || state.Ready() {
			t.Fatalf("first refresh rollback progress=%+v ready=%v", progress, state.Ready())
		}
		if _, err := state.BeginData(3_500_000_000, 3, 0, DataRequest{Records: []wire.WireRecord{record}}); !errors.Is(err, ErrRefreshRequired) {
			t.Fatalf("data during retained due err=%v", err)
		}
		writer.writeErr = nil
		retry, err := state.BeginTemplate(3_500_000_000, 4, 0)
		if err != nil || retry.LogicalSendInstant() != 3_500_000_000 {
			t.Fatalf("retry template=(%+v,%v)", retry, err)
		}
		commitFull(t, state, retry)
	})

	t.Run("ipfix-interval", func(t *testing.T) {
		state, writer := stateFor(t, wire.ProtocolIPFIX, func(config *Config) {
			config.MaxDatagramSize = 65507
			config.RefreshInterval = time.Minute
		})
		bootstrap(t, state, 3_000_000_000, 100)
		shape := mustShape(t, state, 0)
		record := testRecord(t, shape, 3_000_000_000)
		if !state.RefreshDue(100 + uint64(time.Minute)) {
			t.Fatal("ipfix interval refresh not due")
		}
		writer.writeErr = errors.New("encode")
		candidate, err := state.BeginTemplate(4_000_000_000, 100+uint64(time.Minute), 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := candidate.Encode(make([]byte, candidate.DatagramLength())); !errors.Is(err, ErrEncoding) {
			t.Fatalf("first refresh encode err=%v", err)
		}
		progress := state.Progress()
		if !progress.RefreshDue || progress.RefreshActive || progress.NextShape != 0 || state.Ready() {
			t.Fatalf("first refresh rollback progress=%+v ready=%v", progress, state.Ready())
		}
		if _, err := state.BeginData(3_500_000_000, 100+uint64(time.Minute), 0, DataRequest{Records: []wire.WireRecord{record}}); !errors.Is(err, ErrRefreshRequired) {
			t.Fatalf("data during retained due err=%v", err)
		}
		writer.writeErr = nil
		retry, err := state.BeginTemplate(3_500_000_000, 100+2*uint64(time.Minute), 0)
		if err != nil || retry.LogicalSendInstant() != 3_500_000_000 {
			t.Fatalf("retry template=(%+v,%v)", retry, err)
		}
		commitFull(t, state, retry)
	})
}

func TestRefreshActiveEncodeFailureRetainsExactProgress(t *testing.T) {
	state, writer := stateFor(t, wire.ProtocolV9, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.V9RefreshPacketCount = 1
	})
	bootstrap(t, state, 3_000_000_000, 0)
	shape := mustShape(t, state, 0)
	packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, 3_000_000_000)}})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, packet)
	first, err := state.BeginTemplate(3_000_000_000, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	before := state.Progress()
	if !before.RefreshActive || before.NextShape != 1 || !before.RefreshDue {
		t.Fatalf("active refresh before failure=%+v", before)
	}
	writer.writeErr = errors.New("encode")
	failed, err := state.BeginTemplate(4_000_000_000, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failed.Encode(make([]byte, failed.DatagramLength())); !errors.Is(err, ErrEncoding) {
		t.Fatalf("partial refresh encode err=%v", err)
	}
	after := state.Progress()
	if after != before || state.Ready() {
		t.Fatalf("partial refresh rollback=%+v before=%+v ready=%v", after, before, state.Ready())
	}
	writer.writeErr = nil
	retry, err := state.BeginTemplate(3_500_000_000, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, retry)
	if !state.Ready() {
		t.Fatal("refresh did not complete after retry")
	}
}

func mustShape(t *testing.T, state *State, index int) wire.Shape {
	t.Helper()
	shape, ok := state.Catalog().ShapeAt(index)
	if !ok {
		t.Fatalf("missing shape %d", index)
	}
	return shape
}
