package destination

import (
	"errors"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestEpochRestartFreshAndInstanceIsolation(t *testing.T) {
	first, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	second, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	bootstrap(t, first, 3_000_000_000, 1)
	bootstrap(t, second, 3_000_000_000, 1)
	shape := mustShape(t, first, 0)
	record := testRecord(t, shape, 3_000_000_000)
	packet, err := first.BeginData(3_000_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, first, packet)
	if first.Sequence() == second.Sequence() {
		t.Fatal("instances share protocol sequence")
	}
	if first.Catalog().IDs()[0] != second.Catalog().IDs()[0] {
		t.Fatal("independent instances changed compiler catalog IDs")
	}

	restarted := first.Restart()
	if restarted.ID != 2 || restarted.Sequence != 0 || restarted.Ready || restarted.HasStartOrigin {
		t.Fatalf("restart snapshot=%+v", restarted)
	}
	if first.Catalog().IDs()[0] != 256 {
		t.Fatal("restart changed compiler template ID")
	}
}

func TestEpochV9StartOriginAndUptimeExhaustion(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	if _, err := state.BeginData(9_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{{}}}); err == nil {
		t.Fatal("invalid candidate data accepted")
	}
	state.mu.Lock()
	haveReservedWall := state.haveReservedWall
	state.mu.Unlock()
	if state.Epoch().HasStartOrigin || haveReservedWall {
		t.Fatalf("invalid candidate advanced clock: epoch=%+v reserved=%v", state.Epoch(), haveReservedWall)
	}
	packet, err := state.BeginTemplate(9_000_000_123, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := packet.request.Header.UptimeOriginUnixNanos; got != 9_000_000_123 {
		t.Fatalf("candidate origin=%d", got)
	}
	n, err := encodePacket(t, packet)
	if err != nil {
		t.Fatal(err)
	}
	result, err := state.Commit(packet, n-1, nil)
	if err != nil || result.Class != WriteShortNil {
		t.Fatalf("failed start result=%+v err=%v", result, err)
	}
	if state.Epoch().HasStartOrigin {
		t.Fatalf("failed candidate kept origin=%+v", state.Epoch())
	}

	v5, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.UptimeOriginUnixNanos = 0
	})
	shape := mustShape(t, v5, 0)
	record := testRecord(t, shape, 0)
	tooLarge := (uint64(math.MaxUint32) + 1) * 1_000_000
	if _, err := v5.BeginData(tooLarge, 1, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("uptime exhaustion err=%v", err)
	}
	if !v5.Epoch().UptimeExhausted {
		t.Fatalf("uptime exhaustion was not latched")
	}
	if _, err := v5.BeginData(0, 2, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("latched exhaustion err=%v", err)
	}

	v9, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	bootstrap(t, v9, 3_000_000_000, 0)
	shape = mustShape(t, v9, 0)
	record = testRecord(t, shape, 3_000_000_000)
	tooLarge = 3_000_000_000 + (uint64(math.MaxUint32)+1)*1_000_000
	if _, err := v9.BeginData(tooLarge, 1, 0, DataRequest{Records: []wire.WireRecord{record}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("v9 uptime exhaustion err=%v", err)
	}
	if !v9.Epoch().UptimeExhausted {
		t.Fatalf("v9 uptime exhaustion was not latched")
	}
	if _, err := v9.BeginData(3_000_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("v9 latched exhaustion err=%v", err)
	}
}

func TestEpochBackwardWallReservation(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.UptimeOriginUnixNanos = 0
	})
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 1_000_000)
	first, err := state.BeginData(4_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}})
	if err != nil {
		t.Fatal(err)
	}
	n, err := encodePacket(t, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Commit(first, n, errors.New("ambiguous")); err != nil {
		t.Fatal(err)
	}
	second, err := state.BeginData(2_000_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}})
	if err != nil {
		t.Fatal(err)
	}
	if second.LogicalSendInstant() != 4_000_000_000 {
		t.Fatalf("backward wall reservation=%d", second.LogicalSendInstant())
	}
}

func TestEpochInvalidCommitDiscardsUnpublishedCandidate(t *testing.T) {
	for _, invalidN := range []int{-1, 1 << 20} {
		state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
		first, err := state.BeginTemplate(3_000_000_000, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, first)
		second, err := state.BeginTemplate(3_000_000_000, 2, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := encodePacket(t, second); err != nil {
			t.Fatal(err)
		}
		result, err := state.Commit(second, invalidN, nil)
		if !errors.Is(err, ErrInvalidWrite) || result.Class != WriteInvalid {
			t.Fatalf("invalid n=%d result=%+v err=%v", invalidN, result, err)
		}
		progress := state.Progress()
		epoch := state.Epoch()
		if epoch.HasStartOrigin || epoch.Sequence != 0 || progress.NextShape != 0 || progress.CompletedRounds != 0 || progress.RefreshActive || progress.RefreshDue {
			t.Fatalf("invalid n=%d retained candidate epoch=%+v progress=%+v", invalidN, epoch, progress)
		}
	}
}

func TestEpochInvalidCommitRestoresEarlierWall(t *testing.T) {
	for _, invalidN := range []int{-1, 1 << 20} {
		state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
		packet, err := state.BeginTemplate(4_000_000_000, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := encodePacket(t, packet); err != nil {
			t.Fatal(err)
		}
		if _, err := state.Commit(packet, invalidN, nil); !errors.Is(err, ErrInvalidWrite) {
			t.Fatalf("invalid n=%d err=%v", invalidN, err)
		}
		state.mu.Lock()
		wall, haveWall := state.lastReservedWall, state.haveReservedWall
		state.mu.Unlock()
		if haveWall || wall != 0 {
			t.Fatalf("invalid n=%d retained wall=%v/%d", invalidN, haveWall, wall)
		}
		retry, err := state.BeginTemplate(2_000_000_000, 2, 0)
		if err != nil || retry.LogicalSendInstant() != 2_000_000_000 {
			t.Fatalf("invalid n=%d retry=(%+v,%v)", invalidN, retry, err)
		}
		commitFull(t, state, retry)
	}
}

func TestEpochCandidateEncodeFailureDiscardsCandidate(t *testing.T) {
	state, writer := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	first, err := state.BeginTemplate(3_000_000_000, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	writer.writeErr = errors.New("encode")
	failed, err := state.BeginTemplate(4_000_000_000, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failed.Encode(make([]byte, failed.DatagramLength())); !errors.Is(err, ErrEncoding) {
		t.Fatalf("candidate encode err=%v", err)
	}
	progress := state.Progress()
	epoch := state.Epoch()
	state.mu.Lock()
	wall, haveWall := state.lastReservedWall, state.haveReservedWall
	state.mu.Unlock()
	if epoch.HasStartOrigin || epoch.Sequence != 0 || progress.NextShape != 0 || progress.CompletedRounds != 0 || progress.RefreshActive || progress.RefreshDue || !haveWall || wall != 3_000_000_000 {
		t.Fatalf("candidate encode retained epoch=%+v progress=%+v wall=%v/%d", epoch, progress, haveWall, wall)
	}
	writer.writeErr = nil
	retry, err := state.BeginTemplate(3_500_000_000, 3, 0)
	if err != nil || retry.LogicalSendInstant() != 3_500_000_000 {
		t.Fatalf("candidate retry=(%+v,%v)", retry, err)
	}
	commitFull(t, state, retry)
}
