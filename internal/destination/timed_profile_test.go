package destination

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
)

const destinationTimedOrigin = uint64(1_788_220_800_000_000_000)

func timedDestinationState(t *testing.T) *State {
	t.Helper()
	compiled, err := mapping.Compile(mapping.Config{
		Profile:               mapping.ProfileV9Timed,
		Protocol:              wire.ProtocolV9,
		LossPolicy:            mapping.LossPolicyEncodeAndCount,
		ProtocolIdentifiers:   []mapping.ProtocolIdentifier{{Token: "tcp", Number: 6}},
		NetworkTypeVersions:   []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}},
		MaxDatagramSize:       464,
		PathMTU:               65535,
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: destinationTimedOrigin,
	})
	if err != nil {
		t.Fatalf("compile timed destination mapping: %v", err)
	}
	config := DefaultConfig(wire.ProtocolV9)
	config.SourceID, config.ObservationDomainID = 42, 42
	config.HasUptimeOrigin = true
	config.UptimeOriginUnixNanos = destinationTimedOrigin
	config.MaxDatagramSize = 464
	state, err := NewState(compiled, netflow9.Writer{}, config)
	if err != nil {
		t.Fatalf("new timed destination state: %v", err)
	}
	bootstrap(t, state, destinationTimedOrigin+5_000_000_000, 1)
	return state
}

func TestTimedProfileConfiguredUptimeLastValidAndLatched(t *testing.T) {
	state := timedDestinationState(t)
	shape := mustShape(t, state, 0)
	last := destinationTimedOrigin + uint64(math.MaxUint32)*1_000_000
	packet, err := state.BeginData(last, 2, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, last)}})
	if err != nil {
		t.Fatalf("last representable uptime rejected: %v", err)
	}
	commitFull(t, state, packet)
	firstExhausted := destinationTimedOrigin + (uint64(math.MaxUint32)+1)*1_000_000
	if _, err := state.BeginData(firstExhausted, 3, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, last)}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("first exhausted uptime error=%v, want %v", err, ErrUptimeExhausted)
	}
	if !state.Epoch().UptimeExhausted {
		t.Fatal("uptime exhaustion was not latched")
	}
	if _, err := state.BeginData(destinationTimedOrigin+6_000_000_000, 4, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, destinationTimedOrigin+6_000_000_000)}}); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("post-exhaustion uptime error=%v, want latched %v", err, ErrUptimeExhausted)
	}
}

func TestTimedProfileBadSiblingSubsetAndPacketization(t *testing.T) {
	state := timedDestinationState(t)
	logs := testpdata.CanonicalLogs()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	base := records.At(0)
	for i := 1; i < 10; i++ {
		base.CopyTo(records.AppendEmpty())
	}
	const badOrdinal = 4
	records.At(badOrdinal).Attributes().PutInt("flow.end", int64(destinationTimedOrigin+500_000_000))

	var packets [][]byte
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			packets = append(packets, append([]byte(nil), datagram...))
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return destinationTimedOrigin + 5_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil {
		t.Fatalf("timed bad sibling Pack() error=%v", err)
	}
	counts := result.Counts()
	if counts.Covered != 10 || counts.Valid != 9 || counts.Invalid != 1 || counts.Confirmed != 9 || counts.Unsent != 0 {
		t.Fatalf("timed bad sibling counts=%+v", counts)
	}
	for ordinal := uint64(0); ordinal < 10; ordinal++ {
		want := SourceConfirmed
		if ordinal == badOrdinal {
			want = SourceInvalid
		}
		if got := result.Classification(ordinal); got != want {
			t.Fatalf("ordinal %d class=%v, want %v", ordinal, got, want)
		}
	}
	if len(packets) != 2 || len(packets[0]) != 432 || len(packets[1]) != 76 {
		t.Fatalf("timed packetization lengths=%v, want [432 76]", packetLengths(packets))
	}
	for index, packet := range packets {
		wantRecords := []uint16{8, 1}[index]
		wantLength := []uint16{412, 56}[index]
		if binary.BigEndian.Uint16(packet[0:2]) != 9 || binary.BigEndian.Uint16(packet[2:4]) != wantRecords ||
			binary.BigEndian.Uint32(packet[4:8]) != 5000 || binary.BigEndian.Uint16(packet[20:22]) != 256 || binary.BigEndian.Uint16(packet[22:24]) != wantLength {
			t.Fatalf("timed packet %d envelope=%x, want records=%d set-length=%d", index, packet[:24], wantRecords, wantLength)
		}
	}
}

func packetLengths(packets [][]byte) []int {
	lengths := make([]int, len(packets))
	for i := range packets {
		lengths[i] = len(packets[i])
	}
	return lengths
}
