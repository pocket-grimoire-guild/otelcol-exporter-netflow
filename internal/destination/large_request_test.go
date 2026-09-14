package destination

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/plog"
)

const largeRequestRecordCount = 65_537

type largePacketCapture struct {
	packets [][]byte
}

func (c *largePacketCapture) write(_ context.Context, packet []byte) (int, error) {
	c.packets = append(c.packets, append([]byte(nil), packet...))
	return len(packet), nil
}

func TestPackerAcceptsLargeValidRequestAllProtocols(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			maxRecords := uint16(1024)
			if protocol == wire.ProtocolV5 {
				maxRecords = 30
			}
			state := packingFuzzState(t, protocol, maxRecords, 65507)
			logs := largeValidPackerLogs(t, protocol, largeRequestRecordCount)
			capture := new(largePacketCapture)
			packer, err := NewPacker(state, PackerConfig{
				Write: capture.write,
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			initialSequence := state.Sequence()
			result, err := packer.Pack(context.Background(), logs, nil)
			if err != nil || result.Outcome() != PackSucceeded {
				t.Fatalf("large pack = (%d,%v), counts=%+v", result.Outcome(), err, result.Counts())
			}
			counts := result.Counts()
			if counts.Covered != largeRequestRecordCount || counts.Valid != largeRequestRecordCount || counts.Confirmed != largeRequestRecordCount || counts.Invalid != 0 || counts.Unsent != 0 {
				t.Fatalf("large ledger counts = %+v", counts)
			}
			dataPackets := assertLargePackets(t, protocol, capture.packets, maxRecords, initialSequence)
			if result.Packets() != uint64(dataPackets) || dataPackets < 2 {
				t.Fatalf("large data packet counts = result %d capture %d", result.Packets(), dataPackets)
			}
			wantSequence := initialSequence + uint32(largeRequestRecordCount)
			if protocol == wire.ProtocolV9 {
				wantSequence = initialSequence + uint32(len(capture.packets))
			}
			if state.Sequence() != wantSequence {
				t.Fatalf("final protocol sequence = %d, want %d", state.Sequence(), wantSequence)
			}
		})
	}
}

func largeValidPackerLogs(t *testing.T, protocol wire.Protocol, count int) plog.Logs {
	t.Helper()
	logs := testpdata.CanonicalLogs()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	base := records.At(0)
	for ordinal := 1; ordinal < count; ordinal++ {
		base.CopyTo(records.AppendEmpty())
	}
	for ordinal := 0; ordinal < count; ordinal++ {
		record := records.At(ordinal)
		record.Attributes().PutInt("source.port", int64(1000+ordinal%60000))
		if protocol == wire.ProtocolV5 {
			for _, key := range []string{"flow.time_received", "flow.start", "flow.end"} {
				record.Attributes().PutInt(key, 3_000_000_000)
			}
		}
	}
	// This metadata is deliberately outside the mapping and substantially larger
	// and deeper than the selected fields. It must not change packetization of
	// the valid selected fields.
	first := records.At(0)
	first.Attributes().PutStr("ignored.large", strings.Repeat("m", 65<<20))
	deep := first.Attributes().PutEmptyMap("ignored.deep")
	for depth := 0; depth < 1024; depth++ {
		deep = deep.PutEmptyMap("next")
	}
	return logs
}

func assertLargePackets(t *testing.T, protocol wire.Protocol, packets [][]byte, maxRecords uint16, initialSequence uint32) int {
	t.Helper()
	var ordinal uint64
	sequence := uint64(initialSequence)
	dataPackets := 0
	for index, packet := range packets {
		if len(packet) < 2 {
			t.Fatalf("packet %d too short: %d", index, len(packet))
		}
		if got, want := binary.BigEndian.Uint16(packet[:2]), protocolVersion(protocol); got != want {
			t.Fatalf("packet %d version = %d, want %d", index, got, want)
		}
		var records, dataOffset, recordWidth int
		var packetSequence uint32
		switch protocol {
		case wire.ProtocolV5:
			if len(packet) < 24 {
				t.Fatalf("v5 packet %d too short: %d", index, len(packet))
			}
			records = int(binary.BigEndian.Uint16(packet[2:4]))
			dataOffset, recordWidth = 24, 48
			packetSequence = binary.BigEndian.Uint32(packet[16:20])
			if records < 1 || records > int(maxRecords) || len(packet) != dataOffset+records*recordWidth {
				t.Fatalf("v5 packet %d count/length = %d/%d", index, records, len(packet))
			}
		case wire.ProtocolV9:
			if len(packet) < 24 {
				t.Fatalf("v9 packet %d too short: %d", index, len(packet))
			}
			count := int(binary.BigEndian.Uint16(packet[2:4]))
			if count < 1 {
				t.Fatalf("v9 packet %d header count = %d", index, count)
			}
			records = count
			dataOffset, recordWidth = 24, 2
			packetSequence = binary.BigEndian.Uint32(packet[12:16])
			if binary.BigEndian.Uint16(packet[20:22]) < 256 {
				if uint64(packetSequence) != sequence {
					t.Fatalf("template packet %d sequence = %d, want %d", index, packetSequence, sequence)
				}
				sequence++
				continue
			}
			setLength := int(binary.BigEndian.Uint16(packet[22:24]))
			if records > int(maxRecords) || setLength != 4+records*recordWidth || len(packet) != dataOffset+records*recordWidth {
				t.Fatalf("v9 packet %d count/set/length = %d/%d/%d", index, records, setLength, len(packet))
			}
		case wire.ProtocolIPFIX:
			if len(packet) < 20 {
				t.Fatalf("ipfix packet %d too short: %d", index, len(packet))
			}
			messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
			setLength := int(binary.BigEndian.Uint16(packet[18:20]))
			records = (setLength - 4) / 2
			dataOffset, recordWidth = 20, 2
			packetSequence = binary.BigEndian.Uint32(packet[8:12])
			if records < 1 || records > int(maxRecords) || setLength != 4+records*recordWidth || messageLength != len(packet) || len(packet) != dataOffset+records*recordWidth {
				t.Fatalf("ipfix packet %d set/message/length = %d/%d/%d", index, setLength, messageLength, len(packet))
			}
		default:
			t.Fatalf("unsupported protocol %d", protocol)
		}
		if uint64(packetSequence) != sequence {
			t.Fatalf("packet %d sequence = %d, want %d", index, packetSequence, sequence)
		}
		dataPackets++
		for recordIndex := 0; recordIndex < records; recordIndex++ {
			offset := dataOffset + recordIndex*recordWidth
			var got uint16
			if protocol == wire.ProtocolV5 {
				got = binary.BigEndian.Uint16(packet[offset+32 : offset+34])
			} else {
				got = binary.BigEndian.Uint16(packet[offset : offset+2])
			}
			want := uint16(1000 + ordinal%60000)
			if got != want {
				t.Fatalf("packet %d record %d source port = %d, want %d", index, recordIndex, got, want)
			}
			ordinal++
		}
		if protocol == wire.ProtocolV9 {
			sequence++
		} else {
			sequence += uint64(records)
		}
	}
	if ordinal != largeRequestRecordCount {
		t.Fatalf("packetized records = %d, want %d", ordinal, largeRequestRecordCount)
	}
	return dataPackets
}

func protocolVersion(protocol wire.Protocol) uint16 {
	switch protocol {
	case wire.ProtocolV5:
		return 5
	case wire.ProtocolV9:
		return 9
	case wire.ProtocolIPFIX:
		return 10
	default:
		return 0
	}
}
