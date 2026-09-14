package independent_test

import (
	"encoding/binary"
	"testing"
)

// assertGeneralPacket is an independent literal check for the fresh 152/153
// profile stream. It deliberately does not call the exporter writer or its
// shape catalog to derive expected IDs, widths, offsets, or values.
func assertGeneralPacket(t *testing.T, packet []byte, phase string, sequence uint32, shape, expectedRecords int) {
	t.Helper()
	if len(packet) < 16 || binary.BigEndian.Uint16(packet[:2]) != 10 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || binary.BigEndian.Uint32(packet[8:12]) != sequence || binary.BigEndian.Uint32(packet[12:16]) != 42 {
		t.Fatalf("general %s header/sequence/domain: %x", phase, packet)
	}
	if phase != "data" {
		if len(packet) != 104 || binary.BigEndian.Uint16(packet[16:18]) != 2 || binary.BigEndian.Uint16(packet[18:20]) != 88 || binary.BigEndian.Uint16(packet[20:22]) != uint16(256+shape) || binary.BigEndian.Uint16(packet[22:24]) != 20 {
			t.Fatalf("general template envelope: %x", packet)
		}
		ids := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 152, 153}
		widths := []uint16{8, 8, 1, 1, 2, 2, 4, 1, 4, 2, 4, 1, 4, 4, 4, 4, 1, 1, 8, 8}
		if shape == 1 {
			ids[6], widths[6], ids[7], ids[10], widths[10], ids[11] = 27, 16, 29, 28, 16, 30
		}
		for index, wantID := range ids {
			offset := 24 + index*4
			if got := binary.BigEndian.Uint16(packet[offset : offset+2]); got != wantID || binary.BigEndian.Uint16(packet[offset+2:offset+4]) != widths[index] {
				t.Fatalf("general template field %d=%d/%d, want %d/%d", index, got, binary.BigEndian.Uint16(packet[offset+2:offset+4]), wantID, widths[index])
			}
		}
		return
	}
	if expectedRecords != 1 {
		t.Fatalf("general assertion only supports one data record, got %d", expectedRecords)
	}
	recordLength := uint16(72)
	startOffset := 56
	if shape == 1 {
		recordLength, startOffset = 96, 80
	}
	if len(packet) != 16+4+int(recordLength) || binary.BigEndian.Uint16(packet[16:18]) != uint16(256+shape) || binary.BigEndian.Uint16(packet[18:20]) != recordLength+4 {
		t.Fatalf("general data envelope len=%d set=%x", len(packet), packet[16:20])
	}
	record := 20 + startOffset
	if got := binary.BigEndian.Uint64(packet[record : record+8]); got != 1_788_220_800_123 {
		t.Fatalf("general start=%d, want 1788220800123", got)
	}
	if got := binary.BigEndian.Uint64(packet[record+8 : record+16]); got != 1_788_220_801_123 {
		t.Fatalf("general end=%d, want 1788220801123", got)
	}
}
