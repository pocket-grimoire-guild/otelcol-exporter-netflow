//go:build linux

package independent_test

import (
	"encoding/binary"
	"testing"
	"time"
)

// assertTimedPacket is an independent literal check for the v9 timed profile.
// It does not call the exporter's catalog or writer to derive field identity,
// widths, offsets, or measured values.
func assertTimedPacket(t *testing.T, packet []byte, phase string, sequence uint32, shape, expectedRecords int) {
	t.Helper()
	if len(packet) < 20 || binary.BigEndian.Uint16(packet[:2]) != 9 || binary.BigEndian.Uint32(packet[12:16]) != sequence || binary.BigEndian.Uint32(packet[16:20]) != 42 {
		t.Fatalf("timed %s header/sequence/source drift: %x", phase, packet)
	}
	if phase != "data" {
		if len(packet) != 108 || binary.BigEndian.Uint16(packet[20:22]) != 0 || binary.BigEndian.Uint16(packet[22:24]) != 88 || binary.BigEndian.Uint16(packet[24:26]) != uint16(256+shape) || binary.BigEndian.Uint16(packet[26:28]) != 20 {
			t.Fatalf("timed template envelope: %x", packet)
		}
		ids := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 22, 21}
		widths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1, 4, 4}
		if shape == 1 {
			ids[6], widths[6] = 27, 16
			ids[7] = 29
			ids[10], widths[10] = 28, 16
			ids[11] = 30
		}
		for index, wantID := range ids {
			offset := 28 + index*4
			if gotID, gotWidth := binary.BigEndian.Uint16(packet[offset:offset+2]), binary.BigEndian.Uint16(packet[offset+2:offset+4]); gotID != wantID || gotWidth != widths[index] {
				t.Fatalf("timed template field %d=%d/%d, want %d/%d", index, gotID, gotWidth, wantID, widths[index])
			}
		}
		return
	}
	if expectedRecords != 1 {
		t.Fatalf("timed assertion only supports one data record, got %d", expectedRecords)
	}
	recordLength := 51
	timeOffset := 43
	if shape == 1 {
		recordLength, timeOffset = 75, 67
	}
	if len(packet) != 20+4+recordLength+1 || binary.BigEndian.Uint16(packet[20:22]) != uint16(256+shape) || binary.BigEndian.Uint16(packet[22:24]) != uint16(recordLength+5) {
		t.Fatalf("timed data envelope len=%d set=%x", len(packet), packet[20:24])
	}
	record := 24
	if got := binary.BigEndian.Uint32(packet[record+timeOffset : record+timeOffset+4]); got != 3000 {
		t.Fatalf("timed FIRST_SWITCHED=%d, want 3000", got)
	}
	if got := binary.BigEndian.Uint32(packet[record+timeOffset+4 : record+timeOffset+8]); got != 4000 {
		t.Fatalf("timed LAST_SWITCHED=%d, want 4000", got)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got < 4000 {
		t.Fatalf("timed header sysUptime=%d precedes LAST_SWITCHED=4000", got)
	}
	if packet[len(packet)-1] != 0 {
		t.Fatalf("timed data padding=%x, want zero", packet[len(packet)-1])
	}
}

func nfdumpTimedProjection(tc fixtureCase, stream []exportPacket) []map[string]any {
	rows := nfdumpProjection("v9", tc, stream)
	rowIndex := 0
	for _, packet := range stream {
		if packet.phase != "data" {
			continue
		}
		baseMillis := int64(0)
		if len(packet.bytes) >= 12 {
			// v9 carries export time only to whole seconds. Reconstructing the
			// configured origin through that header necessarily shifts both
			// switched times by the discarded export fraction.
			exportMillis := int64(binary.BigEndian.Uint32(packet.bytes[8:12])) * 1000
			sysUptime := int64(binary.BigEndian.Uint32(packet.bytes[4:8]))
			baseMillis = exportMillis - sysUptime
		}
		for range tc.ExpectedRecords {
			if rowIndex >= len(rows) {
				break
			}
			rows[rowIndex]["first"] = time.UnixMilli(baseMillis + 3000).UTC().Format(nfdumpTimeLayout)
			rows[rowIndex]["last"] = time.UnixMilli(baseMillis + 4000).UTC().Format(nfdumpTimeLayout)
			rowIndex++
		}
	}
	return rows
}
