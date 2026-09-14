package netflowexporter

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/plog"
)

const timedExporterOrigin = uint64(1_788_220_800_000_000_000)

// TestV9TimedProfilePacketization keeps the default 464-byte path at the
// protocol boundary: eight IPv4 records and five IPv6 records fit, while the
// next record starts a sibling packet. The check also confirms sequence and
// template state remain intact when one request crosses that boundary.
func TestV9TimedProfilePacketization(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ipv6        bool
		records     int
		firstCount  int
		firstBytes  int
		secondBytes int
		recordSize  int
		shapeID     uint16
	}{
		{name: "ipv4-eight", records: 9, firstCount: 8, firstBytes: 432, secondBytes: 76, recordSize: 51, shapeID: 256},
		{name: "ipv6-five", ipv6: true, records: 6, firstCount: 5, firstBytes: 400, secondBytes: 100, recordSize: 75, shapeID: 257},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig("netflow_v9")
			config.Mapping.Profile = ptr(mapping.ProfileV9Timed)
			config.UptimeOrigin = ptr(timedExporterOrigin)
			config.Identity.SourceID = ptr(uint32(42))
			steps := []testtransport.WriteStep{
				{N: 108}, {N: 108}, {N: 108}, {N: 108},
				{N: tc.firstBytes}, {N: tc.secondBytes},
			}
			exporter, conn := fakeExporter(t, config, steps...)
			if err := exporter.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			logs := timedRepeatedLogs(tc.ipv6, tc.records)
			if err := exporter.ConsumeLogs(context.Background(), logs); err != nil {
				t.Fatalf("timed packetization: %v", err)
			}
			writes := conn.Writes()
			if len(writes) != len(steps) {
				t.Fatalf("writes=%d, want %d", len(writes), len(steps))
			}
			for index, write := range writes[:4] {
				packet := write.Payload
				if write.N != 108 || len(packet) != 108 || binary.BigEndian.Uint16(packet) != 9 || binary.BigEndian.Uint32(packet[16:20]) != 42 || binary.BigEndian.Uint16(packet[20:22]) != 0 || binary.BigEndian.Uint16(packet[22:24]) != 88 || binary.BigEndian.Uint16(packet[24:26]) != 256+uint16(index%2) {
					t.Fatalf("template %d n/len/version/source/set/length/id=%d/%d/%d/%d/%d/%d/%d", index, write.N, len(packet), binary.BigEndian.Uint16(packet), binary.BigEndian.Uint32(packet[16:20]), binary.BigEndian.Uint16(packet[20:22]), binary.BigEndian.Uint16(packet[22:24]), binary.BigEndian.Uint16(packet[24:26]))
				}
			}
			for index, want := range []struct {
				count, bytes, records int
			}{
				{tc.firstCount, tc.firstBytes, tc.firstCount},
				{1, tc.secondBytes, 1},
			} {
				packet := writes[4+index].Payload
				setLength := (4 + want.records*tc.recordSize + 3) &^ 3
				if len(packet) != want.bytes || binary.BigEndian.Uint16(packet) != 9 || binary.BigEndian.Uint16(packet[2:4]) != uint16(want.count) || binary.BigEndian.Uint32(packet[12:16]) != uint32(4+index) || binary.BigEndian.Uint32(packet[16:20]) != 42 || binary.BigEndian.Uint16(packet[20:22]) != tc.shapeID || binary.BigEndian.Uint16(packet[22:24]) != uint16(setLength) {
					t.Fatalf("data %d len/count/sequence/source/id/set=%d/%d/%d/%d/%d/%d, want len=%d records=%d", index, len(packet), binary.BigEndian.Uint16(packet[2:4]), binary.BigEndian.Uint32(packet[12:16]), binary.BigEndian.Uint32(packet[16:20]), binary.BigEndian.Uint16(packet[20:22]), binary.BigEndian.Uint16(packet[22:24]), want.bytes, want.count)
				}
				record := 24
				if first, last := binary.BigEndian.Uint32(packet[record+tc.recordSize-8:]), binary.BigEndian.Uint32(packet[record+tc.recordSize-4:]); first != 1000 || last != 1001 {
					t.Fatalf("data %d switched=%d/%d, want 1000/1001", index, first, last)
				}
			}
		})
	}
}

func timedRepeatedLogs(ipv6 bool, records int) (logs plog.Logs) {
	if ipv6 {
		logs = testpdata.CanonicalIPv6Logs()
	} else {
		logs = testpdata.CanonicalLogs()
	}
	scope := logs.ResourceLogs().At(0).ScopeLogs().At(0)
	first := scope.LogRecords().At(0)
	for range records - 1 {
		destination := scope.LogRecords().AppendEmpty()
		first.CopyTo(destination)
	}
	logs.MarkReadOnly()
	return logs
}
