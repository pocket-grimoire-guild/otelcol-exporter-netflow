package netflowexporter

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter/exportertest"
)

func TestBootstrapPackageCompiles(t *testing.T) {
	t.Parallel()
}

func TestIPFIXGeneralPublicExporterMultiDatagram(t *testing.T) {
	c := validConfig("ipfix")
	c.Mapping.Profile = ptr(mapping.ProfileIPFIXGeneral)
	c.Templates.IDBase = 300
	c.MaxRecordsPerMessage = ptr(uint16(1))
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(c.Endpoint),
		testtransport.WriteStep{N: 104}, testtransport.WriteStep{N: 104}, testtransport.WriteStep{N: 104}, testtransport.WriteStep{N: 104},
		testtransport.WriteStep{N: 92}, testtransport.WriteStep{N: 116})
	e, err := newLogsExporter(context.Background(), exportertest.NewNopSettings(NewFactory().Type()), c,
		testclock.New(1_788_220_802_000_000_000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })

	logs := testpdata.CanonicalLogs()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	// The middle sibling reverses source start/end and must be rejected while
	// the surrounding valid IPv4/IPv6 records continue into separate packets.
	bad := records.AppendEmpty()
	records.At(0).CopyTo(bad)
	bad.Attributes().PutInt("flow.end", 1_788_220_800_999_000_000)
	ipv6 := testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	ipv6.CopyTo(records.AppendEmpty())
	logs.MarkReadOnly()
	if err := e.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("general consume with one reversed sibling: %v", err)
	}

	writes := conn.Writes()
	if len(writes) != 6 {
		t.Fatalf("writes=%d, want four startup templates and two data packets", len(writes))
	}
	wantTemplateIDs := []uint16{300, 301, 300, 301}
	for i, wantID := range wantTemplateIDs {
		packet := writes[i].Payload
		if len(packet) != 104 || binary.BigEndian.Uint16(packet[0:2]) != 10 || binary.BigEndian.Uint32(packet[8:12]) != 0 || binary.BigEndian.Uint16(packet[20:22]) != wantID {
			t.Fatalf("startup packet %d len/version/sequence/template=%d/%d/%d/%d, want 104/10/0/%d", i, len(packet), binary.BigEndian.Uint16(packet[0:2]), binary.BigEndian.Uint32(packet[8:12]), binary.BigEndian.Uint16(packet[20:22]), wantID)
		}
	}
	wantDataIDs := []uint16{300, 301}
	wantLengths := []int{92, 116}
	wantOffsets := []int{56, 80}
	wantTimes := [][2]uint64{{1_788_220_801_000, 1_788_220_801_001}, {1_788_220_801_000, 1_788_220_801_001}}
	for i, wantID := range wantDataIDs {
		packet := writes[4+i].Payload
		if len(packet) != wantLengths[i] || binary.BigEndian.Uint16(packet[0:2]) != 10 || binary.BigEndian.Uint32(packet[8:12]) != uint32(i) || binary.BigEndian.Uint16(packet[16:18]) != wantID || binary.BigEndian.Uint16(packet[18:20]) != uint16(wantLengths[i]-16) {
			t.Fatalf("data packet %d len/version/sequence/set=%d/%d/%d/%d, want %d/10/%d/%d", i, len(packet), binary.BigEndian.Uint16(packet[0:2]), binary.BigEndian.Uint32(packet[8:12]), binary.BigEndian.Uint16(packet[16:18]), wantLengths[i], i, wantID)
		}
		record := 20
		if got := binary.BigEndian.Uint64(packet[record+wantOffsets[i] : record+wantOffsets[i]+8]); got != wantTimes[i][0] {
			t.Fatalf("data packet %d start=%d, want %d", i, got, wantTimes[i][0])
		}
		if got := binary.BigEndian.Uint64(packet[record+wantOffsets[i]+8 : record+wantOffsets[i]+16]); got != wantTimes[i][1] {
			t.Fatalf("data packet %d end=%d, want %d", i, got, wantTimes[i][1])
		}
	}
}
