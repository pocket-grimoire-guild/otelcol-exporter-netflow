package netflowexporter

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	largeSubsetRecords               = 65540
	largeSubsetPacketRecords         = 1024
	largeSubsetBootstrap             = 2
	largeSubsetCancellationBootstrap = 4
	largeSubsetAmbiguousSequence     = 63 * largeSubsetPacketRecords
)

var errLargeSubsetAmbiguous = errors.New("large subset: ambiguous handoff")

type largeSubsetConn struct {
	mu sync.Mutex

	local, remote netip.AddrPort
	failSequence  int64
	closed        bool
	attempted     int
	confirmed     int
	writes        [][]byte
}

func newLargeSubsetConn(failSequence int64) *largeSubsetConn {
	return &largeSubsetConn{
		local:        netip.MustParseAddrPort("127.0.0.1:40000"),
		remote:       netip.MustParseAddrPort("127.0.0.1:4739"),
		failSequence: failSequence,
		writes:       make([][]byte, 0, 80),
	}
}

func (c *largeSubsetConn) LocalAddr() netip.AddrPort  { return c.local }
func (c *largeSubsetConn) RemoteAddr() netip.AddrPort { return c.remote }

func (c *largeSubsetConn) SetWriteDeadline(_ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return transport.ErrClosed
	}
	return nil
}

func (c *largeSubsetConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, transport.ErrClosed
	}
	c.attempted++
	c.writes = append(c.writes, append([]byte(nil), payload...))
	if len(payload) >= 20 && binary.BigEndian.Uint16(payload[:2]) == 10 && binary.BigEndian.Uint16(payload[16:18]) >= 256 && c.failSequence >= 0 && int64(binary.BigEndian.Uint32(payload[8:12])) == c.failSequence {
		return len(payload), errLargeSubsetAmbiguous
	}
	c.confirmed++
	return len(payload), nil
}

func (c *largeSubsetConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *largeSubsetConn) counts() (attempted, confirmed int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempted, c.confirmed
}

func (c *largeSubsetConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	packets := make([][]byte, len(c.writes))
	for i := range c.writes {
		packets[i] = append([]byte(nil), c.writes[i]...)
	}
	return packets
}

func TestLargeReturnedSubsetCrossesUint16Boundary(t *testing.T) {
	conn := newLargeSubsetConn(largeSubsetAmbiguousSequence)
	c := validConfig("ipfix")
	c.MaxDatagramSize = 65507
	c.PathMTU = ptr(uint64(65535))
	c.MaxRecordsPerMessage = ptr(uint16(largeSubsetPacketRecords))
	c.Mapping.Profile = nil
	c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
	c.Mapping.ProtocolIdentifiers = nil
	c.Mapping.NetworkTypeVersions = nil
	e, err := newLogsExporter(context.Background(), exportertest.NewNopSettings(NewFactory().Type()), c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })

	logs := largeSubsetLogs(t)
	err = e.ConsumeLogs(context.Background(), logs)
	logsErr, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) {
		t.Fatalf("large subset error=%v, want transient subset", err)
	}
	attempted, confirmed := conn.counts()
	if attempted != largeSubsetBootstrap+64 || confirmed != largeSubsetBootstrap+63 {
		t.Fatalf("writes attempted/confirmed=%d/%d, want %d/%d", attempted, confirmed, largeSubsetBootstrap+64, largeSubsetBootstrap+63)
	}
	packets := conn.packets()
	if len(packets) != attempted {
		t.Fatalf("captured packets=%d, want %d", len(packets), attempted)
	}
	dataPackets := packets[largeSubsetBootstrap:]
	if len(dataPackets) < 3 {
		t.Fatalf("data packets=%d, want multiple confirmed packets and an ambiguous packet", len(dataPackets))
	}
	for index, packet := range dataPackets {
		if len(packet) < 20 || binary.BigEndian.Uint16(packet[:2]) != 10 {
			t.Fatalf("data packet %d has invalid IPFIX header", index)
		}
		sequence := binary.BigEndian.Uint32(packet[8:12])
		wantSequence := uint32(index * largeSubsetPacketRecords)
		if sequence != wantSequence {
			t.Fatalf("data packet %d sequence=%d, want %d", index, sequence, wantSequence)
		}
	}

	subset := logsErr.Data()
	if got := subset.LogRecordCount(); got != 1026 {
		t.Fatalf("returned subset records=%d, want 1026", got)
	}
	subsetRecords := subset.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	for index := 0; index < 1026; index++ {
		want := int64(64513 + index)
		if index == 1025 {
			want = 65539
		}
		record := subsetRecords.At(index)
		value, ok := record.Attributes().Get("ordinal")
		if !ok || value.Int() != want {
			t.Fatalf("returned subset ordinal %d=%v/%t, want %d", index, value, ok, want)
		}
	}
	if subset.ResourceLogs().Len() != 1 || subset.ResourceLogs().At(0).ScopeLogs().Len() != 1 {
		t.Fatalf("returned subset hierarchy=%d/%d, want 1/1", subset.ResourceLogs().Len(), subset.ResourceLogs().At(0).ScopeLogs().Len())
	}

	assertLargeSubsetByteOwnership(t, logs, subset)
}

func TestLargeReturnedSubsetCancellationPreservesUnsentValid(t *testing.T) {
	conn := newLargeSubsetConn(-1)
	c := validConfig("ipfix")
	e, err := newLogsExporter(context.Background(), exportertest.NewNopSettings(NewFactory().Type()), c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = e.ConsumeLogs(ctx, testpdata.CanonicalLogs())
	logsErr, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) || logsErr.Data().LogRecordCount() != 1 {
		t.Fatalf("canceled consume=%v, subset records=%d", err, logsErr.Data().LogRecordCount())
	}
	attempted, confirmed := conn.counts()
	if attempted != largeSubsetCancellationBootstrap || confirmed != largeSubsetCancellationBootstrap {
		t.Fatalf("canceled data writes attempted/confirmed=%d/%d, want %d/%d", attempted, confirmed, largeSubsetCancellationBootstrap, largeSubsetCancellationBootstrap)
	}
}

func largeSubsetLogs(t *testing.T) plog.Logs {
	t.Helper()
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	resource.Resource().Attributes().PutEmptyBytes("resource.bytes").FromRaw([]byte{1, 2, 3})
	scope := resource.ScopeLogs().AppendEmpty()
	scope.Scope().Attributes().PutEmptyBytes("scope.bytes").FromRaw([]byte{4, 5, 6})
	records := scope.LogRecords()
	base := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	for ordinal := 0; ordinal < largeSubsetRecords; ordinal++ {
		record := records.AppendEmpty()
		base.CopyTo(record)
		record.Attributes().PutInt("ordinal", int64(ordinal))
		record.Attributes().PutEmptyBytes("record.bytes").FromRaw([]byte{7, byte(ordinal), 9})
		if ordinal == 0 || ordinal == 65538 {
			record.Body().SetStr("invalid body")
		}
	}
	return logs
}

func assertLargeSubsetByteOwnership(t *testing.T, source, subset plog.Logs) {
	t.Helper()
	sourceResource := source.ResourceLogs().At(0)
	subsetResource := subset.ResourceLogs().At(0)
	sourceResourceBytes, ok := sourceResource.Resource().Attributes().Get("resource.bytes")
	if !ok {
		t.Fatal("source resource bytes missing")
	}
	subsetResourceBytes, ok := subsetResource.Resource().Attributes().Get("resource.bytes")
	if !ok {
		t.Fatal("subset resource bytes missing")
	}
	originalResource := subsetResourceBytes.Bytes().At(0)
	sourceResourceBytes.Bytes().SetAt(0, originalResource+10)
	if got := subsetResourceBytes.Bytes().At(0); got != originalResource {
		t.Fatalf("subset resource byte changed with source mutation: got %d, want %d", got, originalResource)
	}
	subsetResourceBytes.Bytes().SetAt(0, originalResource+20)
	if got := sourceResourceBytes.Bytes().At(0); got != originalResource+10 {
		t.Fatalf("source resource byte changed with subset mutation: got %d, want %d", got, originalResource+10)
	}

	sourceScope := sourceResource.ScopeLogs().At(0)
	subsetScope := subsetResource.ScopeLogs().At(0)
	sourceScopeBytes, ok := sourceScope.Scope().Attributes().Get("scope.bytes")
	if !ok {
		t.Fatal("source scope bytes missing")
	}
	subsetScopeBytes, ok := subsetScope.Scope().Attributes().Get("scope.bytes")
	if !ok {
		t.Fatal("subset scope bytes missing")
	}
	originalScope := subsetScopeBytes.Bytes().At(0)
	sourceScopeBytes.Bytes().SetAt(0, originalScope+10)
	if got := subsetScopeBytes.Bytes().At(0); got != originalScope {
		t.Fatalf("subset scope byte changed with source mutation: got %d, want %d", got, originalScope)
	}
	subsetScopeBytes.Bytes().SetAt(0, originalScope+20)
	if got := sourceScopeBytes.Bytes().At(0); got != originalScope+10 {
		t.Fatalf("source scope byte changed with subset mutation: got %d, want %d", got, originalScope+10)
	}

	sourceRecords := sourceScope.LogRecords()
	subsetRecords := subsetScope.LogRecords()
	for index := 0; index < subsetRecords.Len(); index++ {
		subsetRecord := subsetRecords.At(index)
		ordinal, ok := subsetRecord.Attributes().Get("ordinal")
		if !ok {
			t.Fatalf("subset record %d ordinal missing", index)
		}
		sourceRecord := sourceRecords.At(int(ordinal.Int()))
		sourceBytes, ok := sourceRecord.Attributes().Get("record.bytes")
		if !ok {
			t.Fatalf("source record %d bytes missing", ordinal.Int())
		}
		subsetBytes, ok := subsetRecord.Attributes().Get("record.bytes")
		if !ok {
			t.Fatalf("subset record %d bytes missing", ordinal.Int())
		}
		original := subsetBytes.Bytes().At(0)
		sourceBytes.Bytes().SetAt(0, original+10)
		if got := subsetBytes.Bytes().At(0); got != original {
			t.Fatalf("subset record %d byte changed with source mutation: got %d, want %d", ordinal.Int(), got, original)
		}
		subsetBytes.Bytes().SetAt(0, original+20)
		if got := sourceBytes.Bytes().At(0); got != original+10 {
			t.Fatalf("source record %d byte changed with subset mutation: got %d, want %d", ordinal.Int(), got, original+10)
		}
	}
}
