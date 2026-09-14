//go:build integration

package netflowexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	loadDefaultRecords     = 100000
	loadDefaultBatch       = 100
	loadDefaultBatches     = loadDefaultRecords / loadDefaultBatch
	ignoredMetadataRecords = 7
	ipfixSelectedCoreWidth = 72
)

type loadConn struct {
	local, remote netip.AddrPort
	closed        atomic.Bool
	attempted     atomic.Uint64
	confirmed     atomic.Uint64
	bytes         atomic.Uint64
	failAfter     atomic.Uint64
	failEnabled   atomic.Bool

	mu        sync.Mutex
	capture   bool
	packets   [][]byte
	sequences []uint32
}

func newLoadConn(remote netip.AddrPort) *loadConn {
	return &loadConn{local: netip.MustParseAddrPort("127.0.0.1:40000"), remote: remote}
}

func (c *loadConn) LocalAddr() netip.AddrPort  { return c.local }
func (c *loadConn) RemoteAddr() netip.AddrPort { return c.remote }
func (c *loadConn) SetWriteDeadline(time.Time) error {
	if c.closed.Load() {
		return transport.ErrClosed
	}
	return nil
}
func (c *loadConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *loadConn) resetSamples() {
	c.mu.Lock()
	c.packets = nil
	c.sequences = nil
	c.mu.Unlock()
	c.attempted.Store(0)
	c.confirmed.Store(0)
	c.bytes.Store(0)
}
func (c *loadConn) setCapture(enabled bool) {
	c.mu.Lock()
	c.capture = enabled
	c.mu.Unlock()
}
func (c *loadConn) Write(payload []byte) (int, error) {
	attempt := c.attempted.Add(1)
	if c.closed.Load() {
		return 0, transport.ErrClosed
	}
	full := !c.failEnabled.Load() || attempt <= c.failAfter.Load()
	if full {
		c.confirmed.Add(1)
		c.bytes.Add(uint64(len(payload)))
	}
	c.mu.Lock()
	if c.capture {
		c.packets = append(c.packets, append([]byte(nil), payload...))
	}
	if len(payload) >= 12 && binary.BigEndian.Uint16(payload) == 10 {
		c.sequences = append(c.sequences, binary.BigEndian.Uint32(payload[8:12]))
	}
	c.mu.Unlock()
	if !full {
		return len(payload) - 1, errors.New("load: deterministic short write")
	}
	return len(payload), nil
}
func (c *loadConn) samples() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint32(nil), c.sequences...)
}
func (c *loadConn) capturedPackets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	packets := make([][]byte, len(c.packets))
	for i := range c.packets {
		packets[i] = append([]byte(nil), c.packets[i]...)
	}
	return packets
}

func ipfixLoadConfig() *Config {
	c := validConfig("ipfix")
	c.Endpoint = "127.0.0.1:4739"
	c.MaxDatagramSize = 65507
	c.PathMTU = ptr(uint64(65535))
	c.MaxRecordsPerMessage = ptr(uint16(1))
	return c
}

var functionalIPFIXFields = []FieldSelection{
	{Canonical: "flow.io.bytes", Target: "octet_delta_count"},
	{Canonical: "flow.io.packets", Target: "packet_delta_count"},
	{Canonical: "network.transport"},
	{Canonical: "flow.ip_tos"},
	{Canonical: "flow.tcp_flags"},
	{Canonical: "source.port"},
	{Canonical: "source.address"},
	{Canonical: "flow.src_net"},
	{Canonical: "flow.in_if"},
	{Canonical: "destination.port"},
	{Canonical: "destination.address"},
	{Canonical: "flow.dst_net"},
	{Canonical: "flow.out_if"},
	{Canonical: "flow.src_as"},
	{Canonical: "flow.dst_as"},
	{Canonical: "flow.sampling_rate"},
	{Canonical: "flow.ip_ttl"},
	{Canonical: "network.type", Target: "ip_version"},
	{Canonical: "flow.start"},
	{Canonical: "flow.end"},
}

func variableOctetConfig() *Config {
	c := ipfixLoadConfig()
	c.Endpoint = "192.0.2.200:2055"
	c.MaxRecordsPerMessage = nil
	c.Mapping.Profile = nil
	fields := append([]FieldSelection(nil), functionalIPFIXFields...)
	c.Mapping.Fields = &fields
	names := testpdata.VariableOctetFieldNames()
	c.Mapping.Custom = make([]CustomField, len(names))
	for i, name := range names {
		pen, element, variable, maxLength := uint32(32473), uint32(100+i), true, uint32(4096)
		c.Mapping.Custom[i] = CustomField{Source: name, PEN: &pen, ElementID: &element, Encoding: "octet_array", Variable: &variable, MaxLength: &maxLength}
	}
	return c
}

func loadExporter(t *testing.T, c *Config, conn *loadConn) *logsExporter {
	t.Helper()
	set := exportertest.NewNopSettings(NewFactory().Type())
	e, err := newLogsExporter(context.Background(), set, c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	conn.resetSamples()
	return e
}

func dataPackets(packets [][]byte) [][]byte {
	data := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		if len(packet) >= 20 && binary.BigEndian.Uint16(packet) == 10 && binary.BigEndian.Uint16(packet[16:]) >= 256 {
			data = append(data, packet)
		}
	}
	return data
}

func assertIPFIXSequences(t *testing.T, packets [][]byte, want int) {
	t.Helper()
	if len(packets) != want {
		t.Fatalf("IPFIX data packets=%d, want %d", len(packets), want)
	}
	for i, packet := range packets {
		if got := binary.BigEndian.Uint32(packet[8:12]); got != uint32(i) {
			t.Fatalf("IPFIX packet %d sequence=%d, want %d", i, got, i)
		}
	}
}

func TestLoadDefault(t *testing.T) {
	conn := newLoadConn(netip.MustParseAddrPort("127.0.0.1:4739"))
	e := loadExporter(t, ipfixLoadConfig(), conn)
	batchLogs := testpdata.CanonicalBatch(loadDefaultBatch)
	batchLogs.MarkReadOnly()
	for batch := 0; batch < loadDefaultBatches; batch++ {
		if err := e.ConsumeLogs(context.Background(), batchLogs); err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
	}
	if got := conn.attempted.Load(); got != loadDefaultRecords {
		t.Fatalf("attempted data packets=%d, want %d", got, loadDefaultRecords)
	}
	if got := conn.confirmed.Load(); got != loadDefaultRecords {
		t.Fatalf("confirmed data packets=%d, want %d", got, loadDefaultRecords)
	}
	sequences := conn.samples()
	if len(sequences) != loadDefaultRecords {
		t.Fatalf("IPFIX sequence samples=%d, want %d", len(sequences), loadDefaultRecords)
	}
	for i, sequence := range sequences {
		if sequence != uint32(i) {
			t.Fatalf("IPFIX packet %d sequence=%d, want %d", i, sequence, i)
		}
	}
}

func TestLoadIgnoredMetadata(t *testing.T) {
	conn := newLoadConn(netip.MustParseAddrPort("127.0.0.1:4739"))
	e := loadExporter(t, ipfixLoadConfig(), conn)
	conn.setCapture(true)
	counter := &countHelper{Logs: e.helper}
	e.helper = counter
	logs := testpdata.IgnoredMetadataLogs(ignoredMetadataRecords)
	logs.MarkReadOnly()
	if err := e.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("ignored metadata export: %v", err)
	}
	if counter.consumes.Load() != 1 {
		t.Fatalf("ignored metadata helper calls=%d, want 1", counter.consumes.Load())
	}
	packets := dataPackets(conn.capturedPackets())
	assertIPFIXSequences(t, packets, ignoredMetadataRecords)
	if got := conn.attempted.Load(); got != ignoredMetadataRecords {
		t.Fatalf("ignored metadata attempted packets=%d, want %d", got, ignoredMetadataRecords)
	}
	if got := conn.confirmed.Load(); got != ignoredMetadataRecords {
		t.Fatalf("ignored metadata confirmed packets=%d, want %d", got, ignoredMetadataRecords)
	}
}

func TestLoadVariableOctetPackets(t *testing.T) {
	conn := newLoadConn(netip.MustParseAddrPort("192.0.2.200:2055"))
	e := loadExporter(t, variableOctetConfig(), conn)
	conn.setCapture(true)
	logs := testpdata.VariableOctetLogs()
	logs.MarkReadOnly()
	if err := e.ConsumeLogs(context.Background(), logs); err != nil {
		t.Fatalf("variable octet export: %v", err)
	}
	packets := dataPackets(conn.capturedPackets())
	assertIPFIXSequences(t, packets, testpdata.VariableOctetRecordCount)
	if got := conn.attempted.Load(); got != testpdata.VariableOctetRecordCount {
		t.Fatalf("variable octet attempted packets=%d, want %d", got, testpdata.VariableOctetRecordCount)
	}
	if got := conn.confirmed.Load(); got != testpdata.VariableOctetRecordCount {
		t.Fatalf("variable octet confirmed packets=%d, want %d", got, testpdata.VariableOctetRecordCount)
	}
	names := testpdata.VariableOctetFieldNames()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	var packetBytes uint64
	for i, packet := range packets {
		packetBytes += uint64(len(packet))
		attrs := records.At(i).Attributes()
		assertVariableOctetPacket(t, packet, attrs, names, i)
	}
	if got := conn.bytes.Load(); got != packetBytes {
		t.Fatalf("variable octet bytes=%d, want sum of data packets %d", got, packetBytes)
	}
}

func assertVariableOctetPacket(t *testing.T, packet []byte, attrs pcommon.Map, names []string, recordIndex int) {
	t.Helper()
	if len(packet) <= 40<<10 || len(packet) > 65507 {
		t.Fatalf("variable octet packet %d length=%d, want between 40KiB and UDP payload limit", recordIndex, len(packet))
	}
	if binary.BigEndian.Uint16(packet) != 10 {
		t.Fatalf("variable octet packet %d version=%d, want IPFIX", recordIndex, binary.BigEndian.Uint16(packet))
	}
	if got := int(binary.BigEndian.Uint16(packet[2:4])); got != len(packet) {
		t.Fatalf("variable octet packet %d message length=%d, want %d", recordIndex, got, len(packet))
	}
	setLength := int(binary.BigEndian.Uint16(packet[18:20]))
	if setLength != len(packet)-16 || binary.BigEndian.Uint16(packet[16:18]) != 256 {
		t.Fatalf("variable octet packet %d set id=%d length=%d, want data set and %d", recordIndex, binary.BigEndian.Uint16(packet[16:18]), setLength, len(packet)-16)
	}
	cursor := 20 + ipfixSelectedCoreWidth
	for _, name := range names {
		value, ok := attrs.Get(name)
		if !ok || value.Type() != pcommon.ValueTypeBytes {
			t.Fatalf("record %d custom field %q missing", recordIndex, name)
		}
		want := value.Bytes().AsRaw()
		if cursor+3 > len(packet) || packet[cursor] != 0xff {
			t.Fatalf("record %d custom field %q missing two-octet variable length at offset %d", recordIndex, name, cursor)
		}
		gotLength := int(binary.BigEndian.Uint16(packet[cursor+1 : cursor+3]))
		if gotLength != len(want) {
			t.Fatalf("record %d custom field %q length=%d, want %d", recordIndex, name, gotLength, len(want))
		}
		cursor += 3
		if cursor+gotLength > len(packet) || !bytes.Equal(packet[cursor:cursor+gotLength], want) {
			t.Fatalf("record %d custom field %q bytes differ", recordIndex, name)
		}
		cursor += gotLength
	}
	if wantLength := (cursor + 3) &^ 3; len(packet) != wantLength {
		t.Fatalf("record %d message length=%d, want aligned data end %d", recordIndex, len(packet), wantLength)
	}
	for _, padding := range packet[cursor:] {
		if padding != 0 {
			t.Fatalf("record %d nonzero data-set padding byte=%d", recordIndex, padding)
		}
	}
}

func TestLoadVariableOctetSubsetOwnership(t *testing.T) {
	conn := newLoadConn(netip.MustParseAddrPort("192.0.2.200:2055"))
	e := loadExporter(t, variableOctetConfig(), conn)
	logs := testpdata.VariableOctetLogs()
	conn.failAfter.Store(conn.attempted.Load())
	conn.failEnabled.Store(true)
	err := e.ConsumeLogs(context.Background(), logs)
	logsErr, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) {
		t.Fatalf("variable octet failure=%v, want transient subset", err)
	}
	if conn.attempted.Load() != 1 || conn.confirmed.Load() != 0 {
		t.Fatalf("variable octet handoff attempted=%d confirmed=%d, want 1/0", conn.attempted.Load(), conn.confirmed.Load())
	}
	sequences := conn.samples()
	if len(sequences) != 1 || sequences[0] != 0 {
		t.Fatalf("variable octet handoff sequences=%v, want [0]", sequences)
	}
	subset := logsErr.Data()
	if subset.LogRecordCount() != testpdata.VariableOctetRecordCount {
		t.Fatalf("subset records=%d, want %d", subset.LogRecordCount(), testpdata.VariableOctetRecordCount)
	}
	assertVariableOctetValues(t, logs, subset)
	assertVariableOctetOwnership(t, logs, subset)
}

func assertVariableOctetValues(t *testing.T, source, subset plog.Logs) {
	t.Helper()
	sourceRecords := source.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	subsetRecords := subset.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	names := testpdata.VariableOctetFieldNames()
	if sourceRecords.Len() != subsetRecords.Len() {
		t.Fatalf("source/subset record counts=%d/%d", sourceRecords.Len(), subsetRecords.Len())
	}
	for recordIndex := 0; recordIndex < sourceRecords.Len(); recordIndex++ {
		sourceRecord, subsetRecord := sourceRecords.At(recordIndex), subsetRecords.At(recordIndex)
		for _, field := range functionalIPFIXFields {
			sourceValue, sourceOK := sourceRecord.Attributes().Get(field.Canonical)
			subsetValue, subsetOK := subsetRecord.Attributes().Get(field.Canonical)
			if !sourceOK || !subsetOK || !equalLoadValue(sourceValue, subsetValue) {
				t.Fatalf("selected value not preserved at record=%d field=%s", recordIndex, field.Canonical)
			}
		}
		for _, name := range names {
			sourceValue, sourceOK := sourceRecord.Attributes().Get(name)
			subsetValue, subsetOK := subsetRecord.Attributes().Get(name)
			if !sourceOK || !subsetOK || sourceValue.Type() != pcommon.ValueTypeBytes || subsetValue.Type() != pcommon.ValueTypeBytes || !sourceValue.Bytes().Equal(subsetValue.Bytes()) {
				t.Fatalf("custom bytes not preserved at record=%d field=%s", recordIndex, name)
			}
		}
	}
}

func assertVariableOctetOwnership(t *testing.T, source, subset plog.Logs) {
	t.Helper()
	names := testpdata.VariableOctetFieldNames()
	sourceValue, sourceOK := source.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get(names[0])
	subsetValue, subsetOK := subset.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get(names[0])
	if !sourceOK || !subsetOK || sourceValue.Type() != pcommon.ValueTypeBytes || subsetValue.Type() != pcommon.ValueTypeBytes {
		t.Fatal("ownership fixture custom field missing")
	}
	sourceBefore := sourceValue.Bytes().At(0)
	subsetBefore := subsetValue.Bytes().At(0)
	subsetValue.Bytes().SetAt(0, subsetBefore^0xff)
	if got := sourceValue.Bytes().At(0); got != sourceBefore {
		t.Fatalf("mutating subset changed source byte from %d to %d", sourceBefore, got)
	}
	sourceValue.Bytes().SetAt(1, sourceValue.Bytes().At(1)^0xff)
	if got := subsetValue.Bytes().At(1); got == sourceValue.Bytes().At(1) {
		t.Fatalf("mutating source changed subset byte to %d", got)
	}
}

func equalLoadValue(left, right pcommon.Value) bool {
	if left.Type() != right.Type() {
		return false
	}
	switch left.Type() {
	case pcommon.ValueTypeStr:
		return left.Str() == right.Str()
	case pcommon.ValueTypeInt:
		return left.Int() == right.Int()
	case pcommon.ValueTypeBytes:
		return left.Bytes().Equal(right.Bytes())
	default:
		return false
	}
}
