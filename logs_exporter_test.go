package netflowexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestFactory(t *testing.T) {
	f := NewFactory()
	if f.Type().String() != "netflow" || f.LogsStability() != component.StabilityLevelAlpha {
		t.Fatal("factory metadata")
	}
	if f.CreateDefaultConfig() == f.CreateDefaultConfig() {
		t.Fatal("shared config")
	}
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			c := validConfig(protocol)
			c.Endpoint = listener.LocalAddr().String()
			if protocol == "netflow_v5" {
				c.UptimeOrigin = ptr(uint64(time.Now().Truncate(time.Millisecond).Add(-2 * time.Second).UnixNano()))
			}
			// Real connected UDP and public factory lifecycle; fixture origin is stable.
			e, err := f.CreateLogs(context.Background(), exportertest.NewNopSettings(f.Type()), c)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Shutdown(context.Background())
			if e.Capabilities().MutatesData {
				t.Fatal("mutates pdata")
			}
			if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			logs := testpdata.CanonicalLogs()
			if protocol == "netflow_v5" {
				attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
				attrs.PutInt("flow.start", int64(*c.UptimeOrigin+1_000_000_000))
				attrs.PutInt("flow.end", int64(*c.UptimeOrigin+1_001_000_000))
			}
			logs.MarkReadOnly()
			if err = e.ConsumeLogs(context.Background(), logs); err != nil {
				t.Fatal(err)
			}
			templates := 4
			version, header, goldenStart := uint16(9), 20, 100
			folder := "v9"
			switch protocol {
			case "netflow_v5":
				templates = 0
				version = 5
				header = 24
				goldenStart = 24
				folder = "v5"
			case "ipfix":
				version = 10
				header = 16
				goldenStart = 104
				folder = "ipfix"
			}
			_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 65507)
			for i := 0; i <= templates; i++ {
				n, _, err := listener.ReadFromUDP(buffer)
				if err != nil {
					t.Fatal(err)
				}
				packet := buffer[:n]
				if binary.BigEndian.Uint16(packet) != version {
					t.Fatal("version")
				}
				if i < templates {
					continue
				}
				// Golden payloads are independently authored by the checked Python fixture
				// generator. Compare the entire data set/record (including padding), while
				// live header time and instance identity are intentionally different.
				golden, err := os.ReadFile("integration/testdata/golden/" + folder + "/canonical-ipv4-v1.bin")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(packet[header:], golden[goldenStart:]) {
					t.Fatalf("data bytes\ngot %x\nwant %x", packet[header:], golden[goldenStart:])
				}
				switch version {
				case 5:
					if binary.BigEndian.Uint32(packet[16:]) != 0 {
						t.Fatal("v5 sequence")
					}
				case 9:
					if binary.BigEndian.Uint32(packet[12:]) != uint32(templates) {
						t.Fatal("v9 bootstrap sequence")
					}
				case 10:
					if binary.BigEndian.Uint32(packet[8:]) != 0 {
						t.Fatal("IPFIX templates counted as records")
					}
				}
			}
			if err = e.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = e.ConsumeLogs(context.Background(), logs); !errors.Is(err, destination.ErrRuntimeClosed) {
				t.Fatalf("post-close %v", err)
			}
		})
	}
}

type countedConn struct {
	*testtransport.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }
func fakeExporter(t *testing.T, c *Config, steps ...testtransport.WriteStep) (*logsExporter, *countedConn) {
	t.Helper()
	remote := netip.MustParseAddrPort(c.Endpoint)
	conn := &countedConn{Conn: testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), remote, steps...)}
	e, err := newLogsExporter(context.Background(), exportertest.NewNopSettings(NewFactory().Type()), c, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e, conn
}
func bootstrapSteps(protocol string) []testtransport.WriteStep {
	if protocol == "netflow_v5" {
		return nil
	}
	size := 100
	if protocol == "ipfix" {
		size = 104
	}
	return []testtransport.WriteStep{{N: size}, {N: size}, {N: size}, {N: size}}
}
func packetLength(protocol string) int {
	switch protocol {
	case "netflow_v5":
		return 72
	case "netflow_v9":
		return 68
	default:
		return 92
	}
}
func mixedLogs() plog.Logs {
	logs := plog.NewLogs()
	canonical := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	for i := 0; i < 3; i++ {
		r := logs.ResourceLogs().AppendEmpty()
		r.SetSchemaUrl("resource-schema")
		r.Resource().Attributes().PutInt("resource", int64(i))
		for j := 0; j < 2; j++ {
			s := r.ScopeLogs().AppendEmpty()
			s.SetSchemaUrl("scope-schema")
			s.Scope().SetName("scope")
			s.Scope().SetVersion("version")
			record := s.LogRecords().AppendEmpty()
			canonical.CopyTo(record)
			ordinal := i*2 + j
			record.Attributes().PutInt("ordinal", int64(ordinal))
			if ordinal == 1 || ordinal == 3 {
				record.Body().SetStr("unsupported raw secret")
			}
		}
	}
	return logs
}
func TestReturnedSubset(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			for _, failure := range []testtransport.WriteStep{{N: 0}, {N: 1}, {N: 0, Err: errors.New("secret")}, {N: 1, Err: errors.New("secret")}, {N: packetLength(protocol), Err: errors.New("secret")}} {
				c := validConfig(protocol)
				c.MaxRecordsPerMessage = ptr(uint16(1))
				steps := append(bootstrapSteps(protocol), testtransport.WriteStep{N: packetLength(protocol)}, failure)
				e, conn := fakeExporter(t, c, steps...)
				if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
					t.Fatal(err)
				}
				logs := mixedLogs()
				original, _ := normalize.Inspect(logs)
				logs.MarkReadOnly()
				err := e.ConsumeLogs(context.Background(), logs)
				subsetErr, ok := errors.AsType[consumererror.Logs](err)
				if !ok || consumererror.IsPermanent(err) {
					t.Fatalf("expected transient subset: %v", err)
				}
				subset := subsetErr.Data()
				stats, err := normalize.Inspect(subset)
				if err != nil {
					t.Fatal(err)
				}
				if subset.LogRecordCount() != 3 || stats.Records > original.Records {
					t.Fatal("subset occupancy/count")
				}
				cursor := logCursor{logs: subset}
				for i, want := range []int64{2, 4, 5} {
					record, ok := cursor.at(uint64(i))
					if !ok {
						t.Fatal("missing subset")
					}
					got, _ := record.Attributes().Get("ordinal")
					if got.Int() != want {
						t.Fatalf("ordinal %d != %d", got.Int(), want)
					}
				}
				if subset.ResourceLogs().Len() != 2 || subset.ResourceLogs().At(0).ScopeLogs().Len() != 1 || subset.ResourceLogs().At(1).ScopeLogs().Len() != 2 {
					t.Fatal("hierarchy copied incorrectly")
				}
				for _, r := range []plog.ResourceLogs{subset.ResourceLogs().At(0), subset.ResourceLogs().At(1)} {
					if r.SchemaUrl() != "resource-schema" {
						t.Fatal("resource provenance")
					}
					for j := 0; j < r.ScopeLogs().Len(); j++ {
						s := r.ScopeLogs().At(j)
						if s.SchemaUrl() != "scope-schema" || s.Scope().Name() != "scope" || s.Scope().Version() != "version" {
							t.Fatal("scope provenance")
						}
					}
				}
				// Copied pdata is independent even though the caller marked its input read-only.
				first, _ := cursor.at(2)
				first.Attributes().PutInt("ordinal", 99)
				if logs.LogRecordCount() != 6 {
					t.Fatal("input mutated")
				}
				writes := 0
				for _, event := range conn.Events() {
					if event.Kind == testtransport.EventWrite {
						writes++
					}
				}
				if writes != len(steps) {
					t.Fatal("suffix write/retry")
				}
				if err := e.Shutdown(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestAdmission(t *testing.T) {
	c := validConfig("netflow_v5")
	entered := make(chan struct{})
	e, conn := fakeExporter(t, c, testtransport.WriteStep{N: 72, Started: entered, Wait: make(chan struct{})})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("write did not enter")
	}
	if err := e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeBusy) {
		t.Fatalf("busy read malformed pdata: %v", err)
	}
	closed := make(chan error, 4)
	for range 4 {
		go func() { closed <- e.Shutdown(context.Background()) }()
	}
	for range 4 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown blocked")
		}
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("interrupted write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("consume not joined")
	}
	if conn.closes.Load() != 1 {
		t.Fatal("handle closed more than once")
	}
	if err := e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatal(err)
	}
	// Malformed root failure does not enter the helper at all.
	e2, _ := fakeExporter(t, c)
	counter := &countHelper{Logs: e2.helper}
	e2.helper = counter
	if err := e2.ConsumeLogs(context.Background(), plog.Logs{}); !consumererror.IsPermanent(err) || counter.consumes.Load() != 0 {
		t.Fatalf("preflight entered helper: %v", err)
	}
}

func TestCustomBytes(t *testing.T) {
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			sizes := []int{3}
			if protocol == "ipfix" {
				sizes = []int{0, 3, 255}
			}
			for _, size := range sizes {
				listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				c := validConfig(protocol)
				c.Endpoint = listener.LocalAddr().String()
				c.Mapping.Profile = nil
				c.Mapping.Fields = ptr([]FieldSelection{{Canonical: "source.port"}})
				c.Mapping.ProtocolIdentifiers = nil
				c.Mapping.NetworkTypeVersions = nil
				c.Mapping.LossPolicy = ptr(LossPolicy("reject"))
				custom := CustomField{Source: "vendor.bytes", Encoding: "octet_array"}
				if protocol == "netflow_v9" {
					custom.FieldType = ptr(uint32(40000))
					custom.AllowPrivate = ptr(true)
					custom.FixedLength = ptr(uint16(size))
				} else {
					custom.PEN = ptr(uint32(32473))
					custom.ElementID = ptr(uint32(1))
					custom.Variable = ptr(true)
					custom.MaxLength = ptr(uint32(255))
				}
				c.Mapping.Custom = []CustomField{custom}
				e, err := newLogsExporter(context.Background(), exportertest.NewNopSettings(NewFactory().Type()), c, testclock.New(1788220802000000000, 0), transport.NewDialer("udp", netip.AddrPort{}).Dial)
				if err != nil {
					t.Fatal(err)
				}
				if err = e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
					t.Fatal(err)
				}
				logs := testpdata.CanonicalLogs()
				value := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutEmptyBytes("vendor.bytes")
				for i := 0; i < size; i++ {
					value.Append(byte(i))
				}
				logs.MarkReadOnly()
				if err = e.ConsumeLogs(context.Background(), logs); err != nil {
					t.Fatal(err)
				}
				_ = listener.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 464)
				// The family-independent explicit catalog has one shape, two copies.
				for i := 0; i < 3; i++ {
					n, _, err := listener.ReadFromUDP(buf)
					if err != nil {
						t.Fatal(err)
					}
					if i < 2 {
						continue
					}
					header := 20
					if protocol == "ipfix" {
						header = 16
					}
					want := []byte{1, 0, 0, 0, 0x30, 0x39} // Set ID 256, length below, source.port 12345
					if protocol == "ipfix" {
						if size < 255 {
							want = append(want, byte(size))
						} else {
							want = append(want, 255, 0, 255)
						}
					}
					for j := 0; j < size; j++ {
						want = append(want, byte(j))
					}
					// IPFIX may only pad less than its three-byte minimum record size.
					padding := (4 - len(want)%4) % 4
					if protocol == "netflow_v9" || padding < 3 {
						want = append(want, make([]byte, padding)...)
					}
					binary.BigEndian.PutUint16(want[2:4], uint16(len(want)))
					if !bytes.Equal(buf[header:n], want) {
						t.Fatalf("custom payload size %d: got %x want %x", size, buf[header:n], want)
					}
				}
				if err = e.Shutdown(context.Background()); err != nil {
					t.Fatal(err)
				}
				listener.Close()
			}
		})
	}
}
