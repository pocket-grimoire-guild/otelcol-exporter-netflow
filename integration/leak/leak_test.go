//go:build integration

package leak_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	cycleCount   = 100
	warmupCycles = 2

	cycleTimeout = 10 * time.Second
	readTimeout  = 2 * time.Second

	// DNS refresh is the shortest accepted production interval. It creates a
	// real maintenance timer on every hostname cycle without making the 100
	// cycle check wait for a timer expiry.
	dnsRefreshInterval = time.Second
)

var leakProtocols = []string{"netflow_v5", "netflow_v9", "ipfix"}

var logSocketUnavailable sync.Once

type resourceSnapshot struct {
	goroutines int
	sockets    int
	hasSockets bool
}

func TestProcessLeakAcceptance(t *testing.T) {
	for _, protocol := range leakProtocols {
		t.Run(protocol, func(t *testing.T) {
			baseline := positiveControlBaseline(t)
			for range warmupCycles {
				runCycle(t, protocol)
			}
			warm := settleResources(t)
			if !sameResources(warm, baseline) {
				t.Fatalf("warmup resources did not return to baseline: got %+v want %+v", warm, baseline)
			}
			baseline = warm

			final := baseline
			for cycle := 0; cycle < cycleCount; cycle++ {
				runCycle(t, protocol)
				got := settleResources(t)
				if !sameResources(got, baseline) {
					t.Fatalf("cycle %d resources did not return to baseline: got %+v want %+v", cycle+1, got, baseline)
				}
				final = got
			}
			t.Logf("protocol=%s cycles=%d baseline-goroutines=%d final-goroutines=%d baseline-sockets=%d final-sockets=%d sockets-available=%t", protocol, cycleCount, baseline.goroutines, final.goroutines, baseline.sockets, final.sockets, final.hasSockets)
		})
	}
}

func runCycle(t *testing.T, protocol string) {
	t.Helper()
	listener, port := loopbackListener(t)
	defer listener.Close()
	cycleBaseline := currentResources(t)

	factory := netflowexporter.NewFactory()
	cfg := cycleConfig(protocol, port)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	exporter, err := factory.CreateLogs(context.Background(), exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	shutdown := false
	defer func() {
		if !shutdown {
			if err := exporter.Shutdown(context.Background()); err != nil {
				t.Errorf("deferred shutdown: %v", err)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), cycleTimeout)
	defer cancel()
	if err := exporter.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	bootstrap := 0
	if protocol != "netflow_v5" {
		bootstrap = 4
	}
	for range bootstrap {
		assertBootstrapPacket(t, protocol, readPacket(t, listener))
	}
	active := currentResources(t)
	if active.goroutines <= cycleBaseline.goroutines {
		t.Fatal("live exporter maintenance goroutine was not observed")
	}
	if cycleBaseline.hasSockets && (!active.hasSockets || active.sockets <= cycleBaseline.sockets) {
		t.Fatalf("live exporter socket was not observed: active=%+v baseline=%+v", active, cycleBaseline)
	}

	logs := canonicalLogs(protocol, cfg)
	if err := exporter.ConsumeLogs(ctx, logs); err != nil {
		t.Fatal(err)
	}
	assertDataPacket(t, protocol, readPacket(t, listener))

	if err := exporter.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	shutdown = true

	if err := exporter.ConsumeLogs(context.Background(), logs); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatalf("valid record after shutdown: got %v, want %v", err, destination.ErrRuntimeClosed)
	}
	if err := listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listener.ReadFromUDP(make([]byte, 65507)); err == nil {
		t.Fatal("packet arrived after shutdown")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("post-shutdown read: %v", err)
	}
	closed := currentResources(t)
	runtime.KeepAlive(exporter)
	if !sameResources(closed, cycleBaseline) {
		t.Fatalf("resources did not close while exporter was live: got %+v want %+v", closed, cycleBaseline)
	}
}

func cycleConfig(protocol string, port int) *netflowexporter.Config {
	factory := netflowexporter.NewFactory()
	cfg := factory.CreateDefaultConfig().(*netflowexporter.Config)
	cfg.Endpoint = net.JoinHostPort("localhost", strconv.Itoa(port))
	cfg.Protocol = protocol
	cfg.Mapping.LossPolicy = ptr(netflowexporter.LossPolicy("encode_and_count"))
	cfg.Mapping.ProtocolIdentifiers = []netflowexporter.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	cfg.DNS.RefreshInterval = dnsRefreshInterval
	cfg.DNS.StaleAfter = dnsRefreshInterval

	switch protocol {
	case "netflow_v5":
		cfg.Mapping.Profile = ptr(mapping.ProfileV5)
		cfg.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		cfg.Identity.EngineType = ptr(uint8(0))
		cfg.Identity.EngineID = ptr(uint8(0))
		cfg.UptimeOrigin = ptr(uint64(time.Now().Truncate(time.Millisecond).Add(-2 * time.Second).UnixNano()))
	case "netflow_v9":
		cfg.Mapping.Profile = ptr(mapping.ProfileV9)
		cfg.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
		cfg.Identity.SourceID = ptr(uint32(42))
	case "ipfix":
		cfg.Mapping.Profile = ptr(mapping.ProfileIPFIX)
		cfg.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
		cfg.Identity.ObservationDomainID = ptr(uint32(42))
	}
	return cfg
}

func canonicalLogs(protocol string, cfg *netflowexporter.Config) plog.Logs {
	logs := testpdata.CanonicalLogs()
	if protocol == "netflow_v5" {
		attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
		attrs.PutInt("flow.start", int64(*cfg.UptimeOrigin+1_000_000_000))
		attrs.PutInt("flow.end", int64(*cfg.UptimeOrigin+1_001_000_000))
	}
	logs.MarkReadOnly()
	return logs
}

func loopbackListener(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return listener, listener.LocalAddr().(*net.UDPAddr).Port
}

func readPacket(t *testing.T, listener *net.UDPConn) []byte {
	t.Helper()
	if err := listener.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65507)
	n, addr, err := listener.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || addr == nil || !addr.IP.IsLoopback() {
		t.Fatalf("invalid loopback datagram from %v, length %d", addr, n)
	}
	return packet[:n]
}

func assertBootstrapPacket(t *testing.T, protocol string, packet []byte) {
	t.Helper()
	wantVersion := uint16(0)
	setOffset := 0
	switch protocol {
	case "netflow_v9":
		wantVersion, setOffset = 9, 20
	case "ipfix":
		wantVersion, setOffset = 10, 16
	default:
		t.Fatal("v5 has no bootstrap packet")
	}
	if len(packet) < 2 {
		t.Fatalf("bootstrap packet too short: length=%d", len(packet))
	}
	if len(packet) < setOffset+2 || binary.BigEndian.Uint16(packet[:2]) != wantVersion {
		t.Fatalf("bootstrap packet version/length: version=%d length=%d", binary.BigEndian.Uint16(packet[:2]), len(packet))
	}
	if setID := binary.BigEndian.Uint16(packet[setOffset:]); setID >= 256 {
		t.Fatalf("bootstrap packet has data set id %d", setID)
	}
}

func assertDataPacket(t *testing.T, protocol string, packet []byte) {
	t.Helper()
	switch protocol {
	case "netflow_v5":
		if len(packet) < 2 {
			t.Fatalf("v5 data packet too short: length=%d", len(packet))
		}
		if len(packet) != 72 || binary.BigEndian.Uint16(packet[:2]) != 5 || binary.BigEndian.Uint16(packet[2:4]) != 1 {
			t.Fatalf("v5 data packet version/length: version=%d length=%d", binary.BigEndian.Uint16(packet[:2]), len(packet))
		}
	case "netflow_v9":
		assertDataSet(t, packet, 9, 20)
	case "ipfix":
		assertDataSet(t, packet, 10, 16)
	}
}

func assertDataSet(t *testing.T, packet []byte, version uint16, setOffset int) {
	t.Helper()
	if len(packet) < 2 {
		t.Fatalf("data packet too short: length=%d", len(packet))
	}
	if len(packet) < setOffset+4 || binary.BigEndian.Uint16(packet[:2]) != version {
		t.Fatalf("data packet version/length: version=%d length=%d", binary.BigEndian.Uint16(packet[:2]), len(packet))
	}
	wantLength := 68
	if version == 10 {
		wantLength = 92
	}
	if len(packet) != wantLength || int(binary.BigEndian.Uint16(packet[setOffset+2:])) != len(packet)-setOffset {
		t.Fatalf("data packet payload length: packet=%d set=%d want packet=%d", len(packet), binary.BigEndian.Uint16(packet[setOffset+2:]), wantLength)
	}
	if setID := binary.BigEndian.Uint16(packet[setOffset:]); setID < 256 {
		t.Fatalf("data packet has template set id %d", setID)
	}
}

func positiveControlBaseline(t *testing.T) resourceSnapshot {
	t.Helper()
	baseline := settleResources(t)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listenerClosed := false
	defer func() {
		if !listenerClosed {
			_ = listener.Close()
		}
	}()
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	go func() {
		close(started)
		<-release
	}()
	<-started
	live := currentResources(t)
	if live.goroutines <= baseline.goroutines {
		t.Fatalf("goroutine positive control was invisible: live=%+v baseline=%+v", live, baseline)
	}
	if baseline.hasSockets {
		if !live.hasSockets || live.sockets <= baseline.sockets {
			t.Fatalf("socket positive control was invisible: live=%+v baseline=%+v", live, baseline)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	listenerClosed = true
	once.Do(func() { close(release) })
	settled := settleResources(t)
	if !sameResources(settled, baseline) {
		t.Fatalf("positive control cleanup did not return to baseline: got %+v want %+v", settled, baseline)
	}
	return settled
}

func settleResources(t *testing.T) resourceSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var previous resourceSnapshot
	stable := 0
	for {
		current := currentResources(t)
		if stable > 0 && sameResources(current, previous) {
			stable++
		} else {
			stable = 1
		}
		if stable >= 5 {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("resources did not settle: current=%+v previous=%+v", current, previous)
		}
		previous = current
		time.Sleep(20 * time.Millisecond)
	}
}

func currentResources(t *testing.T) resourceSnapshot {
	t.Helper()
	sockets, hasSockets := processSocketCount()
	if !hasSockets {
		logSocketUnavailable.Do(func() {
			t.Log("OS socket measurement unavailable; continuing functional and goroutine checks")
		})
	}
	return resourceSnapshot{goroutines: runtime.NumGoroutine(), sockets: sockets, hasSockets: hasSockets}
}

func sameResources(a, b resourceSnapshot) bool {
	if a.goroutines != b.goroutines || a.hasSockets != b.hasSockets {
		return false
	}
	return !a.hasSockets || a.sockets == b.sockets
}

func ptr[T any](value T) *T { return &value }
