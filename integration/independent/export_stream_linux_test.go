package independent_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
)

type exportPacket struct {
	bytes    []byte
	phase    string
	sequence uint32
	shape    int
}

// Each independent receiver consumes this same public-factory live stream.
// The retained bytes are checked against goldens before unchanged forwarding.
func exportStream(t *testing.T, ctx context.Context, dir string, port int, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int) ([]exportPacket, []byte) {
	return exportStreamProfile(t, ctx, dir, port, protocol, ledger, tc, customLen, "")
}

// exportStreamProfile is the same live public-factory stream used by all
// independent receivers, with an optional profile override for a versioned
// profile that has no legacy ledger entry. The override is intentionally
// scoped to this test seam and never changes the authored receiver fixtures.
func exportStreamProfile(t *testing.T, ctx context.Context, dir string, port int, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int, profileOverride string) ([]exportPacket, []byte) {
	t.Helper()

	// Retain received exporter payloads before forwarding them unchanged over
	// one UDP socket. This captures application datagrams, not outer headers.
	capture := udpListener(t)
	forward, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	must(t, err)
	defer forward.Close()
	factory := netflowexporter.NewFactory()
	cfg := factory.CreateDefaultConfig().(*netflowexporter.Config)
	profile := ledger.Profile
	if profileOverride != "" {
		profile = profileOverride
	}
	cfg.Endpoint, cfg.Protocol, cfg.Mapping.Profile = capture.LocalAddr().String(), ledger.Protocol, &profile
	cfg.Mapping.LossPolicy = ptr(netflowexporter.LossPolicy("encode_and_count"))
	cfg.Mapping.ProtocolIdentifiers = []netflowexporter.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	logs := fixtureLogs(t, ledger, tc)
	if profileOverride == "contrib-netflowreceiver-v0.160.0/ipfix-general-v1" {
		for i := range logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len() {
			attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i).Attributes()
			attrs.PutInt("flow.start", 1788220800123456789)
			attrs.PutInt("flow.end", 1788220801123999999)
		}
	}
	if profileOverride == "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1" {
		origin := uint64(time.Now().Truncate(time.Second).Add(-5 * time.Second).UnixNano())
		cfg.UptimeOrigin = ptr(origin)
		for i := range logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len() {
			a := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i).Attributes()
			a.PutInt("flow.start", int64(origin+3_000_000_000))
			a.PutInt("flow.end", int64(origin+4_000_000_000))
		}
	}
	if protocol == "v5" {
		cfg.Identity.EngineType, cfg.Identity.EngineID = ptr(uint8(0)), ptr(uint8(0))
		cfg.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		cfg.UptimeOrigin = ptr(uint64(time.Now().Truncate(time.Millisecond).Add(-2 * time.Second).UnixNano()))
		a := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
		a.PutInt("flow.start", int64(*cfg.UptimeOrigin+1_000_000_000))
		a.PutInt("flow.end", int64(*cfg.UptimeOrigin+1_001_000_000))
	} else {
		cfg.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
		if protocol == "v9" {
			cfg.Identity.SourceID, cfg.NetFlowV9.TemplateRefreshPackets = ptr(uint32(42)), ptr(uint32(2))
		} else {
			cfg.Identity.ObservationDomainID, cfg.IPFIX.TemplateRefreshDataPackets = ptr(uint32(42)), ptr(uint32(2))
		}
	}
	var custom []byte
	if customLen >= 0 {
		custom = make([]byte, customLen)
		for i := range custom {
			custom[i] = byte(i % 251)
		}
		cfg.Mapping.Custom = []netflowexporter.CustomField{
			{Source: "vendor.fixed", PEN: ptr(uint32(32473)), ElementID: ptr(uint32(400)), Encoding: "octet_array", FixedLength: ptr(uint16(4))},
			{Source: "vendor.variable", PEN: ptr(uint32(32473)), ElementID: ptr(uint32(401)), Encoding: "octet_array", Variable: ptr(true), MaxLength: ptr(uint32(255))},
		}
		a := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
		a.PutEmptyBytes("vendor.fixed").FromRaw([]byte{0, 127, 128, 255})
		a.PutEmptyBytes("vendor.variable").FromRaw(custom)
	}
	must(t, cfg.Validate())
	writeJSON(t, filepath.Join(dir, "exporter-config.json"), cfg)
	ex, err := factory.CreateLogs(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	must(t, err)
	defer func() { must(t, ex.Shutdown(context.Background())) }()
	var packets []capturedPacket
	var stream []exportPacket
	defer func() { writeJSON(t, filepath.Join(dir, "datagrams.json"), packets) }()
	var source string
	receive := func(phase string, sequence uint32, shape int) []byte {
		t.Helper()
		must(t, capture.SetReadDeadline(time.Now().Add(3*time.Second)))
		buffer := make([]byte, 65507)
		n, addr, err := capture.ReadFromUDP(buffer)
		must(t, err)
		packet := buffer[:n]
		if source == "" {
			source = addr.String()
		} else if source != addr.String() {
			t.Fatal("exporter changed socket/epoch")
		}
		file := fmt.Sprintf("%02d-%s.bin", len(packets), phase)
		must(t, os.WriteFile(filepath.Join(dir, file), packet, 0600))
		packets = append(packets, capturedPacket{file, fmt.Sprintf("%x", sha256.Sum256(packet)), n, phase, sequence, source})
		stream = append(stream, exportPacket{packet, phase, sequence, shape})
		if profileOverride == "" {
			assertPacket(t, protocol, tc, packet, phase, sequence, shape, custom)
		} else if profileOverride == "contrib-netflowreceiver-v0.160.0/ipfix-general-v1" {
			assertGeneralPacket(t, packet, phase, sequence, shape, tc.ExpectedRecords)
		} else if profileOverride == "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1" {
			assertTimedPacket(t, packet, phase, sequence, shape, tc.ExpectedRecords)
		} else {
			t.Fatalf("unsupported profile override %q", profileOverride)
		}
		n, err = forward.Write(packet)
		must(t, err)
		if n != len(packet) {
			t.Fatal("partial forwarding datagram")
		}
		return packet
	}
	must(t, ex.Start(ctx, componenttest.NewNopHost()))
	sequence := uint32(0)
	if protocol != "v5" {
		for i := range 4 {
			receive("bootstrap", sequence, i%2)
			if protocol == "v9" {
				sequence++
			}
		}
	}
	// Reject a malformed input before any data or template-refresh state change.
	bad := plog.NewLogs()
	logs.CopyTo(bad)
	bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("raw replay is unsupported")
	if tc.ExpectedRecords == 2 {
		bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1).Body().SetStr("raw replay is unsupported")
	}
	if err := ex.ConsumeLogs(ctx, bad); !consumererror.IsPermanent(err) {
		t.Fatalf("expected permanent raw-body rejection: %v", err)
	}
	logs.MarkReadOnly()
	for round := range 3 {
		must(t, ex.ConsumeLogs(ctx, logs))
		dataShape := 0
		if strings.Contains(tc.Name, "ipv6") {
			dataShape = 1
		}
		receive("data", sequence, dataShape)
		if protocol == "v9" {
			sequence++
		} else {
			sequence += uint32(tc.ExpectedRecords)
		}
		if round == 1 && protocol != "v5" {
			for shape := range 2 {
				receive("refresh", sequence, shape)
				if protocol == "v9" {
					sequence++
				}
			}
		}
	}
	must(t, ex.Shutdown(ctx))
	must(t, capture.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	if _, _, err := capture.ReadFromUDP(make([]byte, 65507)); err == nil {
		t.Fatal("unexpected extra exporter datagram")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
	return stream, custom
}
