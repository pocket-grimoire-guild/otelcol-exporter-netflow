package netflowexporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// refreshLogs keeps each offered request in one address family. This gives
// the independent oracle one data packet per request while exercising both
// template shapes across the three finite offers.
func refreshLogs(t *testing.T, startPort int64, ipv6 bool) plog.Logs {
	t.Helper()
	base := testpdata.CanonicalLogs()
	if ipv6 {
		base = testpdata.CanonicalIPv6Logs()
	}
	source := base.ResourceLogs().At(0)
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	source.Resource().CopyTo(resource.Resource())
	resource.SetSchemaUrl(source.SchemaUrl())
	scopeSource := source.ScopeLogs().At(0)
	scope := resource.ScopeLogs().AppendEmpty()
	scopeSource.Scope().CopyTo(scope.Scope())
	scope.SetSchemaUrl(scopeSource.SchemaUrl())
	baseRecord := scopeSource.LogRecords().At(0)
	for i := int64(0); i < 3; i++ {
		record := scope.LogRecords().AppendEmpty()
		baseRecord.CopyTo(record)
		record.Attributes().PutInt("source.port", startPort+i)
	}
	logs.MarkReadOnly()
	return logs
}

func waitTimeRefreshTimer(t *testing.T, timer *testclock.Timer, resets int) []time.Duration {
	t.Helper()
	if timer == nil {
		t.Fatal("template refresh timer is nil")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		delays, stopped, changed := timer.Snapshot()
		if len(delays) >= resets {
			if stopped || len(delays) != resets {
				t.Fatalf("template timer resets=%v stopped=%v, want %d resets", delays, stopped, resets)
			}
			return delays
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("template timer resets=%d, want %d", len(delays), resets)
		}
	}
}

func assertTimeRefreshTemplates(t *testing.T, protocol string, packets []dnsTransitionDatagram) {
	t.Helper()
	if len(packets) != 2 {
		t.Fatalf("refresh packets=%d, want 2", len(packets))
	}
	ids := make([]uint16, len(packets))
	for index, packet := range packets {
		if len(packet.payload) < 24 {
			t.Fatalf("refresh packet %d too short: %d", index, len(packet.payload))
		}
		version := binary.BigEndian.Uint16(packet.payload)
		offset, wantSet := 20, uint16(0)
		if protocol == "ipfix" {
			offset, wantSet = 16, 2
		}
		if version != map[string]uint16{"netflow_v9": 9, "ipfix": 10}[protocol] {
			t.Fatalf("refresh packet %d version=%d, want %d", index, version, map[string]uint16{"netflow_v9": 9, "ipfix": 10}[protocol])
		}
		if got := binary.BigEndian.Uint16(packet.payload[offset:]); got != wantSet {
			t.Fatalf("refresh packet %d set id=%d, want template set %d", index, got, wantSet)
		}
		if len(packet.payload) < offset+6 {
			t.Fatalf("refresh packet %d lacks template id", index)
		}
		ids[index] = binary.BigEndian.Uint16(packet.payload[offset+4:])
		if ids[index] != uint16(256+index) {
			t.Fatalf("refresh packet %d template id=%d, want %d", index, ids[index], 256+index)
		}
	}
	if ids[0] == ids[1] || bytes.Equal(packets[0].payload, packets[1].payload) {
		t.Fatalf("refresh templates did not contain two independent ids/shapes: ids=%v", ids)
	}
}

func assertTimeRefreshPeer(t *testing.T, want, got dnsTransitionDatagram) {
	t.Helper()
	if got.peer == nil || want.peer == nil || !got.peer.IP.Equal(want.peer.IP) || got.peer.Port != want.peer.Port {
		t.Fatalf("UDP peer changed: first=%v current=%v", want.peer, got.peer)
	}
	if got.destination != want.destination {
		t.Fatalf("UDP destination changed: first=%s current=%s", want.destination, got.destination)
	}
}

func sumTimeRefreshPayloads(packets []dnsTransitionDatagram) int64 {
	var total int64
	for _, packet := range packets {
		total += int64(len(packet.payload))
	}
	return total
}

func assertTimeRefreshMetrics(t *testing.T, fixture *dnsTransitionFixture, protocol string, startup, refresh, data []dnsTransitionDatagram) conditionalSnapshot {
	t.Helper()
	var metrics metricdata.ResourceMetrics
	if err := fixture.reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatal(err)
	}
	values := conditionalMetricValues(conditionalSnapshotFromMetrics(&metrics))
	exporter := "exporter=netflow/time-refresh-" + protocol
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|"+exporter+"|outcome=succeeded", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|"+exporter+"|outcome=failed", 0)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.endpoint_epochs|"+exporter, 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.records|"+exporter+"|outcome=confirmed", 9)
	for _, outcome := range []string{"ambiguous", "unsent", "invalid"} {
		requireConditionalMetric(t, values, "otelcol_netflow.exporter.records|"+exporter+"|outcome="+outcome, 0)
	}
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.data_messages|"+exporter+"|outcome=confirmed", 3)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.data_messages|"+exporter+"|outcome=ambiguous", 0)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.bytes|"+exporter+"|message_kind=data|outcome=confirmed", sumTimeRefreshPayloads(data))
	wantBootstrap := int64(0)
	wantRefresh := int64(0)
	if protocol != "netflow_v5" {
		wantBootstrap, wantRefresh = 4, 2
	}
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|"+exporter+"|message_kind=bootstrap|outcome=confirmed", wantBootstrap)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|"+exporter+"|message_kind=refresh|outcome=confirmed", wantRefresh)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|"+exporter+"|message_kind=bootstrap|outcome=ambiguous", 0)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|"+exporter+"|message_kind=refresh|outcome=ambiguous", 0)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.bytes|"+exporter+"|message_kind=bootstrap|outcome=confirmed", sumTimeRefreshPayloads(startup))
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.bytes|"+exporter+"|message_kind=refresh|outcome=confirmed", sumTimeRefreshPayloads(refresh))
	if got := values["otelcol_netflow.exporter.failures|"+exporter+"|reason=refresh"]; got != 0 {
		t.Fatalf("refresh failures=%d, want 0", got)
	}
	snapshot := conditionalSnapshotFromMetrics(&metrics)
	snapshot.Source = "TestTemplateRefreshTimeDeadlineRealUDP"
	return snapshot
}

func assertTimeRefreshResolverTrace(t *testing.T, lookup *testtransport.Resolver) {
	t.Helper()
	events := lookup.Events()
	if len(events) != 1 || events[0].AnswerCount != 1 || events[0].HadError {
		t.Fatalf("resolver trace=%+v, want one successful lookup with no DNS refresh", events)
	}
}

func TestTemplateRefreshTimeDeadlineRealUDP(t *testing.T) {
	// This is a bounded monotonic-clock direct pushLogs supplement. It proves
	// local UDP handoff and independent receipt/cache decode; it is not an
	// actual Collector/Testbed or wall-clock 30-second campaign.
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.LocalAddr().(*net.UDPAddr).Port
			lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
			fixture := dnsTransitionFixtureForNameWithDNS(t, protocol, port, lookup, "time-refresh-"+protocol, time.Minute, 2*time.Minute)
			if err := fixture.exporter.Start(ctx, componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			fixture.events.wait(t, destination.DNSSucceeded, 1)
			fixture.events.wait(t, destination.EpochPublished, 1)
			waitDNSTransitionTimer(t, fixture.dnsTimer, 1)
			dnsDelays, dnsStopped, _ := fixture.dnsTimer.Snapshot()
			if len(dnsDelays) != 1 || dnsStopped || dnsDelays[0] != time.Minute {
				t.Fatalf("initial DNS timer state delays=%v stopped=%v, want one 1m timer", dnsDelays, dnsStopped)
			}

			startup := readDNSTransitionDatagrams(t, listener, transitionBootstrapCount(protocol))
			if protocol == "netflow_v5" {
				if fixture.refreshTimer != nil {
					t.Fatal("v5 unexpectedly created a template refresh timer")
				}
				fixture.clock.Advance(0, uint64(30*time.Second))
				assertNoDNSTransitionReceipt(t, listener)
			} else {
				assertTransitionBootstrap(t, protocol, startup)
				delays := waitTimeRefreshTimer(t, fixture.refreshTimer, 1)
				if delays[0] != 30*time.Second {
					t.Fatalf("initial template timer delay=%v, want 30s", delays[0])
				}
			}

			offers := []struct {
				port int64
				ipv6 bool
			}{{20001, false}, {20004, protocol != "netflow_v5"}, {20007, false}}
			if protocol != "netflow_v5" {
				fixture.clock.Advance(0, uint64(29*time.Second))
				if !fixture.refreshTimer.Fire() {
					t.Fatal("early template timer was not armed")
				}
				delays := waitTimeRefreshTimer(t, fixture.refreshTimer, 2)
				if delays[1] != time.Second {
					t.Fatalf("early template timer delay=%v, want 1s remainder", delays[1])
				}
				assertNoDNSTransitionReceipt(t, listener)
				if fixture.events.count(destination.RefreshConfirmed) != 0 || fixture.events.count(destination.RefreshAmbiguous) != 0 {
					t.Fatalf("early timer emitted refresh events: confirmed=%d ambiguous=%d", fixture.events.count(destination.RefreshConfirmed), fixture.events.count(destination.RefreshAmbiguous))
				}

				fixture.clock.Advance(0, uint64(time.Second))
				if !fixture.refreshTimer.Fire() {
					t.Fatal("deadline template timer was not armed")
				}
				delays = waitTimeRefreshTimer(t, fixture.refreshTimer, 3)
				if delays[2] != 30*time.Second {
					t.Fatalf("post-refresh template timer delay=%v, want 30s", delays[2])
				}
				refresh := readDNSTransitionDatagrams(t, listener, 2)
				assertTimeRefreshTemplates(t, protocol, refresh)
				fixture.events.wait(t, destination.RefreshConfirmed, 2)

				data := make([]dnsTransitionDatagram, 0, 3)
				for index, offer := range offers {
					if err := fixture.exporter.pushLogs(ctx, refreshLogs(t, offer.port, offer.ipv6)); err != nil {
						t.Fatalf("post-refresh pushLogs %d: %v", index, err)
					}
					packet := readDNSTransitionDatagram(t, listener)
					assertTransitionData(t, protocol, packet, 3)
					data = append(data, packet)
				}
				if len(startup) == 0 {
					t.Fatal("v9/IPFIX bootstrap capture unexpectedly empty")
				}
				assertTimeRefreshPeer(t, startup[0], refresh[0])
				for _, packet := range refresh[1:] {
					assertTimeRefreshPeer(t, startup[0], packet)
				}
				for _, packet := range data {
					assertTimeRefreshPeer(t, startup[0], packet)
				}
				dir := runDNSTransitionTShark(t, protocol, "refresh", port, append(append([]dnsTransitionDatagram{}, refresh...), data...), [][]int{{20001, 20002, 20003}, {20004, 20005, 20006}, {20007, 20008, 20009}})
				snapshot := assertTimeRefreshMetrics(t, fixture, protocol, startup, refresh, data)
				if dir != "" {
					writeConditionalSnapshot(t, filepath.Join(dir, "telemetry-snapshot.json"), snapshot)
				} else {
					t.Log("independent TShark 4.4.18 refresh-cache decoding is opt-in; local UDP receipt and direct pushLogs accounting passed")
				}
			} else {
				data := make([]dnsTransitionDatagram, 0, 3)
				for index, offer := range offers {
					if err := fixture.exporter.pushLogs(ctx, refreshLogs(t, offer.port, offer.ipv6)); err != nil {
						t.Fatalf("v5 pushLogs %d: %v", index, err)
					}
					packet := readDNSTransitionDatagram(t, listener)
					assertTransitionData(t, protocol, packet, 3)
					data = append(data, packet)
				}
				peer := data[0]
				for _, packet := range data[1:] {
					assertTimeRefreshPeer(t, peer, packet)
				}
				dir := runDNSTransitionTShark(t, protocol, "control", port, data, [][]int{{20001, 20002, 20003}, {20004, 20005, 20006}, {20007, 20008, 20009}})
				snapshot := assertTimeRefreshMetrics(t, fixture, protocol, startup, nil, data)
				if dir != "" {
					writeConditionalSnapshot(t, filepath.Join(dir, "telemetry-snapshot.json"), snapshot)
				} else {
					t.Log("independent TShark 4.4.18 v5 control decoding is opt-in; local UDP receipt and direct pushLogs accounting passed")
				}
			}

			assertTimeRefreshResolverTrace(t, fixture.lookup)
			if fixture.events.count(destination.DNSFailed) != 0 || fixture.events.count(destination.EpochPublished) != 1 {
				t.Fatalf("DNS/epoch events changed without a DNS timer fire: failed=%d epochs=%d", fixture.events.count(destination.DNSFailed), fixture.events.count(destination.EpochPublished))
			}
			dnsDelays, dnsStopped, _ = fixture.dnsTimer.Snapshot()
			if len(dnsDelays) != 1 || dnsStopped {
				t.Fatalf("DNS timer state before shutdown delays=%v stopped=%v, want one armed timer", dnsDelays, dnsStopped)
			}
			if err := fixture.exporter.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertDNSTransitionTimerStopped(t, fixture.dnsTimer)
			if fixture.refreshTimer != nil {
				assertDNSTransitionTimerStopped(t, fixture.refreshTimer)
			}
			assertNoDNSTransitionReceipt(t, listener)
		})
	}
}
