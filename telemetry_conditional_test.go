package netflowexporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type conditionalDialPlan struct {
	steps []testtransport.WriteStep
	err   error
}

type conditionalDialer struct {
	mu      sync.Mutex
	plans   []conditionalDialPlan
	local   netip.AddrPort
	conns   []*testtransport.Conn
	dialErr []error
}

func (d *conditionalDialer) dial(_ context.Context, remote netip.AddrPort) (transport.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.plans) == 0 {
		return nil, errors.New("conditional fixture dial script exhausted")
	}
	plan := d.plans[0]
	d.plans = d.plans[1:]
	if plan.err != nil {
		d.dialErr = append(d.dialErr, plan.err)
		return nil, plan.err
	}
	conn := testtransport.NewConn(d.local, remote, plan.steps...)
	d.conns = append(d.conns, conn)
	return conn, nil
}

type conditionalRuntimeFixture struct {
	runtime *destination.Runtime
	clock   *testclock.Clock
	timers  []*testclock.Timer
	lookup  *testtransport.Resolver
	dialer  *conditionalDialer
}

func conditionalProtocol(name string) wire.Protocol {
	switch name {
	case "netflow_v5":
		return wire.ProtocolV5
	case "netflow_v9":
		return wire.ProtocolV9
	case "ipfix":
		return wire.ProtocolIPFIX
	default:
		panic("unknown conditional protocol " + name)
	}
}

func conditionalRuntime(t *testing.T, protocol string, host string, lookup *testtransport.Resolver, plans []conditionalDialPlan, observe destination.Observer) *conditionalRuntimeFixture {
	t.Helper()
	c := validConfig(protocol)
	c.Endpoint = host + ":4739"
	c.Templates.RefreshInterval = 30 * time.Second
	p := conditionalProtocol(protocol)
	profile := *c.Mapping.Profile
	mappingConfig := mapping.Config{
		Schema: c.Schema, Protocol: p, Profile: profile,
		ProtocolIdentifiers: c.Mapping.ProtocolIdentifiers,
		NetworkTypeVersions: c.Mapping.NetworkTypeVersions,
		InputGuarantees:     c.Mapping.InputGuarantees,
		LossPolicy:          *c.Mapping.LossPolicy, IDBase: c.Templates.IDBase,
		MaxDatagramSize: c.MaxDatagramSize, Endpoint: c.Endpoint,
	}
	if p == wire.ProtocolV5 {
		mappingConfig.IDBase = 0
	}
	if c.UptimeOrigin != nil {
		mappingConfig.HasUptimeOrigin = true
		mappingConfig.UptimeOriginUnixNanos = *c.UptimeOrigin
	}
	compiled, err := mapping.Compile(mappingConfig)
	if err != nil {
		t.Fatal(err)
	}
	var writer wire.ContractWriter
	switch p {
	case wire.ProtocolV5:
		writer = netflow5.NewWriter()
	case wire.ProtocolV9:
		writer = netflow9.NewWriter()
	case wire.ProtocolIPFIX:
		writer = ipfix.NewWriter()
	}
	state := destination.DefaultConfig(p)
	state.MaxDatagramSize = c.MaxDatagramSize
	state.InitialCopies = c.Templates.InitialCopies
	state.RefreshInterval = c.Templates.RefreshInterval
	state.V9RefreshPacketCount = 1
	state.IPFIXDataMessageRefreshCount = 1
	switch p {
	case wire.ProtocolV5:
		state.EngineType = *c.Identity.EngineType
		state.EngineID = *c.Identity.EngineID
		state.HasUptimeOrigin = true
		state.UptimeOriginUnixNanos = *c.UptimeOrigin
	case wire.ProtocolV9:
		state.SourceID = *c.Identity.SourceID
	case wire.ProtocolIPFIX:
		state.ObservationDomainID = *c.Identity.ObservationDomainID
	}
	resolver, err := transport.NewResolverWithLookup("udp", host, c.DNS.Timeout, lookup)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &conditionalDialer{local: netip.MustParseAddrPort("127.0.0.1:40000"), plans: append([]conditionalDialPlan(nil), plans...)}
	candidateDialer, err := transport.NewCandidateDialer(resolver, 4739, c.MaxDatagramSize, compiled.MaxDatagramSize(), 0, dialer.dial, c.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	clock := testclock.New(1788220802000000000, 0)
	var runtimeClock transport.Clock = clock
	if p != wire.ProtocolIPFIX {
		runtimeClock = millisecondClock{clock: clock, origin: state.UptimeOriginUnixNanos, checkUptime: state.HasUptimeOrigin}
	}
	fixture := &conditionalRuntimeFixture{clock: clock, lookup: lookup, dialer: dialer}
	config := destination.RuntimeConfig{State: state, DNSRefresh: time.Second, DNSStaleAfter: time.Minute, Observe: observe}
	config.NewTimer = func(time.Duration) transport.Timer {
		timer := testclock.NewTimer()
		fixture.timers = append(fixture.timers, timer)
		return timer
	}
	fixture.runtime, err = destination.NewRuntime(compiled, writer, config, candidateDialer, runtimeClock)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func conditionalExporter(t *testing.T, provider *sdkmetric.MeterProvider, protocol, name, host string, lookup *testtransport.Resolver, plans []conditionalDialPlan) (*logsExporter, *conditionalRuntimeFixture) {
	return conditionalExporterWithHook(t, provider, protocol, name, host, lookup, plans, nil)
}

func conditionalExporterWithHook(t *testing.T, provider *sdkmetric.MeterProvider, protocol, name, host string, lookup *testtransport.Resolver, plans []conditionalDialPlan, hook func(destination.Event)) (*logsExporter, *conditionalRuntimeFixture) {
	t.Helper()
	set := exportertest.NewNopSettings(NewFactory().Type())
	set.ID = component.NewIDWithName(NewFactory().Type(), name)
	set.Logger = zap.NewNop()
	set.MeterProvider = provider
	set.TracerProvider = trace.NewNoopTracerProvider()
	builder, err := metadata.NewTelemetryBuilder(set.TelemetrySettings)
	if err != nil {
		t.Fatal(err)
	}
	tel := telemetry{builder: builder, instance: attribute.String("exporter", set.ID.String())}
	observe := tel.observe
	if hook != nil {
		observe = func(ctx context.Context, event destination.Event, bytes uint64) {
			tel.observe(ctx, event, bytes)
			hook(event)
		}
	}
	fixture := conditionalRuntime(t, protocol, host, lookup, plans, observe)
	e := &logsExporter{runtime: fixture.runtime, telemetry: tel}
	c := validConfig(protocol)
	c.Endpoint = host + ":4739"
	helper, err := exporterhelper.NewLogs(context.Background(), set, c, e.pushLogs,
		exporterhelper.WithStart(func(context.Context, component.Host) error { return fixture.runtime.Start(context.Background()) }),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithTimeout(exporterhelper.TimeoutConfig{Timeout: 0}),
	)
	if err != nil {
		t.Fatal(err)
	}
	e.helper = helper
	registration, err := tel.registerLifetime(metadata.Meter(set.TelemetrySettings), fixture.runtime)
	if err != nil {
		t.Fatalf("conditional lifetime registration: %v", err)
	}
	tel.lifetimeReg = registration
	e.telemetry = tel
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e, fixture
}

func conditionalFullSteps(protocol string) []testtransport.WriteStep {
	return append([]testtransport.WriteStep(nil), bootstrapSteps(protocol)...)
}

func conditionalTemplateLength(protocol string) int {
	if protocol == "netflow_v9" {
		return 100
	}
	return 104
}

func conditionalDataSteps(protocol string) []testtransport.WriteStep {
	return append(conditionalFullSteps(protocol), testtransport.WriteStep{N: packetLength(protocol)})
}

func conditionalLogs() plog.Logs { return testpdata.CanonicalLogs() }

type conditionalSnapshot struct {
	Mode          string              `json:"mode"`
	Source        string              `json:"source"`
	ScopeCount    int                 `json:"scope_count"`
	ResourceAttrs []string            `json:"resource_attributes"`
	Metrics       []conditionalMetric `json:"metrics"`
}

type conditionalMetric struct {
	Name        string             `json:"name"`
	Unit        string             `json:"unit"`
	Description string             `json:"description"`
	DataType    string             `json:"data_type"`
	Monotonic   *bool              `json:"monotonic,omitempty"`
	Temporality string             `json:"temporality,omitempty"`
	Points      []conditionalPoint `json:"points"`
}

type conditionalPoint struct {
	Value      any               `json:"value"`
	Attributes map[string]string `json:"attributes"`
}

func conditionalSnapshotFromMetrics(rm *metricdata.ResourceMetrics) conditionalSnapshot {
	snapshot := conditionalSnapshot{Mode: "actual-sdk-snapshot", Source: "TestTelemetryConditionalProbe", ScopeCount: len(rm.ScopeMetrics)}
	for _, kv := range rm.Resource.Attributes() {
		snapshot.ResourceAttrs = append(snapshot.ResourceAttrs, string(kv.Key))
	}
	sort.Strings(snapshot.ResourceAttrs)
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			entry := conditionalMetric{Name: metric.Name, Unit: metric.Unit, Description: metric.Description}
			switch data := metric.Data.(type) {
			case metricdata.Sum[int64]:
				entry.DataType, entry.Monotonic, entry.Temporality = "sum[int64]", ptr(data.IsMonotonic), data.Temporality.String()
				for _, point := range data.DataPoints {
					entry.Points = append(entry.Points, conditionalPoint{Value: point.Value, Attributes: conditionalAttributes(point.Attributes)})
				}
			case metricdata.Gauge[int64]:
				entry.DataType = "gauge[int64]"
				for _, point := range data.DataPoints {
					entry.Points = append(entry.Points, conditionalPoint{Value: point.Value, Attributes: conditionalAttributes(point.Attributes)})
				}
			case metricdata.Gauge[float64]:
				entry.DataType = "gauge[float64]"
				for _, point := range data.DataPoints {
					entry.Points = append(entry.Points, conditionalPoint{Value: point.Value, Attributes: conditionalAttributes(point.Attributes)})
				}
			default:
				entry.DataType = fmt.Sprintf("%T", metric.Data)
			}
			snapshot.Metrics = append(snapshot.Metrics, entry)
		}
	}
	sort.Slice(snapshot.Metrics, func(i, j int) bool { return snapshot.Metrics[i].Name < snapshot.Metrics[j].Name })
	return snapshot
}

func conditionalAttributes(set attribute.Set) map[string]string {
	result := make(map[string]string, len(set.ToSlice()))
	for _, kv := range set.ToSlice() {
		if kv.Value.Type() != attribute.STRING {
			panic(fmt.Sprintf("conditional telemetry attribute %q has type %s", kv.Key, kv.Value.Type()))
		}
		result[string(kv.Key)] = kv.Value.AsString()
	}
	return result
}

func conditionalMetricValues(snapshot conditionalSnapshot) map[string]int64 {
	values := make(map[string]int64)
	for _, metric := range snapshot.Metrics {
		for _, point := range metric.Points {
			value, ok := point.Value.(int64)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(point.Attributes))
			for key, value := range point.Attributes {
				keys = append(keys, key+"="+value)
			}
			sort.Strings(keys)
			values[metric.Name+"|"+strings.Join(keys, "|")] += value
		}
	}
	return values
}

func conditionalAssertSDKContract(t *testing.T, snapshot conditionalSnapshot) {
	t.Helper()
	metrics := make(map[string]int64)
	helperSeen := map[string]bool{}
	lifetimeSeen := map[string]map[string]bool{}
	for _, metric := range snapshot.Metrics {
		if metric.Name == "otelcol_exporter_in_flight_requests" {
			helperSeen[metric.Name] = true
			if metric.DataType != "sum[int64]" || metric.Monotonic == nil || *metric.Monotonic || metric.Unit != "{request}" {
				t.Fatalf("in_flight helper metric type=%s monotonic=%v unit=%q", metric.DataType, metric.Monotonic, metric.Unit)
			}
		}
		if metric.Name == "otelcol_exporter_sent_log_records" {
			helperSeen[metric.Name] = true
			if metric.DataType != "sum[int64]" || metric.Monotonic == nil || !*metric.Monotonic || metric.Unit != "{record}" {
				t.Fatalf("sent_log_records helper metric type=%s monotonic=%v unit=%q", metric.DataType, metric.Monotonic, metric.Unit)
			}
		}
		if strings.HasPrefix(metric.Name, "otelcol_netflow.exporter.") {
			shortName := strings.TrimPrefix(metric.Name, "otelcol_netflow.exporter.")
			if shortName == "uptime_exhausted" || shortName == "uptime_remaining" {
				wantType, wantUnit := "gauge[int64]", "1"
				if shortName == "uptime_remaining" {
					wantType, wantUnit = "gauge[float64]", "s"
				}
				if metric.DataType != wantType || metric.Monotonic != nil || metric.Temporality != "" || metric.Unit != wantUnit {
					t.Fatalf("project gauge %s type=%s monotonic=%v temporality=%q unit=%q", metric.Name, metric.DataType, metric.Monotonic, metric.Temporality, metric.Unit)
				}
				for _, point := range metric.Points {
					if len(point.Attributes) != 1 || point.Attributes["exporter"] == "" {
						t.Fatalf("lifetime gauge attributes=%v", point.Attributes)
					}
					if strings.HasPrefix(point.Attributes["exporter"], "netflow/ipfix-") {
						t.Fatalf("IPFIX emitted lifetime gauge %s for %q", metric.Name, point.Attributes["exporter"])
					}
					if lifetimeSeen[point.Attributes["exporter"]] == nil {
						lifetimeSeen[point.Attributes["exporter"]] = map[string]bool{}
					}
					lifetimeSeen[point.Attributes["exporter"]][shortName] = true
					if shortName == "uptime_exhausted" {
						value, ok := point.Value.(int64)
						if !ok || (value != 0 && value != 1) {
							t.Fatalf("invalid exhausted gauge value=%v", point.Value)
						}
					} else {
						value, ok := point.Value.(float64)
						if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
							t.Fatalf("invalid remaining gauge value=%v", point.Value)
						}
					}
				}
				continue
			}
			if metric.DataType != "sum[int64]" || metric.Monotonic == nil || !*metric.Monotonic {
				t.Fatalf("project metric %s type=%s monotonic=%v", metric.Name, metric.DataType, metric.Monotonic)
			}
			wantUnit := map[string]string{
				"admission": "{request}", "bytes": "By", "data_messages": "{message}", "dns": "{lookup}",
				"endpoint_epochs": "{epoch}", "failures": "{event}", "losses": "{event}", "records": "{record}", "rejected_records": "{record}", "templates": "{message}",
			}[strings.TrimPrefix(metric.Name, "otelcol_netflow.exporter.")]
			if metric.Unit != wantUnit {
				t.Fatalf("project metric %s unit=%q want %q", metric.Name, metric.Unit, wantUnit)
			}
		}
		for _, point := range metric.Points {
			value, ok := point.Value.(int64)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(point.Attributes))
			for key, value := range point.Attributes {
				keys = append(keys, key+"="+value)
			}
			sort.Strings(keys)
			name := metric.Name
			if strings.HasPrefix(name, "otelcol_netflow.exporter.") {
				metrics[strings.TrimPrefix(name, "otelcol_netflow.exporter.")+"|"+strings.Join(keys, "|")] += value
			}
		}
	}
	acceptanceAssertLocalVocabulary(t, metrics)
	values := conditionalMetricValues(snapshot)
	// Only the injected invalid-write PackInternal path may emit internal.
	// Normal-context runtime rejections must not fall through the nil-result
	// default in pushLogs, including the public admission-guard fixture.
	for key, count := range values {
		if strings.HasPrefix(key, "otelcol_netflow.exporter.failures|") &&
			strings.HasSuffix(key, "|reason=internal") &&
			key != "otelcol_netflow.exporter.failures|exporter=netflow/internal|reason=internal" && count != 0 {
			t.Fatalf("guarded nil-result internal fallback emitted %s=%d", key, count)
		}
	}
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|exporter=netflow/dns-success|outcome=succeeded", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.rejected_records|exporter=netflow/dns-success|rejection_reason=unsupported_body", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.dns|exporter=netflow/dns-failure|outcome=failed", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/unavailable|reason=unavailable", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/runtime-busy|reason=busy", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/runtime-closed|reason=closed", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/internal|reason=internal", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/candidate|reason=candidate", 1)
	for _, reason := range []string{"busy", "closed"} {
		requireConditionalMetric(t, values, "otelcol_netflow.exporter.admission|exporter=netflow/admission|reason="+reason, 1)
		if got := values["otelcol_netflow.exporter.failures|exporter=netflow/admission|reason="+reason]; got != 0 {
			t.Fatalf("public admission emitted failures reason=%s count=%d", reason, got)
		}
	}
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		for _, kind := range []string{"bootstrap", "refresh"} {
			for _, outcome := range []string{"confirmed", "ambiguous"} {
				name := protocol + "-" + kind + "-" + outcome
				if outcome == "confirmed" {
					count := 4
					if kind == "refresh" {
						count = 2
					}
					requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|exporter=netflow/"+name+"|message_kind="+kind+"|outcome=confirmed", int64(count))
					requireConditionalMetric(t, values, "otelcol_netflow.exporter.bytes|exporter=netflow/"+name+"|message_kind="+kind+"|outcome=confirmed", int64(count*conditionalTemplateLength(protocol)))
				} else {
					requireConditionalMetric(t, values, "otelcol_netflow.exporter.templates|exporter=netflow/"+name+"|message_kind="+kind+"|outcome=ambiguous", 1)
					requireConditionalMetric(t, values, "otelcol_netflow.exporter.bytes|exporter=netflow/"+name+"|message_kind="+kind+"|outcome=ambiguous", int64(conditionalTemplateLength(protocol)))
				}
			}
		}
	}
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/netflow_v9-bootstrap-ambiguous|reason=bootstrap", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/ipfix-bootstrap-ambiguous|reason=bootstrap", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/netflow_v9-refresh-ambiguous|reason=refresh", 1)
	requireConditionalMetric(t, values, "otelcol_netflow.exporter.failures|exporter=netflow/ipfix-refresh-ambiguous|reason=refresh", 1)
	if _, ok := values["otelcol_exporter_sent_log_records|exporter=netflow/dns-success"]; !ok {
		t.Fatal("actual helper sent_log_records signal absent")
	}
	if !helperSeen["otelcol_exporter_in_flight_requests"] || !helperSeen["otelcol_exporter_sent_log_records"] {
		t.Fatal("actual Collector helper signals incomplete")
	}
	if !lifetimeSeen["netflow/dns-success"]["uptime_remaining"] || !lifetimeSeen["netflow/dns-success"]["uptime_exhausted"] {
		t.Fatalf("production callback did not publish both dns-success lifetime gauges: %v", lifetimeSeen)
	}
}

func requireConditionalMetric(t *testing.T, values map[string]int64, key string, want int64) {
	t.Helper()
	if got := values[key]; got != want {
		t.Fatalf("%s=%d want %d", key, got, want)
	}
}

func writeConditionalSnapshot(t *testing.T, path string, snapshot conditionalSnapshot) {
	t.Helper()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitConditionalTimer(t *testing.T, timer *testclock.Timer) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		delays, _, changed := timer.Snapshot()
		if len(delays) > 0 {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("conditional maintenance timer did not arm")
		}
	}
}

func waitConditionalDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("conditional maintenance operation did not complete")
	}
}

func TestTelemetryConditionalProbe(t *testing.T) {
	capture := os.Getenv("NETFLOW_CONDITIONAL_SNAPSHOT")
	if capture == "" {
		capture = t.TempDir() + "/conditional-snapshot.json"
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	addrA := netip.MustParseAddr("192.0.2.10")
	addrB := netip.MustParseAddr("192.0.2.11")

	// DNS success is the package-local Runtime/ResolverWithLookup boundary.
	e, _ := conditionalExporter(t, provider, "netflow_v5", "dns-success", "collector.example", testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{addrA}}), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}, {N: packetLength("netflow_v5")}}}})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err := e.ConsumeLogs(context.Background(), conditionalLogs()); err != nil {
		t.Fatal(err)
	}
	mixed := conditionalLogs()
	base := mixed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	invalid := mixed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	base.CopyTo(invalid)
	invalid.Body().SetStr("conditional unsupported body")
	mixed.MarkReadOnly()
	if err := e.ConsumeLogs(context.Background(), mixed); err != nil {
		t.Fatalf("genuine rejection probe=%v", err)
	}
	// DNS failure is a scripted lookup/answer failure before numeric dialing.
	e, _ = conditionalExporter(t, provider, "netflow_v5", "dns-failure", "collector.example", testtransport.NewResolver(testtransport.ResolverStep{Err: errors.New("scripted lookup failure")}), nil)
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err == nil {
		t.Fatal("DNS failure unexpectedly started runtime")
	}

	// Public admission guards remain separate from pushLogs failure attribution.
	e, fixture := conditionalExporter(t, provider, "netflow_v5", "admission", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}}}})
	entered, release, consumed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	go func() {
		consumed <- fixture.runtime.Consume(context.Background(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	if err := e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeBusy) {
		t.Fatalf("public busy admission=%v", err)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-consumed; err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.ConsumeLogs(context.Background(), plog.Logs{}); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatalf("public closed admission=%v", err)
	}

	// The runtime Pack path reaches unavailable before Start.
	e, _ = conditionalExporter(t, provider, "netflow_v5", "unavailable", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}}}})
	if err := e.pushLogs(context.Background(), conditionalLogs()); !errors.Is(err, destination.ErrRuntimeUnavailable) {
		t.Fatalf("unavailable pushLogs=%v", err)
	}

	// A held transport write makes the internal Pack send lock busy.
	enteredWrite, releaseWrite := make(chan struct{}), make(chan struct{})
	var releaseWriteOnce sync.Once
	t.Cleanup(func() { releaseWriteOnce.Do(func() { close(releaseWrite) }) })
	e, _ = conditionalExporter(t, provider, "netflow_v5", "runtime-busy", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5"), Started: enteredWrite, Wait: releaseWrite}}}})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- e.pushLogs(context.Background(), conditionalLogs()) }()
	<-enteredWrite
	if err := e.pushLogs(context.Background(), conditionalLogs()); !errors.Is(err, destination.ErrRuntimeBusy) {
		t.Fatalf("runtime busy pushLogs=%v", err)
	}
	releaseWriteOnce.Do(func() { close(releaseWrite) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}

	// Closed is exercised through pushLogs after Runtime shutdown, distinct
	// from the public ConsumeLogs admission guard above.
	e, fixture = conditionalExporter(t, provider, "netflow_v5", "runtime-closed", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}}}})
	if err := fixture.runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.pushLogs(context.Background(), conditionalLogs()); !errors.Is(err, destination.ErrRuntimeClosed) {
		t.Fatalf("runtime closed pushLogs=%v", err)
	}

	// Invalid write length is the injected transport contract violation that
	// reaches PackInternal and is attributed by pushLogs as internal.
	e, fixture = conditionalExporter(t, provider, "netflow_v5", "internal", "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5") + 1}}}})
	if err := fixture.runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.pushLogs(context.Background(), conditionalLogs()); !consumererror.IsPermanent(err) {
		t.Fatalf("internal pushLogs=%v", err)
	}

	// DNS replacement with a scripted dial failure reaches candidate.
	candidateDone := make(chan struct{})
	var candidateOnce sync.Once
	e, fixture = conditionalExporterWithHook(t, provider, "netflow_v5", "candidate", "collector.example", testtransport.NewResolver(
		testtransport.ResolverStep{Answers: []netip.Addr{addrA}},
		testtransport.ResolverStep{Answers: []netip.Addr{addrB}},
	), []conditionalDialPlan{{steps: []testtransport.WriteStep{{N: packetLength("netflow_v5")}}}, {err: errors.New("scripted replacement dial failure")}}, func(event destination.Event) {
		if event == destination.CandidateFailed {
			candidateOnce.Do(func() { close(candidateDone) })
		}
	})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	waitConditionalTimer(t, fixture.timers[0])
	fixture.clock.Advance(0, uint64(time.Second))
	if !fixture.timers[0].Fire() {
		t.Fatal("DNS timer did not fire")
	}
	waitConditionalDone(t, candidateDone)

	// Bootstrap and refresh handoffs cover every protocol/outcome combination.
	for _, protocol := range []string{"netflow_v9", "ipfix"} {
		for _, outcome := range []string{"confirmed", "ambiguous"} {
			name := protocol + "-bootstrap-" + outcome
			steps := conditionalFullSteps(protocol)
			if outcome == "ambiguous" {
				steps = []testtransport.WriteStep{{N: 1}}
				if protocol == "ipfix" {
					steps = []testtransport.WriteStep{{N: 0}}
				}
			}
			e, _ = conditionalExporter(t, provider, protocol, name, "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: steps}})
			err := e.Start(context.Background(), componenttest.NewNopHost())
			if outcome == "confirmed" && err != nil {
				t.Fatal(err)
			}
			if outcome == "ambiguous" && err == nil {
				t.Fatal("ambiguous bootstrap unexpectedly succeeded")
			}
		}
		for _, outcome := range []string{"confirmed", "ambiguous"} {
			name := protocol + "-refresh-" + outcome
			done := make(chan struct{})
			var observed int
			var doneOnce sync.Once
			steps := conditionalFullSteps(protocol)
			refresh := conditionalFullSteps(protocol)
			if outcome == "ambiguous" {
				switch protocol {
				case "netflow_v9":
					refresh = []testtransport.WriteStep{{N: 0, Err: errors.New("scripted refresh zero error")}}
				case "ipfix":
					refresh = []testtransport.WriteStep{{N: 1, Err: errors.New("scripted refresh short error")}}
				}
			}
			steps = append(steps, refresh...)
			wantEvent := destination.RefreshConfirmed
			if outcome == "ambiguous" {
				wantEvent = destination.RefreshFailed
			}
			e, fixture = conditionalExporterWithHook(t, provider, protocol, name, "127.0.0.1", testtransport.NewResolver(), []conditionalDialPlan{{steps: steps}}, func(event destination.Event) {
				if event != wantEvent {
					return
				}
				observed++
				if outcome == "ambiguous" || observed == 2 {
					doneOnce.Do(func() { close(done) })
				}
			})
			if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
				t.Fatal(err)
			}
			waitConditionalTimer(t, fixture.timers[0])
			fixture.clock.Advance(0, uint64(30*time.Second))
			if !fixture.timers[0].Fire() {
				t.Fatal("refresh timer did not fire")
			}
			waitConditionalDone(t, done)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	snapshot := conditionalSnapshotFromMetrics(&rm)
	conditionalAssertSDKContract(t, snapshot)
	writeConditionalSnapshot(t, capture, snapshot)
}
