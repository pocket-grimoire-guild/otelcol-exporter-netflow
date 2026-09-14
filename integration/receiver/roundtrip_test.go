package receiver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type fixtureCase struct {
	Name              string         `json:"name"`
	FixtureID         string         `json:"fixture_id"`
	ExpectedRecords   int            `json:"expected_records"`
	DataBytes         int64          `json:"data_bytes"`
	WireSamplingRates []int64        `json:"wire_sampling_rates"`
	Attributes        map[string]any `json:"attributes"`
}

type fixtureLedger struct {
	Protocol             string         `json:"protocol"`
	Profile              string         `json:"profile"`
	CanonicalFileSHA256  string         `json:"canonical_file_sha256"`
	BootstrapDatagrams   int            `json:"bootstrap_datagrams"`
	BootstrapBytes       int64          `json:"bootstrap_bytes"`
	FixtureDatagramCount int            `json:"fixture_datagram_count"`
	Attributes           map[string]any `json:"attributes"`
	Cases                []fixtureCase  `json:"cases"`
}

// This exercises the public component factories over real loopback UDP. The
// receiver is a semantic oracle; the independent goldens/TShark remain the wire
// authority. Each fresh receiver has no earlier Options sampling cache.
func TestSemanticRoundTrip(t *testing.T) {
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		var ledger fixtureLedger
		readJSON(t, filepath.Join("..", "testdata", "receiver", protocol, "ledger.json"), &ledger)
		if ledger.FixtureDatagramCount <= 0 || ledger.FixtureDatagramCount != ledger.BootstrapDatagrams+1 || len(ledger.Cases) == 0 {
			t.Fatal("invalid complete bootstrap-plus-data ledger")
		}
		for _, tc := range ledger.Cases {
			t.Run(protocol+"/"+tc.Name, func(t *testing.T) {
				runRoundTrip(t, ledger, tc)
			})
		}
	}
}

func runRoundTrip(t *testing.T, ledger fixtureLedger, tc fixtureCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logs := canonicalLogs(t, ledger, tc)

	// Reserve once, release immediately before Start, and fail on a bind race.
	// The receiver cannot adopt a socket or report an ephemeral bound port.
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	defer reservation.Close()
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	if port == 0 {
		t.Fatal("reservation returned port zero")
	}
	f := netflowreceiver.NewFactory()
	cfg, ok := f.CreateDefaultConfig().(*netflowreceiver.Config)
	if !ok {
		t.Fatal("pinned receiver config type changed")
	}
	fixtureDatagramCount := ledger.FixtureDatagramCount
	cfg.Scheme, cfg.Hostname, cfg.Port = "netflow", "127.0.0.1", port
	cfg.Sockets, cfg.Workers, cfg.QueueSize, cfg.SendRaw = 1, 1, fixtureDatagramCount, false
	must(t, cfg.Validate())
	sink := &consumertest.LogsSink{}
	rx, err := f.CreateLogs(ctx, receivertest.NewNopSettings(f.Type()), cfg, sink)
	must(t, err)
	// The pinned receiver Shutdown is not idempotent: invoke exactly once.
	rxStopped := false
	defer func() {
		if !rxStopped {
			shutdown(t, rx)
		}
	}()
	host := componenttest.NewNopHost()
	must(t, reservation.Close())
	must(t, rx.Start(ctx, host)) // Successful Start is the only readiness signal.

	ef := netflowexporter.NewFactory()
	ec := ef.CreateDefaultConfig().(*netflowexporter.Config)
	ec.Endpoint = net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	ec.Protocol = ledger.Protocol
	ec.Mapping.Profile = &ledger.Profile
	loss := netflowexporter.LossPolicy("encode_and_count")
	ec.Mapping.LossPolicy = &loss
	ec.Mapping.ProtocolIdentifiers = []netflowexporter.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	identity := uint32(42)
	zero := uint8(0)
	if ledger.Protocol == "netflow_v5" {
		ec.Identity.EngineType, ec.Identity.EngineID = &zero, &zero
		ec.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		// Rebase only uptime and its two relative fields so this fixture does not
		// expire at the v5 uint32-millisecond uptime ceiling. Preserve 1000/1001ms.
		origin := uint64(time.Now().Truncate(time.Millisecond).Add(-2 * time.Second).UnixNano())
		ec.UptimeOrigin = &origin
		a := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
		a.PutInt("flow.start", int64(origin+1_000_000_000))
		a.PutInt("flow.end", int64(origin+1_001_000_000))
	} else {
		ec.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
		if ledger.Protocol == "netflow_v9" {
			ec.Identity.SourceID = &identity
		} else {
			ec.Identity.ObservationDomainID = &identity
		}
	}
	must(t, ec.Validate())
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	settings := exportertest.NewNopSettings(ef.Type())
	settings.MeterProvider = provider
	ex, err := ef.CreateLogs(ctx, settings, ec)
	must(t, err)
	defer shutdown(t, ex)
	if ex.Capabilities().MutatesData {
		t.Fatal("exporter advertises pdata mutation")
	}
	must(t, ex.Start(ctx, host))

	// Credible failures must not add data packets or contaminate the fresh
	// receiver's state. Keep the immutable input intact for the valid request.
	for _, raw := range []bool{true, false} {
		bad := plog.NewLogs()
		logs.CopyTo(bad)
		for i := 0; i < bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len(); i++ {
			r := bad.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(i)
			if raw {
				r.Body().SetStr("{Type:NETFLOW_V9 SrcAddr:[192 0 2 1]}")
			} else {
				r.Attributes().PutStr("source.address", "invalid IP")
			}
		}
		bad.MarkReadOnly()
		if err := ex.ConsumeLogs(ctx, bad); !consumererror.IsPermanent(err) {
			t.Fatalf("raw=%v: expected permanent rejection, got %v", raw, err)
		}
	}
	logs.MarkReadOnly()
	before := time.Now().Unix()
	must(t, ex.ConsumeLogs(ctx, logs))
	after := time.Now().Unix()
	shutdown(t, ex)
	assertDatagramLedger(t, reader, ledger, tc)

	// Count records, never batches: template packets also produce empty batches.
	stableRecords(t, ctx, sink, tc.ExpectedRecords)
	shutdown(t, rx)
	rxStopped = true
	if got := sink.LogRecordCount(); got != tc.ExpectedRecords {
		t.Fatalf("after receiver shutdown: records=%d, want %d", got, tc.ExpectedRecords)
	}
	assertRecords(t, sink.AllLogs(), logs, ledger, tc, before, after)
	t.Logf("records=%d datagrams=%d bootstrap=%d first-data-sequence=%v sampling=%v -> %v", tc.ExpectedRecords,
		fixtureDatagramCount, ledger.BootstrapDatagrams, ledger.Attributes["flow.sequence_num"], tc.WireSamplingRates, tc.Attributes["flow.sampling_rate"])
}

func stableRecords(t *testing.T, ctx context.Context, sink *consumertest.LogsSink, want int) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var stable time.Time
	for {
		got := sink.LogRecordCount()
		if got > want {
			t.Fatalf("extra receiver records: %d > %d", got, want)
		}
		if got == want {
			if stable.IsZero() {
				stable = time.Now()
			} else if time.Since(stable) >= 100*time.Millisecond {
				return
			}
		} else {
			stable = time.Time{}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("receiver records=%d, want stable %d: %v", got, want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertRecords(t *testing.T, batches []plog.Logs, input plog.Logs, ledger fixtureLedger, tc fixtureCase, before, after int64) {
	t.Helper()
	ordinal := 0
	for _, batch := range batches {
		for i := 0; i < batch.ResourceLogs().Len(); i++ {
			rl := batch.ResourceLogs().At(i)
			if rl.Resource().Attributes().Len() != 0 || rl.SchemaUrl() != "" || rl.Resource().DroppedAttributesCount() != 0 {
				t.Fatal("receiver resource changed")
			}
			for j := 0; j < rl.ScopeLogs().Len(); j++ {
				sl := rl.ScopeLogs().At(j)
				scope := sl.Scope()
				if scope.Name() != "otelcol/netflowreceiver" || scope.Version() != "" || scope.Attributes().Len() != 1 || scope.DroppedAttributesCount() != 0 || sl.SchemaUrl() != "" {
					t.Fatal("receiver scope changed")
				}
				assertAttribute(t, scope.Attributes(), "receiver", "netflow")
				for k := 0; k < sl.LogRecords().Len(); k++ {
					r := sl.LogRecords().At(k)
					a := r.Attributes()
					if ordinal >= tc.ExpectedRecords || r.Body().Type() != pcommon.ValueTypeEmpty {
						t.Fatal("unexpected record or nonempty parsed body")
					}
					expected := make(map[string]any)
					for key, value := range ledger.Attributes {
						expected[key] = value
					}
					for key, value := range tc.Attributes {
						expected[key] = value
					}
					in := input.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(ordinal).Attributes()
					if ledger.Protocol == "netflow_v5" {
						for _, key := range []string{"flow.start", "flow.end"} {
							v, _ := in.Get(key)
							expected[key] = json.Number(fmt.Sprint(v.Int()))
						}
					} else if ledger.Protocol == "netflow_v9" {
						start := intAttribute(t, a, "flow.start")
						if start%1_000_000_000 != 0 || start/1_000_000_000 < before || start/1_000_000_000 > after {
							t.Fatalf("v9 omitted timing must use export seconds: %d outside [%d,%d]", start, before, after)
						}
						expected["flow.start"], expected["flow.end"] = json.Number(fmt.Sprint(start)), json.Number(fmt.Sprint(start))
					}
					received := intAttribute(t, a, "flow.time_received")
					if received < 0 || uint64(r.ObservedTimestamp()) != uint64(received) {
						t.Fatal("receiver observed time must equal nonnegative flow.time_received")
					}
					expected["flow.time_received"] = json.Number(fmt.Sprint(received))
					if uint64(r.Timestamp()) != uint64(intAttribute(t, a, "flow.start")) {
						t.Fatal("record timestamp differs from flow.start")
					}
					original, _ := in.Get("flow.sampler_address")
					sampler, _ := a.Get("flow.sampler_address")
					if original.Str() != "192.0.2.254" || sampler.Str() == original.Str() {
						t.Fatal("original sampler must not be recovered from UDP")
					}
					if a.Len() != len(expected) {
						t.Fatalf("attributes=%d, want %d: %v", a.Len(), len(expected), a.AsRaw())
					}
					for key, value := range expected {
						assertAttribute(t, a, key, value)
					}
					ordinal++
				}
			}
		}
	}
	if ordinal != tc.ExpectedRecords {
		t.Fatalf("flattened records=%d, want %d", ordinal, tc.ExpectedRecords)
	}
}

func assertAttribute(t *testing.T, attrs pcommon.Map, key string, want any) {
	t.Helper()
	got, ok := attrs.Get(key)
	if !ok {
		t.Fatalf("missing attribute %s", key)
	}
	switch v := want.(type) {
	case string:
		if got.Type() != pcommon.ValueTypeStr || got.Str() != v {
			t.Fatalf("%s=%v (%s), want string %q", key, got.AsRaw(), got.Type(), v)
		}
	case json.Number:
		n, err := v.Int64()
		must(t, err)
		if got.Type() != pcommon.ValueTypeInt || got.Int() != n {
			t.Fatalf("%s=%v (%s), want int %d", key, got.AsRaw(), got.Type(), n)
		}
	default:
		t.Fatalf("unsupported fixture type %T", want)
	}
}

func intAttribute(t *testing.T, attrs pcommon.Map, key string) int64 {
	t.Helper()
	v, ok := attrs.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeInt {
		t.Fatalf("%s is not an OTel Int", key)
	}
	return v.Int()
}

// The ledger counts successful local datagrams, not remote acknowledgements.
// Existing golden tests establish their template/data layouts and no Options.
func assertDatagramLedger(t *testing.T, reader *sdkmetric.ManualReader, ledger fixtureLedger, tc fixtureCase) {
	t.Helper()
	var data metricdata.ResourceMetrics
	must(t, reader.Collect(context.Background(), &data))
	counts := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, point := range sum.DataPoints {
				counts[metric.Name] += point.Value
			}
		}
	}
	for name, want := range map[string]int64{
		"otelcol_netflow.exporter.templates":       int64(ledger.BootstrapDatagrams),
		"otelcol_netflow.exporter.data_messages":   1,
		"otelcol_netflow.exporter.bytes":           ledger.BootstrapBytes + tc.DataBytes,
		"otelcol_netflow.exporter.endpoint_epochs": 1,
	} {
		if counts[name] != want {
			t.Fatalf("%s=%d, ledger=%d", name, counts[name], want)
		}
	}
}

type canonicalFixture struct {
	ID         string         `json:"id"`
	Base       string         `json:"base_fixture_id"`
	Attributes map[string]any `json:"attributes"`
	Overrides  struct {
		Attributes map[string]any `json:"attributes"`
	} `json:"overrides"`
	Records []struct {
		Overrides struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"overrides"`
	} `json:"records"`
}

func canonicalLogs(t *testing.T, ledger fixtureLedger, tc fixtureCase) plog.Logs {
	t.Helper()
	path := filepath.Join("..", "testdata", "canonical", "fixtures.json")
	data, err := os.ReadFile(path)
	must(t, err)
	if fmt.Sprintf("%x", sha256.Sum256(data)) != ledger.CanonicalFileSHA256 {
		t.Fatal("canonical fixture hash changed; review ledger")
	}
	var manifest struct {
		Fixtures []canonicalFixture `json:"fixtures"`
	}
	decodeJSON(t, data, &manifest)
	byID := map[string]canonicalFixture{}
	for _, f := range manifest.Fixtures {
		byID[f.ID] = f
	}
	var resolve func(string, int) map[string]any
	resolve = func(id string, depth int) map[string]any {
		f, ok := byID[id]
		if !ok || depth > len(byID) {
			t.Fatalf("invalid fixture reference %s", id)
		}
		attrs := map[string]any{}
		if f.Base != "" {
			attrs = resolve(f.Base, depth+1)
		}
		for key, v := range f.Attributes {
			attrs[key] = v
		}
		for key, v := range f.Overrides.Attributes {
			attrs[key] = v
		}
		return attrs
	}
	attrs := resolve(tc.FixtureID, 0)
	fixture := byID[tc.FixtureID]
	count := len(fixture.Records)
	if count == 0 {
		count = 1
	}
	if count != tc.ExpectedRecords || len(tc.WireSamplingRates) != count {
		t.Fatal("fixture record/rate ledger mismatch")
	}
	logs := plog.NewLogs()
	sl := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	sl.Scope().SetName("otelcol/netflowreceiver")
	sl.Scope().Attributes().PutStr("receiver", "netflow")
	for i := 0; i < count; i++ {
		r := sl.LogRecords().AppendEmpty()
		put := func(key string, v any) {
			switch value := v.(type) {
			case string:
				r.Attributes().PutStr(key, value)
			case json.Number:
				n, err := value.Int64()
				must(t, err)
				r.Attributes().PutInt(key, n)
			default:
				t.Fatalf("unsupported canonical value %T", v)
			}
		}
		for key, v := range attrs {
			put(key, v)
		}
		if len(fixture.Records) != 0 {
			for key, v := range fixture.Records[i].Overrides.Attributes {
				put(key, v)
			}
		}
		if intAttribute(t, r.Attributes(), "flow.sampling_rate") != tc.WireSamplingRates[i] {
			t.Fatal("input sampling rates differ from ledger")
		}
		r.SetTimestamp(pcommon.Timestamp(intAttribute(t, r.Attributes(), "flow.start")))
		r.SetObservedTimestamp(pcommon.Timestamp(intAttribute(t, r.Attributes(), "flow.time_received")))
	}
	return logs
}

func readJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	decodeJSON(t, data, out)
}
func decodeJSON(t *testing.T, data []byte, out any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	must(t, decoder.Decode(out))
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func shutdown(t *testing.T, c component.Component) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}
