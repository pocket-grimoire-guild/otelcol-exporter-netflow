package receiver_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	largeRequestValidRecords   = 65
	largeRequestInvalidRecords = 8
	largeRequestMetadataSize   = 17 << 20
	largeRequestMaxDatagram    = 464
)

type largeDataPacket struct {
	Records     int
	Length      int
	Sequence    uint32
	FirstRecord int
}

type largeInputSnapshot struct {
	Pdata              [32]byte
	PdataBytes         int
	ResourceAttributes [32]byte
	LargeMetadata      [32]byte
	LargeMetadataBytes int
}

// TestLargePinnedReceiverPacketization proves that one public exporter call
// can cross the retired request-size thresholds while preserving packet
// boundaries, receiver order, and valid siblings of malformed records.
func TestLargePinnedReceiverPacketization(t *testing.T) {
	for _, protocol := range []string{"netflow_v5", "netflow_v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			runLargePinnedReceiver(t, protocol)
		})
	}
}

func runLargePinnedReceiver(t *testing.T, protocol string) {
	t.Helper()
	var ledger fixtureLedger
	readJSON(t, filepathForReceiverFixture(protocol), &ledger)
	if len(ledger.Cases) == 0 {
		t.Fatal("receiver ledger has no canonical case")
	}
	tc := ledger.Cases[0]
	validLogs, validPorts, origin := largeReceiverLogs(t, ledger, tc, protocol)
	if len(validPorts) != largeRequestValidRecords {
		t.Fatalf("valid ports=%d, want %d", len(validPorts), largeRequestValidRecords)
	}
	if validLogs.LogRecordCount() != largeRequestValidRecords+largeRequestInvalidRecords {
		t.Fatalf("request records=%d, want %d valid plus %d invalid", validLogs.LogRecordCount(), largeRequestValidRecords, largeRequestInvalidRecords)
	}
	initialSequence := uint32(0)
	if protocol == "netflow_v9" {
		initialSequence = uint32(ledger.BootstrapDatagrams)
	}
	packets := largeDataPacketLayout(protocol, len(validPorts), initialSequence)
	if len(packets) < 2 {
		t.Fatal("large request did not cross a packet boundary")
	}
	snapshot := snapshotLargeInput(t, validLogs)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	defer reservation.Close()
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	if port == 0 {
		t.Fatal("reservation returned port zero")
	}

	receiverFactory := netflowreceiver.NewFactory()
	receiverConfig, ok := receiverFactory.CreateDefaultConfig().(*netflowreceiver.Config)
	if !ok {
		t.Fatal("pinned receiver config type changed")
	}
	bootstrapDatagrams := ledger.BootstrapDatagrams
	queueSize := bootstrapDatagrams + len(packets)
	receiverConfig.Scheme = "netflow"
	receiverConfig.Hostname = "127.0.0.1"
	receiverConfig.Port = port
	receiverConfig.Sockets = 1
	receiverConfig.Workers = 1
	receiverConfig.QueueSize = queueSize
	receiverConfig.SendRaw = false
	must(t, receiverConfig.Validate())
	sink := &consumertest.LogsSink{}
	rx, err := receiverFactory.CreateLogs(ctx, receivertest.NewNopSettings(receiverFactory.Type()), receiverConfig, sink)
	must(t, err)
	rxStopped := false
	defer func() {
		if !rxStopped {
			shutdown(t, rx)
		}
	}()
	host := componenttest.NewNopHost()
	must(t, reservation.Close())
	must(t, rx.Start(ctx, host))

	exporterFactory := netflowexporter.NewFactory()
	exporterConfig := exporterFactory.CreateDefaultConfig().(*netflowexporter.Config)
	exporterConfig.Endpoint = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	exporterConfig.Protocol = protocol
	exporterConfig.Mapping.Profile = &ledger.Profile
	loss := netflowexporter.LossPolicy("encode_and_count")
	exporterConfig.Mapping.LossPolicy = &loss
	exporterConfig.Mapping.ProtocolIdentifiers = []netflowexporter.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	exporterConfig.MaxDatagramSize = largeRequestMaxDatagram
	zero := uint8(0)
	identity := uint32(42)
	if protocol == "netflow_v5" {
		exporterConfig.Identity.EngineType = &zero
		exporterConfig.Identity.EngineID = &zero
		exporterConfig.Mapping.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		exporterConfig.UptimeOrigin = &origin
	} else {
		exporterConfig.Mapping.NetworkTypeVersions = []netflowexporter.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
		if protocol == "netflow_v9" {
			exporterConfig.Identity.SourceID = &identity
		} else {
			exporterConfig.Identity.ObservationDomainID = &identity
		}
	}
	must(t, exporterConfig.Validate())
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	settings := exportertest.NewNopSettings(exporterFactory.Type())
	settings.MeterProvider = provider
	ex, err := exporterFactory.CreateLogs(ctx, settings, exporterConfig)
	must(t, err)
	exStopped := false
	defer func() {
		if !exStopped {
			shutdown(t, ex)
		}
	}()
	if ex.Capabilities().MutatesData {
		t.Fatal("exporter advertises pdata mutation")
	}
	must(t, ex.Start(ctx, host))

	validBefore := time.Now().Unix()
	validLogs.MarkReadOnly()
	consumeErr := ex.ConsumeLogs(ctx, validLogs)
	validAfter := time.Now().Unix()
	if consumeErr != nil {
		t.Fatalf("mixed valid/invalid request error=%v, want nil after valid siblings confirmed", consumeErr)
	}
	assertLargeInputSnapshot(t, validLogs, snapshot)
	stableRecords(t, ctx, sink, largeRequestValidRecords)

	shutdown(t, ex)
	exStopped = true
	stableRecords(t, ctx, sink, largeRequestValidRecords)
	assertLargeDatagramMetrics(t, reader, ledger, packets)
	assertLargeReceiverRecords(t, sink.AllLogs(), ledger, tc, validPorts, packets, protocol, validBefore, validAfter, origin)

	shutdown(t, rx)
	rxStopped = true
	if got := sink.LogRecordCount(); got != largeRequestValidRecords {
		t.Fatalf("after receiver shutdown: records=%d, want %d", got, largeRequestValidRecords)
	}
	t.Logf("valid=%d invalid=%d data-datagrams=%d data-bytes=%d bootstrap=%d", len(validPorts), validLogs.LogRecordCount()-len(validPorts), len(packets), largePacketBytes(packets), ledger.BootstrapDatagrams)
}

func filepathForReceiverFixture(protocol string) string {
	return "../testdata/receiver/" + map[string]string{
		"netflow_v5": "v5",
		"netflow_v9": "v9",
		"ipfix":      "ipfix",
	}[protocol] + "/ledger.json"
}

// largeReceiverLogs retains the existing canonical fixture and ledger
// authority, then inserts invalid siblings after valid counts that surround
// the 6-, 9-, and 10-record packet boundaries. The resource string is outside
// the selected mapping and intentionally larger than the retired 16 MiB cap.
func largeReceiverLogs(t *testing.T, ledger fixtureLedger, tc fixtureCase, protocol string) (plog.Logs, []int, uint64) {
	t.Helper()
	canonical := canonicalLogs(t, ledger, tc)
	sourceResource := canonical.ResourceLogs().At(0)
	sourceScope := sourceResource.ScopeLogs().At(0)
	base := sourceScope.LogRecords().At(0)
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	sourceResource.Resource().CopyTo(resource.Resource())
	resource.SetSchemaUrl(sourceResource.SchemaUrl())
	scope := resource.ScopeLogs().AppendEmpty()
	sourceScope.Scope().CopyTo(scope.Scope())
	scope.SetSchemaUrl(sourceScope.SchemaUrl())
	resource.Resource().Attributes().PutStr("ignored.large", strings.Repeat("m", largeRequestMetadataSize))

	// These invalid records occur before the first valid record, immediately
	// around the 6/9/10-record packet boundaries, and after the final record.
	invalidAfterValid := map[int]bool{0: true, 6: true, 9: true, 10: true, 18: true, 20: true, 60: true, 65: true}
	rawBodyAfterValid := map[int]bool{20: true}
	validPorts := make([]int, 0, largeRequestValidRecords)
	validIndex := 0
	for sourceIndex := 0; validIndex < largeRequestValidRecords || invalidAfterValid[validIndex]; sourceIndex++ {
		if invalidAfterValid[validIndex] {
			r := scope.LogRecords().AppendEmpty()
			base.CopyTo(r)
			if rawBodyAfterValid[validIndex] {
				r.Body().SetStr("raw replay is unsupported")
			} else {
				r.Attributes().PutStr("source.address", "invalid IP")
			}
			delete(invalidAfterValid, validIndex)
			continue
		}
		if validIndex >= largeRequestValidRecords {
			break
		}
		r := scope.LogRecords().AppendEmpty()
		base.CopyTo(r)
		port := 10000 + validIndex
		r.Attributes().PutInt("source.port", int64(port))
		validPorts = append(validPorts, port)
		validIndex++
	}

	var origin uint64
	if protocol == "netflow_v5" {
		origin = uint64(time.Now().Truncate(time.Millisecond).Add(-2 * time.Second).UnixNano())
		for i := 0; i < scope.LogRecords().Len(); i++ {
			a := scope.LogRecords().At(i).Attributes()
			a.PutInt("flow.start", int64(origin+1_000_000_000))
			a.PutInt("flow.end", int64(origin+1_001_000_000))
		}
	}
	return logs, validPorts, origin
}

func largeDataPacketLayout(protocol string, records int, initialSequence uint32) []largeDataPacket {
	var width, maxRecords int
	switch protocol {
	case "netflow_v5":
		width, maxRecords = 48, 9
	case "netflow_v9":
		width, maxRecords = 43, 10
	case "ipfix":
		width, maxRecords = 72, 6
	default:
		panic("unsupported protocol " + protocol)
	}
	packets := make([]largeDataPacket, 0, (records+maxRecords-1)/maxRecords)
	sequence := initialSequence
	first := 0
	for first < records {
		count := records - first
		if count > maxRecords {
			count = maxRecords
		}
		base, setHeader := 24, 0
		if protocol == "netflow_v9" {
			base, setHeader = 20, 4
		} else if protocol == "ipfix" {
			base, setHeader = 16, 4
		}
		dataSetLength := setHeader + count*width
		if protocol != "netflow_v5" && dataSetLength%4 != 0 {
			padding := 4 - dataSetLength%4
			if padding < width {
				dataSetLength += padding
			}
		}
		packets = append(packets, largeDataPacket{
			Records: count, Length: base + dataSetLength, Sequence: sequence, FirstRecord: first,
		})
		if protocol == "netflow_v9" {
			sequence++
		} else {
			sequence += uint32(count)
		}
		first += count
	}
	return packets
}

func largePacketBytes(packets []largeDataPacket) int {
	total := 0
	for _, packet := range packets {
		total += packet.Length
	}
	return total
}

func assertLargeDatagramMetrics(t *testing.T, reader *metric.ManualReader, ledger fixtureLedger, packets []largeDataPacket) {
	t.Helper()
	var data metricdata.ResourceMetrics
	must(t, reader.Collect(context.Background(), &data))
	counts := map[string]int64{}
	recordOutcomes := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, point := range sum.DataPoints {
				counts[metric.Name] += point.Value
				if metric.Name == "otelcol_netflow.exporter.records" {
					outcome, ok := point.Attributes.Value("outcome")
					if !ok {
						t.Fatalf("records metric missing outcome: %v", point.Attributes)
					}
					recordOutcomes[outcome.AsString()] += point.Value
				}
			}
		}
	}
	want := map[string]int64{
		"otelcol_netflow.exporter.templates":       int64(ledger.BootstrapDatagrams),
		"otelcol_netflow.exporter.data_messages":   int64(len(packets)),
		"otelcol_netflow.exporter.bytes":           ledger.BootstrapBytes + int64(largePacketBytes(packets)),
		"otelcol_netflow.exporter.endpoint_epochs": 1,
	}
	for name, value := range want {
		if counts[name] != value {
			t.Fatalf("%s=%d, want %d (all metrics=%v)", name, counts[name], value, counts)
		}
	}
	if recordOutcomes["confirmed"] != largeRequestValidRecords || recordOutcomes["invalid"] != largeRequestInvalidRecords || recordOutcomes["ambiguous"] != 0 || recordOutcomes["unsent"] != 0 {
		t.Fatalf("record outcomes=%v, want confirmed=%d invalid=%d and no ambiguous/unsent", recordOutcomes, largeRequestValidRecords, largeRequestInvalidRecords)
	}
}

func assertLargeReceiverRecords(t *testing.T, batches []plog.Logs, ledger fixtureLedger, tc fixtureCase, validPorts []int, packets []largeDataPacket, protocol string, before, after int64, origin uint64) {
	t.Helper()
	ordinal := 0
	groups := make(map[uint32][]int, len(packets))
	for _, batch := range batches {
		for i := 0; i < batch.ResourceLogs().Len(); i++ {
			resource := batch.ResourceLogs().At(i)
			if resource.Resource().Attributes().Len() != 0 || resource.SchemaUrl() != "" || resource.Resource().DroppedAttributesCount() != 0 {
				t.Fatal("receiver resource changed")
			}
			for j := 0; j < resource.ScopeLogs().Len(); j++ {
				scope := resource.ScopeLogs().At(j)
				if scope.Scope().Name() != "otelcol/netflowreceiver" || scope.Scope().Version() != "" || scope.Scope().Attributes().Len() != 1 || scope.Scope().DroppedAttributesCount() != 0 || scope.SchemaUrl() != "" {
					t.Fatal("receiver scope changed")
				}
				assertAttribute(t, scope.Scope().Attributes(), "receiver", "netflow")
				for k := 0; k < scope.LogRecords().Len(); k++ {
					if ordinal >= len(validPorts) {
						t.Fatalf("receiver returned extra record at ordinal %d", ordinal)
					}
					record := scope.LogRecords().At(k)
					if record.Body().Type() != pcommon.ValueTypeEmpty {
						t.Fatal("receiver returned nonempty body")
					}
					packet := packets[ordinalPacket(packets, ordinal)]
					attrs := record.Attributes()
					expected := make(map[string]any, len(ledger.Attributes)+len(tc.Attributes)+2)
					for key, value := range ledger.Attributes {
						expected[key] = value
					}
					for key, value := range tc.Attributes {
						expected[key] = value
					}
					expected["source.port"] = json.Number(strconv.Itoa(validPorts[ordinal]))
					expected["flow.sequence_num"] = json.Number(strconv.FormatUint(uint64(packet.Sequence), 10))
					if protocol == "netflow_v5" {
						expected["flow.start"] = json.Number(strconv.FormatUint(origin+1_000_000_000, 10))
						expected["flow.end"] = json.Number(strconv.FormatUint(origin+1_001_000_000, 10))
					} else if protocol == "netflow_v9" {
						start := intAttribute(t, attrs, "flow.start")
						if start%1_000_000_000 != 0 || start/1_000_000_000 < before || start/1_000_000_000 > after {
							t.Fatalf("v9 flow.start=%d outside export-second range [%d,%d]", start, before, after)
						}
						end := intAttribute(t, attrs, "flow.end")
						if end != start {
							t.Fatalf("v9 flow.end=%d, want flow.start=%d", end, start)
						}
						expected["flow.start"], expected["flow.end"] = json.Number(strconv.FormatInt(start, 10)), json.Number(strconv.FormatInt(end, 10))
					}
					received := intAttribute(t, attrs, "flow.time_received")
					if received < 0 || uint64(record.ObservedTimestamp()) != uint64(received) {
						t.Fatal("receiver observed time differs from flow.time_received")
					}
					expected["flow.time_received"] = json.Number(strconv.FormatInt(received, 10))
					if uint64(record.Timestamp()) != uint64(intAttribute(t, attrs, "flow.start")) {
						t.Fatal("receiver timestamp differs from flow.start")
					}
					if attrs.Len() != len(expected) {
						t.Fatalf("record %d attributes=%d, want %d: %v", ordinal, attrs.Len(), len(expected), attrs.AsRaw())
					}
					for key, value := range expected {
						assertAttribute(t, attrs, key, value)
					}
					sequence := uint32(intAttribute(t, attrs, "flow.sequence_num"))
					groups[sequence] = append(groups[sequence], int(intAttribute(t, attrs, "source.port")))
					ordinal++
				}
			}
		}
	}
	if ordinal != len(validPorts) {
		t.Fatalf("decoded records=%d, want %d", ordinal, len(validPorts))
	}
	if len(groups) != len(packets) {
		t.Fatalf("decoded sequence groups=%d, want %d: %v", len(groups), len(packets), groups)
	}
	for _, packet := range packets {
		ports, ok := groups[packet.Sequence]
		if !ok || len(ports) != packet.Records {
			t.Fatalf("sequence %d group records=%d, want %d", packet.Sequence, len(ports), packet.Records)
		}
		for i, port := range ports {
			if port != validPorts[packet.FirstRecord+i] {
				t.Fatalf("sequence %d record %d source.port=%d, want %d", packet.Sequence, i, port, validPorts[packet.FirstRecord+i])
			}
		}
	}
}

func ordinalPacket(packets []largeDataPacket, ordinal int) int {
	for index, packet := range packets {
		if ordinal >= packet.FirstRecord && ordinal < packet.FirstRecord+packet.Records {
			return index
		}
	}
	panic(fmt.Sprintf("record ordinal %d outside packet layout", ordinal))
}

func snapshotLargeInput(t *testing.T, logs plog.Logs) largeInputSnapshot {
	t.Helper()
	resource := logs.ResourceLogs().At(0)
	large, ok := resource.Resource().Attributes().Get("ignored.large")
	if !ok || large.Type() != pcommon.ValueTypeStr {
		t.Fatal("large resource metadata missing")
	}
	attrs := resource.Resource().Attributes().AsRaw()
	delete(attrs, "ignored.large")
	pdata, err := (&plog.ProtoMarshaler{}).MarshalLogs(logs)
	must(t, err)
	return largeInputSnapshot{
		Pdata:              sha256.Sum256(pdata),
		PdataBytes:         len(pdata),
		ResourceAttributes: sha256.Sum256(mustJSON(t, attrs)),
		LargeMetadata:      sha256.Sum256([]byte(large.Str())),
		LargeMetadataBytes: len(large.Str()),
	}
}

func assertLargeInputSnapshot(t *testing.T, logs plog.Logs, before largeInputSnapshot) {
	t.Helper()
	after := snapshotLargeInput(t, logs)
	if after.Pdata != before.Pdata || after.PdataBytes != before.PdataBytes || after.ResourceAttributes != before.ResourceAttributes || after.LargeMetadata != before.LargeMetadata || after.LargeMetadataBytes != before.LargeMetadataBytes {
		t.Fatal("resource metadata changed during export")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	must(t, err)
	return data
}
