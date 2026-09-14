package netflowexporter

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

type fragmentFlagCase struct {
	family wire.Family
	flags  int64
}

func TestIPFIXFragmentFlagsPublicExporter(t *testing.T) {
	t.Run("mixed-valid-siblings-and-literal-wire", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		config := fragmentFlagsConfig()
		steps := append(fragmentFlagsBootstrapSteps(),
			testtransport.WriteStep{N: 21},
			testtransport.WriteStep{N: 21},
			testtransport.WriteStep{N: 21},
		)
		exporter, conn := fragmentFlagsExporter(t, config, reader, "fragment-mixed", steps...)
		if err := exporter.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		if err := exporter.ConsumeLogs(context.Background(), fragmentFlagLogs(
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 0},
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 4},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 1},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 2},
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 3},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 7},
		)); err != nil {
			t.Fatalf("mixed ConsumeLogs=%v, want nil", err)
		}
		writes := conn.Writes()
		if len(writes) != 5 {
			t.Fatalf("writes=%d want 5 (two templates plus three data packets)", len(writes))
		}
		for index, want := range []byte{0x00, 0x20, 0x60} {
			packet := writes[index+2]
			if packet.N != 21 || packet.Err != nil || len(packet.Payload) != 21 {
				t.Fatalf("data write %d=(n=%d err=%v bytes=%d), want 21-byte full write", index, packet.N, packet.Err, len(packet.Payload))
			}
			if !bytes.Equal(packet.Payload, fragmentFlagsDataPacket(index, want)) {
				t.Fatalf("data packet %d=%x want literal %x", index, packet.Payload, fragmentFlagsDataPacket(index, want))
			}
		}
		metrics := localMetrics(t, reader)
		requireMetric(t, metrics, "records", 3, "exporter=netflow/fragment-mixed", "outcome=confirmed")
		requireMetric(t, metrics, "records", 3, "exporter=netflow/fragment-mixed", "outcome=invalid")
		requireMetric(t, metrics, "data_messages", 3, "exporter=netflow/fragment-mixed", "outcome=confirmed")
	})

	t.Run("ambiguous-and-unsent-valid-subset-excludes-invalid-suffix", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		config := fragmentFlagsConfig()
		steps := append(fragmentFlagsBootstrapSteps(),
			testtransport.WriteStep{N: 21},
			testtransport.WriteStep{N: 20, Err: errors.New("ambiguous")},
		)
		exporter, conn := fragmentFlagsExporter(t, config, reader, "fragment-partial", steps...)
		if err := exporter.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		logs := fragmentFlagLogs(
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 0},
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 3},
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 4},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 1},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 2},
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 1},
		)
		err := exporter.ConsumeLogs(context.Background(), logs)
		if err == nil || consumererror.IsPermanent(err) {
			t.Fatalf("ConsumeLogs=%v, want transient subset", err)
		}
		writes := conn.Writes()
		if len(writes) != 4 {
			t.Fatalf("writes=%d want 4 (two templates plus two data attempts)", len(writes))
		}
		if !bytes.Equal(writes[2].Payload, fragmentFlagsDataPacket(0, 0x00)) || writes[2].N != 21 || writes[2].Err != nil {
			t.Fatalf("confirmed data write=%+v want literal full packet", writes[2])
		}
		if !bytes.Equal(writes[3].Payload, fragmentFlagsDataPacket(1, 0x60)) || writes[3].N != 20 || writes[3].Err == nil {
			t.Fatalf("ambiguous data write=%+v want literal short-error packet", writes[3])
		}
		logsErr, ok := errors.AsType[consumererror.Logs](err)
		if !ok {
			t.Fatalf("error type=%T want consumererror.Logs", err)
		}
		subset := logsErr.Data()
		if subset.LogRecordCount() != 3 {
			t.Fatalf("subset records=%d want 3 (ambiguous ordinal 1 and unsent ordinals 3,5)", subset.LogRecordCount())
		}
		cursor := logCursor{logs: subset}
		for index, wantOrdinal := range []int64{1, 3, 5} {
			record, ok := cursor.at(uint64(index))
			if !ok {
				t.Fatalf("missing subset record %d", index)
			}
			value, ok := record.Attributes().Get("ordinal")
			if !ok || value.Int() != wantOrdinal {
				t.Fatalf("subset ordinal %d=%d/%v want %d", index, value.Int(), ok, wantOrdinal)
			}
		}
		metrics := localMetrics(t, reader)
		requireMetric(t, metrics, "records", 1, "exporter=netflow/fragment-partial", "outcome=confirmed")
		requireMetric(t, metrics, "records", 2, "exporter=netflow/fragment-partial", "outcome=invalid")
		requireMetric(t, metrics, "records", 1, "exporter=netflow/fragment-partial", "outcome=ambiguous")
		requireMetric(t, metrics, "records", 2, "exporter=netflow/fragment-partial", "outcome=unsent")
		requireMetric(t, metrics, "data_messages", 1, "exporter=netflow/fragment-partial", "outcome=confirmed")
		requireMetric(t, metrics, "data_messages", 1, "exporter=netflow/fragment-partial", "outcome=ambiguous")
	})

	t.Run("all-invalid-is-permanent-without-data-write", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		exporter, conn := fragmentFlagsExporter(t, fragmentFlagsConfig(), reader, "fragment-invalid", fragmentFlagsBootstrapSteps()...)
		if err := exporter.Start(context.Background(), componenttest.NewNopHost()); err != nil {
			t.Fatal(err)
		}
		err := exporter.ConsumeLogs(context.Background(), fragmentFlagLogs(
			fragmentFlagCase{family: wire.FamilyIPv4, flags: 4},
			fragmentFlagCase{family: wire.FamilyIPv6, flags: 2},
		))
		if err == nil || !consumererror.IsPermanent(err) {
			t.Fatalf("ConsumeLogs=%v want permanent", err)
		}
		if writes := conn.Writes(); len(writes) != 2 {
			t.Fatalf("writes=%d want only two template writes", len(writes))
		}
		metrics := localMetrics(t, reader)
		requireMetric(t, metrics, "records", 2, "exporter=netflow/fragment-invalid", "outcome=invalid")
	})
}

func fragmentFlagsConfig() *Config {
	config := validConfig("ipfix")
	config.Mapping.Profile = nil
	config.Mapping.Fields = ptr([]FieldSelection{{Canonical: "flow.ip_flags"}})
	config.Mapping.ProtocolIdentifiers = nil
	config.Mapping.NetworkTypeVersions = nil
	config.MaxRecordsPerMessage = ptr(uint16(1))
	return config
}

func fragmentFlagsBootstrapSteps() []testtransport.WriteStep {
	return []testtransport.WriteStep{{N: 28}, {N: 28}}
}

func fragmentFlagsExporter(t *testing.T, config *Config, reader *sdkmetric.ManualReader, name string, steps ...testtransport.WriteStep) (*logsExporter, *testtransport.Conn) {
	t.Helper()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	settings := exportertest.NewNopSettings(NewFactory().Type())
	settings.ID = component.NewIDWithName(NewFactory().Type(), name)
	settings.MeterProvider = provider
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort(config.Endpoint), steps...)
	exporter, err := newLogsExporter(context.Background(), settings, config, testclock.New(1788220802000000000, 1), func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })
	return exporter, conn
}

func fragmentFlagLogs(cases ...fragmentFlagCase) plog.Logs {
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	scope := resource.ScopeLogs().AppendEmpty()
	for ordinal, testCase := range cases {
		var source plog.LogRecord
		if testCase.family == wire.FamilyIPv6 {
			source = testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		} else {
			source = testpdata.CanonicalIPv4Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		}
		record := scope.LogRecords().AppendEmpty()
		source.CopyTo(record)
		record.Attributes().PutStr("flow.type", "ipfix")
		record.Attributes().PutInt("flow.ip_flags", testCase.flags)
		record.Attributes().PutInt("ordinal", int64(ordinal))
	}
	logs.MarkReadOnly()
	return logs
}

func fragmentFlagsDataPacket(sequence int, value byte) []byte {
	return []byte{
		0x00, 0x0a, 0x00, 0x15,
		0x6a, 0x96, 0x15, 0x82,
		byte(sequence >> 24), byte(sequence >> 16), byte(sequence >> 8), byte(sequence),
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x05, value,
	}
}
