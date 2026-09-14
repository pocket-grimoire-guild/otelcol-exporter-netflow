package netflowexporter

import (
	"context"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/metadata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/netip"
	"time"
)

// NewFactory creates the alpha, logs-only NetFlow/IPFIX UDP exporter factory.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(metadata.Type, createDefaultConfig, exporter.WithLogs(createLogs, metadata.LogsStability))
}
func createLogs(ctx context.Context, set exporter.Settings, cfg component.Config) (exporter.Logs, error) {
	c, ok := cfg.(*Config)
	if !ok || c == nil {
		return nil, configError()
	}
	return newLogsExporter(ctx, set, c, transport.NewClock(), transport.NewDialer("udp", netip.AddrPort{}).Dial)
}
func newLogsExporter(ctx context.Context, set exporter.Settings, c *Config, clock transport.Clock, dial transport.NumericDial) (*logsExporter, error) {
	if set.Logger == nil || set.MeterProvider == nil || set.TracerProvider == nil {
		return nil, configError()
	}
	builder, err := metadata.NewTelemetryBuilder(set.TelemetrySettings)
	if err != nil {
		return nil, err
	}
	tel := telemetry{builder: builder, instance: attribute.String("exporter", set.ID.String())}
	r, err := c.newRuntimeWithObserver(clock, dial, tel.observe)
	if err != nil {
		builder.Shutdown()
		return nil, err
	}
	e := &logsExporter{runtime: r, telemetry: tel}
	// Helper emits only a fixed failure message with our redacted errors and an
	// item count. Preserve the Collector logger's clock, fields, and options
	// while adding a coarser one-event/minute burst-one cap.
	set.Logger = set.Logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewSamplerWithOptions(core, time.Minute, 1, 0)
	}))
	helper, err := exporterhelper.NewLogs(ctx, set, c, e.pushLogs,
		exporterhelper.WithStart(func(ctx context.Context, _ component.Host) error { return r.Start(ctx) }),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
		exporterhelper.WithTimeout(exporterhelper.TimeoutConfig{Timeout: 0}),
	)
	if err != nil {
		builder.Shutdown()
		return nil, err
	}
	e.helper = helper
	return e, nil
}
