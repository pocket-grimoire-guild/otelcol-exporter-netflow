package netflowexporter

import (
	"context"
	"errors"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
	"sync"
)

type logsExporter struct {
	telemetry    telemetry
	helper       exporter.Logs
	runtime      *destination.Runtime
	shutdownOnce sync.Once
	shutdownErr  error
}

func (e *logsExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}
func (e *logsExporter) Start(ctx context.Context, host component.Host) error {
	return e.helper.Start(ctx, host)
}
func (e *logsExporter) Shutdown(ctx context.Context) error {
	// Runtime closes sockets immediately and drains the entire admitted adapter
	// call before helper shutdown. Concurrent callers share the bounded result.
	err := e.runtime.Shutdown(ctx)
	e.shutdownOnce.Do(func() {
		e.shutdownErr = err
		if e.telemetry.lifetimeReg != nil {
			if unregisterErr := e.telemetry.lifetimeReg.Unregister(); unregisterErr != nil && e.shutdownErr == nil {
				e.shutdownErr = errors.New("netflow: shutdown failed")
			}
		}
		if e.telemetry.builder != nil {
			defer e.telemetry.builder.Shutdown()
		}
		if helperErr := e.helper.Shutdown(ctx); helperErr != nil && e.shutdownErr == nil {
			e.shutdownErr = errors.New("netflow: shutdown failed")
		}
	})
	return e.shutdownErr
}
func (e *logsExporter) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	entered := false
	err := e.runtime.Consume(ctx, func(ctx context.Context) error {
		entered = true
		if err := normalize.Preflight(logs); err != nil {
			e.telemetry.admission(ctx, "preflight")
			return consumererror.NewPermanent(errors.New("netflow: malformed logs"))
		}
		e.telemetry.admission(ctx, "accepted")
		return e.helper.ConsumeLogs(ctx, logs)
	})
	if !entered {
		reason := "invalid_context"
		switch {
		case errors.Is(err, destination.ErrRuntimeBusy):
			reason = "busy"
		case errors.Is(err, destination.ErrRuntimeClosed):
			reason = "closed"
		}
		if ctx == nil {
			ctx = context.Background()
		}
		e.telemetry.admission(ctx, reason)
	}
	return err
}
