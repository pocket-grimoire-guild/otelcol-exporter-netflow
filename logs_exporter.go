package netflowexporter

import (
	"context"
	"errors"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func (e *logsExporter) pushLogs(ctx context.Context, logs plog.Logs) error {
	cursor := logCursor{logs: logs}
	result, err := e.runtime.Pack(ctx, logs, func(ordinal uint64, key string) (wire.Value, bool) {
		record, ok := cursor.at(ordinal)
		if !ok {
			return wire.Value{}, false
		}
		value, ok := record.Attributes().Get(key)
		if !ok {
			return wire.Value{}, false
		}
		switch value.Type() {
		case pcommon.ValueTypeInt:
			return wire.IntValue(value.Int()), true
		case pcommon.ValueTypeStr:
			return wire.StringValue(value.Str()), true
		case pcommon.ValueTypeBytes:
			return wire.BorrowedBytesValue(value.Bytes()), true
		default:
			return wire.Value{}, false
		}
	})
	e.telemetry.record(ctx, result)
	if err == nil {
		return nil
	}
	if result == nil {
		reason := "internal"
		switch {
		case errors.Is(err, destination.ErrRuntimeBusy):
			reason = "busy"
		case errors.Is(err, destination.ErrRuntimeClosed):
			reason = "closed"
		case errors.Is(err, destination.ErrRuntimeUnavailable):
			reason = "unavailable"
		}
		e.telemetry.failure(ctx, reason)
		return err
	} // fixed unavailable/busy/closed, before packet work
	if result.Outcome() == destination.PackInternal {
		e.telemetry.failure(ctx, "internal")
	}
	if result.Outcome() != destination.PackTransient {
		return consumererror.NewPermanent(errors.New("netflow: records rejected"))
	}
	subset, err := returnedSubset(logs, result)
	if err != nil {
		return consumererror.NewPermanent(errors.New("netflow: subset rejected"))
	}
	return consumererror.NewLogs(errors.New("netflow: transient packet handoff"), subset)
}

// logCursor visits hierarchy nodes once while servicing monotonically ordered
// source ordinals. Repeated lookups for one record borrow the same log handle.
type logCursor struct {
	logs                    plog.Logs
	resource, scope, record int
	ordinal                 uint64
}

func (c *logCursor) at(want uint64) (plog.LogRecord, bool) {
	if want < c.ordinal {
		return plog.LogRecord{}, false
	}
	resources := c.logs.ResourceLogs()
	for c.resource < resources.Len() {
		scopes := resources.At(c.resource).ScopeLogs()
		for c.scope < scopes.Len() {
			records := scopes.At(c.scope).LogRecords()
			for c.record < records.Len() {
				if c.ordinal == want {
					return records.At(c.record), true
				}
				c.record++
				c.ordinal++
			}
			c.scope++
			c.record = 0
		}
		c.resource++
		c.scope = 0
	}
	return plog.LogRecord{}, false
}

// returnedSubset selects the existing ledger's ambiguous and valid unsent
// ordinals. It copies each retained resource/scope envelope once, and only the
// selected logs. The packet result already owns the complete source ledger;
// subset construction therefore does not run a second aggregate admission or
// bounds check over arbitrary metadata.
func returnedSubset(logs plog.Logs, result *destination.PackResult) (plog.Logs, error) {
	if result == nil {
		return plog.Logs{}, errors.New("netflow: missing packet result")
	}
	subset := plog.NewLogs()
	var ordinal uint64
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		sourceResource := logs.ResourceLogs().At(i)
		var targetResource plog.ResourceLogs
		resourceCopied := false
		for j := 0; j < sourceResource.ScopeLogs().Len(); j++ {
			sourceScope := sourceResource.ScopeLogs().At(j)
			var targetScope plog.ScopeLogs
			scopeCopied := false
			for k := 0; k < sourceScope.LogRecords().Len(); k++ {
				class := result.Classification(ordinal)
				ordinal++
				if class != destination.SourceAmbiguous && class != destination.SourceUnsentValid {
					continue
				}
				if !resourceCopied {
					targetResource = subset.ResourceLogs().AppendEmpty()
					sourceResource.Resource().CopyTo(targetResource.Resource())
					targetResource.SetSchemaUrl(sourceResource.SchemaUrl())
					resourceCopied = true
				}
				if !scopeCopied {
					targetScope = targetResource.ScopeLogs().AppendEmpty()
					sourceScope.Scope().CopyTo(targetScope.Scope())
					targetScope.SetSchemaUrl(sourceScope.SchemaUrl())
					scopeCopied = true
				}
				sourceScope.LogRecords().At(k).CopyTo(targetScope.LogRecords().AppendEmpty())
			}
		}
	}
	// pdata Value.CopyTo preserves the backing array of bytes values in the
	// pinned collector API. Detach every byte leaf after the hierarchy has been
	// selected so a retry can outlive and independently mutate its input.
	// Each leaf's backing is moved into a per-call scratch ByteSlice and copied
	// back into its existing bytes wrapper, which also remains safe when
	// pdata's optional proto pooling feature gate is enabled.
	detachLogsBytes(subset)
	return subset, nil
}

func detachLogsBytes(logs plog.Logs) {
	// Reuse one standalone byte wrapper for every leaf. Moving the source into
	// scratch leaves its existing AnyValue bytes wrapper in place; copying back
	// through ByteSlice then gives the source leaf independent backing without
	// allocating a replacement AnyValue wrapper for every leaf. The scratch is
	// local to this subset copy and never shared between calls.
	scratch := pcommon.NewByteSlice()
	work := make([]pcommon.Value, 0, 64)
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		resource := logs.ResourceLogs().At(i)
		detachMapBytes(resource.Resource().Attributes(), scratch, &work)
		for j := 0; j < resource.ScopeLogs().Len(); j++ {
			scope := resource.ScopeLogs().At(j)
			detachMapBytes(scope.Scope().Attributes(), scratch, &work)
			for k := 0; k < scope.LogRecords().Len(); k++ {
				record := scope.LogRecords().At(k)
				detachMapBytes(record.Attributes(), scratch, &work)
				detachValueBytesWork(record.Body(), scratch, &work)
			}
		}
	}
}

func detachMapBytes(values pcommon.Map, scratch pcommon.ByteSlice, work *[]pcommon.Value) {
	values.Range(func(_ string, value pcommon.Value) bool {
		appendDetachWork(value, work)
		return true
	})
	detachValuesBytes(work, scratch)
}

func detachValueBytes(value pcommon.Value, scratch pcommon.ByteSlice) {
	work := make([]pcommon.Value, 0, 1)
	detachValueBytesWork(value, scratch, &work)
}

// detachValuesBytes walks selected AnyValue containers with an explicit
// stack. pdata's public CopyTo methods recursively copy AnyValue values, so
// this adapter-owned byte detachment must avoid adding another recursive walk
// when metadata is deeper than the old admission policy allowed.
func detachValueBytesWork(value pcommon.Value, scratch pcommon.ByteSlice, work *[]pcommon.Value) {
	appendDetachWork(value, work)
	detachValuesBytes(work, scratch)
}

func detachValuesBytes(work *[]pcommon.Value, scratch pcommon.ByteSlice) {
	for len(*work) != 0 {
		last := len(*work) - 1
		value := (*work)[last]
		*work = (*work)[:last]
		switch value.Type() {
		case pcommon.ValueTypeBytes:
			source := value.Bytes()
			source.MoveTo(scratch)
			scratch.CopyTo(source)
		case pcommon.ValueTypeMap:
			value.Map().Range(func(_ string, child pcommon.Value) bool {
				appendDetachWork(child, work)
				return true
			})
		case pcommon.ValueTypeSlice:
			slice := value.Slice()
			for i := 0; i < slice.Len(); i++ {
				appendDetachWork(slice.At(i), work)
			}
		}
	}
}

func appendDetachWork(value pcommon.Value, work *[]pcommon.Value) {
	switch value.Type() {
	case pcommon.ValueTypeBytes, pcommon.ValueTypeMap, pcommon.ValueTypeSlice:
		*work = append(*work, value)
	}
}
