package destination

import (
	"context"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// Consume holds the sole whole-request slot through preflight, helper entry,
// Pack and failed-subset copying. It borrows the callback only until return.
// The lifecycle mutex is the same authority used by publication and Shutdown;
// send remains reserved for packet work, not preflight or helper processing.
func (r *Runtime) Consume(ctx context.Context, consume func(context.Context) error) error {
	if ctx == nil || consume == nil {
		return transport.ErrInvalidContext
	}
	r.lifecycle.Lock()
	if r.closing {
		r.lifecycle.Unlock()
		return ErrRuntimeClosed
	}
	if r.requestCancel != nil {
		r.lifecycle.Unlock()
		return ErrRuntimeBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	r.requestCancel = cancel
	r.activeCalls++
	r.lifecycle.Unlock()
	defer func() {
		cancel()
		r.lifecycle.Lock()
		r.requestCancel = nil
		r.endCallLocked()
		r.lifecycle.Unlock()
	}()
	return consume(ctx)
}
