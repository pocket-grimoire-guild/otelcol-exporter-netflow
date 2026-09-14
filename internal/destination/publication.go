package destination

import (
	"context"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
)

// bootstrap writes outside send: only this registered, attached attempt can
// use its unpublished socket. State bounds rounds and shapes and commits each
// full template datagram with the selected protocol's sequence rules.
func (r *Runtime) bootstrap(ctx context.Context, attempt *candidateAttempt, state *State) error {
	if state.Epoch().Ready { // v5 has no bootstrap datagram
		return nil
	}
	buffer := make([]byte, int(state.Config().MaxDatagramSize))
	for !state.Epoch().Ready {
		if ctx.Err() != nil {
			return ErrRuntimeUnavailable
		}
		wall, mono := r.clock.Now()
		packet, err := state.BeginTemplate(wall, mono, state.Progress().NextShape)
		if err != nil {
			return err
		}
		n, err := packet.Encode(buffer)
		if err != nil {
			return err
		}
		r.lifecycle.Lock()
		candidate := attempt.candidate
		if r.closing || r.attempt != attempt || candidate == nil || ctx.Err() != nil {
			r.lifecycle.Unlock()
			_ = packet.Abort()
			return ErrRuntimeUnavailable
		}
		r.activeWrites++
		r.lifecycle.Unlock()
		writeN, writeErr := candidate.Write(ctx, buffer[:n])
		r.endWrite()
		commit, err := state.Commit(packet, writeN, writeErr)
		if err != nil {
			return err
		}
		r.config.Observe.handoff(ctx, BootstrapConfirmed, BootstrapAmbiguous, commit)
		if !commit.Committed {
			return ErrPackTransient
		}
	}
	return nil
}

func (r *Runtime) publish(ctx context.Context, attempt *candidateAttempt, token transport.MaintenanceToken, next *endpoint) error {
	// Retire the old handle outside both locks, but before the registered
	// attempt completes. Shutdown therefore joins this cleanup as well.
	var retired *endpoint
	defer func() {
		if retired != nil {
			_ = retired.candidate.Close()
		}
	}()
	r.send.Lock()
	defer r.send.Unlock()
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closing || ctx.Err() != nil || r.attempt != attempt || attempt.candidate != next.candidate || r.published != attempt.previous || !next.state.Epoch().Ready {
		return ErrRuntimeUnavailable
	}
	snapshot := r.resolver.Snapshot()
	if next.candidate.Generation() != token.Generation() || snapshot.Generation != token.Generation() || snapshot.Selected != next.candidate.RemoteAddr().Addr() {
		return ErrRuntimeUnavailable
	}
	// This is the last fallible step. No observer can see resolver publication
	// without its matching fully bootstrapped socket, State and Packer.
	if err := r.resolver.CommitPublishedCandidate(token); err != nil {
		return err
	}
	retired, r.published = r.published, next
	attempt.candidate = nil // transfer ownership; failure cleanup cannot close it
	return nil
}
