package destination

import "context"

// sendPermit serializes packet work without creating a waiter goroutine. The
// single token is never closed: operation contexts and lifecycle registration
// provide cancellation and shutdown ownership independently of serialization.
type sendPermit struct {
	token chan struct{}
}

func newSendPermit() sendPermit {
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return sendPermit{token: token}
}

// acquire returns true only when the caller owns the permit. The post-select
// context check handles the race where cancellation and a ready permit are
// observed together; in that case the token is returned before reporting
// failure.
func (p *sendPermit) acquire(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-p.token:
	}
	if ctx.Err() != nil {
		p.release()
		return false
	}
	return true
}

func (p *sendPermit) release() {
	p.token <- struct{}{}
}
