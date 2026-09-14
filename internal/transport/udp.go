package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MinWriteTimeout and MaxWriteTimeout are the transport-level bounds.  A
	// destination's drain timeout is validated separately and must be at least
	// as large as this configured per-write timeout.
	MinWriteTimeout = 100 * time.Millisecond
	MaxWriteTimeout = 30 * time.Second

	maxUDPPayload = 65507
	// MaxUDPPayload is the largest IPv4/IPv6 UDP payload accepted by the
	// whole-datagram writer.
	MaxUDPPayload = maxUDPPayload
)

var (
	ErrInvalidContext     = errors.New("transport: invalid context")
	ErrInvalidTimeout     = errors.New("transport: invalid write timeout")
	ErrInvalidAddress     = errors.New("transport: invalid UDP address")
	ErrInvalidNetwork     = errors.New("transport: invalid UDP network")
	ErrDatagramTooLarge   = errors.New("transport: datagram exceeds UDP payload limit")
	ErrDeadlineSetup      = errors.New("transport: write deadline setup failed")
	ErrWriteTimeout       = errors.New("transport: write timeout")
	ErrWriteCanceled      = errors.New("transport: write canceled")
	ErrWrite              = errors.New("transport: write failed")
	ErrInvalidWriteResult = errors.New("transport: invalid write result")
	ErrClosed             = errors.New("transport: connection closed")
	ErrDial               = errors.New("transport: UDP dial failed")
)

// Conn is the narrow connected-UDP contract consumed by Writer and the
// destination lifecycle.  Addresses are netip values so the caller can
// inspect endpoint identity without parsing diagnostic strings.
// Close must promptly disable network writes and interrupt an in-flight Write;
// it must not wait for the lifecycle owner or an application callback. The
// production UDPConn satisfies this with the standard-library socket close.
type Conn interface {
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
	SetWriteDeadline(time.Time) error
	Write([]byte) (int, error)
	Close() error
}

// Dialer performs one context-aware dial of a numeric UDP endpoint.  It
// intentionally accepts netip.AddrPort rather than a hostname: name
// resolution and candidate selection belong to the resolver/lifecycle seam.
type Dialer struct {
	Network   string
	LocalAddr netip.AddrPort
}

// NewDialer constructs a numeric UDP dialer.  A zero local address lets the OS
// choose the source address and port; network must be udp, udp4, or udp6.
func NewDialer(network string, local netip.AddrPort) *Dialer {
	return &Dialer{Network: network, LocalAddr: local}
}

// Dial connects to one already-parsed numeric endpoint.
func (d *Dialer) Dial(ctx context.Context, remote netip.AddrPort) (Conn, error) {
	if ctx == nil {
		return nil, ErrInvalidContext
	}
	if err := validateUDPAddress(d.network(), d.local(), remote); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, classifyNetworkError(err)
	}
	conn, err := (&net.Dialer{}).DialUDP(ctx, d.network(), d.local(), remote)
	if err != nil {
		return nil, classifyDialError(err)
	}
	local, okLocal := conn.LocalAddr().(*net.UDPAddr)
	actualRemote, okRemote := conn.RemoteAddr().(*net.UDPAddr)
	if !okLocal || !okRemote || local == nil || actualRemote == nil {
		_ = conn.Close()
		return nil, ErrDial
	}
	localPort := local.AddrPort()
	remotePort := actualRemote.AddrPort()
	if !localPort.IsValid() || !remotePort.IsValid() {
		_ = conn.Close()
		return nil, ErrDial
	}
	return &UDPConn{conn: conn, local: localPort, remote: remotePort}, nil
}

func (d *Dialer) network() string {
	if d == nil {
		return ""
	}
	return d.Network
}

func (d *Dialer) local() netip.AddrPort {
	if d == nil {
		return netip.AddrPort{}
	}
	return d.LocalAddr
}

func validateUDPAddress(network string, local, remote netip.AddrPort) error {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return ErrInvalidNetwork
	}
	if !remote.IsValid() || remote.Addr().Zone() != "" && remote.Addr().Is4() {
		return ErrInvalidAddress
	}
	if local.IsValid() && local.Addr().Zone() != "" && local.Addr().Is4() {
		return ErrInvalidAddress
	}
	if network == "udp4" && !remote.Addr().Is4() {
		return ErrInvalidAddress
	}
	if network == "udp6" && remote.Addr().Is4() {
		return ErrInvalidAddress
	}
	if local.IsValid() {
		if network == "udp4" && !local.Addr().Is4() {
			return ErrInvalidAddress
		}
		if network == "udp6" && local.Addr().Is4() {
			return ErrInvalidAddress
		}
	}
	return nil
}

// UDPConn wraps the standard-library connected socket and records stable
// local/remote identity at dial time.  Close is idempotent; lifecycle code
// remains the sole owner responsible for deciding when to invoke it.
type UDPConn struct {
	conn   *net.UDPConn
	local  netip.AddrPort
	remote netip.AddrPort

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
}

func (c *UDPConn) LocalAddr() netip.AddrPort {
	if c == nil {
		return netip.AddrPort{}
	}
	return c.local
}

func (c *UDPConn) RemoteAddr() netip.AddrPort {
	if c == nil {
		return netip.AddrPort{}
	}
	return c.remote
}

func (c *UDPConn) SetWriteDeadline(deadline time.Time) error {
	if c == nil || c.conn == nil || c.closed.Load() {
		return ErrClosed
	}
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return classifyDeadlineError(err)
	}
	return nil
}

// Write hands exactly one datagram to the connected socket.  It never retries
// or writes a suffix after a short result.  The returned count is preserved so
// destination State can apply its full-write-only commit rule.
func (c *UDPConn) Write(payload []byte) (int, error) {
	if c == nil || c.conn == nil || c.closed.Load() {
		return 0, ErrClosed
	}
	if len(payload) > maxUDPPayload {
		return 0, ErrDatagramTooLarge
	}
	n, err := c.conn.Write(payload)
	if err != nil {
		return n, classifyWriteError(err)
	}
	return n, nil
}

func (c *UDPConn) Close() error {
	if c == nil || c.conn == nil {
		return ErrClosed
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if err := c.conn.Close(); err != nil {
			c.closeErr = classifyCloseError(err)
		}
	})
	return c.closeErr
}

// ValidateWriteTimeout checks the transport bound without normalizing or
// silently selecting a different timeout.
func ValidateWriteTimeout(timeout time.Duration) error {
	if timeout < MinWriteTimeout || timeout > MaxWriteTimeout {
		return ErrInvalidTimeout
	}
	return nil
}

// Writer performs one synchronous, context-bound whole-datagram handoff.
// Callers must serialize calls on one Writer/Conn; the mutex also protects the
// deadline cleanup boundary when a context cancellation callback is running.
// Writer never owns connection closure; the lifecycle owner must close Conn.
type Writer struct {
	conn    Conn
	timeout time.Duration
	mu      sync.Mutex
}

// NewWriter validates the timeout before constructing a writer.
func NewWriter(conn Conn, timeout time.Duration) (*Writer, error) {
	if conn == nil {
		return nil, ErrClosed
	}
	if err := ValidateWriteTimeout(timeout); err != nil {
		return nil, err
	}
	return &Writer{conn: conn, timeout: timeout}, nil
}

// Conn exposes the injected connection for lifecycle identity and closure.
func (w *Writer) Conn() Conn {
	if w == nil {
		return nil
	}
	return w.conn
}

// Timeout reports the validated configured write timeout.
func (w *Writer) Timeout() time.Duration {
	if w == nil {
		return 0
	}
	return w.timeout
}

// Write sets the earlier of the caller's deadline and configured timeout,
// then synchronously writes one datagram.  A cancellation callback interrupts
// an outstanding socket write by setting its deadline; it never closes the
// socket.  stop plus callback completion is joined before clearing the
// deadline, preventing a canceled call from poisoning a later write.
func (w *Writer) Write(ctx context.Context, payload []byte) (int, error) {
	if w == nil || w.conn == nil {
		return 0, ErrClosed
	}
	if ctx == nil {
		return 0, ErrInvalidContext
	}
	if len(payload) > maxUDPPayload {
		return 0, ErrDatagramTooLarge
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, classifyContextError(err)
	}
	now := time.Now()
	deadline := now.Add(w.timeout)
	if operationDeadline, ok := ctx.Deadline(); ok && operationDeadline.Before(deadline) {
		deadline = operationDeadline
	}
	if !deadline.After(now) {
		return 0, ErrWriteTimeout
	}
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return 0, classifyDeadlineError(err)
	}

	state := &cancelWriteState{active: atomic.Bool{}, done: make(chan struct{})}
	state.active.Store(true)
	stop := context.AfterFunc(ctx, func() {
		if state.active.Load() {
			// This callback is intentionally best-effort.  The Write result and
			// configured close owner remain authoritative.
			_ = w.conn.SetWriteDeadline(time.Now())
		}
		close(state.done)
	})

	n, writeErr := w.conn.Write(payload)
	state.active.Store(false)
	if !stop() {
		<-state.done
	}
	// Clearing the deadline is cleanup only.  Never replace the observed write
	// count or nil/non-nil outcome with a cleanup error.
	_ = w.conn.SetWriteDeadline(time.Time{})
	if n < 0 || n > len(payload) {
		return n, ErrInvalidWriteResult
	}
	if writeErr == nil {
		return n, nil
	}
	return n, classifyWriteResult(ctx, writeErr)
}

type cancelWriteState struct {
	active atomic.Bool
	done   chan struct{}
}

func classifyContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return ErrWriteCanceled
	}
	return ErrWriteTimeout
}

func classifyNetworkError(err error) error {
	if errors.Is(err, context.Canceled) {
		return ErrWriteCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrWriteTimeout
	}
	return ErrDial
}

func classifyDialError(err error) error { return classifyNetworkError(err) }

func classifyDeadlineError(err error) error {
	if fixed := fixedTransportError(err); fixed != nil {
		return fixed
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	if errors.Is(err, context.Canceled) {
		return ErrWriteCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrWriteTimeout
	}
	return ErrDeadlineSetup
}

func classifyWriteError(err error) error {
	if fixed := fixedTransportError(err); fixed != nil {
		return fixed
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	if errors.Is(err, context.Canceled) {
		return ErrWriteCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrWriteTimeout
	}
	return ErrWrite
}

func fixedTransportError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidContext):
		return ErrInvalidContext
	case errors.Is(err, ErrInvalidTimeout):
		return ErrInvalidTimeout
	case errors.Is(err, ErrInvalidAddress):
		return ErrInvalidAddress
	case errors.Is(err, ErrInvalidNetwork):
		return ErrInvalidNetwork
	case errors.Is(err, ErrDatagramTooLarge):
		return ErrDatagramTooLarge
	case errors.Is(err, ErrDeadlineSetup):
		return ErrDeadlineSetup
	case errors.Is(err, ErrWriteTimeout):
		return ErrWriteTimeout
	case errors.Is(err, ErrWriteCanceled):
		return ErrWriteCanceled
	case errors.Is(err, ErrWrite):
		return ErrWrite
	case errors.Is(err, ErrInvalidWriteResult):
		return ErrInvalidWriteResult
	case errors.Is(err, ErrClosed):
		return ErrClosed
	case errors.Is(err, ErrDial):
		return ErrDial
	default:
		return nil
	}
}

func classifyWriteResult(ctx context.Context, err error) error {
	if ctx != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return classifyContextError(contextErr)
		}
	}
	return classifyWriteError(err)
}

func classifyCloseError(err error) error {
	if fixed := fixedTransportError(err); fixed != nil {
		return fixed
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	return ErrClosed
}
