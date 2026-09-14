package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
)

func TestUDPWriteTimeoutValidation(t *testing.T) {
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:10001"), netip.MustParseAddrPort("127.0.0.1:10002"))
	for _, timeout := range []time.Duration{0, MinWriteTimeout - time.Nanosecond, MaxWriteTimeout + time.Nanosecond} {
		if _, err := NewWriter(conn, timeout); !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("timeout %v error = %v, want ErrInvalidTimeout", timeout, err)
		}
	}
	writer, err := NewWriter(conn, MinWriteTimeout)
	if err != nil {
		t.Fatalf("minimum timeout rejected: %v", err)
	}
	if writer.Timeout() != MinWriteTimeout {
		t.Fatalf("timeout = %v, want %v", writer.Timeout(), MinWriteTimeout)
	}
}

func TestUDPWritePreservesAllSixOutcomes(t *testing.T) {
	payload := []byte("one complete datagram")
	writeErr := errors.New("scripted write failure")
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: len(payload)},
		testtransport.WriteStep{N: len(payload), Err: writeErr},
		testtransport.WriteStep{N: len(payload) - 1},
		testtransport.WriteStep{N: len(payload) - 1, Err: writeErr},
		testtransport.WriteStep{N: 0},
		testtransport.WriteStep{N: 0, Err: writeErr},
	)
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		n   int
		err bool
	}{
		{len(payload), false}, {len(payload), true},
		{len(payload) - 1, false}, {len(payload) - 1, true},
		{0, false}, {0, true},
	}
	for i, tc := range want {
		n, gotErr := writer.Write(context.Background(), payload)
		if n != tc.n || (gotErr != nil) != tc.err {
			t.Fatalf("outcome %d = (%d,%v), want (%d,error=%t)", i, n, gotErr, tc.n, tc.err)
		}
		if tc.err && !errors.Is(gotErr, ErrWrite) {
			t.Fatalf("outcome %d error = %v, want sanitized ErrWrite", i, gotErr)
		}
	}
	writes := conn.Writes()
	if len(writes) != len(want) {
		t.Fatalf("write event count = %d, want %d", len(writes), len(want))
	}
	for i, event := range writes {
		if string(event.Payload) != string(payload) || event.N != want[i].n || (event.Err != nil) != want[i].err {
			t.Fatalf("event %d = payload %q n=%d err=%v", i, event.Payload, event.N, event.Err)
		}
	}
}

func TestUDPDeadlineSelectionAndCancellationCleanup(t *testing.T) {
	started := make(chan struct{})
	wait := make(chan struct{})
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{Wait: wait, Started: started, Err: os.ErrDeadlineExceeded},
		testtransport.WriteStep{N: 2},
	)
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	firstDone := make(chan struct{})
	var firstN int
	var firstErr error
	go func() {
		firstN, firstErr = writer.Write(ctx, []byte("ab"))
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scripted write did not start")
	}
	cancel()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("canceled write did not return")
	}
	if firstN != 0 || !errors.Is(firstErr, ErrWriteCanceled) {
		t.Fatalf("canceled write = (%d,%v), want (0, ErrWriteCanceled)", firstN, firstErr)
	}
	secondN, secondErr := writer.Write(context.Background(), []byte("cd"))
	if secondN != 2 || secondErr != nil {
		t.Fatalf("subsequent write = (%d,%v), want (2,nil)", secondN, secondErr)
	}
	var deadlines []time.Time
	for _, event := range conn.Events() {
		if event.Kind == testtransport.EventDeadline {
			deadlines = append(deadlines, event.Deadline)
		}
	}
	if len(deadlines) < 4 || deadlines[0].IsZero() || !deadlines[len(deadlines)-1].IsZero() {
		t.Fatalf("deadline events = %v, want setup/cancel/clear for both writes", deadlines)
	}
	if len(conn.Writes()) != 2 {
		t.Fatalf("write events = %d, want 2", len(conn.Writes()))
	}
}

func TestUDPAlreadyCanceledExpiredAndDeadlineSetupFailure(t *testing.T) {
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:10001"), netip.MustParseAddrPort("127.0.0.1:10002"))
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := writer.Write(canceled, []byte("x")); n != 0 || !errors.Is(err, ErrWriteCanceled) {
		t.Fatalf("already canceled = (%d,%v)", n, err)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if n, err := writer.Write(expired, []byte("x")); n != 0 || !errors.Is(err, ErrWriteTimeout) {
		t.Fatalf("expired context = (%d,%v)", n, err)
	}
	if len(conn.Events()) != 0 {
		t.Fatalf("pre-canceled calls touched connection: %+v", conn.Events())
	}
	setupErr := errors.New("sensitive endpoint setup detail")
	conn.SetDeadlineError(setupErr)
	n, writeErr := writer.Write(context.Background(), []byte("x"))
	if n != 0 || !errors.Is(writeErr, ErrDeadlineSetup) {
		t.Fatalf("deadline setup failure = (%d,%v)", n, writeErr)
	}
	if errors.Is(writeErr, setupErr) {
		t.Fatal("raw deadline setup error escaped")
	}
}

func TestUDPRejectsOversizeWithoutWrite(t *testing.T) {
	conn := testtransport.NewConn(netip.MustParseAddrPort("127.0.0.1:10001"), netip.MustParseAddrPort("127.0.0.1:10002"))
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write(context.Background(), make([]byte, maxUDPPayload+1)); n != 0 || !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversize = (%d,%v)", n, err)
	}
	if len(conn.Events()) != 0 {
		t.Fatalf("oversize write touched connection: %+v", conn.Events())
	}
}

func TestUDPCloseInterruptsOutstandingWrite(t *testing.T) {
	started := make(chan struct{})
	wait := make(chan struct{})
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{Wait: wait, Started: started},
	)
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var n int
	var writeErr error
	go func() {
		n, writeErr = writer.Write(context.Background(), []byte("blocked"))
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scripted write did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt write")
	}
	if n != 0 || !errors.Is(writeErr, ErrClosed) {
		t.Fatalf("interrupted write = (%d,%v), want (0, ErrClosed)", n, writeErr)
	}
}

func TestUDPRealIPv4LoopbackIdentityDatagramAndClose(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	conn, err := NewDialer("udp4", netip.AddrPort{}).Dial(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.LocalAddr().IsValid() || !conn.RemoteAddr().IsValid() {
		t.Fatalf("invalid identities local=%v remote=%v", conn.LocalAddr(), conn.RemoteAddr())
	}
	if conn.RemoteAddr() != remote {
		t.Fatalf("remote identity = %v, want %v", conn.RemoteAddr(), remote)
	}

	payload := []byte("loopback datagram")
	readDone := make(chan struct{})
	var got []byte
	var source *net.UDPAddr
	var readErr error
	go func() {
		buf := make([]byte, 128)
		var n int
		n, source, readErr = listener.ReadFromUDP(buf)
		got = append([]byte(nil), buf[:n]...)
		close(readDone)
	}()
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write(context.Background(), payload); n != len(payload) || err != nil {
		t.Fatalf("loopback write = (%d,%v)", n, err)
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("loopback datagram not received")
	}
	if readErr != nil || string(got) != string(payload) {
		t.Fatalf("loopback receive = (%q,%v)", got, readErr)
	}
	if source == nil || source.Port != int(conn.LocalAddr().Port()) {
		t.Fatalf("source identity = %v, local = %v", source, conn.LocalAddr())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if n, err := writer.Write(context.Background(), payload); n != 0 || !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close = (%d,%v), want (0, ErrClosed)", n, err)
	}
}

func TestUDPWriterPreservesFixedUnderlyingClasses(t *testing.T) {
	classes := []error{ErrWriteTimeout, ErrWriteCanceled, ErrWrite, ErrInvalidWriteResult, ErrClosed, ErrDatagramTooLarge, ErrDeadlineSetup, ErrDial}
	for _, want := range classes {
		t.Run(want.Error(), func(t *testing.T) {
			conn := testtransport.NewConn(
				netip.MustParseAddrPort("127.0.0.1:10001"),
				netip.MustParseAddrPort("127.0.0.1:10002"),
				testtransport.WriteStep{N: 1, Err: want},
			)
			writer, err := NewWriter(conn, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			n, got := writer.Write(context.Background(), []byte("x"))
			if n != 1 || !errors.Is(got, want) {
				t.Fatalf("result = (%d,%v), want (1,%v)", n, got, want)
			}
		})
	}
}

func TestUDPWriterRetainsFullSuccessWhenCancellationRacesAfterWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: 1, OnWrite: func() {
			cancel()
		}},
	)
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr := writer.Write(ctx, []byte("x"))
	if n != 1 || writeErr != nil {
		t.Fatalf("full success raced with cancellation = (%d,%v), want (1,nil)", n, writeErr)
	}
	if ctx.Err() == nil {
		t.Fatal("write hook did not cancel context")
	}
}

func TestUDPWriterRejectsInvalidWriteCounts(t *testing.T) {
	for _, count := range []int{-1, 2} {
		conn := testtransport.NewConn(
			netip.MustParseAddrPort("127.0.0.1:10001"),
			netip.MustParseAddrPort("127.0.0.1:10002"),
			testtransport.WriteStep{N: count},
		)
		writer, err := NewWriter(conn, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		n, got := writer.Write(context.Background(), []byte("x"))
		if n != count || !errors.Is(got, ErrInvalidWriteResult) {
			t.Errorf("count %d result = (%d,%v), want (%d,ErrInvalidWriteResult)", count, n, got, count)
		}
	}
}

func TestUDPDeadlineSelectionAndConfiguredExpiration(t *testing.T) {
	callerDeadline := time.Now().Add(500 * time.Millisecond)
	callerConn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: 1},
	)
	callerWriter, err := NewWriter(callerConn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	callerCtx, cancel := context.WithDeadline(context.Background(), callerDeadline)
	defer cancel()
	if n, err := callerWriter.Write(callerCtx, []byte("x")); n != 1 || err != nil {
		t.Fatalf("caller-deadline write = (%d,%v)", n, err)
	}
	callerEvents := callerConn.Events()
	if len(callerEvents) == 0 || !callerEvents[0].Deadline.Equal(callerDeadline) {
		t.Fatalf("caller deadline = %v, want exactly %v", callerEvents[0].Deadline, callerDeadline)
	}

	before := time.Now()
	timeoutConn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: 1},
	)
	timeoutWriter, err := NewWriter(timeoutConn, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := timeoutWriter.Write(context.Background(), []byte("x")); n != 1 || err != nil {
		t.Fatalf("configured-timeout write = (%d,%v)", n, err)
	}
	after := time.Now()
	timeoutDeadline := timeoutConn.Events()[0].Deadline
	if timeoutDeadline.Before(before.Add(200*time.Millisecond)) || timeoutDeadline.After(after.Add(200*time.Millisecond)) {
		t.Fatalf("configured deadline = %v, want within [%v,%v]", timeoutDeadline, before.Add(200*time.Millisecond), after.Add(200*time.Millisecond))
	}

	started := make(chan struct{})
	wait := make(chan struct{})
	expireConn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{Wait: wait, Started: started},
	)
	expireWriter, err := NewWriter(expireConn, MinWriteTimeout)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var n int
	var writeErr error
	go func() {
		n, writeErr = expireWriter.Write(context.Background(), []byte("x"))
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("configured-timeout write did not start")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("configured timeout did not interrupt write")
	}
	if n != 0 || !errors.Is(writeErr, ErrWriteTimeout) {
		t.Fatalf("configured expiration = (%d,%v), want (0,ErrWriteTimeout)", n, writeErr)
	}
}

func TestUDPDelayedCancellationCleanupAndCleanupFailure(t *testing.T) {
	started := make(chan struct{})
	wait := make(chan struct{})
	callbackEntered := make(chan struct{})
	releaseDeadline := make(chan struct{})
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{Wait: wait, Started: started, Err: os.ErrDeadlineExceeded},
	)
	conn.BlockDeadlineCall(2, releaseDeadline, callbackEntered)
	writer, err := NewWriter(conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var n int
	var writeErr error
	var releaseWrite, releaseCallback sync.Once
	closeWrite := func() { releaseWrite.Do(func() { close(wait) }) }
	closeCallback := func() { releaseCallback.Do(func() { close(releaseDeadline) }) }
	t.Cleanup(func() {
		cancel()
		closeWrite()
		closeCallback()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("delayed-callback write did not clean up")
		}
	})
	go func() {
		n, writeErr = writer.Write(ctx, []byte("x"))
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delayed-callback write did not start")
	}
	cancel()
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not enter blocked deadline setup")
	}
	closeWrite()
	select {
	case <-done:
		t.Fatal("writer returned before joining blocked cancellation callback")
	case <-time.After(50 * time.Millisecond):
	}
	closeCallback()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delayed callback did not finish")
	}
	if n != 0 || !errors.Is(writeErr, ErrWriteCanceled) {
		t.Fatalf("delayed cancellation = (%d,%v)", n, writeErr)
	}
	if err := conn.AddStep(testtransport.WriteStep{N: 1}); err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write(context.Background(), []byte("x")); n != 1 || err != nil {
		t.Fatalf("write after delayed cleanup = (%d,%v)", n, err)
	}

	cleanupConn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: 1},
	)
	cleanupErr := errors.New("cleanup endpoint detail")
	cleanupConn.SetDeadlineErrorOnCall(2, cleanupErr)
	cleanupWriter, err := NewWriter(cleanupConn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr = cleanupWriter.Write(context.Background(), []byte("x"))
	if n != 1 || writeErr != nil {
		t.Fatalf("cleanup failure changed result = (%d,%v), want (1,nil)", n, writeErr)
	}
}

func TestUDPTestTransportBoundsAndSnapshotIsolation(t *testing.T) {
	tooMany := make([]testtransport.WriteStep, testtransport.MaxScriptSteps+1)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("oversized script did not fail explicitly")
			}
		}()
		_ = testtransport.NewConn(netip.AddrPort{}, netip.AddrPort{}, tooMany...)
	}()
	conn := testtransport.NewConn(
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		testtransport.WriteStep{N: 1},
	)
	if n, err := conn.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("scripted write = (%d,%v)", n, err)
	}
	first := conn.Events()
	first[0].Payload[0] = 'y'
	if got := string(conn.Events()[0].Payload); got != "x" {
		t.Fatalf("event snapshot mutation changed retained payload: %q", got)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, testtransport.ErrScriptExhausted) {
		t.Fatalf("exhausted script error = %v", err)
	}
	for i := 0; i < testtransport.MaxEvents-2; i++ {
		if err := conn.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("event overflow did not fail explicitly")
			}
		}()
		_ = conn.SetWriteDeadline(time.Time{})
	}()
}
