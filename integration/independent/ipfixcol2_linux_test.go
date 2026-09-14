package independent_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in only: the caller supplies a stock release and its matching plugins
// and libfds definitions. Tests never download or install external programs.
func TestIPFIXcol2(t *testing.T) {
	bin := os.Getenv("IPFIXCOL2_BINARY")
	if bin == "" {
		t.Skip("set IPFIXCOL2_BINARY to stock IPFIXcol2 2.8.0 with libfds 0.6.0")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	must(t, err)
	if !bytes.Contains(version, []byte("Version:      2.8.0\n")) || !bytes.Contains(version, []byte("GIT hash:     03528c6\n")) {
		t.Fatalf("requires stock IPFIXcol2 2.8.0: %s", version)
	}
	root := os.Getenv("IPFIXCOL2_ARTIFACTS")
	if root == "" {
		root = t.TempDir()
	} else {
		root, err = filepath.Abs(root)
		must(t, err)
		must(t, os.Mkdir(root, 0700)) // Never accept stale decoded output.
	}
	must(t, os.WriteFile(filepath.Join(root, "version.txt"), version, 0600))
	writeJSON(t, filepath.Join(root, "binary.json"), map[string]string{
		"path": bin, "sha256": fmt.Sprintf("%x", sha256.Sum256(readFile(t, bin))),
		"plugins": os.Getenv("IPFIXCOL2_PLUGINS"), "definitions": os.Getenv("IPFIXCOL2_DEFINITIONS"),
	})
	t.Logf("receiver artifacts: %s", root)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		var ledger fixtureLedger
		decodeJSON(t, readFile(t, filepath.Join("..", "testdata", "receiver", protocol, "ledger.json")), &ledger)
		if len(ledger.Cases) == 0 {
			t.Fatal("empty fixture ledger")
		}
		for _, tc := range ledger.Cases {
			t.Run(protocol+"/"+tc.Name, func(t *testing.T) { runIPFIXcol2(t, bin, root, protocol, ledger, tc, -1) })
		}
		if protocol == "ipfix" {
			for _, n := range []int{3, 255} {
				t.Run(fmt.Sprintf("ipfix/enterprise-%d", n), func(t *testing.T) { runIPFIXcol2(t, bin, root, protocol, ledger, ledger.Cases[0], n) })
			}
		}
	}
}

func runIPFIXcol2(t *testing.T, bin, root, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int) {
	t.Helper()
	dir := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	must(t, os.Mkdir(dir, 0700))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reservation := udpListener(t)
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	output := filepath.Join(dir, "decoded.jsonl")
	// Listen before starting the JSON send output. Its constructor connects;
	// accepting that connection before export avoids any absent-client loss.
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(t, err)
	defer listener.Close()
	jsonPort := listener.Addr().(*net.TCPAddr).Port
	if port < 1024 || jsonPort < 1024 {
		t.Fatal("requires unprivileged ports")
	}
	config := fmt.Sprintf(`<ipfixcol2>
 <inputPlugins><input><name>UDP</name><plugin>udp</plugin><params>
  <localIPAddress>127.0.0.1</localIPAddress><localPort>%d</localPort>
 </params></input></inputPlugins>
 <outputPlugins><output><name>JSON</name><plugin>json</plugin><params>
  <tcpFlags>raw</tcpFlags><timestamp>unix</timestamp><protocol>raw</protocol>
  <ignoreUnknown>false</ignoreUnknown><ignoreOptions>false</ignoreOptions>
  <octetArrayAsUint>false</octetArrayAsUint><numericNames>true</numericNames>
  <detailedInfo>true</detailedInfo><templateInfo>true</templateInfo>
  <outputs><send><name>Loopback</name><ip>127.0.0.1</ip><port>%d</port>
   <protocol>tcp</protocol><blocking>false</blocking>
  </send></outputs>
 </params></output></outputPlugins>
</ipfixcol2>
`, port, jsonPort)
	configPath := filepath.Join(dir, "ipfixcol2.xml")
	must(t, os.WriteFile(configPath, []byte(config), 0600))
	must(t, reservation.Close())
	stop := startIPFIXcol2(t, ctx, bin, configPath, dir, port)
	must(t, listener.SetDeadline(time.Now().Add(3*time.Second)))
	conn, err := listener.AcceptTCP()
	must(t, err)
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	must(t, conn.SetReadDeadline(deadline))
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, err)
	copied := make(chan error, 1)
	go func() {
		// This nine-case matrix has at most tens of KiB per case. Bound a broken
		// receiver's output, and fail instead of accepting a truncated prefix.
		n, err := io.Copy(file, io.LimitReader(conn, 1<<20))
		if err == nil && n == 1<<20 {
			err = fmt.Errorf("receiver output exceeded 1 MiB")
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		copied <- err
	}()
	joined := false
	defer func() {
		_ = conn.Close()
		if !joined {
			<-copied
		}
	}()
	stream, custom := exportStream(t, ctx, dir, port, protocol, ledger, tc, customLen)
	expected := ipfixcolProjection(protocol, tc, stream, custom)
	writeJSON(t, filepath.Join(dir, "expected.json"), expected)
	var stable time.Time
	for {
		rows, err := readRows(output, false)
		must(t, err)
		if len(rows) > len(expected) {
			t.Fatalf("extra decoded rows: %d > %d", len(rows), len(expected))
		}
		if len(rows) == len(expected) {
			must(t, compareIPFIXcolRows(rows, expected))
			if stable.IsZero() {
				stable = time.Now()
			} else if time.Since(stable) >= 100*time.Millisecond {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("decoded %d/%d rows: %v; see %s", len(rows), len(expected), ctx.Err(), dir)
		case <-time.After(10 * time.Millisecond):
		}
	}
	stop()
	select {
	case err := <-copied:
		joined = true
		must(t, err)
	case <-ctx.Done():
		t.Fatal("JSON connection did not close after receiver shutdown")
	}
	rows, err := readRows(output, true)
	must(t, err)
	must(t, compareIPFIXcolRows(rows, expected))
	t.Logf("%d exact JSON rows (%d data records) from %d retained datagrams", len(rows), 3*tc.ExpectedRecords, len(stream))
}

func startIPFIXcol2(t *testing.T, ctx context.Context, bin, config, dir string, port int) func() {
	t.Helper()
	logPath := filepath.Join(dir, "receiver.log")
	log, err := os.Create(logPath)
	must(t, err)
	t.Cleanup(func() { _ = log.Close() })
	args := []string{"-c", config, "-vvv"}
	for _, opt := range []struct{ env, flag string }{{"IPFIXCOL2_PLUGINS", "-p"}, {"IPFIXCOL2_DEFINITIONS", "-e"}} {
		if value := os.Getenv(opt.env); value != "" {
			args = append(args, opt.flag, value)
		}
	}
	// The stock logger uses stdio buffering even for readiness messages.
	// Line buffering exposes its actual bind/thread-start messages promptly.
	stdbuf, err := exec.LookPath("stdbuf")
	must(t, err)
	command := append([]string{"-oL", "-eL", bin}, args...)
	writeJSON(t, filepath.Join(dir, "command.json"), append([]string{stdbuf}, command...))
	cmd := exec.Command(stdbuf, command...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	must(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Signal(syscall.SIGINT)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ipfixcol2 exit: %v; see %s", err, logPath)
			}
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			t.Errorf("ipfixcol2 shutdown exceeded 5 seconds; see %s", logPath)
		}
	}
	t.Cleanup(stop)
	for {
		data := readFile(t, logPath)
		if bytes.Contains(data, []byte(fmt.Sprintf("Bind succeed on 127.0.0.1 (port %d)", port))) && bytes.Contains(data, []byte("All threads of instances has been successfully started.")) {
			return stop
		}
		select {
		case err := <-done:
			stopped = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Fatalf("ipfixcol2 exited before readiness: %v\n%s", err, readFile(t, logPath))
		case <-ctx.Done():
			t.Fatalf("ipfixcol2 readiness: %v\n%s", ctx.Err(), data)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func compareIPFIXcolRows(got, want []map[string]any) error {
	// JSON output follows input order, including every duplicate/refresh
	// template. Full equality forbids missing/extra fields, wrong types, Options,
	// scaled counters, or a silently omitted enterprise value.
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("IPFIXcol2 JSON mismatch:\n got %#v\nwant %#v", got, want)
	}
	return nil
}
