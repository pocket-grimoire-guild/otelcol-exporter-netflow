package independent_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The operator-authorized v1.7.9 smoke uses stock binaries supplied by the
// caller. No download, install, aggregation, or receiver source patch occurs.
func TestNfcapd(t *testing.T) {
	bin, dump := os.Getenv("NFCAPD_BINARY"), os.Getenv("NFDUMP_BINARY")
	if bin == "" && dump == "" {
		t.Skip("set NFCAPD_BINARY and NFDUMP_BINARY to stock nfdump 1.7.9 binaries")
	}
	if bin == "" || dump == "" {
		t.Fatal("both NFCAPD_BINARY and NFDUMP_BINARY are required")
	}
	root := os.Getenv("NFCAPD_ARTIFACTS")
	if root == "" {
		root = t.TempDir()
	} else {
		var err error
		root, err = filepath.Abs(root)
		must(t, err)
		must(t, os.Mkdir(root, 0700)) // Stale flow files cannot satisfy a run.
	}
	for name, path := range map[string]*string{"nfcapd": &bin, "nfdump": &dump} {
		var err error
		*path, err = filepath.Abs(*path)
		must(t, err)
		version := runNfdumpCommand(t, context.Background(), *path, "-V")
		if !bytes.Contains(version, []byte(": Version: 1.7.9-release options:")) {
			t.Fatalf("requires stock nfdump 1.7.9: %s", version)
		}
		must(t, os.WriteFile(filepath.Join(root, name+"-version.txt"), version, 0600))
		writeJSON(t, filepath.Join(root, name+"-binary.json"), map[string]string{
			"path": *path, "sha256": fmt.Sprintf("%x", sha256.Sum256(readFile(t, *path))),
		})
	}
	t.Logf("receiver artifacts: %s", root)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		var ledger fixtureLedger
		decodeJSON(t, readFile(t, filepath.Join("..", "testdata", "receiver", protocol, "ledger.json")), &ledger)
		if len(ledger.Cases) == 0 {
			t.Fatal("empty fixture ledger")
		}
		for _, tc := range ledger.Cases {
			t.Run(protocol+"/"+tc.Name, func(t *testing.T) { runNfcapd(t, bin, dump, root, protocol, ledger, tc, -1) })
		}
		if protocol == "ipfix" {
			for _, n := range []int{3, 255} {
				t.Run(fmt.Sprintf("ipfix/enterprise-%d", n), func(t *testing.T) {
					runNfcapd(t, bin, dump, root, protocol, ledger, ledger.Cases[0], n)
				})
			}
		}
	}
	// The versioned general profile deliberately has no old receiver ledger
	// entry. Reuse the same pinned nfcapd path with a fresh measured-time input
	// so the independent collector decodes IE 152/153 rather than NTP 156/157.
	var generalLedger fixtureLedger
	decodeJSON(t, readFile(t, filepath.Join("..", "testdata", "receiver", "ipfix", "ledger.json")), &generalLedger)
	t.Run("ipfix-general/canonical-ipv4", func(t *testing.T) {
		runNfcapdProfile(t, bin, dump, root, "ipfix", generalLedger, generalLedger.Cases[0], -1, "contrib-netflowreceiver-v0.160.0/ipfix-general-v1")
	})
	v9Timed := fixtureLedger{}
	decodeJSON(t, readFile(t, filepath.Join("..", "testdata", "receiver", "v9", "ledger.json")), &v9Timed)
	for _, name := range []string{"canonical-ipv4", "canonical-ipv6"} {
		var selected fixtureCase
		for _, candidate := range v9Timed.Cases {
			if candidate.Name == name {
				selected = candidate
				break
			}
		}
		if selected.Name == "" {
			t.Fatalf("timed profile fixture %q missing", name)
		}
		t.Run("v9-timed/"+name, func(t *testing.T) {
			runNfcapdProfile(t, bin, dump, root, "v9", v9Timed, selected, -1, "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1")
		})
	}
}

func runNfcapd(t *testing.T, bin, dump, root, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int) {
	runNfcapdProfile(t, bin, dump, root, protocol, ledger, tc, customLen, "")
}

func runNfcapdProfile(t *testing.T, bin, dump, root, protocol string, ledger fixtureLedger, tc fixtureCase, customLen int, profileOverride string) {
	t.Helper()
	dir := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	flows := filepath.Join(dir, "flows")
	must(t, os.Mkdir(dir, 0700))
	must(t, os.Mkdir(flows, 0700))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reservation := udpListener(t)
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	if port < 1024 {
		t.Fatal("requires an unprivileged receiver port")
	}
	must(t, reservation.Close())
	stop := startNfcapd(t, ctx, bin, dir, flows, port)
	started := time.Now().Truncate(time.Millisecond)
	stream, _ := exportStreamProfile(t, ctx, dir, port, protocol, ledger, tc, customLen, profileOverride)
	projectionProtocol := protocol
	if profileOverride == "contrib-netflowreceiver-v0.160.0/ipfix-general-v1" {
		projectionProtocol = "ipfix-general"
	}
	expected := nfdumpProjection(projectionProtocol, tc, stream)
	if profileOverride == "contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1" {
		expected = nfdumpTimedProjection(tc, stream)
	}
	writeJSON(t, filepath.Join(dir, "expected.json"), expected)
	// Decode only completed, renamed flow files. Range syntax supplies one
	// ordered input stream, so cnt is continuous even across file rotation.
	read := func() []map[string]any {
		t.Helper()
		entries, err := os.ReadDir(flows)
		must(t, err)
		var names []string
		completed := regexp.MustCompile(`^nfcapd\.[0-9]{14}$`)
		for _, entry := range entries {
			if !completed.MatchString(entry.Name()) {
				continue
			}
			info, err := entry.Info()
			must(t, err)
			if !info.Mode().IsRegular() || info.Size() > 1<<20 {
				t.Fatal("expected a regular flow file no larger than 1 MiB")
			}
			names = append(names, entry.Name())
		}
		if len(names) == 0 {
			return nil
		}
		args := []string{"-C", "none", "-q", "-R", filepath.Join(flows, names[0]) + ":" + names[len(names)-1], "-o", "ndjson"}
		writeJSON(t, filepath.Join(dir, "decode-command.json"), append([]string{dump}, args...))
		data := runNfdumpCommand(t, ctx, dump, args...)
		must(t, os.WriteFile(filepath.Join(dir, "decoded.jsonl"), data, 0600))
		rows, err := parseRows(data, true)
		must(t, err)
		return rows
	}
	var stable time.Time
	for {
		rows := read()
		if len(rows) > len(expected) {
			t.Fatalf("extra decoded rows: %d > %d", len(rows), len(expected))
		}
		if len(rows) == len(expected) {
			must(t, compareNfdumpRows(rows, expected, started, time.Now()))
			if stable.IsZero() {
				stable = time.Now()
			} else if time.Since(stable) >= 100*time.Millisecond {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("decoded %d/%d rows: %v; see %s", len(rows), len(expected), ctx.Err(), dir)
		case <-time.After(50 * time.Millisecond):
		}
	}
	stop() // Joins the receiver's final rotation and postprocessor flush.
	rows := read()
	must(t, compareNfdumpRows(rows, expected, started, time.Now()))
	t.Logf("%d exact flow records from %d retained datagrams; sampling and enterprise losses projected explicitly", len(rows), len(stream))
}

func startNfcapd(t *testing.T, ctx context.Context, bin, dir, flows string, port int) func() {
	t.Helper()
	logPath := filepath.Join(dir, "receiver.log")
	log, err := os.Create(logPath)
	must(t, err)
	t.Cleanup(func() { _ = log.Close() })
	args := []string{"-C", "none", "-w", flows, "-b", "127.0.0.1", "-p", fmt.Sprint(port), "-4", "-t", "2", "-I", "otel-netflow"}
	writeJSON(t, filepath.Join(dir, "command.json"), append([]string{bin}, args...))
	cmd := exec.Command(bin, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	cmd.Env = append(os.Environ(), "TZ=UTC")
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
				t.Errorf("nfcapd exit: %v; see %s", err, logPath)
			}
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			t.Errorf("nfcapd shutdown exceeded 5 seconds; see %s", logPath)
		}
	}
	t.Cleanup(stop)
	for {
		data := readFile(t, logPath)
		// Foreground LogInfo goes to stderr. This message follows successful
		// bind, decoder initialization, postprocessor launch and bookkeepers.
		if bytes.Contains(data, []byte("Startup nfcapd.")) {
			select {
			case err := <-done:
				stopped = true
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				t.Fatalf("nfcapd exited at readiness: %v\n%s", err, data)
			default:
			}
			return stop
		}
		select {
		case err := <-done:
			stopped = true
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Fatalf("nfcapd exited before readiness: %v\n%s", err, data)
		case <-ctx.Done():
			t.Fatalf("nfcapd readiness: %v\n%s", ctx.Err(), data)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type nfdumpOutput struct{ bytes.Buffer }

func (b *nfdumpOutput) Write(p []byte) (int, error) {
	if len(p) > (1<<20)-b.Len() {
		return 0, fmt.Errorf("nfdump output exceeded 1 MiB")
	}
	return b.Buffer.Write(p)
}

func runNfdumpCommand(t *testing.T, parent context.Context, bin string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	cmd.WaitDelay = time.Second
	var output nfdumpOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("nfdump command: %v\n%s", err, output.Bytes())
	}
	return output.Bytes()
}
