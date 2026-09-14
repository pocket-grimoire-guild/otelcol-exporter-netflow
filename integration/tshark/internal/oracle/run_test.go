package oracle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOracleHelperProcess(t *testing.T) {
	if os.Getenv("NETFLOW_ORACLE_HELPER") != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	if args[0] == "--url" {
		args = args[2:]
	} else if args[0] == "--remote=false" {
		args = args[1:]
	}
	dir := os.Getenv("NETFLOW_ORACLE_HELPER_DIR")
	mode := os.Getenv("NETFLOW_ORACLE_HELPER_MODE")
	switch args[0] {
	case "image":
		if mode == "identity" {
			fmt.Println("wrong image")
		} else {
			fmt.Println("image-id sha256:digest linux/amd64")
		}
	case "rm":
		if err := os.WriteFile(filepath.Join(dir, "removed"), []byte(strings.Join(args, " ")), 0600); err != nil {
			panic(err)
		}
		if mode == "cleanup" {
			os.Exit(1)
		}
	case "run":
		data, _ := json.Marshal(args)
		if err := os.WriteFile(filepath.Join(dir, "argv.json"), data, 0600); err != nil {
			panic(err)
		}
		switch mode {
		case "timeout":
			time.Sleep(time.Minute)
		case "output":
			fmt.Print(strings.Repeat("x", outputLimit+1))
		case "stderr":
			fmt.Fprintln(os.Stderr, "decoder warning")
		case "start":
			os.Exit(126)
		}
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

func TestContainerFailuresAndCleanup(t *testing.T) {
	for _, mode := range []string{"success", "identity", "start", "timeout", "output", "stderr", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			dir := trustedTestDir(t)
			if err := os.Mkdir(filepath.Join(dir, "fixtures"), 0700); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\\''") + "' -test.run=^TestOracleHelperProcess$ -- \"$@\"\n"
			if err = os.WriteFile(filepath.Join(dir, "podman"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			t.Setenv("NETFLOW_ORACLE_HELPER", "1")
			t.Setenv("NETFLOW_ORACLE_HELPER_DIR", dir)
			t.Setenv("NETFLOW_ORACLE_HELPER_MODE", mode)
			id := identity{ref: "oracle@sha256:digest", id: "image-id", platform: "linux/amd64", executable: "/pinned/tshark"}
			ctx := context.Background()
			if mode == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				// Cancel only after run begins, not during image inspection;
				// race-instrumented helper startup/exit can exceed 300 ms.
				go func() {
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							if _, err := os.Stat(filepath.Join(dir, "argv.json")); err == nil {
								cancel()
								return
							}
						}
					}
				}()
			}
			_, err = id.container(ctx, dir, "test", id.executable, "--version")
			if (err == nil) != (mode == "success") {
				t.Fatalf("mode %s: %v", mode, err)
			}
			_, removedErr := os.Stat(filepath.Join(dir, "removed"))
			if mode == "identity" {
				if _, err = os.Stat(filepath.Join(dir, "argv.json")); !os.IsNotExist(err) {
					t.Fatal("executed with wrong image")
				}
				return
			}
			if removedErr != nil {
				t.Fatal("container removal was skipped", removedErr)
			}
			data, err := os.ReadFile(filepath.Join(dir, "argv.json"))
			if err != nil {
				t.Fatal(err)
			}
			var args []string
			if err = json.Unmarshal(data, &args); err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"--pull=never", "--network=none", "--read-only", "--read-only-tmpfs=false", "--cap-drop=all", "--security-opt=no-new-privileges",
				"--memory=512m", "--memory-swap=512m", "--pids-limit=128", "--cpus=1", "--ulimit=nofile=128:128", "--log-driver=none",
				"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,notmpcopyup", "--env=HOME=/nonexistent",
				"type=bind,src=" + filepath.Join(dir, "fixtures") + ",dst=/fixtures,ro=true", id.ref,
			} {
				if !slices.Contains(args, required) {
					t.Fatalf("missing constraint %s", required)
				}
			}
			if slices.Contains(args[slices.Index(args, "--mount")+1:], "--mount") {
				t.Fatal("more than one fixture mount")
			}
		})
	}
}

func TestIdentityLocks(t *testing.T) {
	repo, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(repo, "integration/tshark/IMAGE_DIGEST"))
	if err != nil {
		t.Fatal(err)
	}
	image := strings.TrimSpace(string(pin))
	if _, err = loadIdentity(repo, image); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Split(image, "@")[0], image + "bad"} {
		if _, err = loadIdentity(repo, bad); err == nil {
			t.Fatal("accepted unpinned image")
		}
	}
}

func TestTrustedArtifactPaths(t *testing.T) {
	root := trustedTestDir(t)
	leaf := filepath.Join(root, "fixtures")
	if err := os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := trustedDirectory(leaf); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0770, 0777} {
		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
		if trustedDirectory(leaf) == nil {
			t.Fatal("accepted replaceable ancestor")
		}
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(leaf, leaf+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(leaf+"-original", leaf); err != nil {
		t.Fatal(err)
	}
	if trustedDirectory(leaf) == nil {
		t.Fatal("accepted substituted fixture symlink")
	}
	if trustedDirectory(root+",ro=false") == nil {
		t.Fatal("accepted mount separator")
	}
}

func TestPodmanConnection(t *testing.T) {
	for _, tc := range []struct {
		host, connection string
		valid            bool
	}{
		{"", "", true}, {"unix:///run/user/1001/podman/podman.sock", "", true},
		{"tcp://127.0.0.1:1234", "", false}, {"ssh://host/run/podman.sock", "", false},
		{"unix://host/run/podman.sock", "", false}, {"unix:///run/../podman.sock", "", false},
		{"unix:///run/podman.sock?query", "", false}, {"", "named", false},
	} {
		_, err := podmanConnection(tc.host, tc.connection)
		if (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

// The harness TMPDIR may be a group-writable shared artifact directory; use
// Linux's sticky /tmp so these tests exercise the same ancestry checks as Run.
func trustedTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "netflow-oracle-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
