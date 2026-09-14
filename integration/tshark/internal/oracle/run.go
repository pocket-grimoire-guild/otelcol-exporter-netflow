package oracle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

// Config names a trusted checkout and optionally an existing shared artifact
// directory. With remote Podman, these absolute paths must exist on its host.
type Config struct{ Repo, Image, Artifacts string }

type identity struct{ ref, id, platform, executable, executableHash string }

func loadIdentity(repo, image string) (identity, error) {
	var id identity
	data, err := os.ReadFile(filepath.Join(repo, "integration/tshark/source.lock"))
	if err != nil {
		return id, err
	}
	values := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || values[k] != "" {
			return id, fmt.Errorf("invalid source lock")
		}
		values[k] = v
	}
	pin, err := os.ReadFile(filepath.Join(repo, "integration/tshark/IMAGE_DIGEST"))
	if err != nil {
		return id, err
	}
	if values["schema"] != "otel-netflow-tshark-source-v1" || values["version"] != "4.6.8" ||
		values["source_commit"] != "e677bf052328efc1ed897a547fa161836a0e4ff7" ||
		strings.TrimSpace(string(pin)) != image || values["image_ref"] != image || !strings.Contains(image, "@sha256:") ||
		values["platform"] != "linux/amd64" || len(values["image_id"]) != 64 || len(values["executable_sha256"]) != 64 ||
		values["executable_path"] != "/opt/tshark-4.6.8/bin/tshark" {
		return id, fmt.Errorf("the exact checked-in source/image identity is required")
	}
	return identity{image, values["image_id"], values["platform"], values["executable_path"], values["executable_sha256"]}, nil
}

type limitedOutput struct {
	buffer   bytes.Buffer
	overflow bool
	cancel   context.CancelFunc
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > outputLimit-b.buffer.Len() {
		b.overflow = true
		b.cancel()
		return 0, fmt.Errorf("command output exceeds 1 MiB")
	}
	return b.buffer.Write(p)
}

// command drains bounded stdout/stderr concurrently. Overflow, deadline and
// cancellation kill the client; callers separately remove the remote container.
func command(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stdout, stderr := &limitedOutput{cancel: cancel}, &limitedOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, fmt.Errorf("command output exceeded 1 MiB"))
	}
	return stdout.buffer.Bytes(), stderr.buffer.Bytes(), err
}

// Select the local engine explicitly so environment/named connections cannot
// silently redirect bind mounts to an SSH/TCP host. A mounted local Unix socket
// is supported only with the documented identical shared workspace paths.
func podman(ctx context.Context, args ...string) ([]byte, []byte, error) {
	prefix, err := podmanConnection(os.Getenv("CONTAINER_HOST"), os.Getenv("CONTAINER_CONNECTION"))
	if err != nil {
		return nil, nil, err
	}
	return command(ctx, "podman", append(prefix, args...)...)
}

func podmanConnection(host, connection string) ([]string, error) {
	if connection != "" {
		return nil, fmt.Errorf("named Podman connections are unsupported")
	}
	if host == "" {
		return []string{"--remote=false"}, nil
	}
	u, err := url.Parse(host)
	if err != nil || u.Scheme != "unix" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path {
		return nil, fmt.Errorf("only a local Unix Podman socket with identical shared filesystem paths is supported")
	}
	return []string{"--url", host}, nil
}

func (id identity) check(ctx context.Context) error {
	out, stderr, err := podman(ctx, "image", "inspect", id.ref, "--format", "{{.Id}} {{.Digest}} {{.Os}}/{{.Architecture}}")
	_, digest, _ := strings.Cut(id.ref, "@")
	if err != nil || len(stderr) != 0 || strings.TrimSpace(string(out)) != id.id+" "+digest+" "+id.platform {
		return fmt.Errorf("pinned image inspect mismatch/failure: %w", errors.Join(err, errors.New(string(stderr))))
	}
	return nil
}

func (id identity) container(ctx context.Context, stage, label, entry string, args ...string) (out []byte, result error) {
	if err := id.check(ctx); err != nil {
		return nil, err
	}
	if err := trustedDirectory(filepath.Join(stage, "fixtures")); err != nil {
		return nil, err
	}
	name := "netflow-" + filepath.Base(stage) + "-" + label
	// Cleanup has an independent deadline: a canceled decode cannot skip it.
	// --rm handles ordinary exits; force/remove also covers timeout/start failure.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, stderr, err := podman(cleanup, "rm", "--force", "--ignore", "--time=2", name)
		if err != nil || len(stderr) != 0 {
			result = errors.Join(result, fmt.Errorf("container cleanup failed: %v: %s", err, stderr))
		}
	}()
	cmd := []string{"run", "--rm", "--name", name, "--pull=never", "--userns=keep-id", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--network=none", "--read-only", "--read-only-tmpfs=false", "--cap-drop=all", "--security-opt=no-new-privileges",
		"--memory=512m", "--memory-swap=512m", "--pids-limit=128", "--cpus=1", "--ulimit=nofile=128:128", "--log-driver=none",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,notmpcopyup", "--env=HOME=/nonexistent", "--env=TZ=UTC", "--env=LC_ALL=C",
		"--mount", "type=bind,src=" + filepath.Join(stage, "fixtures") + ",dst=/fixtures,ro=true", "--entrypoint", entry, id.ref}
	cmd = append(cmd, args...)
	out, stderr, err := podman(ctx, cmd...)
	if writeErr := os.WriteFile(filepath.Join(stage, label+".stdout"), out, 0600); writeErr != nil {
		result = errors.Join(result, writeErr)
	}
	if writeErr := os.WriteFile(filepath.Join(stage, label+".stderr"), stderr, 0600); writeErr != nil {
		result = errors.Join(result, writeErr)
	}
	if err != nil || len(stderr) != 0 {
		result = errors.Join(result, fmt.Errorf("%s container failed: %v: %s", label, err, stderr))
	}
	return out, result
}

// Run performs all seven decodes or returns an error. It never falls back to
// a host binary, mutable image tag, preexisting decoder report, or network pull.
func Run(ctx context.Context, cfg Config) (result error) {
	id, err := loadIdentity(cfg.Repo, cfg.Image)
	if err != nil {
		return err
	}
	out, stderr, err := podman(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil || len(stderr) != 0 || strings.TrimSpace(string(out)) != "true" || os.Getuid() == 0 {
		return fmt.Errorf("rootless Podman and non-root caller required: %v: %s", err, stderr)
	}
	packets, err := fixturepcap.ReadVerified(filepath.Join(cfg.Repo, "integration/testdata/pcap/payload-manifest.yaml"), filepath.Join(cfg.Repo, "integration/testdata/golden/manifest.json"), filepath.Join(cfg.Repo, "integration/testdata/pcap"))
	if err != nil {
		return err
	}
	parent := cfg.Artifacts
	if parent == "" {
		parent = filepath.Join(cfg.Repo, "dist")
		if err = os.MkdirAll(parent, 0700); err != nil {
			return err
		}
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	if err := trustedDirectory(parent); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, "tshark-")
	if err != nil {
		return err
	}
	if cfg.Artifacts == "" {
		defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()
	}
	if err = os.Mkdir(filepath.Join(stage, "fixtures"), 0700); err != nil {
		return err
	}
	for _, p := range packets {
		if err = os.WriteFile(filepath.Join(stage, "fixtures", p.PCAP), p.PCAPBytes, 0400); err != nil {
			return err
		}
	}
	out, err = id.container(ctx, stage, "version", id.executable, "--version")
	if err != nil {
		return err
	}
	if strings.SplitN(string(out), "\n", 2)[0] != "TShark (Wireshark) 4.6.8 (Git commit e677bf052328)." {
		return fmt.Errorf("TShark version mismatch")
	}
	out, err = id.container(ctx, stage, "executable", "/usr/bin/sha256sum", id.executable)
	if err != nil {
		return err
	}
	if string(out) != id.executableHash+"  "+id.executable+"\n" {
		return fmt.Errorf("TShark executable hash mismatch")
	}
	for _, p := range packets {
		out, err = id.container(ctx, stage, p.SlotID, id.executable, "-n", "-r", "/fixtures/"+p.PCAP, "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-T", "pdml")
		if err != nil {
			return err
		}
		if err = VerifyPDML(out, p); err != nil {
			return fmt.Errorf("%s: %w", p.SlotID, err)
		}
	}
	// A compact ledger is emitted only after all independent checks and cleanup.
	return os.WriteFile(filepath.Join(stage, "PASS.txt"), []byte("synthetic-golden only\n"+id.ref+"\nimage_id="+id.id+"\nseven payloads: PDML field values/order/widths/offsets, lengths, hashes, checksums\n"), 0600)
}
