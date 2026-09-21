package mapping

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const manifestCheckerDiagnostic = "mapping manifest: FAIL: invalid manifest\n"

const (
	receiverDocumentPath = "docs/compatibility/receiver-attributes.md"
	matrixDocumentPath   = "docs/compatibility/protocol-mapping.md"
)

// sourceFixture is a deliberately small checkout containing the real checker,
// manifest, source documents and the real source files named by the manifest's
// extra references. The checker derives its root from its own location, so the
// fixture exercises the production path resolution without an override.
type sourceFixture struct {
	root      string
	manifest  string
	originals map[string][]byte
}

func newSourceFixture(t *testing.T) *sourceFixture {
	t.Helper()
	const maxSourceBytes = 512 * 1024
	const maxFixtureBytes = 4 << 20
	files := []string{
		"scripts/check-mapping-manifest.py",
		"integration/testdata/mapping/manifest.yaml",
		receiverDocumentPath,
		matrixDocumentPath,
		"internal/mapping/compiler_test.go",
		"internal/normalize/malformed_test.go",
		"internal/normalize/preflight_test.go",
	}
	repoRoot := repositoryRoot(t)
	fixture := &sourceFixture{
		root:      t.TempDir(),
		originals: make(map[string][]byte, len(files)),
	}
	fixture.manifest = filepath.Join(fixture.root, "integration", "testdata", "mapping", "manifest.yaml")
	var total int64
	for _, relative := range files {
		source := filepath.Join(repoRoot, filepath.FromSlash(relative))
		info, err := os.Lstat(source)
		if err != nil {
			t.Fatalf("stat fixture source %s: %v", relative, err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("fixture source %s is not a regular file", relative)
		}
		if info.Size() > maxSourceBytes {
			t.Fatalf("source %s is %d bytes, exceeds %d-byte bound", relative, info.Size(), maxSourceBytes)
		}
		total += info.Size()
	}
	if len(files) != 7 || total > maxFixtureBytes {
		t.Fatalf("fixture initial bound files=%d bytes=%d, want 7 files and at most %d bytes", len(files), total, maxFixtureBytes)
	}
	for _, relative := range files {
		source := filepath.Join(repoRoot, filepath.FromSlash(relative))
		fixture.originals[relative] = readFixtureFile(t, source, maxSourceBytes)
	}
	var copiedBytes int64
	for _, relative := range files {
		data := fixture.originals[relative]
		copiedBytes += int64(len(data))
		if copiedBytes > maxFixtureBytes {
			t.Fatalf("fixture copied bytes=%d, exceeds %d-byte bound", copiedBytes, maxFixtureBytes)
		}
		destination := filepath.Join(fixture.root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			t.Fatalf("create fixture directory for %s: %v", relative, err)
		}
		if err := os.WriteFile(destination, data, 0600); err != nil {
			t.Fatalf("write fixture source %s: %v", relative, err)
		}
		written, err := os.Stat(destination)
		if err != nil || !written.Mode().IsRegular() {
			t.Fatalf("fixture destination %s is not regular: %v", relative, err)
		}
	}
	if len(fixture.originals) != 7 {
		t.Fatalf("fixture regular file count=%d, want 7", len(fixture.originals))
	}
	return fixture
}

func readFixtureFile(t *testing.T, path string, limit int64) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture source %s: %v", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		t.Fatalf("read fixture source %s: %v", path, readErr)
	}
	if closeErr != nil {
		t.Fatalf("close fixture source %s: %v", path, closeErr)
	}
	if int64(len(data)) > limit {
		t.Fatalf("fixture source %s exceeded %d-byte read bound", path, limit)
	}
	return data
}

func (f *sourceFixture) path(relative string) string {
	return filepath.Join(f.root, filepath.FromSlash(relative))
}

func (f *sourceFixture) restore(t *testing.T) {
	t.Helper()
	for relative, data := range f.originals {
		if err := os.WriteFile(f.path(relative), data, 0600); err != nil {
			t.Fatalf("restore fixture source %s: %v", relative, err)
		}
	}
}

func (f *sourceFixture) runChecker(t *testing.T) checkerResult {
	t.Helper()
	result := runCheckerCommand(f.root, f.manifest)
	if result.setupErr != nil {
		t.Fatalf("checker setup failed: %v", result.setupErr)
	}
	if result.timedOut {
		t.Fatalf("checker timed out: %q", result.output)
	}
	if result.outputExceeded {
		t.Fatalf("checker diagnostics exceeded %d-byte bound", checkerOutputLimit)
	}
	return result
}

func assertCheckerValid(t *testing.T, fixture *sourceFixture) {
	t.Helper()
	result := fixture.runChecker(t)
	if result.exitCode != 0 {
		t.Fatalf("valid fixture exit=%d output=%q", result.exitCode, result.output)
	}
	if !strings.HasPrefix(result.output, "mapping manifest: PASS canonical=123 attributes=41 protocols=3 extras=4 ") {
		t.Fatalf("unexpected valid checker output=%q", result.output)
	}
}

func assertCheckerInvalid(t *testing.T, fixture *sourceFixture) {
	t.Helper()
	result := fixture.runChecker(t)
	if result.exitCode != 1 {
		t.Fatalf("invalid fixture exit=%d, want 1, output=%q", result.exitCode, result.output)
	}
	if result.output != manifestCheckerDiagnostic {
		t.Fatalf("invalid fixture diagnostic=%q, want %q", result.output, manifestCheckerDiagnostic)
	}
}

func replaceFixtureText(t *testing.T, fixture *sourceFixture, relative, old, replacement string, wantCount int) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	text := string(data)
	if count := strings.Count(text, old); count != wantCount {
		t.Fatalf("replacement %q in %s matched %d times, want %d", old, relative, count, wantCount)
	}
	updated := strings.Replace(text, old, replacement, wantCount)
	if updated == text {
		t.Fatalf("replacement %q in %s made no change", old, relative)
	}
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func appendFixtureText(t *testing.T, fixture *sourceFixture, relative, text string) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if err := os.WriteFile(path, append(data, []byte(text)...), 0600); err != nil {
		t.Fatalf("append %s: %v", relative, err)
	}
}

func replaceLineText(t *testing.T, line, old, replacement string) string {
	t.Helper()
	if count := strings.Count(line, old); count != 1 {
		t.Fatalf("line replacement %q matched %d times, want 1", old, count)
	}
	return strings.Replace(line, old, replacement, 1)
}

func mutateFixtureLine(t *testing.T, fixture *sourceFixture, relative, prefix string, mutate func(string) string) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	parts := strings.SplitAfter(string(data), "\n")
	matched := 0
	for index, part := range parts {
		line := strings.TrimSuffix(part, "\n")
		if strings.HasPrefix(line, prefix) {
			matched++
			parts[index] = mutate(line) + strings.TrimPrefix(part, line)
		}
	}
	if matched != 1 {
		t.Fatalf("line prefix %q in %s matched %d times, want 1", prefix, relative, matched)
	}
	if err := os.WriteFile(path, []byte(strings.Join(parts, "")), 0600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func removeFixtureLine(t *testing.T, fixture *sourceFixture, relative, prefix string) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	parts := strings.SplitAfter(string(data), "\n")
	kept := make([]string, 0, len(parts))
	matched := 0
	for _, part := range parts {
		line := strings.TrimSuffix(part, "\n")
		if strings.HasPrefix(line, prefix) {
			matched++
			continue
		}
		kept = append(kept, part)
	}
	if matched != 1 {
		t.Fatalf("line prefix %q in %s matched %d times, want 1", prefix, relative, matched)
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "")), 0600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func duplicateFixtureLine(t *testing.T, fixture *sourceFixture, relative, prefix string) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	parts := strings.SplitAfter(string(data), "\n")
	matched := 0
	duplicated := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		line := strings.TrimSuffix(part, "\n")
		duplicated = append(duplicated, part)
		if strings.HasPrefix(line, prefix) {
			matched++
			duplicated = append(duplicated, part)
		}
	}
	if matched != 1 {
		t.Fatalf("line prefix %q in %s matched %d times, want 1", prefix, relative, matched)
	}
	if err := os.WriteFile(path, []byte(strings.Join(duplicated, "")), 0600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func swapFixtureLines(t *testing.T, fixture *sourceFixture, relative, firstPrefix, secondPrefix string) {
	t.Helper()
	path := fixture.path(relative)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	parts := strings.SplitAfter(string(data), "\n")
	first, second := -1, -1
	for index, part := range parts {
		line := strings.TrimSuffix(part, "\n")
		if strings.HasPrefix(line, firstPrefix) {
			if first != -1 {
				t.Fatalf("line prefix %q in %s matched more than once", firstPrefix, relative)
			}
			first = index
		}
		if strings.HasPrefix(line, secondPrefix) {
			if second != -1 {
				t.Fatalf("line prefix %q in %s matched more than once", secondPrefix, relative)
			}
			second = index
		}
	}
	if first == -1 || second == -1 {
		t.Fatalf("line prefixes %q/%q in %s did not each match once", firstPrefix, secondPrefix, relative)
	}
	parts[first], parts[second] = parts[second], parts[first]
	if err := os.WriteFile(path, []byte(strings.Join(parts, "")), 0600); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func assertSourceMutation(t *testing.T, name string, mutate func(*testing.T, *sourceFixture)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		fixture := newSourceFixture(t)
		assertCheckerValid(t, fixture)
		mutate(t, fixture)
		assertCheckerInvalid(t, fixture)
		fixture.restore(t)
		assertCheckerValid(t, fixture)
	})
}

func readFixtureManifest(t *testing.T, fixture *sourceFixture) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(fixture.originals["integration/testdata/mapping/manifest.yaml"], &document); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}
	return document
}

func manifestObject(t *testing.T, document map[string]any, path ...string) map[string]any {
	t.Helper()
	var current any = document
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("manifest path %v is not an object at %s", path, key)
		}
		current, ok = object[key]
		if !ok {
			t.Fatalf("manifest path %v missing %s", path, key)
		}
	}
	object, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("manifest path %v is not an object", path)
	}
	return object
}

func assertManifestMutation(t *testing.T, name string, mutate func(*testing.T, map[string]any)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		fixture := newSourceFixture(t)
		assertCheckerValid(t, fixture)
		document := readFixtureManifest(t, fixture)
		mutate(t, document)
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("encode manifest mutation: %v", err)
		}
		if err := os.WriteFile(fixture.manifest, encoded, 0600); err != nil {
			t.Fatalf("write manifest mutation: %v", err)
		}
		assertCheckerInvalid(t, fixture)
		fixture.restore(t)
		assertCheckerValid(t, fixture)
	})
}

func TestManifestSourceContract(t *testing.T) {
	t.Run("valid-isolated-fixture", func(t *testing.T) {
		fixture := newSourceFixture(t)
		assertCheckerValid(t, fixture)
		fixture.restore(t)
		assertCheckerValid(t, fixture)
	})

	for _, tc := range []struct {
		name   string
		change func(*testing.T, *sourceFixture)
	}{
		{
			name: "comment-receiver",
			change: func(t *testing.T, fixture *sourceFixture) {
				appendFixtureText(t, fixture, receiverDocumentPath, "\n<!-- source-contract editorial comment -->\n")
			},
		},
		{
			name: "comment-matrix",
			change: func(t *testing.T, fixture *sourceFixture) {
				appendFixtureText(t, fixture, matrixDocumentPath, "\n<!-- source-contract editorial comment -->\n")
			},
		},
		{
			name: "narrative-receiver",
			change: func(t *testing.T, fixture *sourceFixture) {
				replaceFixtureText(t, fixture, receiverDocumentPath, "README is descriptive evidence only.", "README remains descriptive evidence only.", 1)
			},
		},
		{
			name: "narrative-link-matrix",
			change: func(t *testing.T, fixture *sourceFixture) {
				replaceFixtureText(t, fixture, matrixDocumentPath, "[`receiver-attributes.md`](receiver-attributes.md)", "[`receiver profile`](receiver-attributes.md)", 1)
			},
		},
		{
			name: "matrix-whitespace-normalization",
			change: func(t *testing.T, fixture *sourceFixture) {
				mutateFixtureLine(t, fixture, matrixDocumentPath, "| `source.port` |", func(line string) string {
					return replaceLineText(t, line, "**exact** `L4_SRC_PORT` (7), 2 B; 0..65535.", "**exact**  `L4_SRC_PORT`  (7),  2 B;  0..65535.")
				})
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSourceFixture(t)
			assertCheckerValid(t, fixture)
			tc.change(t, fixture)
			assertCheckerValid(t, fixture)
			fixture.restore(t)
			assertCheckerValid(t, fixture)
		})
	}

	assertSourceMutation(t, "receiver-rename", func(t *testing.T, fixture *sourceFixture) {
		mutateFixtureLine(t, fixture, receiverDocumentPath, "| `source.address` |", func(line string) string {
			return replaceLineText(t, line, "`source.address`", "`source.address.renamed`")
		})
	})
	assertSourceMutation(t, "receiver-remove", func(t *testing.T, fixture *sourceFixture) {
		removeFixtureLine(t, fixture, receiverDocumentPath, "| `source.port` |")
	})
	assertSourceMutation(t, "receiver-duplicate", func(t *testing.T, fixture *sourceFixture) {
		duplicateFixtureLine(t, fixture, receiverDocumentPath, "| `destination.address` |")
	})
	assertSourceMutation(t, "receiver-reorder", func(t *testing.T, fixture *sourceFixture) {
		swapFixtureLines(t, fixture, receiverDocumentPath, "| `source.address` |", "| `source.port` |")
	})
	assertSourceMutation(t, "matrix-classification", func(t *testing.T, fixture *sourceFixture) {
		mutateFixtureLine(t, fixture, matrixDocumentPath, "| `source.address` |", func(line string) string {
			return replaceLineText(t, line, "**exact** `srcaddr`, 4 B; IPv4 only. IPv6 is a family-mismatch rejection.", "**lossy** `srcaddr`, 4 B; IPv4 only. IPv6 is a family-mismatch rejection.")
		})
	})
	assertSourceMutation(t, "matrix-qualified-outcome", func(t *testing.T, fixture *sourceFixture) {
		mutateFixtureLine(t, fixture, matrixDocumentPath, "| `source.address` |", func(line string) string {
			return replaceLineText(t, line, "IPv4 only", "IPv4 and IPv6")
		})
	})

	for _, tc := range []struct {
		name  string
		path  []string
		key   string
		value any
	}{
		{name: "receiver-profile-id", path: []string{"sources", "receiver_profile"}, key: "id", value: "other-profile"},
		{name: "contrib-commit", path: []string{"sources", "receiver_profile"}, key: "contrib_commit", value: strings.Repeat("0", 40)},
		{name: "goflow2-commit", path: []string{"sources", "receiver_profile"}, key: "goflow2_commit", value: strings.Repeat("0", 40)},
		{name: "receiver-path", path: []string{"sources", "receiver_profile"}, key: "path", value: "docs/other-receiver.md"},
		{name: "matrix-id", path: []string{"sources", "matrix"}, key: "id", value: "other-matrix"},
		{name: "matrix-path", path: []string{"sources", "matrix"}, key: "path", value: "docs/other-matrix.md"},
	} {
		tc := tc
		assertManifestMutation(t, "provenance-"+tc.name, func(t *testing.T, document map[string]any) {
			setManifestField(t, document, tc.path, tc.key, tc.value)
		})
	}

	for _, tc := range []struct {
		name string
		path []string
		key  string
	}{
		{name: "receiver-id", path: []string{"sources", "receiver_profile"}, key: "id"},
		{name: "receiver-contrib", path: []string{"sources", "receiver_profile"}, key: "contrib_commit"},
		{name: "receiver-goflow2", path: []string{"sources", "receiver_profile"}, key: "goflow2_commit"},
		{name: "receiver-path", path: []string{"sources", "receiver_profile"}, key: "path"},
		{name: "matrix-id", path: []string{"sources", "matrix"}, key: "id"},
		{name: "matrix-path", path: []string{"sources", "matrix"}, key: "path"},
	} {
		tc := tc
		assertManifestMutation(t, "missing-identity-"+tc.name, func(t *testing.T, document map[string]any) {
			delete(manifestObject(t, document, tc.path...), tc.key)
		})
	}

	assertManifestMutation(t, "version-1", func(t *testing.T, document map[string]any) {
		document["version"] = 1
	})
	assertManifestMutation(t, "unsupported-version", func(t *testing.T, document map[string]any) {
		document["version"] = 999
	})
	for _, source := range []string{"receiver_profile", "matrix"} {
		source := source
		assertManifestMutation(t, "legacy-sha256-"+source, func(t *testing.T, document map[string]any) {
			manifestObject(t, document, "sources", source)["sha256"] = strings.Repeat("0", 64)
		})
	}
}

func setManifestField(t *testing.T, document map[string]any, path []string, key string, value any) {
	t.Helper()
	manifestObject(t, document, path...)[key] = value
}
