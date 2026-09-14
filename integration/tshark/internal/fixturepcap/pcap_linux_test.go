package fixturepcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	manifestPath = "../../../testdata/pcap/payload-manifest.yaml"
	goldenPath   = "../../../testdata/golden/manifest.json"
)

func TestGoldenPCAPs(t *testing.T) {
	out := t.TempDir()
	must(t, Generate(manifestPath, goldenPath, out))
	must(t, Verify(manifestPath, goldenPath, out))
	// Regeneration is deterministic and may not rewrite an existing file.
	path := filepath.Join(out, "v5-canonical-ipv4-v1.pcap")
	before, err := os.Stat(path)
	must(t, err)
	must(t, Generate(manifestPath, goldenPath, out))
	after, err := os.Stat(path)
	must(t, err)
	if before.ModTime() != after.ModTime() {
		t.Fatal("regeneration rewrote an existing capture")
	}
	fixtures, err := load(manifestPath, goldenPath)
	must(t, err)
	for _, f := range fixtures {
		t.Run(f.SlotID, func(t *testing.T) {
			before := bytes.Clone(f.payload)
			packet, err := Wrap(f.payload, f.port)
			must(t, err)
			if !bytes.Equal(before, f.payload) {
				t.Fatal("wrapper mutated its input")
			}
			// Literal envelope/payload offsets supplement parser checks.
			if len(packet) != 82+f.Length || !bytes.Equal(packet[82:], f.payload) ||
				binary.BigEndian.Uint16(packet[56:58]) != uint16(28+f.Length) ||
				binary.BigEndian.Uint16(packet[78:80]) != uint16(8+f.Length) {
				t.Fatal("literal PCAP/IP/UDP framing differs")
			}
			for n := 0; n < len(packet); n++ {
				if _, err := Extract(packet[:n], f.port); err == nil {
					t.Fatalf("accepted truncation at byte %d", n)
				}
			}
		})
	}
}

func TestPCAPCorruption(t *testing.T) {
	fixtures, err := load(manifestPath, goldenPath)
	must(t, err)
	f := fixtures[4] // IPFIX: zero checksums must never be accepted.
	packet, err := Wrap(f.payload, f.port)
	must(t, err)
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"magic", 0}, {"version", 4}, {"reserved", 8}, {"snaplen", 16}, {"linktype", 20},
		{"timestamp", 24}, {"timestamp-fraction", 28}, {"captured-length", 32}, {"original-length", 36},
		{"ethernet", 40}, {"ethertype", 52}, {"ip-version-ihl", 54}, {"ip-length", 56},
		{"ip-id", 58}, {"fragment-flags", 60}, {"fragment-offset", 61}, {"ttl", 62},
		{"ip-protocol", 63}, {"ip-checksum", 64}, {"ip-source", 66}, {"ip-destination", 70},
		{"udp-source", 74}, {"udp-destination", 76}, {"udp-length", 78}, {"udp-checksum", 80},
		{"flow-header", 82}, {"flow-record", len(packet) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(packet)
			bad[tc.offset] ^= 1
			if _, err := Extract(bad, f.port); err == nil {
				t.Fatal("accepted corrupted packet")
			}
		})
	}
	for _, extra := range [][]byte{{0}, packet[24:]} {
		if _, err := Extract(append(bytes.Clone(packet), extra...), f.port); err == nil {
			t.Fatal("accepted trailing bytes/second packet")
		}
	}
	bad := bytes.Clone(packet)
	clear(bad[80:82])
	if _, err := Extract(bad, f.port); err == nil {
		t.Fatal("accepted absent UDP checksum")
	}
	if _, err := Extract(packet, 2055); err == nil {
		t.Fatal("accepted wrong destination protocol port")
	}
}

func TestChecksumsAndBounds(t *testing.T) {
	// RFC 1071 section 3 example: folded sum ddf2, complemented to 220d.
	vector, err := hex.DecodeString("0001f203f4f5f6f7")
	must(t, err)
	if checksum(vector) != 0x220d {
		t.Fatal("checksum differs from independent RFC 1071 example")
	}
	// For the documented addresses, ports 40000/4739, and UDP length 10,
	// the zero-checksum pseudoheader/header sum is 0x34e5. Payload 0xcb1a
	// makes the sum 0xffff; RFC 768 requires 0xffff on wire, never zero.
	zero, err := Wrap([]byte{0xcb, 0x1a}, 4739)
	must(t, err)
	if binary.BigEndian.Uint16(zero[80:82]) != 0xffff {
		t.Fatal("computed-zero UDP checksum was not transmitted as all ones")
	}
	_, err = Extract(zero, 4739)
	must(t, err)
	for _, n := range []int{1, 3, maxPayload - 1, maxPayload} {
		payload := bytes.Repeat([]byte{0xff}, n)
		packet, err := Wrap(payload, 4739)
		must(t, err)
		got, err := Extract(packet, 4739)
		must(t, err)
		if !bytes.Equal(got, payload) {
			t.Fatal("odd/maximum payload changed")
		}
	}
	for _, n := range []int{0, maxPayload + 1} {
		if _, err := Wrap(make([]byte, n), 4739); err == nil {
			t.Fatal("accepted out-of-range payload")
		}
	}
	if _, err := Wrap([]byte{1}, 0); err == nil {
		t.Fatal("accepted port zero")
	}
}

func TestManifestAndPayloadRejection(t *testing.T) {
	base, err := os.ReadFile(manifestPath)
	must(t, err)
	for _, tc := range []struct {
		name string
		edit func(*Manifest)
	}{
		{"missing", func(m *Manifest) { m.Captures = m.Captures[:6] }},
		{"duplicate", func(m *Manifest) { m.Captures[1] = m.Captures[0] }},
		{"reorder", func(m *Manifest) { m.Captures[1], m.Captures[2] = m.Captures[2], m.Captures[1] }},
		{"golden-binding", func(m *Manifest) { m.GoldenManifestSHA256 = strings.Repeat("0", 64) }},
		{"live-substitution", func(m *Manifest) { m.Kind = "live" }},
		{"length", func(m *Manifest) { m.Captures[0].Length++ }},
		{"digest", func(m *Manifest) { m.Captures[0].SHA256 = strings.Repeat("0", 64) }},
		{"path-traversal", func(m *Manifest) { m.Captures[0].PCAP = "../out.pcap" }},
		{"golden-path", func(m *Manifest) { m.Captures[0].Golden = "/tmp/other.bin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m Manifest
			must(t, json.Unmarshal(base, &m))
			tc.edit(&m)
			data, err := json.Marshal(m)
			must(t, err)
			path := filepath.Join(t.TempDir(), "manifest.yaml")
			must(t, os.WriteFile(path, data, 0600))
			out := filepath.Join(t.TempDir(), "not-created")
			if err := Generate(path, goldenPath, out); err == nil {
				t.Fatal("accepted invalid manifest")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("created output before validating complete inputs")
			}
		})
	}
	t.Run("checksummed-payload-substitution", func(t *testing.T) {
		out := t.TempDir()
		must(t, Generate(manifestPath, goldenPath, out))
		fixtures, err := load(manifestPath, goldenPath)
		must(t, err)
		f := fixtures[0]
		f.payload[len(f.payload)-1] ^= 1
		packet, err := Wrap(f.payload, f.port) // Recompute valid outer checksums.
		must(t, err)
		path := filepath.Join(out, f.PCAP)
		must(t, os.WriteFile(path, packet, 0600))
		if err := Verify(manifestPath, goldenPath, out); err == nil || !strings.Contains(err.Error(), "differs from golden") {
			t.Fatalf("accepted substituted payload with valid checksums: %v", err)
		}
		if err := Generate(manifestPath, goldenPath, out); err == nil {
			t.Fatal("overwrote a differing capture")
		}
		got, err := os.ReadFile(path)
		must(t, err)
		if !bytes.Equal(got, packet) {
			t.Fatal("modified differing capture")
		}
	})
	t.Run("extra-capture", func(t *testing.T) {
		out := t.TempDir()
		must(t, Generate(manifestPath, goldenPath, out))
		must(t, os.WriteFile(filepath.Join(out, "extra.pcap"), []byte{1}, 0600))
		if err := Verify(manifestPath, goldenPath, out); err == nil {
			t.Fatal("accepted undeclared capture")
		}
	})
}

func TestRegularFixtureFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	must(t, os.WriteFile(file, []byte{1, 2, 3}, 0600))
	link := filepath.Join(dir, "link")
	must(t, os.Symlink(file, link))
	dirLink := filepath.Join(dir, "dir-link")
	must(t, os.Symlink(dir, dirLink))
	fifo := filepath.Join(dir, "fifo")
	must(t, syscall.Mkfifo(fifo, 0600))
	for _, path := range []string{dir, link, filepath.Join(dirLink, "regular"), fifo} {
		if _, err := readRegular(path, 100); err == nil {
			t.Fatalf("accepted non-regular/symlink input: %s", path)
		}
	}
	if _, err := readRegular(file, 2); err == nil {
		t.Fatal("accepted input over read bound")
	}
	data, err := readRegular(file, 3)
	must(t, err)
	if !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatal("regular file read changed bytes")
	}
	if err := Generate(manifestPath, goldenPath, dirLink); err == nil {
		t.Fatal("accepted symlink output directory")
	}
	out := t.TempDir()
	must(t, Generate(manifestPath, goldenPath, out))
	pcap := filepath.Join(out, "v5-canonical-ipv4-v1.pcap")
	must(t, os.Rename(pcap, pcap+".saved"))
	must(t, os.Symlink(pcap+".saved", pcap))
	if err := Verify(manifestPath, goldenPath, out); err == nil {
		t.Fatal("accepted symlink capture")
	}
	if err := Generate(manifestPath, goldenPath, out); err == nil {
		t.Fatal("accepted existing symlink output")
	}
}

func TestOutputDirectorySubstitution(t *testing.T) {
	base := t.TempDir()
	out := filepath.Join(base, "out")
	dir, err := openDirectory(out, true)
	must(t, err)
	defer dir.Close()
	// Deterministically replace the checked path after obtaining the handle.
	// Writes and existing-file checks must stay in the originally opened dir.
	saved := filepath.Join(base, "saved")
	must(t, os.Rename(out, saved))
	other := t.TempDir()
	must(t, os.Symlink(other, out))
	data := []byte{1, 2, 3}
	must(t, writeCapture(dir, "fixture.pcap", data))
	must(t, writeCapture(dir, "fixture.pcap", data))
	got, err := os.ReadFile(filepath.Join(saved, "fixture.pcap"))
	must(t, err)
	if !bytes.Equal(got, data) {
		t.Fatal("write left the held output directory")
	}
	entries, err := os.ReadDir(other)
	must(t, err)
	if len(entries) != 0 {
		t.Fatal("created files in substituted directory")
	}
	if _, err := openDirectory(filepath.Join(out, "new"), true); err == nil {
		t.Fatal("created a directory through substituted symlink")
	}
	if err := Verify(manifestPath, goldenPath, out); err == nil {
		t.Fatal("verified a substituted output pathname")
	}
}

func TestVerificationDirectorySubstitution(t *testing.T) {
	for _, extra := range []bool{false, true} {
		base := t.TempDir()
		out := filepath.Join(base, "out")
		must(t, Generate(manifestPath, goldenPath, out))
		dir, err := openDirectory(out, false)
		must(t, err)
		defer dir.Close()
		saved := filepath.Join(base, "saved")
		must(t, os.Rename(out, saved))
		// A replacement regular directory has a valid complete matrix. It must
		// not hide corruption or an extra capture in the held directory.
		must(t, Generate(manifestPath, goldenPath, out))
		name := "v5-canonical-ipv4-v1.pcap"
		if extra {
			name = "extra.pcap"
		}
		must(t, os.WriteFile(filepath.Join(saved, name), []byte{1}, 0600))
		fixtures, err := load(manifestPath, goldenPath)
		must(t, err)
		if err := verifyDirectory(fixtures, dir); err == nil {
			t.Fatal("verified replacement instead of held directory")
		}
		must(t, Verify(manifestPath, goldenPath, out))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
