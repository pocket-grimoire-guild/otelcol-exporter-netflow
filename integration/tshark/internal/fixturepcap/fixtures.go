package fixturepcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Manifest is authored fixture inventory, not output discovered from a capture.
// The .yaml file uses JSON syntax (a YAML subset), as do the OCB fixture inputs.
type Manifest struct {
	Schema               string    `json:"schema"`
	Version              int       `json:"version"`
	Kind                 string    `json:"kind"`
	GoldenManifestSHA256 string    `json:"golden_manifest_sha256"`
	Captures             []Capture `json:"captures"`
}

type Capture struct {
	SlotID string `json:"slot_id"`
	PCAP   string `json:"pcap"`
	Golden string `json:"golden"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

// Packet holds the exact bytes read and verified through one directory handle.
// Oracle callers stage these bytes, never reopen the original input paths.
type Packet struct {
	Capture
	PCAPBytes []byte
	Payload   []byte
}

type fixture struct {
	Capture
	payload []byte
	port    uint16
}

// load binds the authored inventory to the existing golden manifest and files.
// The existing scripts/check-golden-manifest.py remains the canonical-source
// schema validator; this code checks the complete, hash-bound payload relation.
func load(manifestPath, goldenPath string) ([]fixture, error) {
	data, err := readRegular(manifestPath, 1<<20)
	if err != nil {
		return nil, err
	}
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing manifest data")
	}
	if m.Schema != "otel-netflow-pcap-payload-manifest" || m.Version != 1 || m.Kind != "synthetic-golden" {
		return nil, fmt.Errorf("unsupported payload manifest; live captures need separate evidence")
	}
	goldenData, err := readRegular(goldenPath, 1<<20)
	if err != nil {
		return nil, err
	}
	if hash(goldenData) != m.GoldenManifestSHA256 {
		return nil, fmt.Errorf("golden manifest hash differs from authored payload inventory")
	}
	var goldens struct {
		Schema  string
		Version int
		Slots   []struct {
			ID       string
			Protocol string
			Status   string
			Payloads []struct {
				Path   string
				Length int
				SHA256 string
			}
		}
	}
	if err := json.Unmarshal(goldenData, &goldens); err != nil {
		return nil, err
	}
	// A smaller or duplicated matrix cannot produce PASS, even if both input
	// manifests are accidentally edited together.
	expected := []string{
		"v5/canonical-ipv4-v1.bin",
		"v9/canonical-ipv4-v1.bin", "v9/canonical-ipv6-v1.bin", "v9/sampling-ie34-two-distinct-rates-v1.bin",
		"ipfix/canonical-ipv4-v1.bin", "ipfix/canonical-ipv6-v1.bin", "ipfix/sampling-ie34-two-distinct-rates-v1.bin",
	}
	if goldens.Schema != "otel-netflow-golden-manifest" || goldens.Version != 1 ||
		len(goldens.Slots) != len(expected) || len(m.Captures) != len(expected) {
		return nil, fmt.Errorf("exact seven-golden matrix required")
	}
	var result []fixture
	var paths []string
	for i, c := range m.Captures {
		slot := goldens.Slots[i]
		if len(slot.Payloads) != 1 || slot.Status != "complete" {
			return nil, fmt.Errorf("slot must contain one complete golden")
		}
		p := slot.Payloads[0]
		if c.Golden != expected[i] || p.Path != c.Golden || p.Length != c.Length || p.SHA256 != c.SHA256 ||
			c.SlotID != slot.ID || c.SlotID != strings.ReplaceAll(strings.TrimSuffix(c.Golden, ".bin"), "/", "-") ||
			c.PCAP != c.SlotID+".pcap" || slot.Protocol != strings.Split(c.Golden, "/")[0] ||
			c.Length <= 0 || c.Length > maxPayload || slices.Contains(paths, c.PCAP) {
			return nil, fmt.Errorf("capture %d does not bind the expected golden exactly once", i)
		}
		paths = append(paths, c.PCAP)
		payload, err := readRegular(filepath.Join(filepath.Dir(goldenPath), c.Golden), maxPayload)
		if err != nil {
			return nil, err
		}
		if len(payload) != c.Length || hash(payload) != c.SHA256 {
			return nil, fmt.Errorf("golden length/hash mismatch: %s", c.Golden)
		}
		version, port := uint16(5), uint16(2055)
		switch slot.Protocol {
		case "v9":
			version = 9
		case "ipfix":
			version, port = 10, 4739
		}
		if len(payload) < 2 || binary.BigEndian.Uint16(payload) != version {
			return nil, fmt.Errorf("golden protocol mismatch: %s", c.Golden)
		}
		result = append(result, fixture{c, payload, port})
	}
	return result, nil
}

// Generate writes only missing PCAPs; existing identical files are accepted.
// It never overwrites a golden, manifest, or differing capture. The complete
// input matrix is checked before output creation, and the output is verified.
func Generate(manifestPath, goldenPath, out string) error {
	fixtures, err := load(manifestPath, goldenPath)
	if err != nil {
		return err
	}
	dir, err := openDirectory(out, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, f := range fixtures {
		data, err := Wrap(f.payload, f.port)
		if err != nil {
			return err
		}
		if err := writeCapture(dir, f.PCAP, data); err != nil {
			return err
		}
	}
	return verifyDirectory(fixtures, dir)
}

// Verify proves the one-to-one payload relation, including all captured bytes.
func Verify(manifestPath, goldenPath, root string) error {
	_, err := ReadVerified(manifestPath, goldenPath, root)
	return err
}

// ReadVerified checks the complete inventory before returning any packets.
func ReadVerified(manifestPath, goldenPath, root string) ([]Packet, error) {
	fixtures, err := load(manifestPath, goldenPath)
	if err != nil {
		return nil, err
	}
	dir, err := openDirectory(root, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return readDirectory(fixtures, dir)
}

// The same directory descriptor owns every packet read and the inventory scan.
// Generate also calls this with the descriptor it used for all output writes.
func verifyDirectory(fixtures []fixture, dir *os.File) error {
	_, err := readDirectory(fixtures, dir)
	return err
}

func readDirectory(fixtures []fixture, dir *os.File) ([]Packet, error) {
	var packets []Packet
	for _, f := range fixtures {
		data, err := readRegularAt(dir, f.PCAP, 1<<17)
		if err != nil {
			return nil, err
		}
		payload, err := Extract(data, f.port)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.PCAP, err)
		}
		if len(payload) != f.Length || hash(payload) != f.SHA256 || !bytes.Equal(payload, f.payload) {
			return nil, fmt.Errorf("%s: captured UDP payload differs from golden", f.PCAP)
		}
		packets = append(packets, Packet{f.Capture, data, payload})
	}
	// Reject undeclared PCAPs rather than leaving a glob consumer a different
	// set of inputs from the set verified here. Other files (README, manifest)
	// are not packet inputs.
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, f := range fixtures {
		paths = append(paths, f.PCAP)
	}
	for _, e := range entries {
		if strings.EqualFold(filepath.Ext(e.Name()), ".pcap") && !slices.Contains(paths, e.Name()) {
			return nil, fmt.Errorf("undeclared PCAP: %s", e.Name())
		}
	}
	return packets, nil
}

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
