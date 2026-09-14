package oracle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

const (
	generalIPv4Length = 180
	generalIPv6Length = 204
)

// RunGeneral independently decodes the fresh IPFIX Unix-millisecond fixtures
// with the same pinned image and isolation policy as Run. The separate entry
// point keeps the established seven-golden matrix immutable while allowing the
// new profile to acquire an actual decoder execution seam.
func RunGeneral(ctx context.Context, cfg Config) (result error) {
	id, err := loadIdentity(cfg.Repo, cfg.Image)
	if err != nil {
		return err
	}
	out, stderr, err := podman(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil || len(stderr) != 0 || strings.TrimSpace(string(out)) != "true" || os.Getuid() == 0 {
		return fmt.Errorf("rootless Podman and non-root caller required: %v: %s", err, stderr)
	}
	packets, err := readGeneralPackets(cfg.Repo)
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
	stage, err := os.MkdirTemp(parent, "tshark-general-")
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
		if err = VerifyGeneralPDML(out, p); err != nil {
			return fmt.Errorf("%s: %w", p.SlotID, err)
		}
	}
	return os.WriteFile(filepath.Join(stage, "PASS.txt"), []byte("fresh IPFIX general 152/153 payloads: PDML field values/order/widths/offsets, lengths, hashes, checksums\n"+id.ref+"\nimage_id="+id.id+"\n"), 0600)
}

func readGeneralPackets(repo string) ([]fixturepcap.Packet, error) {
	root := filepath.Join(repo, "integration/testdata/golden/ipfix")
	if err := trustedDirectory(root); err != nil {
		return nil, err
	}
	type fixture struct {
		name, slot string
		length     int
		hash       string
	}
	fixtures := []fixture{
		{"general-ipv4-v1.bin", "ipfix-general-ipv4-v1", generalIPv4Length, "d13784d17f685d41faa64d40b371b4037031ababecc52b534fe0aafab4a12b01"},
		{"general-ipv6-v1.bin", "ipfix-general-ipv6-v1", generalIPv6Length, "7ef96d2a3b76ad904d3c08d91a98122f6f6d4f01b790c3f3c166a67820ddbed6"},
	}
	var packets []fixturepcap.Packet
	for _, f := range fixtures {
		payload, err := readLiveFile(root, f.name)
		if err != nil {
			return nil, err
		}
		if len(payload) != f.length {
			return nil, fmt.Errorf("%s length %d, want %d", f.name, len(payload), f.length)
		}
		if err := validateGeneralPayload(payload); err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		gotHash := fmt.Sprintf("%x", sha256.Sum256(payload))
		if f.hash != "" && gotHash != f.hash {
			return nil, fmt.Errorf("%s SHA-256 %s, want %s", f.name, gotHash, f.hash)
		}
		pcap, err := fixturepcap.Wrap(payload, 4739)
		if err != nil {
			return nil, err
		}
		packets = append(packets, fixturepcap.Packet{
			Capture:   fixturepcap.Capture{SlotID: f.slot, PCAP: f.slot + ".pcap", Length: len(payload), SHA256: gotHash},
			PCAPBytes: pcap,
			Payload:   payload,
		})
	}
	return packets, nil
}

// VerifyGeneralPDML uses literal expectations for the two new payloads. It
// deliberately does not ask the production catalog for field names or offsets.
func VerifyGeneralPDML(data []byte, packet fixturepcap.Packet) error {
	want, err := expectedGeneralFlow(packet.SlotID)
	if err != nil {
		return err
	}
	length := generalIPv4Length
	if strings.HasSuffix(packet.SlotID, "ipv6-v1") {
		length = generalIPv6Length
	}
	expected := map[string]any{
		"frame.number": 1, "frame.len": length + 42, "frame.cap_len": length + 42,
		"frame.protocols": "eth:ethertype:ip:udp:cflow", "frame.time_epoch": "1788220803.000000000",
		"eth.src": "02:00:00:00:00:01", "eth.dst": "02:00:00:00:00:02", "eth.type": "0x0800",
		"ip.version": 4, "ip.hdr_len": 20, "ip.len": length + 28, "ip.src": "192.0.2.254", "ip.dst": "192.0.2.253",
		"ip.proto": 17, "ip.frag_offset": 0, "ip.flags.mf": "False", "ip.checksum.status": 1,
		"udp.srcport": 40000, "udp.dstport": 4739, "udp.length": length + 8, "udp.checksum.status": 1,
	}
	return verifyPDML(data, packet, want, expected)
}

func expectedGeneralFlow(slot string) ([]field, error) {
	canonical := "ipfix-canonical-ipv4-v1"
	if strings.HasSuffix(slot, "ipv6-v1") {
		canonical = "ipfix-canonical-ipv6-v1"
	}
	want, err := expectedFlow(canonical)
	if err != nil {
		return nil, err
	}
	for i := range want {
		switch want[i].Name {
		case "cflow.od_id":
			want[i].Show = "42"
		case "cflow.template_ipfix_field_type":
			switch want[i].Show {
			case "156":
				want[i].Show = "152"
			case "157":
				want[i].Show = "153"
			}
		case "cflow.abstimestart":
			want[i].Show = "2026-09-01T00:00:00.123000000+0000"
		case "cflow.abstimeend":
			want[i].Show = "2026-09-01T00:00:01.123000000+0000"
		}
	}
	return want, nil
}

// Keep these constants and checks close to the oracle so a changed fixture
// cannot silently become a different decoder input.
func validateGeneralPayload(payload []byte) error {
	if len(payload) < 16 || binary.BigEndian.Uint16(payload) != 10 || int(binary.BigEndian.Uint16(payload[2:])) != len(payload) {
		return fmt.Errorf("invalid general IPFIX payload envelope")
	}
	return nil
}
