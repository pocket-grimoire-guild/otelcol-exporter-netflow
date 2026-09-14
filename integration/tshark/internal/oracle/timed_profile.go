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
	timedIPv4Length = 164
	timedIPv6Length = 188
)

// RunTimed independently decodes the immutable v9 timed payloads with the
// pinned TShark image. It is opt-in because the normal test suite must remain
// usable on hosts without rootless Podman.
func RunTimed(ctx context.Context, cfg Config) (result error) {
	id, err := loadIdentity(cfg.Repo, cfg.Image)
	if err != nil {
		return err
	}
	out, stderr, err := podman(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil || len(stderr) != 0 || strings.TrimSpace(string(out)) != "true" || os.Getuid() == 0 {
		return fmt.Errorf("rootless Podman and non-root caller required: %v: %s", err, stderr)
	}
	packets, err := readTimedPackets(cfg.Repo)
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
	stage, err := os.MkdirTemp(parent, "tshark-timed-")
	if err != nil {
		return err
	}
	if cfg.Artifacts == "" {
		defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()
	}
	if err = os.Mkdir(filepath.Join(stage, "fixtures"), 0700); err != nil {
		return err
	}
	for _, packet := range packets {
		if err = os.WriteFile(filepath.Join(stage, "fixtures", packet.PCAP), packet.PCAPBytes, 0400); err != nil {
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
	for _, packet := range packets {
		out, err = id.container(ctx, stage, packet.SlotID, id.executable, "-n", "-r", "/fixtures/"+packet.PCAP,
			"-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-T", "pdml")
		if err != nil {
			return err
		}
		if err = VerifyTimedPDML(out, packet); err != nil {
			return fmt.Errorf("%s: %w", packet.SlotID, err)
		}
	}
	return os.WriteFile(filepath.Join(stage, "PASS.txt"), []byte("fresh NetFlow v9 timed 22/21 payloads: PDML field values/order/widths/offsets, lengths, hashes, checksums\n"+id.ref+"\nimage_id="+id.id+"\n"), 0600)
}

func readTimedPackets(repo string) ([]fixturepcap.Packet, error) {
	root := filepath.Join(repo, "integration/testdata/golden/v9")
	if err := trustedDirectory(root); err != nil {
		return nil, err
	}
	type fixture struct {
		name, slot string
		length     int
		hash       string
	}
	fixtures := []fixture{
		{"timed-ipv4-v1.bin", "v9-timed-ipv4-v1", timedIPv4Length, "204cd5586cc098c407ebfbae6dab6587710b80dc82d8eb27c0b9b6ce156dd20b"},
		{"timed-ipv6-v1.bin", "v9-timed-ipv6-v1", timedIPv6Length, "66f7a79d1304e3921824dbb90bcfe0577f0fdd75024591b54bdd67b9f4e0d4e8"},
	}
	packets := make([]fixturepcap.Packet, 0, len(fixtures))
	for _, fixture := range fixtures {
		payload, err := readLiveFile(root, fixture.name)
		if err != nil {
			return nil, err
		}
		if len(payload) != fixture.length {
			return nil, fmt.Errorf("%s length %d, want %d", fixture.name, len(payload), fixture.length)
		}
		if err := validateTimedPayload(payload); err != nil {
			return nil, fmt.Errorf("%s: %w", fixture.name, err)
		}
		gotHash := fmt.Sprintf("%x", sha256.Sum256(payload))
		if gotHash != fixture.hash {
			return nil, fmt.Errorf("%s SHA-256 %s, want %s", fixture.name, gotHash, fixture.hash)
		}
		pcap, err := fixturepcap.Wrap(payload, 4739)
		if err != nil {
			return nil, err
		}
		packets = append(packets, fixturepcap.Packet{
			Capture:   fixturepcap.Capture{SlotID: fixture.slot, PCAP: fixture.slot + ".pcap", Length: len(payload), SHA256: gotHash},
			PCAPBytes: pcap,
			Payload:   payload,
		})
	}
	return packets, nil
}

// VerifyTimedPDML checks both timed families against literal expectations,
// including the two additional template fields and the measured record times.
func VerifyTimedPDML(data []byte, packet fixturepcap.Packet) error {
	want, err := expectedTimedFlow(packet.SlotID)
	if err != nil {
		return err
	}
	length := timedIPv4Length
	if strings.HasSuffix(packet.SlotID, "ipv6-v1") {
		length = timedIPv6Length
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

func expectedTimedFlow(slot string) ([]field, error) {
	canonical := "v9-canonical-ipv4-v1"
	if strings.HasSuffix(slot, "ipv6-v1") {
		canonical = "v9-canonical-ipv6-v1"
	}
	want, err := expectedFlow(canonical)
	if err != nil {
		return nil, err
	}
	dataIndex, flowsets := -1, 0
	for i, item := range want {
		if item.Name == "cflow.flowset_id" {
			flowsets++
			if flowsets == 2 {
				dataIndex = i
				break
			}
		}
	}
	if dataIndex < 0 {
		return nil, fmt.Errorf("timed oracle data flowset missing")
	}
	dataPosition := want[dataIndex].Pos
	for i := dataIndex; i < len(want); i++ {
		want[i].Pos += 8
	}
	lengths := 0
	for i := range want {
		switch want[i].Name {
		case "cflow.template_field_count":
			want[i].Show = "20"
		case "cflow.flowset_length":
			lengths++
			if lengths == 1 {
				want[i].Show = "88"
			} else if lengths == 2 {
				if strings.HasSuffix(slot, "ipv6-v1") {
					want[i].Show = "80"
				} else {
					want[i].Show = "56"
				}
			}
		case "cflow.sysuptime":
			want[i].Show = "5.000000000"
		case "cflow.unix_secs":
			want[i].Show = "1788220805"
		}
	}
	timedTemplate := []field{
		{Name: "cflow.template_field_type", Show: "22", Size: 2, Pos: dataPosition},
		{Name: "cflow.template_field_length", Show: "4", Size: 2, Pos: dataPosition + 2},
		{Name: "cflow.template_field_type", Show: "21", Size: 2, Pos: dataPosition + 4},
		{Name: "cflow.template_field_length", Show: "4", Size: 2, Pos: dataPosition + 6},
	}
	withTemplate := make([]field, 0, len(want)+len(timedTemplate))
	withTemplate = append(withTemplate, want[:dataIndex]...)
	withTemplate = append(withTemplate, timedTemplate...)
	withTemplate = append(withTemplate, want[dataIndex:]...)
	want = withTemplate
	paddingIndex := -1
	for i := dataIndex + len(timedTemplate); i < len(want); i++ {
		if want[i].Name == "cflow.padding" {
			paddingIndex = i
			break
		}
	}
	if paddingIndex < 0 {
		paddingIndex = len(want)
	}
	timePosition := 0
	if paddingIndex < len(want) {
		timePosition = want[paddingIndex].Pos
		want[paddingIndex].Pos += 8
	} else {
		last := want[len(want)-1]
		timePosition = last.Pos + last.Size
	}
	timedRecord := []field{
		{Name: "cflow.timestart", Show: "3.000000000", Size: 4, Pos: timePosition},
		{Name: "cflow.timeend", Show: "4.000000000", Size: 4, Pos: timePosition + 4},
	}
	withTimes := make([]field, 0, len(want)+len(timedRecord))
	withTimes = append(withTimes, want[:paddingIndex]...)
	withTimes = append(withTimes, timedRecord...)
	withTimes = append(withTimes, want[paddingIndex:]...)
	want = withTimes
	return want, nil
}

func validateTimedPayload(payload []byte) error {
	if (len(payload) != timedIPv4Length && len(payload) != timedIPv6Length) || binary.BigEndian.Uint16(payload[0:2]) != 9 || binary.BigEndian.Uint16(payload[2:4]) != 2 ||
		binary.BigEndian.Uint32(payload[4:8]) != 5000 || binary.BigEndian.Uint32(payload[8:12]) != 1788220805 ||
		binary.BigEndian.Uint32(payload[12:16]) != 0 {
		return fmt.Errorf("invalid timed v9 header")
	}
	if binary.BigEndian.Uint16(payload[20:22]) != 0 || binary.BigEndian.Uint16(payload[22:24]) != 88 ||
		binary.BigEndian.Uint16(payload[26:28]) != 20 {
		return fmt.Errorf("invalid timed v9 template envelope")
	}
	ids := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 22, 21}
	if len(payload) == timedIPv6Length {
		ids[6], ids[7], ids[10], ids[11] = 27, 29, 28, 30
	}
	for i, id := range ids {
		offset := 28 + i*4
		if binary.BigEndian.Uint16(payload[offset:offset+2]) != id || binary.BigEndian.Uint16(payload[offset+2:offset+4]) == 0 {
			return fmt.Errorf("invalid timed v9 template field %d", i)
		}
	}
	if binary.BigEndian.Uint16(payload[108:110]) < 256 || binary.BigEndian.Uint16(payload[110:112]) == 0 {
		return fmt.Errorf("invalid timed v9 data envelope")
	}
	return nil
}
