package oracle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

type liveOutput struct {
	File, SHA256, Source, Endpoint string
	Length                         int
}

type livePacket struct {
	frame       []byte
	seconds, ns uint32
	index       int
	output      liveOutput
	origin      int64
}

// Read each fixture once, without following a symlink or blocking on a FIFO.
func readLiveFile(root, name string) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid live fixture name")
	}
	fd, err := syscall.Open(filepath.Join(root, name), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > outputLimit {
		return nil, fmt.Errorf("live fixture must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, outputLimit+1))
	if len(data) > outputLimit {
		return nil, fmt.Errorf("live fixture exceeds 1 MiB")
	}
	return data, err
}

func readLive(root string) ([]byte, []livePacket, error) {
	if err := trustedDirectory(root); err != nil {
		return nil, nil, err
	}
	var network struct {
		Indexes []int  `json:"application_indexes"`
		Hash    string `json:"pcap_sha256"`
		Drops   int    `json:"packet_socket_drops"`
		Packets int    `json:"packet_socket_packets"`
	}
	var capture struct {
		Outputs        []liveOutput
		OriginUnixNano int64
	}
	for name, target := range map[string]any{"network.json": &network, "capture.json": &capture} {
		data, err := readLiveFile(root, name)
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(data, target); err != nil {
			return nil, nil, err
		}
	}
	pcap, err := readLiveFile(root, "live.pcap")
	if err != nil {
		return nil, nil, err
	}
	if len(pcap) < 24 || fmt.Sprintf("%x", sha256.Sum256(pcap)) != network.Hash || network.Drops != 0 || network.Packets != 21 || len(network.Indexes) != 21 || len(capture.Outputs) != 21 {
		return nil, nil, fmt.Errorf("live capture identity/count/drop mismatch")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	if le.Uint32(pcap) != 0xa1b23c4d || le.Uint16(pcap[4:]) != 2 || le.Uint16(pcap[6:]) != 4 || le.Uint64(pcap[8:]) != 0 || le.Uint32(pcap[16:]) != 65549 || le.Uint32(pcap[20:]) != 1 {
		return nil, nil, fmt.Errorf("expected nanosecond Ethernet PCAP")
	}
	remaining := pcap[24:]
	var packets []livePacket
	seen := map[int]bool{}
	for _, index := range network.Indexes {
		if index < 0 || index >= 21 || seen[index] || len(remaining) < 16 {
			return nil, nil, fmt.Errorf("invalid live packet index/framing")
		}
		seen[index] = true
		n := int(le.Uint32(remaining[8:]))
		seconds, ns := le.Uint32(remaining), le.Uint32(remaining[4:])
		if n < 43 || n > 65549 || len(remaining) < 16+n || int(le.Uint32(remaining[12:])) != n || ns >= 1e9 {
			return nil, nil, fmt.Errorf("truncated/invalid live frame")
		}
		frame := remaining[16 : 16+n]
		remaining = remaining[16+n:]
		out := capture.Outputs[index]
		protocol := "v9"
		if index >= 4 && index <= 11 || index >= 16 {
			protocol = "ipfix"
		}
		label := protocol
		if index >= 8 && index <= 11 || index == 20 {
			label = "rejected"
		} else if index == 12 {
			label = "v5"
		}
		if out.File != fmt.Sprintf("%02d-%s.bin", index, label) || out.Length != n-42 || out.SHA256 != fmt.Sprintf("%x", sha256.Sum256(frame[42:])) {
			return nil, nil, fmt.Errorf("live application inventory mismatch")
		}
		payload, err := readLiveFile(root, out.File)
		if err != nil || !bytes.Equal(payload, frame[42:]) {
			return nil, nil, fmt.Errorf("live payload bytes mismatch: %v", err)
		}
		if frame[12] != 8 || frame[13] != 0 || frame[14] != 0x45 || frame[23] != 17 || int(be.Uint16(frame[16:])) != n-14 || be.Uint16(frame[20:])&0x3fff != 0 || int(be.Uint16(frame[38:])) != n-34 || be.Uint16(frame[40:]) == 0 {
			return nil, nil, fmt.Errorf("invalid live IP/UDP framing")
		}
		source := fmt.Sprintf("%s:%d", net.IP(frame[26:30]), be.Uint16(frame[34:]))
		dest := fmt.Sprintf("%s:%d", net.IP(frame[30:34]), be.Uint16(frame[36:]))
		if source != out.Source || dest != out.Endpoint || !bytes.Equal(frame[26:34], []byte{198, 18, 0, 2, 198, 18, 0, 1}) {
			return nil, nil, fmt.Errorf("live socket identity mismatch")
		}
		packets = append(packets, livePacket{frame, seconds, ns, index, out, capture.OriginUnixNano})
	}
	if len(remaining) != 0 {
		return nil, nil, fmt.Errorf("extra live frames")
	}
	return pcap, packets, nil
}

// Reuse the immutable oracle's literal profile fields. Only the documented
// receiver projection, split template/data packets and live headers differ.
func expectedLiveFlow(p livePacket) ([]field, error) {
	i := p.index
	protocol, suffix := "v9", "canonical-ipv4-v1"
	if i >= 4 && i <= 11 || i >= 16 {
		protocol = "ipfix"
	}
	if i == 12 {
		protocol = "v5"
	}
	if i < 12 && i%2 == 1 || i == 14 || i == 17 {
		suffix = "canonical-ipv6-v1"
	} else if i == 15 || i == 18 {
		suffix = "sampling-ie34-two-distinct-rates-v1"
	}
	want, err := expectedFlow(protocol + "-" + suffix)
	if err != nil {
		return nil, err
	}
	minimum, version := 20, uint16(9)
	if protocol == "v5" {
		minimum, version = 24, 5
	}
	if protocol == "ipfix" {
		minimum, version = 16, 10
	}
	if len(p.frame) < 42+minimum || binary.BigEndian.Uint16(p.frame[42:]) != version {
		return nil, fmt.Errorf("invalid live flow header")
	}
	payload := p.frame[42:]
	if protocol == "v5" {
		nanos := binary.BigEndian.Uint32(payload[12:])
		wall := int64(binary.BigEndian.Uint32(payload[8:]))*1e9 + int64(nanos)
		if nanos >= 1e9 || nanos%1e6 != 0 || p.origin <= 0 || wall < p.origin ||
			(wall-p.origin)/1e6 > int64(^uint32(0)) || (wall-p.origin)%1e6 != 0 ||
			uint32((wall-p.origin)/1e6) != binary.BigEndian.Uint32(payload[4:]) {
			return nil, fmt.Errorf("live v5 timestamp/uptime differs from configured origin")
		}
	}
	header, template := 20, 80
	seq, count, domain := 0, 1, 42
	if protocol == "ipfix" {
		header, template = 16, 88
	}
	if i < 4 {
		seq = i
	} else if i >= 8 && i <= 11 || i == 20 {
		domain = 43
	} else if i >= 13 && i <= 15 {
		seq = i - 9
	} else if i >= 16 && i <= 18 {
		seq = i - 16
	} else if i == 19 {
		seq = 4
	}
	if i == 15 || i == 18 {
		count = 2
	}
	var result []field
	for _, f := range want {
		if protocol != "v5" {
			if i < 12 && f.Pos >= 42+header+template || i >= 12 && f.Pos >= 42+header && f.Pos < 42+header+template {
				continue
			}
			if i >= 12 && f.Pos >= 42+header+template {
				f.Pos -= template
			}
		}
		switch f.Name {
		case "cflow.sequence":
			f.Show = strconv.Itoa(seq)
		case "cflow.count":
			f.Show = strconv.Itoa(count)
		case "cflow.len":
			f.Show = strconv.Itoa(len(payload))
		case "cflow.source_id", "cflow.od_id":
			f.Show = strconv.Itoa(domain)
		case "cflow.sysuptime":
			ms := binary.BigEndian.Uint32(payload[4:])
			f.Show = fmt.Sprintf("%d.%09d", ms/1000, ms%1000*1000000)
		case "cflow.unix_secs", "cflow.exporttime":
			offset := 8
			if protocol == "ipfix" {
				offset = 4
			}
			seconds := binary.BigEndian.Uint32(payload[offset:])
			if seconds > p.seconds || p.seconds-seconds > 2 {
				return nil, fmt.Errorf("export time outside live capture interval")
			}
			f.Show = strconv.FormatUint(uint64(seconds), 10)
		case "cflow.unix_nsecs":
			f.Show = strconv.FormatUint(uint64(binary.BigEndian.Uint32(payload[12:])), 10)
		case "cflow.engine_id":
			f.Show = "1"
		case "cflow.sampling_interval":
			f.Show = "0"
		case "cflow.abstimeend":
			f.Show = "2026-09-01T00:00:01.000999998+0000"
		case "cflow.protocol":
			if i >= 19 {
				f.Show = "17"
			}
		}
		result = append(result, f)
	}
	return result, nil
}

func verifyLivePDML(data []byte, packets []livePacket) error {
	if len(data) > outputLimit || len(packets) != 21 {
		return fmt.Errorf("live PDML/count outside bounds")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	root, closed, count := false, false, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Space != "" {
				return fmt.Errorf("unexpected live PDML namespace")
			}
			if !root && t.Name.Local == "pdml" {
				creator := ""
				for _, a := range t.Attr {
					if a.Name.Local == "creator" {
						if creator != "" {
							return fmt.Errorf("duplicate creator")
						}
						creator = a.Value
					}
				}
				if creator != "wireshark/4.6.8" {
					return fmt.Errorf("live decoder identity mismatch")
				}
				root = true
				continue
			}
			if !root || closed || t.Name.Local != "packet" || len(t.Attr) != 0 || count >= len(packets) {
				return fmt.Errorf("unexpected/extra live PDML packet")
			}
			var packet struct {
				Inner string `xml:",innerxml"`
			}
			if err := d.DecodeElement(&packet, &t); err != nil {
				return err
			}
			p := packets[count]
			want, err := expectedLiveFlow(p)
			if err != nil {
				return err
			}
			frame := p.frame
			n := len(frame) - 42
			expected := map[string]any{
				"frame.number": count + 1, "frame.len": len(frame), "frame.cap_len": len(frame),
				"frame.protocols": "eth:ethertype:ip:udp:cflow", "frame.time_epoch": fmt.Sprintf("%d.%09d", p.seconds, p.ns),
				"eth.src": net.HardwareAddr(frame[6:12]).String(), "eth.dst": net.HardwareAddr(frame[:6]).String(), "eth.type": "0x0800",
				"ip.version": 4, "ip.hdr_len": 20, "ip.len": n + 28, "ip.src": "198.18.0.2", "ip.dst": "198.18.0.1",
				"ip.proto": 17, "ip.frag_offset": 0, "ip.flags.mf": "False", "ip.checksum.status": 1,
				"udp.srcport": binary.BigEndian.Uint16(frame[34:]), "udp.dstport": binary.BigEndian.Uint16(frame[36:]), "udp.length": n + 8, "udp.checksum.status": 1,
			}
			fixture := fixturepcap.Packet{Capture: fixturepcap.Capture{Length: n, SHA256: p.output.SHA256}, Payload: frame[42:]}
			single := []byte(`<pdml creator="wireshark/4.6.8"><packet>` + packet.Inner + `</packet></pdml>`)
			if err := verifyPDML(single, fixture, want, expected); err != nil {
				return fmt.Errorf("live packet %d (application %d): %w", count+1, p.index, err)
			}
			count++
		case xml.EndElement:
			if !root || closed || t.Name.Local != "pdml" {
				return fmt.Errorf("unexpected live PDML closure")
			}
			closed = true
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return fmt.Errorf("unexpected live PDML text")
			}
		case xml.Directive:
			return fmt.Errorf("XML directives are not accepted")
		}
	}
	if !root || !closed || count != 21 {
		return fmt.Errorf("incomplete live PDML")
	}
	return nil
}

// RunLive independently decodes the unchanged frames from a successful live
// smoke. The caller must run that smoke first; a stored capture alone does not
// establish a fresh Collector execution.
func RunLive(ctx context.Context, cfg Config, root string) (result error) {
	id, err := loadIdentity(cfg.Repo, cfg.Image)
	if err != nil {
		return err
	}
	out, stderr, err := podman(ctx, "info", "--format", "{{.Host.Security.Rootless}}")
	if err != nil || len(stderr) != 0 || strings.TrimSpace(string(out)) != "true" || os.Getuid() == 0 {
		return fmt.Errorf("rootless Podman and non-root caller required")
	}
	pcap, packets, err := readLive(root)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(root, "tshark-")
	if err != nil {
		return err
	}
	if err = os.Mkdir(filepath.Join(stage, "fixtures"), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(stage, "fixtures", "live.pcap"), pcap, 0400); err != nil {
		return err
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
	args := []string{"-n", "-r", "/fixtures/live.pcap", "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-T", "pdml"}
	ports := map[uint16]bool{}
	for _, p := range packets {
		port := binary.BigEndian.Uint16(p.frame[36:])
		if !ports[port] {
			args = append(args, "-d", fmt.Sprintf("udp.port==%d,cflow", port))
			ports[port] = true
		}
	}
	out, err = id.container(ctx, stage, "live", id.executable, args...)
	if err != nil {
		return err
	}
	if err = verifyLivePDML(out, packets); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stage, "PASS.txt"), []byte("live OCB: 21 original veth frames; payload identity, literal projected fields, templates, sequence, outer lengths and nonzero valid checksums\n"+id.ref+"\n"), 0600)
}
