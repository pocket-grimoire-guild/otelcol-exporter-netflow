package oracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These regressions consume actual retained output after the full live command;
// stored PDML by itself is never execution evidence.
func TestRecordedLivePDML(t *testing.T) {
	root, report := os.Getenv("NETFLOW_TSHARK_LIVE_DIR"), os.Getenv("NETFLOW_TSHARK_LIVE_PDML")
	if root == "" || report == "" {
		t.Skip("set NETFLOW_TSHARK_LIVE_DIR and NETFLOW_TSHARK_LIVE_PDML after the real live smoke")
	}
	_, packets, err := readLive(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyLivePDML(data, packets); err != nil {
		t.Fatal(err)
	}
	// Mutate every distinct selected field's value, width, byte offset and
	// presence in real PDML, including template metadata and both address families.
	names := map[string]bool{}
	for _, p := range packets {
		fields, err := expectedLiveFlow(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fields {
			names[f.Name] = true
		}
	}
	for name := range names {
		start := bytes.Index(data, []byte(`<field name="`+name+`"`))
		if start < 0 {
			t.Fatalf("missing mutation field %s", name)
		}
		end := start + bytes.IndexByte(data[start:], '>') + 1
		tag := data[start:end]
		for _, attr := range []string{"show", "size", "pos", "name"} {
			t.Run(name+"/"+attr, func(t *testing.T) {
				prefix := []byte(attr + `="`)
				i := bytes.Index(tag, prefix)
				if i < 0 {
					t.Fatal("missing mutation attribute")
				}
				i += len(prefix)
				j := i + bytes.IndexByte(tag[i:], '"')
				bad := append(bytes.Clone(data[:start+i]), []byte("999999")...)
				bad = append(bad, data[start+j:]...)
				if verifyLivePDML(bad, packets) == nil {
					t.Fatal("accepted corrupted live field")
				}
			})
		}
	}
	for name, replacement := range map[string][2]string{
		"payload":      {`name="udp.payload"`, `name="missing.payload"`},
		"checksum":     {`name="udp.checksum.status"`, `name="missing.checksum"`},
		"ip-checksum":  {`name="ip.checksum.status"`, `name="missing.checksum"`},
		"length":       {`name="udp.length"`, `name="missing.length"`},
		"extra-packet": {`</pdml>`, `<packet/></pdml>`},
		"expert":       {`</proto>`, `<field name="_ws.expert"/></proto>`},
		"version":      {`creator="wireshark/4.6.8"`, `creator="wireshark/other"`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Replace(data, []byte(replacement[0]), []byte(replacement[1]), 1)
			if bytes.Equal(bad, data) || verifyLivePDML(bad, packets) == nil {
				t.Fatal("accepted mutated live evidence")
			}
		})
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := d.Token()
		if err != nil {
			break
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Local == "packet" {
			if verifyLivePDML(data[:d.InputOffset()], packets) == nil {
				t.Fatal("accepted truncated live report")
			}
		}
	}
}

func TestLiveInputRejections(t *testing.T) {
	dir := trustedTestDir(t)
	for _, data := range [][]byte{nil, []byte("bad"), bytes.Repeat([]byte{0}, outputLimit+1)} {
		if err := os.WriteFile(filepath.Join(dir, "live.pcap"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readLive(dir); err == nil {
			t.Fatal("accepted absent/invalid capture identity")
		}
	}
	if _, err := readLiveFile(dir, "../escape"); err == nil {
		t.Fatal("accepted path escape")
	}
	if err := os.Symlink("live.pcap", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readLiveFile(dir, "link"); err == nil {
		t.Fatal("accepted symlink")
	}
	for _, data := range []string{"", `<pdml creator="wireshark/4.6.8"/>`, strings.Repeat("x", outputLimit+1), `<!DOCTYPE pdml><pdml/>`} {
		if verifyLivePDML([]byte(data), make([]livePacket, 21)) == nil {
			t.Fatal("accepted malformed live PDML")
		}
	}
}

func TestRecordedLiveBinding(t *testing.T) {
	root := os.Getenv("NETFLOW_TSHARK_LIVE_DIR")
	if root == "" {
		t.Skip("set NETFLOW_TSHARK_LIVE_DIR after the real live smoke")
	}
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"truncated", "extra-frame", "payload", "index", "drop", "count", "socket", "hash"} {
		t.Run(mutation, func(t *testing.T) {
			dir := trustedTestDir(t)
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				data, err := readLiveFile(root, file.Name())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, file.Name()), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			pcap, packets, err := readLive(dir)
			if err != nil {
				t.Fatal(err)
			}
			var network map[string]any
			data, err := readLiveFile(dir, "network.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &network); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "truncated":
				pcap = pcap[:len(pcap)-1]
			case "extra-frame":
				pcap = append(pcap, pcap[24:40+len(packets[0].frame)]...)
			case "payload":
				pcap[82] ^= 1
			case "socket":
				pcap[74] ^= 1
			case "index":
				network["application_indexes"].([]any)[0] = network["application_indexes"].([]any)[1]
			case "drop":
				network["packet_socket_drops"] = 1
			case "count":
				network["packet_socket_packets"] = 20
			case "hash":
				network["pcap_sha256"] = "invalid"
			}
			if mutation != "hash" {
				network["pcap_sha256"] = fmt.Sprintf("%x", sha256.Sum256(pcap))
			}
			data, err = json.Marshal(network)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "network.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "live.pcap"), pcap, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readLive(dir); err == nil {
				t.Fatal("accepted substituted live capture")
			}
		})
	}
}

func TestRecordedLiveV5Clock(t *testing.T) {
	root := os.Getenv("NETFLOW_TSHARK_LIVE_DIR")
	if root == "" {
		t.Skip("set NETFLOW_TSHARK_LIVE_DIR after the real live smoke")
	}
	_, packets, err := readLive(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packets {
		if p.index != 12 {
			continue
		}
		if _, err := expectedLiveFlow(p); err != nil {
			t.Fatal(err)
		}
		for _, change := range []string{"uptime", "nanos", "submillisecond", "future-origin", "expired-origin", "short-header"} {
			t.Run(change, func(t *testing.T) {
				bad := p
				bad.frame = bytes.Clone(p.frame)
				switch change {
				case "uptime":
					bad.frame[49] ^= 1
				case "nanos":
					binary.BigEndian.PutUint32(bad.frame[54:], 1e9)
				case "submillisecond":
					bad.frame[57] |= 1
				case "future-origin":
					bad.origin += int64(1e12)
				case "expired-origin":
					bad.origin = 1
				case "short-header":
					bad.frame = bad.frame[:43]
				}
				if _, err := expectedLiveFlow(bad); err == nil {
					t.Fatal("accepted inconsistent live v5 clock/header")
				}
			})
		}
		return
	}
	t.Fatal("missing live v5 packet")
}
