// Package oracle verifies the pinned independent decoder's immutable-golden
// and live OCB output against literal profile fields and original packet bytes.
package oracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

const outputLimit = 1 << 20

// VerifyPDML requires exactly one complete packet, every selected flow field in
// order with its independent value/width/offset, and the same original payload.
// PDML provides widths and offsets that a flattened fields CSV cannot express.
func VerifyPDML(data []byte, packet fixturepcap.Packet) error {
	if len(data) > outputLimit {
		return fmt.Errorf("PDML exceeds 1 MiB")
	}
	want, err := expectedFlow(packet.SlotID)
	if err != nil {
		return err
	}
	port := 2055
	if strings.HasPrefix(packet.SlotID, "ipfix-") {
		port = 4739
	}
	expected := map[string]any{
		"frame.number": 1, "frame.len": packet.Length + 42, "frame.cap_len": packet.Length + 42,
		"frame.protocols": "eth:ethertype:ip:udp:cflow", "frame.time_epoch": "1788220803.000000000",
		"eth.src": "02:00:00:00:00:01", "eth.dst": "02:00:00:00:00:02", "eth.type": "0x0800",
		"ip.version": 4, "ip.hdr_len": 20, "ip.len": packet.Length + 28, "ip.src": "192.0.2.254", "ip.dst": "192.0.2.253",
		"ip.proto": 17, "ip.frag_offset": 0, "ip.flags.mf": "False", "ip.checksum.status": 1,
		"udp.srcport": 40000, "udp.dstport": port, "udp.length": packet.Length + 8, "udp.checksum.status": 1,
	}
	return verifyPDML(data, packet, want, expected)
}

func verifyPDML(data []byte, packet fixturepcap.Packet, want []field, expected map[string]any) error {
	if len(data) > outputLimit {
		return fmt.Errorf("PDML exceeds 1 MiB")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var stack, protocols []string
	var flow []field
	outer := map[string][]field{}
	packets, roots := 0, 0
	proto := ""
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, t.Name.Local)
			if len(stack) > 64 || t.Name.Space != "" {
				return fmt.Errorf("unsupported PDML nesting/namespace")
			}
			attr := map[string]string{}
			for _, a := range t.Attr {
				if _, ok := attr[a.Name.Local]; ok {
					return fmt.Errorf("duplicate XML attribute")
				}
				attr[a.Name.Local] = a.Value
			}
			switch t.Name.Local {
			case "pdml":
				roots++
				if parent != "" || roots != 1 || attr["creator"] != "wireshark/4.6.8" {
					return fmt.Errorf("PDML identity/root mismatch")
				}
			case "packet":
				packets++
				if parent != "pdml" || packets != 1 {
					return fmt.Errorf("expected exactly one packet")
				}
			case "proto":
				if parent != "packet" {
					return fmt.Errorf("unexpected nested protocol")
				}
				proto = attr["name"]
				protocols = append(protocols, proto)
			case "field":
				if parent != "proto" && parent != "field" {
					return fmt.Errorf("field outside protocol")
				}
				var f field
				// Decode attributes only; keep streaming children to enforce depth bounds.
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "name":
						f.Name = a.Value
					case "show":
						f.Show = a.Value
					case "value":
						f.Value = a.Value
					case "size":
						if f.Size, err = strconv.Atoi(a.Value); err != nil {
							return err
						}
					case "pos":
						if f.Pos, err = strconv.Atoi(a.Value); err != nil {
							return err
						}
					}
				}
				if strings.HasPrefix(f.Name, "_ws.") {
					return fmt.Errorf("TShark expert/malformed output: %s", f.Name)
				}
				if strings.HasPrefix(f.Name, "cflow.") {
					if proto != "cflow" {
						return fmt.Errorf("flow field outside cflow protocol")
					}
					// These duplicate already-checked values or expose flag sub-bits. No
					// Options, missing-template, sequence or other expert field is ignored.
					if f.Name != "cflow.timestamp" && f.Name != "cflow.timedelta" && f.Name != "cflow.template_frame" && !strings.HasPrefix(f.Name, "cflow.tcpflags.") {
						f.Value = ""
						flow = append(flow, f)
					}
				} else if f.Name != "" {
					outer[f.Name] = append(outer[f.Name], f)
				}
			default:
				return fmt.Errorf("unexpected PDML element %q", t.Name.Local)
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
			if t.Name.Local == "proto" {
				proto = ""
			}
		case xml.Directive:
			return fmt.Errorf("XML directives are not accepted")
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return fmt.Errorf("unexpected PDML text")
			}
		}
	}
	if roots != 1 || packets != 1 || !slices.Equal(protocols, []string{"geninfo", "frame", "eth", "ip", "udp", "cflow"}) {
		return fmt.Errorf("missing/extra packet or protocol")
	}
	if len(flow) != len(want) {
		return fmt.Errorf("flow field count %d, want %d", len(flow), len(want))
	}
	for i := range want {
		if flow[i] != want[i] {
			return fmt.Errorf("flow field %d: got %+v, want %+v", i, flow[i], want[i])
		}
	}
	for name, value := range expected {
		fs := outer[name]
		if len(fs) != 1 || fs[0].Show != fmt.Sprint(value) {
			return fmt.Errorf("outer field %s: got %+v, want %v", name, fs, value)
		}
	}
	checksums := outer["udp.checksum"]
	if len(checksums) != 1 || checksums[0].Value == "0000" || len(checksums[0].Value) != 4 {
		return fmt.Errorf("missing/nonzero UDP checksum requirement failed")
	}
	payloads := outer["udp.payload"]
	if len(payloads) != 1 || payloads[0].Size != packet.Length || payloads[0].Pos != 42 {
		return fmt.Errorf("UDP payload location/length mismatch")
	}
	payload, err := hex.DecodeString(payloads[0].Value)
	if err != nil || len(payload) != packet.Length || fmt.Sprintf("%x", sha256.Sum256(payload)) != packet.SHA256 || !bytes.Equal(payload, packet.Payload) {
		return fmt.Errorf("TShark UDP payload identity mismatch")
	}
	return nil
}
