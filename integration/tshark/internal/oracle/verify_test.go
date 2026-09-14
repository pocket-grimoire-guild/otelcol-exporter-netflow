package oracle

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

func oraclePackets(t *testing.T) []fixturepcap.Packet {
	t.Helper()
	manifest, goldens := "../../../testdata/pcap/payload-manifest.yaml", "../../../testdata/golden/manifest.json"
	root := t.TempDir()
	if err := fixturepcap.Generate(manifest, goldens, root); err != nil {
		t.Fatal(err)
	}
	packets, err := fixturepcap.ReadVerified(manifest, goldens, root)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

// Run after the real pinned runner, using its retained .stdout PDML files.
// These are parser regressions, not independent execution evidence by themselves.
func TestRecordedPDML(t *testing.T) {
	dir := os.Getenv("NETFLOW_TSHARK_PDML_DIR")
	if dir == "" {
		t.Skip("set NETFLOW_TSHARK_PDML_DIR to a retained pinned-oracle output directory")
	}
	for _, p := range oraclePackets(t) {
		t.Run(p.SlotID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, p.SlotID+".stdout"))
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyPDML(data, p); err != nil {
				t.Fatal(err)
			}
			// Mutate every cflow field that contributes to acceptance in the actual
			// independent decoder output: omission, value, width and position.
			want, err := expectedFlow(p.SlotID)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range want {
				start := bytes.Index(data, []byte(`<field name="`+f.Name+`"`))
				// Repeated fields must select the matching byte position as well.
				for start >= 0 {
					end := start + bytes.IndexByte(data[start:], '>') + 1
					tag := data[start:end]
					if bytes.Contains(tag, fmt.Appendf(nil, `pos="%d"`, f.Pos)) {
						for _, mutation := range []string{"show", "size", "pos", "omit"} {
							t.Run(fmt.Sprintf("%s/%d/%s", f.Name, f.Pos, mutation), func(t *testing.T) {
								var replacement []byte
								if mutation == "omit" {
									replacement = bytes.Replace(tag, []byte(`name="`+f.Name+`"`), []byte(`name=""`), 1)
								} else {
									attr := []byte(mutation + `="`)
									i := bytes.Index(tag, attr) + len(attr)
									j := i + bytes.IndexByte(tag[i:], '"')
									replacement = append(bytes.Clone(tag[:i]), []byte("999999")...)
									replacement = append(replacement, tag[j:]...)
								}
								bad := append(bytes.Clone(data[:start]), replacement...)
								bad = append(bad, data[end:]...)
								if err := VerifyPDML(bad, p); err == nil {
									t.Fatal("accepted corrupted decoder field")
								}
							})
						}
						break
					}
					next := bytes.Index(data[end:], []byte(`<field name="`+f.Name+`"`))
					if next < 0 {
						start = -1
					} else {
						start = end + next
					}
				}
				if start < 0 {
					t.Fatalf("missing test mutation target %+v", f)
				}
			}
			for _, tc := range []struct{ name, old, new string }{
				{"payload", "value=\"" + fmt.Sprintf("%x", p.Payload), "value=\"ff" + fmt.Sprintf("%x", p.Payload[1:])},
				{"checksum-status", `name="udp.checksum.status"`, `name="missing.checksum.status"`},
				{"outer-length", `name="ip.len"`, `name="missing.ip.len"`},
				{"options", `</packet>`, `<proto name="cflow.options"/></packet>`},
				{"expert", `</proto>`, `<field name="_ws.expert"/></proto>`},
				{"extra-packet", `</pdml>`, `<packet/></pdml>`},
				{"decoder-version", `creator="wireshark/4.6.8"`, `creator="wireshark/other"`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					bad := bytes.Replace(data, []byte(tc.old), []byte(tc.new), 1)
					if bytes.Equal(bad, data) {
						t.Fatal("mutation target absent")
					}
					if err := VerifyPDML(bad, p); err == nil {
						t.Fatal("accepted corrupt evidence")
					}
				})
			}
			// Truncation at every XML token boundary catches omitted trailing records,
			// fields, protocol ends and root closures without a quadratic byte loop.
			decoder := xml.NewDecoder(bytes.NewReader(data))
			for {
				_, err := decoder.Token()
				if err != nil {
					break
				}
				n := int(decoder.InputOffset())
				if bytes.Contains(data[n:], []byte("</pdml>")) && VerifyPDML(data[:n], p) == nil {
					t.Fatalf("accepted truncation at %d", n)
				}
			}
		})
	}
}

func TestPDMLRejectsMalformed(t *testing.T) {
	p := oraclePackets(t)[0]
	for _, data := range []string{"", `<pdml/>`, `<pdml creator="wireshark/4.6.8"><packet/></pdml>`,
		`<!DOCTYPE pdml><pdml/>`, strings.Repeat("<field>", 65), strings.Repeat("x", outputLimit+1),
		`<pdml creator="wireshark/4.6.8"><packet><proto name="cflow"><field name="cflow.version" size="bad"/></proto></packet></pdml>`,
	} {
		if VerifyPDML([]byte(data), p) == nil {
			t.Fatal("accepted malformed/missing packet evidence")
		}
	}
	p.SlotID = "unknown"
	if VerifyPDML(nil, p) == nil {
		t.Fatal("accepted unknown slot")
	}
}
