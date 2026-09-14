package independent_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Literal golden bytes are authored independently of the Go writers. Compare
// all template/data bytes, including padding, while checking live headers and
// sequence separately. Custom fields extend that baseline with literal IEs.
func assertPacket(t *testing.T, protocol string, tc fixtureCase, packet []byte, phase string, sequence uint32, shape int, custom []byte) {
	t.Helper()
	header, dataOffset, version, seqOffset := 20, 100, uint16(9), 12
	switch protocol {
	case "v5":
		header, dataOffset, version, seqOffset = 24, 24, 5, 16
	case "ipfix":
		header, dataOffset, version, seqOffset = 16, 104, 10, 8
	}
	if len(packet) < header || binary.BigEndian.Uint16(packet) != version || binary.BigEndian.Uint32(packet[seqOffset:]) != sequence {
		t.Fatalf("unexpected %s %s header/sequence: %x", protocol, phase, packet)
	}
	if protocol == "ipfix" && int(binary.BigEndian.Uint16(packet[2:])) != len(packet) {
		t.Fatal("IPFIX message length")
	}
	if protocol != "v5" && binary.BigEndian.Uint32(packet[header-4:]) != 42 {
		t.Fatal("source/observation domain")
	}
	if protocol == "v5" && (!bytes.Equal(packet[20:24], []byte{0, 0, 3, 232}) || binary.BigEndian.Uint16(packet[2:]) != 1) {
		t.Fatal("v5 engine/sampling/count")
	}
	if protocol == "v9" {
		count := 1
		if phase == "data" {
			count = tc.ExpectedRecords
		}
		if int(binary.BigEndian.Uint16(packet[2:])) != count {
			t.Fatal("v9 count")
		}
	}
	name := tc.Name + "-v1.bin"
	if phase != "data" {
		name = []string{"canonical-ipv4-v1.bin", "canonical-ipv6-v1.bin"}[shape]
	}
	golden := readFile(t, filepath.Join("..", "testdata", "golden", protocol, name))
	var want []byte
	if phase == "data" {
		want = append([]byte(nil), golden[dataOffset:]...)
		if custom != nil {
			// IPv4 core record is 72 bytes, after the 4-byte Set header.
			want = append(want[:76], 0, 127, 128, 255)
			if len(custom) < 255 {
				want = append(want, byte(len(custom)))
			} else {
				want = append(want, 255, 0, 255)
			}
			want = append(want, custom...)
			for len(want)%4 != 0 {
				want = append(want, 0)
			}
			binary.BigEndian.PutUint16(want[2:], uint16(len(want)))
		}
	} else {
		want = append([]byte(nil), golden[header:dataOffset]...)
		if custom != nil {
			// PEN 32473, IE 400/fixed four octets, IE 401/variable octets.
			want = append(want, 0x81, 0x90, 0, 4, 0, 0, 0x7e, 0xd9, 0x81, 0x91, 0xff, 0xff, 0, 0, 0x7e, 0xd9)
			binary.BigEndian.PutUint16(want[2:], uint16(len(want)))
			binary.BigEndian.PutUint16(want[6:], 22)
		}
	}
	if !bytes.Equal(packet[header:], want) {
		t.Fatalf("%s %s template/data bytes:\n got %x\nwant %x", protocol, phase, packet[header:], want)
	}
}

// This is pmacct's explicit projection, not the OTel receiver projection.
// Source: v1.7.9 pkt_handlers.c and plugin_cmn_json.c (see README).
func pmacctProjection(protocol string, tc fixtureCase, packet []byte, sequence uint32, custom []byte) []map[string]any {
	num := func(n uint64) json.Number { return json.Number(fmt.Sprint(n)) }
	version, timeOffset, domain := uint64(9), 8, uint64(42)
	if protocol == "v5" {
		version, domain = 5, 0
	} else if protocol == "ipfix" {
		version, timeOffset = 10, 4
	}
	exported := binary.BigEndian.Uint32(packet[timeOffset:])
	start, end := exported, uint32(0)
	if protocol == "v5" {
		uptime := binary.BigEndian.Uint32(packet[4:])
		// pmacct discards v5 subsecond precision and header unix_nsecs.
		start = exported - (uptime-1000)/1000
		end = exported - (uptime-1001)/1000
	}
	src, dst, mask := "192.0.2.1", "198.51.100.2", uint64(24)
	if strings.Contains(tc.Name, "ipv6") {
		src, dst, mask = "2001:db8::1", "2001:db8::2", 64
	}
	var rows []map[string]any
	for i := range tc.ExpectedRecords {
		row := map[string]any{
			"event_type": "purge", "ip_src": src, "ip_dst": dst,
			"port_src": num(12345), "port_dst": num(443), "ip_proto": "tcp", "tos": num(0), "tcp_flags": "24",
			"iface_in": num(10), "iface_out": num(20), "as_src": num(64513), "as_dst": num(64514),
			"mask_src": num(mask), "mask_dst": num(mask), "flows": num(1), "packets": num(1234), "bytes": num(56789),
			"sampling_rate":      num(uint64(1000 * (i + 1))),
			"export_proto_seqno": num(uint64(sequence)), "export_proto_version": num(version), "export_proto_sysid": num(domain),
			"timestamp_start": fmt.Sprintf("%d.000000", start), "timestamp_end": fmt.Sprintf("%d.000000", end),
			"timestamp_export": fmt.Sprintf("%d.000000", exported),
		}
		if custom != nil {
			row["pen_fixed"] = "00-7F-80-FF"
			parts := make([]string, len(custom))
			for i, b := range custom {
				parts[i] = fmt.Sprintf("%02X", b)
			}
			row["pen_vlen"] = strings.Join(parts, "-")
		}
		rows = append(rows, row)
	}
	return rows
}

func TestPmacctOutputValidation(t *testing.T) {
	valid := []byte("{\"export_proto_seqno\":4,\"sampling_rate\":1000,\"bytes\":56789}\n")
	want, err := parseRows(valid, true)
	must(t, err)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"correct", valid},
		{"missing", nil},
		{"duplicate", append(append([]byte(nil), valid...), valid...)},
		{"scaled-counters", bytes.ReplaceAll(valid, []byte("56789"), []byte("56789000"))},
		{"ignored-sampling", bytes.ReplaceAll(valid, []byte("1000"), []byte("0"))},
		{"wrong-sequence", bytes.ReplaceAll(valid, []byte(":4,"), []byte(":0,"))},
		{"wrong-type", bytes.ReplaceAll(valid, []byte("56789"), []byte(`"56789"`))},
		{"truncated", valid[:len(valid)-2]},
		{"null", []byte("null\n")},
		{"trailing", []byte("{\"bytes\":56789} {}\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRows(tc.data, true)
			if err == nil {
				err = compareRows(got, want)
			}
			if (err == nil) != (tc.name == "correct") {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
	// A partial next line must not count during live polling, and must not
	// survive the final post-shutdown validation.
	partial := append(append([]byte(nil), valid...), []byte(`{"bytes":`)...)
	rows, err := parseRows(partial, false)
	must(t, err)
	must(t, compareRows(rows, want))
	if _, err := parseRows(partial, true); err == nil {
		t.Fatal("partial final line accepted")
	}
}
