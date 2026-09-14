package independent_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// These literal layouts come from the accepted static profiles and stock
// IPFIXcol2 netflow5.c's conversion template, not the exporter encoder.
func ipfixcolFields(protocol string, ipv6, custom bool) []any {
	layout := [][2]int{{1, 8}, {2, 8}, {4, 1}, {5, 1}, {6, 2}, {7, 2}, {8, 4}, {9, 1}, {10, 4}, {11, 2}, {12, 4}, {13, 1}, {14, 4}, {16, 4}, {17, 4}, {34, 4}, {52, 1}, {60, 1}, {156, 8}, {157, 8}}
	if protocol == "v9" {
		layout = layout[:18]
		layout[0][1], layout[1][1], layout[4][1], layout[8][1], layout[12][1] = 4, 4, 1, 2, 2
	}
	if ipv6 {
		layout[6], layout[7], layout[10], layout[11] = [2]int{27, 16}, [2]int{29, 1}, [2]int{28, 16}, [2]int{30, 1}
	}
	if protocol == "v5" {
		layout = [][2]int{{8, 4}, {12, 4}, {15, 4}, {10, 2}, {14, 2}, {2, 4}, {1, 4}, {152, 8}, {153, 8}, {7, 2}, {11, 2}, {210, 1}, {6, 1}, {4, 1}, {5, 1}, {16, 2}, {17, 2}, {9, 1}, {13, 1}, {35, 1}, {210, 1}, {34, 4}}
	}
	var fields []any
	add := func(id, length, pen int) {
		fields = append(fields, map[string]any{"ipfix:elementId": jsonNum(id), "ipfix:enterpriseId": jsonNum(pen), "ipfix:fieldLength": jsonNum(length)})
	}
	for _, f := range layout {
		add(f[0], f[1], 0)
	}
	if custom {
		add(400, 4, 32473)
		add(401, 65535, 32473)
	}
	return fields
}

func jsonNum[N ~int | ~uint32 | ~uint64](n N) json.Number { return json.Number(fmt.Sprint(n)) }

// Explicit libfds JSON projection; see README for pinned conversion sources.
// Original payloads have already passed the independent golden/literal check.
func ipfixcolProjection(protocol string, tc fixtureCase, stream []exportPacket, custom []byte) []map[string]any {
	var rows []map[string]any
	convertedSequence := uint32(0)
	for index, p := range stream {
		timeOffset, domain := 8, 42
		if protocol == "ipfix" {
			timeOffset = 4
		}
		if protocol == "v5" {
			domain = 0
		}
		length := len(p.bytes)
		if protocol == "v5" {
			length = 80
			if index == 0 {
				length += 96
			}
		} else if protocol == "v9" {
			length = 96
			if p.phase == "data" {
				size := 43
				if strings.Contains(tc.Name, "ipv6") {
					size = 67
				}
				length = 20 + size*tc.ExpectedRecords // converter drops v9 padding
			}
		}
		metadata := func(kind string, template int) map[string]any {
			return map[string]any{
				"@type": kind, "ipfix:templateId": jsonNum(template),
				"ipfix:exportTime": jsonNum(binary.BigEndian.Uint32(p.bytes[timeOffset:])),
				"ipfix:seqNumber":  jsonNum(convertedSequence), "ipfix:odid": jsonNum(domain),
				"ipfix:msgLength": jsonNum(length), "ipfix:srcAddr": "127.0.0.1",
			}
		}
		if p.phase != "data" || (protocol == "v5" && index == 0) {
			row := metadata("ipfix.template", 256+p.shape)
			row["ipfix:fields"] = ipfixcolFields(protocol, p.shape == 1, custom != nil)
			rows = append(rows, row)
		}
		if p.phase != "data" {
			continue
		}
		for i := range tc.ExpectedRecords {
			ipv6 := strings.Contains(tc.Name, "ipv6")
			template := 256
			if ipv6 {
				template++
			}
			row := metadata("ipfix.entry", template)
			for id, n := range map[int]int{1: 56789, 2: 1234, 4: 6, 5: 0, 6: 24, 7: 12345, 10: 10, 11: 443, 14: 20, 16: 64513, 17: 64514, 34: 1000 * (i + 1)} {
				row[fmt.Sprintf("en0:id%d", id)] = jsonNum(n)
			}
			if ipv6 {
				row["en0:id27"], row["en0:id28"] = "2001:db8::1", "2001:db8::2"
				row["en0:id29"], row["en0:id30"] = jsonNum(64), jsonNum(64)
			} else {
				row["en0:id8"], row["en0:id12"] = "192.0.2.1", "198.51.100.2"
				row["en0:id9"], row["en0:id13"] = jsonNum(24), jsonNum(24)
			}
			if protocol == "v5" {
				row["en0:id15"], row["en0:id35"] = "192.0.2.254", jsonNum(0)
				exported := uint64(binary.BigEndian.Uint32(p.bytes[8:]))*1000 + uint64(binary.BigEndian.Uint32(p.bytes[12:]))/1_000_000
				uptime := uint64(binary.BigEndian.Uint32(p.bytes[4:]))
				row["en0:id152"], row["en0:id153"] = jsonNum(exported-uptime+1000), jsonNum(exported-uptime+1001)
			} else {
				row["en0:id52"], row["en0:id60"] = jsonNum(64), jsonNum(4)
				if ipv6 {
					row["en0:id60"] = jsonNum(6)
				}
			}
			if protocol == "ipfix" {
				// libfds converts the NTP fraction to milliseconds with integer
				// truncation. The encoded +1 ms end is just below that boundary.
				row["en0:id156"], row["en0:id157"] = jsonNum(uint64(1788220801000)), jsonNum(uint64(1788220801000))
			}
			if custom != nil {
				row["en32473:id400"] = "0x007F80FF"
				row["en32473:id401"] = fmt.Sprintf("0x%X", custom)
			}
			rows = append(rows, row)
		}
		convertedSequence += uint32(tc.ExpectedRecords)
	}
	return rows
}

func TestIPFIXcolOutputValidation(t *testing.T) {
	// Include template identity/width, a large enterprise field, and a precise
	// timestamp so the oracle's failure tests cover more than row counts.
	row := map[string]any{"@type": "ipfix.entry", "ipfix:seqNumber": jsonNum(2), "en0:id34": jsonNum(2000), "en0:id1": jsonNum(56789), "en0:id157": jsonNum(uint64(1788220801000)), "en32473:id401": "0x000102"}
	template := map[string]any{"@type": "ipfix.template", "ipfix:templateId": jsonNum(256), "ipfix:fields": ipfixcolFields("ipfix", false, true)}
	data, _ := json.Marshal(template)
	line, _ := json.Marshal(row)
	valid := append(append(data, '\n'), append(line, '\n')...)
	want, err := parseRows(valid, true)
	must(t, err)
	for _, tc := range []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
	}{
		{"correct", func(r []map[string]any) []map[string]any { return r }},
		{"missing", func(r []map[string]any) []map[string]any { return r[:1] }},
		{"duplicate", func(r []map[string]any) []map[string]any { return append(r, r[1]) }},
		{"options", func(r []map[string]any) []map[string]any { r[0]["@type"] = "ipfix.optionsTemplate"; return r }},
		{"sampling", func(r []map[string]any) []map[string]any { r[1]["en0:id34"] = jsonNum(0); return r }},
		{"scaling", func(r []map[string]any) []map[string]any { r[1]["en0:id1"] = jsonNum(56789000); return r }},
		{"type", func(r []map[string]any) []map[string]any { r[1]["en0:id1"] = "56789"; return r }},
		{"sequence", func(r []map[string]any) []map[string]any { r[1]["ipfix:seqNumber"] = jsonNum(4); return r }},
		{"time", func(r []map[string]any) []map[string]any {
			r[1]["en0:id157"] = jsonNum(uint64(1788220801001))
			return r
		}},
		{"enterprise-missing", func(r []map[string]any) []map[string]any { delete(r[1], "en32473:id401"); return r }},
		{"enterprise-bytes", func(r []map[string]any) []map[string]any { r[1]["en32473:id401"] = "0x0001"; return r }},
		{"template-width", func(r []map[string]any) []map[string]any {
			r[0]["ipfix:fields"].([]any)[0].(map[string]any)["ipfix:fieldLength"] = jsonNum(4)
			return r
		}},
		{"unexpected", func(r []map[string]any) []map[string]any { r[1]["extra"] = nil; return r }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRows(valid, true)
			must(t, err)
			err = compareIPFIXcolRows(tc.mutate(got), want)
			if (err == nil) != (tc.name == "correct") {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}
