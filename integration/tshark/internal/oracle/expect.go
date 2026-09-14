package oracle

import (
	"fmt"
	"strconv"
	"strings"
)

// These are literal expectations from the canonical fixture metadata and the
// accepted static profile tables, independent of exporter encoders and PDML.
// Offsets are Ethernet-frame offsets, as reported by TShark's PDML writer.
type field struct {
	Name  string `xml:"name,attr"`
	Show  string `xml:"show,attr"`
	Size  int    `xml:"size,attr"`
	Pos   int    `xml:"pos,attr"`
	Value string `xml:"value,attr"`
}

type recordField struct {
	name, show string
	width, id  int
}

func expectedFlow(slot string) ([]field, error) {
	type fixture struct {
		version, length, domain int
		ipv6, two               bool
	}
	fixtures := map[string]fixture{
		"v5-canonical-ipv4-v1":                      {5, 72, 0, false, false},
		"v9-canonical-ipv4-v1":                      {9, 148, 42, false, false},
		"v9-canonical-ipv6-v1":                      {9, 172, 43, true, false},
		"v9-sampling-ie34-two-distinct-rates-v1":    {9, 192, 47, false, true},
		"ipfix-canonical-ipv4-v1":                   {10, 180, 46, false, false},
		"ipfix-canonical-ipv6-v1":                   {10, 204, 51, true, false},
		"ipfix-sampling-ie34-two-distinct-rates-v1": {10, 252, 48, false, true},
	}
	f, ok := fixtures[slot]
	if !ok {
		return nil, fmt.Errorf("unknown oracle fixture %q", slot)
	}
	var want []field
	pos := 42
	add := func(name string, show any, size int) {
		want = append(want, field{Name: "cflow." + name, Show: fmt.Sprint(show), Size: size, Pos: pos})
		pos += size
	}
	add("version", f.version, 2)
	if f.version == 5 {
		add("count", 1, 2)
		add("sysuptime", "3.000000000", 4)
		add("unix_secs", 1788220803, 4)
		add("unix_nsecs", 0, 4)
		add("sequence", 0, 4)
		add("engine_type", 1, 1)
		add("engine_id", 5, 1)
		add("samplingmode", 0, 2)
		pos -= 2
		add("samplerate", 1000, 2)
		for _, r := range []recordField{
			{"srcaddr", "192.0.2.1", 4, 0}, {"dstaddr", "198.51.100.2", 4, 0}, {"nexthop", "192.0.2.254", 4, 0},
			{"inputint", "10", 2, 0}, {"outputint", "20", 2, 0}, {"packets", "1234", 4, 0}, {"octets", "56789", 4, 0},
			{"timestart", "1.000000000", 4, 0}, {"timeend", "1.001000000", 4, 0},
			{"srcport", "12345", 2, 0}, {"dstport", "443", 2, 0}, {"padding", "00", 1, 0},
			{"tcpflags", "0x18", 1, 0}, {"protocol", "6", 1, 0}, {"tos", "0x00", 1, 0},
			{"srcas", "64513", 2, 0}, {"dstas", "64514", 2, 0}, {"srcmask", "24", 1, 0}, {"dstmask", "24", 1, 0}, {"padding", "00:00", 2, 0},
		} {
			add(r.name, r.show, r.width)
		}
		return want, nil
	}
	records := 1
	if f.two {
		records = 2
	}
	if f.version == 9 {
		add("count", 1+records, 2)
		add("sysuptime", "3.000000000", 4)
		add("unix_secs", 1788220803, 4)
		add("sequence", 0, 4)
		add("source_id", f.domain, 4)
	} else {
		add("len", f.length, 2)
		add("exporttime", 1788220803, 4)
		add("sequence", 0, 4)
		add("od_id", f.domain, 4)
	}
	record := []recordField{
		{"octets", "56789", 4, 1}, {"packets", "1234", 4, 2}, {"protocol", "6", 1, 4}, {"tos", "0x00", 1, 5},
		{"tcpflags", "0x18", 1, 6}, {"srcport", "12345", 2, 7}, {"srcaddr", "192.0.2.1", 4, 8}, {"srcmask", "24", 1, 9},
		{"inputint", "10", 2, 10}, {"dstport", "443", 2, 11}, {"dstaddr", "198.51.100.2", 4, 12}, {"dstmask", "24", 1, 13},
		{"outputint", "20", 2, 14}, {"srcas", "64513", 4, 16}, {"dstas", "64514", 4, 17}, {"sampling_interval", "1000", 4, 34},
		{"ttl_min", "64", 1, 52}, {"ip_version", "4", 1, 60},
	}
	if f.ipv6 {
		record[6] = recordField{"srcaddrv6", "2001:db8::1", 16, 27}
		record[7] = recordField{"srcmaskv6", "64", 1, 29}
		record[10] = recordField{"dstaddrv6", "2001:db8::2", 16, 28}
		record[11] = recordField{"dstmaskv6", "64", 1, 30}
		record[17].show = "6"
	}
	templateSet, templateID := 0, 256
	if f.ipv6 {
		templateID = 257
	}
	if f.version == 10 {
		templateSet = 2
		record[0].width = 8
		record[1].width = 8
		record[4].width = 2
		record[4].show = "0x0018"
		record[8].width = 4
		record[12].width = 4
		// TShark floors NTP fractions to ns; the immutable nearest-NTP fraction
		// 0x00418937 is 999999 ns, as the pinned receiver also observes.
		record = append(record, recordField{"abstimestart", "2026-09-01T00:00:01.000000000+0000", 8, 156}, recordField{"abstimeend", "2026-09-01T00:00:01.000999999+0000", 8, 157})
	}
	add("flowset_id", templateSet, 2)
	add("flowset_length", 8+4*len(record), 2)
	add("template_id", templateID, 2)
	add("template_field_count", len(record), 2)
	for _, r := range record {
		name := "template_field_type"
		if f.version == 10 {
			add("template_ipfix_pen_provided", "False", 2)
			pos -= 2
			name = "template_ipfix_field_type"
		}
		add(name, r.id, 2)
		add("template_field_length", r.width, 2)
	}
	recordSize := 0
	for _, r := range record {
		recordSize += r.width
	}
	pad := (4 - records*recordSize%4) % 4
	add("flowset_id", templateID, 2)
	add("flowset_length", 4+records*recordSize+pad, 2)
	for i := range records {
		for _, r := range record {
			if r.id == 34 {
				r.show = strconv.Itoa(1000 * (i + 1))
			}
			add(r.name, r.show, r.width)
		}
	}
	if pad != 0 {
		add("padding", strings.TrimSuffix(strings.Repeat("00:", pad), ":"), pad)
	}
	if pos != 42+f.length {
		return nil, fmt.Errorf("oracle expectation length mismatch")
	}
	return want, nil
}
