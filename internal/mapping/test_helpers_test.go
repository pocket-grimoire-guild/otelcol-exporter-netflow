package mapping

import (
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func uint16ptr(value uint16) *uint16 { return &value }

func uint32ptr(value uint32) *uint32 { return &value }

func boolptr(value bool) *bool { return &value }

func testTokenVocabularyBoundary(t *testing.T) {
	// This table is copied from the pinned receiver artifact, rather than
	// asserting only the size or a few endpoints of the implementation map.
	tokens := []string{
		"hopopt", "icmp", "igmp", "ggp", "ipv4", "st", "tcp", "cbt", "egp", "igp",
		"bbn-rcc-mon", "nvp-ii", "pup", "argus", "emcon", "xnet", "chaos", "udp", "mux", "dcn-meas",
		"hmp", "prm", "xns-idp", "trunk-1", "trunk-2", "leaf-1", "leaf-2", "rdp", "irtp", "iso-tp4",
		"netblt", "mfe-nsp", "merit-inp", "dccp", "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++",
		"il", "ipv6", "sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre", "dsr", "bna", "esp",
		"ah", "i-nlsp", "swipe", "narp", "min-ipv4", "tlsp", "skip", "ipv6-icmp", "ipv6-nonxt", "ipv6-opts",
		"any-host-internal-protocol", "cftp", "any-local-network", "sat-expak", "kryptolan", "rvd", "ippc", "any-distributed-file-system", "sat-mon", "visa",
		"ipcv", "cpnx", "cphb", "wsn", "pvp", "br-sat-mon", "sun-nd", "wb-mon", "wb-expak", "iso-ip",
		"vmtp", "secure-vmtp", "vines", "iptm", "nsfnet-igp", "dgp", "tcf", "eigrp", "ospfigp", "sprite-rpc",
		"larp", "mtp", "ax.25", "ipip", "micp", "scc-sp", "etherip", "encap", "any-private-encryption-scheme", "gmtp",
		"ifmp", "pnni", "pim", "aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer",
		"ipx-in-ip", "vrrp", "pgm", "any-0-hop-protocol", "l2tp", "ddx", "iatp", "stp", "srp", "uti",
		"smp", "sm", "ptp", "isis over ipv4", "fire", "crtp", "crudp", "sscopmce", "iplt", "sps",
		"pipe", "sctp", "fc", "rsvp-e2e-ignore", "mobility header", "udplite", "mpls-in-ip", "manet", "hip", "shim6",
		"wesp", "rohc", "ethernet", "aggfrag", "nsh",
	}
	if len(tokens) != 146 {
		t.Fatalf("pinned token table length=%d", len(tokens))
	}
	for number, token := range tokens {
		got, ok := ProtocolNumber(token)
		if !ok || int(got) != number {
			t.Fatalf("token %q=%d/%v want %d/true", token, got, ok, number)
		}
	}
	for _, alias := range []string{"unknown", "TCP", "udp ", "6", "ipv4-address", "IPV6-ICMP"} {
		if _, ok := ProtocolNumber(alias); ok {
			t.Fatalf("invalid token alias accepted: %q", alias)
		}
	}
	for _, tc := range []struct {
		token   string
		version uint8
	}{
		{"ipv4", 4}, {"ipv6", 6},
	} {
		if got, ok := NetworkVersion(tc.token); !ok || got != tc.version {
			t.Fatalf("network token %q=%d/%v", tc.token, got, ok)
		}
	}
	for _, alias := range []string{"unknown", "ipv4 ", "IPv4", "ethernet", "arp"} {
		if _, ok := NetworkVersion(alias); ok {
			t.Fatalf("invalid network token accepted: %q", alias)
		}
	}
}

func testPMTUBoundary(t *testing.T) {
	base := func() Config {
		return explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	}
	cases := []struct {
		name     string
		pathMTU  uint64
		payload  uint64
		endpoint string
		valid    bool
	}{
		{"absent-464", 0, 464, "", true},
		{"absent-465", 0, 465, "", false},
		{"ipv4-512-484", 512, 484, "192.0.2.1:4739", true},
		{"ipv4-512-485", 512, 485, "192.0.2.1:4739", false},
		{"ipv6-512-464", 512, 464, "[2001:db8::1]:4739", true},
		{"ipv6-512-465", 512, 465, "[2001:db8::1]:4739", false},
		{"hostname-512-464", 512, 464, "collector.example:4739", true},
		{"hostname-512-465", 512, 465, "collector.example:4739", false},
		{"ipv4-max-65507", 65535, 65507, "192.0.2.1:4739", true},
		{"ipv4-max-one-beyond", 65535, 65508, "192.0.2.1:4739", false},
		{"ipv6-max-65487", 65535, 65487, "[2001:db8::1]:4739", true},
		{"ipv6-max-65488", 65535, 65488, "[2001:db8::1]:4739", false},
		{"hostname-max-65487", 65535, 65487, "collector.example:4739", true},
		{"hostname-max-65488", 65535, 65488, "collector.example:4739", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := base()
			config.PathMTU, config.MaxDatagramSize, config.Endpoint = tc.pathMTU, tc.payload, tc.endpoint
			_, err := Compile(config)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	for _, pathMTU := range []uint64{511, 65536} {
		config := base()
		config.PathMTU = pathMTU
		if _, err := Compile(config); err == nil {
			t.Fatalf("invalid path MTU %d accepted", pathMTU)
		}
	}
	if err := validatePMTU(Config{PathMTU: 65535}, math.MaxUint64, wire.ProtocolIPFIX); err == nil {
		t.Fatal("checked PMTU addition overflow accepted")
	}
	if got, ok := mappingDataBytes(wire.ProtocolV5, 48); !ok || got != 72 {
		t.Fatalf("v5 data budget=%d/%v want 72/true", got, ok)
	}
}

func testStaticBoundaryMatrix(t *testing.T) {
	base := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		valid  bool
	}{
		{"shapes-16", func(c *Config) { c.Limits.MaxShapes = 16 }, true},
		{"shapes-17", func(c *Config) { c.Limits.MaxShapes = 17 }, false},
		{"fields-64", func(c *Config) { c.Limits.MaxFieldsPerShape = 64 }, true},
		{"fields-65", func(c *Config) { c.Limits.MaxFieldsPerShape = 65 }, false},
		{"template-4096", func(c *Config) { c.Limits.MaxTemplateBytes = 4096 }, true},
		{"template-4097", func(c *Config) { c.Limits.MaxTemplateBytes = 4097 }, false},
		{"custom-32", func(c *Config) { c.Limits.MaxCustomMappings = 32 }, true},
		{"custom-33", func(c *Config) { c.Limits.MaxCustomMappings = 33 }, false},
		{"pens-32", func(c *Config) { c.Limits.MaxPENs = 32 }, true},
		{"pens-33", func(c *Config) { c.Limits.MaxPENs = 33 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			tc.mutate(&config)
			if tc.name == "custom-32" || tc.name == "custom-33" || tc.name == "pens-32" || tc.name == "pens-33" {
				config.Custom = make([]CustomField, 32)
				for i := range config.Custom {
					config.Custom[i] = CustomField{Source: "vendor." + strconv.Itoa(i), PEN: uint32ptr(uint32(i + 1)), ElementID: uint32ptr(uint32(i + 1)), Encoding: "unsigned8", FixedLength: uint16ptr(1)}
				}
				if tc.name == "custom-33" {
					config.Custom = append(config.Custom, CustomField{Source: "vendor.extra", PEN: uint32ptr(33), ElementID: uint32ptr(33), Encoding: "unsigned8", FixedLength: uint16ptr(1)})
				}
			}
			_, err := Compile(config)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	for _, baseID := range []uint32{255, 65536} {
		config := base
		config.IDBase = baseID
		if _, err := Compile(config); err == nil {
			t.Fatalf("ID base %d accepted", baseID)
		}
	}
	for _, baseID := range []uint32{256, 65535} {
		config := base
		config.IDBase = baseID
		if _, err := Compile(config); err != nil {
			t.Fatalf("ID base %d rejected: %v", baseID, err)
		}
	}
	if _, ok := templateBytes(wire.ProtocolIPFIX, make([]wire.FieldDescriptor, 1022)); !ok {
		t.Fatal("4096-byte template arithmetic rejected")
	}
	if _, ok := templateBytes(wire.ProtocolIPFIX, make([]wire.FieldDescriptor, 1023)); ok {
		t.Fatal("overlarge template arithmetic accepted")
	}

	shapeFields := []wire.FieldDescriptor{{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, ID: 7, Length: 2, Encoding: wire.EncodingUnsigned16}}
	shapes := make([]wire.ShapeSpec, wire.DefaultMaxShapes)
	for i := range shapes {
		shapes[i] = wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: uint32(256 + i), Fields: shapeFields, RecordLength: 2, TemplateBytes: 12}
	}
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: shapes}); err != nil {
		t.Fatalf("actual 16-shape ceiling rejected: %v", err)
	}
	shapes = append(shapes, wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 272, Fields: shapeFields, RecordLength: 2, TemplateBytes: 12})
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: shapes}); err == nil {
		t.Fatal("actual 17-shape ceiling accepted")
	}

	fields := make([]wire.FieldDescriptor, wire.DefaultMaxFieldsPerShape)
	for i := range fields {
		fields[i] = wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, ID: uint16(i + 1), Length: 2, Encoding: wire.EncodingUnsigned16}
	}
	fieldShape := wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 256, Fields: fields, RecordLength: 128, TemplateBytes: 264}
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: []wire.ShapeSpec{fieldShape}}); err != nil {
		t.Fatalf("actual 64-field ceiling rejected: %v", err)
	}
	fieldShape.Fields = append(fields, wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldSourcePort, ID: 65, Length: 2, Encoding: wire.EncodingUnsigned16})
	fieldShape.RecordLength = 130
	fieldShape.TemplateBytes = 268
	if _, err := wire.NewCatalog(wire.CatalogSpec{Protocol: wire.ProtocolV9, IDBase: 256, Shapes: []wire.ShapeSpec{fieldShape}}); err == nil {
		t.Fatal("actual 65-field ceiling accepted")
	}
	if got := wire.DefaultMaxTemplateBytes; got != 4096 {
		t.Fatalf("template ceiling changed to %d", got)
	}
	if over := wire.DefaultMaxTemplateBytes + 1; over != 4097 {
		t.Fatalf("template over-ceiling arithmetic=%d", over)
	}
	tooLargeTemplate := wire.ShapeSpec{Protocol: wire.ProtocolV9, Family: wire.FamilyIPv4, ID: 256, Fields: shapeFields, RecordLength: 2, TemplateBytes: 4097}
	if _, err := wire.NewShape(tooLargeTemplate); err == nil {
		t.Fatal("actual 4097-byte template ceiling accepted")
	}
}

func testConcurrentMapper(t *testing.T) {
	compiled, err := Compile(explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "source.port"}}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewRecord(wire.FamilyIPv6, []wire.FieldValue{{Field: wire.FieldSourcePort, Value: wire.UintValue(443)}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := compiled.Fingerprint()
	shape, _ := compiled.Catalog().ShapeAt(0)
	fields := shape.Fields()
	fields[0].ID = 1
	shapeAgain, _ := compiled.Catalog().ShapeAt(0)
	if shapeAgain.Fields()[0].ID == 1 || compiled.Fingerprint() != fingerprint {
		t.Fatal("catalog accessor mutated immutable mapping")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				mapped, err := compiled.Map(record, nil)
				if err != nil || mapped.Len() != 1 || mapped.Family() != shape.Family() {
					t.Errorf("concurrent map=%v/%v", mapped, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	customConfig := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "source.port"}})
	customConfig.MaxDatagramSize, customConfig.PathMTU, customConfig.Endpoint = 4200, 4228, "192.0.2.1:4739"
	customConfig.Custom = []CustomField{{Source: "vendor.concurrent", PEN: uint32ptr(32473), ElementID: uint32ptr(100), Encoding: "string", Variable: boolptr(true), MaxLength: uint32ptr(16)}}
	custom, err := Compile(customConfig)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Uint64
	var customErrors atomic.Uint64
	wg = sync.WaitGroup{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mapped, mapErr := custom.Map(record, func(source string) (wire.Value, bool) {
				if source != "vendor.concurrent" {
					customErrors.Add(1)
					return wire.Value{}, false
				}
				calls.Add(1)
				return wire.StringValue("concurrent"), true
			})
			if mapErr != nil || mapped.Len() != 2 {
				customErrors.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 16 || customErrors.Load() != 0 {
		t.Fatalf("concurrent custom calls=%d errors=%d", calls.Load(), customErrors.Load())
	}
}

func testMapperAddressMACTimeAndRangeGates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		field  string
		family wire.Family
		good   uint64
		bad    uint64
	}{
		{"vlan", "flow.vlan_id", wire.FamilyIPv4, 4095, 4096},
		{"fragment-offset", "flow.fragment_offset", wire.FamilyIPv4, 0x1fff, 0x2000},
		{"ipv4-prefix", "flow.src_net", wire.FamilyIPv4, 32, 33},
		{"ipv6-prefix", "flow.src_net", wire.FamilyIPv6, 128, 129},
		{"observation-point", "flow.observation_point_id", wire.FamilyIPv4, math.MaxUint32, math.MaxUint32 + 1},
		{"ipv6-label", "flow.ipv6_flow_label", wire.FamilyIPv6, 0xfffff, 0x100000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: tc.field}})
			compiled, err := Compile(config)
			if err != nil {
				t.Fatal(err)
			}
			record, err := wire.NewRecord(tc.family, []wire.FieldValue{{Field: mustCanonical(t, tc.field), Value: wire.UintValue(tc.good)}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = compiled.Map(record, nil); err != nil {
				t.Fatalf("good value rejected: %v", err)
			}
			record, err = wire.NewRecord(tc.family, []wire.FieldValue{{Field: mustCanonical(t, tc.field), Value: wire.UintValue(tc.bad)}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = compiled.Map(record, nil); err == nil {
				t.Fatal("bad value accepted")
			}
		})
	}

	origin := uint64(1_000_000_000)
	config := explicitConfig(wire.ProtocolV9, []FieldSelection{{Canonical: "flow.start"}})
	config.HasUptimeOrigin, config.UptimeOriginUnixNanos = true, origin
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value uint64
		valid bool
	}{{origin, true}, {origin + 1_000_000, true}, {origin + 1, false}} {
		record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowStart, Value: wire.UnixNanosValue(tc.value)}})
		_, mapErr := compiled.Map(record, nil)
		if (mapErr == nil) != tc.valid {
			t.Fatalf("v9 start %d valid=%v err=%v", tc.value, tc.valid, mapErr)
		}
	}
	config = explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "flow.start"}})
	compiled, err = Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value uint64
		valid bool
	}{{maxIPFIXUnixNanos, true}, {maxIPFIXUnixNanos + 1, false}} {
		record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowStart, Value: wire.UnixNanosValue(tc.value)}})
		_, mapErr := compiled.Map(record, nil)
		if (mapErr == nil) != tc.valid {
			t.Fatalf("IPFIX start %d valid=%v err=%v", tc.value, tc.valid, mapErr)
		}
	}

	config = explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "flow.src_mac", Target: "source_mac_address"}})
	compiled, err = Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowSrcMAC, Value: wire.StringValue("00:11:22:33:44:55")}})
	if _, err = compiled.Map(record, nil); err == nil {
		t.Fatal("malformed canonical MAC type accepted")
	}
}

func mustCanonical(t *testing.T, name string) wire.CanonicalField {
	t.Helper()
	field, ok := canonicalField(name)
	if !ok {
		t.Fatalf("unknown test field %q", name)
	}
	return field
}
