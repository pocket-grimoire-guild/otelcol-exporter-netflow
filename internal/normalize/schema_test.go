package normalize

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestSchema(t *testing.T) {
	t.Run("required-optional", TestSchemaRequiredAndOptionalKeys)
	t.Run("missing-required", TestSchemaMissingEachRequiredKey)
	t.Run("optional-absence", TestSchemaOnlyOptionalAbsenceAllowed)
	t.Run("all-field-vectors", TestSchemaAllFieldVectors)
	t.Run("address-vectors", TestSchemaAddressVectors)
	t.Run("mac-vectors", TestSchemaMACVectors)
	t.Run("bad-utf8", TestSchemaBadUTF8)
	t.Run("token-vectors", TestSchemaTokenVectors)
}

func TestSchemaRequiredAndOptionalKeys(t *testing.T) {
	if len(requiredFields) != 39 {
		t.Fatalf("required field count = %d, want 39", len(requiredFields))
	}
	seen := make(map[wire.CanonicalField]bool, len(requiredFields))
	for _, field := range requiredFields {
		if !field.Valid() || seen[field] {
			t.Fatalf("invalid or duplicate required field %v", field)
		}
		seen[field] = true
	}
	if seen[wire.FieldFlowNextHop] || seen[wire.FieldFlowBGPNextHop] {
		t.Fatal("optional key is marked required")
	}
	if len(canonicalFieldByName) != wire.CanonicalFieldCount {
		t.Fatalf("canonical key count = %d, want 41", len(canonicalFieldByName))
	}
}

// canonicalSchemaVectors is deliberately test-owned. It is the independent
// 41-field contract oracle; implementation registries are only cross-checked
// after these literals have driven the acceptance and rejection cases.
var canonicalSchemaVectors = [...]struct {
	name     string
	field    wire.CanonicalField
	pdata    pcommon.ValueType
	kind     wire.ValueKind
	numeric  bool
	max      uint64
	zeroText string
	optional bool
}{
	{name: "source.address", field: wire.FieldSourceAddress, pdata: pcommon.ValueTypeStr, kind: wire.ValueIP, zeroText: "0.0.0.0"},
	{name: "source.port", field: wire.FieldSourcePort, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 65535},
	{name: "destination.address", field: wire.FieldDestinationAddress, pdata: pcommon.ValueTypeStr, kind: wire.ValueIP, zeroText: "0.0.0.0"},
	{name: "destination.port", field: wire.FieldDestinationPort, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 65535},
	{name: "network.transport", field: wire.FieldNetworkTransport, pdata: pcommon.ValueTypeStr, kind: wire.ValueString, zeroText: "unknown"},
	{name: "network.type", field: wire.FieldNetworkType, pdata: pcommon.ValueTypeStr, kind: wire.ValueString, zeroText: "unknown"},
	{name: "flow.io.bytes", field: wire.FieldFlowIOBytes, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxInt64},
	{name: "flow.io.packets", field: wire.FieldFlowIOPackets, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxInt64},
	{name: "flow.type", field: wire.FieldFlowType, pdata: pcommon.ValueTypeStr, kind: wire.ValueString, zeroText: "unknown"},
	{name: "flow.sequence_num", field: wire.FieldFlowSequenceNum, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.time_received", field: wire.FieldFlowTimeReceived, pdata: pcommon.ValueTypeInt, kind: wire.ValueUnixNanos, numeric: true, max: math.MaxInt64},
	{name: "flow.start", field: wire.FieldFlowStart, pdata: pcommon.ValueTypeInt, kind: wire.ValueUnixNanos, numeric: true, max: math.MaxInt64},
	{name: "flow.end", field: wire.FieldFlowEnd, pdata: pcommon.ValueTypeInt, kind: wire.ValueUnixNanos, numeric: true, max: math.MaxInt64},
	{name: "flow.sampling_rate", field: wire.FieldFlowSamplingRate, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxInt64},
	{name: "flow.sampler_address", field: wire.FieldFlowSamplerAddress, pdata: pcommon.ValueTypeStr, kind: wire.ValueIP, zeroText: "0.0.0.0"},
	{name: "flow.tcp_flags", field: wire.FieldFlowTCPFlags, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 65535},
	{name: "flow.in_if", field: wire.FieldFlowInIf, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.out_if", field: wire.FieldFlowOutIf, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.ip_tos", field: wire.FieldFlowIPTOS, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint8},
	{name: "flow.ip_ttl", field: wire.FieldFlowIPTTL, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint8},
	{name: "flow.ip_flags", field: wire.FieldFlowIPFlags, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.fragment_id", field: wire.FieldFlowFragmentID, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.fragment_offset", field: wire.FieldFlowFragmentOffset, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.ipv6_flow_label", field: wire.FieldFlowIPv6FlowLabel, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 0xfffff},
	{name: "flow.icmp_type", field: wire.FieldFlowICMPType, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint8},
	{name: "flow.icmp_code", field: wire.FieldFlowICMPCode, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint8},
	{name: "flow.src_mac", field: wire.FieldFlowSrcMAC, pdata: pcommon.ValueTypeStr, kind: wire.ValueMAC, zeroText: "00:00:00:00:00:00"},
	{name: "flow.dst_mac", field: wire.FieldFlowDstMAC, pdata: pcommon.ValueTypeStr, kind: wire.ValueMAC, zeroText: "00:00:00:00:00:00"},
	{name: "flow.src_vlan", field: wire.FieldFlowSrcVLAN, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 4095},
	{name: "flow.dst_vlan", field: wire.FieldFlowDstVLAN, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 4095},
	{name: "flow.vlan_id", field: wire.FieldFlowVLANID, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 4095},
	{name: "flow.next_hop", field: wire.FieldFlowNextHop, pdata: pcommon.ValueTypeStr, kind: wire.ValueIP, zeroText: "0.0.0.0", optional: true},
	{name: "flow.next_hop_as", field: wire.FieldFlowNextHopAS, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.src_as", field: wire.FieldFlowSrcAS, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.dst_as", field: wire.FieldFlowDstAS, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.bgp_next_hop", field: wire.FieldFlowBGPNextHop, pdata: pcommon.ValueTypeStr, kind: wire.ValueIP, zeroText: "0.0.0.0", optional: true},
	{name: "flow.src_net", field: wire.FieldFlowSrcNet, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 128},
	{name: "flow.dst_net", field: wire.FieldFlowDstNet, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: 128},
	{name: "flow.forwarding_status", field: wire.FieldFlowForwardingStatus, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.observation_domain_id", field: wire.FieldFlowObservationDomainID, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
	{name: "flow.observation_point_id", field: wire.FieldFlowObservationPointID, pdata: pcommon.ValueTypeInt, kind: wire.ValueUint, numeric: true, max: math.MaxUint32},
}

func TestSchemaAllFieldVectors(t *testing.T) {
	if len(canonicalSchemaVectors) != 41 {
		t.Fatalf("independent schema vector count = %d, want 41", len(canonicalSchemaVectors))
	}
	seen := make(map[wire.CanonicalField]bool, len(canonicalSchemaVectors))
	for index, tc := range canonicalSchemaVectors {
		t.Run(tc.name, func(t *testing.T) {
			if tc.field != wire.CanonicalField(index) || seen[tc.field] {
				t.Fatalf("field identity = %v at index %d", tc.field, index)
			}
			seen[tc.field] = true
			if got, ok := canonicalFieldByName[tc.name]; !ok || got != tc.field {
				t.Fatalf("implementation key mapping = (%v,%v), want %v", got, ok, tc.field)
			}
			if tc.field.CanonicalName() != tc.name {
				t.Fatalf("canonical name = %q, want %q", tc.field.CanonicalName(), tc.name)
			}
			required := false
			for _, field := range requiredFields {
				if field == tc.field {
					required = true
					break
				}
			}
			if tc.optional == required {
				t.Fatalf("presence policy optional=%v, required=%v", tc.optional, required)
			}

			logs := testpdata.CanonicalLogs()
			if tc.field == wire.FieldFlowSrcNet || tc.field == wire.FieldFlowDstNet {
				logs = testpdata.CanonicalIPv6Logs()
			}
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			if tc.numeric {
				record.Attributes().PutInt(tc.name, 0)
			} else {
				record.Attributes().PutStr(tc.name, tc.zeroText)
			}
			if got, ok := record.Attributes().Get(tc.name); !ok || got.Type() != tc.pdata {
				t.Fatalf("pdata type = (%v,%v), want %v", got.Type(), ok, tc.pdata)
			}
			got, err := normalizeTestRecord(logs)
			if err != nil {
				t.Fatalf("zero/minimum normalization: %v", err)
			}
			value, ok := got.Lookup(tc.field)
			if !ok || value.Kind() != tc.kind {
				t.Fatalf("zero value = (%v,%v), want kind %v", value, ok, tc.kind)
			}
			t.Run("wrong-type", func(t *testing.T) {
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				if tc.numeric {
					record.Attributes().PutStr(tc.name, "0")
				} else {
					record.Attributes().PutInt(tc.name, 0)
				}
				if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidType) {
					t.Fatalf("wrong type error = %v, want invalid-type", err)
				}
			})

			if tc.numeric {
				for _, boundary := range []struct {
					name  string
					value uint64
				}{
					{name: "minimum", value: 0},
					{name: "maximum", value: tc.max},
				} {
					t.Run(boundary.name, func(t *testing.T) {
						boundaryLogs := testpdata.CanonicalLogs()
						if tc.field == wire.FieldFlowSrcNet || tc.field == wire.FieldFlowDstNet {
							boundaryLogs = testpdata.CanonicalIPv6Logs()
						}
						boundaryRecord := boundaryLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
						boundaryRecord.Attributes().PutInt(tc.name, int64(boundary.value))
						if _, err := normalizeTestRecord(boundaryLogs); err != nil {
							t.Fatalf("%s value %d rejected: %v", boundary.name, boundary.value, err)
						}
					})
				}
				if tc.max < math.MaxInt64 {
					t.Run("maximum-plus-one", func(t *testing.T) {
						logs := testpdata.CanonicalLogs()
						if tc.field == wire.FieldFlowSrcNet || tc.field == wire.FieldFlowDstNet {
							logs = testpdata.CanonicalIPv6Logs()
						}
						record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
						record.Attributes().PutInt(tc.name, int64(tc.max+1))
						if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
							t.Fatalf("maximum+1 error = %v, want invalid-value", err)
						}
					})
				}
				for _, negative := range []struct {
					name  string
					value int64
				}{
					{name: "negative", value: -1},
					{name: "decode-overflow", value: math.MinInt64},
				} {
					t.Run(negative.name, func(t *testing.T) {
						logs := testpdata.CanonicalLogs()
						record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
						record.Attributes().PutInt(tc.name, negative.value)
						if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
							t.Fatalf("negative/overflow error = %v, want invalid-value", err)
						}
					})
				}
				return
			}

		})
	}
}

func TestSchemaAddressVectors(t *testing.T) {
	addressFields := []struct {
		name  string
		field wire.CanonicalField
	}{
		{name: "source.address", field: wire.FieldSourceAddress},
		{name: "destination.address", field: wire.FieldDestinationAddress},
		{name: "flow.sampler_address", field: wire.FieldFlowSamplerAddress},
		{name: "flow.next_hop", field: wire.FieldFlowNextHop},
		{name: "flow.bgp_next_hop", field: wire.FieldFlowBGPNextHop},
	}
	for _, tc := range addressFields {
		t.Run(tc.name+"/ipv4", func(t *testing.T) {
			logs := testpdata.CanonicalIPv4Logs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutStr(tc.name, "192.0.2.99")
			got, err := normalizeTestRecord(logs)
			if err != nil {
				t.Fatalf("canonical IPv4 rejected: %v", err)
			}
			value, ok := got.Lookup(tc.field)
			if !ok || value.Kind() != wire.ValueIP || !value.IP().Is4() || value.IP().Is4In6() {
				t.Fatalf("IPv4 value = (%v,%v)", value, ok)
			}
		})
		t.Run(tc.name+"/ipv6", func(t *testing.T) {
			logs := testpdata.CanonicalIPv6Logs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutStr(tc.name, "2001:db8::99")
			got, err := normalizeTestRecord(logs)
			if err != nil {
				t.Fatalf("canonical IPv6 rejected: %v", err)
			}
			value, ok := got.Lookup(tc.field)
			if !ok || value.Kind() != wire.ValueIP || !value.IP().Is6() || value.IP().Is4() || value.IP().Is4In6() {
				t.Fatalf("IPv6 value = (%v,%v)", value, ok)
			}
		})
		for _, text := range []string{"192.000.2.1", "2001:0db8::1", "::ffff:192.0.2.1", "invalid IP", "not-an-address"} {
			t.Run(tc.name+"/reject/"+text, func(t *testing.T) {
				logs := testpdata.CanonicalIPv4Logs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, text)
				if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("address %q error = %v, want invalid-value", text, err)
				}
			})
		}
	}

	for _, tc := range []struct {
		name  string
		field string
		value int64
		ipv6  bool
		want  error
	}{
		{name: "ipv4-src-32", field: "flow.src_net", value: 32},
		{name: "ipv4-src-33", field: "flow.src_net", value: 33, want: ErrInvalidValue},
		{name: "ipv4-dst-32", field: "flow.dst_net", value: 32},
		{name: "ipv4-dst-33", field: "flow.dst_net", value: 33, want: ErrInvalidValue},
		{name: "ipv6-src-128", field: "flow.src_net", value: 128, ipv6: true},
		{name: "ipv6-src-129", field: "flow.src_net", value: 129, ipv6: true, want: ErrInvalidValue},
		{name: "ipv6-dst-128", field: "flow.dst_net", value: 128, ipv6: true},
		{name: "ipv6-dst-129", field: "flow.dst_net", value: 129, ipv6: true, want: ErrInvalidValue},
	} {
		t.Run("prefix/"+tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalIPv4Logs()
			if tc.ipv6 {
				logs = testpdata.CanonicalIPv6Logs()
			}
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutInt(tc.field, tc.value)
			_, err := normalizeTestRecord(logs)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("prefix %d rejected: %v", tc.value, err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("prefix %d error = %v, want %v", tc.value, err, tc.want)
			}
		})
	}
}

func TestSchemaMACVectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field wire.CanonicalField
	}{
		{name: "flow.src_mac", field: wire.FieldFlowSrcMAC},
		{name: "flow.dst_mac", field: wire.FieldFlowDstMAC},
	} {
		for _, value := range []struct {
			name string
			text string
			mac  [6]byte
		}{
			{name: "minimum", text: "00:00:00:00:00:00", mac: [6]byte{}},
			{name: "maximum", text: "ff:ff:ff:ff:ff:ff", mac: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		} {
			t.Run(tc.name+"/"+value.name, func(t *testing.T) {
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, value.text)
				got, err := normalizeTestRecord(logs)
				if err != nil {
					t.Fatalf("MAC rejected: %v", err)
				}
				if actual, ok := got.Lookup(tc.field); !ok || actual.Kind() != wire.ValueMAC || actual.MAC() != value.mac {
					t.Fatalf("MAC = (%v,%v), want %v", actual, ok, value.mac)
				}
			})
		}
		for _, text := range []string{"00:11:22:33:44:FF", "00-11-22-33-44-55", "00:11:22:33:44", "00:11:22:33:44:55:66"} {
			t.Run(tc.name+"/reject/"+text, func(t *testing.T) {
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, text)
				if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("MAC %q error = %v, want invalid-value", text, err)
				}
			})
		}
	}
}

func TestSchemaBadUTF8(t *testing.T) {
	for _, tc := range canonicalSchemaVectors {
		if tc.numeric {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().PutStr(tc.name, string([]byte{0xff, 0xfe}))
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("bad UTF-8 error = %v, want invalid-value", err)
			}
		})
	}
}

// These lists are the pinned receiver's literal vocabulary in protocol-number
// order. They intentionally do not reuse the production maps as an oracle.
var testNetworkTransportTokens = [...]string{
	"hopopt", "icmp", "igmp", "ggp", "ipv4", "st", "tcp", "udp", "cbt",
	"egp", "igp", "bbn-rcc-mon", "nvp-ii", "pup", "argus", "emcon", "xnet",
	"chaos", "mux", "dcn-meas", "hmp", "prm", "xns-idp", "trunk-1", "trunk-2",
	"leaf-1", "leaf-2", "rdp", "irtp", "iso-tp4", "netblt", "mfe-nsp", "merit-inp",
	"dccp", "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++", "il", "ipv6",
	"sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre", "dsr", "bna",
	"esp", "ah", "i-nlsp", "swipe", "narp", "min-ipv4", "tlsp", "skip",
	"ipv6-icmp", "ipv6-nonxt", "ipv6-opts", "any-host-internal-protocol", "cftp", "any-local-network",
	"sat-expak", "kryptolan", "rvd", "ippc", "any-distributed-file-system", "sat-mon", "visa",
	"ipcv", "cpnx", "cphb", "wsn", "pvp", "br-sat-mon", "sun-nd", "wb-mon",
	"wb-expak", "iso-ip", "vmtp", "secure-vmtp", "vines", "iptm", "nsfnet-igp", "dgp",
	"tcf", "eigrp", "ospfigp", "sprite-rpc", "larp", "mtp", "ax.25", "ipip",
	"micp", "scc-sp", "etherip", "encap", "any-private-encryption-scheme", "gmtp", "ifmp",
	"pnni", "pim", "aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer",
	"ipx-in-ip", "vrrp", "pgm", "any-0-hop-protocol", "l2tp", "ddx", "iatp", "stp",
	"srp", "uti", "smp", "sm", "ptp", "isis over ipv4", "fire", "crtp", "crudp",
	"sscopmce", "iplt", "sps", "pipe", "sctp", "fc", "rsvp-e2e-ignore", "mobility header",
	"udplite", "mpls-in-ip", "manet", "hip", "shim6", "wesp", "rohc", "ethernet", "aggfrag", "nsh",
	"unknown",
}

var testNetworkTypeTokens = [...]string{
	"unknown", "arp", "ipv4", "snmp", "ipv6", "mpls", "eapol", "lldp", "macsec", "mvrp", "ptp", "6lowpan",
}

var testFlowTypeTokens = [...]string{"unknown", "sflow_5", "netflow_v5", "netflow_v9", "ipfix"}

func TestSchemaTokenVectors(t *testing.T) {
	cases := []struct {
		name        string
		tokens      []string
		implemented map[string]struct{}
		invalid     []string
	}{
		{name: "network.transport", tokens: testNetworkTransportTokens[:], implemented: networkTransports, invalid: []string{"", "TCP", " tcp", "6", "ipv4 "}},
		{name: "network.type", tokens: testNetworkTypeTokens[:], implemented: networkTypes, invalid: []string{"", "IPv4", "ethernet", " ipv4", "1"}},
		{name: "flow.type", tokens: testFlowTypeTokens[:], implemented: flowTypes, invalid: []string{"", "NetFlow_v9", "netflow-v9", " netflow_v9", "3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.name {
			case "network.transport":
				if len(tc.tokens) != 147 { // protocol numbers 0..145 plus unknown
					t.Fatalf("transport token count = %d, want 147", len(tc.tokens))
				}
			case "network.type":
				if len(tc.tokens) != 12 { // eleven network types plus unknown
					t.Fatalf("network type token count = %d, want 12", len(tc.tokens))
				}
			case "flow.type":
				if len(tc.tokens) != 5 {
					t.Fatalf("flow type token count = %d, want 5", len(tc.tokens))
				}
			}
			if len(tc.tokens) != len(tc.implemented) {
				t.Fatalf("independent token count = %d, implementation count = %d", len(tc.tokens), len(tc.implemented))
			}
			expected := make(map[string]struct{}, len(tc.tokens))
			for _, token := range tc.tokens {
				if _, duplicate := expected[token]; duplicate {
					t.Fatalf("duplicate independent token %q", token)
				}
				expected[token] = struct{}{}
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, token)
				if _, err := normalizeTestRecord(logs); err != nil {
					t.Fatalf("pinned token %q rejected: %v", token, err)
				}
			}
			for token := range tc.implemented {
				if _, present := expected[token]; !present {
					t.Fatalf("implementation has unowned token %q", token)
				}
			}
			for _, token := range tc.invalid {
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, token)
				if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("alias/unknown token %q error = %v, want invalid-value", token, err)
				}
			}
			for index, token := range tc.tokens {
				for _, invalid := range []string{strings.ToUpper(token), token + " ", " " + token, strconv.Itoa(index)} {
					logs := testpdata.CanonicalLogs()
					record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
					record.Attributes().PutStr(tc.name, invalid)
					if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("alias/case/whitespace/numeric token %q error = %v, want invalid-value", invalid, err)
					}
				}
			}
			for _, invalid := range []string{"definitely-unknown", "unknown-value"} {
				logs := testpdata.CanonicalLogs()
				record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
				record.Attributes().PutStr(tc.name, invalid)
				if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("unknown token %q error = %v, want invalid-value", invalid, err)
				}
			}
		})
	}
}

func TestSchemaMissingEachRequiredKey(t *testing.T) {
	for _, field := range requiredFields {
		t.Run(field.CanonicalName(), func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			record.Attributes().Remove(field.CanonicalName())
			if _, err := normalizeTestRecord(logs); !errors.Is(err, ErrMissingRequired) {
				t.Fatalf("error = %v, want missing-required", err)
			}
		})
	}
}

func TestSchemaOnlyOptionalAbsenceAllowed(t *testing.T) {
	logs := testpdata.CanonicalLogsWithoutOptional()
	if _, err := normalizeTestRecord(logs); err != nil {
		t.Fatalf("optional absence rejected: %v", err)
	}
}
