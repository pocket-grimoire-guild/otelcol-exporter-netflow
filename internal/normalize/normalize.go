package normalize

import (
	"math"
	"strings"
	"unicode/utf8"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// requiredFields is the receiver's 39 mandatory R keys in canonical wire
// order. The two omitted fields are the only optional keys in this profile.
var requiredFields = [...]wire.CanonicalField{
	wire.FieldSourceAddress,
	wire.FieldSourcePort,
	wire.FieldDestinationAddress,
	wire.FieldDestinationPort,
	wire.FieldNetworkTransport,
	wire.FieldNetworkType,
	wire.FieldFlowIOBytes,
	wire.FieldFlowIOPackets,
	wire.FieldFlowType,
	wire.FieldFlowSequenceNum,
	wire.FieldFlowTimeReceived,
	wire.FieldFlowStart,
	wire.FieldFlowEnd,
	wire.FieldFlowSamplingRate,
	wire.FieldFlowSamplerAddress,
	wire.FieldFlowTCPFlags,
	wire.FieldFlowInIf,
	wire.FieldFlowOutIf,
	wire.FieldFlowIPTOS,
	wire.FieldFlowIPTTL,
	wire.FieldFlowIPFlags,
	wire.FieldFlowFragmentID,
	wire.FieldFlowFragmentOffset,
	wire.FieldFlowIPv6FlowLabel,
	wire.FieldFlowICMPType,
	wire.FieldFlowICMPCode,
	wire.FieldFlowSrcMAC,
	wire.FieldFlowDstMAC,
	wire.FieldFlowSrcVLAN,
	wire.FieldFlowDstVLAN,
	wire.FieldFlowVLANID,
	// FieldFlowNextHop is optional.
	wire.FieldFlowNextHopAS,
	wire.FieldFlowSrcAS,
	wire.FieldFlowDstAS,
	// FieldFlowBGPNextHop is optional.
	wire.FieldFlowSrcNet,
	wire.FieldFlowDstNet,
	wire.FieldFlowForwardingStatus,
	wire.FieldFlowObservationDomainID,
	wire.FieldFlowObservationPointID,
}

var canonicalFieldByName = map[string]wire.CanonicalField{
	"source.address":             wire.FieldSourceAddress,
	"source.port":                wire.FieldSourcePort,
	"destination.address":        wire.FieldDestinationAddress,
	"destination.port":           wire.FieldDestinationPort,
	"network.transport":          wire.FieldNetworkTransport,
	"network.type":               wire.FieldNetworkType,
	"flow.io.bytes":              wire.FieldFlowIOBytes,
	"flow.io.packets":            wire.FieldFlowIOPackets,
	"flow.type":                  wire.FieldFlowType,
	"flow.sequence_num":          wire.FieldFlowSequenceNum,
	"flow.time_received":         wire.FieldFlowTimeReceived,
	"flow.start":                 wire.FieldFlowStart,
	"flow.end":                   wire.FieldFlowEnd,
	"flow.sampling_rate":         wire.FieldFlowSamplingRate,
	"flow.sampler_address":       wire.FieldFlowSamplerAddress,
	"flow.tcp_flags":             wire.FieldFlowTCPFlags,
	"flow.in_if":                 wire.FieldFlowInIf,
	"flow.out_if":                wire.FieldFlowOutIf,
	"flow.ip_tos":                wire.FieldFlowIPTOS,
	"flow.ip_ttl":                wire.FieldFlowIPTTL,
	"flow.ip_flags":              wire.FieldFlowIPFlags,
	"flow.fragment_id":           wire.FieldFlowFragmentID,
	"flow.fragment_offset":       wire.FieldFlowFragmentOffset,
	"flow.ipv6_flow_label":       wire.FieldFlowIPv6FlowLabel,
	"flow.icmp_type":             wire.FieldFlowICMPType,
	"flow.icmp_code":             wire.FieldFlowICMPCode,
	"flow.src_mac":               wire.FieldFlowSrcMAC,
	"flow.dst_mac":               wire.FieldFlowDstMAC,
	"flow.src_vlan":              wire.FieldFlowSrcVLAN,
	"flow.dst_vlan":              wire.FieldFlowDstVLAN,
	"flow.vlan_id":               wire.FieldFlowVLANID,
	"flow.next_hop":              wire.FieldFlowNextHop,
	"flow.next_hop_as":           wire.FieldFlowNextHopAS,
	"flow.src_as":                wire.FieldFlowSrcAS,
	"flow.dst_as":                wire.FieldFlowDstAS,
	"flow.bgp_next_hop":          wire.FieldFlowBGPNextHop,
	"flow.src_net":               wire.FieldFlowSrcNet,
	"flow.dst_net":               wire.FieldFlowDstNet,
	"flow.forwarding_status":     wire.FieldFlowForwardingStatus,
	"flow.observation_domain_id": wire.FieldFlowObservationDomainID,
	"flow.observation_point_id":  wire.FieldFlowObservationPointID,
}

var flowTypes = map[string]struct{}{
	"unknown": {}, "sflow_5": {}, "netflow_v5": {}, "netflow_v9": {}, "ipfix": {},
}

var networkTypes = map[string]struct{}{
	"unknown": {}, "arp": {}, "ipv4": {}, "snmp": {}, "ipv6": {}, "mpls": {},
	"eapol": {}, "lldp": {}, "macsec": {}, "mvrp": {}, "ptp": {}, "6lowpan": {},
}

// The values are copied from the pinned receiver parser vocabulary. Keeping
// the closed set here prevents aliases, case folding, or runtime inference.
var networkTransports = map[string]struct{}{
	"hopopt": {}, "icmp": {}, "igmp": {}, "ggp": {}, "ipv4": {}, "st": {}, "tcp": {}, "udp": {}, "cbt": {},
	"egp": {}, "igp": {}, "bbn-rcc-mon": {}, "nvp-ii": {}, "pup": {}, "argus": {}, "emcon": {}, "xnet": {},
	"chaos": {}, "mux": {}, "dcn-meas": {}, "hmp": {}, "prm": {}, "xns-idp": {}, "trunk-1": {}, "trunk-2": {},
	"leaf-1": {}, "leaf-2": {}, "rdp": {}, "irtp": {}, "iso-tp4": {}, "netblt": {}, "mfe-nsp": {}, "merit-inp": {},
	"dccp": {}, "3pc": {}, "idpr": {}, "xtp": {}, "ddp": {}, "idpr-cmtp": {}, "tp++": {}, "il": {}, "ipv6": {},
	"sdrp": {}, "ipv6-route": {}, "ipv6-frag": {}, "idrp": {}, "rsvp": {}, "gre": {}, "dsr": {}, "bna": {},
	"esp": {}, "ah": {}, "i-nlsp": {}, "swipe": {}, "narp": {}, "min-ipv4": {}, "tlsp": {}, "skip": {},
	"ipv6-icmp": {}, "ipv6-nonxt": {}, "ipv6-opts": {}, "any-host-internal-protocol": {}, "cftp": {}, "any-local-network": {},
	"sat-expak": {}, "kryptolan": {}, "rvd": {}, "ippc": {}, "any-distributed-file-system": {}, "sat-mon": {}, "visa": {},
	"ipcv": {}, "cpnx": {}, "cphb": {}, "wsn": {}, "pvp": {}, "br-sat-mon": {}, "sun-nd": {}, "wb-mon": {},
	"wb-expak": {}, "iso-ip": {}, "vmtp": {}, "secure-vmtp": {}, "vines": {}, "iptm": {}, "nsfnet-igp": {}, "dgp": {},
	"tcf": {}, "eigrp": {}, "ospfigp": {}, "sprite-rpc": {}, "larp": {}, "mtp": {}, "ax.25": {}, "ipip": {},
	"micp": {}, "scc-sp": {}, "etherip": {}, "encap": {}, "any-private-encryption-scheme": {}, "gmtp": {}, "ifmp": {},
	"pnni": {}, "pim": {}, "aris": {}, "scps": {}, "qnx": {}, "a/n": {}, "ipcomp": {}, "snp": {}, "compaq-peer": {},
	"ipx-in-ip": {}, "vrrp": {}, "pgm": {}, "any-0-hop-protocol": {}, "l2tp": {}, "ddx": {}, "iatp": {}, "stp": {},
	"srp": {}, "uti": {}, "smp": {}, "sm": {}, "ptp": {}, "isis over ipv4": {}, "fire": {}, "crtp": {}, "crudp": {},
	"sscopmce": {}, "iplt": {}, "sps": {}, "pipe": {}, "sctp": {}, "fc": {}, "rsvp-e2e-ignore": {}, "mobility header": {},
	"udplite": {}, "mpls-in-ip": {}, "manet": {}, "hip": {}, "shim6": {}, "wesp": {}, "rohc": {}, "ethernet": {}, "aggfrag": {}, "nsh": {},
	"unknown": {},
}

// normalizeRecord converts one record after the containing request has passed
// structural preflight. It is intentionally private so callers cannot bypass
// the request boundary.
func normalizeRecord(record plog.LogRecord) (result wire.NormalizedRecord, err error) {
	defer func() {
		if recover() != nil {
			result = wire.NormalizedRecord{}
			err = ErrMalformed
		}
	}()
	if record.Body().Type() != pcommon.ValueTypeEmpty {
		return wire.NormalizedRecord{}, ErrUnsupportedBody
	}

	var values [wire.CanonicalFieldCount]wire.Value
	var present [wire.CanonicalFieldCount]bool
	var attrErr error
	record.Attributes().Range(func(key string, value pcommon.Value) bool {
		field, selected := canonicalFieldByName[key]
		if !selected || int(field) >= wire.CanonicalFieldCount {
			return true
		}
		converted, err := normalizeValue(field, value)
		if err != nil {
			attrErr = err
			return false
		}
		values[field] = converted
		present[field] = true
		return true
	})
	if attrErr != nil {
		return wire.NormalizedRecord{}, attrErr
	}
	for _, field := range requiredFields {
		if !present[field] {
			return wire.NormalizedRecord{}, ErrMissingRequired
		}
	}

	family := wire.FamilyUnknown
	source := values[wire.FieldSourceAddress]
	if source.Kind() != wire.ValueIP {
		return wire.NormalizedRecord{}, ErrInvalidValue
	}
	if source.IP().Is4() {
		family = wire.FamilyIPv4
	} else if source.IP().Is6() && !source.IP().Is4() {
		family = wire.FamilyIPv6
	} else {
		return wire.NormalizedRecord{}, ErrInvalidValue
	}
	if family == wire.FamilyIPv4 && ((present[wire.FieldFlowSrcNet] && values[wire.FieldFlowSrcNet].Uint() > 32) || (present[wire.FieldFlowDstNet] && values[wire.FieldFlowDstNet].Uint() > 32)) {
		return wire.NormalizedRecord{}, ErrInvalidValue
	}

	var fields [wire.CanonicalFieldCount + 2]wire.FieldValue
	count := 0
	for field := wire.CanonicalField(0); int(field) < wire.CanonicalFieldCount; field++ {
		if !present[field] {
			continue
		}
		fields[count] = wire.FieldValue{Field: field, Value: values[field]}
		count++
	}
	result, err = wire.NewRecord(family, fields[:count])
	if err != nil {
		return wire.NormalizedRecord{}, ErrInvalidValue
	}
	return result, nil
}

// NormalizeEach performs preflight and then synchronously visits each
// normalized record. No output slice or pdata object is retained.
func NormalizeEach(logs plog.Logs, consume func(wire.NormalizedRecord) error) error {
	if consume == nil {
		return ErrInvalidCallback
	}
	stats, err := Inspect(logs)
	if err != nil {
		return err
	}
	if stats.Records == 0 {
		return ErrNoRecords
	}
	return normalizeAdmitted(logs, consume)
}

// NormalizeEachIndexed performs preflight and then synchronously visits each
// normalized source record in resource/scope/log traversal order. Every
// source record receives an ordinal, including records that fail
// normalization. A nil callback result continues traversal; the callback
// receives a zero record and fixed record-local error for a failed record.
func NormalizeEachIndexed(logs plog.Logs, consume func(uint64, wire.NormalizedRecord, error) error) error {
	if consume == nil {
		return ErrInvalidCallback
	}
	stats, err := Inspect(logs)
	if err != nil {
		return err
	}
	if stats.Records == 0 {
		return ErrNoRecords
	}
	return normalizeAdmittedIndexed(logs, consume)
}

// normalizeAdmitted traverses pdata only after Inspect has checked the whole
// request. Callback invocation is deliberately outside any recover boundary so
// consumer panics retain their normal propagation semantics.
func normalizeAdmitted(logs plog.Logs, consume func(wire.NormalizedRecord) error) error {
	return normalizeAdmittedIndexed(logs, func(_ uint64, record wire.NormalizedRecord, recordErr error) error {
		if recordErr != nil {
			return recordErr
		}
		return consume(record)
	})
}

func normalizeAdmittedIndexed(logs plog.Logs, consume func(uint64, wire.NormalizedRecord, error) error) error {
	var ordinal uint64
	resources := logs.ResourceLogs()
	for resourceIndex := 0; resourceIndex < resources.Len(); resourceIndex++ {
		scopes := resources.At(resourceIndex).ScopeLogs()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			records := scopes.At(scopeIndex).LogRecords()
			for recordIndex := 0; recordIndex < records.Len(); recordIndex++ {
				record, recordErr := normalizeRecord(records.At(recordIndex))
				if err := consume(ordinal, record, recordErr); err != nil {
					return err
				}
				ordinal++
			}
		}
	}
	return nil
}

func normalizeValue(field wire.CanonicalField, value pcommon.Value) (wire.Value, error) {
	if value.Type() == pcommon.ValueTypeEmpty {
		return wire.Value{}, ErrInvalidType
	}
	if isStringField(field) {
		if value.Type() != pcommon.ValueTypeStr {
			return wire.Value{}, ErrInvalidType
		}
		// Validate and parse directly from pdata-owned text. Fixed-size parsed
		// values do not retain the source string; clone only a closed-vocabulary
		// value that crosses the adapter boundary.
		text := value.Str()
		if !utf8.ValidString(text) {
			return wire.Value{}, ErrInvalidValue
		}
		switch field {
		case wire.FieldSourceAddress, wire.FieldDestinationAddress, wire.FieldFlowSamplerAddress, wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop:
			parsed, err := wire.ParseIPValue(text)
			if err != nil || parsed.IP().Is4In6() {
				return wire.Value{}, ErrInvalidValue
			}
			return parsed, nil
		case wire.FieldFlowSrcMAC, wire.FieldFlowDstMAC:
			parsed, err := wire.ParseMACValue(text)
			if err != nil {
				return wire.Value{}, ErrInvalidValue
			}
			return parsed, nil
		case wire.FieldNetworkTransport:
			if _, ok := networkTransports[text]; !ok {
				return wire.Value{}, ErrInvalidValue
			}
		case wire.FieldNetworkType:
			if _, ok := networkTypes[text]; !ok {
				return wire.Value{}, ErrInvalidValue
			}
		case wire.FieldFlowType:
			if _, ok := flowTypes[text]; !ok {
				return wire.Value{}, ErrInvalidValue
			}
		}
		return wire.StringValue(strings.Clone(text)), nil
	}
	if value.Type() != pcommon.ValueTypeInt {
		return wire.Value{}, ErrInvalidType
	}
	integer := value.Int()
	if integer < 0 {
		return wire.Value{}, ErrInvalidValue
	}
	unsigned := uint64(integer)
	max := maxForField(field)
	if unsigned > max {
		return wire.Value{}, ErrInvalidValue
	}
	if isTimeField(field) {
		return wire.UnixNanosValue(unsigned), nil
	}
	return wire.UintValue(unsigned), nil
}

func isStringField(field wire.CanonicalField) bool {
	switch field {
	case wire.FieldSourceAddress, wire.FieldDestinationAddress, wire.FieldNetworkTransport, wire.FieldNetworkType, wire.FieldFlowType, wire.FieldFlowSamplerAddress, wire.FieldFlowSrcMAC, wire.FieldFlowDstMAC, wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop:
		return true
	default:
		return false
	}
}

func isTimeField(field wire.CanonicalField) bool {
	return field == wire.FieldFlowTimeReceived || field == wire.FieldFlowStart || field == wire.FieldFlowEnd
}

func maxForField(field wire.CanonicalField) uint64 {
	switch field {
	case wire.FieldSourcePort, wire.FieldDestinationPort:
		return math.MaxUint16
	case wire.FieldFlowSequenceNum, wire.FieldFlowInIf, wire.FieldFlowOutIf, wire.FieldFlowIPFlags, wire.FieldFlowFragmentID, wire.FieldFlowFragmentOffset, wire.FieldFlowForwardingStatus, wire.FieldFlowObservationDomainID, wire.FieldFlowObservationPointID, wire.FieldFlowNextHopAS, wire.FieldFlowSrcAS, wire.FieldFlowDstAS:
		return math.MaxUint32
	case wire.FieldFlowTCPFlags:
		return math.MaxUint16
	case wire.FieldFlowIPTOS, wire.FieldFlowIPTTL, wire.FieldFlowICMPType, wire.FieldFlowICMPCode:
		return math.MaxUint8
	case wire.FieldFlowIPv6FlowLabel:
		return 0xfffff
	case wire.FieldFlowSrcVLAN, wire.FieldFlowDstVLAN, wire.FieldFlowVLANID:
		return 4095
	case wire.FieldFlowTimeReceived, wire.FieldFlowStart, wire.FieldFlowEnd, wire.FieldFlowIOBytes, wire.FieldFlowIOPackets, wire.FieldFlowSamplingRate:
		return math.MaxInt64
	case wire.FieldFlowSrcNet, wire.FieldFlowDstNet:
		return 128
	default:
		return math.MaxInt64
	}
}
