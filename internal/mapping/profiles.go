package mapping

import (
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// The receiver parser has a deliberately closed token vocabulary. Keeping the
// frozen reverse map in source avoids a runtime registry, aliases, and name
// recovery from the canonical `unknown` token.
var protocolNumbers = func() map[string]uint8 {
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
	result := make(map[string]uint8, len(tokens))
	for number, token := range tokens {
		result[token] = uint8(number)
	}
	return result
}()

var networkVersions = map[string]uint8{"ipv4": 4, "ipv6": 6}

func protocolNumber(token string) (uint8, bool) {
	number, ok := protocolNumbers[token]
	return number, ok && token != "unknown"
}

// ProtocolNumber resolves only a token in the pinned receiver vocabulary.
func ProtocolNumber(token string) (uint8, bool) { return protocolNumber(token) }

// NetworkVersion resolves only the two explicit family tokens.
func NetworkVersion(token string) (uint8, bool) {
	version, ok := networkVersions[token]
	return version, ok
}

func validProfile(name string) (wire.Protocol, bool) {
	switch name {
	case ProfileV5:
		return wire.ProtocolV5, true
	case ProfileV9:
		return wire.ProtocolV9, true
	case ProfileV9Timed:
		return wire.ProtocolV9, true
	case ProfileIPFIX:
		return wire.ProtocolIPFIX, true
	case ProfileIPFIXGeneral:
		return wire.ProtocolIPFIX, true
	default:
		return wire.ProtocolUnknown, false
	}
}

func builtinCatalog(protocol wire.Protocol, profile string) wire.Catalog {
	switch protocol {
	case wire.ProtocolV5:
		return wire.BuiltinV5()
	case wire.ProtocolV9:
		if profile == ProfileV9Timed {
			return wire.BuiltinV9Timed()
		}
		return wire.BuiltinV9()
	case wire.ProtocolIPFIX:
		if profile == ProfileIPFIXGeneral {
			return wire.BuiltinIPFIXGeneral()
		}
		return wire.BuiltinIPFIX()
	default:
		return wire.Catalog{}
	}
}

type conversionClass uint8

const (
	classExact conversionClass = iota + 1
	classLossy
	classSynthesized
	classUnsupported
	classInapplicable
)

func (c conversionClass) lossy() bool { return c == classLossy || c == classSynthesized }

// classFor is the compatibility matrix's classification reduced to the
// canonical mapping decisions. Width gates remain runtime checks.
func classFor(protocol wire.Protocol, field wire.CanonicalField, target string) conversionClass {
	switch protocol {
	case wire.ProtocolV5:
		switch field {
		case wire.FieldSourceAddress, wire.FieldSourcePort, wire.FieldDestinationAddress, wire.FieldDestinationPort, wire.FieldFlowNextHop, wire.FieldFlowIOPackets, wire.FieldFlowSrcNet, wire.FieldFlowDstNet, wire.FieldFlowIPTOS:
			return classExact
		case wire.FieldFlowIOBytes, wire.FieldFlowInIf, wire.FieldFlowOutIf, wire.FieldFlowStart, wire.FieldFlowEnd, wire.FieldFlowTCPFlags, wire.FieldFlowSrcAS, wire.FieldFlowDstAS:
			return classLossy
		case wire.FieldNetworkTransport:
			return classSynthesized
		case wire.FieldFlowSamplingRate:
			return classSynthesized
		case wire.FieldFlowSamplerAddress, wire.FieldFlowNextHopAS:
			return classUnsupported
		default:
			return classInapplicable
		}
	case wire.ProtocolV9:
		switch field {
		case wire.FieldSourceAddress, wire.FieldSourcePort, wire.FieldDestinationAddress, wire.FieldDestinationPort, wire.FieldFlowIOBytes, wire.FieldFlowIOPackets, wire.FieldNetworkTransport, wire.FieldFlowIPTOS, wire.FieldFlowTCPFlags, wire.FieldFlowInIf, wire.FieldFlowOutIf, wire.FieldFlowSrcAS, wire.FieldFlowDstAS, wire.FieldFlowSamplingRate, wire.FieldFlowIPTTL, wire.FieldNetworkType, wire.FieldFlowSrcNet, wire.FieldFlowDstNet, wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop, wire.FieldFlowSrcMAC, wire.FieldFlowDstMAC, wire.FieldFlowSrcVLAN, wire.FieldFlowDstVLAN, wire.FieldFlowFragmentID, wire.FieldFlowFragmentOffset, wire.FieldFlowIPv6FlowLabel:
			if field == wire.FieldFlowIOBytes || field == wire.FieldFlowIOPackets || field == wire.FieldFlowTCPFlags || field == wire.FieldFlowInIf || field == wire.FieldFlowOutIf {
				return classLossy
			}
			if field == wire.FieldNetworkTransport {
				return classSynthesized
			}
			if field == wire.FieldNetworkType {
				return classSynthesized
			}
			return classExact
		case wire.FieldFlowStart, wire.FieldFlowEnd, wire.FieldFlowICMPTypeCode:
			return classSynthesized
		case wire.FieldFlowForwardingStatus, wire.FieldFlowVLANID:
			return classLossy
		case wire.FieldFlowTimeReceived, wire.FieldFlowIPFlags, wire.FieldFlowType, wire.FieldFlowSequenceNum, wire.FieldFlowObservationDomainID, wire.FieldFlowObservationPointID:
			return classInapplicable
		case wire.FieldFlowSamplerAddress, wire.FieldFlowNextHopAS, wire.FieldFlowICMPType, wire.FieldFlowICMPCode:
			return classUnsupported
		default:
			return classUnsupported
		}
	case wire.ProtocolIPFIX:
		switch field {
		case wire.FieldSourceAddress, wire.FieldSourcePort, wire.FieldDestinationAddress, wire.FieldDestinationPort, wire.FieldFlowIOBytes, wire.FieldFlowIOPackets, wire.FieldFlowIPTOS, wire.FieldFlowTCPFlags, wire.FieldFlowInIf, wire.FieldFlowOutIf, wire.FieldFlowSrcAS, wire.FieldFlowDstAS, wire.FieldFlowSamplingRate, wire.FieldFlowIPTTL, wire.FieldFlowFragmentID, wire.FieldFlowFragmentOffset, wire.FieldFlowIPv6FlowLabel, wire.FieldFlowICMPType, wire.FieldFlowICMPCode, wire.FieldFlowSrcVLAN, wire.FieldFlowDstVLAN, wire.FieldFlowVLANID, wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop, wire.FieldFlowSrcNet, wire.FieldFlowDstNet:
			if field == wire.FieldFlowIOBytes || field == wire.FieldFlowIOPackets || field == wire.FieldFlowSrcMAC || field == wire.FieldFlowDstMAC {
				return classLossy
			}
			return classExact
		case wire.FieldNetworkTransport, wire.FieldNetworkType, wire.FieldFlowTimeReceived, wire.FieldFlowIPFlags:
			return classSynthesized
		case wire.FieldFlowSrcMAC, wire.FieldFlowDstMAC, wire.FieldFlowForwardingStatus, wire.FieldFlowObservationPointID, wire.FieldFlowStart, wire.FieldFlowEnd:
			return classLossy
		case wire.FieldFlowType, wire.FieldFlowSequenceNum, wire.FieldFlowObservationDomainID:
			return classInapplicable
		case wire.FieldFlowSamplerAddress, wire.FieldFlowNextHopAS:
			return classUnsupported
		default:
			return classUnsupported
		}
	default:
		return classUnsupported
	}
}

func isAmbiguous(protocol wire.Protocol, field wire.CanonicalField) bool {
	if protocol == wire.ProtocolV9 {
		return field == wire.FieldFlowIOBytes || field == wire.FieldFlowIOPackets
	}
	if protocol == wire.ProtocolIPFIX {
		return field == wire.FieldFlowIOBytes || field == wire.FieldFlowIOPackets || field == wire.FieldNetworkType || field == wire.FieldFlowTimeReceived || field == wire.FieldFlowSrcMAC || field == wire.FieldFlowDstMAC
	}
	return false
}

func allowedTarget(protocol wire.Protocol, field wire.CanonicalField, target string) bool {
	switch protocol {
	case wire.ProtocolV9:
		return (field == wire.FieldFlowIOBytes && (target == "in_bytes" || target == "out_bytes")) || (field == wire.FieldFlowIOPackets && (target == "in_packets" || target == "out_packets"))
	case wire.ProtocolIPFIX:
		switch field {
		case wire.FieldFlowIOBytes:
			return target == "octet_delta_count" || target == "post_octet_delta_count"
		case wire.FieldFlowIOPackets:
			return target == "packet_delta_count" || target == "post_packet_delta_count"
		case wire.FieldNetworkType:
			return target == "ip_version"
		case wire.FieldFlowTimeReceived:
			return target == "observation_time_nanoseconds"
		case wire.FieldFlowStart:
			return target == "flow_start_milliseconds"
		case wire.FieldFlowEnd:
			return target == "flow_end_milliseconds"
		case wire.FieldFlowSrcMAC:
			return target == "source_mac_address" || target == "post_source_mac_address"
		case wire.FieldFlowDstMAC:
			return target == "destination_mac_address" || target == "post_destination_mac_address"
		}
	}
	return false
}

func familySupport(protocol wire.Protocol, field wire.CanonicalField) (bool, bool, bool) {
	// Returns IPv4 support, IPv6 support, and whether the descriptor is
	// family-dependent when both are supported.
	switch field {
	case wire.FieldSourceAddress, wire.FieldDestinationAddress, wire.FieldFlowNextHop, wire.FieldFlowBGPNextHop, wire.FieldFlowSrcNet, wire.FieldFlowDstNet:
		if protocol == wire.ProtocolV5 {
			return true, false, false
		}
		return true, true, true
	case wire.FieldFlowFragmentID:
		if protocol == wire.ProtocolV9 {
			return true, false, false
		}
		return true, true, false
	case wire.FieldFlowIPv6FlowLabel:
		if protocol == wire.ProtocolV5 {
			return false, false, false
		}
		return false, true, false
	case wire.FieldFlowICMPTypeCode:
		return protocol == wire.ProtocolV9, false, false
	case wire.FieldFlowICMPType, wire.FieldFlowICMPCode:
		if protocol == wire.ProtocolV9 {
			return false, false, false
		}
		return true, true, true
	default:
		return true, true, false
	}
}

func descriptorFor(protocol wire.Protocol, field wire.CanonicalField, target string, family wire.Family) (wire.FieldDescriptor, error) {
	d := wire.FieldDescriptor{Protocol: protocol, Field: field, Encoding: wire.EncodingUnspecified}
	v4 := family == wire.FamilyIPv4
	if family != wire.FamilyIPv4 && family != wire.FamilyIPv6 {
		return d, wire.ErrInvalidFamily
	}
	switch protocol {
	case wire.ProtocolV5:
		d.ID = v5ID(field)
		d.Length, d.Encoding = v5LengthEncoding(field)
	case wire.ProtocolV9:
		d.ID, d.Length, d.Encoding = v9Identity(field, target, v4)
	case wire.ProtocolIPFIX:
		d.ID, d.Length, d.Encoding, d.Enterprise = ipfixIdentity(field, target, v4)
	default:
		return d, wire.ErrInvalidProtocol
	}
	if d.ID == 0 || d.Encoding == wire.EncodingUnspecified {
		return d, wire.ErrInvalidDescriptor
	}
	return d, d.Validate()
}

func v5ID(field wire.CanonicalField) uint16 {
	switch field {
	case wire.FieldSourceAddress:
		return 1
	case wire.FieldDestinationAddress:
		return 2
	case wire.FieldFlowNextHop:
		return 3
	case wire.FieldFlowInIf:
		return 4
	case wire.FieldFlowOutIf:
		return 5
	case wire.FieldFlowIOPackets:
		return 6
	case wire.FieldFlowIOBytes:
		return 7
	case wire.FieldFlowStart:
		return 8
	case wire.FieldFlowEnd:
		return 9
	case wire.FieldSourcePort:
		return 10
	case wire.FieldDestinationPort:
		return 11
	case wire.FieldFlowTCPFlags:
		return 13
	case wire.FieldNetworkTransport:
		return 14
	case wire.FieldFlowIPTOS:
		return 15
	case wire.FieldFlowSrcAS:
		return 16
	case wire.FieldFlowDstAS:
		return 17
	case wire.FieldFlowSrcNet:
		return 18
	case wire.FieldFlowDstNet:
		return 19
	default:
		return 0
	}
}

func v5LengthEncoding(field wire.CanonicalField) (uint16, wire.DescriptorEncoding) {
	switch field {
	case wire.FieldSourceAddress, wire.FieldDestinationAddress, wire.FieldFlowNextHop:
		return 4, wire.EncodingIPv4Address
	case wire.FieldFlowInIf, wire.FieldFlowOutIf, wire.FieldSourcePort, wire.FieldDestinationPort, wire.FieldFlowSrcAS, wire.FieldFlowDstAS:
		return 2, wire.EncodingUnsigned16
	case wire.FieldFlowIOPackets, wire.FieldFlowIOBytes, wire.FieldFlowStart, wire.FieldFlowEnd:
		return 4, wire.EncodingUnsigned32
	case wire.FieldFlowTCPFlags, wire.FieldNetworkTransport, wire.FieldFlowIPTOS, wire.FieldFlowSrcNet, wire.FieldFlowDstNet:
		return 1, wire.EncodingUnsigned8
	default:
		return 0, wire.EncodingUnspecified
	}
}

func v9Identity(field wire.CanonicalField, target string, ipv4 bool) (uint16, uint16, wire.DescriptorEncoding) {
	address := func(v4, v6 uint16) uint16 {
		if ipv4 {
			return v4
		}
		return v6
	}
	switch field {
	case wire.FieldFlowIOBytes:
		if target == "out_bytes" {
			return 23, 4, wire.EncodingUnsigned32
		}
		return 1, 4, wire.EncodingUnsigned32
	case wire.FieldFlowIOPackets:
		if target == "out_packets" {
			return 24, 4, wire.EncodingUnsigned32
		}
		return 2, 4, wire.EncodingUnsigned32
	case wire.FieldNetworkTransport:
		return 4, 1, wire.EncodingUnsigned8
	case wire.FieldFlowIPTOS:
		return 5, 1, wire.EncodingUnsigned8
	case wire.FieldFlowTCPFlags:
		return 6, 1, wire.EncodingUnsigned8
	case wire.FieldSourcePort:
		return 7, 2, wire.EncodingUnsigned16
	case wire.FieldSourceAddress:
		return address(8, 27), func() uint16 {
			if ipv4 {
				return 4
			}
			return 16
		}(), mapAddressEncoding(ipv4)
	case wire.FieldFlowSrcNet:
		return address(9, 29), 1, wire.EncodingUnsigned8
	case wire.FieldFlowInIf:
		return 10, 2, wire.EncodingUnsigned16
	case wire.FieldDestinationPort:
		return 11, 2, wire.EncodingUnsigned16
	case wire.FieldDestinationAddress:
		return address(12, 28), func() uint16 {
			if ipv4 {
				return 4
			}
			return 16
		}(), mapAddressEncoding(ipv4)
	case wire.FieldFlowDstNet:
		return address(13, 30), 1, wire.EncodingUnsigned8
	case wire.FieldFlowOutIf:
		return 14, 2, wire.EncodingUnsigned16
	case wire.FieldFlowSrcAS:
		return 16, 4, wire.EncodingUnsigned32
	case wire.FieldFlowDstAS:
		return 17, 4, wire.EncodingUnsigned32
	case wire.FieldFlowNextHop:
		return address(15, 62), func() uint16 {
			if ipv4 {
				return 4
			}
			return 16
		}(), mapAddressEncoding(ipv4)
	case wire.FieldFlowBGPNextHop:
		return address(18, 63), func() uint16 {
			if ipv4 {
				return 4
			}
			return 16
		}(), mapAddressEncoding(ipv4)
	case wire.FieldFlowEnd:
		return 21, 4, wire.EncodingUnsigned32
	case wire.FieldFlowStart:
		return 22, 4, wire.EncodingUnsigned32
	case wire.FieldFlowSamplingRate:
		return 34, 4, wire.EncodingUnsigned32
	case wire.FieldFlowIPTTL:
		return 52, 1, wire.EncodingUnsigned8
	case wire.FieldFlowFragmentID:
		return 54, 4, wire.EncodingUnsigned32
	case wire.FieldFlowSrcMAC:
		return 56, 6, wire.EncodingMACAddress
	case wire.FieldFlowDstMAC:
		return 57, 6, wire.EncodingMACAddress
	case wire.FieldFlowVLANID, wire.FieldFlowSrcVLAN:
		return 58, 2, wire.EncodingUnsigned16
	case wire.FieldFlowDstVLAN:
		return 59, 2, wire.EncodingUnsigned16
	case wire.FieldNetworkType:
		return 60, 1, wire.EncodingUnsigned8
	case wire.FieldFlowFragmentOffset:
		return 88, 2, wire.EncodingUnsigned16
	case wire.FieldFlowForwardingStatus:
		return 89, 1, wire.EncodingUnsigned8
	case wire.FieldFlowIPv6FlowLabel:
		// RFC 3954 assigns a three-octet field to the 20-bit label. The
		// shared descriptor contract has no reduced-size unsigned encoding;
		// the mapper supplies the fixed three-octet representation explicitly.
		return 31, 3, wire.EncodingOctetArray
	case wire.FieldFlowICMPTypeCode:
		return 32, 2, wire.EncodingUnsigned16
	default:
		return 0, 0, wire.EncodingUnspecified
	}
}

func mapAddressEncoding(ipv4 bool) wire.DescriptorEncoding {
	if ipv4 {
		return wire.EncodingIPv4Address
	}
	return wire.EncodingIPv6Address
}

func ipfixIdentity(field wire.CanonicalField, target string, ipv4 bool) (uint16, uint16, wire.DescriptorEncoding, bool) {
	address := func(v4, v6 uint16) uint16 {
		if ipv4 {
			return v4
		}
		return v6
	}
	width := func(v4, v6 uint16) uint16 {
		if ipv4 {
			return v4
		}
		return v6
	}
	switch field {
	case wire.FieldFlowIOBytes:
		if target == "post_octet_delta_count" {
			return 23, 8, wire.EncodingUnsigned64, false
		}
		return 1, 8, wire.EncodingUnsigned64, false
	case wire.FieldFlowIOPackets:
		if target == "post_packet_delta_count" {
			return 24, 8, wire.EncodingUnsigned64, false
		}
		return 2, 8, wire.EncodingUnsigned64, false
	case wire.FieldNetworkTransport:
		return 4, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowIPTOS:
		return 5, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowTCPFlags:
		return 6, 2, wire.EncodingUnsigned16, false
	case wire.FieldSourcePort:
		return 7, 2, wire.EncodingUnsigned16, false
	case wire.FieldSourceAddress:
		return address(8, 27), width(4, 16), mapAddressEncoding(ipv4), false
	case wire.FieldFlowSrcNet:
		return address(9, 29), 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowInIf:
		return 10, 4, wire.EncodingUnsigned32, false
	case wire.FieldDestinationPort:
		return 11, 2, wire.EncodingUnsigned16, false
	case wire.FieldDestinationAddress:
		return address(12, 28), width(4, 16), mapAddressEncoding(ipv4), false
	case wire.FieldFlowDstNet:
		return address(13, 30), 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowOutIf:
		return 14, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowSrcAS:
		return 16, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowDstAS:
		return 17, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowNextHop:
		return address(15, 62), width(4, 16), mapAddressEncoding(ipv4), false
	case wire.FieldFlowBGPNextHop:
		return address(18, 63), width(4, 16), mapAddressEncoding(ipv4), false
	case wire.FieldFlowIPv6FlowLabel:
		return 31, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowSamplingRate:
		return 34, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowIPTTL:
		return 52, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowFragmentID:
		return 54, 4, wire.EncodingUnsigned32, false
	case wire.FieldFlowSrcMAC:
		if target == "post_source_mac_address" {
			return 81, 6, wire.EncodingMACAddress, false
		}
		return 56, 6, wire.EncodingMACAddress, false
	case wire.FieldFlowDstMAC:
		if target == "destination_mac_address" {
			return 80, 6, wire.EncodingMACAddress, false
		}
		return 57, 6, wire.EncodingMACAddress, false
	case wire.FieldFlowSrcVLAN, wire.FieldFlowVLANID:
		return 58, 2, wire.EncodingUnsigned16, false
	case wire.FieldFlowDstVLAN:
		return 59, 2, wire.EncodingUnsigned16, false
	case wire.FieldNetworkType:
		return 60, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowTimeReceived:
		return 325, 8, wire.EncodingDateTimeNanoseconds, false
	case wire.FieldFlowStart:
		if target == "flow_start_milliseconds" {
			return 152, 8, wire.EncodingDateTimeMilliseconds, false
		}
		return 156, 8, wire.EncodingDateTimeNanoseconds, false
	case wire.FieldFlowEnd:
		if target == "flow_end_milliseconds" {
			return 153, 8, wire.EncodingDateTimeMilliseconds, false
		}
		return 157, 8, wire.EncodingDateTimeNanoseconds, false
	case wire.FieldFlowIPFlags:
		return 197, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowFragmentOffset:
		return 88, 2, wire.EncodingUnsigned16, false
	case wire.FieldFlowICMPType:
		if ipv4 {
			return 176, 1, wire.EncodingUnsigned8, false
		}
		return 178, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowICMPCode:
		if ipv4 {
			return 177, 1, wire.EncodingUnsigned8, false
		}
		return 179, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowForwardingStatus:
		return 89, 1, wire.EncodingUnsigned8, false
	case wire.FieldFlowObservationPointID:
		return 138, 8, wire.EncodingUnsigned64, false
	default:
		return 0, 0, wire.EncodingUnspecified, false
	}
}

func encodingFromName(name string) (wire.DescriptorEncoding, bool) {
	switch name {
	case "unsigned8":
		return wire.EncodingUnsigned8, true
	case "unsigned16":
		return wire.EncodingUnsigned16, true
	case "unsigned32":
		return wire.EncodingUnsigned32, true
	case "unsigned64":
		return wire.EncodingUnsigned64, true
	case "signed8":
		return wire.EncodingSigned8, true
	case "signed16":
		return wire.EncodingSigned16, true
	case "signed32":
		return wire.EncodingSigned32, true
	case "signed64":
		return wire.EncodingSigned64, true
	case "ipv4_address":
		return wire.EncodingIPv4Address, true
	case "ipv6_address":
		return wire.EncodingIPv6Address, true
	case "mac_address":
		return wire.EncodingMACAddress, true
	case "octet_array":
		return wire.EncodingOctetArray, true
	case "string":
		return wire.EncodingString, true
	default:
		return wire.EncodingUnspecified, false
	}
}

func naturalLength(encoding wire.DescriptorEncoding) uint16 {
	switch encoding {
	case wire.EncodingUnsigned8, wire.EncodingSigned8:
		return 1
	case wire.EncodingUnsigned16, wire.EncodingSigned16:
		return 2
	case wire.EncodingUnsigned32, wire.EncodingSigned32:
		return 4
	case wire.EncodingUnsigned64, wire.EncodingSigned64:
		return 8
	case wire.EncodingIPv4Address:
		return 4
	case wire.EncodingIPv6Address:
		return 16
	case wire.EncodingMACAddress:
		return 6
	default:
		return 0
	}
}

func maxUintForEncoding(encoding wire.DescriptorEncoding) uint64 {
	switch encoding {
	case wire.EncodingUnsigned8:
		return math.MaxUint8
	case wire.EncodingUnsigned16:
		return math.MaxUint16
	case wire.EncodingUnsigned32:
		return math.MaxUint32
	case wire.EncodingUnsigned64:
		return math.MaxUint64
	default:
		return 0
	}
}
