// Package testpdata provides deterministic receiver-shaped pdata inputs for
// normalization tests. It is intentionally not used by production code.
package testpdata

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// CanonicalLogs returns the populated IPv4 receiver profile from the pinned
// fixture authority, including both optional next-hop keys.
func CanonicalLogs() plog.Logs { return buildLogs(false, true) }

// CanonicalIPv4Logs is an explicit IPv4 spelling of CanonicalLogs.
func CanonicalIPv4Logs() plog.Logs { return buildLogs(false, true) }

// CanonicalIPv6Logs returns the same values with the address family changed to
// the canonical documentation IPv6 range.
func CanonicalIPv6Logs() plog.Logs { return buildLogs(true, true) }

// CanonicalLogsWithoutOptional returns a valid record with both optional keys
// absent, preserving the receiver's absent-versus-zero distinction.
func CanonicalLogsWithoutOptional() plog.Logs { return buildLogs(false, false) }

// NewCanonicalLogs is a concise compatibility alias for tests.
func NewCanonicalLogs() plog.Logs { return CanonicalLogs() }

// Canonical and IPv4Logs/IPv6Logs are descriptive aliases used by focused
// package tests.
func Canonical() plog.Logs { return CanonicalLogs() }
func IPv4Logs() plog.Logs  { return CanonicalIPv4Logs() }
func IPv6Logs() plog.Logs  { return CanonicalIPv6Logs() }

func buildLogs(ipv6, optional bool) plog.Logs {
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	scope := resource.ScopeLogs().AppendEmpty()
	scope.Scope().SetName("otelcol/netflowreceiver")
	scope.Scope().Attributes().PutStr("receiver", "netflow")
	record := scope.LogRecords().AppendEmpty()
	attrs := record.Attributes()
	if ipv6 {
		attrs.PutStr("source.address", "2001:db8::1")
		attrs.PutStr("destination.address", "2001:db8::2")
		attrs.PutStr("flow.sampler_address", "2001:db8::fe")
	} else {
		attrs.PutStr("source.address", "192.0.2.1")
		attrs.PutStr("destination.address", "198.51.100.2")
		attrs.PutStr("flow.sampler_address", "192.0.2.254")
	}
	attrs.PutInt("source.port", 12345)
	attrs.PutInt("destination.port", 443)
	attrs.PutStr("network.transport", "tcp")
	if ipv6 {
		attrs.PutStr("network.type", "ipv6")
	} else {
		attrs.PutStr("network.type", "ipv4")
	}
	attrs.PutInt("flow.io.bytes", 56789)
	attrs.PutInt("flow.io.packets", 1234)
	attrs.PutStr("flow.type", "netflow_v9")
	attrs.PutInt("flow.sequence_num", 7)
	attrs.PutInt("flow.time_received", 1788220802000000000)
	attrs.PutInt("flow.start", 1788220801000000000)
	attrs.PutInt("flow.end", 1788220801001000000)
	// The pinned receiver copies these canonical attributes into the record
	// envelope. Normalization still treats the attributes as authoritative.
	record.SetTimestamp(pcommon.Timestamp(1788220801000000000))
	record.SetObservedTimestamp(pcommon.Timestamp(1788220802000000000))
	attrs.PutInt("flow.sampling_rate", 1000)
	attrs.PutInt("flow.tcp_flags", 24)
	attrs.PutInt("flow.in_if", 10)
	attrs.PutInt("flow.out_if", 20)
	attrs.PutInt("flow.ip_tos", 0)
	attrs.PutInt("flow.ip_ttl", 64)
	attrs.PutInt("flow.ip_flags", 0)
	attrs.PutInt("flow.fragment_id", 0)
	attrs.PutInt("flow.fragment_offset", 0)
	attrs.PutInt("flow.ipv6_flow_label", 0)
	attrs.PutInt("flow.icmp_type", 0)
	attrs.PutInt("flow.icmp_code", 0)
	attrs.PutStr("flow.src_mac", "00:11:22:33:44:55")
	attrs.PutStr("flow.dst_mac", "66:77:88:99:aa:bb")
	attrs.PutInt("flow.src_vlan", 100)
	attrs.PutInt("flow.dst_vlan", 200)
	attrs.PutInt("flow.vlan_id", 100)
	if optional {
		if ipv6 {
			attrs.PutStr("flow.next_hop", "2001:db8::fe")
			attrs.PutStr("flow.bgp_next_hop", "2001:db8::3")
		} else {
			attrs.PutStr("flow.next_hop", "192.0.2.254")
			attrs.PutStr("flow.bgp_next_hop", "198.51.100.1")
		}
	}
	attrs.PutInt("flow.next_hop_as", 64512)
	attrs.PutInt("flow.src_as", 64513)
	attrs.PutInt("flow.dst_as", 64514)
	attrs.PutInt("flow.src_net", 24)
	attrs.PutInt("flow.dst_net", 24)
	attrs.PutInt("flow.forwarding_status", 0)
	attrs.PutInt("flow.observation_domain_id", 42)
	attrs.PutInt("flow.observation_point_id", 7)
	return logs
}
