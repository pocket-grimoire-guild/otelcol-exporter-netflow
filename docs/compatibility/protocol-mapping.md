# Receiver-to-protocol conversion matrix

Status: bounded mapping policy (2026-09-02). The input is the
immutable `contrib-netflowreceiver-v0.160.0` profile in
[`receiver-attributes.md`](receiver-attributes.md).  The table below contains
each of its 41 canonical attributes exactly once.  It does not define an
encoder implementation or configuration field names.

## Classification vocabulary

* **exact** means the value and the field semantics are representable at the
  stated length.  A width gate may reject values outside that range.
* **lossy** means an otherwise encodable value loses precision, width, or a
  source distinction.  A value that cannot be represented is rejected rather
  than clamped or truncated.
* **synthesized** means the target value is deliberately derived from one or
  more canonical values (for example, the v9 combined ICMP field).
* **unsupported** means there is no safe field/semantic match in the target
  protocol.  **inapplicable** means the protocol has no per-record field (or
  fixes the value in its format/header).  Parenthetical qualifiers identify
  the condition or loss; classifications can be combined.

The protocol authorities are Cisco's v5 format tables
([header B-3](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006108),
[record B-4](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006186)),
RFC 3954 §§5.1 and 8 (including verified errata 2096, 2168, and 2979),
RFC 7011 §§3.1 and 6.1 (including verified errata 4396 and 7875),
RFC 7012 §§3.1 and 7 (including verified erratum 3881), and the
[IANA IPFIX registry](https://www.iana.org/assignments/ipfix) (last updated
2026-07-22; IDs, names, types, and maximum lengths below are from the
[current CSV](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv)).
NetFlow v9 IDs 52, 54, and 89 are the registered NFv9-compatible extensions;
their original absence from RFC 3954's table is intentional and not a claim
that they are historical RFC fields.

## Canonical attribute matrix

| Canonical attribute | NetFlow v5 | NetFlow v9 | IPFIX |
| --- | --- | --- | --- |
| `source.address` | **exact** `srcaddr`, 4 B; IPv4 only. IPv6 is a family-mismatch rejection. | **exact** `IPV4_SRC_ADDR` (8), 4 B or `IPV6_SRC_ADDR` (27), 16 B; select from the parsed address family. | **exact** `sourceIPv4Address` (8), 4 B or `sourceIPv6Address` (27), 16 B; select from the parsed address family. |
| `source.port` | **exact** `srcport`, 2 B; 0..65535 only. | **exact** `L4_SRC_PORT` (7), 2 B; 0..65535. | **exact** `sourceTransportPort` (7), unsigned16, 2 B; 0..65535. |
| `destination.address` | **exact** `dstaddr`, 4 B; IPv4 only. IPv6 is a family-mismatch rejection. | **exact** `IPV4_DST_ADDR` (12), 4 B or `IPV6_DST_ADDR` (28), 16 B; select from the parsed address family. | **exact** `destinationIPv4Address` (12), 4 B or `destinationIPv6Address` (28), 16 B; select from the parsed address family. |
| `destination.port` | **exact** `dstport`, 2 B; 0..65535 only. | **exact** `L4_DST_PORT` (11), 2 B; 0..65535. | **exact** `destinationTransportPort` (11), unsigned16, 2 B; 0..65535. |
| `network.transport` | **synthesized** `prot`, 1 B, only through an explicit configured token-to-IANA-number map; `unknown` or an absent map is unsupported (never infer a number). | **synthesized** `PROTOCOL` (4), 1 B under the same explicit map; parser names with no numeric identity are otherwise unsupported. | **synthesized** `protocolIdentifier` (4), unsigned8, 1 B under the same explicit map; no silent name/number recovery. |
| `network.type` | **inapplicable**: v5 records are fixed IPv4. A non-IPv4 address/family is rejected; the EtherType token is not copied. | **synthesized** `IP_PROTOCOL_VERSION` (60), 1 B only for an explicit `ipv4`→4 or `ipv6`→6 map. Other EtherTypes and `unknown` are unsupported. | **synthesized/unsupported** `ethernetType` (256), unsigned16, 2 B requires retained numeric L2 EtherType provenance; a lookup token alone is insufficient. When only an explicit IPv4/IPv6 family map is retained, use IE `ipVersion` (60), 1 B instead; never guess an EtherType. `unknown` is unsupported. |
| `flow.io.bytes` | **lossy/unsupported (layer semantics; width-gated)** `dOctets`, 4 B; values above `2^32-1` reject. Cisco defines this as Layer-3 octets, but the canonical receiver value can originate from frame/data-link or direction-specific fields; without retained L3 provenance a required L3-only conversion is unsupported. | **lossy (direction/layer semantics unknown; width-gated)** a static template must choose `IN_BYTES` (1) or `OUT_BYTES` (23), each template length 4 B by RFC default; defaulting to IN_BYTES is explicit policy, not inference. Values above `2^32-1` reject; receiver IN/OUT overwrite and frame-vs-L3 meaning are canonical-source loss. | **lossy (direction/layer semantics unknown)** a static template must choose `octetDeltaCount` (1) or `postOctetDeltaCount` (23), unsigned64, 8 B; defaulting to octetDeltaCount is explicit policy. Receiver direction/overwrite and frame-vs-L3 meaning remain source loss. |
| `flow.io.packets` | **exact (width-gated)** `dPkts`, 4 B; values above `2^32-1` reject. | **lossy (direction unknown; width-gated)** a static template must choose `IN_PKTS` (2) or `OUT_PKTS` (24), each template length 4 B by RFC default; defaulting to IN_PKTS is explicit policy. Values above `2^32-1` reject; receiver IN/OUT overwrite remains source loss. | **lossy (direction unknown)** a static template must choose `packetDeltaCount` (2) or `postPacketDeltaCount` (24), unsigned64, 8 B; defaulting to packetDeltaCount is explicit policy. Source direction/overwrite ambiguity remains. |
| `flow.type` | **inapplicable**: v5 header `version`, 2 B, is selected by the destination, never inferred from this token. | **inapplicable**: v9 header `Version`, 2 B, is selected by the destination, never inferred from this token. | **inapplicable**: IPFIX header `Version`, 2 B (value 10), is selected by the destination, never inferred from this token. |
| `flow.sequence_num` | **inapplicable (header state)**: v5 header `flow_sequence`, 4 B, is maintained per destination and is never copied from the incoming record. | **inapplicable (header state)**: v9 header `Sequence Number`, 4 B, is maintained per destination and is never copied from the incoming record. | **inapplicable (header state)**: IPFIX header `Sequence Number`, 4 B, is maintained per stream/destination and is never copied from the incoming record. |
| `flow.time_received` | **inapplicable**: no per-record receive-time field; v5 header `unix_secs` (4 B)/`unix_nsecs` (4 B) is exporter send time, not this value. | **inapplicable**: no per-record receive-time field; v9 header UNIX time (`UNIX Secs`, 4 B) is exporter send time. | **unsupported by default**: this is receiver-ingest time, not an observation-point time. An explicit opt-in may **synthesize** `observationTimeNanoseconds` (325), dateTimeNanoseconds, 8 B as a documented semantic substitution, with NTP quantization and 1900..2036 era rejection; do not silently substitute it. |
| `flow.start` | **lossy/synthesized (explicit origin)** v5 `First`, 4 B: with trusted, stable configured `uptime_origin` (UTC ns), encode `(flow.start - uptime_origin) / 1,000,000` elapsed milliseconds. Require `flow.start >= uptime_origin`, exact 1-ms alignment (non-aligned rejects), `flow.start <= flow.end`, elapsed <= `uint32`, no uptime rollover, and the packet-time inequality `0 <= First <= Last <= header_sysUpTime <= uint32 max` at construction. Without the origin, the fixed First field is unsupported and the record rejects; never infer boot time. | **lossy/synthesized (explicit origin)** `FIRST_SWITCHED` (22), 4 B: use the same UTC-ns-to-integer-ms calculation, ordering/alignment/range/no-rollover checks, stable `uptime_origin`, and (when fields 21/22 are selected) `0 <= FIRST_SWITCHED <= LAST_SWITCHED <= header_sysUpTime <= uint32 max` at packet construction. Without origin the chosen template must omit fields 21/22; a shape requiring them is unsupported. | **lossy (timestamp precision/range)** `flowStartMilliseconds` (152), dateTimeMilliseconds, 8 B in general-v1 or explicit `flow_start_milliseconds`: floor canonical ns / 1,000,000 after original ordering validation. Legacy core-v1 and target-less explicit mapping retain `flowStartNanoseconds` (156), dateTimeNanoseconds, 8 B with NTP quantization and the 2036 era gate. |
| `flow.end` | **lossy/synthesized (explicit origin)** v5 `Last`, 4 B: with the same trusted stable `uptime_origin`, encode `(flow.end - uptime_origin) / 1,000,000` elapsed milliseconds. Require `flow.end >= uptime_origin`, exact 1-ms alignment (non-aligned rejects), `flow.start <= flow.end`, elapsed <= `uint32`, no uptime rollover, and the packet-time inequality `0 <= First <= Last <= header_sysUpTime <= uint32 max` at construction. Without origin, the fixed Last field is unsupported and the record rejects; never infer boot time. | **lossy/synthesized (explicit origin)** `LAST_SWITCHED` (21), 4 B: use the same UTC-ns-to-integer-ms calculation, ordering/alignment/range/no-rollover checks, stable `uptime_origin`, and (when fields 21/22 are selected) `0 <= FIRST_SWITCHED <= LAST_SWITCHED <= header_sysUpTime <= uint32 max` at packet construction. Without origin the chosen template must omit fields 21/22; a shape requiring them is unsupported. | **lossy (timestamp precision/range)** `flowEndMilliseconds` (153), dateTimeMilliseconds, 8 B in general-v1 or explicit `flow_end_milliseconds`: floor canonical ns / 1,000,000 after original ordering validation. Legacy core-v1 and target-less explicit mapping retain `flowEndNanoseconds` (157), dateTimeNanoseconds, 8 B with NTP quantization and the 2036 era gate. |
| `flow.sampling_rate` | **lossy/synthesized (header-level)** v5 `sampling_interval`, 2 B: mode in the top two bits and a 14-bit interval. One common value is required for every record in a packet; differing values, values above 16383, or an unavailable mode reject that packet. Zero is preserved. | **exact (width-gated)** `SAMPLING_INTERVAL` (34), 4 B; per-record values 0..`2^32-1`; larger values reject. | **exact (deprecated IE; width-gated)** `samplingInterval` (34), unsigned32, 4 B; larger values reject. IE 34 is deprecated; do not silently substitute `samplingPacketInterval` (305). |
| `flow.sampler_address` | **unsupported**: v5 has no sampler-address field; do not substitute source IP or exporter identity. | **unsupported**: v9 has no sampler-address field; `FLOW_SAMPLER_ID` (48) is not an address. | **unsupported**: no sampler-address IE; `exporterIPv4Address`/`exporterIPv6Address` identify the exporter, not the sampler. |
| `flow.tcp_flags` | **lossy (width-gated)** `tcp_flags`, 1 B; values above 255 reject (no truncation). | **lossy (width-gated)** `TCP_FLAGS` (6), 1 B; values above 255 reject. | **exact (width-gated)** `tcpControlBits` (6), unsigned16, 2 B; values above 65535 reject. |
| `flow.in_if` | **lossy (width-gated)** `input`, 2 B; values above 65535 reject. | **lossy (width-gated)** `INPUT_SNMP` (10), template length 2 B (RFC default); values above 65535 reject. | **exact** `ingressInterface` (10), unsigned32, 4 B. |
| `flow.out_if` | **lossy (width-gated)** `output`, 2 B; values above 65535 reject. | **lossy (width-gated)** `OUTPUT_SNMP` (14), template length 2 B (RFC default); values above 65535 reject. | **exact** `egressInterface` (14), unsigned32, 4 B. |
| `flow.ip_tos` | **exact** `tos`, 1 B; 0..255. | **exact** `SRC_TOS` (5), 1 B; 0..255. | **exact** `ipClassOfService` (5), unsigned8, 1 B; 0..255. |
| `flow.ip_ttl` | **inapplicable**: no v5 record field. | **exact** registered NFv9 `MIN_TTL` (52), 1 B; 0..255, with zero preserved as the receiver sentinel. | **exact** `minimumTTL` (52), unsigned8, 1 B; 0..255, with zero preserved. |
| `flow.ip_flags` | **inapplicable**: no v5 record field. | **inapplicable**: RFC 3954/v9 has no standard IP-fragment-flags field. | **lossy/synthesized (IPFIX-origin only)** `fragmentFlags` (197), unsigned8, 1 B. Require explicit input provenance `flow.type=ipfix` and canonical values 0..3 for source IPv4 or 0..1 for source IPv6, then invert the pinned decoder's shift with `wire = v << 5`. IANA IE197 requires the reserved flag to be zero for both families and DF to be zero for IPv6; invalid values reject without masking or truncation. Valid IPv4 values 0/1/2/3 encode as `0x00`/`0x20`/`0x40`/`0x60`; IPv6 0/1 encode as `0x00`/`0x20`. Packet-derived NetFlow/sFlow bits have origin-specific layouts and no generic inverse, so they remain unsupported. The decoder-discarded don't-care bits cannot be restored. |
| `flow.fragment_id` | **inapplicable**: no v5 record field. | **exact (IPv4 only)** `IPV4_IDENT` (54), 4 B; an IPv6 family mismatch rejects a required conversion. | **exact** `fragmentIdentification` (54), unsigned32, 4 B; applies to IPv4 or IPv6, with zero retained. |
| `flow.fragment_offset` | **inapplicable**: no v5 record field. | **exact (range-gated)** `FRAGMENT_OFFSET` (88), 2 B; registry range 0..0x1fff, larger values reject. | **exact (range-gated)** `fragmentOffset` (88), unsigned16, 2 B; registry range 0..0x1fff, larger values reject. |
| `flow.ipv6_flow_label` | **inapplicable**: no v5 record field. | **exact (IPv6 only)** `IPV6_FLOW_LABEL` (31), 3 B; value must be 0..0xfffff and an IPv6 flow, otherwise the field is inapplicable. | **exact (IPv6 only)** `flowLabelIPv6` (31), unsigned32, 4 B; value must be 0..0xfffff and an IPv6 flow. |
| `flow.icmp_type` | **inapplicable**: no v5 ICMP field. | **synthesized (IPv4/protocol 1 only)** with `ICMP_TYPE` (32), 2 B: require IPv4 addresses, an explicit protocol-number mapping to ICMP (1), and both type/code; encode `(type << 8) | code`. ICMPv6 has no RFC 3954 field and is unsupported. | **exact (family/protocol-gated)** `icmpTypeIPv4` (176) or `icmpTypeIPv6` (178), unsigned8, 1 B; require matching address family and ICMP protocol. |
| `flow.icmp_code` | **inapplicable**: no v5 ICMP field. | **synthesized (IPv4/protocol 1 only)** with `ICMP_TYPE` (32), 2 B: the low byte is code; require IPv4 addresses, type/code 0..255, and protocol 1. ICMPv6 is unsupported absent a sourced extension. | **exact (family/protocol-gated)** `icmpCodeIPv4` (177) or `icmpCodeIPv6` (179), unsigned8, 1 B; require matching address family and ICMP protocol. |
| `flow.src_mac` | **inapplicable**: no v5 MAC fields. | **exact** `SRC_MAC` (56), 6 B; canonical six-octet value only. | **lossy/unsupported (pre/post direction collapsed)** a static mapping must choose `sourceMacAddress` (56) or `postSourceMacAddress` (81), macAddress, 6 B; the canonical key does not retain pre/post direction, so no unconditional exact mapping is claimed. |
| `flow.dst_mac` | **inapplicable**: no v5 MAC fields. | **exact** `DST_MAC` (57), 6 B; canonical six-octet value only. | **lossy/unsupported (pre/post direction collapsed)** a static mapping must choose `destinationMacAddress` (80) or `postDestinationMacAddress` (57), macAddress, 6 B; IE 57 is not a generic exact destination mapping without retained direction provenance. |
| `flow.src_vlan` | **inapplicable**: no v5 VLAN fields. | **exact** `SRC_VLAN` (58), 2 B; 0..4095. | **exact** `vlanId` (58), unsigned16, 2 B; 0..4095. |
| `flow.dst_vlan` | **inapplicable**: no v5 VLAN fields. | **exact** `DST_VLAN` (59), 2 B; 0..4095. | **exact** `postVlanId` (59), unsigned16, 2 B; 0..4095. |
| `flow.vlan_id` | **inapplicable**: no v5 VLAN fields. | **lossy/synthesized** `SRC_VLAN` (58), 2 B, as the only generic v9 slot; source/destination direction distinction is lost. | **exact** `vlanId` (58), unsigned16, 2 B; the canonical generic ID may coexist with `flow.src_vlan`. |
| `flow.next_hop` | **exact (fixed IPv4; required)** `nexthop`, 4 B; missing, invalid, or non-IPv4 values reject the record (never omit the field). | **exact (family-selected)** `IPV4_NEXT_HOP` (15), 4 B or `IPV6_NEXT_HOP` (62), 16 B; optional key may be omitted. | **exact (family-selected)** `ipNextHopIPv4Address` (15), 4 B or `ipNextHopIPv6Address` (62), 16 B; optional key may be omitted. |
| `flow.next_hop_as` | **unsupported**: no v5 field. | **unsupported**: no v9 field with this semantic. | **unsupported**: `bgpNextAdjacentAsNumber` (128) is adjacent-AS, not the receiver's next-hop AS; it is not substituted. |
| `flow.src_as` | **lossy (width-gated)** `src_as`, 2 B; values above 65535 reject. | **exact** `SRC_AS` (16), template length 4 B (the RFC permits 2 or 4); 0..`2^32-1`. | **exact** `bgpSourceAsNumber` (16), unsigned32, 4 B. |
| `flow.dst_as` | **lossy (width-gated)** `dst_as`, 2 B; values above 65535 reject. | **exact** `DST_AS` (17), template length 4 B; 0..`2^32-1`. | **exact** `bgpDestinationAsNumber` (17), unsigned32, 4 B. |
| `flow.bgp_next_hop` | **inapplicable**: no v5 BGP next-hop field. | **exact (family-selected)** `BGP_IPV4_NEXT_HOP` (18), 4 B or `BGP_IPV6_NEXT_HOP` (63), 16 B; optional key may be omitted. | **exact (family-selected)** `bgpNextHopIPv4Address` (18), 4 B or `bgpNextHopIPv6Address` (63), 16 B; optional key may be omitted. |
| `flow.src_net` | **exact (IPv4 only)** `src_mask`, 1 B, 0..32; an IPv6 family mismatch rejects a required conversion. | **exact (family-selected)** `SRC_MASK` (9), 1 B for IPv4 or `IPV6_SRC_MASK` (29), 1 B for IPv6; 0..32/128 respectively. | **exact (family-selected)** `sourceIPv4PrefixLength` (9), unsigned8, 1 B (0..32) or `sourceIPv6PrefixLength` (29), unsigned8, 1 B (0..128). |
| `flow.dst_net` | **exact (IPv4 only)** `dst_mask`, 1 B, 0..32; an IPv6 family mismatch rejects a required conversion. | **exact (family-selected)** `DST_MASK` (13), 1 B for IPv4 or `IPV6_DST_MASK` (30), 1 B for IPv6; 0..32/128 respectively. | **exact (family-selected)** `destinationIPv4PrefixLength` (13), unsigned8, 1 B (0..32) or `destinationIPv6PrefixLength` (30), unsigned8, 1 B (0..128). |
| `flow.forwarding_status` | **inapplicable**: no v5 forwarding-status field. | **lossy (current one-byte profile)** `FORWARDING_STATUS` (89), 1 B; values above 255 reject. | **lossy (current one-byte profile)** `forwardingStatus` (89), reduced-size length 1 B; values above 255 reject. The registry describes future bits but the current status is one byte. |
| `flow.observation_domain_id` | **inapplicable (header-only)**: v5 has no domain field; destination identity is configured. | **inapplicable (header-only)**: v9 `Source ID`, 4 B, is a configured outbound header value, never the incoming attribute. | **inapplicable (header-only)**: IPFIX header Observation Domain ID, 4 B, is configured per destination; never copy the incoming attribute. |
| `flow.observation_point_id` | **inapplicable**: no v5 field. | **inapplicable**: no v9 field; do not conflate it with Source ID. | **lossy (canonical source already truncated)** `observationPointId` (138), unsigned64, 8 B; zero-extend the retained uint32. The original IPFIX value above uint32 was irreversibly lost by goflow2 before OTel normalization. |

### Sampling-rate receiver qualifier

The v9 `SAMPLING_INTERVAL` (34) and IPFIX `samplingInterval` (34) cells above
remain **exact (wire, width-gated)** ordinary Data-Template mappings: values
0..`MaxUint32` are encoded as four bytes and larger values reject.  At the
pinned Contrib/goflow2 receiver, however, a nonzero ordinary Data-Record IE 34
is not copied into `FlowMessage.SamplingRate`; absent unrelated Options cache
state the producer emits canonical rate zero.  If such Options state exists,
the first matching Options value (search order 305, then 50, then 34) is cached
by source-IP/version/domain and reused across ordinary records, so it can mask
distinct per-record rates.  This is pinned receiver/producer asymmetry, not
exporter wire loss or permission to emit Options output.

Evidence is the receiver and protocol behavior retained in this repository,
including the [source ledger](../research/source-ledger.md),
the pinned [goflow2 producer](https://github.com/netsampler/goflow2/blob/c9824f41bcad11d4490a668ed5270b03056d8217/producer/proto/producer_nf.go#L747-L830),
and the pinned [Contrib parser](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L248-L260).

### IPFIX timestamp quantization

The general profile's 152/153 timestamps use unsigned 64-bit big-endian Unix
milliseconds, flooring each canonical ns value by 1,000,000. Original ordering
is checked before flooring; sub-ms interval collapse is permitted. Exact-ms
and sub-ms values receive the same per-selected-descriptor lossy classification,
not a count of nanoseconds discarded. Canonical range stays `0..MaxInt64` ns;
the NTP era gate does not apply to 152/153. Export headers still require uint32
Unix seconds. IPFIX end <= export time is a deployment prerequisite, not a
runtime gate. No measured-time provenance is inferred or restored. See the
[general profile and omission recipe](default-profiles.md#ipfix-general-v1-recommended).

Every selected IPFIX `dateTimeNanoseconds` value uses RFC 7011's 64-bit NTP
representation. The exporter converts the Unix-nanosecond remainder to the
nearest binary `2^-32`-second tick with exact integer arithmetic,
`(nanoseconds*4294967296 + 500000000) / 1000000000`; no floating-point or
silent truncation is permitted. The accepted nonnegative Unix-nanosecond era
ends at `2085978495999999999` (2036-02-07 06:28:15.999999999 UTC), and the next
value rejects before narrowing. This quantization remains exporter loss under
the classifications above even though its maximum rounding error is less than
one-eighth nanosecond.

## Envelope, missing values, and rejection policy

`flow.start` is authoritative for the OTel `Timestamp`; `flow.time_received` is
authoritative for `ObservedTimestamp`, but it is receiver-ingest time rather
than an observation-point timestamp.  Neither envelope timestamp is a fallback
for a missing canonical key, and header export time is generated from the
exporter clock.  Parsed records have an empty body; the receiver's `send_raw`
formatted `ProtoProducerMessage` body is unsupported and is not datagram
passthrough.  Resource and scope attributes remain provenance only and cannot
select a receiver version or fill a flow field.

Missing required canonical keys, malformed addresses (including `invalid IP`),
inconsistent source/destination families, protocol mismatches, and out-of-range
values reject that record for the affected destination.  The optional
`flow.next_hop` and `flow.bgp_next_hop` keys may be omitted unless selected by
the destination.  Each valid hop may have an independent IP family when
unselected, without changing the flow family or mapped output.  A selected
hop must match its descriptor's family and width (4 bytes for IPv4, 16 for
IPv6); v5 always selects an IPv4 next hop and has no BGP next-hop slot.
Malformed present hops reject even when unselected.  Zero and sentinel values
are retained as values; they are never guessed, replaced, or used to infer
protocol, family, sampling mode, or boot time.  Any narrowing, reduced-size
encoding, or timestamp conversion is range-checked; there is no clamp or
truncation. Unsupported or inapplicable selected arms fail configuration;
`encode_and_count` accepts only documented supported exact, lossy, or synthesized
transformations, and only selected lossy or synthesized bindings contribute
exporter loss. A valid unselected field contributes no mapping or loss count
merely because it is absent from output.

`Canonical-source loss` is information already discarded by the pinned
receiver/goflow2 path (for example, IN/OUT counter overwrite, an unknown
protocol/EtherType number rendered as a token, or an IPFIX observation-point
value narrowed to protobuf `uint32`).  `Exporter loss` is introduced here by a
selected target's documented supported lossy or synthesized transformation,
such as a representable width conversion or timestamp quantization. Unsupported
and inapplicable selected arms fail configuration rather than becoming loss or
omission. The exporter records these classes separately; it never claims to
recover canonical-source loss. See the detailed
[loss contract](default-profiles.md#loss-errors-and-diagnostics).

NetFlow v5 uses a fixed 24-byte header and 48-byte flow record, with a
1..30-record packet count from Cisco tables B-3/B-4.  It has no Source ID:
header identity is the configured engine type (1 B) and engine ID (1 B), while
`sysUpTime`, UNIX time, sequence, and sampling header state are exporter-owned.
The fixed record's `pad1` at offset 36 (1 B) and `pad2` at offsets 46..47 (2 B)
are always zero-filled; no canonical or custom mapping may write nonzero pad
bytes.  First/Last uptime values use only the explicit stable `uptime_origin`
policy in the matrix; there is no rollover handling.  At packet construction,
reserve one logical `header_instant` and derive
`header_sysUpTime = (header_instant - uptime_origin) / 1,000,000` with the same
exact-ms and range gates.  Require `0 <= First <= Last <= header_sysUpTime <=
uint32 max`; for v9, apply the corresponding
`0 <= FIRST_SWITCHED <= LAST_SWITCHED <= header_sysUpTime <= uint32 max` when
those fields are selected.  The upper-bound/order check is an explicit project
semantic inference from Cisco v5/RFC 3954's switch-time definitions, not a new
protocol MUST.
NetFlow v9 uses RFC 3954 templates;
template field lengths are explicit and template/data ordering follows the RFC
(including the verified padding erratum).  IPFIX uses RFC 7011 templates and
the 32-bit header Observation Domain ID; its sequence counts Data Records sent
before the current message (verified erratum 4396), and timestamp IEs use the
RFC 7011 §6.1 encodings (verified erratum 3881).

## Bounded custom and unknown mapping

The input record and unknown OTel attributes are left untouched.  Extraction is
limited to keys explicitly named by a configured, static template/mapping and
to hard limits on attribute count, key bytes, and value bytes; there is no
dynamic template shape, key discovery, or unbounded label/cardinality growth.
An IPFIX enterprise IE requires an explicit PEN, IE ID, abstract type, and
encoded length.  A NetFlow v9 private numeric type is explicit opt-in only,
has no PEN on the wire, and has limited interoperability; its semantics and
length must be configured.  NetFlow v5 has no extension mechanism in the fixed
record and rejects extension mappings.  No custom rule may override the
canonical safety policies above or silently recover a number, family, or boot
epoch from a name or scope.

### Versioned v9 timed profile

The recommended [timed profile](default-profiles.md#netflow-v9-timed-v1-recommended-bounded-lifetime)
selects the existing FIRST_SWITCHED 22/4 and LAST_SWITCHED 21/4 matrix cells
for both families, after the unchanged 18 core fields. It requires explicit
`uptime_origin`, measured-time provenance, exact origin-relative milliseconds,
ordered times no later than export, and the existing uint32 uptime lifetime.
Core-v1 remains explicit time omission. The whole-second export header creates
the [reconstruction ambiguity](../operator-guide.md#time-ranges-and-process-lifetime);
this selection does not infer provenance, widen v9 fields or implement rollover.
