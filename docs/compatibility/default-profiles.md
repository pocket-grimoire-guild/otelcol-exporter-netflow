# Static export profiles and mapping grammar

Status: accepted static mapping/profile contract (2026-09-03).

This document publishes the immutable built-in profiles and the explicit
mapping grammar for the sole supported receiver schema. It is the operator
compatibility surface; it does not define an encoder implementation. Protocol
field meanings remain those in the [receiver-to-protocol conversion
matrix](protocol-mapping.md), and the accepted source packet for this contract
is the [static profile decision](../decisions/0005-static-export-profiles.md).

## Schema and profile identity

The sole supported input schema is
`contrib-netflowreceiver-v0.160.0`, defined by Collector Contrib `v0.160.0`
at immutable commit
[`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver)
and resolved goflow2/v2 `v2.2.6` at immutable commit
[`c9824f41bcad11d4490a668ed5270b03056d8217`](https://github.com/netsampler/goflow2/tree/c9824f41bcad11d4490a668ed5270b03056d8217).
The complete 41-key schema, OTel types, presence, units, sentinels, and
normalization rules are in [`receiver-attributes.md`](receiver-attributes.md);
its 39 `R` keys are required and only `flow.next_hop` and
`flow.bgp_next_hop` are optional.

The immutable built-in catalog identifiers are:

* `contrib-netflowreceiver-v0.160.0/netflow-v5-fixed-v1`
* `contrib-netflowreceiver-v0.160.0/netflow-v9-core-v1` (explicit time omission)
* `contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1` (recommended bounded lifetime)
* `contrib-netflowreceiver-v0.160.0/ipfix-core-v1` (legacy NTP)
* `contrib-netflowreceiver-v0.160.0/ipfix-general-v1` (recommended Unix milliseconds)

An identifier includes the schema, protocol, and catalog version. A future
catalog changes its `-vN` identifier. An existing identifier's field order,
target, width, transform, family variants, and template ordinals never change.

## Selection and recommended configuration

`createDefaultConfig` leaves `mapping.profile`, `mapping.fields`, both token
sequences, input guarantees, and `mapping.loss_policy` unset. There is no
implicit mapping or implicit loss acknowledgement. Decoded configuration must
select exactly one of:

1. a nonempty `mapping.profile` matching the configured schema and protocol; or
2. a nonempty ordered `mapping.fields` list.

`mapping.fields` is optional/pointer-valued, so absent differs from an explicit
empty list. Empty `fields`, both selectors, neither selector, a profile for a
different schema/protocol, and an unknown profile name fail validation.
Nonempty `fields` replaces rather than extends a profile. `mapping.custom`
appends fixed fields to v9/IPFIX selections after canonical fields. NetFlow v5
requires exactly its built-in fixed profile and rejects both `mapping.fields`
and `mapping.custom`; its wire slots cannot be omitted, reordered, or extended.

`mapping.loss_policy` is required and pointer-valued. Absent, empty, or unknown
values fail validation. Every built-in catalog requires the explicit
`encode_and_count` acknowledgement. The strict `reject` policy is available
only with a nonempty explicit field list whose expanded canonical fields are
all exact.

The following is the complete recommended IPFIX mapping configuration. The
five protocol entries and two network-version entries are explicit, frozen
operator input, not hidden defaults or a complete vocabulary:

```yaml
mapping:
  # Attest measured source times in canonical flow.start/flow.end.
  profile: contrib-netflowreceiver-v0.160.0/ipfix-general-v1
  protocol_identifiers:
    - token: icmp
      number: 1
    - token: tcp
      number: 6
    - token: udp
      number: 17
    - token: ipv6-icmp
      number: 58
    - token: sctp
      number: 132
  network_type_versions:
    - token: ipv4
      version: 4
    - token: ipv6
      version: 6
  input_guarantees: {}
  loss_policy: encode_and_count
  custom: []
```

Other valid receiver tokens remain unconfigured until an operator supplies a
sequence containing them; sequences never merge with hidden values. Every
parsed input must satisfy the pinned schema with exact OTel types. Structural
preflight walks resource/scope containers only to count records and check
structural validity. Normalization scans top-level log attributes to validate
canonical values; selected custom sources follow their own mapping rules.
Unknown and unselected noncanonical attributes are ignored for mapping and loss,
but present canonical
attributes are still normalized even when unselected. Preflight does not
inspect arbitrary metadata. Work and failed-subset copies still scale with
input size, and extreme pdata nesting retains the documented
[stack-exhaustion risk](alpha-upgrades.md#sampling-delivery-and-results).
A `send_raw` formatted body is unsupported and rejects before mapping.

The general shape does not include ICMP type/code, even when the operator
allows ICMP tokens. Select those fields explicitly if needed. For a complete
validated receiver/exporter pipeline, use
[`distribution/ocb/config.yaml`](../../distribution/ocb/config.yaml), with its
source-template attestation and fresh v9/IPFIX template range 300/301.

### Explicit token and provenance sequences

`protocol_identifiers` is a sequence, not a YAML map. It has 1..32 entries
whenever `network.transport` is emitted or a selected transform (currently the
v9 `flow.icmp_type_code` composite) consumes a resolved protocol number; when
neither is active, supplying it is rejected as inactive. Each entry's token
matches the exact pinned receiver literal byte-for-byte. No trim, case fold,
alias, numeric string, runtime IANA lookup, or reverse host lookup occurs.
`unknown` is forbidden. Each number is uint8 and must equal the token's frozen
value in the receiver's complete 0..145 table; duplicate token or number fails
validation. The immutable table is published in
[`receiver-token-vocabulary.md`](receiver-token-vocabulary.md). A record using
an unconfigured token rejects with the fixed map-miss reason.

`network_type_versions` is required whenever `network.type` is selected and is
otherwise rejected as inactive. The initial grammar accepts exactly one
`ipv4:4` and one `ipv6:6`. It never reconstructs EtherType. The token must
agree with the source/destination address-derived family; family is selected
from parsed addresses, never from this token, `flow.type`, scope, resource, or
body. The complete receiver token behavior is in the
[`receiver-token-vocabulary.md`](receiver-token-vocabulary.md) artifact.

The v5 fixed catalog additionally requires the trusted operator assertion
`mapping.input_guarantees.flow_io_bytes: layer3_total_octets`. This is an input
contract, not a value inferred by the exporter: without it, the fixed `dOctets`
slot is unsupported because the canonical receiver field may have lost layer
or direction provenance. The assertion is accepted only for v5 and does not
repair incorrect upstream data. Absence or any other value fails v5 validation.

## Built-in catalogs

Field order is a project compatibility choice. RFCs define identities and
encodings but do not mandate these default orders. All width, family, protocol,
time, and missing-value gates in the [conversion matrix](protocol-mapping.md)
remain in force.

### NetFlow v5 fixed v1

There is no template and `templates.id_base` is unused. The Cisco fixed record
is 48 bytes in this exact order (Cisco format tables B-3/B-4 are linked from
the [matrix](protocol-mapping.md)):

| Offset | Bytes | Source/slot | Classification and gate |
| ---: | ---: | --- | --- |
| 0 | 4 | `source.address` -> `srcaddr` | exact; IPv4 |
| 4 | 4 | `destination.address` -> `dstaddr` | exact; IPv4 |
| 8 | 4 | `flow.next_hop` -> `nexthop` | exact; present IPv4 required |
| 12 | 2 | `flow.in_if` -> `input` | lossy width gate |
| 14 | 2 | `flow.out_if` -> `output` | lossy width gate |
| 16 | 4 | `flow.io.packets` -> `dPkts` | exact width gate |
| 20 | 4 | `flow.io.bytes` -> `dOctets` | only with the configured Layer-3-total guarantee; width gate |
| 24 | 4 | `flow.start` -> `First` | lossy/synthesized exact-ms configured-origin gate |
| 28 | 4 | `flow.end` -> `Last` | lossy/synthesized exact-ms configured-origin gate |
| 32 | 2 | `source.port` -> `srcport` | exact width gate |
| 34 | 2 | `destination.port` -> `dstport` | exact width gate |
| 36 | 1 | `pad1` | constant zero |
| 37 | 1 | `flow.tcp_flags` -> `tcp_flags` | lossy width gate |
| 38 | 1 | `network.transport` -> `prot` | configured-token synthesis |
| 39 | 1 | `flow.ip_tos` -> `tos` | exact |
| 40 | 2 | `flow.src_as` -> `src_as` | lossy width gate |
| 42 | 2 | `flow.dst_as` -> `dst_as` | lossy width gate |
| 44 | 1 | `flow.src_net` -> `src_mask` | exact IPv4 range |
| 45 | 1 | `flow.dst_net` -> `dst_mask` | exact IPv4 range |
| 46 | 2 | `pad2` | constant zero |

The packet header uses configured engine type/id and `uptime_origin`; destination
state owns send time and sequence. `flow.sampling_rate` plus configured raw
two-bit mode supplies the header's 14-bit interval. A packet never mixes
sampling rates: a valid changed rate flushes the current packet and starts
another; values above 16383 reject that record. The count is 1..30. Every
record requires same-family IPv4 source, destination, and next-hop plus the
exact-ms/order/header-uptime checks in the matrix. This profile is valid only
with `encode_and_count`. `pad1` and `pad2` are always zero-filled; no canonical
or custom mapping may write nonzero pad bytes.

### NetFlow v9 core v1

Validation compiles exactly two ordinary Data Templates and no Options output.
IPv4 is `templates.id_base`; IPv6 is `templates.id_base+1`. Both templates have
18 fields in this order:

| Ordinal | Canonical source | IPv4 type/length | IPv6 type/length | Classification |
| ---: | --- | --- | --- | --- |
| 1 | `flow.io.bytes` | IN_BYTES 1/4 | same | lossy direction/layer policy |
| 2 | `flow.io.packets` | IN_PKTS 2/4 | same | lossy direction policy |
| 3 | `network.transport` | PROTOCOL 4/1 | same | configured-token synthesis |
| 4 | `flow.ip_tos` | SRC_TOS 5/1 | same | exact |
| 5 | `flow.tcp_flags` | TCP_FLAGS 6/1 | same | lossy width gate |
| 6 | `source.port` | L4_SRC_PORT 7/2 | same | exact |
| 7 | `source.address` | IPV4_SRC_ADDR 8/4 | IPV6_SRC_ADDR 27/16 | exact family variant |
| 8 | `flow.src_net` | SRC_MASK 9/1 | IPV6_SRC_MASK 29/1 | exact family variant |
| 9 | `flow.in_if` | INPUT_SNMP 10/2 | same | lossy width gate |
| 10 | `destination.port` | L4_DST_PORT 11/2 | same | exact |
| 11 | `destination.address` | IPV4_DST_ADDR 12/4 | IPV6_DST_ADDR 28/16 | exact family variant |
| 12 | `flow.dst_net` | DST_MASK 13/1 | IPV6_DST_MASK 30/1 | exact family variant |
| 13 | `flow.out_if` | OUTPUT_SNMP 14/2 | same | lossy width gate |
| 14 | `flow.src_as` | SRC_AS 16/4 | same | exact |
| 15 | `flow.dst_as` | DST_AS 17/4 | same | exact |
| 16 | `flow.sampling_rate` | SAMPLING_INTERVAL 34/4 | same | exact wire/width gate; receiver qualifier applies |
| 17 | `flow.ip_ttl` | MIN_TTL 52/1 | same | exact |
| 18 | `network.type` | IP_PROTOCOL_VERSION 60/1 | same | configured family-token synthesis |

The fixed Data Record lengths are 43 bytes (IPv4) and 67 bytes (IPv6). Each
Template Record is 76 bytes; a one-Template-Record Template FlowSet is 80 bytes
before packet packing. Source and destination families must match. This legacy profile
omits FIRST/LAST, so it does not require `uptime_origin` for record timestamps.
It also omits receiver-optional next-hop fields, composites, MAC/VLAN/fragment
fields, and fields with stronger provenance ambiguity. Ordinary v9 type 34 is a
Data-Template field; no Options Template or Options Data is emitted.

### NetFlow v9 timed v1 (recommended bounded lifetime)

`contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1` preserves all 18 ordered
core fields above and appends these two fields for both families:

| Ordinal | Canonical source | Type/length | Classification |
| ---: | --- | --- | --- |
| 19 | `flow.start` | FIRST_SWITCHED 22/4 | synthesized configured-origin elapsed milliseconds |
| 20 | `flow.end` | LAST_SWITCHED 21/4 | synthesized configured-origin elapsed milliseconds |

The IPv4/IPv6 Data Records are 51/75 bytes. Each Template Record is 84 bytes;
its Template FlowSet is 88 bytes. The two family ordinals remain base/base+1.
At the default 464-byte payload, data packets fit 8 IPv4 or 5 IPv6 records.
All core counter/interface width gates remain; use IPFIX for wider values.

This selection requires explicit `uptime_origin` and `encode_and_count`.
All 39 required input keys still apply. Measured start/end values must be exact
milliseconds relative to that stable origin, ordered, and no later than export
time. An origin need not itself be aligned to Unix milliseconds. No time is
inferred from receipt, export, or envelope timestamps. For the supplied
receiver pipeline, deployment must attest that original source templates carried
measured values and the receiver preserved them. Another producer that constructs
the exact compatible representation must establish its own measured-time
semantics and provenance. An old time-free source template does not establish
that provenance.

This is a **bounded-lifetime setup**: elapsed uptime cannot exceed
4,294,967,295 ms (about 49.71 days), and exhaustion latches without wrapping.
A planned restart with a new origin must still place that origin at or before
every accepted historical flow. Prefer the [IPFIX general profile](#ipfix-general-v1-recommended)
for longer unattended service. V9's whole-second export header can shift a
consumer's reconstructed absolute endpoints by less than one second while
preserving their interval; see the [time-range guidance](../operator-guide.md#time-ranges-and-process-lifetime).

The complete [Collector example](../../distribution/ocb/config.yaml) supplies
`NETFLOW_V9_ORIGIN` and fresh templates 300/301. Use a fresh range or deliberately
isolated identity when migrating; a restart does not invalidate all consumer
caches. For explicit time omission, select unchanged `netflow-v9-core-v1`.
It needs no record-time origin, though its header still has a bounded startup
origin. No Options output or automatic origin rollover is added.

### IPFIX core v1

Validation compiles exactly two ordinary Data Templates with the same ID
ordinals and no Options output. IPv4 is `templates.id_base`; IPv6 is
`templates.id_base+1`. The 20 fields, identities, abstract types, and lengths
are:

| Ordinal | Canonical source | IPv4 IE/name/type/length | IPv6 IE/name/type/length | Classification |
| ---: | --- | --- | --- | --- |
| 1 | `flow.io.bytes` | 1 `octetDeltaCount`/unsigned64/8 | same | lossy direction/layer policy |
| 2 | `flow.io.packets` | 2 `packetDeltaCount`/unsigned64/8 | same | lossy direction policy |
| 3 | `network.transport` | 4 `protocolIdentifier`/unsigned8/1 | same | configured-token synthesis |
| 4 | `flow.ip_tos` | 5 `ipClassOfService`/unsigned8/1 | same | exact |
| 5 | `flow.tcp_flags` | 6 `tcpControlBits`/unsigned16/2 | same | exact width gate |
| 6 | `source.port` | 7 `sourceTransportPort`/unsigned16/2 | same | exact |
| 7 | `source.address` | 8 `sourceIPv4Address`/ipv4Address/4 | 27 `sourceIPv6Address`/ipv6Address/16 | exact family variant |
| 8 | `flow.src_net` | 9 `sourceIPv4PrefixLength`/unsigned8/1 | 29 `sourceIPv6PrefixLength`/unsigned8/1 | exact family variant |
| 9 | `flow.in_if` | 10 `ingressInterface`/unsigned32/4 | same | exact |
| 10 | `destination.port` | 11 `destinationTransportPort`/unsigned16/2 | same | exact |
| 11 | `destination.address` | 12 `destinationIPv4Address`/ipv4Address/4 | 28 `destinationIPv6Address`/ipv6Address/16 | exact family variant |
| 12 | `flow.dst_net` | 13 `destinationIPv4PrefixLength`/unsigned8/1 | 30 `destinationIPv6PrefixLength`/unsigned8/1 | exact family variant |
| 13 | `flow.out_if` | 14 `egressInterface`/unsigned32/4 | same | exact |
| 14 | `flow.src_as` | 16 `bgpSourceAsNumber`/unsigned32/4 | same | exact |
| 15 | `flow.dst_as` | 17 `bgpDestinationAsNumber`/unsigned32/4 | same | exact |
| 16 | `flow.sampling_rate` | 34 `samplingInterval`/unsigned32/4 | same | exact wire/width gate; receiver qualifier applies |
| 17 | `flow.ip_ttl` | 52 `minimumTTL`/unsigned8/1 | same | exact |
| 18 | `network.type` | 60 `ipVersion`/unsigned8/1 | same | configured family-token synthesis |
| 19 | `flow.start` | 156 `flowStartNanoseconds`/dateTimeNanoseconds/8 | same | lossy NTP precision/era gate |
| 20 | `flow.end` | 157 `flowEndNanoseconds`/dateTimeNanoseconds/8 | same | lossy NTP precision/era gate |

The fixed Data Record lengths are 72 bytes (IPv4) and 96 bytes (IPv6). Each
Template Record is 84 bytes; a one-Template-Record Template Set is 88 bytes.
Counters use the non-post ingress choices `octetDeltaCount` and
`packetDeltaCount`; this is explicit lossy policy, not recovered direction. IE
34 is the deprecated ordinary four-byte `samplingInterval`, never IE 305 and
never Options state. With a fresh pinned receiver and no prior Options cache,
the semantic test expects zero for distinct nonzero ordinary IE 34 values while
TShark preserves them. A receiver with prior matching Options cache state may
instead emit that packet-wide cached value; the exporter neither relies on nor
creates such state.

### IPFIX general v1 (recommended)

`contrib-netflowreceiver-v0.160.0/ipfix-general-v1` preserves the exact ordered
first 18 fields of IPFIX core v1 above. Only the final two descriptors change:

| Ordinal | Canonical source | Both families: IE/name/type/length | Classification |
| ---: | --- | --- | --- |
| 19 | `flow.start` | 152 `flowStartMilliseconds`/dateTimeMilliseconds/8 | lossy millisecond precision |
| 20 | `flow.end` | 153 `flowEndMilliseconds`/dateTimeMilliseconds/8 | lossy millisecond precision |

There are two ordinary templates: IPv4 at the base, IPv6 at base+1. Records
remain 72/96 bytes; Template Records remain 84 bytes (88-byte Template Sets).
At the default 464-byte UDP payload, data-only packets fit 6 IPv4 or 4 IPv6
records. There is no new request-wide admission limit.

Per [RFC 7011 §6.1.8](https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1.8)
and the [IANA registry](https://www.iana.org/assignments/ipfix), serialization
writes unsigned big-endian Unix milliseconds. Canonical nonnegative signed-safe
Unix ns stay authoritative: check original start <= end before flooring each
endpoint with integer division by 1,000,000. Sub-ms intervals may collapse.
Both exact-ms and sub-ms inputs have the same existing selected-descriptor loss
count under `encode_and_count`; no metric measures discarded nanoseconds.
This profile removes the legacy NTP era-zero gate, but does not expand the
canonical `0..MaxInt64` ns range or the uint32 Unix export-header range.
IPFIX does not currently enforce end <= export time; deployments must ensure
that prerequisite. Receipt time and log-envelope timestamps are never fallbacks.

For the supplied receiver pipeline, the source deployment must attest that its
original templates carried measured times and that the receiver preserved them
into canonical attributes. Another producer may construct the exact compatible
representation without literal Contrib origin or receiver scope identity, but
it must establish its own measured-time semantics and provenance. The exporter
only re-encodes the canonical attributes; the profile cannot verify provenance.
Keep original device identity in upstream provenance and isolate downstream
exporter identities/destinations as needed; the outgoing observation domain and
UDP source describe this exporter, not a recovered original device.

When migrating an existing destination, allocate a fresh template range such
as 300/301 (or deliberately isolate a new exporter identity). Restarting alone
does not invalidate every collector's template cache. The legacy NTP profile
remains explicitly selectable with `mapping.profile:
contrib-netflowreceiver-v0.160.0/ipfix-core-v1` and retains all bytes and gates.

#### Explicit time omission

Replace the example's entire `mapping` object with this field list to retain
the same first 18 fields and omit flow times. All 39 required input keys still
apply, including start/end: omission changes the output, not the input schema.
Use a fresh template range for this different layout as well.

```yaml
mapping:
  fields:
    - {canonical: flow.io.bytes, target: octet_delta_count}
    - {canonical: flow.io.packets, target: packet_delta_count}
    - {canonical: network.transport}
    - {canonical: flow.ip_tos}
    - {canonical: flow.tcp_flags}
    - {canonical: source.port}
    - {canonical: source.address}
    - {canonical: flow.src_net}
    - {canonical: flow.in_if}
    - {canonical: destination.port}
    - {canonical: destination.address}
    - {canonical: flow.dst_net}
    - {canonical: flow.out_if}
    - {canonical: flow.src_as}
    - {canonical: flow.dst_as}
    - {canonical: flow.sampling_rate}
    - {canonical: flow.ip_ttl}
    - {canonical: network.type, target: ip_version}
  protocol_identifiers: [{token: tcp, number: 6}, {token: udp, number: 17}]
  network_type_versions: [{token: ipv4, version: 4}, {token: ipv6, version: 6}]
  loss_policy: encode_and_count
```

## Explicit canonical field objects and static shapes

An explicit mapping has 1..64 ordered object entries. `canonical` and optional
`target` are the only accepted YAML keys; scalar strings and unknown keys fail:

```yaml
mapping:
  fields:
    - canonical: source.address
    - canonical: flow.io.bytes
      target: in_bytes
    - canonical: flow.icmp_type_code
```

Ordinary `canonical` values are exact names in the 41-field schema. The virtual
v9-only `flow.icmp_type_code` composite is the sole exception. A `target` is
required for these ambiguous matrix cells:

| Canonical selector | Protocol | Allowed `target` values |
| --- | --- | --- |
| `flow.io.bytes` | v9 | `in_bytes`, `out_bytes` |
| `flow.io.bytes` | IPFIX | `octet_delta_count`, `post_octet_delta_count` |
| `flow.io.packets` | v9 | `in_packets`, `out_packets` |
| `flow.io.packets` | IPFIX | `packet_delta_count`, `post_packet_delta_count` |
| `network.type` | IPFIX | `ip_version` only; canonical string input cannot select `ethernet_type` |
| `flow.time_received` | IPFIX | `observation_time_nanoseconds` |
| `flow.src_mac` | IPFIX | `source_mac_address`, `post_source_mac_address` |
| `flow.dst_mac` | IPFIX | `destination_mac_address`, `post_destination_mac_address` |

IPFIX also permits optional `flow_start_milliseconds` for `flow.start` and
`flow_end_milliseconds` for `flow.end`. Omitting either target retains its
legacy 156/157 NTP descriptor. Wrong field/protocol targets and repeated
selectors for the same canonical time are rejected. Targets are forbidden
outside the cases documented here.

Built-in catalogs carry their choices directly and do not serialize this table.
Arbitrary numeric IDs, names, widths, aliases, and implicit first/last-wins
resolution are forbidden in canonical entries.

V9's combined ICMP field is the sole initial composite selector. It consumes
`flow.icmp_type`, `flow.icmp_code`, the configured protocol number, and IPv4.
Selecting either scalar separately for v9 fails. Selecting the composite
activates `protocol_identifiers`, compiles an IPv4-only catalog, and rejects
every IPv6 or non-ICMP record before packing; it never compiles an IPv6 shape
that silently omits the selected field. IPFIX keeps family-specific ICMP scalar
IEs. Any two selections that compile to the same wire identity fail, including
`flow.src_vlan` versus `flow.vlan_id` at type/IE 58. A wire identity is a v9
numeric type, IPFIX standard IE ID, or IPFIX enterprise `(PEN, IE ID)`.

All selected receiver-required sources remain required. Selecting either
receiver-optional next-hop key makes it required for every record and requires
its family to equal the source/destination family. There are no
presence-derived variants, optional custom fields, record-created templates,
or sentinel insertion.

If the selected fields support both families and no field is family-dependent,
compile one shape at `id_base`. If both families are supported and any field is
family-dependent, compile the complete two-shape catalog at validation: IPv4 at
`id_base` and IPv6 at `id_base+1`. The v9 ICMP composite narrows the
intersection to the sole IPv4 shape at `id_base`; an empty family intersection
fails configuration. A record selects only one precompiled index from parsed
same-family source/destination addresses. Alternating hostile records cannot
create an ID, shape, map entry, cache entry, or allocation.

Every shape has at least one field and a positive fixed minimum Data Record
length. The widened check `id_base + shape_count - 1 <= 65535` precedes
narrowing. After complete expansion, the ceilings are 16 shapes, 64
fields/shape, 4096 encoded template bytes/shape, 32 custom mappings, and 32
PENs. Checked widened arithmetic proves every expanded template fits the
permitted template datagram and that protocol header + Set/FlowSet header + one
fixed record (or the minimum variable-field prefixes/payload) fits
`max_datagram_size`; otherwise validation fails before allocation. Larger
variable values remain runtime packet-budget checks.

The transport payload budget is additionally governed by
[ADR 0006](../decisions/0006-explicit-pmtu-budget.md). With no trusted
`path_mtu` assertion, a payload above 464 bytes fails configuration. With one,
validation reserves 28 outer bytes for an IPv4 literal and 48 for an IPv6
literal or hostname, then proves the configured payload, every expanded
template, and one minimum record fit. A profile never silently reduces the
operator's value or relies on the current DNS family.

## Custom field grammar and limits

Custom sources are exact, nonempty top-level log-attribute keys with byte length
`1..256` in the public exporter configuration. This static mapping grammar
bound does not limit keys in unselected metadata.
Dots are literal key bytes, not traversal. Resource, scope, body, nested paths,
and all 41 canonical keys are forbidden as custom sources. A custom source is
required in every accepted record and declares one exact OTel input type. There
is no string/number/sign/unit/epoch coercion, padding, truncation, or fallback.

The protocol selects one closed YAML object grammar. An IPFIX fixed field is:

```yaml
custom:
  - source: vendor.counter
    pen: 32473
    element_id: 100
    encoding: unsigned32
    fixed_length: 4
```

An IPFIX variable field is:

```yaml
custom:
  - source: vendor.label
    pen: 32473
    element_id: 101
    encoding: string
    variable: true
    max_length: 4096
```

For IPFIX, `source`, `pen`, `element_id`, and `encoding` are required. Exactly
one length form is present: `fixed_length`, or `variable: true` plus
`max_length`; `variable: false`, both forms, neither form, and unknown keys
fail. `fixed_length` must equal the natural address/integer/MAC width or the
declared exact string/octet length.

A v9 private field is:

```yaml
custom:
  - source: vendor.counter
    field_type: 40000
    encoding: unsigned32
    fixed_length: 4
    allow_private: true
```

For v9, exactly `source`, `field_type`, `encoding`, `fixed_length`, and
`allow_private: true` are required. IPFIX keys, variable/max length, a false
opt-in, and unknown keys fail.

IPFIX custom fields require nonzero uint32 PEN, element ID 1..32767, and one of
these closed encodings. Their Field Specifier always sets `E=1`, carries the
configured 15-bit element ID, and appends the four-byte PEN, so it is eight
bytes. `E=0`, a missing PEN, or a four-byte standard Field Specifier for a
custom entry is a configuration/writer error.

| Encoding | OTel input | Permitted template/runtime length |
| --- | --- | --- |
| `unsigned8\|unsigned16\|unsigned32\|unsigned64` | int | natural 1/2/4/8 bytes; negative or overflow rejects |
| `signed8\|signed16\|signed32\|signed64` | int | natural 1/2/4/8 bytes; overflow rejects |
| `ipv4_address\|ipv6_address` | string | parsed canonical address of exact family; 4/16 bytes |
| `mac_address` | string | exact canonical six-octet form; 6 bytes |
| `octet_array` | bytes | fixed descriptor syntax 1..65535 bytes exactly, or IPFIX variable; complete-record fit required |
| `string` | string | valid UTF-8 and fixed descriptor syntax 1..65535 bytes exactly, or IPFIX variable; complete-record fit required |

IPFIX variable string/octet fields use Template length 65535 and require
`max_length` 1..65535 as a descriptor ceiling. A 65,535-byte value cannot fit
alongside Set/message headers; the usable maximum is lower and depends on sibling
fields, length prefixes and the path budget. Complete encoded records must also fit their Set,
message and configured datagram/path budget; the former 4096-byte mapped-value
policy and root `limits.max_mapped_value_bytes` setting have been removed.
Runtime lengths 0..`max_length` charge and check `prefix + value` with a
one-byte prefix below 255 and the 255 marker plus two-byte length at or above
255. Other abstract types, reduced-size custom integers, lists/maps, and
implicit timestamps are deferred.

V9 private fields additionally require `allow_private: true`, numeric type
256..65535, one of the same encodings, and a fixed natural/exact length. V9
variable length and enterprise identity are rejected. A registered or selected
type collision fails. Custom fields append in configured order to every shape.
All duplicate identities are checked after profile expansion across built-in,
canonical, composite, and custom fields.

When appended to the built-in v9 profile, each private field adds four bytes to
its 76-byte Template Record (an 80-byte one-Template-Record FlowSet including
the header). When appended to the built-in IPFIX profile, each enterprise field
adds eight bytes to its 84-byte Template Record (an 88-byte one-Template-Record
Set including the header). Checked arithmetic includes all custom Field
Specifiers and permitted zero padding and rejects any expanded template above
4096 bytes or the configured template-datagram budget.

## Envelope and missing values

`flow.start` is authoritative for the OTel `Timestamp`; `flow.time_received`
is authoritative for `ObservedTimestamp`, and receiver-ingest time is not an
observation-point timestamp. Neither envelope timestamp is a fallback for a
missing canonical key, and header export time is generated from the exporter
clock. Parsed records have an empty body; a formatted raw body is not a
datagram passthrough. Resource and scope attributes remain provenance only and
cannot select a receiver version or fill a flow field.

## Loss, errors, and diagnostics

`encode_and_count` accepts only matrix-enumerated exact, lossy, and synthesized
transformations whose stated predicates and required configuration are
satisfied. It never turns an unsupported or inapplicable arm into loss.
Runtime absence, map miss, family/protocol/provenance mismatch, width/range
failure, or invalid custom input rejects the record.

`reject` fails configuration when any expanded canonical field is lossy or
synthesized. Width-gated exact fields remain valid at configuration and reject
out-of-range records. All three built-in catalogs require `encode_and_count`; a
strict v9/IPFIX user supplies a nonempty all-exact field list. V5 has no strict
catalog because its fixed record necessarily includes lossy/synthesized
conversions.

Canonical-source ambiguity and exporter-introduced loss have separate fixed
counter classes. Only selected fields contribute conversion/loss counters;
unknown and unselected input is not mislabeled as exporter loss.

Canonical-source loss is information already discarded by the pinned
receiver/goflow2 path, such as IN/OUT counter overwrite, an unknown
protocol/EtherType number rendered as a token, or an IPFIX observation-point
value narrowed to protobuf `uint32`. Exporter-introduced loss is only an
accepted matrix-enumerated lossy or synthesized transform, such as a configured
counter-direction choice, representable width narrowing, or timestamp
quantization. Unsupported and inapplicable cells are never downgraded to loss
or omission. The exporter records these classes separately and never claims to
recover canonical-source loss.

Config compilation returns the first error only, with a fixed code, protocol,
static config path, field/shape ordinal, and safe actual/limit counts, capped at
256 bytes. It never includes endpoint, attribute key/value, PEN/IE/type,
template ID, address/MAC/body, or a wrapped raw error. Runtime mapping reasons
are fixed enums within the accepted 16-reason/96-series limit. Template names,
IDs, tokens, custom identifiers, and input values never become metric labels.

Missing required canonical keys, invalid address placeholders (`invalid IP`),
family mismatches, protocol mismatches, and out-of-range values reject that
record for the affected destination. Optional next-hop keys may be omitted only
when they are not selected; selecting either makes it required for every record.
Zero and sentinel values are retained as values; they are never guessed,
replaced, or used to infer protocol, family, sampling mode, or boot time. Any
narrowing, reduced-size encoding, or timestamp conversion is range-checked;
there is no clamp or unchecked truncation; the general profile explicitly floors timestamps to milliseconds. An unsupported or inapplicable field cannot be
compiled into a destination template and is a configuration error regardless
of loss policy.

## Normative sources and verification boundary

The receiver schema and pinned source locations are in
[`receiver-attributes.md`](receiver-attributes.md); the exact protocol token
tables are in [`receiver-token-vocabulary.md`](receiver-token-vocabulary.md);
and protocol identities, classifications, widths, timestamp rules, and
missing-value policy are in [`protocol-mapping.md`](protocol-mapping.md).
Wire authorities are [Cisco v5 header B-3](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006108)
and [record B-4](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006186),
[RFC 3954](https://www.rfc-editor.org/rfc/rfc3954) §§5.1 and 8 (including
verified errata 2096, 2168, and 2979), [RFC
7011](https://www.rfc-editor.org/rfc/rfc7011) §§3.1 and 6.1 (including verified
errata 4396 and 7875), [RFC
7012](https://www.rfc-editor.org/rfc/rfc7012) §§3.1 and 7 (including verified
erratum 3881), and the [IANA IPFIX
registry](https://www.iana.org/assignments/ipfix) (CSV
[source](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv),
last updated 2026-07-22). The focused writer strategy is recorded in
[ADR 0002](../decisions/0002-focused-wire-encoders.md).

Before implementation, reviewers must check v5 offsets against Cisco B-4, all
v9 types against RFC 3954 and its compatible registry, all IPFIX IDs/types/
widths against IANA, calculated field/template/record lengths, receiver token
values against Contrib commit
`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`, and classifications against the
accepted 41-by-3 matrix. Independent TShark fixtures must prove both family
templates, order/width, ordinary sampling IE 34, and no Options output; the
pinned receiver remains a separate semantic oracle.
