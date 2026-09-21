# Alpha compatibility and upgrade contract

This is the public compatibility summary for the unpublished alpha source and
module candidate. It describes the supported parsed input and the wire
profiles that have local evidence. The complete field and conversion
contracts remain in the [receiver schema](receiver-attributes.md),
[token vocabulary](receiver-token-vocabulary.md),
[protocol matrix](protocol-mapping.md), and [profile catalog](default-profiles.md).

## Supported boundary

The component is a Go logs exporter with public `netflowexporter.NewFactory()`.
It is built into a custom Collector; installing a stock Collector does not add
this exporter. The locally qualified user path is Linux/amd64 with Go
`1.26.8`, OCB `v0.160.0`, Collector Core `v1.66.0` and beta Collector modules
`v0.160.0`, including the pinned `netflowreceiver v0.160.0`. The
[versioned consumer recipe](../../distribution/ocb/consumer/README.md) uses
`v0.1.0-alpha.1` only as synthetic local staging for `check-consumer.sh`; the
alpha is unpublished and must not be described as publicly fetchable. Existing
public tag `v0.1.0` remains at the earlier public baseline, while the current
source fixes are untagged.

The only input schema is
`contrib-netflowreceiver-v0.160.0`. It supplies 41 canonical flow keys: 39
required keys and two optional address keys, `flow.next_hop` and
`flow.bgp_next_hop`. See the linked receiver contract for the complete key list.

`Timestamp` and `ObservedTimestamp` are log-envelope metadata in the receiver
contract, not additional flow keys and not fallbacks for `flow.start` or
`flow.time_received`. Parsed attributes are authoritative. Formatted
`send_raw` bodies, arbitrary flow-log schemas, and inferred receiver-version
metadata are unsupported. A receiver upgrade needs a field, type, unit,
presence, sentinel, and fixture review; changed schema semantics require a new
profile. A dependency upgrade alone does not redefine the schema.

## Protocol and profile choices

All three protocols remain supported over one connected UDP destination per
named instance.

| Protocol | Recommended profile | Upgrade and time boundary |
| --- | --- | --- |
| NetFlow v5 | `contrib-netflowreceiver-v0.160.0/netflow-v5-fixed-v1` | Fixed IPv4 48-byte records, no templates. `flow.next_hop` must be present and IPv4, and the mapping must assert `mapping.input_guarantees.flow_io_bytes: layer3_total_octets`. The configured origin and 32-bit millisecond uptime create an approximately 49.71-day lifetime; there is no rollover. |
| NetFlow v9 | `contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1` | Timed IPv4/IPv6 records are 51/75 bytes and require an explicit `uptime_origin`. The 32-bit millisecond uptime creates the same approximately 49.71-day lifetime and exhaustion is latched. `netflow-v9-core-v1` is the explicit time-free legacy layout (43/67-byte records). |
| IPFIX | `contrib-netflowreceiver-v0.160.0/ipfix-general-v1` | Recommended general output uses Unix-millisecond IE 152/153 values, with 72/96-byte IPv4/IPv6 records. `ipfix-core-v1` is the explicit legacy NTP layout and retains its era-zero boundary in 2036. |

The recommended timed profiles re-encode measured `flow.start` and `flow.end`.
Another producer may construct this exact receiver-compatible representation
without being the literal Contrib receiver or carrying its scope identity, but
acceptance cannot attest measured-time, sampling, or other field provenance.
For the supplied receiver pipeline, the deployment must attest that original
source templates carried measured times and that the receiver preserved them; another
producer must establish its own field semantics and provenance. The exporter
cannot detect receipt or export-time fallback. It does not use log timestamps
or envelope metadata as a repair. IPFIX general time is floored to milliseconds
after canonical ordering checks. Deployments must ensure IPFIX flow end is no
later than export time; the exporter does not enforce that relation. V9 header
seconds discard the fractional export second, which can shift reconstructed
absolute times by less than one second. Header export seconds are also bounded
by their protocol width.

Select exactly one nonempty profile or one nonempty ordered `mapping.fields`
list and set `mapping.loss_policy`. Built-in profiles require the explicit
`encode_and_count` acknowledgement. Mapping selection is not inferred from
`flow.type`, address family, resource metadata, scope metadata, or the
destination endpoint. Use fresh template IDs when a v9/IPFIX layout changes;
the complete example uses 300/301. A restart creates an in-memory protocol
epoch and does not invalidate every downstream template cache.

`protocol_identifiers` is an explicit sequence of exact receiver token and
uint8-number pairs. There is no case folding, aliasing, numeric-string
conversion, IANA lookup, or reverse lookup; `unknown` cannot be configured.
`network_type_versions` is a separate explicit map and accepts only `ipv4:4`
and `ipv6:6`. The v5 fixed profile requires IPv4 source, destination, and
next-hop values. Other profiles apply their documented family and width gates.
Missing required values, invalid addresses, protocol or family mismatches,
and timestamp or width failures reject that record. Unsupported or inapplicable
selected arms fail configuration. The `encode_and_count` policy accepts only
documented supported exact, lossy, or synthesized transformations; only selected
lossy or synthesized transformations contribute exporter loss. A valid unselected
field contributes no mapping or loss count merely because it is absent from
output. See the [loss contract](default-profiles.md#loss-errors-and-diagnostics).
The normalization-optional next-hop keys are not optional selected output slots:
selecting one requires its value and descriptor family/width checks, and v5
always selects an IPv4 next hop. Values are not clamped or silently truncated.

## Sampling, delivery, and results

`flow.sampling_rate` maps to the ordinary static profile field where selected.
The exporter does not promise Options sampling caches, general renormalization,
or a reconstructed original device identity. IPFIX ordinary IE 34 remains
decodable in the built-in shape; it is not silently replaced with IE 305.
Consumer scaling, Cisco Secure Network Analytics ingestion/storage, and
sampled-counter behavior are unverified. No proprietary consumer certification
is implied.

An OTel request is packetized at complete record boundaries. There is no
request-wide record, byte, metadata-size, or metadata-depth admission ceiling;
actual field, complete-message, Set, UDP payload, path, and per-message limits
still apply. Valid siblings continue when another record is permanently
unrepresentable. Large requests therefore produce as many datagrams as their
records require.

UDP full-write success means local kernel handoff only. Datagrams can be lost,
duplicated, or reordered. The exporter supplies no acknowledgement,
automatic retry, persistent queue, batching queue, congestion shaping,
encryption, or peer authentication. Collector queue and retry settings are
rejected. A transient failure returns only the ambiguous packet and valid
unsent suffix; retrying it can duplicate a datagram that may already have
arrived.

Mixed-result behavior is deliberate. Permanently invalid records are dropped
for the affected destination; valid siblings can complete and `ConsumeLogs`
can return nil when all valid records finished. If all records are invalid it
returns a redacted permanent error. The Collector helper reports failure using
the original request count, while exporter-local confirmed, invalid,
ambiguous, and unsent counters describe the actual protocol outcome. These
metrics are not interchangeable.

Work ledgers, failed-subset copies, and packet work scale with input size.
The pinned pdata API recursively copies nested values when a failed subset is
returned, so an extreme nesting depth can exhaust the stack. The parsed
receiver normally supplies a closed flow shape, but a processor or other
producer can admit attacker-controlled pdata. No unlimited-depth or fixed
whole-process memory claim is made.

## Upgrade procedure

1. Pin the exporter, Collector Core/Contrib, receiver schema, and Go toolchain
   together. Do not assume that a receiver version can be inferred at runtime.
2. Compare the [receiver contract](receiver-attributes.md) with the new
   receiver's names, OTel types, units, presence rules, sentinels, and
   timestamp behavior. Populate, empty, raw, and unknown/custom fixtures are
   required before accepting a new profile.
3. Keep the old profile identifier for its old wire layout. Add a versioned
   profile for a changed field order, width, transform, family variant, or
   presence gate. Do not silently reinterpret an existing profile name.
4. Re-check explicit token and family maps, measured-time provenance, v5/v9
   origin lifetime, sampling semantics, message/path budgets, and partial
   failure metrics. Allocate fresh template IDs for a changed v9/IPFIX layout.
5. Rebuild the pinned custom Collector and run the recipe's validation and
   synthetic flow checks. Inspect the selected local UDP output with an
   independent decoder where wire behavior changed. A successful socket write
   still does not establish remote receipt.

For operational configuration, including complete environment values,
origins, mapping examples, refresh intervals, and result counters, use the
[operator guide](../operator-guide.md). The current default template refresh
is ten minutes; an explicit 30-second option is supported when a consumer
needs faster template learning and increases template traffic.
