# ADR 0005: Immutable static export profiles and explicit mappings

- Status: accepted
- Date: 2026-09-03
- Owners: project

## Context

The exporter consumes one pinned receiver schema,
`contrib-netflowreceiver-v0.160.0`, consisting of 41 canonical attributes.
Collector Contrib `v0.160.0` is fixed at commit
[`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver)
and its resolved goflow2/v2 `v2.2.6` source at commit
[`c9824f41bcad11d4490a668ed5270b03056d8217`](https://github.com/netsampler/goflow2/tree/c9824f41bcad11d4490a668ed5270b03056d8217).
The receiver retains lookup tokens and drops some numeric provenance, while the
three wire protocols have different field identities, widths, families,
timestamps, and direction semantics. The [receiver-to-protocol conversion
matrix](../compatibility/protocol-mapping.md) therefore marks conversions as
exact, lossy, synthesized, unsupported, or inapplicable; several cells need an
operator-selected target.

The implementation-blocking ambiguity was an empty mapping that supposedly
selected a documented protocol default without naming which order, target,
width, transform, family variant, or loss acknowledgement that meant. Hidden
defaults would make identical input depend on an undocumented implementation
choice and could silently endorse source ambiguity or exporter-introduced loss.
Dynamic per-record templates would also make IDs, memory, and wire output
dependent on hostile input. The [compatibility profile contract](../compatibility/default-profiles.md)
resolves these boundaries; this ADR records the durable choice.

## Decision

Publish immutable, versioned static export profiles and require explicit mapping
objects. The initial built-in catalogs are documented in
[`default-profiles.md`](../compatibility/default-profiles.md):

* `contrib-netflowreceiver-v0.160.0/netflow-v5-fixed-v1`
* `contrib-netflowreceiver-v0.160.0/netflow-v9-core-v1`
* `contrib-netflowreceiver-v0.160.0/ipfix-core-v1`

An identifier names the exact receiver schema, output protocol, and catalog
version. Its field order, target, width, transform, family variants, and
template ordinals are immutable. A future catalog receives a new `-vN`
identifier; an existing identifier is never silently reinterpreted.

Configuration selects exactly one nonempty `mapping.profile` matching the
schema/protocol or one nonempty ordered `mapping.fields` list. The two selectors
cannot coexist, and absent differs from an explicit empty list. Unknown or
schema/protocol-mismatched profiles, empty or missing selectors, and scalar
field entries fail validation. `mapping.fields` replaces a profile rather than
extending it. NetFlow v5 permits only its fixed catalog; v9 and IPFIX may append
the closed `mapping.custom` grammar after canonical fields.

Every field object has the exact `canonical` key and, only for the documented
ambiguous matrix cells, an allowed `target`. Arbitrary numeric IDs, names,
widths, aliases, and first/last-wins resolution are forbidden. The v9
`flow.icmp_type_code` composite is the sole initial virtual selector and has
explicit IPv4/protocol-map gates. Duplicate wire identities are rejected after
profile expansion. Selected fields and optional next-hop presence are compiled
into finite family shapes before socket creation; records choose only a
precompiled shape. IDs, field counts, template bytes, custom mappings, PENs,
and datagram sizes are checked with widened arithmetic against the published
limits.

There is no hidden mapping or loss policy. `createDefaultConfig` leaves profile,
fields, token sequences, input guarantees, and `mapping.loss_policy` unset.
`mapping.loss_policy` is pointer-valued and required; absent, empty, or unknown
values fail. Built-in catalogs explicitly require `encode_and_count`.
`reject` is available only to an explicit all-exact v9/IPFIX field list. Token
and provenance sequences are explicit bounded sequences; they never merge with
hidden values. Custom sources are exact top-level keys with declared OTel input
types and closed fixed/variable encodings; no coercion, padding, truncation,
or dynamic discovery is allowed. Full grammar, limits, and loss/error classes
are normative in [`default-profiles.md`](../compatibility/default-profiles.md).

## Why this choice

Immutable profile identity makes wire shape and semantic policy reproducible
across restarts, versions, tests, and independent decoders. Explicit objects
make ambiguous choices visible at configuration time: for example, direction
for counters, IP-version versus EtherType, pre/post MAC identity, and the v9
ICMP composite. Requiring the loss acknowledgement prevents a permissive
runtime default from turning canonical-source ambiguity into an unreviewed
exporter promise. Static shape compilation bounds IDs, allocations, cardinality,
and template churn before hostile records reach the writer. These properties
align with the focused, deterministic, caller-buffered writers selected by
[ADR 0002](0002-focused-wire-encoders.md).

## Consequences

* Operators can audit a profile's complete ordered fields, identities, widths,
  transforms, family variants, record/template sizes, and loss policy from one
  versioned artifact. A configuration fingerprint can identify the exact shape.
* Validation can reject inactive maps, unsupported targets, collisions,
  missing provenance, and impossible limits before socket creation. Alternating
  records cannot create new template IDs, shapes, caches, or labels.
* The configuration is deliberately verbose: operators must acknowledge loss,
  provide active token pairs, and choose targets for ambiguous fields. There is
  no automatic receiver-version detection, IANA/name recovery, or latest
  profile alias.
* Built-in v5 remains fixed and cannot be extended. v9/IPFIX custom fields are
  finite, explicitly typed, required, and appended in order. Unsupported or
  inapplicable selections fail configuration; a missing or invalid selected
  runtime value rejects the record and is never silently omitted as loss.
* Receiver or protocol evolution requires a new profile identifier and a
  migration decision. Existing configurations do not silently change wire
  output, but the project must maintain documentation and tests for each
  identifier it continues to advertise.

## Alternatives considered

* **Empty mapping selects a protocol default:** rejected. It hides lossy target
  choices and makes output depend on undocumented order or implementation
  details.
* **Mutable profile names or a `latest` alias:** rejected. Receiver revisions,
  registry changes, and wire-shape edits would silently alter an existing
  configuration; immutable `-vN` identities make upgrades deliberate.
* **Scalar strings, numeric IDs, or implicit first/last-wins field selection:**
  rejected. They cannot represent the required target/provenance distinctions
  and invite aliases, collisions, and silent reinterpretation.
* **Dynamic templates or record-discovered attributes:** rejected. They permit
  hostile input to create unbounded IDs, state, templates, and allocations and
  cannot provide deterministic independent verification.
* **Require a complete field list for every configuration:** rejected for the
  initial surface. Named built-ins provide reviewed common shapes while the
  explicit list remains available for strict or specialized v9/IPFIX output.

## Supersession and upgrade policy

This ADR remains in force until a later accepted ADR explicitly supersedes it.
Changing any existing profile's schema identity, field order, target, width,
transform, family variants, template ordinals, custom limits, or loss behavior
requires a new profile identifier and a new compatibility artifact; it is not an
in-place edit. A receiver/dependency revision requires a schema diff (names,
OTel types, source widths, units, presence, and sentinels) plus populated,
empty, raw, and unknown/custom fixtures before a new profile can be accepted.

A superseding ADR must preserve explicit selector semantics and bounded static
shape/ID behavior, cite immutable protocol/registry and receiver sources, state
why the prior profile cannot remain sufficient, and provide independent
golden/decoder evidence for every advertised protocol and family. Until those
criteria are accepted, the current identifiers and this decision remain the
compatibility contract. Removing an old identifier or changing its support
window also requires an explicit accepted decision; no upgrade may silently
rewrite existing operator configuration.

## Evidence

* [Static export profiles and mapping grammar](../compatibility/default-profiles.md)
* [Canonical receiver-compatible log contract](../compatibility/receiver-attributes.md)
* [Receiver network token vocabulary](../compatibility/receiver-token-vocabulary.md)
* [Receiver-to-protocol conversion matrix](../compatibility/protocol-mapping.md)
* [ADR 0002: Focused project-owned wire encoders](0002-focused-wire-encoders.md)
