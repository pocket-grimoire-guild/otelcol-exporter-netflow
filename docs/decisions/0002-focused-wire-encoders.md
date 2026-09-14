# ADR 0002: Focused project-owned NetFlow/IPFIX wire encoders

- Status: accepted
- Date: 2026-09-02
- Owners: project

## Context

The exporter must emit NetFlow v5, NetFlow v9, and IPFIX from the immutable
[`contrib-netflowreceiver-v0.160.0`](../compatibility/receiver-attributes.md)
41-field profile. The accepted conversion policy requires explicit loss and
range handling, static template shape, enterprise mapping, and protocol-specific
timestamp semantics; it forbids silent coercion, clamping, truncation, or
recovery of discarded receiver provenance. Wire bytes must be deterministic,
bounded, and independently decoded. Sequence numbers, template refresh and
expiry, observation-domain/source identity, packet packing, transport, and
lifecycle are destination concerns, not record semantics.

The [source ledger](../research/source-ledger.md) records primary-source
anchors and bounded local observations.
Released goflow2/v2 `v2.2.6` is decoder-only. Goflow2 main at
`6dee964c38ee5f6b04a38681d069427c28ee5cb3` adds all three encoders but is an
unreleased `/v3` main commit; the probe found missing v5 count checks, wrapped
oversize v9/IPFIX lengths, omitted v9 PEN identity, and no cross-message state.
VMware go-ipfix `v0.18.0` is released and bounded, but IPFIX-only, lacks the
required nanosecond IE value path, and couples state to its process/transport.
Its absent Options Template surface matters only if a selected static shape
requires one. Zoomoid is IPFIX-only and its pinned README describes a
one-person project with no practical deployment. nl6 `v0.28.0` is an Apache
licensed simulator executable with useful reference encoders, not a reusable
module; its IPFIX sequence policy and fixed synthetic data model do not match
the RFC/mapping contract.

## Decision

Implement three focused, project-owned pure wire writers: one each for v5, v9,
and IPFIX, behind a small checked packet-writing contract. Use standard-library
binary primitives and caller-owned output buffers. A writer receives already
normalized values and an explicitly selected static template shape; it returns
an error before writing when field widths, variable-length markers, set/message
lengths, record counts, or the caller's buffer budget cannot represent the
request.

Keep destination-owned state outside the writers: sequence counters, template
catalog and refresh/expiry decisions, observation-domain/source identity,
record batching and MTU budget, DNS/UDP/retry behavior, and Collector lifecycle.
Writers are deterministic for the same inputs and do not read wall clock,
network state, or mutable global state. Initial support includes statically
compiled templates, explicitly configured IPFIX enterprise PEN/IE/type/length,
opt-in NetFlow v9 private numeric fields, RFC timestamp encodings, and bounded
variable-length elements. No initial library dependency or fork is adopted;
the screened projects remain reference material and independent test subjects.

Sampling-rate handling follows the receiver/protocol evidence in the
[compatibility matrix](../compatibility/protocol-mapping.md): no selected
initial v9/IPFIX static shape requires Options Templates or Options
Data; ordinary v9 type 34 and IPFIX IE 34 are emitted in Data Templates. Any
future scoped Options support requires a new decision and does not add a
capability to a screened library candidate.

This ADR selects a strategy, not an implementation. It does not assert that a
focused writer exists, is wire-correct, or is ready for production.

## Alternatives considered

* **Released goflow2/v2 `v2.2.6`:** rejected because the pinned tree contains
  decoders/producers but no flow-wire encoder.
* **Unreleased goflow2 main `/v3`:** rejected as a production dependency because
  it has no release pin and the probe found unchecked v5 counts, wrapped 16-bit
  lengths, v9 PEN loss, caller-only state, and five allocations on the narrow
  v9 path. It remains useful source/probe evidence.
* **VMware go-ipfix `v0.18.0` plus project v5/v9 writers:** rejected as the
  initial mixed strategy. It is IPFIX-only and lacks the required nanosecond IE
  value path. Its absent Options Template surface would block only selected
  static shapes that require one; independently, its process-owned
  transport/state would require an adapter that recreates the destination
  boundary. Its narrow reusable-buffer probe measured zero allocations, but
  that does not offset the semantic/API mismatch.
* **Zoomoid go-ipfix `v0.4.1`:** rejected as an all-protocol solution because it
  is IPFIX-only; its broad generic data model, optional caches, and limited
  maintenance/deployment evidence would still require a substantial adapter.
* **nl6 `v0.28.0`:** rejected as a dependency because it is a `package main`
  simulator with synthetic fixed fields and application-owned state. Its source
  tests are useful fixtures, not an independent exporter oracle.
* **Fork or extract a candidate:** rejected initially. Correcting bounds,
  timestamps, templates, and state boundaries would leave this project owning
  the difficult protocol work plus a foreign data model and fork maintenance.

## Consequences

The project owns protocol correctness, release maintenance, and the cost of
three small encoders, but can keep protocol semantics independent of Collector
and transport changes. Destination isolation is explicit, hostile records can
be rejected before allocation, and allocation behavior can be benchmarked with
reusable buffers. Each protocol needs its own golden packets, malformed-input
tests, fuzz target, race coverage for the surrounding state layer, and an
independent decoder/collector check. Self-round trips through the same writer
and decoder are not sufficient. Library improvements may be tracked as research
or upstream contributions without entering the production dependency graph.

## Implementation constraints and non-goals

* Validate all counts, set/message length sums, template field lengths,
  variable-length prefixes, timestamp ranges/precision, and MTU budgets before
  narrowing or allocating. Reject unsupported/mismatched values; never clamp,
  truncate, infer a PEN/family/boot epoch, or copy inbound sequence/domain state.
* Keep v5's fixed 30-record limit, v9 template/options/padding rules, and IPFIX
  sequence/timestamp/enterprise rules explicit in tests and mapping docs.
* Preserve unknown input attributes outside configured extraction; do not create
  dynamic templates or unbounded field/cardinality state.
* This ADR does not decide Collector package layout, configuration, queueing,
  retry policy, or raw-message passthrough; each requires a separate design.

## Reconsideration criteria

A library or fork can be proposed only by a superseding ADR backed by an
immutable released version (or a demonstrably supportable mixed strategy),
all-three-protocol coverage or a simpler proven split, checked count/length and
MTU behavior, required templates/enterprise/timestamp/variable-length support,
explicit state/lifecycle fit, license and maintenance review, allocation data,
malformed-input fuzz/race results, and independent TShark/golden interoperability
for every advertised protocol. A failed criterion keeps this decision in force.

## Evidence

* [Primary-source and tool-version ledger](../research/source-ledger.md)
* [Independent TShark oracle and local checks](../design-docs/implementation-verification.md)
