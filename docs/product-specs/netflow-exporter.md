# NetFlow/IPFIX exporter product specification

Status: accepted product contract, amended on 2026-09-08.
The wire, mapping, destination and Collector integration work has recorded
evidence in the retained tests and local acceptance record. The [acceptance matrix](../mvp-acceptance.md)
records the demonstrated behavior, checks and remaining pinned-API, transport,
time-range and platform limits.

## Purpose

Provide an OpenTelemetry Collector exporter that consumes flow records carried
as OpenTelemetry logs in the schema produced by the Contrib NetFlow receiver and
emits standards-conforming NetFlow or IPFIX messages to external collectors.

The exporter is generic in the sense that destinations and wire protocol are
configurable and the mapping architecture can grow. Receiver-compatible records
are the normative initial input. Raw-message passthrough or replay is deferred.

## Initial protocol scope

- IPFIX over UDP
- NetFlow v9 over UDP
- NetFlow v5 over UDP
- sFlow is out of scope
- TCP/SCTP/TLS transport is deferred and unsupported by the initial profile

The implementation uses shared checked wire foundations and canonical fixtures,
then independently reviewable NetFlow v5, NetFlow v9, and IPFIX writers. Each
advertised protocol has independent checks in the retained test suite.

## Input contract

A log record represents one flow. Canonical fields are extracted from the log's
attributes using the immutable
[`contrib-netflowreceiver-v0.160.0`](../compatibility/receiver-attributes.md)
profile. Canonical attributes are authoritative; resource and scope data remain
provenance, duplicate record timestamps are not fallbacks, parsed-mode bodies
are empty, and formatted `send_raw` bodies are rejected as unsupported input.

The exporter must define behavior for:

- missing required fields;
- accepted integer and address representations;
- overflows and negative values;
- unsupported attributes;
- receiver-version schema changes;
- user-defined mappings or enterprise Information Elements;
- raw receiver records when `send_raw` was enabled.

No implicit conversion may silently change meaning or truncate a value.

### Large requests and record validity

An OTel request is not a single wire message. Supported, representable flow
records must be processed incrementally into as many complete datagrams as
required. The default/hard 8,192/65,536-record and 16/64 MiB logical-input
ceilings have been removed; they were implementation policies, not protocol limits. Size,
depth, keys or entry counts in unmapped metadata must not arbitrarily invalidate
otherwise encodable flows. Preserve metadata required by input ownership and
partial-failure returns.

Enforce actual field representations, complete message/Set lengths and the
configured transport/path budget, including v5's 30-record datagram maximum.
Flush full packets and continue with valid records. A single record that cannot
fit or be represented receives a precise record-local error; values must not be
truncated or records fragmented across messages. Review mapped-value policies,
including the 4,096-byte variable-field cap, against actual encoding constraints.

Keep bounded concurrent work and packet buffers, cancellation and accurate
ambiguous/unsent subsets. Temporary resource pressure is distinct from permanent
invalid data. The historical fixed RSS targets are deferred qualification; they
must not dictate record acceptance. The normative amendment, protocol sources
and focused completion checks are in
[component design](../design-docs/collector-component.md) and
[verification strategy](../design-docs/implementation-verification.md), which
supersede conflicting admission/memory requirements in older drafts. The retired
root `limits` configuration is removed. Extreme-depth failed-subset
copying retains the pinned pdata recursive CopyTo limitation documented in the
component ownership contract.

## Output contract

For each destination, configuration selects a protocol and transport settings.
The exporter produces valid messages with correct headers, lengths, template
references, sequence semantics, source/observation-domain identity, timestamps,
and field encoding.

For every canonical field, the compatibility matrix must say whether conversion
is exact, lossy, synthesized, unsupported, or protocol-inapplicable.

The accepted [123-cell protocol matrix](../compatibility/protocol-mapping.md)
and [static export profiles](../compatibility/default-profiles.md) define those
outcomes. Configuration must select a profile or explicit nonempty field list;
there is no hidden mapping default.

## Operational behavior

The component must:

- integrate with current Collector exporter lifecycle and configuration APIs;
- support multiple isolated destinations as separate named exporter instances;
- expose bounded-cardinality telemetry for accepted, encoded, dropped, invalid,
  lossy, and failed records/messages;
- avoid panics on malformed input;
- honor Collector shutdown and context cancellation;
- document delivery semantics for UDP;
- make template refresh and restart behavior predictable.

## Deferred passthrough

A future mode may replay raw NetFlow/IPFIX payloads preserved by the receiver.
It is not assumed to be equivalent to normal encoding and must have a separate
security and compatibility design.

## Initial acceptance milestone

The exporter MVP is complete when:

1. The canonical receiver schema is versioned and tested.
2. Each advertised protocol has independently decoded golden output.
3. Supported mappings and losses are documented.
4. Stateful protocol behavior passes race and deterministic lifecycle tests.
5. Large valid requests pass protocol-based acceptance; malformed-input, load,
   fuzz, lifecycle, and memory-ownership checks meet the current component criteria.
   Deferred whole-process RSS qualification is not an MVP gate or a claimed pass.
6. A custom Collector distribution demonstrates end-to-end export.

The exact local checks and independent-oracle requirements are specified in the
accepted [implementation verification strategy](../design-docs/implementation-verification.md).
