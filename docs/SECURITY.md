# Security model

The exporter receives OpenTelemetry log records and configured UDP endpoints at
the Collector boundary. Treat both as untrusted data. Records may contain
pathological lengths, incorrect types, invalid addresses, large attribute maps,
or values that exercise allocation and packing edges.

The component bounds selected field cardinality and encoded length, variable
Information Elements, template and enterprise-field cardinality, packet size,
configured destinations, concurrent work, packet buffers, and telemetry label
cardinality. Traversal and retry-copy work scale with actual input. Valid large
requests are packetized at record boundaries; arbitrary unmapped metadata does
not invalidate an otherwise encodable record.

Failed-subset copying uses the pinned public pdata recursive `CopyTo` API and
retains an extreme-depth stack limitation. Iterative byte detachment preserves
ownership of returned subsets but does not make that recursive operation
unlimited-depth safe. The exporter makes no fixed whole-process RSS claim.

Diagnostics are redacted and bounded. Full flow payloads, credentials, raw
errors, and sensitive address data must not be logged. Formatted receiver
`send_raw` bodies are rejected as input and are not a replay mechanism.

UDP provides local datagram handoff only. It has no confidentiality, peer
authentication, acknowledgement, persistence, automatic retry, or replay
protection. Loss, duplication, and reordering are possible; replaying an
ambiguous subset can duplicate a datagram. Use a trusted network, firewall, or
externally managed secure tunnel when confidentiality or peer identity is
required.

The [operator guide](operator-guide.md),
[component design](design-docs/collector-component.md), and
[implementation verification strategy](design-docs/implementation-verification.md)
define the operational, ownership, and test boundaries.
