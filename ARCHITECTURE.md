# Architecture

This file is the high-level map. Detailed design belongs in
`docs/design-docs/`; accepted architectural decisions are in `docs/decisions/`.

## Component boundary

The exporter accepts OpenTelemetry log records using the canonical schema
emitted by the OpenTelemetry Collector Contrib NetFlow receiver. It validates
and maps those records into protocol-neutral internal flow records, then
encodes and transmits NetFlow v5, NetFlow v9, or IPFIX messages according to
destination configuration.

```text
OTel logs
  -> schema extraction and validation
  -> canonical internal flow model
  -> protocol mapping and loss accounting
  -> template/state manager (v9/IPFIX)
  -> message packing / MTU policy
  -> transport and destination state
  -> self-telemetry
```

The detailed package and lifecycle design is in
[`collector-component.md`](docs/design-docs/collector-component.md); protocol
state and transport are in
[`protocol-state-transport.md`](docs/design-docs/protocol-state-transport.md).
The receiver and wire contracts live under [`docs/compatibility/`](docs/compatibility/).
The implementation and interoperability boundary is summarized in the
[verification strategy](docs/design-docs/implementation-verification.md).

## Non-goals

- Byte-for-byte replay of raw incoming datagrams
- sFlow export
- Collector Contrib inclusion as part of this alpha component
- An undocumented generic attribute-to-Information-Element free-for-all
- Encoding based solely on a decoder library's inverse assumptions
