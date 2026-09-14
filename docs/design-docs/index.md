# Design documents

| Document | Scope | Accepted decisions |
| --- | --- | --- |
| [`collector-component.md`](collector-component.md) | Collector factory/config, bounded input wrapper, lifecycle, errors, telemetry, and custom distribution | ADR 0003 |
| [`protocol-state-transport.md`](protocol-state-transport.md) | Destination-local sequence/template/clock/DNS/UDP state, packing, and failure transitions | ADR 0004 |
| [`implementation-verification.md`](implementation-verification.md) | Local implementation checks, independent goldens/TShark, receiver roundtrip, Collector smoke, and race/fuzz/leak/load hardening | Current verification strategy |

The receiver schema and per-protocol field mapping live in `compatibility/`.
Encoder research and upstream receiver candidates live in `research/`.
Verification requirements are accepted design authority; unfinished component
and integration results are described by the verification strategy and acceptance record.

Do not treat an unreviewed design document as approval. Consequential accepted
choices are recorded in `decisions/`.
