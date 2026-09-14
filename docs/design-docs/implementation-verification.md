# Implementation verification strategy

This document describes the current test layers, independent oracles, and
evidence limits for the alpha component. The product contract is in
[`netflow-exporter.md`](../product-specs/netflow-exporter.md); component,
protocol, receiver, and profile contracts are authoritative in the linked
design and compatibility documents.

## Dependency authority

The ordinary baseline is:

```bash
make check test
```

Stateful and concurrent code also runs `go test -race` with the package set and
timeout appropriate to the check. These checks use the normal module graphs,
the nested receiver module, local fixtures, and checked-in scripts.

The implementation baseline is Go `1.26.8`. Collector Core is `v0.160.0` at
commit `cd3455cf3a7f672208140b1ebb1581c542b2b0ed`; stable modules are
`v1.66.0`. The receiver profile is Collector Contrib `v0.160.0` at commit
`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`, using goflow2/v2 `v2.2.6` at
commit `c9824f41bcad11d4490a668ed5270b03056d8217`. The checked-in `go.mod`,
`go.sum`, and nested receiver module locks are dependency authority. Generator
revisions are listed in the [source ledger](../research/source-ledger.md).

Wire semantics come from RFC 3954, RFC 7011, RFC 7012, their verified errata,
Cisco NetFlow Collection Engine Appendix B tables B-3/B-4, and the IANA IPFIX
registry snapshot cited in the ledger.

## Verification layers

| Layer | Required proof | Retained checks |
| --- | --- | --- |
| Wire foundation | Boundary, immutability, allocation, sizing, and preflight checks for caller-buffer cursors and immutable wire contracts. | Unit and fuzz tests under `internal/wire/`. |
| Fixtures and writers | Hash-bound source fixtures, immutable v5/v9/IPFIX datagrams, independent offset/width calculations, malformed/boundary tests, and no golden rewriting during ordinary tests. | Canonical fixtures, golden manifest, writer tests, and TShark checks. |
| Normalization | Incremental processing of large supported requests, exact receiver schema, type/range/address checks, raw-body rejection, cancellation, and pdata ownership. | `internal/normalize/`, root request tests, and receiver fixtures. |
| Mapping | Explicit profile/field selection, 123-cell coverage, loss policy, bounded custom mappings and template shapes, and checked PMTU arithmetic. | `internal/mapping/`, compatibility tables, and mapping manifest. |
| Destination and transport | Protocol-correct sequence/template state, bounded packing, full-datagram commit semantics, DNS/UDP failures, instance isolation, and cancellation-safe lifecycle. | `internal/destination/`, `internal/transport/`, race and lifecycle tests. |
| Collector component | Public Collector APIs, generated metadata, bounded admission, large-request packetization, failed subsets, bounded telemetry, lifecycle, and isolation. | Root exporter tests, generated checks, and OCB operator example. |
| Receiver semantics | A nested read-only Contrib NetFlow receiver consumes emitted v5/v9/IPFIX and yields documented normalized semantics. | `integration/receiver/`; this is a semantic oracle, not a wire oracle. |
| Independent wire interoperability | Byte-bound immutable and live UDP payloads; independent decoder proves headers, templates, field IDs/widths/values, sequence, lengths, padding, and checksums. | Digest-locked TShark runner and golden/live capture checks. |
| Hardening | Large-input, malformed-input, fuzz, race/lifecycle, ownership, leak, and telemetry checks. | `scripts/`, integration tests, and the acceptance record. Fixed whole-process RSS qualification remains unclaimed. |

A self-roundtrip never substitutes for independent wire decoding. TShark never
substitutes for receiver semantics or Collector lifecycle tests.

## Fixture and hostile-input contract

`integration/testdata/canonical/fixtures.json` is the authored source for the
canonical IPv4 record, explicit-zero cases, IPv6 family, optional next-hop and
BGP-next-hop cases, and the two-rate ordinary IE/type 34 case. The golden
manifest binds each protocol payload to those fixtures.

Current tests cover at least 65,537 valid records and a request above the former
aggregate logical-byte ceiling, with irrelevant unmapped metadata. They assert
that every valid record is accounted for across complete datagrams, exact-fit
and one-beyond encoding boundaries are handled, and v5 retains its 30-record
maximum. These are positive acceptance cases, not rejection budgets. Mapped
size policies are checked against actual field representation and record,
message, Set, and path fit.

Tests also cover all six UDP `{n,error}` outcomes, address-family mismatches,
time/origin boundaries, sequence wrap, missing/zero values, wrong OTel types,
bad UTF-8, noncanonical addresses, and raw receiver bodies. Rejection never
clamps, truncates, panics, logs sensitive values, or partially commits state.

The receiver time regression tests are intentionally retained: they exercise
receiver-produced `flow.start`/`flow.end` and exporter output independently.
The completed audit covers 15 receiver-produced cases, 67 valid outputs, and
six expected non-millisecond rejects. The exporter preserves those projected
times; it does not infer source timestamp provenance.

## Independent TShark oracle

TShark `v4.6.8`, source commit
`e677bf052328efc1ed897a547fa161836a0e4ff7`, is the independent decoder.
`integration/tshark/IMAGE_DIGEST` and `integration/tshark/source.lock` lock the
test dependency. The runner requires rootless Podman and the exact digest-
qualified image with `--pull=never`, verifies image identity, runs without
network or host credentials, accepts only regular non-symlink fixtures, and
enforces bounded resources and output.

For v5, v9, and IPFIX, the oracle proves protocol/header values, template and
data records, lengths, field order and widths, padding, sequences, and
timestamps. V9/IPFIX exercise both address families and ordinary four-byte
type/IE 34 values `1000` then `2000` with no Options records. Outer packet
checks include IP/UDP lengths and a nonzero valid IPFIX UDP checksum. The
pinned receiver separately proves normalized semantics.

## Collector integration and hardening

The component is exercised through public Collector APIs and a runnable custom
Collector Builder distribution. The OCB smoke routes receiver logs through the
exporter, captures live v5/v9/IPFIX datagrams, checks shutdown, and submits the
same bytes to the TShark oracle. Generated binaries and captures are test
outputs, not tracked source.

Fuzzing covers admission, normalization, mapping, template/catalog state,
packing, and all three writers. Race tests cover publication, DNS, sends,
shutdown, and instance isolation. Load and leak runners use explicit timeouts
and bounded local resources. Additional working memory, ownership, and leaks
remain reviewable component concerns; fixed RSS targets are deferred
qualification and do not force permanent rejection of representable data.

## Acceptance boundary

The retained evidence supports these claims:

1. Receiver-compatible logs normalize, map, and packetize through the generic
   exporter, including large supported requests.
2. IPFIX, NetFlow v9, and representable NetFlow v5 records transmit over UDP.
3. Sequence, template, refresh, DNS, failure, and shutdown behavior pass
   deterministic and race tests.
4. Each protocol has immutable-golden and independent TShark evidence.
5. The pinned receiver semantic roundtrip and local OCB Collector smoke pass.
6. Affected malformed-input, fuzz, ownership, leak, telemetry, and isolation
   checks meet the current component criteria.
7. Configuration and operator documentation describe the implemented behavior.

These claims are bounded to the pinned Linux/amd64 environment and local
checks. They do not establish remote delivery, appliance ingestion, physical
NIC behavior, hosted CI execution, cross-architecture support, a capacity
limit, or a production SLA.
