# Primary-source and tool-version ledger

This concise ledger records the external sources and pinned tools behind the
component's current contracts. Classifications distinguish primary-source
facts, repeatable local observations, project inferences, and open evidence
limits. Links use immutable revisions where the source exposes them.

## Collector and receiver dependencies

| Surface | Pin and source anchors | Contract used here |
| --- | --- | --- |
| Collector Core | `v0.160.0`, commit [`cd3455cf3a7f672208140b1ebb1581c542b2b0ed`](https://github.com/open-telemetry/opentelemetry-collector/tree/cd3455cf3a7f672208140b1ebb1581c542b2b0ed), [`versions.yaml`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/versions.yaml), [`go.mod`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/go.mod) | Stable modules are `v1.66.0`; beta modules are `v0.160.0`. Public exporter, consumer, and helper APIs are selected from this revision. |
| Collector Contrib NetFlow receiver | `v0.160.0`, commit [`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver), [README data format](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/README.md#data-format), [`parser.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L216-L301) | Supplies the versioned 41-key parsed schema. Integer values are OTel `int64`; `next_hop` and `bgp_next_hop` are conditional on valid addresses; parsed timestamps and scope provenance are preserved as documented. |
| Receiver dependency | goflow2/v2 `v2.2.6`, commit [`c9824f41bcad11d4490a668ed5270b03056d8217`](https://github.com/netsampler/goflow2/tree/c9824f41bcad11d4490a668ed5270b03056d8217), [`go.mod`](https://github.com/netsampler/goflow2/blob/c9824f41bcad11d4490a668ed5270b03056d8217/go.mod), [decoder tree](https://github.com/netsampler/goflow2/tree/c9824f41bcad11d4490a668ed5270b03056d8217/decoders) | Supplies the receiver's v5/v9/IPFIX decoder and projection behavior. The receiver's v2 dependency is distinct from any unreleased v3 encoder work. |
| OCB and metadata generator | `go.opentelemetry.io/collector/cmd/builder@v0.160.0` and `go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0`, Core commit above; [Builder README](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/cmd/builder/README.md), [mdatagen README](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/cmd/mdatagen/README.md) | Generates the custom Collector and checked-in metadata outputs from authored `metadata.yaml`. Generated files are not hand-edited. |

The Go module locks in this checkout remain the executable dependency authority;
the links above explain the selected API and schema revisions.

## Protocol authorities

| Authority | Relevant contract |
| --- | --- |
| [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954.html) and [verified errata](https://www.rfc-editor.org/errata/rfc3954) | NetFlow v9 packet/header, FlowSet, template, data, options, and field definitions. Errata 2096, 2168, and 2979 are treated as verified requirements. |
| [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011.html) and [verified errata](https://www.rfc-editor.org/errata/rfc7011) | IPFIX message, sequence, field specifier, template, encoding, transport, and security semantics. Verified errata 4396 and 7875 are retained. |
| [RFC 7012](https://www.rfc-editor.org/rfc/rfc7012.html) and [verified errata](https://www.rfc-editor.org/errata/rfc7012) | IPFIX information model and timestamp types; verified erratum 3881 is retained. |
| [Cisco NetFlow Collection Engine Appendix B](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html) | v5 header table B-3 and record table B-4; network byte order and count 1–30. |
| [IANA IPFIX registry](https://www.iana.org/assignments/ipfix) and [IE CSV](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv) | Normative Information Element registry and NFv9-compatible IDs 0–127; ledger snapshot last updated 2026-07-22. |

The implementation preserves the current timestamp and protocol limits: source
flow start/end are receiver-projected values, v5/v9 uptime fields are exact
millisecond values within uint32 bounds, IPFIX general profiles use Unix
milliseconds, legacy IPFIX uses NTP time, and no uptime rollover or Options
export is implied.

## Independent oracle provenance

The independent wire decoder is TShark `4.6.8`, source commit
[`e677bf052328efc1ed897a547fa161836a0e4ff7`](https://github.com/wireshark/wireshark/tree/e677bf052328efc1ed897a547fa161836a0e4ff7),
with source anchors in [`packet-netflow.c`](https://github.com/wireshark/wireshark/blob/e677bf052328efc1ed897a547fa161836a0e4ff7/epan/dissectors/packet-netflow.c)
and the [TShark manual](https://github.com/wireshark/wireshark/blob/e677bf052328efc1ed897a547fa161836a0e4ff7/doc/man_pages/tshark.adoc).
The local Linux/amd64 test image is
`localhost/otel-netflow/tshark-oracle@sha256:1b0a680887ceb212beeda59fb3cf84289d00c138a3517028a8b651631e51f7c6`;
`integration/tshark/IMAGE_DIGEST` and the source lock preserve that identity.
The verified TShark executable hash is
`021e06894d69ed7a4ed0709de69507b35bdeab7acc018d2a7a4e435db7bd2100`. The runner uses
`--pull=never`, verifies the digest, and bounds network, capabilities,
filesystem, process, memory, and output access. This is Linux/amd64 test
provenance and does not establish cross-architecture support.

Independent receiver tools retained by the integration suite include pmacct,
IPFIXcol2, nfdump `1.7.9` (commit
[`94d5f8a8636aba91731ad228bc8b2724c75f1c76`](https://github.com/phaag/nfdump/tree/94d5f8a8636aba91731ad228bc8b2724c75f1c76)),
and their checked-in invocation contracts. They are optional local lanes, not
hosted service dependencies or a claim of downstream appliance support.

## Project-owned evidence

Authored protocol fixtures live under `integration/testdata/`; the golden
manifest binds their expected payloads. The receiver time regression suite
retains the independent flow-time audit: 15 receiver-produced cases, 67 valid
outputs, and six expected non-millisecond rejects. The exporter preserves
`flow.start` and `flow.end`; no exporter timestamp defect was found.

The public component and its tests are Apache-2.0. External tools remain
test-time oracles and are not copied into the module. Any future copied source,
binary, container, or notice bundle requires an independent license and
artifact review.

## Evidence limits

The ledger supports local, pinned claims only. It does not assert anonymous
public module retrieval before `v0.1.0-alpha.1` is tagged, hosted workflow
execution, remote UDP receipt, appliance ingestion, production capacity,
unlimited-depth processing, fixed whole-process RSS, or broad platform
compatibility. Upgrade the receiver or any tool only with a schema/provenance
review and refreshed fixtures and oracle checks.
