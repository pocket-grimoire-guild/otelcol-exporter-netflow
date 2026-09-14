# MVP acceptance and test coverage

The component is alpha. This record describes the local implementation and
interoperability evidence retained in the repository; it does not establish a
production SLA, a hosted CI result, public package retrieval, or broad platform
qualification. The tested baseline is Go `1.26.8` on Linux/amd64, Collector
Core stable `v1.66.0`/beta `v0.160.0`, Contrib NetFlow receiver `v0.160.0`,
goflow2/v2 `v2.2.6`, and digest-locked TShark `4.6.8`.

## Requirement, implementation, and evidence

| Requirement | Implementation | Verification boundary |
| --- | --- | --- |
| Collector logs component and runnable configuration | [`factory.go`](../factory.go), [`config.go`](../config.go), [`distribution/ocb/config.yaml`](../distribution/ocb/config.yaml) | Pinned OCB build and operator-example tests validate the YAML, export all three protocols, and shut down. |
| Versioned receiver schema and explicit mapping | [`internal/normalize`](../internal/normalize), [`internal/mapping`](../internal/mapping), [receiver attributes](compatibility/receiver-attributes.md), [profiles](compatibility/default-profiles.md) | Normalization, type/presence/raw-body tests and the [mapping manifest](../integration/testdata/mapping/manifest.yaml) cover 41 canonical attributes across v5/v9/IPFIX. Exact, lossy, synthesized, unsupported, and inapplicable outcomes remain explicit. |
| Correct IPFIX fragment flags | [`internal/mapping/runtime.go`](../internal/mapping/runtime.go), [protocol mapping](compatibility/protocol-mapping.md) | The family/value matrix checks six valid controls and rejects ten reserved or IPv6-DF combinations; exporter regressions check valid siblings and failed subsets. |
| Record-boundary packetization | [`packer.go`](../internal/destination/packer.go), [`internal/wire/`](../internal/wire/) | Large-request tests export 65,537 records with more than 64 MiB of ignored metadata. Mapping and packet tests check exact-fit and one-beyond field, Set, message, path, v5 30-record, short-record, and padding boundaries. |
| Accurate partial outcomes and ownership | [`logs_exporter.go`](../logs_exporter.go), [`ledger.go`](../internal/destination/ledger.go) | Large failed suffix, subset-copy, helper-accounting, load, cancellation, read-only input, and detached-byte tests cover confirmed prefixes, invalid exclusions, ambiguous/unsent ordering, and independent ownership. |
| Time, sequence, and template behavior | [`internal/destination/`](../internal/destination), [`clock.go`](../clock.go), [protocol state design](design-docs/protocol-state-transport.md) | Deterministic clock, epoch, sequence, template, refresh, ambiguous-write, and restart tests verify commit semantics and refresh behavior. The operator guide states uint32 uptime, origin, Unix export-time, and NTP-era limits. |
| UDP, DNS, PMTU, and destination isolation | [`internal/transport/`](../internal/transport), [`internal/destination/`](../internal/destination) | Boundary, deadline, cancellation, DNS-generation, staleness, PMTU, and Linux transport-isolation tests cover v5/v9/IPFIX recovery. IPv6 loopback is covered by component tests; live oracle evidence uses IPv4 transport. |
| Concurrency and lifecycle cleanup | [`exporter.go`](../exporter.go), lifecycle tests | Race coverage, coalesced-trigger tests, and [leak checks](../integration/leak/README.md) cover publication, DNS, sends, shutdown, goroutine counts, socket counts, bounded buffers, and active calls. |
| Telemetry and diagnostics | [`telemetry.go`](../telemetry.go), [generated metrics](../documentation.md) | Telemetry tests verify outcomes, bytes, maintenance, helper accounting, instance isolation, bounded labels, and sampled diagnostics. The implemented local series fit the documented acceptance ceiling. |
| Hostile input and functional load | [`integration/testdata/fuzz/`](../integration/testdata/fuzz/), [load checks](../integration/load/README.md) | Reviewed fuzz seeds and tagged load cases cover malformed input, variable bytes, packet accounting, repeated calls, and detached ambiguous/unsent subsets. |
| Receiver semantic interoperability | [`integration/receiver/`](../integration/receiver), [receiver fixtures](../integration/testdata/receiver/README.md) | Pinned receiver tests cover valid and invalid flows, ignored metadata, sampling, and timestamp projection for each protocol. |
| Independent wire evidence | [golden manifest](../integration/testdata/golden/manifest.json), [TShark runner](../integration/tshark/README.md), [OCB distribution checks](../distribution/ocb/README.md) | Digest-locked TShark decodes seven immutable goldens and live OCB frames, checking byte identity, fields, templates, sequences, padding, lengths, and valid checksums. |
| Flow-time preservation | [receiver flow-time tests](../integration/receiver/flow_time_test.go), [TShark companion](../integration/receiver/flow_time_tshark_test.go) | The receiver preserves `flow.start` and `flow.end`; exporter code introduces no timestamp defect. The audit covers 15 receiver-produced cases, 67 valid outputs, and six expected non-millisecond rejects. |

## Reproducing local checks

Run from the checkout root with the pinned Go toolchain. Container checks need
the existing local images and rootless Podman described in the linked guides;
they do not pull substitute images.

```bash
make check test
go test -race ./... -count=1 -timeout=30m
scripts/test-load.sh
scripts/check-leaks.sh --race
(cd integration/receiver && go test -mod=readonly . -count=1 -timeout=10m)
(cd integration/receiver && go test -race -mod=readonly . -count=1 -timeout=10m)
./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
NETFLOW_OCB_BINARY=/tmp/otel-netflow-collector \
  go test -race ./integration/ocb -run '^TestCollectorOperatorExample' -count=1 -timeout=2m
./distribution/ocb/smoke_test.sh --binary /tmp/otel-netflow-collector \
  --fixture integration/testdata/ocb/canonical.yaml
```

Then run the [immutable oracle commands](../integration/tshark/README.md) and
the [live capture command](../distribution/ocb/README.md#live-packets-and-independent-checksums).
Race-running the OCB driver does not instrument the separate Collector binary.

## Remaining limits

UDP handoff is not remote receipt. Delivery, ordering, deduplication, template
cache recovery, and atomic cross-instance fan-out are not guaranteed. There is
no exporter queue, automatic retry, persistence, raw replay, sFlow output,
additional transport, DTLS, dynamic template catalog, Options export, or
uptime rollover. Sampling normalization, downstream ingestion, physical-NIC
behavior, and fixed whole-process RSS qualification remain outside this record.

Failed-subset envelope copying uses the pinned public pdata recursive `CopyTo`
API and retains its extreme-depth stack limitation. Iterative byte detachment
does not make that recursive copy unlimited-depth safe. Work and retry storage
scale with actual input; this is a bounded component test record, not a memory
capacity promise.
