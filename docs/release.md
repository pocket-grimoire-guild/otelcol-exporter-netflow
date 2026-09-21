# Alpha release notes and publication checklist

Existing public tag `v0.1.0` points at the earlier public baseline. The current
source fixes are untagged. `v0.1.0-alpha.1` is a synthetic local staging
version used only by `check-consumer.sh`; it is unpublished and cannot be
fetched from a public module proxy. This checkout is suitable for local build
and review; it does not establish anonymous module retrieval, a maintained
binary or image, or a hosted CI result.

## Component

- Module: `github.com/pocket-grimoire-guild/otelcol-exporter-netflow`
- Package: `netflowexporter`
- Collector component type: `netflow`
- License: [Apache-2.0](../LICENSE)
- Supported source build: Linux/amd64, Go `1.26.8`
- Collector Core: stable modules `v1.66.0`, beta modules `v0.160.0`
- Collector Contrib NetFlow receiver: `v0.160.0`
- Collector Builder: `v0.160.0`

The component consumes the pinned parsed 41-key receiver schema and emits
NetFlow v5, NetFlow v9, or IPFIX over UDP through a public Collector exporter
factory. Recommended profiles are IPFIX Unix-millisecond general and timed v9;
legacy v9 time-free and IPFIX NTP layouts remain explicit alternatives.
Records are packetized at record boundaries, cancellation and partial failures
are reported, and named destinations have separate protocol state.

## Untagged source changes

Compared with the `v0.1.0` baseline, current source adds cancelable waiting for
internal maintenance while preserving immediate busy responses for a second
request, independent next-hop family validation at selected wire slots, and
bounded configuration diagnostics. Fixed rejection-reason counters and v5/v9
lifetime gauges make local drops and terminal uptime exhaustion observable.
The operator examples enable metrics through `NETFLOW_METRICS_PORT`.

The mapping coverage manifest uses version 2, with pinned source declarations
and semantic table checks instead of whole-document hashes. Ordinary
regressions and the reusable conformance and Collector checks accompany these
changes. These source changes have no newly selected release tag.

## Known limits

Input must be parsed `contrib-netflowreceiver-v0.160.0` flow data. Formatted
`send_raw` bodies and arbitrary flow-log schemas are unsupported. Measured-time
provenance is deployment-owned. V5/v9 uptime conversion has an approximately
49.71-day 32-bit millisecond lifetime with no rollover. IPFIX general and
legacy NTP profiles have distinct time semantics. Sampling normalization,
Options sampling, proprietary-consumer ingestion/storage, and appliance
qualification are unverified.

UDP has loss, duplication, and reordering; local write success means kernel
handoff only. The exporter adds no queue, automatic retry, acknowledgement,
persistence, encryption, peer authentication, or replay protection. Work and
failed-subset copies scale with input, and the pinned pdata recursive copy
retains an extreme-depth stack limitation. No fixed whole-process memory or
unlimited-depth claim is made.

## Evidence and provenance

The [MVP acceptance record](mvp-acceptance.md) summarizes deterministic,
race, receiver-roundtrip, Collector, and independent wire checks. The
[verification strategy](design-docs/implementation-verification.md) gives
the test layers and reproduction commands. Independent decoding uses the
digest-locked TShark `4.6.8` oracle; receiver semantics use Contrib
`netflowreceiver v0.160.0` and goflow2/v2 `v2.2.6`. The
[source ledger](research/source-ledger.md) records the exact upstream anchors,
protocol authorities, tool pins, and known limits.

Evidence is local and version-specific. It does not claim hosted workflow
execution, public registry ingestion, remote UDP receipt, downstream appliance
compatibility, or broad platform support.

## Before publishing a tag

Run the checks against the exact commit selected for the tag. Set the ports,
endpoints, loopback `NETFLOW_METRICS_PORT` and uptime origins from the
[operator guide](operator-guide.md#build-and-run-the-example) before validating
the configuration. Copy the binary outside the checkout;
OCB also generates an ignored `dist/ocb/` build directory:

```bash
make check test
git diff --check
./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
/tmp/otel-netflow-collector validate --config distribution/ocb/config.yaml
```

Run the receiver, independent-oracle, OCB, and selected integration checks
documented by the [operator guide](operator-guide.md) and
[verification strategy](design-docs/implementation-verification.md). Re-run
dependency or advisory checks when the selected commit or pins change; record
their scope and date.

After a real immutable tag is published, verify from a fresh consumer with
ordinary public proxy/checksum settings and no local replacement. Build the
versioned recipe with strict version checking, run its complete configuration,
and record the resolved module version and checksum. A local checkout, file
proxy, or authenticated source does not satisfy this check.

Binary, container, signing, checksum, SBOM, and linked notice bundles require a
separate artifact decision. No such maintained artifact is promised by this
alpha source release.

The project also needs a maintainer decision about a confidential security
reporting route before claiming that capability. `SECURITY.md` intentionally
does not invent an address or nonfunctional link.
