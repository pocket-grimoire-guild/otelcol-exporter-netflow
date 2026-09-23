# v0.2.0 source release

`v0.2.0` is a source/Go-module release with the changes below since `v0.1.0`.
It retains **pre-1.0 alpha maturity**, the pinned parsed receiver schema and
the existing protocol/delivery limits. No maintained binary or container image
is offered. The [versioned consumer recipe](../distribution/ocb/consumer/README.md)
selects exporter `v0.2.0` and distribution version `0.2.0`; it requires the
public immutable tag. A staged local build does not establish tag availability,
hosted CI success or anonymous public module retrieval.

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

## Changes since v0.1.0

- An admitted request can wait cancelably for internal maintenance. A concurrent
  second request still receives busy; this does not add a request queue or retry.
- Next-hop addresses are validated against selected wire slots independently
  of the flow's source/destination family. An unselected next hop no longer
  invalidates a flow just because its family differs. Selected values must
  still fit their output slot; v5 remains IPv4-only.
- Configuration diagnostics identify fixed rules and paths with bounded
  messages, without echoing raw endpoints, tokens or compiler-error text.
- Rejected records have fixed first-reason counters with a closed, 13-value
  `rejection_reason` vocabulary. These counters make rejected records visible
  even when valid siblings complete successfully in a mixed request.
- Operator examples enable a loopback Prometheus reader through
  `NETFLOW_METRICS_PORT`. The `otelcol_netflow_exporter_uptime_remaining` and
  `otelcol_netflow_exporter_uptime_exhausted` gauges describe published v5/v9
  origin-relative lifetime state. IPFIX has no lifetime pair. Collection does
  not latch exhaustion, extend lifetime or confirm remote delivery.
- Mapping coverage manifest version 2 pins source declarations and checks
  semantic tables instead of whole-document hashes. Regression and reusable
  conformance checks cover the corresponding source changes.

## Install or upgrade

Use the [complete consumer recipe](../distribution/ocb/consumer/README.md) with
Go `1.26.8` on Linux/amd64. Copy its manifest and both linked configuration
files into a separate consumer directory, then run:

```bash
mkdir -p dist
go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
  --config manifest.yaml --skip-strict-versioning=false
gofmt -w dist/ocb/*.go
./dist/ocb/otel-netflow-collector --version
go version -m ./dist/ocb/otel-netflow-collector
```

Expect Collector distribution version `0.2.0` and exporter dependency
`github.com/pocket-grimoire-guild/otelcol-exporter-netflow v0.2.0`, without
an exporter replacement. Export **all environment settings in the recipe**,
including a distinct loopback `NETFLOW_METRICS_PORT` for each process, before
validating and running `config.yaml`. The optional `config-consumer-30s.yaml`
selects a 30-second template refresh; the default remains ten minutes.

To upgrade from `v0.1.0`, select `v0.2.0` in the exporter `gomod` entry and
`0.2.0` in `dist.version`, rebuild the Collector with the same pinned toolchain,
and validate the deployment's configuration before replacing its executable.
The component type `netflow`, package `netflowexporter`, configuration keys,
input schema and built-in profile contracts are unchanged. Set the metrics
port when adopting the updated examples; review the
[operator metrics semantics](operator-guide.md#operator-metrics-and-mixed-requests)
for mixed requests, lifetime gauges and absent series. Preserve explicit
origins appropriate to historical source flows; restarting with the same
origin does not reset the approximately 49.71-day v5/v9 lifetime. See the
[compatibility and upgrade contract](compatibility/alpha-upgrades.md) before
changing origins, templates or time profiles.

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

## Verification and publication checklist

Run repository and isolated packaging checks against the exact reviewed
candidate, with Go `1.26.8` on `PATH`:

```bash
make check test
git diff --check
./distribution/ocb/check-consumer.sh --revision "$(git rev-parse HEAD)"
```

The staged check archives that revision under synthetic `v0.1.0-alpha.1` and
rewrites only a temporary copy of the consumer manifest. It uses a local file
proxy and an exporter-only checksum exemption, strict OCB version checking,
embedded binary/module identity assertions, and bounded Collector
smoke/config/transport checks. It is packaging evidence, not anonymous
installation evidence. The development recipe retains its deliberate local
replacement. Neither path may stand in for public versioned consumption.

For publication, review the exact source/history and preserve existing tags.
After publishing an immutable tag, verify its hosted CI separately and use a
fresh consumer with `GOPROXY=https://proxy.golang.org`,
`GOSUMDB=sum.golang.org`, no private-module/checksum bypass, credentials, local
replacement or staged exporter cache. Record the resolved version and module
checksums, build the unchanged versioned recipe with strict checking, and run
the bounded Collector checks with `NETFLOW_OCB_BUILD=versioned`. A download or
`--version` alone is not complete integration evidence. Never move a published
tag to conceal a defect; a corrective release needs a new version.

Reuse unchanged wire qualification with its recorded scope. Re-run affected
checks when source, configuration or pins change; identify dated advisory
results as historical. No hosted CI, tag publication or anonymous retrieval
success is asserted by this checklist.

Binary, container, signing, checksum, SBOM, and linked notice bundles require a
separate artifact decision. No such maintained artifact is promised by this
alpha source release.

The project also needs a maintainer decision about a confidential security
reporting route before claiming that capability. `SECURITY.md` intentionally
does not invent an address or nonfunctional link.
