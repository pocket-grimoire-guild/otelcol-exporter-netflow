# Tiered CI and qualification commands

The repository has five repeatable local tiers. Each tier writes a fresh,
bounded log directory below `dist/ci/` (or `NETFLOW_CI_ARTIFACTS`) and prints
its path on exit. A selected tier fails during preflight when a required tool,
fixture, image, binary, or environment contract is missing. Logs are capped at
1 MiB per step by default; set `NETFLOW_CI_MAX_LOG_BYTES` only to a smaller
positive limit when a stricter bound is needed. The artifact gate rejects
symlinks and nonregular entries and caps a tier at 640 files and 64 MiB total
by default (`NETFLOW_CI_MAX_ARTIFACT_BYTES` can lower that limit).

Run a tier from the checkout root:

```bash
scripts/ci/run-tier.sh generated
scripts/ci/run-tier.sh ocb
scripts/ci/run-tier.sh receiver
scripts/ci/run-tier.sh conformance
NETFLOW_INTEROP_LANES=tshark,pmacct,ipfixcol2,nfdump \
  scripts/ci/run-tier.sh interop
```

The focused runner guard check exercises missing selected tools, zero-test
selection, and skipped test output without starting a consumer:

```bash
scripts/ci/test-runner.sh
```

The commands are local qualification commands. A hosted workflow may call
them, but no hosted execution, service installation, image pull, or remote UDP
delivery is implied by this document. Tool-dependent lanes are intended for a
dedicated ephemeral Linux amd64 runner with no repository secrets and no
unrelated workload. The runner must have trusted preprovisioned tools and an
explicit finite disk quota for consumer artifacts (256 MiB is sufficient for
the selected cases; build and module caches need separate space); it never installs or fetches an
external consumer. Workflow artifact upload is permitted only when the tier's
fresh artifact directory contains `UPLOAD_READY`; even failed test runs can be uploaded when their evidence passes the gate.

## Generated and manifest tier

`generated` requires Go `1.26.8` on Linux amd64 and Python 3. It runs the
pinned mdatagen drift check and the isolated [configuration schema/parser check](configuration-schema.md), followed by the project-owned canonical fixture,
generated fixture, golden, fuzz, mapping, and PCAP payload-manifest checks:

```text
scripts/check-generated.sh --go 1.26.8 \
  --mdatagen go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0
scripts/check-config-schema.sh
python3 scripts/check-canonical-fixtures.py integration/testdata/canonical/fixtures.json
python3 scripts/check-generated-fixtures.py integration/testdata/canonical/fixtures.json
python3 scripts/check-golden-manifest.py integration/testdata/golden/manifest.json
python3 scripts/check-fuzz-manifest.py
python3 scripts/check-mapping-manifest.py integration/testdata/mapping/manifest.yaml
go run -mod=readonly ./integration/tshark/wrap_pcaps.go \
  --golden-manifest integration/testdata/golden/manifest.json \
  --manifest integration/testdata/pcap/payload-manifest.yaml \
  --out integration/testdata/pcap
go run -mod=readonly ./integration/tshark/verify_payloads.go \
  --manifest integration/testdata/pcap/payload-manifest.yaml \
  --pcap-root integration/testdata/pcap \
  --golden-manifest integration/testdata/golden/manifest.json
```

The generated check temporarily regenerates the existing lifecycle, metadata,
configuration schema, documentation, and telemetry test outputs in the checkout, then fails on any
drift. A passing clean checkout is unchanged. The manifest checks are
independent of production encoder code and fail on missing, substituted, or
changed fixtures.

## OCB build and operator tier

`ocb` requires the exact primary toolchain and builds the checked-in
`distribution/ocb/manifest.yaml` with OCB `v0.160.0` and strict version checks.
The output path is temporary, must be executable and nonempty, and must answer
`--version` before tests run. The tier then invokes the existing smoke command
and the checked-in operator, invalid queue, and 30-second refresh
configurations. The smoke includes the three protocol paths and transport
isolation. `NETFLOW_OCB_ARTIFACTS` is set to a fresh per-step directory by the runner. The built binary is kept in a separate
temporary `dist/ci-bin/` directory and removed at tier exit; it is not uploaded
with qualification logs.

The build path uses source checkout replacement and does not publish a module,
use credentials, modify `go.mod`, or rewrite the root module graph. A missing
builder, invalid configuration, empty binary, or skipped selected test is a
failure.

## Semantic conventions conformance tier

`conformance` invokes the exact portable harness command
`scripts/conformance/run.sh --output <fresh-tier-child>`. The harness guide
[`netflow-conformance-harness.md`](netflow-conformance-harness.md) is the
source of truth for its runner, registry, Weaver, Go-module, and Python package
pins. The local prerequisites are Linux x86_64, Go `1.26.8`, Python `3.13.5`,
the system tools listed in that guide, and network access for the pinned source
checkouts and Weaver archive. The command uses no credentials or service setup.

The tier places the harness output below a newly created `conformance.*`
artifact directory and retains the harness report, artifact hash manifest,
bounded logs, captures, and scenario data. The harness bounds each log at
1 MiB and its dynamic output at 64 MiB; the enclosing tier applies the same
64 MiB total artifact limit, 640-file limit, and regular-file/symlink gate as
the other tiers. The wrapper gives the harness step a finite 25-minute limit.

Missing tools, pinned inputs, registries, scenarios, controls, or fresh output
make the tier fail visibly. The tier also requires exactly one fresh harness
run directory containing a nonempty `report.md`,
`pins/artifact-sha256.txt`, and `logs/harness-guards.log`. The hosted workflow
uploads only the current conformance directory whose fresh `UPLOAD_READY`
marker passed the enclosing artifact gate. A failed harness run may upload its
bounded diagnostic evidence when that outer gate passes; a missing or
over-limit artifact removes the marker and blocks upload.

The result is local self-telemetry evidence against the pinned custom and
upstream registries. It does not claim upstream semantic-conventions
standardization, independent UDP receipt, NetFlow/IPFIX wire interoperability,
appliance ingestion, hosted qualification, or a capacity limit. The hosted
workflow provisions Go `1.26.8` and Python `3.13.5` with immutable action
revisions, but this document does not claim that a hosted run has occurred.

## Nested receiver tier

`receiver` keeps the pinned receiver module separate from the root module:

```text
(cd integration/receiver && \
  go test -mod=readonly . \
    -run '^Test(SemanticRoundTrip|LargePinnedReceiverPacketization)$' \
    -count=1 -timeout=10m -v)
```

The tier requires both `integration/receiver/go.mod` and `go.sum`, and rejects
zero selected tests, any `SKIP`, or any `FAIL` line. Receiver receipt and
decode remain a separate boundary from the exporter’s local UDP write return.
The tier leaves Go’s temporary compilation/test files outside the upload tree;
the dedicated ephemeral runner quota above bounds that workspace, while only a
tier with `UPLOAD_READY` can publish its retained logs.

## TShark and independent consumers

Select exactly the lanes to run with `NETFLOW_INTEROP_LANES`, a comma-separated
list of `tshark`, `pmacct`, `ipfixcol2`, and `nfdump`. An empty selection is a
preflight error. Each selected lane has an explicit contract:

| Lane | Required environment and tool identity | Command/evidence |
| --- | --- | --- |
| `tshark` | `NETFLOW_TSHARK_IMAGE` must equal `integration/tshark/IMAGE_DIGEST`; Podman must already have that digest. The pinned image is TShark `4.6.8`, source commit `e677bf052328efc1ed897a547fa161836a0e4ff7`, Linux amd64. | `integration/tshark/run_oracle.sh --pull=never --image "$NETFLOW_TSHARK_IMAGE"`; seven immutable v5/v9/IPFIX golden cases must report PASS. |
| `pmacct` | `NFACCTD_BINARY` must be executable and be the stock pmacct `nfacctd` `1.7.9` build with Jansson. | `go test -mod=readonly ./integration/independent -run '^TestNfacctd$' -count=1 -timeout=10m -v`; artifacts are selected by `NFACCTD_ARTIFACTS`. |
| `ipfixcol2` | `IPFIXCOL2_BINARY` must be executable and report IPFIXcol2 `2.8.0`, git `03528c6`; set `IPFIXCOL2_PLUGINS` and `IPFIXCOL2_DEFINITIONS` for an extracted installation, plus its library path in `LD_LIBRARY_PATH` when required by that installation. | `go test -mod=readonly ./integration/independent -run '^TestIPFIXcol2$' -count=1 -timeout=10m -v`; artifacts are selected by `IPFIXCOL2_ARTIFACTS`. |
| `nfdump` | `NFCAPD_BINARY` and `NFDUMP_BINARY` must both be executable and come from stock nfdump `1.7.9`, source commit `94d5f8a`. | `go test -mod=readonly ./integration/independent -run '^TestNfcapd$' -count=1 -timeout=10m -v`; artifacts are selected by `NFCAPD_ARTIFACTS`. |

The independent tests retain their own bounded receiver logs, decoded output,
and emitted payload evidence under fresh artifact directories. The runner does
not treat an absent binary as an opt-out: the selected lane fails before its
test command. A test command also fails if its explicit selection produces no
passing test or emits a skip. TShark runs with `--pull=never`; mutable tags,
host TShark fallback, and service setup are unsupported.

Existing consumer evidence is local run output only. It does not satisfy a
fresh tier without a new `UPLOAD_READY` marker in that tier's artifact tree.

Example for a preprovisioned host:

```bash
export NETFLOW_INTEROP_LANES=tshark,pmacct,ipfixcol2,nfdump
export NETFLOW_TSHARK_IMAGE="$(<integration/tshark/IMAGE_DIGEST)"
export NFACCTD_BINARY=/absolute/path/to/nfacctd
export IPFIXCOL2_BINARY=/absolute/path/to/ipfixcol2
export IPFIXCOL2_PLUGINS=/absolute/path/to/usr/lib/x86_64-linux-gnu/ipfixcol2
export IPFIXCOL2_DEFINITIONS=/absolute/path/to/etc/libfds
export LD_LIBRARY_PATH=/absolute/path/to/usr/lib/x86_64-linux-gnu
export NFCAPD_BINARY=/absolute/path/to/nfcapd
export NFDUMP_BINARY=/absolute/path/to/nfdump
scripts/ci/run-tier.sh interop
```

## Version and support boundary

The supported qualification target is deliberately one exact environment.
The labels below describe the evidence boundary, rather than claiming a new
hosted run from this document:

| Platform | Go | Collector Core / Contrib | OCB | Label and evidence boundary |
| --- | --- | --- | --- | --- |
| Linux amd64 | `1.26.8` | Core `v1.66.0` / `v0.160.0`, Contrib `v0.160.0` | `v0.160.0` | `runtime-qualified` for the checked-in operator path in the existing [local acceptance](mvp-acceptance.md) and [OCB evidence](../distribution/ocb/README.md); rerun `ocb` and `receiver` for current-run evidence |

The OCB build result is compilation evidence until the real binary passes the
operator smoke. A successful exporter UDP write remains local kernel handoff
evidence; independent receiver receipt, decoding, loss, reordering, and
template-cache behavior are reported only by their respective selected lane.
No other OS, architecture, Go, Core, Contrib, or OCB version is a support
claim; such probes are compile-only unless separately qualified. No physical
NIC, dual-stack transport, appliance/SNA, remote delivery, or production SLA
claim is covered.

## Workflow selection and local evidence

[The workflow](../.github/workflows/ci.yml) keeps the fast check/test/race job
and runs generated, OCB, receiver and conformance jobs on `ubuntu-24.04` for push, pull
request and manual dispatch. Manual dispatch additionally selects all four
external lanes on `[self-hosted, linux, x64, netflow-interop]`. A hosted guard
fails a dispatch from a non-default branch before external work starts. No
runner, repository, service or hosted execution was configured in this task.
The external runner must supply the tool environment above; missing tools fail.
Actions are pinned to immutable revisions. Evidence uploads use the
[artifact action's explicit path and failure policy](https://github.com/actions/upload-artifact)
and retain only the fresh tier tree after its upload gate, for seven days.

The observed local qualification environment was Debian 13 Linux amd64 with Go
1.26.8; the Ubuntu workflow runner label is configuration, not a claim of a
hosted Ubuntu runtime run.
