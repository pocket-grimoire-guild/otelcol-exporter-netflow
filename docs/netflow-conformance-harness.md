# NetFlow semantic-conventions conformance harness

The portable harness checks the exporter's self-telemetry at the same SDK and
OTLP boundary used by the local conformance check. It runs the existing
`TestTelemetryConditionalProbe` from the current checkout through a temporary
Go build overlay, captures the SDK's complete `ResourceMetrics`, and replays
that capture to the pinned OpenTelemetry semantic-conventions runner over
OTLP/gRPC. The root test and production component are not copied into a
separate probe module.

Run the selected local slice with one command:

```sh
scripts/conformance/run.sh --output ./artifacts/conformance
```

The command creates a fresh timestamp/PID directory below the selected output
parent. A caller may choose any fresh output parent; the default is
`artifacts/conformance` below the checkout. An existing run directory is
rejected so a stale capture cannot be reused. Each command also runs seven
focused guards against its fresh evidence, retained in `logs/harness-guards.log`.

The command requires Linux x86_64, Go `go1.26.8`, Python `3.13.5`, and the
small set of system tools used by the script (`git`, `curl`, `tar`,
`sha256sum`, `mktemp`, `find`, `wc`, `date`, `awk`, `cmp`, `xargs`, `sort`,
`grep`, `uname`, `basename`, `dirname`, `install`, `cp`, `mkdir`, `chmod`, and
`cat`). It sets `GOTOOLCHAIN=local` and `GOWORK=off`; an automatic Go toolchain
download is therefore a failure. Ambient endpoint, capture, and bridge
variables are rejected before the output directory is created.

The inputs are pinned in the repository and checked before a scenario starts:

| Input | Pin or check |
| --- | --- |
| semantic-conventions-conformance runner | commit `17df55b24316a12b1921a6873b24437b52f9f81f` |
| semantic-conventions registry | commit `e10a930844c6951757a43b849d364f7d056ac32b` |
| Weaver | release `0.26.1`; archive SHA-256 `1be79cca68925c09b6da04ef8a3875b563cf7c1dcd51cc5b7eff7d2edbb1a5dc`; executable SHA-256 `40cc3889e273c8dd54501827fb310bfed61539efd514ea042ed8563d18b3bafc` |
| Go modules | sorted complete graph hash in `scripts/conformance/go-module-graph.sha256` |
| Python packages | exact complete freeze in `scripts/conformance/requirements-py3.13.txt` |
| Python packaging tool | pip `25.1.1` |

The script clones both source repositories at detached commits, verifies their
resolved object IDs, downloads and hashes Weaver before extraction, checks both
the upstream model and a task-local custom model, and creates an isolated
Python environment. The Python freeze must equal the requirements file after
normalizing package-name case. The Go module graph is resolved with
`-mod=readonly` from the checkout root and must match its recorded SHA-256;
this rejects an added, removed, or differently resolved module.

The custom model is the pinned upstream `model/` directory plus
`integration/conformance/registry/netflow-extension.yaml`. The extension
declares the nine project metrics and the two Collector helper metrics, with
`exporter`, `message_kind`, `outcome`, `reason`, `loss_class`, and `data_type`
at the required levels recorded by the pilot. Weaver validates both registry
trees before the live checks.

The runner receives two separate scenario packages. The upstream package has
one valid scenario. The custom package has `valid`,
`type_mismatch_control`, and `missing_required_outcome_control`; all three
declare the same 11 metric names. The four runner sessions are kept separate:

| Session | Expected result |
| --- | --- |
| upstream strict | nonzero because the project-local signals are absent from the pinned upstream registry |
| upstream report-only | zero with those upstream findings rendered as WARN |
| custom strict | nonzero because both deliberate controls are unaccepted findings |
| custom report-only | zero with both controls rendered as WARN |

The controls are intentionally omitted from `expected_violations`. This makes
strict mode prove that the checker fails, while report-only mode proves that a
semantic finding is downgraded without hiding it. The verifier requires the
type finding to name metric `otelcol_netflow.exporter.records`, attribute
`outcome`, and observed type `int`; it requires the requiredness finding to
name the same metric and attribute. It also checks that the valid custom
scenario has an `ok` status and no findings in its own raw report.

For every scenario, `scripts/conformance/replay.py` performs these steps:

1. It copies the current `telemetry_conditional_test.go` to a temporary build
   overlay and replaces exactly its final `writeConditionalSnapshot` call with
   `writeConformanceSnapshot`. The overlay adds the serializer adapter as a
   test file. The source site must occur exactly once. No root file is written.
2. It invokes the current checkout with `go test -mod=readonly`, the overlay,
   `-run '^TestTelemetryConditionalProbe$'`, `-count=1`, and a 120-second test
   timeout. `scripts/ci/capture.py` bounds and retains the combined SDK probe
   log while it runs.
3. It reads a fresh JSON snapshot produced by the SDK's actual
   `ResourceMetrics`. The snapshot retains resource attribute values and
   schema URL, scope name/version/attributes and schema URL, metric metadata,
   cumulative temporality, typed point attributes, timestamps, and values. It
   fails closed unless the nested scope metrics and flattened summary agree
   and all 11 names are present exactly once.
4. It locates the first point of the exact `records` metric. For the type
   control it changes only `outcome` from a string to an int64. For the
   requiredness control it removes only `outcome`. Both mutations happen after
   the pre-mutation snapshot is written; the verifier confirms that each
   retained capture still has a string `outcome`.
5. It serializes the captured values to OTLP metrics protobuf and sends them
   to the runner's fresh Weaver gRPC endpoint. The bridge accepts the runner's
   `http://host:port` spelling only as an insecure gRPC endpoint, rejects HTTPS
   and paths, and fails on OTLP partial success.

The 11 required signal names are:

```text
otelcol_netflow.exporter.admission
otelcol_netflow.exporter.bytes
otelcol_netflow.exporter.data_messages
otelcol_netflow.exporter.dns
otelcol_netflow.exporter.endpoint_epochs
otelcol_netflow.exporter.failures
otelcol_netflow.exporter.losses
otelcol_netflow.exporter.records
otelcol_netflow.exporter.templates
otelcol_exporter_in_flight_requests
otelcol_exporter_sent_log_records
```

Each run directory contains `captures/` for the pre-mutation SDK snapshots,
`reports/` for one raw Weaver report per scenario, `data/` for the runner's
complete-run reductions, `logs/` for setup, runner, and bounded Go probe logs,
`pins/` for the resolved Go/Python graphs and source/artifact hashes, and
`report.md` for the run-level boundary and result statement. The source hash
record includes the root module files, the pilot test, the serializer,
scenario definitions, replay/verifier scripts, requirements, the runner, the
graph pin, and `scripts/ci/capture.py`. Those hashes are recomputed after all
sessions and a change aborts the run.

The precise output limits apply to the complete selected run tree. Every file
under `logs/` is at most 1 MiB, and the sum of all regular files under the run
tree is at most 64 MiB. Symlinks and other non-regular output are rejected. The
artifact hash manifest covers every final file except the manifest itself. The
limits exclude prerequisite source checkouts, the isolated Python environment,
the downloaded Weaver executable, Go module and build caches, and the system
tools; the temporary tool checkouts and Python environment are removed on exit,
while Go caches and system tools remain caller-managed. A failed setup
or scenario leaves its bounded task-local logs for diagnosis and does not
turn an incomplete run into a passing report.

This harness demonstrates the current exporter self-telemetry contract against
one task-local custom registry and records the separate findings produced by a
pinned upstream registry. It does not establish upstream standardization,
NetFlow or IPFIX wire interoperability, independent UDP receipt, appliance
ingestion, hosted service behavior, or a capacity limit. CI wiring, metadata
publication and other follow-up work remain separate maintainer decisions.
