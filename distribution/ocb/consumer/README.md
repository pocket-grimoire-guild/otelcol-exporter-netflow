# Versioned Collector consumer

This is the external user path for
`github.com/pocket-grimoire-guild/otelcol-exporter-netflow`. It builds a source-based
OpenTelemetry Collector with the exporter registered through its public
`NewFactory` API. The existing public `v0.1.0` tag points at the earlier public
baseline. The checked-in example uses `v0.1.0-alpha.1` only as a synthetic
local staging version for `check-consumer.sh`; it is unpublished and cannot
be fetched from a public module proxy.

The supported first-release target is Linux/amd64 with Go `1.26.8` and OCB
`v0.160.0`. The manifest pins Collector Core `v1.66.0`, the beta `v0.160.0`
service modules, and the Contrib
`netflowreceiver v0.160.0` schema. Its env and file providers are pinned at
Core `v1.66.0`. The exporter is selected by its explicit module version; the
manifest contains no local replacement and does not require a checkout path,
host bootstrap, credentials, a container socket, or a maintained binary.

## Template for a future versioned build

For the current untagged fixes, use the working
[checkout build](../README.md) from the repository root. The commands
below require a separately published version that includes the desired fixes;
update the manifest to that version first. The checked-in alpha pin works only
with the staged check below, and the existing `v0.1.0` baseline predates these
fixes. No new release version is selected here.

Place [`manifest.yaml`](manifest.yaml), [`config.yaml`](../config.yaml), and
[`config-consumer-30s.yaml`](../config-consumer-30s.yaml) in a separate
consumer directory. With Go `1.26.8` on `PATH`, run OCB from that directory:

```bash
mkdir -p dist
go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
  --config manifest.yaml --skip-strict-versioning=false
gofmt -w dist/ocb/*.go
./dist/ocb/otel-netflow-collector --version
```

The generated `dist/ocb/go.mod` should require the staged
`github.com/pocket-grimoire-guild/otelcol-exporter-netflow v0.1.0-alpha.1` with
no `replace` directive. That check uses a synthetic local file proxy and does
not establish public retrieval. After a future explicit publication, a public
build must resolve its exact immutable version through ordinary Go
proxy/checksum or direct Git settings. The current source fixes are untagged.

Use separate, nonzero input ports and output endpoints, and keep them
different so a pipeline cannot feed itself. Set all of the following before
validation or execution:

```bash
export NETFLOW_V5_PORT=2055
export NETFLOW_V9_PORT=2056
export NETFLOW_IPFIX_PORT=4739
export NETFLOW_METRICS_PORT=8880
export NETFLOW_V5_ENDPOINT=127.0.0.1:15005
export NETFLOW_V9_ENDPOINT=127.0.0.1:15009
export NETFLOW_IPFIX_ENDPOINT=127.0.0.1:14739
export NETFLOW_V5_ORIGIN="$(( $(date -u +%s) - 4 ))000000000"
export NETFLOW_V9_ORIGIN="$NETFLOW_V5_ORIGIN"

./dist/ocb/otel-netflow-collector validate --config config.yaml
./dist/ocb/otel-netflow-collector --config config.yaml

# Optional explicit 30-second v9/IPFIX refresh configuration:
./dist/ocb/otel-netflow-collector validate --config config-consumer-30s.yaml
```

`NETFLOW_METRICS_PORT` is a numeric loopback TCP port for the checked-in pull
Prometheus reader. Assign a different unused value to each Collector process;
two processes cannot bind the same reader port. After startup, inspect the
local endpoint with:

```bash
curl --fail --silent --show-error --max-time 1 \
  --header 'Accept: text/plain; version=0.0.4' \
  "http://127.0.0.1:${NETFLOW_METRICS_PORT}/metrics"
```

The reader reports exporter-local record outcomes and the pinned Collector
helper's whole-request accounting. The [operator guide](../../../docs/operator-guide.md#operator-metrics-and-mixed-requests)
explains why a mixed request can have one confirmed and one rejected local
record while the helper sent count is two, and why a successful UDP write only
proves local kernel handoff. Keep this endpoint on loopback; it has no
authentication or encryption.

For a successfully published v5 or timed-v9 exporter, the reader also reports
`otelcol_netflow_exporter_uptime_remaining` (Float64 gauge, seconds) and
`otelcol_netflow_exporter_uptime_exhausted` (binary Int64 gauge, unit `1`).
Each series has only the `exporter` label; this example uses `netflow/v5` and
`netflow/v9`. IPFIX intentionally has no lifetime pair. Remaining projects
origin-relative lifetime at collection time and does not measure process age
or guarantee representable records or remote UDP delivery. Exhausted reflects
the existing latch and quiet collection does not set it. A `0`/`0` pair is a
projected limit awaiting an existing operation's latch; `1` is terminal,
including after rewind, with valid local records remaining unsent. The pair
may be absent before publication, after failed startup/bootstrap, during
shutdown, for IPFIX or unavailable telemetry; absence requires independent
health monitoring. A scrape already in flight can show the previous epoch
once during replacement; subsequent collection observes a successful replacement.
While unlatched, an invalid non-lifetime clock sample omits only remaining
and exhausted stays zero; a latched epoch keeps its `0`/`1` pair. The full
[operator guide](../../../docs/operator-guide.md#operator-metrics-and-mixed-requests)
also defines the illustrative `remaining <= 86400`-second monitoring rule,
same-explicit-origin restart behavior, migration guidance and existing
startup/helper diagnostic limits; the threshold is not a product cutoff,
retry, reset or configurable lifetime.

The standard configuration selects fresh template IDs 300/301, IPFIX
`ipfix-general-v1` Unix-millisecond times, and timed v9
`netflow-v9-timed-v1` measured FIRST/LAST values with an explicit origin. The
optional `config-consumer-30s.yaml` selects a 30-second v9/IPFIX refresh; the
component default remains ten minutes. Select the legacy `ipfix-core-v1` or
`netflow-v9-core-v1` layouts only when the receiving system requires their
NTP/time-free semantics. Timed v9 and v5 origins have the documented roughly
49.71-day uptime lifetime, and measured source times must be attested by the
deployment.

The input is parsed flow data matching the pinned Contrib receiver schema;
formatted `send_raw` payloads and arbitrary flow-log schemas are not accepted.
Send compatible synthetic flow input to each loopback receiver and inspect the
configured local UDP destinations or Collector outcome metrics. The
[operator guide](../../../docs/operator-guide.md) explains parsed input, measured-time
attestation and outcome counters. To send the synthetic fixtures and verify local
output automatically, run the staged check below. A successful
UDP write establishes local kernel handoff only; it does not prove downstream
receipt. The existing source checkout contains the complete flow fixtures and
independent packet assertions used by the local check.

## Isolated staged check

From the repository root, the bounded local check creates a temporary module
proxy and separate Go module/build caches outside the source tree. It archives
the selected Git revision under the unpublished alpha version, builds this
manifest with strict OCB checking, and runs the existing smoke, transport,
operator-example, queue rejection, and 30-second minimum validation tests from
an archived source tree:

```bash
./distribution/ocb/check-consumer.sh --revision "$(git rev-parse HEAD)"
```

The check logs the selected revision, staged version, Go/OCB pins, binary
identity, archive/test/config hashes, and the dependency resolution policy:
the exporter comes from the staged file proxy; other dependencies use a separate
cache seeded from the current module cache, with public proxy fallback enabled.
This does not attribute individual network downloads. All recipe and test inputs
come from the selected revision, which must contain this consumer recipe. It never adds a replacement to the versioned
manifest or mutates the root module. A staged local proxy verifies packaging
and factory compilation; it does not establish that anonymous public module
retrieval works before publication.

The separate development recipe remains available through
[`../manifest.yaml`](../manifest.yaml), `../build.sh`, and
[`../README.md`](../README.md). It intentionally keeps its relative local
replacement and is covered by the default integration-test identity checks.
