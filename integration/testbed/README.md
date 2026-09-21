# Collector testbed

This optional Linux integration module exercises a generated Collector with
bounded loopback scenarios. It sends canonical IPv4 flow records through the
actual Collector and checks UDP payloads with an independently installed
TShark. The default scenario is a small repeated-measurement check, not a
throughput benchmark or capacity qualification.

Build the testbed distribution from the checkout root with Go `1.26.8` on
`PATH`. The runner defaults to `/usr/local/go/bin`; when Go is installed
elsewhere, set `GO_BIN_DIR` to the directory containing that `go` executable:

```sh
export GO_BIN_DIR="$(dirname "$(command -v go)")"
GOMAXPROCS=2 GOFLAGS=-p=2 timeout --kill-after=5s 180s \
  go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
  --config integration/testbed/manifest.yaml --skip-strict-versioning=false
gofmt -w dist/testbed/*.go
integration/testbed/run.sh
```

The runner accepts `TESTBED_SCENARIO=baseline` (default), `sustained`,
`overload`, or `recovery`. It requires Linux, a TShark executable, and the
generated Collector binary. The script default is TShark `4.4.18`; set
`TSHARK_BIN` and `EXPECTED_TSHARK_VERSION` together when using another
installed version. This host-oracle lane is separate from the digest-locked
TShark `4.6.8` runner in [`integration/tshark`](../tshark/README.md).

Use a fresh artifact parent and keep it outside the checkout:

```sh
export ARTIFACT_PARENT=/tmp/netflow-testbed-artifacts
export TSHARK_BIN=/absolute/path/to/tshark
export EXPECTED_TSHARK_VERSION=4.4.18
integration/testbed/run.sh
```

`baseline` runs three sequential 100-record cases. `sustained` runs one
1,000-record case per protocol, `overload` offers up to 3,000 records through
four synchronous senders, and `recovery` sends 40 records across a receiver
close/rebind. Every scenario uses loopback, bounded deadlines, process-group
cleanup, bounded logs/captures, and a finite fresh run tree. It does not alter
host networking or resolver settings.

The testbed validates real `confmap` and `Config.Validate` decoding, provider
exhaustion, decoder capture rejection, cleanup, child exits, and process-group
reaping. It retains TShark field output, synthetic PCAPs, timing measurements,
configuration/log files, and bounded CPU/heap/RSS observations. These values
include Collector and profiling overhead; they are observations of the selected
scenario, not exporter-only allocation rates or a memory gate.

The recovery scenario checks receiver restart behavior, exporter endpoint epoch,
template cache state, and confirmed/ambiguous/unsent telemetry. It does not
qualify wall-clock template refresh, remote delivery, physical NIC behavior, or
general receiver security. A passing run demonstrates bounded execution and
the stated local observations only.

For a bounded receiver interruption check, use a fresh artifact root and run
the recovery scenario after building the same generated Collector:

```sh
export TESTBED_SCENARIO=recovery
export ARTIFACT_PARENT=/tmp/netflow-testbed-recovery
integration/testbed/run.sh
```

The scenario offers 40 unique records per protocol: three warm records, three
offers while the receiver socket is closed, then 34 offers after rebinding the
same receiver port. It uses loopback, finite deadlines, bounded logs and
captures, process-group cleanup and a fresh run tree. For v9 and IPFIX, the
recovery configuration uses packet-count refresh 20 so template bootstrap and
refresh behavior can be observed; production defaults are unchanged.

The recovery evidence keeps the exporter peer and endpoint epoch, local outcome
and lifetime/drop counters, receiver epochs, call results and independent UDP
receipt/decode observations separate. A missing receipt during the closed
socket interval is an observation-window result, not proof of remote loss.
TShark must account for warm, combined and resumed captures, including the
fresh-cache template boundary; v5 decodes without templates. Template or
sequence ambiguity, missing warm state, late outage receipts and incomplete
decoder ledgers fail the bounded case visibly. TERM/INT must cancel the work
and reap the Collector process group; forced cleanup or nonzero shutdown is a
failure. This scenario remains local loopback evidence and does not establish
remote UDP delivery or wall-clock refresh qualification.

Run the nested tests with:

```sh
cd integration/testbed
GOMAXPROCS=2 GOFLAGS=-p=2 go test -mod=readonly -race ./... -count=1 -timeout=60s
```

The root `make check test` remains the ordinary repository baseline.
