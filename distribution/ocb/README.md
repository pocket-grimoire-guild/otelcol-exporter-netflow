# Local Collector distribution

For a separate Collector using an explicit exporter module version, see the
[v0.2.0 consumer recipe](consumer/README.md). It selects the real module
version without a local replacement. The separate staged check verifies local
packaging and integration under a synthetic identity; it does not prove public
module retrieval.

For the operator-facing walkthrough, complete environment settings, profile
choices, fit calculations and lifetime/security limits, see the
[operator guide](../../docs/operator-guide.md). This README records the pinned
build and acceptance smoke details. The complete
[consumer recipe](config-consumer-30s.yaml) explicitly selects 30-second v9/IPFIX
template refresh; the standard example and component default remain at 10 minutes.
Both use the environment setup and measured-time prerequisites in the operator guide.

This builds an actual Collector with the local logs exporter and the Contrib
NetFlow receiver. It uses standard OCB `v0.160.0`, Core beta modules `v0.160.0`,
stable modules `v1.66.0`, and Go `1.26.8`. No Collector internals are imported by
the exporter. The build formats OCB's generated Go source with `gofmt` so it
also passes the repository-wide formatting check. Generated source, module graph and binary live in the ignored
`dist/ocb/` directory; the root module is not rewritten.

From the repository root, with Go 1.26.8 on `PATH`:

```bash
./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
/tmp/otel-netflow-collector components
./distribution/ocb/smoke_test.sh --binary /tmp/otel-netflow-collector \
  --fixture integration/testdata/ocb/canonical.yaml
```

The build uses the reviewed [manifest](manifest.yaml), enables OCB strict
version checks, and resolves the exporter with `replaces: ... => ../..` relative
to the generated `dist/ocb/go.mod`. Build requires access to the pinned Go modules
or a populated module cache. Run one build at a time in a checkout. To invoke
OCB directly from the root, first create `dist/`:

```bash
mkdir -p dist
go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
  --config distribution/ocb/manifest.yaml --skip-strict-versioning=false
gofmt -w dist/ocb/*.go
```

The smoke runs on Linux with loopback UDP and uses the binary's embedded Go
build information to check the relevant pins and local replacement. It validates
the real YAML config, rejects three invalid configurations before sockets open,
reserves input ports once, and waits for the Collector's post-start “Everything
is ready” event. A bind race fails the test. It sends the seven hash-checked
[goldens](../../integration/testdata/golden/manifest.json) through three receiver
pipelines, covering v5 IPv4 and v9/IPFIX IPv4, IPv6 and two input sampling rates.
The IPv6 cases measure IPv6 flows carried over IPv4 loopback UDP.

Every output template and data byte, including padding, is compared with the
independently authored goldens after the explicit receiver projection below.
Live headers check identity, version, count/length, sequence and export time;
v5 wall time must match its origin/uptime and v9 uptime must fit process lifetime.
The smoke checks four initial template packets per templated instance and no
unexpected packets before data or after shutdown. It requires zero exit status,
the completed-shutdown event within six seconds of SIGTERM, and rebinding all
three receiver ports. A 45-second process deadline, bounded diagnostics, and
process-group kill/reap cleanup cover failures. The smoke script allows five
minutes for the canonical matrix plus the three transport-isolation processes
below.

A fourth named IPFIX exporter has a valid UDP-only token map. All four TCP
records fail on that instance while the healthy sibling exports them. A final
declared UDP derivative succeeds on both: healthy sequence 4 and sibling
sequence 0, distinct source sockets and domains 42/43. The normal run sends
8 datagrams and receives 21 (12 bootstrap, 9 data). This injects a per-record
mapping rejection; it does not establish transport-failure isolation or atomic
fan-out. Collector fan-out can deliver to one instance even when another fails.

The script also runs `TestCollectorTransportIsolation` against the same built
binary, once per v5/v9/IPFIX. Each fresh process has one pinned receiver feeding
two identical mappings with separate UDP destinations. V9/IPFIX use domains
42/43; v5 uses engine type/ID 1/1 on both destinations. After complete bootstrap
and baseline delivery, the driver closes only the sibling's loopback UDP port.
Its next write succeeds locally and induces an ICMP port-unreachable error;
after a 100 ms settling interval, the following request must produce the
exporter-scoped `netflow/failing` transient handoff error with one rejected item.
This Linux-only test requires normal loopback ICMP delivery. Suppressed ICMP,
a port bind race, missing error, or wrong sequence fails the test.

Rebinding that same destination must receive two further inputs on the original
source socket. Healthy sequences advance through all five inputs; the sibling
commits the locally successful closed-port handoff and leaves the failed handoff
uncommitted. Recovery sequences are 3/2 (healthy/sibling) for v5/IPFIX and 7/6
for v9 after its four bootstrap packets. Each input carries a distinct source
port, 12345 through 12349, as a declared canonical-golden derivative. Exact
projected data comparisons therefore also reject replay of the failed record.
No data appears on the reopened port before recovery input, and outputs stay
quiet after bounded SIGTERM shutdown. The receiver port and both exporter source
ports must be reusable after exit. Across the three cases the driver retains
15 inputs and 40 output application datagrams, including 16 bootstrap packets.

To retain config, bounded process log, input/output datagrams and a compact
PID/binary/config/payload hash ledger, set `NETFLOW_OCB_ARTIFACTS` to an existing
directory outside the checkout. Otherwise the Go test removes its temporary
artifacts. For race checking the Go smoke driver:

```bash
NETFLOW_OCB_BINARY=/tmp/otel-netflow-collector \
  go test -race ./integration/ocb -run '^Test(CollectorSmoke|CollectorTransportIsolation|PacketValidation|TransportErrorEvidence)$' \
  -count=1 -timeout=5m
```

This race flag instruments the driver, not the separately built Collector.
Existing component race tests remain separate evidence.
Transport-isolation artifacts use fresh `ocb-transport-*` directories and include
the fully substituted config, bounded process log, phase/instance-labelled
input/output payloads, hashes, socket addresses, PID, binary hash and v5 origin.
Error-evidence mutation tests reject missing/wrong component attribution,
receiver-only messages, incorrect errors/counts and truncated diagnostics.

## Receiver projection and acceptance scope

The [pinned receiver contract](../../integration/testdata/receiver/README.md)
defines the projection. This smoke does not silently rewrite captured output:

- V5 rebases only the input header export seconds and configured origin together
  to avoid the 49-day uptime ceiling. Its 3000 ms input uptime and record bytes
  remain unchanged. The output engine identity is configured independently.
- V9/IPFIX ordinary IE 34 values 1000 and 2000 become receiver sampling zero;
  the second exporter therefore encodes zero. No Options records or sampling
  cache are added. Both input rates remain covered by the immutable goldens
  and earlier independent receiver tests.
- IPFIX's canonical end timestamp becomes `1788220801000999999` ns in the
  receiver. Re-encoding uses the accepted nearest-NTP rule, changing the end
  fraction from `0x00418937` to `0x00418933`. All other selected data bytes stay
  as documented. V9 omitted flow times do not appear in the output profile.
- Receiver sampler address and receive time are newly generated transport
  provenance. The built-in profiles do not export those fields.

The ordinary smoke retains application UDP datagrams from the OCB process.
The live command below also captures original outer IP/UDP headers.
Transport isolation covers a real
Linux UDP handoff error and recovery for all three protocols; it does not cover
timeouts, packet-loss recovery, or remote receiver template-cache recovery.
Product fuzz, load, leak and final integrated MVP acceptance are recorded in
the [completed local acceptance matrix](../../docs/mvp-acceptance.md).

## Live packets and independent checksums

On Linux/amd64, the live command runs the same seven-case matrix and named
mapping-rejection/recovery case across a disposable veth link. It requires
rootless Podman, the existing capture image below (Python 3, iproute2, unshare
and nsenter), and the exact [pinned TShark image](../../integration/tshark/IMAGE_DIGEST)
already present locally. No image is pulled. The capture image is selected by
digest and its image ID/digest/platform and actual container identity are
recorded. Use a local rootless Podman engine with fresh artifact paths owned by
the invoking user. Set `NETFLOW_CAPTURE_IMAGE` to a digest-qualified image that
is already available locally; this repository does not publish or maintain that
image.

```bash
./distribution/ocb/live_capture_test.sh --binary /tmp/otel-netflow-collector \
  --capture-image "$NETFLOW_CAPTURE_IMAGE"
```

The rootless capture container starts with `--network=none`. Its driver namespace
uses `198.18.0.1/30`; the Collector runs in a second namespace at `198.18.0.2/30`.
There is no uplink or default route. `SYS_ADMIN` creates/enters that child network
namespace, `NET_ADMIN` configures its veth pair, and `NET_RAW` captures ingress.
These capabilities exist only in the disposable rootless user namespace. The
container receives one read-only input mount and one private output mount, no
host namespace, engine socket, credentials or repository. Its root filesystem
is read-only, with no new privileges, 512 MiB memory/swap, 128 processes/file
descriptors, two CPUs, bounded output, and a 90-second outer deadline. Cleanup
removes the container on every exit; the decoder separately uses its existing
capless/no-network limits and mandatory cleanup.

Linux loopback keeps checksum offload enabled and its captured UDP checksum can
be unfinished. The veth test instead disables transmit checksum offload on both
ends using the [Linux ethtool UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/ethtool.h)
and requires the effective read-back to be zero before sending. The
[kernel implementation](https://github.com/torvalds/linux/blob/v6.12/net/ethtool/ioctl.c)
applies that operation to the device's supported checksum features. No host
interface setting changes. Captured bytes are never repaired or rewritten.

An AF_PACKET socket receives complete Ethernet/IPv4/UDP frames on the driver
veth before Collector startup, with kernel `SO_TIMESTAMPNS` timestamps. Exactly
21 inbound UDP packets, zero socket drops, and a one-to-one match with every
application capture are required, including peer/local sockets, length, hash
and full payload bytes. Twelve packets bootstrap templates and nine carry
data. Actual capture order is retained, including independently started
exporters; identical bootstrap copies consume separate ordered occurrences.
Checks require valid IPv4 and nonzero valid UDP checksums for every packet.
SIGTERM shutdown, quiet outputs and receiver-port reuse are checked in the
Collector's actual namespace.

The fresh PCAP goes unchanged to the pinned offline TShark runner. Its literal
field expectations reuse the immutable oracle's profile tables, with the
declared receiver projection above, split template/data packets, expected
domains and sequences, and live header times. It independently checks every
selected field's value/order/width/offset, templates, padding, zero Options,
the UDP derivative, both flow address families, packet/socket identity and
outer lengths/checksums. Live IE 34 is zero after the pinned receiver; the two
input rates remain distinguished by the immutable oracle. No synthetic PCAP
can stand in for this command's fresh capture.

Set `NETFLOW_OCB_LIVE_ARTIFACTS` to an existing private directory on the shared
filesystem to retain the input snapshots, compiled driver, image/container
identities, effective config, logs, application payloads, nanosecond `live.pcap`,
`network.json` (kernel, namespace/interface, offload and capture identity), and
the bounded independent decoder output. Otherwise the temporary directory
under ignored `dist/` is removed. To reproduce corruption regressions using
retained evidence:

```bash
python3 -B -m unittest discover -s integration/ocb -p 'test_live_capture.py'
NETFLOW_TSHARK_LIVE_DIR=/path/to/output/ocb-RESULT \
NETFLOW_TSHARK_LIVE_PDML=/path/to/output/ocb-RESULT/tshark-RESULT/live.stdout \
  go test -race ./integration/tshark/internal/oracle \
  -run '^Test(RecordedLivePDML|RecordedLiveBinding|LiveInputRejections)$' -count=1 -timeout=3m
```

These tests reject truncated/corrupt/checksummed-substitute packets, missing or
duplicate captures, socket/hash changes, and mutated decoder fields, payload,
length, checksum, identity and framing evidence. Stored reports alone do not
prove a fresh execution. The veth run establishes IPv4 transport with IPv4 and
IPv6 flow records; it adds no IPv6-transport, physical-NIC, refresh progression,
custom-enterprise or transport-failure capture claim. The separate ordinary
smoke continues to own real Linux UDP failure isolation/recovery.

## Running the configuration

The complete example selects `ipfix-general-v1` and `netflow-v9-timed-v1`,
each with fresh IDs 300/301. Timed v9 requires `NETFLOW_V9_ORIGIN` and is
a bounded-lifetime setup (about 49.71 days); prefer IPFIX for longer unattended
service and wider counters/interfaces.
It requires measured source-template time provenance, as attested in the YAML
comment; the exporter cannot recover missing measured times. Its 152/153 output
uses Unix milliseconds. The historical smoke matrix above explicitly selects
legacy `ipfix-core-v1` and `netflow-v9-core-v1`; `TestCollectorOperatorExample` runs the current example
unchanged. See the [operator guide](../../docs/operator-guide.md) for migration,
legacy NTP selection and an explicit time-omitting recipe.

[config.yaml](config.yaml) has three separate logs pipelines. Set
`NETFLOW_V5_PORT`, `NETFLOW_V9_PORT`, and `NETFLOW_IPFIX_PORT` to distinct nonzero
input ports; set the corresponding `NETFLOW_*_ENDPOINT` variables to the three
output `host:port` destinations. Keep input and output endpoints distinct to
avoid a feedback loop. Set `NETFLOW_V5_ORIGIN` to a stable Unix-nanosecond integer
at or before every input v5 flow start. Set `NETFLOW_V9_ORIGIN` with the same
contract for v9. Do not reset either per record. Timestamps must be exact
milliseconds relative to the configured origin, ordered and no later than export
time; elapsed uptime must fit uint32. A planned restart/new origin must still
precede every accepted historical flow. Source-time provenance is deployment-owned;
a receiver's receipt/export-time fallback is not measured-time preservation.

```bash
export NETFLOW_V5_PORT=2055
export NETFLOW_V9_PORT=2056
export NETFLOW_IPFIX_PORT=4739
export NETFLOW_METRICS_PORT=8888
export NETFLOW_V5_ENDPOINT=127.0.0.1:15005
export NETFLOW_V9_ENDPOINT=127.0.0.1:15009
export NETFLOW_IPFIX_ENDPOINT=127.0.0.1:14739
# Demonstration only: choose stable origins appropriate to all source flows.
export NETFLOW_V5_ORIGIN="$(( $(date -u +%s) - 4 ))000000000"
export NETFLOW_V9_ORIGIN="$NETFLOW_V5_ORIGIN"

/tmp/otel-netflow-collector validate --config distribution/ocb/config.yaml
/tmp/otel-netflow-collector --config distribution/ocb/config.yaml
```

`NETFLOW_METRICS_PORT` is a numeric loopback TCP port for the configured pull
Prometheus reader. Give each Collector process on the host a distinct unused
port, then inspect the local endpoint with:

```bash
curl --fail --silent --show-error --max-time 1 \
  --header 'Accept: text/plain; version=0.0.4' \
  "http://127.0.0.1:${NETFLOW_METRICS_PORT}/metrics"
```

The reader exposes local exporter outcomes and Collector helper accounting;
the [operator guide](../../docs/operator-guide.md#operator-metrics-and-mixed-requests)
defines their mixed-record and UDP handoff semantics. The endpoint is loopback
only and does not acknowledge delivery to a remote UDP receiver.

The same reader exposes the lifetime pair for the successfully published v5
and timed-v9 instances in this example:
`otelcol_netflow_exporter_uptime_remaining` is a Float64 seconds gauge and
`otelcol_netflow_exporter_uptime_exhausted` is a binary Int64 gauge with unit
`1`. Both carry only `exporter`, with observed instances `netflow/v5` and
`netflow/v9`; the IPFIX instance intentionally has no pair. Remaining is a
collection-time projection of age from the configured origin, not Collector
process age and not a promise of packet representability or UDP delivery.
Exhausted reports the existing terminal latch and is not set by a quiet
scrape. A `0`/`0` pair means the projection has reached the limit before an
existing operation has latched the epoch; `1` means the published epoch is
terminal, including after rewind, and valid local records remain unsent.
Absent points cover IPFIX, unpublished or failed startup/bootstrap state,
shutdown and unavailable telemetry; they must not be read as healthy zero.
One scrape already in flight during endpoint replacement may show the old
published epoch once; subsequent collection observes a successful replacement.
While unlatched, invalid non-lifetime clock input omits only remaining and
exhausted stays zero; a latched epoch keeps its `0`/`1` pair. Use independent health
monitoring for reader/provider absence and retain the existing startup/helper
failure and bounded-diagnostics guidance. An illustrative alert is remaining
at or below **86,400 seconds**, adjusted for migration lead time and scrape
interval, together with immediate exhausted-equals-one handling. This is an
operator monitoring example, not a product cutoff, warning, retry, reset or
configurable lifetime; the existing origin/restart and IPFIX guidance applies.

The ordinary smoke matrix intentionally derives `level: none` while retaining
the reader stanza. It holds a numeric test-owned loopback TCP reservation over
startup and shutdown to prove that the disabled provider ignores the reader,
then closes and rebinds that reservation. Transport isolation keeps its
explicit disabled/no-reader service configuration and needs no metrics
environment variable. The normal operator example uses `level: normal` and
releases its reserved metrics port just before process start.

The example intentionally accepts only the TCP and UDP tokens used here. Review
the [mapping profiles](../../docs/compatibility/default-profiles.md) and explicit
loss policy before adapting it. The v5 example asserts layer-3 total octets for
`flow.io.bytes`; that is an operator input guarantee. Endpoint, identity,
mapping, packet/path fit and UDP delivery semantics remain the exporter's public
configuration contract. Exporter queue and retry remain disabled; local UDP
write success is not a delivery acknowledgement.
