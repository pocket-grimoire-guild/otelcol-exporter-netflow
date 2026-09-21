# NetFlow exporter operator guide

This repository contains a pinned OpenTelemetry Collector distribution that
receives parsed NetFlow records and exports them as NetFlow v5, NetFlow v9 or
IPFIX over UDP. The complete distribution configuration is
[`distribution/ocb/config.yaml`](../distribution/ocb/config.yaml). It has
three independent `logs` pipelines and uses the Collector environment
provider included by the pinned OCB manifest.

The supported input is the parsed
`contrib-netflowreceiver-v0.160.0` schema. The example sets `send_raw: false`:
the receiver's parsed records have an empty body, while a `send_raw` formatted
body is unsupported input. Resource and scope attributes are provenance; they
do not fill flow fields or select a receiver version.

For installation in a separate versioned Collector, follow the
[external consumer recipe](../distribution/ocb/consumer/README.md), including
its complete environment settings and publication prerequisite. The recipe
retains fresh templates 300/301, measured-time attestation and explicit legacy
profile selection. The source-checkout build below remains the development path.

For a compact supported-version and upgrade contract, see the
[alpha compatibility summary](compatibility/alpha-upgrades.md). Reporting and
best-effort support expectations are in the [security policy](../SECURITY.md).

## Build and run the example

Use Linux/amd64 and Go 1.26.8. From the repository root, choose unused input ports
and output endpoints. These values are a complete loopback example; input and
output endpoints are deliberately different so the Collector cannot feed its
own output back into the receiver.

```bash
export NETFLOW_V5_PORT=2055
export NETFLOW_V9_PORT=2056
export NETFLOW_IPFIX_PORT=4739
export NETFLOW_METRICS_PORT=8888
export NETFLOW_V5_ENDPOINT=127.0.0.1:15005
export NETFLOW_V9_ENDPOINT=127.0.0.1:15009
export NETFLOW_IPFIX_ENDPOINT=127.0.0.1:14739
# Pick stable origins preceding every accepted v5/v9 flow.
# These recent origins suit newly measured flows in this local example.
export NETFLOW_V5_ORIGIN="$(( $(date -u +%s) - 4 ))000000000"
export NETFLOW_V9_ORIGIN="$NETFLOW_V5_ORIGIN"

./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
/tmp/otel-netflow-collector validate --config distribution/ocb/config.yaml
/tmp/otel-netflow-collector --config distribution/ocb/config.yaml
```

`NETFLOW_V5_ORIGIN` is an integer number of UTC Unix nanoseconds. Set it once
for the process, keep it at or before every v5 flow start, and do not reset it
per record. For a remote collector, replace the three output endpoints with
the actual `host:port` values and allow the UDP traffic through the network
policy. A hostname is accepted, but its DNS resolution and refresh are part of
the destination lifecycle; numeric addresses make this example deterministic.

The Collector resolves the `${env:...}` expressions in the file. Do not paste
the shell values into a second YAML as a substitute for the checked-in
configuration. To exercise the exact file, including startup, all three
protocols and graceful shutdown, build the binary and run:

```bash
NETFLOW_OCB_BINARY=/tmp/otel-netflow-collector \
  go test -mod=readonly ./integration/ocb \
  -run '^TestCollectorOperatorExample' -count=1 -timeout=3m -v
```

The broader smoke command and its independent decoder are documented in the
[distribution README](../distribution/ocb/README.md). Generated Collector
source and binaries are build outputs below `dist/` or the path passed to
`--out`; the root module is not rewritten.

`NETFLOW_METRICS_PORT` must be a numeric, unused TCP port on loopback. Choose a
different value for every Collector process on the same host; the metrics
reader is part of the process lifecycle and cannot be shared by two listeners.
After startup, query the pinned pull reader locally:

```bash
curl --fail --silent --show-error --max-time 1 \
  --header 'Accept: text/plain; version=0.0.4' \
  "http://127.0.0.1:${NETFLOW_METRICS_PORT}/metrics"
```

The example binds this endpoint to `127.0.0.1` and provides no authentication
or encryption. Keep the port on loopback and apply host controls when local
metrics contain operational information. A successful HTTP scrape observes the
Collector's local telemetry endpoint; it does not acknowledge a remote UDP
receiver.

## Operator metrics and mixed requests

With `level: normal`, the checked-in examples expose exporter-local outcomes
and the pinned Collector helper signals through the same pull reader. The real
example regression observes these exact names in a Prometheus text 0.0.4
scrape (`Accept: text/plain; version=0.0.4`):

| Scrape name | Labels on the observed series |
| --- | --- |
| `otelcol_netflow_exporter_records` | `exporter`, `outcome` |
| `otelcol_netflow_exporter_rejected_records` | `exporter`, `rejection_reason` |
| `otelcol_netflow_exporter_data_messages` | `exporter`, `outcome` |
| `otelcol_exporter_sent_log_records` | `exporter` |
| `otelcol_exporter_send_failed_log_records` | `exporter` (observed on the v9 time-rejection control) |
| `otelcol_exporter_in_flight_requests` | `exporter`, `data_type="logs"` |
| `otelcol_netflow_exporter_uptime_remaining` | `exporter` (Float64 gauge, seconds) |
| `otelcol_netflow_exporter_uptime_exhausted` | `exporter` (Int64 gauge, dimensionless `0` or `1`) |

Filter by the trusted configured identity, for example
`exporter="netflow/ipfix"`, and compare counter deltas after requests complete.
The counters have no unit or `_total` suffix. The local SDK instrument names
contain dots, such as `otelcol_netflow.exporter.records`; the text response
escapes them to underscores. Consumers negotiating other formats or UTF-8
escaping policies should verify the response names instead of assuming the
SDK spelling equals the scrape spelling.

The local counters describe the exporter's protocol result for each source
record. For a two-record request with one valid record and one unsupported
protocol map miss, the expected semantic delta is one `records` point with
`outcome=confirmed`, one with `outcome=invalid`, and one
`rejected_records` point with `rejection_reason=map_miss`. The helper's
`otelcol_exporter_sent_log_records` counts the whole request handed to the
helper, so that request contributes two sent records even though only one was
confirmed locally. If the helper receives a returned error, its
`otelcol_exporter_send_failed_log_records` signal likewise accounts for the
original request count; it is not a count of
invalid or unsuccessfully encoded records. Each rejected record contributes one
fixed first-reason point, so the sum of `rejected_records` reasons reconciles
with the local `records{outcome=invalid}` total for the request. An absent,
never-used helper failure series means zero; the successful mixed-request
regression does not force it to materialize. The in-flight signal should return
to zero after the request completes. A valid-only request leaves cumulative
rejection counters unchanged.

These are deliberately separate accounting layers. A mixed request can return
success after valid siblings are handed to UDP while invalid siblings are
dropped and counted locally. A full local UDP write means kernel handoff only;
it does not prove remote delivery or receiver acknowledgement. The helper
queue and automatic retry remain disabled, and a retry of an ambiguous subset
can duplicate a datagram.

The lifetime gauges are read-only observations of the existing v5/v9 epoch
state. In the checked-in example, the actual Prometheus sample names are
`otelcol_netflow_exporter_uptime_remaining` and
`otelcol_netflow_exporter_uptime_exhausted`; each has only the trusted
`exporter` label. The observed example identities are `netflow/v5` and
`netflow/v9`; startup and later pulls from the enabled reader contain both
points for those instances, while `netflow/ipfix` has no lifetime samples.
The remaining gauge is a finite, nonnegative Float64 projection
in seconds of the origin-relative elapsed-millisecond budget. It follows the
configured v5 or timed-v9 origin, or the implicit origin captured by a
successfully published v9 epoch, so it describes origin age rather than
Collector process age. The exhausted gauge is a binary Int64 value in the
dimensionless unit `1` and reports the existing epoch latch. IPFIX has no
uptime window of this kind, so `netflow/ipfix` has no lifetime pair.

Collection refreshes the projection at scrape time. A quiet scrape does not
reserve wall time, capture an origin, send data, change readiness or set or
clear the latch. The latch changes only when an existing data, template,
bootstrap or refresh operation observes exhaustion. A positive remaining
value does not promise that a header or record is otherwise representable or
that a UDP handoff will succeed. At `remaining=0` and
`exhausted=0`, the projection has reached its limit while no existing
operation has observed the terminal latch yet. At `exhausted=1`, the
published epoch is terminal, including after a wall-clock rewind; valid local
records remain unsent and the existing error and accounting paths apply.

The pair is intentionally absent in several conditions. A configured origin
alone, a Collector that has not successfully published an endpoint, a failed
startup or bootstrap candidate (including an expired explicit-origin v9
candidate), a closing or shut-down exporter, and unavailable telemetry do not
produce a healthy zero. A replacement candidate is not observable until it is
published; if replacement fails, the older published epoch remains the one
observed. One scrape already in flight can carry that previous published
epoch, and the next scrape reflects a successful replacement. Shutdown
unregisters the callback before it returns, without manufacturing a final
zero. While the epoch is unlatched, an invalid clock sample unrelated to
lifetime omits only `remaining`; `exhausted` stays zero. That sample cannot
create a lifetime latch, and a later valid sample can restore the projection.
A latched epoch keeps its `0`/`1` pair even with an invalid clock sample. Treat
scrape or provider absence as an independent health signal. A repeated restart
with the same explicit origin does not heal an exhausted epoch; use the
existing origin and migration planning guidance. These observations add no
rollover, reset, retry, endpoint recovery or configurable lifetime behavior.

As an illustrative monitoring rule, alert when `remaining <= 86400` seconds
(24 hours), adjusted for the deployment's migration lead time and scrape
interval, and handle `exhausted == 1` immediately. The 86,400-second value is
an operator monitoring example only: it is not a product warning, admission
cutoff, retry trigger or configurable lifetime. Continue to use the existing
startup errors, helper failure accounting and bounded diagnostic/log guidance
for those failure paths; the lifetime pair carries no origin, reason or
endpoint label.

The ordinary smoke matrix has a deliberate disabled-telemetry control. It
derives `level: none` from the checked-in configuration while retaining the
reader stanza, supplies a numeric loopback metrics port held by a test-owned
occupied TCP socket, and keeps that reservation through startup and shutdown.
Startup must succeed because the disabled provider ignores the retained reader;
the test then closes and rebinds the reservation to distinguish its control
socket from a Collector endpoint. Transport-isolation cases retain their
explicit disabled/no-reader service configuration and do not require a metrics
environment variable. The operator example uses the normal reader and releases
its reserved port immediately before process start, so a bind race remains
visible.

## Schema, profiles and explicit mapping

The example uses one immutable profile per destination. Profile names include
the exact receiver schema and a version, so a schema or field-order change
requires a new profile identifier.

| Protocol | Profile and output shape | Identity and time behavior |
| --- | --- | --- |
| NetFlow v5 | `contrib-netflowreceiver-v0.160.0/netflow-v5-fixed-v1`; fixed 48-byte IPv4 records, no templates | `identity.engine_type`, `identity.engine_id`, optional `sampling_mode`, and required `uptime_origin`; the fixed record requires the Layer-3 octet provenance assertion |
| NetFlow v9 | `contrib-netflowreceiver-v0.160.0/netflow-v9-timed-v1`; one ordinary IPv4 template and one ordinary IPv6 template, with 51-byte and 75-byte records | `identity.source_id` and required `uptime_origin`; FIRST/LAST use origin-relative milliseconds within a bounded lifetime; fresh templates 300/301 |
| IPFIX | `contrib-netflowreceiver-v0.160.0/ipfix-general-v1`; one ordinary IPv4 template and one ordinary IPv6 template, with 72-byte and 96-byte records | `identity.observation_domain_id`; selected start/end fields use IPFIX dateTimeMilliseconds; the example uses fresh template IDs 300/301 |

The v9 and IPFIX profiles send two initial copies of each ordinary template.
They have no Options Template or Options Data records. IPFIX uses ordinary IE
34 `samplingInterval`, which remains decodable but is deprecated; the exporter
does not silently replace it with IE 305 or create an Options sampling cache.
The fixed field order, widths and losses are published in the
[profile contract](compatibility/default-profiles.md) and the
[protocol matrix](compatibility/protocol-mapping.md).

Mapping selection is explicit. A destination must choose exactly one nonempty
profile or nonempty ordered `mapping.fields` list and must set
`mapping.loss_policy`. The built-in profiles require
`encode_and_count`; there is no hidden mapping or implicit loss acknowledgement.
The example declares only the receiver tokens it intends to encode:

```yaml
protocol_identifiers: [{token: tcp, number: 6}, {token: udp, number: 17}]
network_type_versions: [{token: ipv4, version: 4}, {token: ipv6, version: 6}]
loss_policy: encode_and_count
```

An input with another protocol token is rejected by this example until that
token and its frozen number are added. Tokens are exact receiver literals;
there is no case folding, aliasing, numeric-string conversion, IANA lookup or
reverse lookup. `network_type_versions` is used by v9/IPFIX to bind `ipv4:4`
and `ipv6:6` to address-derived families. The v5 mapping additionally declares
`mapping.input_guarantees.flow_io_bytes: layer3_total_octets`, an operator assertion
that is required for its `dOctets` slot and is never inferred by the exporter.

`encode_and_count` acknowledges only the documented exact, lossy and synthesized
matrix cells. Missing required values, malformed addresses, inconsistent flow
endpoint families, protocol mismatches, and width or timestamp failures reject
that record. Unsupported or inapplicable selected arms fail configuration.
Valid optional `flow.next_hop` and `flow.bgp_next_hop` values may each have an
independent IP family when unselected, without changing the flow family or
mapped output. A selected hop
must match its descriptor's IP family and width (4 bytes for IPv4, 16 for IPv6);
v5 always selects an IPv4 next hop and has no BGP next-hop slot. Malformed
present hops reject even when unselected. Values are range checked; they are
not clamped or silently truncated; the general IPFIX profile explicitly floors
times to milliseconds. Unknown and valid unselected attributes do not become
wire loss and do not make an otherwise encodable record invalid.

The recommended v9 timed and IPFIX general profiles require measured-time
provenance. For the supplied receiver pipeline, deployment must attest that
original source templates carried measured flow times and the receiver
preserved them; another producer may construct the exact compatible
representation without literal Contrib origin or receiver scope identity, but
must establish its own field semantics and provenance. Check the prominent
comment in the complete example before deployment. The exporter re-encodes
`flow.start`/`flow.end`; it never infers measured provenance or substitutes
receipt/export/envelope timestamps. Keep original-source identity separate from
this exporter's configured observation domain and UDP identity.
ICMP type/code is absent from the general shape even if ICMP tokens are enabled;
other frozen tokens require explicit sequence entries as documented in the
[profile catalog](compatibility/default-profiles.md).

To omit time output explicitly, use the complete
[time-omitting field-list recipe](compatibility/default-profiles.md#explicit-time-omission).
For v9 time omission, select `contrib-netflowreceiver-v0.160.0/netflow-v9-core-v1`
explicitly. All 39 required input keys still apply. To retain legacy NTP output, select
`contrib-netflowreceiver-v0.160.0/ipfix-core-v1` explicitly. When changing a
layout on an existing destination, allocate fresh template IDs (the example
uses 300/301), or deliberately isolate a new identity. A restart does not
invalidate every collector cache.

## Requests, packet fit and results

An OTel request is streamed across complete packets at record boundaries.
There is no request-wide record, byte, metadata-size or metadata-depth
admission ceiling. A request with many supported records may therefore emit
many datagrams, and ignored resource/scope metadata does not arbitrarily reject
those records. A record that cannot fit an empty message or cannot be
represented by the selected profile is rejected locally; it is never split
across packets. Valid siblings continue.

Each exporter instance admits one request at a time. The admitted request waits
if internal template refresh or endpoint publication is using the destination;
it continues when that work releases send serialization. A second request
receives a transient busy error immediately, even while the first is waiting.
The admitted caller can cancel its wait, and shutdown cancels it and closes the
destination. Cancellation before packing returns transient unavailable, or
closed when shutdown is observed, without sending data. No automatic retry or
request queue is added. A caller without a deadline may wait for internal work;
there is no FIFO or fairness guarantee. After packing begins, cancellation can
still require request-size-dependent validation and failed-subset copying.

The default `max_datagram_size` is 464 bytes of UDP payload. The default
per-message record cap is 30 for v5 and 256 for v9/IPFIX. Under the default
464-byte payload, the fixed profiles fit at most these data records in one
packet (header plus Data Set header included):

| Protocol shape | Record width | Actual default-payload fit |
| --- | ---: | ---: |
| v5 IPv4 | 48 bytes | 9 records |
| v9 timed IPv4 / IPv6 | 51 / 75 bytes | 8 / 5 records |
| v9 legacy core IPv4 / IPv6 | 43 / 67 bytes | 10 / 6 records |
| IPFIX IPv4 / IPv6 | 72 / 96 bytes | 6 / 4 records |

The configured v5 cap can never exceed 30. v9/IPFIX can be configured up to
1,024 records per message, subject to their complete message and Set lengths;
the UDP payload setting is bounded to 65,507 bytes. The two profile templates
also fit the default payload. Custom string/octet lengths may be declared
through 65,535 bytes. V9 private descriptors are fixed length; IPFIX enterprise
descriptors may be fixed or variable length. The complete template, record,
message and path budget still determines whether a particular record fits.

`path_mtu`, when supplied, is a trusted lower-bound assertion from the
operator, not discovery. Validation requires payload plus 28 bytes for a
literal IPv4 endpoint, or 48 bytes for a literal IPv6 endpoint or hostname, to
fit the asserted MTU. Without `path_mtu`, a configured payload above the 464
byte conservative default is rejected. IPv4 options, IPv6 extension headers,
dynamic PMTU discovery and jumbograms are outside this profile.

Invalid records are permanently dropped for the affected destination. If a
request contains invalid records and all valid records complete, `ConsumeLogs`
returns nil. If every record is invalid, it returns a redacted permanent error.
When a transient UDP handoff fails after a confirmed prefix, the returned
`consumererror.NewLogs` contains only the ambiguous current packet and valid
unsent suffix. Confirmed and permanently invalid records are excluded. The
standard Collector helper reports failure against the original request count,
while exporter-local confirmed/invalid/ambiguous/unsent counters describe the
actual protocol outcome; this deliberate difference is observable in
diagnostics and telemetry.

The helper queue and automatic retry are disabled. A caller that retries the
returned subset can duplicate an ambiguous datagram that the receiver may have
received. Retrying the original request can also duplicate the confirmed
prefix. UDP has no receiver acknowledgement.

## UDP delivery, isolation and templates

Each named exporter instance owns one connected UDP destination socket and its
own protocol state. A full local socket write with no error means bytes reached
the local kernel handoff; it does not prove remote receipt. UDP can lose,
duplicate or reorder datagrams, and this exporter adds no acknowledgement,
retransmission, congestion shaping, persistence, batching queue or transport
encryption. `sending_queue.enabled: true` and
`retry_on_failure.enabled: true` are rejected. TCP, SCTP, TLS and DTLS are not
implemented.

Collector fan-out is not atomic: one exporter instance may accept a record even
when a sibling instance fails. Each instance retains its own sequence,
templates, DNS epoch, socket and counters. The example uses numeric loopback
endpoints; hostname destinations resolve bounded A/AAAA answers and can retain
an old address for their configured staleness window before reporting an
unavailable destination.

Catalogs are static for an endpoint epoch: templates are published in catalog
order, are refreshed as a complete round, and are never dynamically withdrawn
or reused under another shape. The default `templates.initial_copies` is 2
(the accepted range is 2 through 8, a project policy), and
`templates.refresh_interval` accepts 30 seconds through 24 hours and defaults
to 10 minutes. Explicit zero is invalid in public Collector configuration;
omitting the setting retains the default. A v9 endpoint also
refreshes after 20 successful Export Packets, including template packets, by
default; an IPFIX data-packet refresh count is disabled when its setting is
absent. Successful v5 and IPFIX data records advance their sequence by record
count modulo 2^32; successful v9 export packets advance sequence by packet,
including template packets. Restart closes the old socket and starts a fresh
in-memory epoch with sequence and template progress reset; no state is
persistent across restart.

For a consumer that benefits from frequent template publication, use the complete
[30-second consumer recipe](../distribution/ocb/config-consumer-30s.yaml).
It explicitly sets `templates.refresh_interval: 30s` for both v9 and IPFIX,
retaining the same profiles, origins, environment variables and three pipelines
as the standard example. After the build and environment setup above:

```bash
/tmp/otel-netflow-collector validate --config distribution/ocb/config-consumer-30s.yaml
/tmp/otel-netflow-collector --config distribution/ocb/config-consumer-30s.yaml
```

The [profile guidance](compatibility/default-profiles.md#ipfix-general-v1-recommended)
records the 30-second option. This recipe provides another
opportunity to learn templates after template loss or a consumer restart,
including when the exporter is idle after bootstrap. UDP delivery is still
unacknowledged; a refresh cannot recover lost data. At idle, a 30-second interval
sends template rounds twenty times as often as the 10-minute default, increasing
network and consumer processing overhead. Packet-count triggers may send rounds
sooner under traffic. These are template publication timers, distinct from a
device's active/inactive flow-cache timeouts; this exporter has no flow cache.
No Options export requirement or SNA appliance ingestion, storage or sampling
success is implied. Measured-time provenance and the v9 origin/lifetime limits
still apply.

Plain UDP has no confidentiality, peer authentication or message integrity
beyond the protocol's ordinary checksum. Use a trusted network, firewall or
an external secure tunnel when those properties are required. The exporter
does not implement the IPFIX DTLS or congestion-control portions of the wider
RFC capability set, so the demonstrated profiles should not be described as
full-RFC transport support.

## Time ranges and process lifetime

Source timestamps and configured origins use nonnegative Unix nanoseconds in
the signed-safe range `0` through
`9,223,372,036,854,775,807` ns. The exporter does not infer an origin from a
record or envelope timestamp.

NetFlow v5 and v9 header export seconds are unsigned 32-bit Unix seconds,
ending at `2106-02-07T06:28:15Z`. Their `sysUpTime` and switched-time fields
are unsigned 32-bit elapsed milliseconds. For a configured origin, each
selected switched time must satisfy exact millisecond alignment,
`origin <= start <= end`, and `0 <= FIRST <= LAST <= sysUpTime <=
4,294,967,295`; there is no rollover handling. The elapsed window is about
49.71 days. The recommended v9 timed profile and v5 require an explicit origin.
The legacy v9 core profile omits
FIRST/LAST; without a configured origin, startup captures an origin before the
first bootstrap write for use by every v9 header. A selected v9 shape containing FIRST/LAST requires the
explicit origin so those record values can be checked against it.

When elapsed time from a v5/v9 origin exceeds the uint32-millisecond limit, exhaustion
is latched. Restarting with the same explicit origin does not heal it; changing
the origin changes the timestamp contract and must be planned against the
input source. A v9 instance without an explicit origin can capture a new
startup origin in a new in-memory epoch after restart. No protocol rollover or
persistent state is provided. A new origin must still precede every accepted
historical flow; resetting it to process start can invalidate delayed records.
This makes timed v9 a **bounded-lifetime setup**. Prefer the IPFIX general
profile for longer unattended service and for wider counters/interfaces.

V9 header export seconds discard the fractional Unix second. A consumer using
`export_seconds * 1000 - sysUpTime + switched` can reconstruct both endpoints
earlier than their measured Unix values by the discarded fraction (0 to less
than 1000 ms), while preserving their interval. With an epoch-ms-aligned origin
the shift is an integer 0..999 ms. An integral-second export instant removes
this ambiguity; the exporter does not round source values to repair it.

The recommended IPFIX general profile floors nonnegative canonical Unix ns to
unsigned 64-bit Unix milliseconds in IEs 152/153. It accepts the signed-safe
canonical range through `MaxInt64` ns, without an NTP-era dependency. Original
start/end ordering is validated before flooring, so sub-ms intervals may collapse
but reversed input rejects. Exact-ms and sub-ms inputs carry the same selected
loss classification. Export headers remain uint32 Unix seconds, ending in 2106;
a year-2262 arithmetic boundary test is not a realistic supported send date.
The exporter does not currently enforce IPFIX end <= export time; deployments
must ensure this prerequisite.

Legacy IPFIX dateTimeNanoseconds values use the 64-bit NTP representation and the
nearest `2^-32`-second fraction. For selected flow timestamps, the current
encoder accepts Unix epoch `0` through
`2,085,978,495,999,999,999` ns (`2036-02-07T06:28:15.999999999Z`); values after
that first NTP era are out of range. IPFIX header export seconds still use the
unsigned 32-bit Unix second bound above. These are range restrictions, not
support for timestamp rollover or arbitrary future eras.

Failed-subset returns preserve the input resource, scope and log envelopes with
the pinned public pdata `CopyTo` API. That API recursively copies nested pdata
values, so extreme nesting can exhaust the Go stack during envelope copying.
The exporter detaches byte leaves with an iterative worklist and tests exceed
the retired depth threshold, but this does not establish unlimited-depth stack
safety or a fixed whole-process RSS guarantee.

## Evidence and scope

The complete requirement/code/test/interop matrix is maintained in the
[MVP acceptance record](mvp-acceptance.md). The runnable example is exercised
by `integration/ocb:TestCollectorOperatorExample`; receiver semantic tests,
immutable goldens, lifecycle/transport checks and the pinned independent
TShark runner provide the corresponding lower-level evidence. The demonstrated
boundary is the pinned OCB `v0.160.0` Linux distribution and its static profiles;
it does not cover every receiver, platform or transport failure mode.

The [product specification](product-specs/netflow-exporter.md),
[profile contract](compatibility/default-profiles.md),
[component contract](design-docs/collector-component.md) and
[security model](SECURITY.md) remain the detailed sources of truth. Raw replay,
additional transports, profile expansion and release packaging are outside
this operator example.

## Configuration schema

Use the generated [configuration schema](configuration-schema.md) for editor
autocomplete and structural checks. The guide records the pinned generation
and validation commands, v5/v9/IPFIX examples, and parser-only constraints.
Collector configuration validation remains authoritative.
