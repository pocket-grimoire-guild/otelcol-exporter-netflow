# Collector logs exporter component

- Status: accepted design, amended by the 2026-09-08 data-acceptance correction
- Date: 2026-09-02
- Scope: component topology, configuration, lifecycle, and Collector integration

This document is a design contract for component topology, configuration,
lifecycle, and Collector integration. The implemented data-acceptance behavior
allows large valid requests while retaining actual field, packet, and transport
bounds. Wire field mappings, packet state, and protocol encoding remain in
[ADR 0002](../decisions/0002-focused-wire-encoders.md) and the
[protocol-state design](protocol-state-transport.md).

`[F]` marks a fact read from a pinned external source; `[D]` marks an accepted
project decision; `[I]` marks an explicit project inference. Source links use
the exact revisions selected by the source ledger.

## Topology and boundaries

`[D]` One configured exporter instance owns exactly one UDP endpoint and one
wire protocol. Multiple destinations are multiple named instances in the same
Collector logs pipeline; the initial profile has no `destinations: []` fan-out.
Collector fan-out is not atomic: one named instance can accept a request before
another returns an error, so cross-destination duplication/loss is a documented
pipeline-level risk.

The instance owns its socket, resolver selection, endpoint epoch, metrics,
admission gate, shutdown state, and destination sequence/template/refresh state.
No mutable state is shared between instances. The dependency direction is:

```text
Collector logs -> structural check -> normalize -> compiled mapping
               -> destination pack/state -> pure protocol writer -> UDP
```

Root component files expose `NewFactory`, `Config`, validation, the logs adapter,
and the small lifecycle wrapper. Internal packages are `internal/model`,
`internal/normalize`, `internal/mapping`,
`internal/wire/{netflow5,netflow9,ipfix}`, `internal/destination`,
`internal/transport`, and generated `internal/metadata`. Writers do not read
clocks, DNS, sockets, Collector objects, or globals; the normalizer does not
know wire layout; transport does not know OTel records. The minimal checked
cursor API lives at `internal/wire/internal/cursor`: its concrete state remains
unexported, and Go's nested `internal` rule makes the small exported sibling API
unimportable outside the wire subtree. Per-destination constructor seams are a clock/timer, a bounded
resolver, and a connected UDP dialer/connection supporting deadlines,
whole-datagram writes, local/remote address inspection, and close. Production
implementations use the Go standard library; deterministic fakes cover clock,
DNS generations, legal/illegal write results, port reuse, and shutdown races.
The component imports no Collector `internal` package; only the pinned public
Collector modules and standard-library destination seams are allowed.

The wire writer is deliberately not repeated here: it is pure and deterministic
over normalized values and a selected static shape. Its state boundary and
independent-decoder obligations are in [ADR 0002](../decisions/0002-focused-wire-encoders.md).
No component or writer implementation, wire correctness, or interoperability
readiness is implied by this publication; those claims require later tests and
independent decoder evidence.

## Collector API and dependency pins

`[F]` The Core release tag is `v0.160.0` (annotated tag object
`109e6fa5484444f9e4d64a08b0a250212bbdcffa`) and dereferences to commit
`cd3455cf3a7f672208140b1ebb1581c542b2b0ed` ([release](https://github.com/open-telemetry/opentelemetry-collector/releases/tag/v0.160.0),
[versions.yaml at the commit](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/versions.yaml)).
Its `versions.yaml` declares stable modules `v1.66.0` and beta modules
`v0.160.0`; its module declares Go `1.26.0` ([versions.yaml](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/versions.yaml),
[go.mod](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/go.mod#L1-L18)).
The receiver-compatible schema is pinned to Contrib `v0.160.0`, commit
[`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/README.md#data-format).

`[F]` Core's public factory types are `CreateLogsFunc` and `NewFactory`, with
`WithLogs` assigning a creator and stability level ([exporter.go, lines
96–103](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporter.go#L96-L103),
[WithLogs/NewFactory](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporter.go#L187-L205)).
The component shape is therefore:

```go
func NewFactory() exporter.Factory {
    return exporter.NewFactory(
        metadata.Type,
        createDefaultConfig,
        exporter.WithLogs(createLogs, component.StabilityLevelAlpha),
    )
}

func createLogs(ctx context.Context, set exporter.Settings, cfg component.Config) (exporter.Logs, error) {
    // Validate cfg, then put helper behind one destination-local wrapper.
    helper, err := exporterhelper.NewLogs(ctx, set, cfg, pushLogs,
        exporterhelper.WithStart(destinationStart),
        exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
    )
    if err != nil {
        return nil, err
    }
    return newLogsWrapper(helper, destination), nil
}
```

The snippet records the required API and ordering, not an implementation. The
exact `exporterhelper.NewLogs` signature is `(context.Context,
exporter.Settings, component.Config, consumer.ConsumeLogsFunc, ...Option)
(exporter.Logs, error)`; it rejects a nil config or pusher and constructs the
logs request exporter ([pinned source](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/logs.go#L16-L32)).
`WithStart`, `WithCapabilities`, `WithTimeout`, `WithRetry`, and `WithQueue` are
public helper options ([source](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/common.go#L15-L47),
[queue option](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/queue_batch.go#L15-L42)).
The initial component passes no shutdown callback to the helper: the wrapper
owns destination shutdown and calls helper `Shutdown` exactly once afterward.

`[F]` Core's public logs consumer says pdata is no longer accessible after
`ConsumeLogs` returns ([consumer/logs.go](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/consumer/logs.go#L13-L27)).
The exporter reports `consumer.Capabilities{MutatesData:false}` through the
public alias and does not mutate pdata. The pusher reads pdata synchronously and
retains no caller objects except a bounded copied failed subset.

## Configuration contract

The following YAML names and absent-versus-zero meanings are the design
contract. Go types may use Collector optional/config helper types only when they
preserve those meanings.

```yaml
endpoint: collector.example:4739       # required host:port; no URL/userinfo/path
protocol: ipfix                        # netflow_v5 | netflow_v9 | ipfix
schema: contrib-netflowreceiver-v0.160.0
identity:
  observation_domain_id: 1234         # required for IPFIX; explicit zero allowed
# Attest that original source templates supplied measured start/end times,
# preserved into flow.start/flow.end. The exporter cannot infer provenance.
mapping:
  profile: contrib-netflowreceiver-v0.160.0/ipfix-general-v1
  protocol_identifiers:
    - {token: icmp, number: 1}
    - {token: tcp, number: 6}
    - {token: udp, number: 17}
    - {token: ipv6-icmp, number: 58}
    - {token: sctp, number: 132}
  network_type_versions:
    - {token: ipv4, version: 4}
    - {token: ipv6, version: 6}
  input_guarantees: {}
  loss_policy: encode_and_count       # required explicit loss acknowledgement
  custom: []                          # bounded static mappings only
ipfix:
  template_refresh_data_packets: 20   # optional count refresh; null disables it
templates:
  id_base: 300                       # fresh range for migration; IPv6 uses 301
  initial_copies: 2
  refresh_interval: 10m
max_datagram_size: 464                # UDP payload bytes
path_mtu: null                        # optional operator-supplied lower bound
max_records_per_message: 256
timeout: 5s
shutdown_drain_timeout: 5s
sending_queue:
  enabled: false                      # true is rejected in the initial profile
retry_on_failure:
  enabled: false                      # true is rejected in the initial profile
dns:
  refresh_interval: 5m
  stale_after: 1h
  timeout: 5s
```

This is the complete recommended IPFIX example, not a programmatic default.
General-v1 emits Unix-ms flow times; ICMP type/code is absent even when its
protocol tokens are enabled. The [profile guidance](../compatibility/default-profiles.md#ipfix-general-v1-recommended)
explains source provenance, fresh template ranges, legacy NTP selection and
explicit time omission.
`createDefaultConfig` leaves the mapping selector, token sequences, input
guarantees, and loss policy unset. Exactly one nonempty versioned profile or
nonempty ordered `fields` list is required; absent, empty, both, or mismatched
selectors fail before component creation. The immutable built-in catalogs,
ordered field-object grammar, token rules, v5 provenance assertion, and custom
field schema are the contract in
[`default-profiles.md`](../compatibility/default-profiles.md). The complete
pinned token vocabulary is in
[`receiver-token-vocabulary.md`](../compatibility/receiver-token-vocabulary.md).

### Numeric and duration validation

All conversions use checked arithmetic; absence selects a documented default,
and zero does not disable protocol or transport bounds. A value outside the range or violating a
cross-field rule is a configuration error before component creation.

| Setting | Default | Accepted range / cross-field rule |
| --- | ---: | --- |
| endpoint text | n/a | 1..512 bytes, static `host:decimal-port`; hostname ≤253 bytes; port 1..65535; no service lookup |
| observation-domain / source ID | n/a | explicit uint32, including zero |
| engine type / engine ID | n/a | explicit uint8 |
| v5 sampling mode | 0 | raw unsigned two-bit value 0..3; no unsourced friendly semantics |
| template ID base | 256 | 256..65535; full compiled catalog fits without wrap/collision |
| template initial copies | 2 | 2..8 complete catalog rounds |
| template refresh interval | 10m | 30s..24h |
| v9 refresh packet count | 20 | 1..1000 successful Export Packets, including template-only packets |
| IPFIX data-packet refresh | 20 | absent disables; present 1..1000 successful data-bearing messages |
| UDP payload | 464 bytes | 128..65507 bytes, further bounded by the PMTU rule below; every compiled template fits |
| configured path MTU | absent | absent caps payload at 464; present 512..65535 and must cover the payload plus base IP/UDP headers |
| records/message | 256 | 1..1024, with absolute v5 cap 30 |
| write/operation timeout | 5s | 100ms..30s and ≤ shutdown drain |
| shutdown drain | 5s | 1s..30s |
| DNS refresh | 5m | 1s..24h |
| DNS staleness | 1h | DNS refresh..7d |
| DNS timeout | 5s | 100ms..30s and ≤ drain |


Additional static limits are at most 16 template shapes, 64 fields per shape,
4096 encoded template bytes per shape, 32 custom mappings, and 32 distinct PENs
per instance. Template IDs are sequential and never reused in an endpoint epoch.

The cross-field contract is bounded and explicit:

* Exactly one protocol-specific identity is required. Endpoint and mapping are
  trusted operator configuration, never data-selected; only the pinned schema
  is accepted; `flow.type` is provenance, not an output selector.
* Custom IPFIX fields specify PEN, element ID, data type, and fixed/variable
  length. V9 private numeric types require explicit opt-in and have no PEN. V5
  custom fields are rejected. A selected immutable profile or explicit ordered
  field list forms a static catalog; there is no hidden mapping default.
  Address-family variants are catalog shapes, not record-controlled templates. Missing required
  fields reject the record, and statically unsupported selections fail config.
  `encode_and_count` permits only matrix-enumerated loss with bounded telemetry;
  `reject` rejects selected lossy/synthesized cells.
* V5 requires a stable configured `uptime_origin`; v9 requires one only when
  FIRST/LAST fields are selected (the default shape omits them). Origins and
  header uptime values are representable, and selected FIRST/LAST values are
  exactly millisecond-aligned with `0 <= FIRST <= LAST <= sysUpTime <= MaxUint32`.
* `path_mtu` is a trusted per-destination lower-bound assertion, not discovery.
  When absent, `max_datagram_size` may not exceed 464. When present, a literal
  IPv4 endpoint reserves 28 bytes (20-byte IPv4 plus UDP), a literal IPv6
  endpoint reserves 48 bytes (40-byte IPv6 plus UDP), and a hostname reserves
  48 bytes because DNS may change family. Checked validation requires payload
  plus that overhead to be no greater than `path_mtu`; it never lowers the
  configured payload silently. This applies to all protocols and implements
  IPFIX's PMTU requirement conservatively. IPv4 options, IPv6 extension
  headers, dynamic PMTU discovery, and jumbograms are not emitted/supported.
* `sending_queue.enabled:true`, `retry_on_failure.enabled:true`, persistence,
  batching/partitioning, `wait_for_result`, and nested options are rejected.
  Effective queue capacity is zero. Queue/retry support requires a future ADR.

## Admission, ownership, and results

The wrapper gates `ConsumeLogs` before helper entry. Admission registration and
the closing check are atomic; no `WaitGroup.Add` races the shutdown wait. A
nonblocking acquisition of the sole whole-request slot admits one caller and
zero waiters. A busy caller receives fixed transient `busy` immediately and
retains no pdata. The winner performs a structural hierarchy check before
helper accounting to reject malformed pdata handles. It does not scan unused
metadata or impose aggregate record, byte, node, depth, map, key or scalar
ceilings. The former `limits` configuration block has been removed; Collector
configuration decoding rejects it as an unknown option. With queue/retry disabled,
helper invokes the pusher synchronously.

The admitted caller retains that request slot through helper return and any
failed-subset copy. If internal template refresh or endpoint publication owns
send serialization, the caller waits with its context; maintenance contention
does not return `busy`. A second external caller still fails immediately before
preflight or helper entry. Direct runtime packing has its own single registered
operation slot, so it cannot accumulate additional waiters. Cancellation before
packing returns fixed transient unavailable (or closed when shutdown is
observed), without constructing packets or a result ledger. This wait adds no
retry, pdata queue, goroutine or fairness guarantee.

Normalization and packing stream one log at a time. A fixed view of at most
64 selected field references borrows pdata scalars until the writer copies them
into a datagram bounded by `max_datagram_size`; no request-wide normalized slice
or per-record goroutine exists. Supported requests continue across as many complete
packets as needed, including beyond the former 65,536-record and 64 MiB ceilings.
Mapped values obey their configured descriptor lengths and complete record/Set/
message/path fit. A record that cannot fit an empty message is permanently
rejected while valid siblings continue; records are never truncated or fragmented.

Each UDP datagram has one local whole-write attempt. Its Write deadline is the
earlier of the `ConsumeLogs` context deadline and configured `timeout`. Only
`{n == len(datagram),
err == nil}` commits. Short-nil, zero-nil, short-error, zero-error, and
full-length-error are uncommitted ambiguous failures; no suffix write occurs.
UDP has no delivery acknowledgement, so upstream replay may duplicate a locally
confirmed prefix.

Invalid records use fixed reasons and are permanently dropped while valid
siblings continue. Mixed invalid plus fully successful valid records returns nil;
all-invalid returns a fixed redacted permanent error. If a transient write
failure follows a confirmed prefix, return `consumererror.NewLogs` containing
only the ambiguous current datagram and unsent valid suffix; confirmed and
invalid records are excluded. Permanent-invalid plus transient uses the
transient subset as precedence. This subset describes remaining component work,
not an anti-replay promise: helper retry is disabled and an upstream caller may
replay the original request.

The copied subset retains only ambiguous and valid unsent records and copies
each retained resource/scope/log envelope once. Byte leaves are detached using
public pdata APIs and a reusable iterative worklist, preserving independent
ownership, duplicate attributes and Resource EntityRefs. The result ledger uses
two bits per source record with dynamically grown storage and 64-bit source and
packet counters. Wire sequence fields retain their protocol-defined widths.
There is no aggregate subset revalidation or fixed input/ledger memory budget.

One request slot, one request datagram, one maintenance datagram, and bounded
mapping/template state remain enforced. Ledger storage, required copied retry
data and worklist storage scale with the actual input. After cancellation or a
send failure, the remaining records are validated to return only valid unsent
records; this suffix work scales with request size. The pinned pdata envelope
`CopyTo` implementation recursively copies nested values. Exact envelope
preservation requires that public API, so extreme metadata nesting during a
failed-subset copy remains an upstream stack-safety limitation; the exporter's
byte-detachment pass adds no recursion. Tests cover nesting beyond the retired
64-level cap, not unlimited-depth stack safety. Fixed whole-process heap/RSS
qualification remains deferred and is not a data-validity rule.

Pinned helper accounting treats a returned error as all original items failed,
even when `consumererror.NewLogs` is a smaller subset. Component-local
confirmed/invalid/ambiguous counters are authoritative for protocol truth; this
intentional metric divergence is documented and tested rather than hidden.

## Lifecycle and endpoint epochs

`[F]` Core requires `Start(ctx, host)` and `Shutdown(ctx)` and says shutdown must
be safe without Start, idempotent, and complete before return ([component.go,
lines 14–61](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/component/component.go#L14-L61)).
The wrapper implements those guarantees around the helper:

1. Start performs bounded setup, resolves and dials one connected UDP socket,
   creates a fresh endpoint epoch, and captures candidate `start_origin`.
   For v9/IPFIX it writes every `initial_copies` complete catalog round before
   publishing success. A candidate header uses its captured origin; only a
   successful publication makes it the component Start origin. Any resolve,
   dial, or bootstrap write failure closes/discards the candidate and fails
   Start. UDP write success proves local handoff only, not remote receipt.
2. One lifecycle mutex linearizes closing, admitted calls, maintenance
   registration, candidate handles, and the published handle. A candidate
   operation token is registered before resolve/dial, and the returned socket is
   attached before its first bootstrap write. Packing registers its sole
   cancelable operation and active call under lifecycle before waiting outside
   lifecycle for a capacity-one send permit. After acquiring it, packing rechecks
   closing/cancellation and reads the current endpoint under lifecycle. It keeps
   the permit through writes, full-write commits and state cleanup. Refresh and
   publication use their registered contexts to acquire the same permit;
   publication then takes lifecycle, rechecks closing/generation and swaps
   handle/state. No path waits for send while holding lifecycle, and cleanup
   releases only an owned permit before ending registration.
3. `sync.Once`-guarded Shutdown marks closing and detaches all handles under the
   lifecycle mutex, unlocks before canceling contexts or closing sockets, and
   closes each detached socket once without waiting for the send permit. It
   cancels registered permit waiters; Close or deadline interrupts a stalled
   write. A completed full write still commits if cancellation follows it. The
   wrapper joins admitted calls, Pack waiters and registered workers, then
   invokes helper Shutdown exactly once. A losing
   candidate closes once; repeated/concurrent Shutdown waits for or returns the
   stored result, and Shutdown before Start is safe.
4. Shutdown uses the earlier of caller deadline and `shutdown_drain_timeout`.
   Every blocking operation is context-aware or interruptible; attempt/DNS
   timeouts do not exceed the drain. On the bound, admission is closed and the
   socket is closed before returning a fixed redacted error; no later write can
   occur. Tests join every worker/timer, including stalled-write and in-flight
   lookup cases. This wrapper exists because pinned helper queue shutdown does
   not provide the required ordering or idempotence.

DNS and endpoint replacement are per-instance singleflight maintenance: one
active run and one coalesced pending trigger. Literal IPs bypass DNS;
hostnames resolve at Start and refresh through dial/revalidation/commit. More
than eight matching, deduplicated A/AAAA answers is rejected. Answers are
sorted and deduplicated: while fresh, retain the current address if present;
otherwise choose the lexicographically first compatible address, never answer
order. A lookup failure retains the old address through finite staleness; once
stale, no packet is built and Consume returns fixed transient unavailable.
Candidate resolution, socket creation, and complete v9/IPFIX bootstrap occur
outside send; under lifecycle the generation/closing state is rechecked and the
fully bootstrapped candidate is published atomically. A failed candidate is
closed and the old epoch retained. Record data never selects an endpoint;
trusted operator configuration may target private, loopback, link-local, or
multicast addresses.

Deep sequence, template, timestamp, padding, and refresh rules remain in the
accepted state packet and [ADR 0002](../decisions/0002-focused-wire-encoders.md).
This document only requires that candidate bootstrap and publication preserve
those writer/state commit boundaries.

## Telemetry, diagnostics, and distribution

Keep exporterhelper standard metrics and add bounded component-local counters for
records, messages/bytes, loss/rejection, templates, DNS, and endpoint epochs.
Only fixed enum attributes are allowed: protocol, outcome, message kind, loss
class, and reason. Never label endpoint/IP/MAC, record key/value, PEN, template
ID, body, or raw error. Metadata enumerates at most 16 reasons and at most 96
local series per instance. Routine logs include only component ID, fixed reason,
and counts, at one event/reason/minute with burst one; config/Start/Shutdown
events are not rate-limited but remain redacted. A copied telemetry setting
allowlists those fields, strips raw errors/endpoints, and samples duplicates at
the same declared rate/burst. Pusher errors are constant safe strings; private
stdlib DNS/socket classification never enters returned errors. A 10,000-failure
test covers helper/component/upstream-visible text and cardinality.

`[D]` The external component remains a standalone module and uses a pinned OCB
`v0.160.0` manifest with a local development `replaces` entry. OCB's manifest
allows module entries and replacements ([Core Builder README, lines 136–175](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/cmd/builder/README.md#L136-L175)).
The project build/test matrix uses Go `1.26.8`; the pinned modules' declared Go
`1.26.0` is their upstream minimum, not this project's runtime pin. Generated
binaries are ignored; integration assets live below `distribution/` and
`integration/testdata/`. A deterministic logs pipeline with multiple named
instances proves isolation. Custom Collector smoke, receiver semantic
round-trip, and independent decoder checks are reproduced by the
[verification strategy](implementation-verification.md) and summarized in the
[MVP acceptance record](../mvp-acceptance.md).

## Deferred work and evidence

The initial profile defers raw replay, TCP/SCTP/TLS, dynamic templates,
automatic IE discovery, untrusted-config egress policy, persistent/in-memory
queues, automatic retry, fixed local ports, v5/v9 uptime rollover, and Contrib
donation. Queue/retry requires a separate ADR proving pre-helper bounded
preflight, retained-object/RSS and subset-copy ceilings, idempotent bounded
shutdown, and UDP duplication semantics.

Evidence and acceptance are recorded in the [verification strategy](implementation-verification.md)
and [MVP acceptance record](../mvp-acceptance.md).
