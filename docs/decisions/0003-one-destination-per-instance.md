# ADR 0003: One destination per exporter instance

- Status: accepted
- Date: 2026-09-02
- Owners: project

## Context

The exporter consumes hostile Collector logs and emits one of three wire
protocols over UDP. Destination-local sequence, template, clock, DNS, socket,
admission, and lifecycle state must not leak between destinations. Collector
fan-out can invoke multiple named exporters, but it does not provide an atomic
cross-destination acceptance ledger. The initial profile also needs bounded
preflight before helper traversal and a deterministic result for ambiguous UDP
writes.

The pinned Core API is stable modules `v1.66.0` and beta modules `v0.160.0` at
commit [`cd3455cf3a7f672208140b1ebb1581c542b2b0ed`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/versions.yaml),
with Go `1.26.0` ([go.mod](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/go.mod#L1-L18)).
Core's public `exporter.NewFactory`/`WithLogs` API ([source](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporter.go#L96-L103))
and `exporterhelper.NewLogs` pusher/options ([source](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/logs.go#L16-L32))
are the only Collector helper surfaces selected. The [component design](../design-docs/collector-component.md)
and [protocol-state design](../design-docs/protocol-state-transport.md) are
the authority for bounds and lifecycle ordering.

## Decision

1. A configured exporter instance represents exactly one UDP endpoint and one
   wire protocol. Multiple destinations are multiple named instances in one
   logs pipeline. There is no initial `destinations: []` fan-out and no mutable
   state shared between instances. Each instance owns its endpoint epoch,
   sequence/template/refresh state, resolver selection, socket, metrics,
   admission gate, and shutdown state.
2. Use a small project-owned `exporter.Logs` wrapper around synchronous
   `exporterhelper.NewLogs`. The wrapper performs an atomic closing/admission
   check, nonblockingly acquires one whole-request slot, and has zero internal
   waiters. A busy caller receives fixed transient `busy`; its pdata is not
   retained. The winner runs iterative bounded preflight before helper entry,
   normalization, or proportional allocation. The pusher reads pdata
   synchronously and reports `consumer.Capabilities{MutatesData:false}`.
3. Queueing, persistence, batching/partitioning, `wait_for_result`, and automatic
   retry are rejected by validation in the initial profile. Effective queue
   capacity is zero. The wrapper passes destination Start to helper construction
   but no destination Shutdown callback; it owns lifecycle ordering and calls
   helper Shutdown exactly once after destination work is canceled and joined.
4. Start resolves/dials one connected UDP socket and bootstraps the complete
   configured v9/IPFIX catalog on a candidate epoch before publishing it. A
   single lifecycle mutex linearizes closing, admitted calls, maintenance,
   candidate/published handles, and write registration. Sends take send then
   lifecycle briefly; publication takes send then lifecycle; no reverse order is
   permitted. `sync.Once`-guarded Shutdown marks closing, detaches/closes handles
   without waiting behind send, interrupts writes, joins calls/workers, and is
   safe before Start and on repeated/concurrent calls.
5. The wrapper preserves the accepted result matrix: only a full `{len,nil}`
   UDP write commits; short/zero/full-error writes are ambiguous and return a
   bounded `consumererror.NewLogs` current-plus-suffix subset. Invalid records
   are fixed-reason permanent losses while valid siblings continue. Helper's
   all-original-item error accounting is documented as intentionally divergent
   from component-local confirmed/invalid/ambiguous counters.

Wire writer semantics and deep sequence/template/timestamp state are not
duplicated here; [ADR 0002](0002-focused-wire-encoders.md) owns that boundary.

## Alternatives considered

* **One exporter with a destination list/fan-out:** rejected initially. It
  obscures per-destination state ownership, gives no atomic acceptance across
  UDP writes, and makes endpoint-specific telemetry/cardinality and shutdown
  ordering harder to bound. Named Collector instances provide the same
  fan-out with explicit isolation.
* **One component instance per protocol, with destinations supplied by data:**
  rejected. Endpoint and protocol are trusted operator configuration; records
  must never select egress or wire semantics. It would also create unbounded
  dynamic template/state pressure.
* **Enable exporterhelper queue/retry/batching:** rejected for the initial
  profile. Helper queue shutdown and retry semantics do not establish the
  required pre-helper hostile-input bound, retained-object/subset-copy ceiling,
  idempotent shutdown ordering, or UDP ambiguity contract. A future queue ADR
  must prove those properties instead of silently falling back.
* **Call the pusher directly with no helper:** rejected. It would discard
  Collector-standard spans/metrics and helper lifecycle conventions. The
  wrapper keeps helper observability while adding only the admission and
  lifecycle guarantees the pinned helper does not provide.
* **Let helper own Start and Shutdown:** rejected. The required candidate epoch
  publication, lock order, socket interruption, and shutdown-before-wait
  ordering need one component-owned authority; helper receives Start but not the
  destination Shutdown callback.
* **Share a transport/state singleton:** rejected. Shared mutable sequence,
  template, DNS, or socket state would violate destination isolation and make
  restart/endpoint epochs non-local. Narrow constructor-injected seams and
  standard-library production implementations preserve testability without a
  general transport abstraction.

## Consequences

The component has a small, explicit backpressure surface: one admitted request
per instance and no waiting requests. Pipeline callers may see `busy`, and
multiple named instances can succeed or fail independently. There is no local
durable buffering or automatic retry; an upstream replay can duplicate a packet
because UDP has no acknowledgement. The failed subset is bounded and describes
remaining component work, not an anti-replay guarantee.

The wrapper and destination state own more lifecycle code than a direct helper
call, but socket close/deadline can interrupt a stalled write and all workers
and timers can be joined at Shutdown. Pure protocol writers remain independent
of Collector, DNS, clocks, sockets, and globals. Component telemetry can report
confirmed protocol outcomes while exposing the helper's all-items-failed metric
divergence.

The model fits a standalone external module and a pinned custom OCB distribution;
the OCB manifest supports module entries and local replacements ([Core Builder
README](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/cmd/builder/README.md#L136-L175)).
Generated binaries and integration assets are not part of this ADR.

## Implementation constraints and non-goals

* Preserve every numeric, duration, input-traversal, mapping, datagram, and
  telemetry-cardinality bound in the accepted component/state packet. Checked
  arithmetic precedes conversions and allocations; zero never means unlimited.
* Preflight must be iterative and complete before helper entry. Normalization is
  one-record-at-a-time with at most 64 selected references and a bounded output
  datagram; no request-wide normalized slice, per-record goroutine, or queue.
* Keep errors/logs redacted: fixed reason/protocol/outcome/message-kind/loss
  enums only; never endpoints, IP/MAC, keys/values, PENs, template IDs, bodies,
  or raw errors. Bound reasons at 16 and local series at 96 per instance.
* This ADR does not define package internals beyond writer/state separation,
  wire field mappings, config defaults beyond the published design, transport
  protocols other than connected UDP, raw passthrough, or production code.

## Reconsideration criteria

A superseding ADR is required to add destinations-in-one-instance, queueing,
retry, batching, or a shared state/transport. It must include an immutable
released API/source pin, an explicit acceptance ledger for each destination,
pre-helper traversal and retained-object/RSS/subset-copy ceilings, bounded
shutdown and write interruption, duplicate/ambiguity semantics, fixed telemetry
cardinality, concurrency/race/fuzz evidence, and independent Collector/protocol
interoperability. A failed criterion keeps this decision in force.

## Evidence

* [Collector component design](../design-docs/collector-component.md)
* [Component design](../design-docs/collector-component.md)
* [Protocol-state design](../design-docs/protocol-state-transport.md)
* [External-component ADR 0001](0001-external-component-first.md)
