# ADR 0004: Destination-local UDP protocol state

- Status: accepted
- Date: 2026-09-02
- Owners: project

## Context

The exporter emits NetFlow v5, NetFlow v9, and IPFIX over UDP from the pinned
receiver-compatible 41-field profile.  Protocol sequence/template state,
endpoint replacement, logical clock handling, packet limits, and shutdown must
not be shared across destinations or read by pure wire writers.  UDP confirms a
local kernel handoff only; a short or errored write is ambiguous and can be
replayed upstream.  The accepted component/state packet requires hostile-input
preflight, no initial queue/retry/persistence, candidate endpoint bootstrap,
and a lock order that lets shutdown interrupt a stalled write.

The [protocol-state design](../design-docs/protocol-state-transport.md) is the
implementation contract.  Collector factory/configuration choices remain in the
component design; this ADR only decides destination, protocol, and UDP state.

## Decision

Implement one destination-local state machine per configured exporter instance:
one protocol, one connected UDP socket use, one endpoint epoch, one sequence and
template catalog, one logical clock, and one DNS maintenance operation.  The
root Collector lifecycle wrapper remains the sole owner of request admission,
the lifecycle mutex, and published/candidate socket-handle closure.  Multiple
destinations are separate named Collector instances in pipeline fan-out; there
is no initial destination list or shared mutable state.

Use three project-owned pure writers (`wire/netflow5`, `wire/netflow9`, and
`wire/ipfix`) behind a checked packet-writing contract.  A writer receives
normalized values and a statically compiled template shape, writes only into a
caller-owned bounded buffer, and never reads clocks, DNS, sockets, Collector
objects, or globals.  Destination state decides when to invoke the writer and
when a datagram's state commits.

The [receiver conversion matrix](../compatibility/protocol-mapping.md) remains
the semantic boundary: only configured/static mappings are extracted, unknown
attributes stay untouched unless an explicitly named key is requested, and no
conversion may clamp, truncate, or silently infer.  An unsupported required
conversion rejects that record for this destination.  IPFIX enterprise fields
require PEN/element ID/type/length; v9 private numeric fields are explicit
opt-in without a PEN and have limited interoperability; v5 extensions are
rejected.

Inject narrow internal seams per destination: a wall/monotonic clock source, a
cancellable bounded A/AAAA resolver, and a connected UDP dialer/connection that
supports local/remote address inspection, write deadlines, whole-datagram Write,
and Close.  Production implementations use the Go standard library; fakes
drive clock steps, DNS generations, endpoint replacement, every write result,
and shutdown races.  These seams do not become a public transport abstraction.

### Epoch and publication

An endpoint epoch stores destination candidate data: socket/address identity,
DNS generation, sequence, template/refresh progress, and reserved logical send
instant.  The root wrapper owns published/candidate handles and closes them
exactly once.  Template IDs are sequential and never reused within an epoch.
Start and endpoint replacement build a candidate outside the send lock.  V9
only captures `start_origin` immediately before its first bootstrap template
write; IPFIX has no `start_origin` and uses only reserved Export Time.  Both
protocols send all `initial_copies` complete catalog rounds before publication.
Publication atomically swaps the fully bootstrapped handle and destination
state only after rechecking DNS generation and closing flag; a failed candidate
is closed by the root wrapper and its v9 origin/progress is discarded, leaving
the old epoch available through the finite staleness window.  UDP local-write
success is not remote-delivery proof.

### Protocol state

* **NetFlow v5:** fixed 24-byte header, 48-byte record, and 1..30 records per
  packet.  Sequence starts at zero per epoch and advances modulo 2^32 by
  successfully written flow-record count.  Engine type/id are configured (v5
  has no Source ID).  UNIX seconds/nanoseconds use the reserved logical send
  instant (seconds fit uint32; nanoseconds are 0..999999999).  The configured
  `uptime_origin` and source flow timestamps are UTC nanoseconds; derived
  `sysUpTime`, `First`, and `Last` are exact-millisecond elapsed uptimes from
  that origin and must be ordered, nonnegative, <= MaxUint32, and non-rolling.
  Packet construction
  additionally requires `0 <= First <= Last <= header sysUpTime <= MaxUint32`;
  this upper bound is project semantic inference from Cisco's switch-time
  definitions, not a new protocol MUST.  Sampling mode is explicit raw two-bit
  configuration and every record in a packet shares one checked 14-bit rate.
  Cisco pad1 (offset 36) and pad2 (46..47) are zero.
* **NetFlow v9:** sequence starts at zero and advances modulo 2^32 by each
  successfully written Export Packet, including template-only packets.  Source
  ID is configured.  Header UNIX seconds use the reserved logical instant and
  must fit uint32.  Configured `uptime_origin` and source flow timestamps are
  UTC nanoseconds; header `sysUpTime` and selected FIRST/LAST are exact-
  millisecond elapsed uptimes from that origin.  Header `sysUpTime` uses
  configured `uptime_origin`, or a v9 candidate `start_origin` captured before
  the first template Write and
  published at successful Start; no rollover is allowed.  FIRST_SWITCHED (22)
  and LAST_SWITCHED (21) are omitted from the default shape.  If selected,
  stable configured origin, exact-ms conversion, ordering, and
  `0 <= FIRST_SWITCHED <= LAST_SWITCHED <= header sysUpTime <= MaxUint32` are
  required; without origin that template shape is unsupported.  Initial output
  contains no Options; if future scope emits an Options-bearing Export Packet,
  each successful packet counts exactly as one Export Packet for
  sequence/refresh counters, with template/options refresh semantics retained
  as protocol facts.
* **IPFIX:** sequence starts at zero and advances modulo 2^32 by successfully
  written Data Record count; Template and Options Template records add zero;
  initial catalogs emit no Options Templates or Options Data.  Observation
  Domain ID is configured per destination.  Export Time is the
  reserved logical instant rounded down to Unix seconds, must fit uint32, and
  is range-checked.
  Timestamp Information Elements use RFC 7011 precision/era rules; enterprise
  fields require explicit PEN, ID, type, and length.

Only `{len(datagram), nil}` commits sequence, template-copy, and refresh
progress.  Short, zero, or full-length error writes are ambiguous: no protocol
counter commits, no suffix write occurs, and the current datagram remains part
of the bounded transient failed subset.  The logical send-instant reservation
survives an ambiguous write.  Sequence header values describe records/packets
sent before the current datagram; IPFIX follows verified RFC 7011 erratum 4396.

Restart creates a fresh in-memory epoch (sequence/template/refresh progress and
logical Export Time reset, new socket, no persistence); in-flight work may be
lost and the local source port may be reused. A configured v5/v9 uptime origin
remains fixed, but elapsed millisecond overflow enters a fixed
`uptime_exhausted`/unavailable state with no rollover or zero sentinel. Each v9
candidate captures a fresh `start_origin` and discards it on candidate failure;
templates complete bootstrap before data in every epoch.

### Templates, refresh, and packing

V9/IPFIX catalogs are static and validation-time bounded (at most 16 shapes, 64
fields/shape, 4096 encoded template bytes/shape, 32 custom mappings, and 32
PENs).  Initial v9/IPFIX catalogs contain ordinary Data Templates only: the
exporter emits no Options Templates or Options Data.  Options scope and
alternative IEs are deferred; any future Options-bearing packet follows the
protocol's standard sequence and refresh rules.  Initial bootstrap sends
`initial_copies` complete
catalog rounds.  This is project policy (default 2, accepted range 2..8): two
is the smallest numeric interpretation of RFC 7011's nonnumeric SHOULD, not an
RFC-required count.  A failed datagram discards the candidate and its exact
progress.  V9
refresh is due by monotonic time or successful Export-Packet count (including
template/data; initial output has no Options.  If future scope emits an
Options-bearing Export Packet, each successful packet counts exactly as one
Export Packet; template/options refresh semantics remain protocol facts); a
round resets only after the whole catalog completes.
IPFIX refreshes
periodically for UDP and may use an optional successful data-message count; it
sends no UDP withdrawals.  Timer and Consume triggers use one singleflight run
and one coalesced pending bit.  V9 private fields are explicit opt-in with no
PEN; v5 custom fields are rejected.

`max_datagram_size` is UDP payload bytes (default 464, absolute range
128..65507) and is additionally constrained by the explicit PMTU contract in
[ADR 0006](0006-explicit-pmtu-budget.md). V5 keeps its 30-record cap; no protocol
application-fragments or splits a Data Record.  A record that cannot fit an
empty message is permanently rejected; an over-size compiled template is a
config/Start error.  V9/IPFIX Set/FlowSet padding is zero-filled and included
in lengths, emitted only when 1..3 padding bytes are strictly shorter than the
smallest record in the set.  All arithmetic and narrowing is checked before
allocation or encoding.

Destination state/transport bounds are payload 128..65507 (default 464) after
the ADR 0006 PMTU calculation, optional configured `path_mtu` 512..65535,
records/message 1..1024 (v5 <=30), initial copies 2..8, template interval
30 seconds..24 hours (default remains 10 minutes), v9 packet and optional IPFIX data-message counts 1..1000,
write timeout 100 ms..30 seconds (not above drain), drain 1..30 seconds, DNS
refresh 1 second..24 hours, stale retention refresh..7 days, and DNS timeout
100 ms..30 seconds (not above drain). Collector factory/config wiring is out
of scope here.

### DNS and lifecycle

Literal IP endpoints bypass DNS; hostnames resolve at Start and through one
singleflight maintenance operation (one active run and one coalesced pending
bit).  Up to eight deduplicated, sorted A/AAAA
answers are accepted.  The current address is retained while present;
otherwise the lexicographically first compatible address is selected.  Lookup
failure retains the old endpoint for finite staleness.  Candidate dial,
bootstrap, and generation revalidation happen outside the send lock; publication
swaps the complete candidate atomically under the wrapper lock contract and the
root wrapper closes the old socket after commit.
Once stale, no datagram is built or state advanced.

The root Collector lifecycle wrapper's mutex is the sole linearization authority
for closing, admitted calls, maintenance tokens, and candidate/published
handles.  Published destination sends take send then the wrapper lifecycle lock
briefly to register a Write, release lifecycle, and Write while retaining send.
Publication takes send then lifecycle and releases in reverse order.  No path
takes send while holding lifecycle.  The wrapper's Shutdown takes lifecycle
only to mark closing and detach handles, releases it before cancel/close, then
joins admitted calls and maintenance operations and calls helper Shutdown once.
The earlier of caller deadline and `shutdown_drain_timeout` bounds all blocking
operations; socket close/deadline interrupts stalled writes.  Shutdown is
idempotent and safe before Start; no write can begin or reach the network after
it returns.

### Input and delivery policy

The root Collector lifecycle wrapper admits one whole request and zero internal
waiters.  It performs iterative preflight before helper entry/normalization, checks the
accepted record/container/logical-byte/depth/map/key/scalar/mapped-value
ceilings, and traverses unknown/unselected values without copying.  Packing
streams one record at a time through a fixed selected-field view and bounded
datagram buffer.  Invalid records are fixed-reason counted and dropped while
valid siblings continue.  A transient failure after a confirmed prefix returns
only the ambiguous datagram and unsent valid suffix in a bounded
`consumererror.NewLogs` subset; this is not an anti-replay guarantee.

Queueing, persistence, batching/partitioning, and automatic retry are rejected
in the initial profile.  Their absence avoids helper traversal before the
preflight boundary and leaves UDP duplicate/loss semantics explicit.

The design document's [atomic failure matrix](../design-docs/protocol-state-transport.md#atomic-failure-matrix)
is normative for full-write commits, ambiguous writes, invalid subsets,
candidate/template failures, DNS staleness, and shutdown races.

## Consequences

Destination failures, DNS churn, template progress, and sequence numbers are
isolated.  Pure writers are deterministic and independently testable, while
clock, resolver, dialer, and Write outcomes are deterministic under fakes.
Candidates cannot publish partial templates, and shutdown can interrupt a
registered write without a lock cycle.  The project accepts local-handoff-only
UDP delivery semantics, ambiguous-write replay risk, no persistent state, and
the cost of bounded synchronous backpressure.  Independent TShark/golden wire
proof, race/fuzz/load/leak tests, and Collector smoke tests are documented in
the [verification strategy](../design-docs/implementation-verification.md).

## Alternatives considered

* **Shared destination or global protocol state — rejected.** It couples
  sequence/template/DNS failures and makes one endpoint's shutdown or refresh
  affect another.  Pipeline fan-out already provides separate instances.
* **Writers owning clocks, sockets, or DNS — rejected.** It makes wire bytes
  nondeterministic and prevents pure unit/golden tests; state belongs to the
  destination boundary.
* **Enable exporterhelper queues/retry now — deferred/rejected initially.** The
  accepted preflight must run before helper traversal, and UDP writes have no
  acknowledgement; a bounded queue/retry ADR must prove retained-object/RSS,
  subset-copy, shutdown, and duplicate semantics before enabling it.
* **Persist sequence/template state — deferred.** Restart starts a fresh epoch,
  sequence zero, new socket, and complete template bootstrap. Persistence would
  require an additional crash-consistency and endpoint-identity design.
* **Unconnected UDP or shared resolver — rejected.** Connected sockets expose
  endpoint identity and permit a bounded whole-datagram seam; per-instance DNS
  generations and singleflight prevent cross-destination coupling.
* **Adopt a library's stateful exporter — rejected.** The accepted
  [focused-encoder ADR](0002-focused-wire-encoders.md) keeps protocol writers
  project-owned and destination state explicit.

## Non-goals and reconsideration

This ADR does not define Collector package/configuration details, queue/retry
implementation, TCP/SCTP/TLS, raw passthrough, dynamic templates, v5/v9 uptime
rollover, or untrusted-config egress policy.  A future queue/retry/persistence
proposal must supersede this ADR with bounded preflight and retained-memory
proof, explicit UDP failure semantics, idempotent shutdown, and deterministic
tests.  A transport/library change likewise requires an ADR backed by the
protocol matrix, independent wire decoding, and state/lifecycle evidence.

## Evidence

* [Component design](../design-docs/collector-component.md)
* [Protocol-state design](../design-docs/protocol-state-transport.md)
* [Protocol state and transport design](../design-docs/protocol-state-transport.md)
* [Receiver conversion matrix](../compatibility/protocol-mapping.md)
* [Source ledger with exact pins and errata](../research/source-ledger.md)
* [RFC 3954 §5.1 and §8](https://www.rfc-editor.org/rfc/rfc3954.html#section-5.1),
  [RFC 7011 §3.1/§6.1](https://www.rfc-editor.org/rfc/rfc7011.html#section-3.1),
  and [RFC 7012 §3.1](https://www.rfc-editor.org/rfc/rfc7012.html#section-3.1);
  verified interpretations include [RFC 3954 erratum 2096](https://www.rfc-editor.org/errata/eid2096),
  [RFC 7011 erratum 4396](https://www.rfc-editor.org/errata/eid4396), and
  [RFC 7012 erratum 3881](https://www.rfc-editor.org/errata/eid3881)
* [Cisco v5 tables B-3/B-4](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006108)
* [IANA IPFIX registry/CSV](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv)
* [Receiver and sampling compatibility](../compatibility/protocol-mapping.md)
* Pinned Collector Core `v0.160.0` commit
  [`cd3455cf3a7f672208140b1ebb1581c542b2b0ed`](https://github.com/open-telemetry/opentelemetry-collector/tree/cd3455cf3a7f672208140b1ebb1581c542b2b0ed)
  and its [`component.Component`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/component/component.go)
  and [`exporterhelper.NewLogs`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/logs.go)
  contracts.
