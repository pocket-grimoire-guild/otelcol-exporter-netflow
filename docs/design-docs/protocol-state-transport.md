# Protocol state, packet packing, and UDP transport

**Current admission and ownership:** The aggregate admission, metadata sizer,
uint32 source ordinal, fixed 16 KiB ledger, bounded-suffix, and fixed
result-storage descriptions below are superseded by the implemented
[admission and ownership contract](collector-component.md#admission-ownership-and-results).
Current source ordinals and request counters are uint64; a dynamically grown
two-bit ledger accounts for arbitrary supported request sizes. Packet buffers,
protocol sequence widths, templates, transport and lifecycle invariants remain
as specified. Suffix validation and exact metadata copies scale with the input;
fixed heap/RSS qualification is deferred. Historical numeric admission policies
in this document must not be used as current data-validity rules.

Status: accepted protocol-state design (2026-09-02). This document turns the
component and transport decisions into an implementation boundary. It does not
select a Collector factory or
configuration API; those are covered by the component design and the pinned
[source ledger](../research/source-ledger.md).

## Boundary and injected seams

One configured exporter instance owns one protocol, one connected UDP endpoint,
and one destination.  Multiple destinations are separate named Collector
instances; Collector fan-out has no atomic acceptance ledger.  Ownership is:

```text
logs -> bounded preflight -> normalize -> compiled mapping
     -> destination state/packing -> pure writer -> connected UDP socket
```

The v5, v9, and IPFIX writers receive normalized values and an explicit static
template shape.  They do not read clocks, DNS, sockets, Collector objects, or
globals.  Destination state owns sequence/template/refresh progress, logical
clock values, packing, candidate epoch data, resolver operations, and socket use
under the wrapper's lock/deadline/close contract.  The root Collector
lifecycle wrapper is the sole owner of request admission, the lifecycle mutex,
and published/candidate socket-handle closure; destination state never closes
or detaches a handle itself.

The [accepted conversion matrix](../compatibility/protocol-mapping.md) is the
semantic boundary: only configured/static mappings are extracted. Unknown
attributes remain untouched in input; an unknown key is extracted only when an
explicitly named mapping requests it and then remains subject to every hard
limit. There are no dynamic templates, shape changes, or cardinality growth.
An unsupported required conversion rejects that record for that destination;
the exporter never clamps, truncates, or silently infers a value. IPFIX
enterprise fields name PEN, element ID, type, and length; v9 private numeric
fields are explicit opt-in without a PEN and have limited interoperability; v5
extensions are rejected.

Each destination injects three narrow internal seams:

| Seam | Required behavior | Deterministic fake coverage |
| --- | --- | --- |
| Clock/timer | Separate UTC wall reads from a monotonic refresh source; reserve one logical send instant before every write. | backward/forward wall steps, monotonic ticks, refresh coalescing, deterministic headers |
| Resolver | Cancellable bounded lookup of A/AAAA; deduplicate and sort answers; expose a generation and staleness result. | NXDOMAIN/error, >8 answers, answer reorder, retained/stale address, generation races |
| Connected UDP dialer/connection | Dial candidate, inspect local/remote addresses, set write deadline, write one complete datagram, and expose Close to the root wrapper. | every short/full/zero/error write, timeout, endpoint/port replacement, close interrupt |

These are constructor-injected implementation seams, not a public transport
abstraction.  Production implementations use the Go standard library.  A
writer returns an error before writing when a checked width, template, set,
message, record-count, or caller buffer budget cannot represent the request.

The clock is constructed only through `transport.NewClock`, which
captures one standard-library `time.Now` origin and returns UTC Unix
nanoseconds separately from the elapsed monotonic offset.  Wall seconds and
nanoseconds are range-checked before conversion; a negative, future, or
otherwise unsupported sample returns an invalid sentinel that State rejects.
Elapsed samples that move backwards fail closed instead of resetting to zero.
A deterministic test clock may step wall and elapsed values independently and
is concurrency-safe.

The connected UDP seam accepts a parsed numeric `netip.AddrPort` through the
fixed `NewDialer(network, local)` constructor and uses the standard-library
context-aware UDP dialer.  Hostname resolution and candidate selection remain
in the resolver/lifecycle layer.  The injected connection exposes its
captured local and remote identities, one whole-datagram `Write`,
write-deadline setup, and `Close`.  A synchronous `NewWriter` validates a
100 ms to 30 s timeout, selects the earlier operation deadline or timeout
deadline, and uses a cancellation callback to interrupt an outstanding write
by setting a deadline.  It joins that callback before clearing the deadline,
so a canceled call cannot change the deadline of a later call.  It never
closes the socket, retries, suffix-writes, queues, or logs payloads or endpoint
values.  Callers serialize writes on one connection, and the root lifecycle
wrapper owns the connection's single close operation.

Transport tests use bounded scripted traces for stalled-write cancellation and
close interruption.  IPv4 loopback proves numeric dialing, local/remote
identity, one payload handoff, idempotent close, and rejection after close;
it does not claim that a real loopback UDP write can be reliably stalled.

## Destination state and endpoint epochs

An epoch is the unit of endpoint identity and protocol state.  Destination state
stores candidate epoch data: connected-socket identity/use, local/remote
addresses, DNS generation, protocol sequence, static template catalog and
progress, refresh counters, reserved logical clock, and (for v9 startup)
candidate `start_origin`.  The root lifecycle wrapper owns the corresponding
published/candidate handles and closes them exactly once.  Template IDs are
sequential, fit the configured catalog, and are never reused within an epoch.
A new epoch is created at initial Start, endpoint address/port change, or local
socket replacement; a same-address DNS refresh keeps the current epoch.

Start resolves and dials a candidate outside the send lock.  For v9 only it
captures `start_origin` immediately before the first bootstrap template write;
IPFIX has no `start_origin` and uses only its reserved Export Time.  The
candidate writes every `initial_copies` complete catalog round and is published
only after all writes succeed; a v9 origin becomes the component Start origin at
that publication point.  Any resolve, dial, revalidation, or bootstrap-write
failure closes the candidate through the root wrapper and discards any v9
origin, progress, and socket use.  Initial Start fails when no published epoch
exists; replacement failure leaves the old epoch available until its finite DNS
staleness deadline.  UDP write success proves local handoff only, never remote
receipt.

## Protocol headers, sequence, and time

The wire definitions are [RFC 3954 §5.1](https://www.rfc-editor.org/rfc/rfc3954.html#section-5.1)
and [§8](https://www.rfc-editor.org/rfc/rfc3954.html#section-8), Cisco's
[v5 header/record tables B-3/B-4](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006108),
and [RFC 7011 §3.1](https://www.rfc-editor.org/rfc/rfc7011.html#section-3.1)
and [§6.1](https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1), plus the
IPFIX information model [RFC 7012 §3.1](https://www.rfc-editor.org/rfc/rfc7012.html#section-3.1).  The
accepted field-level choices remain in the
[conversion matrix](../compatibility/protocol-mapping.md).

| Protocol | Header and state contract |
| --- | --- |
| NetFlow v5 | Fixed 24-byte header and 48-byte record; count is 1..30. Sequence starts at zero per epoch and advances modulo 2^32 by successfully written flow-record count. Engine type/id are configured; there is no Source ID. Header UNIX seconds must fit uint32 and nanoseconds 0..999999999, both from the reserved logical send instant. Configured `uptime_origin` and source flow timestamps are UTC ns; `sysUpTime`, `First`, and `Last` are integer elapsed milliseconds from that origin, only when exactly millisecond-aligned, ordered, nonnegative, <= MaxUint32, and non-rolling. The project additionally requires `0 <= First <= Last <= header sysUpTime <= MaxUint32` as semantic inference from the switch-time definitions, not a new protocol MUST. Every record's sampling rate and the configured raw two-bit mode must agree across a packet. |
| NetFlow v9 | Header Version/Count/sysUpTime/UNIX Secs/Sequence/Source ID follows RFC 3954. Sequence starts at zero and advances modulo 2^32 per successfully written Export Packet, including template-only packets. Source ID is configured. Header UNIX seconds must fit uint32 and use the reserved logical send instant. Configured `uptime_origin` and source flow timestamps are UTC ns; header `sysUpTime` and selected `FIRST_SWITCHED` (22)/`LAST_SWITCHED` (21) are exact-ms elapsed uptimes from that origin. Header sysUpTime uses configured `uptime_origin`, or the v9 candidate `start_origin` captured before its first template write and published at successful Start; it is checked on every message. FIRST/LAST are omitted by the default shape. When selected, exact-ms conversion, ordering, and `0 <= FIRST_SWITCHED <= LAST_SWITCHED <= header sysUpTime <= MaxUint32` are required; without configured origin the shape is unsupported. No uptime rollover occurs. Initial output contains no Options; if future scope emits an Options-bearing Export Packet, each successful packet counts exactly as one Export Packet for sequence/refresh counters, with template/options refresh semantics retained as protocol facts. |
| IPFIX | Header Version/Length/Export Time/Sequence/Observation Domain ID follows RFC 7011. Sequence starts at zero per stream and advances modulo 2^32 by successfully written Data Record count; Template and Options Template records add zero; initial catalogs emit no Options Templates or Options Data. Observation Domain ID is configured per destination. Export Time is the reserved logical send instant rounded down to Unix seconds, must fit uint32, and is range-checked; timestamp IEs use the accepted RFC 7011 NTP precision/era gates. |

Only a full local write (`n == len(datagram)` and `err == nil`) commits sequence,
template-copy, and refresh progress. Short-nil, zero-nil, short-error,
zero-error, and full-length-error writes are ambiguous and do not commit those
counters; the current datagram is never suffix-written. The logical send
instant reservation survives an ambiguous write so a backward wall-clock step
cannot make a later header older than a potentially received packet. Header
sequence values describe records/packets sent before the current datagram;
IPFIX follows the verified [RFC 7011 erratum 4396](https://www.rfc-editor.org/errata/eid4396)
interpretation.

### Restart and uptime exhaustion

Restart creates a fresh in-memory epoch: sequence, template-copy progress,
refresh counters, and logical Export Time start over, and a new socket is
opened (the operating system may reuse the local source port). No sequence,
template, or request state is persisted; in-flight work may be lost. A
configured v5/v9 `uptime_origin` remains configuration, but if elapsed uptime
cannot fit the protocol's unsigned millisecond field, the destination enters a
fixed `uptime_exhausted`/unavailable state and does not roll over or emit a
zero sentinel. A v9 candidate's `start_origin` is fresh for each Start and is
discarded with a failed candidate. Templates must complete bootstrap before
data in every new epoch.

## Template catalog, copies, refresh, and padding

V5 has no templates.  V9 and IPFIX compile a static catalog at validation time;
record-controlled shapes, eviction, withdrawal, and ID reuse are prohibited.
The accepted hard ceilings are 16 shapes, 64 fields per shape, 4096 encoded
template bytes per shape, 32 custom mappings, and 32 PENs per instance.  IPFIX
enterprise fields require explicit PEN, element ID, data type, and length; v9
private numeric fields are explicit opt-in and have no PEN on the wire.

Initial v9/IPFIX catalogs contain ordinary Data Templates only: the exporter
emits no Options Templates or Options Data.  Options scope and alternative IEs
are deferred; any future Options-bearing packet follows the protocol's standard
sequence and refresh rules.

Initial bootstrap and endpoint replacement send `initial_copies` complete
catalog rounds.  This is project policy (default 2, accepted range 2..8): two
is the smallest numeric interpretation of RFC 7011's nonnumeric SHOULD, not an
RFC-required count.  A catalog may span bounded template datagrams.  A failed
datagram discards the unpublished candidate and its exact copy/datagram
progress; it never publishes data on a partially bootstrapped epoch.  An
ambiguous template write may duplicate a template at the collector, but the
discarded candidate carries no project data.

V9 refresh is due on the monotonic interval or the configured count of
successfully written Export Packets (including template/data packets; initial
output has no Options.  If future scope emits an Options-bearing Export Packet,
each successful packet counts exactly as one Export Packet; template/options
refresh semantics remain protocol facts).
The default count is a project policy, not an RFC requirement.  A refresh round
resets its counter only after the complete catalog finishes; failure retains
completed-datagram progress, keeps the round due, and blocks dependent data
until completion.  IPFIX refreshes periodically for UDP and may additionally
refresh after a configured number of successful data-bearing messages; it sends
no UDP withdrawals.  Timer and Consume triggers share one singleflight run and
one coalesced pending bit.

V9/IPFIX Set/FlowSet padding is zero-filled and included in set/message lengths.
Emit one to three padding bytes only when that padding is strictly shorter than
the minimum encoded record permitted by the static Template/shape, not the
smallest record observed in the packet. This follows
[RFC 7011 §3.3.1](https://www.rfc-editor.org/rfc/rfc7011.html#section-3.3.1)
and prevents padding from decoding as an additional short record. In particular,
a variable-only shape with a one-byte minimum cannot emit Set padding.
Otherwise omit padding to avoid record ambiguity. V5 `pad1` (record offset 36,
one byte) and `pad2` (offsets 46..47, two bytes) are always zero.

State and transport configuration is bounded: payload is 128..65507 bytes
(default 464) subject to the explicit PMTU budget below; optional configured
`path_mtu` is 512..65535; records/message are 1..1024 (v5 remains <=30); initial copies
are 2..8; template refresh interval is 30 seconds..24 hours; v9 packet and
optional IPFIX data-message refresh counts are 1..1000; write timeout is
100 ms..30 seconds and no greater than the drain timeout; drain is 1..30
seconds; DNS refresh is 1 second..24 hours, stale retention is refresh..7 days,
and DNS timeout is 100 ms..30 seconds and no greater than drain.  These bounds
belong to destination state/transport; Collector factory and config wiring are
defined elsewhere.

## Packet packing and bounded input ownership

`max_datagram_size` is UDP payload bytes (default 464; absolute range
128..65507), and `path_mtu` is an optional trusted operator assertion about the
lowest path MTU for this destination. Without that assertion, validation caps
the payload at 464: a 512-octet IPv6-base-header-plus-UDP packet
(40 + 8 + 464), the project's conservative interpretation of RFC 7011's
unknown-PMTU recommendation. With `path_mtu` present (512..65535), validation
reserves 28 bytes for a literal IPv4 endpoint, 48 for a literal IPv6 endpoint,
and 48 for a hostname because a later DNS generation may change family. Checked
arithmetic requires `max_datagram_size + overhead <= path_mtu`; the exporter
never silently reduces the configured size. The assertion applies to every
resolved candidate. Runtime DNS replacement cannot publish a family whose
prevalidated budget does not fit. The exporter adds no IPv4 options or IPv6
extension headers and does not implement PMTU discovery or jumbograms.

The compiled mapping retains its validated payload cap immutably. Destination
construction rejects a normalized `max_datagram_size` above that cap before
creating catalog or epoch state; a smaller cap still must fit complete static
templates and minimum records. Increasing the cap requires recompiling the
mapping with a valid endpoint/PMTU budget, not only changing state configuration.

The exporter never application-fragments or splits a Data Record.  V5 retains the absolute 30-record cap;
v9/IPFIX enforce record, set, message, and payload limits.  A record that cannot
fit an otherwise empty message is permanently rejected; a template that cannot
fit is a config/Start error.

Before helper entry, the wrapper performs a structural hierarchy check and
does not scan unused metadata or impose an aggregate record, byte, node, depth,
map, key, or scalar ceiling. Unknown and unselected values are ignored by
normalization and are never copied. With queueing disabled, helper traversal is
synchronous and no request-wide normalized slice is built.

`NormalizeEachIndexed` exposes source traversal synchronously, assigning
zero-based `uint64` ordinals in resource/scope/log order. Invalid records
consume ordinals too; empty containers do not. Each callback receives either a
normalized record or a zero record and fixed normalization error. Returning nil
continues past record-local failures; returning an error stops immediately and
propagates it unchanged, and callback panics propagate. Admission failures
invoke no callbacks. Fully traversed all-invalid input returns nil from this
adapter: the packer counts/classifies the events and applies the aggregate
failure policy. The existing `NormalizeEach` retains its first-error behavior
through the shared traversal. Neither adapter retains request data after
returning.

After preflight, packing streams one record at a time through a fixed view of at
most 64 selected field references and one bounded datagram buffer.  It does not
retain a request-wide normalized slice.  Reusing a source value in multiple
mappings charges each encoded append.  Checked add/multiply precedes every
allocation, length sum, template-ID operation, records-times-width operation,
repeated-mapping charge, and narrowing.

The pure v5/v9/IPFIX writers provide reusable data-packet appenders alongside
the existing whole-request writer. Setup may allocate; Begin, Append, and
Finish use only fixed appender state and the caller's datagram. Begin selects
one immutable shape and explicit header/caps; each Append validates and encodes
one record immediately, retaining no record/value view. Count and lengths are
finalized at Finish. Rejected operations leave the buffer and active state
unchanged; a successful Begin replaces even an unfinished packet so an empty
packet after permanent record rejection can be discarded without allocation.
The destination's `BeginDataStream` reserves the header instant and one pending
transaction before appending records. Each v5 append must supply the packet's
sampling interval; other protocols require zero header sampling metadata.
`Finish` checks the final count/length and makes the transaction eligible for
the existing full-write-only `Commit`. Copied handles share destination-owned
scalar counters; stale handles cannot mutate a later transaction or epoch.
Local Abort or failed construction restores the reserved instant, while a
legal ambiguous write retains it. `Reset` releases the pure appender's buffer
after finalization, construction failure, Abort, or Restart without clearing
the caller's datagram. Setup and fixed per-transaction identity may allocate;
no record/value view is retained. The destination integrates its source-ordinal
failure ledger with request packing.

The destination source ledger stores confirmed, invalid, ambiguous, and
unsent-valid classifications in two bits per source ordinal, with dynamically
grown storage and scalar counts and packet boundaries. The ledger retains no
records, values, pdata, payload bytes, or error objects; queries return
classification or scalar value copies. Storage scales with the actual request
and remains separate from the selected-record view and datagram budget.

Sources are admitted sequentially, including invalid sources. One packet may
own at most 1,024 valid ordinals separated only by invalid ordinals. A monotonic
packet floor prevents skipping an unsent valid source or revisiting earlier
packet ranges, so accepted range processing remains linear. Pending valid
records count as unsent until resolution: only the existing full nil-error
write class confirms them; the five legal non-full outcomes mark them ambiguous.
The ledger's write-resolution operation rejects invalid local results without
mutation; the packer then explicitly aborts the local packet and returns a fixed
internal error, leaving pending records unsent. Ambiguity and local abort stop
further packet attempts. These mutations are package-private; the ledger does
not itself normalize, map, write, commit State, or copy Collector subsets.

`Packer.Pack(ctx, logs, lookup)` now connects indexed normalization and mapping to
streamed State transactions and source-ledger resolution. It requires an
already bootstrapped State and uses injected synchronous writes and clock
reads; the ordinal-aware custom lookup is request-local. Shape, v5 sampling,
capacity, and count boundaries flush data. Each data-packet opening may drain
one complete due refresh round before reserving data. If refresh becomes due
again at the next clock read, the request stops transiently instead of starting
another round. Bootstrap and publication remain lifecycle-owned. The caller context is passed
synchronously through data and refresh writes without retention on the packer.
Cancellation detected before a buffered datagram is handed off aborts its
reservation and leaves its valid sources unsent; suffix validation continues
within the admitted bounds. Once a write is attempted, the existing full-write
or ambiguous-write classification remains authoritative.

After an ambiguous data write or failed refresh, the packer continues source
validation using a setup-time appender from the same selected protocol and the
same datagram buffer. Its empty-message Begin/Append/Finish checks include
actual record sizes and header-dependent time validation. A single extra wall
read supplies a cached suffix-preview instant, bounded below by the last
reserved instant; preview never reserves or commits live State. Reset releases
the appender's buffer after each check. Valid suffix records remain unsent;
record-local rejections become invalid. Unexpected internal failures stop wire
validation and return a fixed internal error without reclassifying valid
pending records as invalid. The returned pointer result owns one fixed ledger;
read-only queries avoid ledger copies, and the packer releases its temporary
ledger pointer on return. Neither result nor packer retains the request lookup,
pdata, normalized records, or raw errors. Collector subset copying follows the
[admission and ownership contract](collector-component.md#admission-ownership-and-results).

The initial profile has no queue, persistence, batching, or automatic retry.
Admission allows one whole request per instance and no waiting queue for
concurrent requests; a second request receives the fixed transient `busy` result
without retaining pdata. The admitted request may wait cancelably for internal
refresh or endpoint publication, as described in the
[admission contract](collector-component.md#admission-ownership-and-results).
Invalid records are fixed-reason counted and dropped while valid
siblings continue.  If a transient write follows a confirmed prefix, the
component copies only the ambiguous datagram and unsent valid suffix into a
bounded `consumererror.NewLogs` subset; confirmed and invalid records are
excluded.  The subset is not an anti-replay promise.

## DNS, socket selection, and endpoint replacement

Literal IP endpoints bypass DNS.  Hostnames resolve at Start and through one
per-instance maintenance operation shared by dial, candidate bootstrap, and
revalidation; one active run and one coalesced pending bit are allowed.  The
maintenance token is a sub-token of the future lifecycle registration: it does
not register a root worker, and the lifecycle owner must defer its End on every
cancel, failure, and close path.  A token generation is allocated once per run
with checked non-wrapping exhaustion; results carry that generation and are
rejected after End or by a foreign/copied-consumed token.  No resolver method
spawns a goroutine, queues work, or schedules a timer; each live token may claim
at most one blocking lookup.  On cancellation the owner cancels the lookup
context, joins that lookup, and only then calls End; End rejects an in-flight
lookup and cannot permit the next run to overlap it.

The standard library `net.Resolver.LookupNetIP` seam uses the earlier caller
deadline or configured 100 ms..30 s timeout.  A raw answer slice longer than
64 is rejected before inspection.  Valid matching A/AAAA answers are normalized
(including IPv4-mapped addresses), deduplicated into a fixed eight-address
array, sorted by `netip.Addr.Compare`, and rejected when more than eight unique
matching answers remain; malformed or zoned answers are fixed errors.  Literal
addresses and explicit `udp`/`udp4`/`udp6` family selection are validated before
lookup.  Resolver and test-fake errors retain fixed redacted classes and never
include host, endpoint, payload, or raw DNS text.  The 64-answer ceiling
bounds exporter-side inspection and retained state; it makes no claim about
allocations or parsing performed inside the standard library.

The value snapshot exposes current/selected addresses, availability, generation,
refresh due state, and stale metadata without mutable backing storage.  Initial
lookup success records a selected candidate but does not publish it.  When a
current address is present in a successful answer it remains selected;
otherwise the first sorted compatible answer is selected.  The current address
remains usable while present in a successful answer and while
within finite staleness after an error or answer exclusion; repeated failures or
exclusions do not move the stale origin.  At stale-after, availability is false
and recovery with the same address requires the explicit
`CommitPublishedCandidate` transition.  That transition is the fallible
metadata step inside the future atomic publication under send -> lifecycle
locks, before the infallible socket/epoch swap; a validation failure aborts
publication.  Backward, invalid, or overflowing monotonic samples return a
fixed time error, force unavailable snapshots, retain the monotonic high-water
and stale-expiry latches, and reject lookup/commit transitions.  A later sample
at or above the high-water resumes evaluation against the unchanged stale
origin: an unexpired current address becomes usable again, while an expiry
latch remains unavailable until successful candidate publication.  Wall-clock
changes do not affect freshness.

`transport.NewCandidateDialer` binds the immutable resolver host/network and
numeric port to an effective payload cap, a separate compiler-validated cap,
the optional PMTU assertion, and the existing numeric dial/write seams. The
caller supplies normalized configuration and `CompiledMapping.MaxDatagramSize`;
effective payload cannot exceed that compiler cap. Construction checks the
payload/PMTU bounds before lookup or dial and derives the fixed 28/48-byte
reserve from the configured host, preserving 48 bytes for every hostname.
No candidate can increase the payload budget after a DNS family change.

Candidate dialing uses the live maintenance token to resolve, apply metadata,
and check the selected address's generation, membership, and family. Lookup
failure updates stale metadata and returns its fixed error without dialing a
replacement or closing the existing handle. Successful dial checks local and
remote numeric identities and the selected port. Rejected returned sockets,
including connection-plus-error and late cancellation, are closed before
ownership transfer; the caller owns each accepted `Candidate` and invokes its
once-guarded `Close`. `Candidate.Write` enforces the effective cap before any
deadline or socket write, then delegates counts and fixed error classes to the
existing whole-datagram writer. It never publishes or ends the maintenance
token; the owner keeps that token live through bootstrap/publication or failure.

The internal destination `Runtime` integrates initial and replacement candidate
resolution, dial and complete v9/IPFIX bootstrap outside send. It registers an
attempt before resolution/dial and attaches the returned handle before bootstrap writes. All
fallible state/packer construction precedes publication. Under send -> lifecycle
it rechecks closing, candidate identity and generation, commits resolver metadata,
then transfers the complete endpoint/state/packer together. Failed attempts end
the maintenance token and close their unpublished candidate exactly once.
Published request packing holds send and briefly registers each write under
lifecycle; its callback rejects a candidate that is no longer published or has
expired DNS availability. The packer also checks availability before construction
and handoff, aborting buffered data locally and retaining valid unsent ordinals.

Hostname instances now register one DNS worker after successful Start cleanup.
Start validates its injected timer/channel before DNS or socket operations and
stops it on failure; a successful Start transfers it to the worker. Numeric
endpoints create no DNS worker. A resettable standard-library timer and one
coalesced Consume wake slot schedule freshness rechecks. Each synchronous run
owns one maintenance token through lookup, optional dial/bootstrap, publication
and cleanup; it never retries a failed lookup before the next due interval.
A still-available selected current address retains its socket and epoch.
A changed or expired address requires a fully bootstrapped fresh epoch, even
when expiry recovery selects the old address again. Publication checks the prior
endpoint as well as closing/generation, then retires the old socket outside both
locks before completing the attempt. The manual test timer supplies bounded
reset traces and explicit wake barriers; wall steps do not trigger DNS.

V9/IPFIX instances also register one template worker, including for literal
endpoints. Start validates a distinct template timer/channel before lookup or
dial and stops both timers on failure. The worker shares the published packer's
buffer and bounded refresh drain with Consume; send serializes them and DNS
publication. A successful final data packet that makes refresh due queues one
coalesced wake while holding send. The worker consumes preceding wakes before
attempting a round, rechecks the published endpoint and DNS availability, and
commits only full writes. Failed idle rounds retain their exact shape progress
and rearm a full configured interval; failed requests do not queue retry wakes.
Early timer ticks use the remaining monotonic interval since the latest complete
round, so Consume-driven refresh and endpoint replacement do not drift the next
deadline or duplicate a fresh catalog. V5 has no template worker or timer.

The root Collector wrapper must reuse this single lifecycle authority when
integrated. `Runtime.Shutdown(ctx)` now registers and joins complete Start/Pack
calls, closes admission and detaches handles under lifecycle, then cancels both
operations and closes sockets outside the lock. `Close` uses the same terminal
operation with the configured drain (default 5 seconds, range 1..30 seconds).
Construction rejects DNS or write timeouts longer than that drain. Shutdown
also cancels and joins both maintenance workers, including timer stops, template
commits and candidate cleanup.
Initial/replacement UDP has IPv4/IPv6-loopback and literal protocol-byte evidence.
Collector helper/subset admission joins and independent external decoding remain
pending.
After stale retention expires, no new datagram is built and state does not
advance; Consume returns a fixed transient unavailable error until a candidate
commits.  Private, loopback, link-local,
and multicast targets are allowed only at the trusted operator-config boundary;
records can never alter an endpoint.

## Lifecycle lock order and shutdown

The root Collector lifecycle wrapper's mutex is the sole linearization
authority for closing, admitted calls, maintenance-operation registration,
candidate handles, and the published handle.  A candidate token is registered
before resolve/dial; a returned socket is attached under that mutex before its
first bootstrap Write.  Destination sends take the send mutex, briefly take the
wrapper lifecycle lock to register the Write against the open handle, release
lifecycle, then Write while retaining send.  Publication takes send then the
wrapper lifecycle lock, rechecks closing/generation, swaps destination state,
and releases in reverse order.  No path takes send while holding lifecycle.

The root wrapper's `sync.Once`-guarded Shutdown takes only lifecycle to mark
closing, prevent new admission/registration, and detach current/candidate
handles; it then releases lifecycle before canceling contexts and closing
detached sockets.  Close/deadline interrupts a stalled Write without waiting
behind send.  Shutdown joins admitted calls and registered maintenance workers,
then calls helper Shutdown exactly once.  It uses the earlier of the caller
deadline and `shutdown_drain_timeout`; no blocking operation exceeds that bound.
Repeated or concurrent Shutdown calls return the stored result, and Shutdown
before Start is safe.  A write that completed before close may commit; no write
can begin or reach the network after Shutdown returns.

The runtime implements this with a lifecycle-protected admitted-call count and
a closed-on-zero drain channel. It creates no goroutine to wait for calls. Each
Shutdown caller starts its context/drain bound before close initiation; the first
caller to observe completed cleanup or a canceled/expired wait stores and
broadcasts the terminal result. A concurrent caller with an earlier deadline can
therefore end the shared wait, and subsequent calls retain that result even if
the outstanding operation later finishes cleanup. The close `sync.Once` never
waits for send or admitted calls; a separate result `sync.Once` publishes the
shared outcome. Injected `Conn.Close` must promptly disable network writes and
interrupt an in-flight write, matching the standard-library UDP implementation;
an arbitrary connection that ignores or blocks close cannot meet this contract.
On a drain error, a noncooperative injected lookup/callback may still unwind,
so that result does not claim a successful join. Closed admission, canceled
operation contexts and already-closed sockets prevent it from publishing or
sending. A late dial result is closed before attachment. Both DNS and template
workers use this same drain; the future Collector helper/subset path must also
join this authority.

## Atomic failure matrix

| Event | State transition | Caller/next behavior |
| --- | --- | --- |
| Full `{len,nil}` write | Commit sequence and applicable template/refresh progress. | Continue or return nil. |
| Short/zero/full-with-error, timeout, or cancellation | Leave protocol counters/progress uncommitted; retain logical instant reservation. | Fixed transient error with ambiguous current datagram and valid suffix. |
| Permanent invalid/missing/range/family/oversize record | No wire-state change; fixed-reason loss counter. | Drop it; nil if valid siblings succeed, permanent error if none are valid. |
| Invalid records plus transient valid-write failure | Exclude invalid and already-confirmed records; leave the failed datagram uncommitted. | Transient valid subset takes precedence; invalid records remain permanently dropped. |
| Preflight budget excess | No wire or protocol-state change. | Fixed permanent request error; no pdata is retained. |
| Unexpected encoder invariant | No wire or protocol-state change; fail closed. | Fixed internal error; never emit malformed bytes. |
| Initial/candidate template failure | Root wrapper closes unpublished candidate handle; destination discards v9 origin/progress; old epoch unchanged. | Start fails, or replacement waits for next bounded candidate attempt from copy zero. |
| Refresh failure after earlier datagrams | Retain exact round progress, remain due, block dependent data. | Fixed failure telemetry; next bounded interval/Consume resumes. |
| DNS failure or >8 answers while old endpoint fresh | Keep old socket/epoch. | Continue old endpoint with bounded telemetry. |
| Candidate dial/bootstrap/revalidation failure | Root wrapper closes candidate handle; destination retains old endpoint through staleness. | One coalesced pending trigger; no tight retry loop. |
| Staleness expiry without candidate | Stop packet construction/state advance. | Fixed transient unavailable result. |
| Successful candidate commit | Root wrapper atomically publishes the bootstrapped handle with destination candidate-local state, then closes old handle after commit. | New data may use the new epoch. |
| Shutdown race | Root wrapper closes admission, cancels work, detaches/closes sockets; only a pre-close full write can commit. | Fixed shutdown/transient result; no post-return write. |

The protocol writers and destination state are tested with deterministic clocks,
DNS generations, endpoint replacements, every legal/illegal Write result,
candidate races, refresh failures, uptime exhaustion, and shutdown races.
Independent TShark decoding, golden packets, race/fuzz/load/leak checks, and
custom Collector smoke tests are summarized in the
[verification strategy](implementation-verification.md) and
[MVP acceptance record](../mvp-acceptance.md).

## Sources

Exact release/tool revisions and verified errata are indexed in the
[source ledger](../research/source-ledger.md): Collector Core `v0.160.0`
commit `cd3455cf3a7f672208140b1ebb1581c542b2b0ed`, Contrib `v0.160.0` commit
`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`, and IANA registry metadata last
updated 2026-07-22.  The lifecycle seam follows the pinned Collector
[`component.Component`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/component/component.go),
[`consumer.Logs`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/consumer/logs.go), and
[`exporterhelper.NewLogs`](https://github.com/open-telemetry/opentelemetry-collector/blob/cd3455cf3a7f672208140b1ebb1581c542b2b0ed/exporter/exporterhelper/logs.go)
contracts.  IPFIX Information Element IDs/types/lengths are the
[IANA CSV](https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv)
and timestamp semantics are [RFC 7011 §6.1](https://www.rfc-editor.org/rfc/rfc7011.html#section-6.1)
and the IPFIX information model [RFC 7012 §3.1](https://www.rfc-editor.org/rfc/rfc7012.html#section-3.1);
v9 templates/padding/header semantics are [RFC 3954 §§5–8](https://www.rfc-editor.org/rfc/rfc3954.html#section-5)
and Cisco's [v5 tables](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html#wp1006108).
Verified interpretations also track [RFC 3954 erratum 2096](https://www.rfc-editor.org/errata/eid2096),
[RFC 7011 erratum 4396](https://www.rfc-editor.org/errata/eid4396), and
[RFC 7012 erratum 3881](https://www.rfc-editor.org/errata/eid3881) in the ledger.
Sampling-rate receiver asymmetry and the initial no-Options scope follow the
[receiver and protocol mapping](../compatibility/protocol-mapping.md).
