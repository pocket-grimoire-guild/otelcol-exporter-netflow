# Process leak acceptance

The tagged `integration/leak` package measures the public Collector exporter
lifecycle over real loopback UDP. It runs two warmup cycles and then 100 fresh
start/send/shutdown cycles for each of NetFlow v5, NetFlow v9, and IPFIX. Every
cycle uses the canonical `internal/testpdata` record, the public factory, a
`localhost:<port>` endpoint, the system resolver, and real standard-library
timers. `localhost` is used so the hostname maintenance path is exercised
without an external DNS dependency; the listener is IPv4 loopback and the
resolver's deterministic address ordering is checked by requiring a loopback
datagram.

The functional assertions require v5 to produce a data datagram, and v9/IPFIX
to produce exactly four template bootstrap datagrams followed by a data-set
datagram. Each data packet's protocol version and template/data set class are
checked from its header. After shutdown, a valid canonical record must be
rejected with the closed-runtime error and a bounded read must observe no
additional datagram.

After an intentional positive control proves that the measurements see a live
goroutine and UDP socket, the test settles a process baseline. It requires
five consecutive equal samples within two seconds after warmup and after every
cycle. Goroutines use `runtime.NumGoroutine`. On Linux, sockets are counted as
`socket:[...]` links under `/proc/self/fd`; the exact count must return to the
baseline. Other platforms report that OS socket counting is unavailable while
still running all functional and goroutine checks; the same fallback applies
if `/proc/self/fd` is unavailable on Linux. There is no per-cycle growth
allowance.

Samples intentionally do not force garbage collection. The closed-resource
sample runs inside the cycle while the exporter remains a live local (and uses
`runtime.KeepAlive` after sampling), with the test listener explicitly included
in that cycle's expected socket count. The following settled sample runs after
the listener closes, so a leaked exporter handle cannot be hidden by the
measurement itself.

Each cycle owns its cleanup defers inside a helper, so a failure cannot retain
300 exporter references. Deferred cleanup also covers failed starts and failed
assertions. The test creates a one-second real DNS maintenance timer on every
hostname cycle, and v9/IPFIX also create the real template-refresh timer. The
public factory exposes no independent expiry callback, so timer firing and
timer retention are not directly measured; template refresh retains its
production minimum of one minute and is checked for setup and shutdown only.
These checks do not measure RSS, allocator growth, kernel timer internals,
packet loss beyond the local socket deadline, or independent collector
decoding.

Run the bounded normal check from the repository root:

```bash
scripts/check-leaks.sh
```

Run the same package under the race detector:

```bash
scripts/check-leaks.sh --race
```

The runner passes an explicit 15-minute test timeout and executes only
`./integration/leak` and the `TestProcessLeakAcceptance` test.
