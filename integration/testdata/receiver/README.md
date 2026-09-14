# Pinned receiver semantic fixtures

`../canonical/fixtures.json` remains the authored input. The three `ledger.json`
files pin its raw file SHA-256 (the golden manifest separately hashes normalized
JSON) and state the expected receiver projection. Ordinary tests never rewrite
inputs or expected values. Run from the repository root:

```bash
(cd integration/receiver && go test -mod=readonly . -run '^Test(SemanticRoundTrip|LargePinnedReceiverPacketization)$' -count=1 -timeout=10m)
```

`TestLargePinnedReceiverPacketization` runs one request through each protocol
with 65 valid IPv4 records and eight invalid siblings. The invalid records are
inserted after valid counts `0, 6, 9, 10, 18, 20, 60, 65`; the record after
count 20 has an unsupported raw body and the others have an invalid source
address. The request also carries a 17 MiB ignored resource string. The test
requires mixed-input completion with a nil request error while all 65 valid
records arrive in source-port order; the eight permanently dropped records
are checked through outcome telemetry. It also checks a full pdata digest before
and after the read-only export call.

The test-owned packet ledger derives each data length from the protocol header,
set header, encoded record width, and permitted set padding. With the default
464-byte payload cap, it expects these data streams and checks their aggregate
data byte total through exporter telemetry (bootstrap is included in the final
byte total):

| Protocol | Data records per packet | Data packet lengths | Data packets / bytes | Total bytes |
| --- | --- | --- | ---: | ---: |
| V5 | 9, then 2 | 7 × 456, 120 | 8 / 3312 | 3312 |
| V9 | 10, then 5 | 6 × 456, 240 | 7 / 2976 | 3376 |
| IPFIX | 6, then 5 | 10 × 452, 380 | 11 / 4900 | 5316 |

V9's selected IPv4 shape has 43 encoded record bytes; the full-record packet
length is 456 after its four-byte FlowSet header and two permitted padding
bytes. The receiver's `flow.sequence_num` groups are checked against the
ledger: V5 and IPFIX advance by record count, while V9 advances once per data
packet after its four bootstrap template packets. Receiver queue capacity is
set to bootstrap plus all expected data packets, and shutdown is followed by
stable-count checks. Existing independent wire captures remain the authority
for each individual datagram's byte identity.

The test uses both public component factories and real loopback UDP, with a fresh
Contrib `v0.160.0` receiver for each case. Each receiver uses one pre-reserved
nonzero port, one socket, one worker, and a queue equal to its complete fixture
datagram count. A bind race fails the case without retry. Receiver Start is
readiness; exporter Start follows it. All-invalid raw-body and invalid-address
requests must fail permanently without adding datagrams. After exporter Shutdown,
record count must equal the ledger and stay unchanged for 100 ms; receiver
Shutdown is followed by another exact count assertion.

| Case | Records | Bootstrap datagrams / bytes | Data datagrams / bytes | First data sequence |
| --- | ---: | ---: | ---: | ---: |
| V5 IPv4 | 1 | 0 / 0 | 1 / 72 | 0 |
| V9 IPv4 | 1 | 4 / 400 | 1 / 68 | 4 |
| V9 IPv6 | 1 | 4 / 400 | 1 / 92 | 4 |
| V9 two sampling rates | 2 | 4 / 400 | 1 / 112 | 4 |
| IPFIX IPv4 | 1 | 4 / 416 | 1 / 92 | 0 |
| IPFIX IPv6 | 1 | 4 / 416 | 1 / 116 | 0 |
| IPFIX two sampling rates | 2 | 4 / 416 | 1 / 164 | 0 |

The default catalogs send two templates per bootstrap copy, each in its own
packet, and send two copies. V9 counts all four successful Export Packets;
IPFIX templates add zero Data Records. Component telemetry verifies one epoch,
exact local datagram count, and total intended payload bytes. Those measurements
are not captured byte identity or remote delivery acknowledgements. Existing
independently authored wire goldens remain required; this semantic test does not
complete TShark or OCB live-capture verification.

All output attributes have exact expected OTel types and values, apart from the
explicit live-time rules below. Missing optional next hops remain absent. Bodies
and resource attributes are empty; scope is `otelcol/netflowreceiver` with only
`receiver=netflow`. Every record has `Timestamp == flow.start` and nonnegative
`ObservedTimestamp == flow.time_received`. The latter is newly generated UDP
receive time, not the input's canonical receive time. The original sampler
`192.0.2.254` becomes `127.0.0.1`, including IPv6 flows carried over IPv4 UDP.
Sampler transport family does not constrain the measured flow family.

- V5 rebases the configured origin and source start/end together to a live
  millisecond boundary, preserving the canonical First/Last values 1000/1001 ms.
  This prevents fixture expiry at the uint32 uptime ceiling; decoded start/end
  must equal those rebased source attributes exactly. Input envelope timestamps
  deliberately remain canonical, proving attributes are authoritative.
- V9's default profile omits FIRST/LAST. Its decoded start and end therefore
  equal header export time in whole seconds, bounded by the actual ConsumeLogs
  call. Neither reconstructs the original canonical start/end.
- IPFIX IE 156/157 retain the canonical NTP mapping. Whole-second start survives
  exactly; the canonical end at `+1 ms` becomes `1788220801000999999` ns in the
  pinned GoFlow conversion (one nanosecond below source).
- Ordinary four-byte IE/type 34 contains rates 1000 and 2000 in the two-rate
  inputs/goldens; both receiver records report zero. No Options are emitted and
  the exporter has no sampling cache. Each case starts with a fresh receiver.

These expectations follow the pinned receiver
[parser](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go),
[producer wrapper](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/producer.go),
and GoFlow2's
[v5 conversion](https://github.com/netsampler/goflow2/blob/c9824f41bcad11d4490a668ed5270b03056d8217/producer/proto/producer_nflegacy.go)
and [v9/IPFIX conversion](https://github.com/netsampler/goflow2/blob/c9824f41bcad11d4490a668ed5270b03056d8217/producer/proto/producer_nf.go).
The pinned receiver ignores its Shutdown context; the outer Go test timeout is
the ultimate cleanup bound. This test makes no broader receiver shutdown claim.
