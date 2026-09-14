# Independent receiver smoke

`TestNfacctd` runs the public Collector exporter against stock pmacct `nfacctd`
1.7.9, whose native C decoder is independent of the OTel receiver's GoFlow2.
It is an opt-in Linux integration test; ordinary `go test ./...` skips the
external process test but runs its output-validation failure cases. No tool is
downloaded, installed or built by a Go test. A supplied unusable binary fails.

From the repository root, with Go 1.26.8 and a Jansson-enabled build:

```bash
smoke_root=$(mktemp -d)
NFACCTD_BINARY=/absolute/path/to/pmacct-1.7.9/src/nfacctd \
NFACCTD_ARTIFACTS="$smoke_root/cases" \
go test ./integration/independent -run '^TestNfacctd$' -count=1 -timeout=5m -v
```

`NFACCTD_ARTIFACTS` must name an absent directory under an existing parent. This
prevents stale output from satisfying a case. Omitting it uses Go's automatically
removed test directory. Keep the directory to inspect actual binary version/hash,
exporter/receiver configs, receiver logs, decoded JSON, explicit expected JSON,
and every emitted payload with length, source socket and SHA-256. These outputs
belong in scratch storage, not Git. Tool versions and source anchors are
summarized in the [source ledger](../../docs/research/source-ledger.md).

Each of the seven [canonical cases](../testdata/receiver/README.md) has a fresh
receiver, no persisted template or sampling state, and one pre-reserved
unprivileged loopback port. One bind attempt is allowed. Readiness requires the
core's bound-socket message **and** the print child's first empty cache purge.
The core message alone arrives before the print child enables pipe wakeups and
can leave a small early burst invisible until shutdown.

A loopback UDP relay retains each received exporter datagram and forwards that
same byte slice unchanged from one socket to nfacctd. The exporter uses its
public factory, validated static profile, real UDP transport and one epoch.
All-invalid raw-body input must reject permanently without adding any datagram.
Three valid requests then exercise these exact streams:

| Protocol | Stream | Data sequences | Decoded aggregates per case |
| --- | --- | --- | --- |
| v5 | data, data, data | 0, 1, 2 | 3 |
| v9 | four bootstrap packets, data, data, two refresh packets, data | 4, 5, 8 | 3; two-rate case 6 |
| IPFIX | four bootstrap packets, data, data, two refresh packets, data | 0, N, 2N for N records/request | 3; two-rate case 6 |

Bootstrap contains two copies of both family templates; refresh contains one
complete catalog. The packet threshold is two, and the last data request stays
below the next threshold. No Options Template/Data is permitted. Tests compare
every template and data byte, including padding, with the existing independently
authored goldens; they separately check header version/count/length, identity,
sequence and v5 header sampling. Live time fields remain live. Distinct sequence
primitives keep the three exports separate in pmacct's cache; distinct sampling
rates keep the two input records separate. JSON lines are still aggregates, not
a general one-to-one promise about flow records.

Two additional IPFIX cases append PEN 32473 / IE 400 (four fixed octets
`00 7f 80 ff`) and IE 401 (variable octets) to the IPv4 profile. Variable payloads
of 3 and 255 bytes exercise both length-prefix forms; byte `i` is `i % 251`.
Literal enterprise template specifiers, prefixes, content and padding extend
the golden baseline. Stock `aggregate_primitives` entries select both identities
with `semantics=raw`; the exact uppercase dash-separated hex JSON strings must
survive. This proves configured enterprise decoding, not arbitrary unknown-field
preservation. V5 has no enterprise fields; v9 private IDs do not carry a PEN.

The explicit pmacct projection asserts all selected keys and exact JSON types:
addresses, ports, protocol, flags, ToS, interfaces, ASNs, masks, flows, packets,
bytes, sampling, export version/sequence/domain and start/end/export timestamps.
There are no unexpected or missing rows/keys. Counts remain exact for a full
print interval plus 100 ms, and again after bounded receiver shutdown.

- `nfacctd_renormalize=false` keeps counters at 1234 packets / 56789 bytes per
  flow. V5 header interval and ordinary four-byte v9/IPFIX IE 34 project to 1000;
  the two-rate cases preserve both 1000 and 2000 without Options state.
- V5 timestamps follow pmacct's whole-second header-minus-uptime calculation;
  header nanoseconds and fractional First/Last precision are discarded. The
  test rebases origin and source times together, preserving wire 1000/1001 ms.
- Default v9 omits flow timing. Pmacct also does not consume the default IPFIX
  IE 156/157 NTP timestamps. For both, start falls back to header export seconds
  and end is zero. This differs from the OTel receiver's documented projection.
- Protocol and TCP flags are strings (`"tcp"`, `"24"`); numeric counters and
  identities are JSON integers; timestamps are epoch-seconds strings with six
  fractional digits. These expectations follow the pinned
  [field handlers](https://github.com/pmacct/pmacct/blob/32fd57ebb5fa966eece1e48ac19e94bb715f0678/src/pkt_handlers.c),
  [JSON renderer](https://github.com/pmacct/pmacct/blob/32fd57ebb5fa966eece1e48ac19e94bb715f0678/src/plugin_cmn_json.c),
  and [custom primitive grammar](https://github.com/pmacct/pmacct/blob/32fd57ebb5fa966eece1e48ac19e94bb715f0678/examples/primitives.lst.example).

The relay does not retain original outer IP/UDP headers and changes the receiver's
transport peer. It does not prove outer checksums, loss-free delivery in other
environments, NTP interpretation by pmacct, next-hop/TTL preservation, sustained
load or general receiver security. External processes use isolated state and a
20-second case deadline, with five seconds for shutdown and process-group cleanup.
The IPFIXcol2 and nfcapd runs are documented below. OCB distribution and
packet capture/TShark verification are summarized in the
[MVP acceptance record](../../docs/mvp-acceptance.md), which also records the
remaining limits.
Those results are separate from this relay smoke.


## IPFIXcol2 / libfds

`TestIPFIXcol2` runs the same shared public-exporter stream against stock CESNET
IPFIXcol2 2.8.0 (`03528c6`) with libfds 0.6.0. Its native C/C++ decoder is
independent of both GoFlow2 and pmacct. The opt-in Linux test requires GNU
`stdbuf`, the UDP/JSON plugins, their runtime libraries, and libfds element
definitions. An explicitly supplied unusable binary or configuration fails.
No download, installation, or source patch happens inside a test.

With an installed release:

```bash
smoke_root=$(mktemp -d)
IPFIXCOL2_BINARY=/absolute/path/to/ipfixcol2 \
IPFIXCOL2_ARTIFACTS="$smoke_root/cases" \
go test ./integration/independent -run '^TestIPFIXcol2$' -count=1 -timeout=5m -v
```

For an extracted package, also set `IPFIXCOL2_PLUGINS` to its plugin directory,
`IPFIXCOL2_DEFINITIONS` to its `etc/libfds` directory, and `LD_LIBRARY_PATH` to
its shared-library directory. The artifacts directory must be absent. As with
pmacct, each case retains binary version/hash, exact command/configuration,
expected/decoded JSON and every actual exporter payload with length/hash/source.

Each of nine fresh receivers binds one pre-reserved unprivileged UDP loopback
port. Readiness requires both its bind and all-threads-started log messages;
`stdbuf -oL -eL` exposes the stock logger's otherwise buffered messages. The
JSON `send` output connects to a TCP listener already bound on loopback, and
the test accepts the connection before export. This avoids absent-client loss
without relying on an external JSON client or polling a buffered stdout stream.
The JSON reader is limited to 1 MiB and the case deadline. Shutdown gets five
seconds before process-group kill; the reader and process are joined.

JSON uses numeric IE names, numeric protocol/flags, Unix millisecond timestamps,
`ignoreUnknown=false`, `ignoreOptions=false`, `octetArrayAsUint=false`,
`detailedInfo=true`, and `templateInfo=true`. Complete ordered JSON equality
checks every key, type and value, including each duplicate/refresh template,
field identity/width, message details, counters, sampling and custom bytes.
Counts stay exact for 100 ms and after receiver shutdown/JSON EOF. Ordinary
unit tests reject missing/duplicate records, wrong template widths/Options,
scaling, lost sampling, changed sequence/time/type and missing enterprise data.

| Wire protocol | Expected receiver conversion | JSON rows per case |
| --- | --- | --- |
| v5 | Synthesized IPFIX template 256 with 22 fields; two padding fields omitted from data JSON. Header sampling becomes ordinary IEs 34/35 (1000/0), without counter scaling. Absolute millisecond First/Last includes header nanoseconds. Converted lengths are 176 then 80/80. | 1 template + 3 data |
| v9 | Templates keep IDs/fields. Sequence becomes Data Record count: 0/N/2N for data, zero for bootstrap, 2N for refresh. Data Set padding is removed; lengths are `20 + 43*N` (IPv4) or `20 + 67*N` (IPv6). Default profile has no time IEs, so no flow times appear. | 6 templates + 3 data; two-rate case 6 data |
| IPFIX | Header identities/sequences/lengths and templates remain native. libfds Unix JSON truncates NTP fractions to milliseconds: canonical start and the encoded +1 ms end both display `1788220801000`. | 6 templates + 3 data; two-rate case 6 data |

`N` is records per request (one, or two distinct ordinary IE 34 rates). V9 and
IPFIX preserve 1000/2000 and unscaled counters, next-hop is checked for v5, and
TTL/family is checked for v9/IPFIX. PEN 32473 / IE 400 and 401 retain their
identities and fixed/variable content as `0x` plus uppercase hex, including the
3/255-byte variable cases. All template rows are ordinary, with zero Options.

The projection follows the pinned
[v5 converter](https://github.com/CESNET/ipfixcol2/blob/03528c600b5692de9fa41e49cb258e5295454b25/src/core/netflow2ipfix/netflow5.c),
[v9 converter](https://github.com/CESNET/ipfixcol2/blob/03528c600b5692de9fa41e49cb258e5295454b25/src/core/netflow2ipfix/netflow9.c),
[JSON plugin](https://github.com/CESNET/ipfixcol2/blob/03528c600b5692de9fa41e49cb258e5295454b25/src/plugins/output/json/src/Storage.cpp),
and libfds 0.6.0 [JSON conversion](https://github.com/CESNET/libfds/blob/ab219dc02bc70063a62da7841339e10b1a37fd3f/src/converters/json.c)
and [NTP conversion](https://github.com/CESNET/libfds/blob/ab219dc02bc70063a62da7841339e10b1a37fd3f/include/libfds/converters.h).
The retained original headers and golden/literal checks remain wire authority
for legacy sequences and lengths. The relay changes the transport peer and
provides no outer-header/checksum capture. Millisecond JSON cannot prove full
NTP precision; these passing cases do not establish general receiver security,
load behavior, template expiry/restart recovery, or the separate OCB/TShark
qualification summarized in the [MVP acceptance record](../../docs/mvp-acceptance.md).

## nfcapd / nfdump

`TestNfcapd` runs the same nine live-exporter cases against stock nfdump 1.7.9
(`94d5f8a`), whose native C decoder is independent of GoFlow2, pmacct and libfds.
The operator authorized this bounded version-specific smoke; it is not broader
nfdump security clearance. Supply both programs from the same reviewed build:

```bash
smoke_root=$(mktemp -d)
NFCAPD_BINARY=/absolute/path/to/nfcapd \
NFDUMP_BINARY=/absolute/path/to/nfdump \
NFCAPD_ARTIFACTS="$smoke_root/cases" \
go test -race ./integration/independent -run '^TestNfcapd$' -count=1 -timeout=5m -v
```

The opt-in Linux test skips only when neither binary is supplied. Missing,
unusable or wrong-version programs fail; tests never download or install tools.
The artifacts directory must be absent. Each fresh receiver uses an isolated
flow directory, a pre-reserved unprivileged loopback port, and this configuration:

```text
nfcapd -C none -w FLOWDIR -b 127.0.0.1 -p PORT -4 -t 2 -I otel-netflow
```

Foreground readiness is the stock `Startup nfcapd.` stderr message after bind,
decoder initialization, postprocessor launch and bookkeeper setup. Completed
timestamped flow files are read in order using
`nfdump -C none -q -R FIRST:LAST -o ndjson`; active `.current.*` files are excluded.
No aggregation or `-s` sampling override is enabled. `TZ=UTC` makes nfdump's
local-time strings explicit. Exact ordered JSON equality checks every
key/type/value except `received`, which must have the exact millisecond format
and fall within the live run. Counts remain exact for 100 ms and again after
SIGINT, final rotation and process exit. Cases have 20-second deadlines and
five-second process-group cleanup; each decoder command has a three-second
timeout and a 1 MiB output cap.

| Wire input | Explicit nfdump 1.7.9 projection |
| --- | --- |
| v5 IPv4 | Header sampling 1000 scales packets/bytes to 1,234,000/56,789,000 and sets numeric `sampled=1`. Header nanoseconds and uptime produce millisecond First/Last, preserving the 1 ms duration. Next hop survives. The decoder never copies the wire `/24` masks: output masks are zero and derived networks empty. |
| v9 IPv4/IPv6 | Counters remain 1234/56789 with `sampled=0`; ordinary IE 34 is skipped. The two-rate case yields six flows, but 1000 and 2000 are indistinguishable in decoded output. Without flow-time IEs, First/Last are Unix epoch strings. `/24` and `/64` prefixes survive. |
| IPFIX IPv4/IPv6 | Ordinary IE 34 has the same loss as v9. NTP IEs 156/157 floor to milliseconds, so canonical start and encoded +1 ms end both display `2026-09-01T00:00:01.000`. Prefixes survive. |
| IPFIX enterprise 3/255 bytes | PEN 32473 IEs 400/401 are unsupported and skipped, including both variable-length prefixes. All three base flow records still decode; no custom field is preserved. Original enterprise bytes remain covered by the shared golden/literal stream checks. |

All cases check addresses, ports, numeric protocol, string TCP flags, ToS,
interfaces, ASNs, counters and loopback router identity. V9/IPFIX also check
min/max TTL 64/0 and the complete layer-2 extension selected by IE 60 (family
4/6 plus zero ancillary fields). `export_sysid=1` is receiver-local identity;
NDJSON does not expose original packet sequence, templates or header domain.
The shared stream retains and verifies those original headers, bootstrap,
complete refresh, zero Options and permanent raw-body rejection.

These projections follow pinned
[v5 conversion](https://github.com/phaag/nfdump/blob/94d5f8a8636aba91731ad228bc8b2724c75f1c76/src/netflow/netflow_v5_v7.c),
[v9 conversion](https://github.com/phaag/nfdump/blob/94d5f8a8636aba91731ad228bc8b2724c75f1c76/src/netflow/netflow_v9.c),
[IPFIX conversion and field map](https://github.com/phaag/nfdump/blob/94d5f8a8636aba91731ad228bc8b2724c75f1c76/src/netflow/ipfix.c),
and [NDJSON rendering](https://github.com/phaag/nfdump/blob/94d5f8a8636aba91731ad228bc8b2724c75f1c76/src/output/output_ndjson.c).
The [source ledger](../../docs/research/source-ledger.md) records tool identity
and source anchors. No exporter repair was needed. This relay does not
capture original outer headers/checksums; unknown-field preservation, Options,
template expiry/restart recovery, load and security remain unproved by this
relay. The separate OCB/TShark qualification is summarized in the
[MVP acceptance record](../../docs/mvp-acceptance.md).

## IPFIX general profile measured-time check

`TestNfcapd/ipfix-general/canonical-ipv4` selects the new general profile through
the public exporter and forwards the actual emitted 152/153 template/data
packets to stock nfcapd/nfdump 1.7.9. Known canonical ns
`1788220800123456789` / `1788220801123999999` decode as
`2026-09-01T00:00:00.123` / `2026-09-01T00:00:01.123`; full tuple/counter
projection, template bootstrap/refresh and sequence assertions remain active.
The same pinned 1.7.9 binaries are used for this bounded case.
The original core-v1 cases remain unchanged, and this result does not imply
sampling Options support, recovered provenance, or proprietary appliance success.
