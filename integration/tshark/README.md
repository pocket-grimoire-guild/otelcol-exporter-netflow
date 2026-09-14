# Independent immutable-golden and live Collector decoder

The runner independently decodes all seven immutable v5/v9/IPFIX goldens with
TShark **4.6.8**, source commit `e677bf052328efc1ed897a547fa161836a0e4ff7`.
It consumes the existing [image digest](IMAGE_DIGEST), [source identity](source.lock),
[goldens](../testdata/golden/manifest.json) and
[verified PCAP inventory](../testdata/pcap/README.md). No production encoder is
imported by the oracle. The literal field expectations come from the
[static profiles](../../docs/compatibility/default-profiles.md) and canonical
fixture metadata, not from a new decoder report.

From the checkout root on Linux/amd64, with Go 1.26.8, rootless Podman and the
exact image already available locally:

```bash
go run ./integration/tshark/wrap_pcaps.go \
  --golden-manifest integration/testdata/golden/manifest.json \
  --manifest integration/testdata/pcap/payload-manifest.yaml \
  --out integration/testdata/pcap
./integration/tshark/run_oracle.sh --pull=never \
  --image localhost/otel-netflow/tshark-oracle@sha256:1b0a680887ceb212beeda59fb3cf84289d00c138a3517028a8b651631e51f7c6
```

The runner fails if any input, image pin, version, executable hash, decode or
cleanup check fails. It checks rootless execution and re-inspects image
ID/digest/platform before every container. It never pulls or uses a mutable tag
or host TShark fallback. The pinned image's source/build identities remain in
`source.lock`. Rebuilding a
similarly named image does not satisfy the pinned identity.

Every PCAP is read through the existing bounded, regular-file/non-symlink
verifier. Only the exact verified bytes are copied into a new private staging
directory; original paths are never reopened for the mount. The decoder gets
one read-only bind mount containing only these PCAPs, no network or capabilities,
no new privileges, a read-only root, and no host home, credentials or engine
socket. Limits are 512 MiB memory including swap, 128 processes, one CPU, 128
file descriptors, 1 MiB per stdout/stderr stream, 30 seconds per command, and
five minutes overall. Each container is removed on success, startup failure,
output overflow, cancellation or timeout, with a separate ten-second cleanup
deadline. Cleanup failure prevents PASS. SIGINT/SIGTERM are forwarded to the
compiled Go driver; the shell waits for its cleanup before deleting the binary.
An unavailable/unresponsive engine can prevent cleanup and is reported as failure.

The private `/tmp` mount is `nosuid,nodev,noexec`, limited to 16 MiB and uses
[`notmpcopyup`](https://docs.podman.io/en/v5.4.1/markdown/podman-run.1.html).
The pinned image retains a roughly 72 MB source archive in `/tmp`; copying that
into the bounded mount caused the earlier `crun: write: No space left on device`
startup failure. Disabling copy-up preserves the limit and starts the same image.
Automatic additional writable tmpfs mounts are disabled.

The supported engine is local rootless Podman with access to the checked-in
fixtures. Root, the invoking UID, and the rootless service are trusted. SSH/TCP
and named remote connections are rejected; arbitrary remote-host staging is
unsupported.
Every staging ancestor must be owned by root or the invoking UID and protected
against group/other replacement; sticky shared ancestors are allowed. The
artifact parent and staged fixtures must be caller-owned and not writable by
group/other. Symlinks and mount-option separators are rejected. No permission
or host runtime setting is automatically changed.

## Evidence and regression checks

The default removes temporary decoder outputs under ignored `dist/`. To retain
bounded stdout/stderr, exact staged PCAPs and a compact success ledger, set
`NETFLOW_TSHARK_ARTIFACTS` to an existing trusted directory on that same shared
filesystem. Each invocation creates a fresh `tshark-*` subdirectory, preventing
old reports from satisfying the run. It contains `PASS.txt` only after all seven
decodes and their container cleanup succeed. The original payload manifest
supplies each staged packet's length/hash.

```bash
NETFLOW_TSHARK_ARTIFACTS=/path/to/private/shared/artifacts \
  ./integration/tshark/run_oracle.sh --pull=never \
  --image localhost/otel-netflow/tshark-oracle@sha256:1b0a680887ceb212beeda59fb3cf84289d00c138a3517028a8b651631e51f7c6
NETFLOW_TSHARK_PDML_DIR=/path/to/private/shared/artifacts/tshark-RESULT \
  go test ./integration/tshark/internal/... -count=1 -timeout=2m
go test -race ./integration/tshark/internal/... -count=1 -timeout=2m
shellcheck integration/tshark/run_oracle.sh
```

The optional recorded-output test mutates every accepted flow field's value,
width, position and presence in the actual retained PDML, then tests payload
substitution, missing checksum/length checks, extra packets/Options, decoder
identity, expert errors and truncation at every XML token boundary. These are
parser regression checks; a supplied report alone does not prove execution.
Ordinary tests also cover malformed/oversized evidence, connection/image
rejection, unsafe staging paths, output limits and synchronous cleanup after
injected container failures. `make check test` includes these ordinary Go tests.

The runner uses full PDML instead of flattened fields CSV because the
[pinned TShark PDML output](https://github.com/wireshark/wireshark/blob/e677bf052328efc1ed897a547fa161836a0e4ff7/doc/man_pages/tshark.adoc)
provides field widths and byte positions as well as values. It requires one
complete Ethernet/IPv4/UDP/flow packet, checks outer lengths and good IP/UDP
checksum status with a nonzero UDP checksum, and binds TShark's extracted UDP
payload length, SHA-256 and full bytes to the verified golden. No display filter
can hide an extra packet. Any expert or malformed field fails.

All selected v5 header/record fields and v9/IPFIX template/data fields must
match literal values, order, widths and offsets. Exact template/data Set IDs
and counts exclude Options. V9/IPFIX cover IPv4, IPv6, and two ordinary four-byte
IE/type 34 rates, 1000 then 2000, with unscaled counters. Padding and zero
sequence are checked. IPFIX's immutable end fraction `0x00418937` decodes to
999999 ns after the start second; the nanosecond projection is explicit.

The default run uses **synthetic golden envelopes** with IPv4 transport even for
IPv6 flow records. It does not establish live capture or checksum offload behavior.

The [OCB live command](../../distribution/ocb/README.md#live-packets-and-independent-checksums)
now produces original veth captures and calls this runner with
`--live-capture /absolute/path/to/fresh/ocb-RESULT`. That mode requires all 21
frames and all 21 application payloads from the complete smoke. It checks the
PCAP hash, complete nanosecond framing, socket/length/hash/full-byte bijection
and fixed inventory before staging the unchanged capture. The same pinned
image, executable identity, resource limits and container cleanup apply.
The decoder gets the four destination-port decode-as rules, with no display
filter or packet rewrite. Full PDML proves the declared receiver projection,
separate bootstrap/data messages, literal field values/order/widths/offsets,
expected domains/sequences, live header times, no Options, outer lengths and
nonzero valid IP/UDP checksums. Every actual packet is checked in capture order.
The immutable mode and live mode retain separate PASS descriptions.

Only a successful fresh OCB live command establishes execution evidence;
re-decoding an existing PCAP or a stored report does not. Neither matrix adds
refresh progression, custom enterprise, physical-NIC or MVP acceptance claims.

## IPFIX general profile

The two additional `general-ipv4-v1.bin` / `general-ipv6-v1.bin` payloads under
`integration/testdata/golden/ipfix/` preserve the core field order with final
IEs 152/153. Their literal lengths and hashes are checked by
`general_profile_test.go`; both materializing and streaming writers compare
against these bytes. The original seven-golden inventory remains unchanged.
Run the fresh fixtures through the same pinned image and isolation helpers:

```bash
NETFLOW_TSHARK_RUN_GENERAL=1 go test ./integration/tshark \
  -run '^TestGeneralProfile' -count=1 -timeout=5m -v
```

The pinned TShark 4.6.8 executable has SHA-256
`021e06894d69ed7a4ed0709de69507b35bdeab7acc018d2a7a4e435db7bd2100`.
Both families passed PDML tuple/count/template/order/width/offset/time and
checksum checks: measured source ns `1788220800123456789` /
`1788220801123999999` serialize to `1788220800123` / `1788220801123` ms,
with a separate valid header export time `1788220803` seconds. These are fresh
152/153 decode results, not legacy receiver fallback evidence. This does not
establish appliance ingestion or source deployment provenance.
