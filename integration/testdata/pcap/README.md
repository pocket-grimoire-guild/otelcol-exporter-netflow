# Immutable golden packet envelopes

The authored [payload inventory](payload-manifest.yaml) binds all seven existing
v5/v9/IPFIX goldens to exactly one generated PCAP apiece. It also pins the raw
golden-manifest SHA-256. Generation does not encode flows or rewrite a golden or
manifest. A changed golden requires an explicit inventory review.

From the repository root on Linux with Go 1.26.8 on `PATH`:

```bash
python3 scripts/check-golden-manifest.py integration/testdata/golden/manifest.json
go run ./integration/tshark/wrap_pcaps.go \
  --golden-manifest integration/testdata/golden/manifest.json \
  --manifest integration/testdata/pcap/payload-manifest.yaml \
  --out integration/testdata/pcap
go run ./integration/tshark/verify_payloads.go \
  --manifest integration/testdata/pcap/payload-manifest.yaml \
  --pcap-root integration/testdata/pcap \
  --golden-manifest integration/testdata/golden/manifest.json
go test ./integration/tshark/internal/fixturepcap -count=1 -timeout=1m
```

PCAPs are disposable, ignored outputs. Re-running the wrapper accepts existing
identical files without rewriting them and fails on a differing file. It may
leave already-created valid PCAPs if a later output fails; remove only those
generated outputs before retrying. The verifier rejects missing, duplicated,
truncated, substituted, or undeclared PCAP inputs. Input reads are bounded and
require regular files with no symlink path components. No network is used.

Each file contains a little-endian microsecond PCAP 2.4 header, one complete
Ethernet frame without FCS, a 20-byte unfragmented IPv4 header, and UDP. The
synthetic source/destination MACs are `02:00:00:00:00:01`/`02:00:00:00:00:02`,
and the outer IPs are `192.0.2.254`/`192.0.2.253`. Source port is 40000;
destination is 2055 for v5/v9 and 4739 for IPFIX. Capture time is fixed at
Unix second 1788220803. IPv6 flow addresses remain inside the original payload;
these envelopes exercise IPv4 transport for all three flow protocols.

The wrapper computes IPv4 and nonzero UDP checksums, including RFC 768's
computed-zero representation. The verifier parses and validates the envelope,
then compares the extracted UDP length, SHA-256 and bytes with the independently
authored golden. It checks the full file, including lengths and the absence of
extra records/trailing bytes; it never skips packets by display filter. Tests
include every truncation point, framing/checksum mutations, a payload change
with recomputed valid checksums, odd and maximum UDP lengths, and filesystem
rejections. The original canonical-source validator remains the authority for
the golden manifest's schema and canonical fixture references.

Format sources are the [PCAP format, revision 06, sections 4–5](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html),
[RFC 791 section 3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1),
and [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html). The checksum unit test
also uses the independent [RFC 1071 section 3 example](https://www.rfc-editor.org/rfc/rfc1071.html#section-3).

These PCAPs are explicitly marked `synthetic-golden`. They prove preservation
of immutable payloads and provide decoder inputs. They cannot prove live
Collector capture identity, kernel checksum generation, checksum offload,
transport failure isolation, or shutdown. The [pinned TShark runner](../../tshark/README.md) independently verifies these
immutable envelopes. Live outer-capture checks are documented in the
[OCB live-capture guide](../../../distribution/ocb/README.md#live-packets-and-independent-checksums).
