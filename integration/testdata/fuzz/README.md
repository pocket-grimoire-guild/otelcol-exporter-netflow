# Hostile-input fuzz seeds

The [manifest](manifest.json) binds named Go fuzz corpus files to boundary and
malformed-input cases. `make check` verifies target inventory, corpus membership,
case labels, and hashes; `go test` replays the seed arguments. Ordinary checks
never regenerate or rewrite this corpus. Review a discovered regression before
adding it as a named seed or ordinary unit test.

The implemented input-path targets are:

| Target | Input and setup bounds | Assertions |
| --- | --- | --- |
| `FuzzPreflight` | At most 256 input bytes; one of nine finite scenarios; hierarchy uses two resources, four scopes, and five records; irrelevant metadata uses at most 16 wide keys or an initial map followed by 16 slice/map pairs. | Structural malformed-root and empty-hierarchy outcomes; canonical IPv4/IPv6 output; exact callback counts and resource/scope ordinal order; irrelevant string, bytes, all OTel value types, wide keys, and deep metadata remain accepted; input pdata stays immutable. |
| `FuzzNormalize` | At most 4096 text bytes; three receiver records spanning resources/scopes; one canonical-field or body mutation in the middle record. | Exact 41-field schema and test-owned token vocabulary; integer widths, nanosecond timestamps, canonical addresses/MACs, sampler-family exception, required/optional presence, all OTel types and raw bodies; indexed continuation and legacy first-error behavior; callback error propagation; no partial invalid output, mutation, or retained mutable pdata. |
| `FuzzCompileMapping` | At most 8192 JSON bytes; one bounded grammar case selected from 39 reviewed profiles, selectors, tokens, custom fields, IDs, PMTU, and limits. | Strict DecodeJSON boundary; known grammar cases have independent accept/reject expectations; rejected Compile calls return zero output and fixed redacted diagnostics; successful catalogs validate, remain deterministic, and do not expose mutable descriptor storage or mutate caller configuration. |
| `FuzzTemplateCatalog` | At most 4096 input bytes; one catalog case or one state scenario. Catalogs use at most 17 shapes and 65 fields to cross the 16/64 ceilings; state setup uses at most three initial copies, six bootstrap packets, three refresh packets, and one data transaction. | Test-owned catalog acceptance for all protocols, field/shape/template/ID bounds, immutable adoption and fixed diagnostics; deterministic bootstrap/order/refresh behavior; v9 template sequence versus IPFIX zero template charge; full, ambiguous, invalid, and encoding-failure outcomes; unpublished bootstrap discard, published refresh retry, restart, and stale-transaction rejection without invalid state commits. |
| `FuzzPacketPacking` | Five scalar byte selectors; at most five records, five captured data packets of at most 464 bytes, and two catalog shapes per scenario. | Independent fixed-offset packet/version/length/value/order checks for v5/v9/IPFIX; record-count, payload, shape, and v5 sampling flushes; invalid gaps; confirmed prefix plus ambiguous/invalid handoff and unsent suffix ledger classes; cancellation and malformed-root admission without callbacks or writes; variable-record oversize rejection, fixed redacted diagnostics, and result stability after request mutation. |
| `FuzzNetFlow5Writer` | Four uint8 selectors; at most 31 fixed 48-byte records (1,512-byte candidate) for immutable writes and two records for streaming checks. | Independent Cisco B-3/B-4 fixed-offset and immutable canonical-golden checks; count 0/1/30/31, integer widths and signed negatives, timestamp/origin/order/millisecond/uptime limits, IPv4/family mismatch, header identity/sampling, exact and short capacity/budget; rejected append/Begin preserve buffers and prefix state, while Finish/Reset lifecycle recovery remains usable. |
| `FuzzNetFlow9Writer` | Four uint8 selectors; at most two fixed records and 256-byte immutable/streaming buffers. | Independent RFC 3954 template/data/header/value oracle and immutable IPv4/IPv6/sampling goldens; template-only/data-only/mixed packets, private one/two-byte padding boundaries, signed/unsigned widths, timestamp/header/count/family/capacity failures; rejected append/Begin preserve buffers and accepted prefixes, with Finish/Reset recovery. |
| `FuzzIPFIXWriter` | Four uint8 selectors; at most 65,536-byte variable values, 65,535-byte immutable buffers, and 600-byte streaming buffers. | Independent fixed-offset Template/Data Set and value oracle with literal full-word NTP vectors; IPv4/IPv6/sampling goldens, enterprise E-bit/PEN and append-only ordering, fixed/variable string/octet prefixes at 0/1/254/255/256/max/above, scalar widths, family/header/count/declared-size and capacity failures, plus atomic streaming prefix/tail preservation, variable 254/255 late rejection, failed Begin recovery, Finish, and Reset. |

The preflight grammar uses `scenario % 9` to route malformed root, empty
hierarchy, canonical IPv4, canonical IPv6, cross-resource/scope order, ignored
string, ignored bytes, all ignored OTel value types with wide keys, or ignored
deep alternating map/slice metadata. The byte input is capped at 256 bytes;
metadata generation is capped at 16 wide keys and 16 nested slice/map pairs. Every
valid route marks pdata read-only before inspection and normalization, checks
the expected record errors and normalized output, and compares serialized input
before and after processing. Packetization and large-request tests retain the
actual record, datagram, and path-boundary checks.

These targets are deterministic, use local pdata or local configuration bytes,
and do not change production registries. The preflight oracle checks explicit
scenario outcomes and source identities; normalization uses independent
schema/vocabulary tables. The mapping oracle uses a finite test-owned configuration grammar
and catalog invariants. Shared `netip`/MAC parsing still uses the Go standard
library. These are input-path checks; independent wire evidence remains owned
by the immutable goldens and TShark tests.

`FuzzCompileMapping` keeps the arbitrary JSON lane useful for strict decoding
and panic resistance, while the grammar lane constructs reviewed valid and
invalid configurations. It covers all three built-in profiles, explicit
field targets and wire-identity collisions, active and inactive token maps,
the v9 ICMP composite, IPFIX fixed and variable enterprise fields, v9 private
fields, pointer-presence errors, template/record/key/value ceilings, ID and
PMTU boundaries, ownership, catalog determinism, and redacted diagnostics.

`FuzzTemplateCatalog` keeps catalog construction separate from the state oracle.
The catalog lane constructs bounded v9/IPFIX `wire.CatalogSpec` values and
classifies acceptance from reviewed shape, field, template-byte, and ID
boundaries before calling production validation/adoption. The v5 lane adopts
the existing valid compiler fixture. The state lane uses the existing
destination test writer and compiler mappings, with no network or shared
production state. Its finite scenarios bootstrap two or three initial copies,
exercise compiler order and shape rejection, trigger one refresh, classify one
write outcome, restart once, or discard a partial bootstrap. Bootstrap failure
seeds cover encoder rejection, all five legal ambiguous write outcomes, and
negative/overlength local write results before retrying from shape zero. A second refresh
scenario fails after the first shape and completes the retry. V9 template
packets advance sequence; IPFIX template packets do not. Catalog and shape
accessors are mutated only through returned copies.

Run each target separately because Go fuzzing selects one target at a time:

```bash
python3 scripts/check-fuzz-manifest.py
go test ./internal/normalize -run '^Fuzz(Preflight|Normalize)$' -count=1
go test ./internal/normalize -run '^$' -fuzz='^FuzzPreflight$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/normalize -run '^$' -fuzz='^FuzzNormalize$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/mapping -run '^FuzzCompileMapping$' -count=1
go test ./internal/mapping -run '^$' -fuzz='^FuzzCompileMapping$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/destination -run '^FuzzTemplateCatalog$' -count=1
go test ./internal/destination -run '^$' -fuzz='^FuzzTemplateCatalog$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/destination -run '^FuzzPacketPacking$' -count=1
go test ./internal/destination -run '^$' -fuzz='^FuzzPacketPacking$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/wire/netflow5 -run '^FuzzNetFlow5Writer$' -count=1
go test ./internal/wire/netflow5 -run '^$' -fuzz='^FuzzNetFlow5Writer$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/wire/netflow9 -run '^FuzzNetFlow9Writer$' -count=1
go test ./internal/wire/netflow9 -run '^$' -fuzz='^FuzzNetFlow9Writer$' -fuzztime=10s -parallel=1 -timeout=5m
go test ./internal/wire/ipfix -run '^FuzzIPFIXWriter$' -count=1
go test ./internal/wire/ipfix -run '^$' -fuzz='^FuzzIPFIXWriter$' -fuzztime=10s -parallel=1 -timeout=5m
```

The IPFIX target uses 88 reviewed corpus seeds. Its finite grammar is a bounded
smoke campaign rather than exhaustive payload fuzzing; larger hard-ceiling
fixtures and independent decoder checks remain in the ordinary IPFIX tests.
