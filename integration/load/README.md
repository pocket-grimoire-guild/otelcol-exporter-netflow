# Functional load regressions

Run the tagged exporter and fixture tests with:

```sh
scripts/test-load.sh
# The same cases with race detection:
scripts/test-load.sh -race
```

The tests in [load_test.go](../../load_test.go) exercise the production Collector
adapter, helper, normalizer, mapper, destination packer and failed-subset copy
through an injected UDP connection. They use the pinned Go/Collector APIs and
ordinary test assertions. They do not measure network throughput or process
memory, and impose no absolute packing-latency thresholds.

| Test | Purpose |
| --- | --- |
| `TestLoadDefault` | Reuse a read-only 100-record batch for 1,000 calls; require 100,000 attempted and confirmed datagrams and contiguous IPFIX sequences. |
| `TestLoadIgnoredMetadata` | Export seven valid records with ignored resource, scope and record metadata; verify helper entry, packet counts and sequence progression. |
| `TestLoadVariableOctetPackets` | Export 33 read-only records with 32 varied enterprise octet fields each. Records naturally require separate datagrams. Test-owned offsets check message/Set lengths, template ID, three-octet variable-length prefixes, every custom byte, alignment, zero padding and aggregate emitted bytes. |
| `TestLoadVariableOctetSubsetOwnership` | Force the first handoff ambiguous; require sequence zero and all 33 records returned in source order, preserving selected values and every custom byte. Mutations verify source/subset byte independence in both directions. |

These smaller fixtures have no exact memory-occupancy target. The default
[large-request test](../../internal/destination/large_request_test.go) separately
protects 65,537 valid records, more than 64 MiB of ignored metadata, complete
datagrams and v5/v9/IPFIX sequence semantics. The default
[large-subset tests](../../large_subset_test.go) protect the confirmed prefix,
boundary-crossing ambiguous packet, valid unsent suffix, cancellation and exact
source order. [Subset ownership tests](../../subset_copy_test.go) retain
duplicate attributes, EntityRefs, nested/body bytes, depth beyond the retired
cap and pdata proto pooling. Small deterministic wire and borrowed-buffer
allocation checks also remain in the default suite.

Pinned pdata hierarchy `CopyTo` preserves full envelope semantics but aliases
byte backing; production detaches each copied byte leaf. Its recursive AnyValue
copy still has an extreme-depth stack limitation. Neither unlimited-depth copy
safety nor fixed whole-process heap/RSS qualification is claimed.

## Fixture and resource boundary

The [canonical manifest](../testdata/canonical/fixtures.json) remains the
fixture authority. The checkers validate generated fixture consistency:

```sh
python3 scripts/check-canonical-fixtures.py integration/testdata/canonical/fixtures.json
python3 scripts/check-generated-fixtures.py integration/testdata/canonical/fixtures.json
```

The load tests do not impose an aggregate request ceiling, exact memory target,
RSS gate, or packing-latency threshold. Supported records reach packetization
under actual field, message, and path limits. Resource qualification for a
particular deployment needs its own scenario and purpose.
