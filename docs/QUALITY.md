# Quality strategy

## Required layers

- Unit tests for schema extraction, normalization, mapping, packing, and state
- Golden wire fixtures generated from documented source values
- Independent protocol decoding of produced messages
- Exporter-to-receiver semantic round-trip tests where representable
- Template refresh, expiry, sequence, observation-domain, and restart tests
- UDP boundary and oversize-record behavior
- Invalid/missing/type-mismatched attribute tests
- Multi-destination isolation and failure tests
- `go test -race` for stateful and concurrent paths
- Fuzz targets for record extraction, mapping, templates, and packet encoding
- Leak and bounded-memory checks under sustained load
- Containerized integration against representative independent collectors or
  decoders selected by the compatibility evidence

## Evidence policy

A self-round-trip through code sharing the same assumptions is insufficient for
wire compatibility. At least one independent oracle is required for each
supported protocol family.

Tests must use deterministic clocks, observation domains, template IDs, sequence
numbers, and packet ordering wherever possible.

## Baseline commands

```bash
make check test
go test -race ./...
```

The [implementation verification strategy](design-docs/implementation-verification.md)
defines the oracle, golden, round-trip, race, fuzz, leak, load, malformed-input,
and Collector-integration requirements. The [MVP acceptance record](mvp-acceptance.md)
states which retained checks have passed and the limits of those results.
