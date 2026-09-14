# Configuration schema

The exporter publishes the JSON Schema generated from `metadata.yaml` at
[`config.schema.json`](../config.schema.json). It is a Draft 2020-12 schema
for one exporter configuration object (the value under `exporters.netflow`
or a named instance), rather than an entire Collector file. It covers the
public `Config` surface: endpoint and protocol selection, the
protocol-specific identity objects, profile or explicit mapping fields,
template controls, DNS controls, packet limits, and the intentionally disabled
queue and retry controls. The schema includes the supported enum values,
defaults, scalar bounds, duration syntax, and array/object member constraints.

The schema is generated with the pinned command below. The repository checker
builds that exact mdatagen version in a temporary module and runs the existing
`go generate .` directive through an isolated staging directory:

```sh
scripts/check-generated.sh --go 1.26.8 \
  --mdatagen go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0
```

The checker uses the Go module cache selected by `go env GOMODCACHE`; set
`GOMODCACHE` explicitly when a hermetic cache is required.

mdatagen v0.160.0 writes `config.schema.json` and, when a `config` section is
present, also writes `generated_config.go` and `generated_config_test.go`.
This component keeps its handwritten `Config` and `Config.Validate` contract,
so the checker stages those two generated Go files and retains only the
schema plus the existing generated metadata, lifecycle, documentation, and
goleak outputs. No generated Go config is used by the production package.

The same mdatagen release injects configuration tables into a `README.md` only
when that file contains its generated-section markers. This repository keeps
the root README hand-written and has no such markers, so the isolated checker
does not stage or modify it; this page is the maintained configuration-schema
reference.

The focused check uses the pinned `github.com/google/jsonschema-go` v0.4.3
validator in the isolated `integration/configschema` module. It validates
each of [`valid-v5.yaml`](../integration/configschema/testdata/config-schema/valid-v5.yaml),
[`valid-v9.yaml`](../integration/configschema/testdata/config-schema/valid-v9.yaml),
and [`valid-ipfix.yaml`](../integration/configschema/testdata/config-schema/valid-ipfix.yaml)
against the schema and then decodes each through Collector `confmap` and the
real `Config.Validate` method. The same check covers structural negatives and
separate parser-only semantic cases. Run it with:

```sh
scripts/check-config-schema.sh
```

The schema describes constraints that are local to a value. The handwritten
parser remains authoritative for relationships between values. mdatagen's
v0.160.0 metadata model does not provide `oneOf`, `if`/`then`, `not`, or a
nullable type union, and its generated object schemas do not emit
`additionalProperties: false`. Consequently the following cases are checked
by the parser and documented as parser-only: protocol-specific identity and
uptime-origin requirements; profile-versus-fields exclusivity; protocol-
specific v9 and IPFIX refresh controls; the relationship between
`dns.stale_after` and `dns.refresh_interval`; and the v9/IPFIX branches of the
custom field grammar. Unknown keys can pass the schema but are rejected by
the strict `Config.Unmarshal` method.

Each `type: duration` node supplies an explicit pattern matching positive Go duration
syntax, including an optional leading `+`, leading or trailing decimal points,
and `us`, `µs`, or Greek `μs` microseconds. Runtime minimum and maximum
durations, including timeout ordering against shutdown drain, are enforced by
`Config.Validate`. Pointer fields are optional in the schema and `x-pointer`
does not add JSON nullability. The real decoder accepts an explicit null only
for `path_mtu` and `ipfix.template_refresh_data_packets`, where null clears the
pointer; the generated schema cannot express that exception, so these are
covered as a known parser/schema boundary. Scalar types remain strict: numeric
strings, booleans represented as strings, and other coercions are rejected
before Collector's weak conversion path can truncate them.

The generated schema's printed `uptime_origin` maximum is
`9223372036854776000`, rounded from the metadata maximum
`9223372036854775807`. With the pinned `jsonschema-go` v0.4.3 validator, the
exact `MaxInt64` value is accepted by both schema and parser checks, while
`MaxInt64+1` is accepted by the schema and rejected by the parser's
configuration validation. A value above the printed maximum, such as
`9223372036854776001`, is rejected at both boundaries. These are observed
results for this validator and configuration parser; they do not establish
that every integer in the printed interval is accepted or that other
validators behave the same way.

For `max_datagram_size`, the valid integer control `464` passes both checks.
The JSON Schema integer rule accepts the integral floating value `464.0`, but
the parser rejects it because its strict input check requires an integer Go
source type. The fractional value `464.5` is rejected by both checks. The
schema/parser test loads representative values through Collector's
`confmaptest.LoadConf` path and checks their concrete types and exact values
before validation, including `uint64(9223372036854775808)` and
`float64(464)`. Configuration acceptance at these boundaries does not claim
that a future epoch can be exported correctly with today's clock.
