# NetFlow Ecosystem Explorer readiness

This optional check validates the Collector metadata needed for a readable
Ecosystem Explorer title and summary. It is a local metadata and generation
check. It does not submit the component, establish an Explorer listing, or
claim upstream approval; Explorer listing is not required to use or publish
this repository.

## Metadata

The [Explorer metadata guide][metadata-guide] identifies top-level
`display_name` and `description` as the presentation fields. The pinned
mdatagen schema accepts both fields as strings. The resulting values in
[`metadata.yaml`](../metadata.yaml) are:

| Field | Value and role |
| --- | --- |
| `type` | `netflow`, configuration identity |
| `display_name` | `NetFlow Exporter`, presentation title |
| `description` | Exports receiver-compatible flow records from OpenTelemetry logs as NetFlow v5, NetFlow v9, or IPFIX over UDP. |
| `status.class` | `exporter` |
| `status.stability` | `alpha: [logs]` |
| `config` | Existing configuration schema input |
| `attributes` / `telemetry.metrics` | Existing self-telemetry definitions |

These fields are presentation metadata; they do not alter the `netflow`
component identity, configuration schema, or generated telemetry.

## Local validation

From the checkout root with Python 3, PyYAML, Go `1.26.8`, Bash, and standard
Unix tools available:

```sh
python3 scripts/check-explorer-metadata.py
scripts/check-generated.sh --go 1.26.8 \
  --mdatagen go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0
```

The [focused check](../scripts/check-explorer-metadata.py) requires nonempty
string presentation fields and preserves `netflow` / `exporter` / alpha logs
identity. The generated check compares `config.schema.json`, generated
component/package tests, `documentation.md`, and metadata outputs. A
`--shape-only PATH` check validates an isolated metadata fixture and skips
generation. Missing tools, wrong pins, or generated drift fail visibly.

This check reuses the existing generator and adds no application or workflow
service. Run `make check test` and the [conformance harness](netflow-conformance-harness.md)
separately when those checks are relevant.

If an operator later wants an Explorer listing, current Explorer policy and
source requirements must be checked at that time. This document provides the
metadata and local validation needed for that decision; it does not make a
listing prerequisite or claim discoverability.

[metadata-guide]: https://github.com/open-telemetry/opentelemetry-ecosystem-explorer/blob/e17da7f5be9121990ff33cb66ea4e3a60d04b816/docs/upstream-metadata.md
