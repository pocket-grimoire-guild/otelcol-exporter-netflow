# Contributing

This repository contains an alpha OpenTelemetry Collector logs exporter. Read
the [product specification](docs/product-specs/netflow-exporter.md),
[compatibility contract](docs/compatibility/alpha-upgrades.md), and relevant
[design documents](docs/design-docs/) before changing supported input, wire
profiles, or transport behavior.

Keep changes small, reviewable, and backed by evidence. A protocol or schema
change should include the directly coupled tests, fixtures, independent
decoding evidence where applicable, and documentation. Preserve explicit
schema/profile selection, record-boundary packetization, cancellation,
ownership, bounded metrics, and accurate partial results. Do not add
credentials, live flow records, host bootstrap material, sibling runtime
directories, or generated Collector binaries to a change.

## Local verification

Use Go `1.26.8` on Linux/amd64 for the supported source-built Collector path.
The baseline checks also require Python 3.11 or newer (for `tomllib`), Bash,
ShellCheck and standard Unix tools on `PATH`. From the repository root, run:

```bash
make check test
git diff --check
```

Run targeted race, fuzz, integration, fixture, or interoperability checks when
the changed behavior warrants them. Record external-tool or platform limits
honestly. For the source-built Collector path, set the ports, endpoints and
uptime origins from the [operator guide](docs/operator-guide.md#build-and-run-the-example)
before validating the configuration. Place the copied binary outside the
repository; OCB also generates an ignored `dist/ocb/` build directory:

```bash
./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
/tmp/otel-netflow-collector validate --config distribution/ocb/config.yaml
```

The [operator guide](docs/operator-guide.md) supplies environment values and
synthetic flow checks. The [consumer recipe](distribution/ocb/consumer/README.md)
is the version-pinned path for a published tag; it cannot retrieve the planned
alpha version until that tag exists. Generated files should be reproduced by
the existing scripts and not edited by hand.

## Changes and reviews

Use imperative commit subjects and explain why a change is needed. Keep
harness, protocol, release, and unrelated cleanup changes separate. Use
repository-relative documentation links and run the repository documentation
check before requesting review.

Review the diff for accidental endpoints, credentials, live flow data,
absolute host paths, generated outputs, and unsupported claims. Use the
[security policy](SECURITY.md) for reporting suspected vulnerabilities; do not
put sensitive values in an issue or pull request.
