# OpenTelemetry NetFlow/IPFIX Exporter

`github.com/pocket-grimoire-guild/otelcol-exporter-netflow` is an alpha
OpenTelemetry Collector logs exporter. Register
`netflowexporter.NewFactory()` in a custom Collector to convert parsed flow
records from the Contrib NetFlow receiver into NetFlow v5, NetFlow v9, or IPFIX
messages over UDP. The root module is a library; it is not a standalone
executable or part of a stock Contrib distribution.

The component identity is `netflow`, the Go package is `netflowexporter`, and
the input schema is the versioned
`contrib-netflowreceiver-v0.160.0` profile. The source is licensed under
[Apache-2.0](LICENSE). The [v0.2.0 source/module release](docs/release.md)
retains pre-1.0 alpha maturity. Its consumer recipe selects `v0.2.0`; public
installation requires that immutable tag. The isolated staged check is local
packaging evidence, not proof of public retrieval. No maintained binary or
container image is offered.

## Supported build

The supported source-built path is Linux/amd64 with Go `1.26.8`, Collector
Core stable modules `v1.66.0`, Collector beta modules `v0.160.0`, OCB
`v0.160.0`, and Contrib `netflowreceiver v0.160.0`.

For a checkout build, use the [OCB development guide](distribution/ocb/README.md).
Before validating the example, set the ports, endpoints and uptime origins in
the [operator guide](docs/operator-guide.md#build-and-run-the-example):

```bash
./distribution/ocb/build.sh --go 1.26.8 --out /tmp/otel-netflow-collector
/tmp/otel-netflow-collector validate --config distribution/ocb/config.yaml
```

Place the linked manifest and configuration files from the
[v0.2.0 consumer recipe](distribution/ocb/consumer/README.md) in a separate
consumer directory. It selects exporter `v0.2.0` with strict version checking:

```bash
go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
  --config manifest.yaml --skip-strict-versioning=false
./dist/ocb/otel-netflow-collector --version
./dist/ocb/otel-netflow-collector validate --config config.yaml
./dist/ocb/otel-netflow-collector --config config.yaml
```

Use all environment settings documented by the recipe. It covers compatible
parsed input, synthetic loopback checks, outcome metrics, fresh template IDs,
explicit mapping and loss acknowledgement, and the measured-time contract.
The default template refresh interval is ten minutes; an optional 30-second
refresh can be configured.

## Configuration and limits

Read the [operator guide](docs/operator-guide.md) for the complete
configuration, endpoint and path limits, telemetry, and troubleshooting. The
[compatibility summary](docs/compatibility/alpha-upgrades.md) covers the
41-key schema, profile-specific gates, exact token selection, and upgrade
rules. [Compatibility tables](docs/compatibility/) describe receiver
attributes, protocol mapping, and built-in profiles.

UDP success means local kernel handoff, not remote delivery. The exporter has
no queue, automatic retry, persistence, encryption, peer authentication, raw
replay, or sFlow output. NetFlow v5/v9 uptime conversion has an approximately
49.71-day 32-bit millisecond lifetime and does not roll over. Measured-time
provenance is deployment-owned. Sampling normalization, proprietary consumer
ingestion/storage, and appliance qualification are outside the verified
boundary. Large valid requests are packetized at record boundaries; work and
partial-failure copies scale with input, and the pinned pdata recursive copy
retains an extreme-depth stack limitation.

The [MVP acceptance record](docs/mvp-acceptance.md) and
[implementation verification strategy](docs/design-docs/implementation-verification.md)
describe demonstrated behavior and remaining limits. They do not establish a
production SLA or qualify arbitrary platforms, Collector versions, or
downstream appliances.

The operator and versioned-consumer examples enable the local pull reader with
`NETFLOW_METRICS_PORT`; keep that numeric TCP port on loopback and distinct for
each Collector process. The reader reports local outcome and lifetime
observations, while a successful UDP write still proves only local kernel
handoff.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](ARCHITECTURE.md) and [design documents](docs/design-docs/)
- [Operator guide](docs/operator-guide.md)
- [Contributing](CONTRIBUTING.md)
- [Release notes and publication checklist](docs/release.md)
- [Security policy](SECURITY.md)

For a non-sensitive issue, include exact versions, a sanitized configuration,
relevant fixed-reason counters, and a minimal synthetic reproducer. Do not
post live flows, credentials, or unredacted production logs. `SECURITY.md`
does not currently configure a confidential reporting route; maintainers must
choose one before claiming that capability.
