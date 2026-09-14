# ADR 0001: Develop as an external Collector component first

- Status: accepted
- Date: 2026-09-01
- Owners: project

## Context

The exporter is new and needs rapid design iteration, protocol experiments, and
external validation. OpenTelemetry Collector contribution guidance expects new
components to mature outside the Contrib repository before donation.

## Decision

Develop the exporter in the standalone module
`github.com/pocket-grimoire-guild/otelcol-exporter-netflow`. Build a pinned custom Collector
distribution for integration testing. Track receiver patches separately and
submit them upstream when they are independently useful.

## Consequences

The project owns release automation and dependency pinning initially. It can
iterate without Contrib release cadence, but must deliberately stay compatible
with current Collector APIs and document the path toward a future donation.
