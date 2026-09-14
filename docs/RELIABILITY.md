# Reliability requirements

The exporter sits on a telemetry path and normally sends connectionless flow
protocols. Its behavior under pressure must be intentional.

The accepted design specifies:

- startup and shutdown ordering;
- queue ownership and bounded capacity;
- how partial batches and invalid records affect Collector consumer errors;
- per-destination isolation;
- UDP write errors and retry policy;
- template transmission before dependent data sets;
- periodic template refresh by time and/or packet count;
- sequence-number semantics for each protocol;
- observation domain/source ID configuration;
- restart behavior and whether protocol state is persistent;
- MTU/message-size limits and treatment of a single unencodable record;
- dropped/lossy/invalid record metrics with bounded cardinality;
- deterministic behavior when clocks move or destination DNS changes.

No retry loop may be unbounded. No malformed record may panic the Collector.

Large valid requests reach record-boundary packetization. Aggregate record/byte
budgets and unused metadata are not protocol validity rules. Invalid records
remain local failures; transient subsets exclude confirmed and invalid records.
The normative lifecycle and admission contract is
[`collector-component.md`](design-docs/collector-component.md); destination
sequence/template/DNS/UDP/PMTU behavior is
[`protocol-state-transport.md`](design-docs/protocol-state-transport.md). The
independent failure, race, leak, and load checks are in the
[`implementation verification strategy`](design-docs/implementation-verification.md).
The [local MVP acceptance matrix](mvp-acceptance.md) records the passing checks
and demonstrated limits. The [operator guide](operator-guide.md) explains
mixed-result handling, upstream replay risks, template refresh and exact
uptime/time-range restrictions, including explicit-origin exhaustion.
