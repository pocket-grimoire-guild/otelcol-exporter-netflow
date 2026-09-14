# Security policy

This policy covers the alpha source/module for
`github.com/pocket-grimoire-guild/otelcol-exporter-netflow`. It is a support
contract, not a security certification. The component accepts parsed flow
records, emits NetFlow v5/v9 or IPFIX over UDP, and is intended to run inside a
pinned custom Collector.

## Reporting a problem

For a non-sensitive defect, open a public issue with the exact module version
or commit, Go and Collector pins, operating system, selected profile, a
sanitized configuration, relevant redacted outcome counters, and a minimal
synthetic reproducer. Explain whether the observed failure is local validation,
UDP handoff, or downstream observation.

Remove credentials, tokens, private keys, live flow records, customer data,
unredacted addresses, and full production logs. A small synthetic reproducer
is more useful than a production packet capture.

This repository does not currently configure a confidential vulnerability
reporting route. Do not put sensitive details in a public issue; maintainers
must select and publish an appropriate private route before claiming that
capability.

## Supported security boundary

Treat every input record and configured destination as untrusted data at the
Collector boundary. The pinned receiver normally supplies a closed flow shape,
but processors or other producers can admit attacker-controlled pdata. Failed
subset returns use the pinned pdata recursive copy operation, which retains an
extreme-nesting stack limitation. The exporter does not claim unlimited-depth
processing or fixed whole-process memory.

The exporter enforces protocol field, message, path, packet, template, and
variable-field limits, one active request, bounded packet buffers, and bounded
telemetry labels. Supported large requests are packetized at record boundaries;
aggregate metadata size or depth is not used as an arbitrary record-validity
rule. Invalid records can be rejected while valid siblings continue. Work and
failed-subset copies scale with the input.

UDP is an unauthenticated datagram handoff. A successful local write does not
prove remote receipt; loss, duplication, and reordering are possible. The
exporter provides no encryption, peer authentication, acknowledgement,
persistent queue, automatic retry, or replay protection. Use a trusted network,
firewall, or externally managed secure tunnel when confidentiality or peer
identity is required. Retrying an ambiguous subset can duplicate a datagram.

Routine diagnostics are redacted and bounded. Do not enable or add logging that
prints full flow payloads, credentials, raw errors, or sensitive address data.
Formatted receiver `send_raw` bodies are unsupported input and are not a raw
replay mechanism. See the [security model](docs/SECURITY.md),
[operator guide](docs/operator-guide.md), and
[verification strategy](docs/design-docs/implementation-verification.md) for
the broader boundaries and local checks.
