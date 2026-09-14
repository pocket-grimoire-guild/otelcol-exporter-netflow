# ADR 0006: Require an explicit path-MTU budget above the conservative default

- Status: accepted
- Date: 2026-09-03
- Owners: project

## Context

The exporter sends one whole NetFlow/IPFIX message in one UDP datagram. The
accepted component design uses a 464-byte default UDP payload so an IPv6 base
header (40 bytes), UDP header (8 bytes), and payload total 512 bytes. It also
allowed the UDP payload to be configured up to 65,507 bytes without connecting
that larger value to a path MTU.

That larger-value rule is incomplete for IPFIX. [RFC 7011
§10.3.3](https://www.rfc-editor.org/rfc/rfc7011.html#section-10.3.3) requires an
IPFIX Exporting Process to configure its maximum message size so the resulting
packet does not exceed the path MTU; when the path MTU is unknown, it recommends
a conservative 512-octet maximum packet. A UDP length fit alone does not prove
that requirement and could invite IP fragmentation or loss.

## Decision

Keep `max_datagram_size` as UDP payload bytes, default 464 and absolute range
128..65,507. Add optional `path_mtu`, a trusted operator assertion that the
given integer is a lower bound for every network path to this configured
destination. It is configuration, not runtime discovery, and accepts
512..65,535.

Validation is checked before socket creation:

* with `path_mtu` absent, `max_datagram_size` may not exceed 464;
* a literal IPv4 endpoint reserves 28 bytes: a 20-byte base IPv4 header plus
  the 8-byte UDP header;
* a literal IPv6 endpoint reserves 48 bytes: a 40-byte base IPv6 header plus
  UDP;
* a hostname reserves 48 bytes even if its current answer is IPv4, because a
  later accepted DNS generation may select IPv6;
* widened arithmetic must prove
  `max_datagram_size + reserved_outer_bytes <= path_mtu` and every compiled
  template and minimum record must independently fit the resulting payload.

The rule applies uniformly to NetFlow v5, v9, and IPFIX. The exporter never
silently reduces a configured payload, learns a larger value from the socket,
or publishes a DNS candidate whose family was not covered by the prevalidated
budget. It does not add IPv4 options or IPv6 extension headers and does not
implement application fragmentation, IPFIX-over-TCP/SCTP, dynamic PMTU
discovery, IPv6 jumbograms, or UDP segmentation offload as part of the initial
profile. A local PMTU/`EMSGSIZE` write error follows the ordinary ambiguous
write-failure contract; it does not mutate the configured budget or retry.

## Consequences

The conservative default remains deterministic and safe for either address
family without a path assertion. Larger datagrams are an explicit operator
choice tied to a finite lower bound rather than an unchecked UDP maximum. A
literal IPv4 destination with `path_mtu: 65535` may use the absolute 65,507-byte
payload; an IPv6 literal or hostname at that MTU is capped at 65,487 bytes.

Configuration tests cover absent PMTU with payload 464/465; a configured
512-byte PMTU with IPv4 payload 484/485 and IPv6/hostname payload 464/465;
minimum/maximum/out-of-range PMTU; checked addition overflow; and a hostname
changing from IPv4 to IPv6. Packing tests still cover the independent UDP and
protocol length ceilings. Live interoperability evidence checks actual outer
IP/UDP lengths and IPFIX UDP checksums.

The assertion cannot prove the operator's network claim. Configuration and
documentation must call that limitation explicit; a deployment with an
incorrect assertion may lose datagrams. Supporting discovery or adapting to
path changes requires a later ADR and new failure/state tests.

## Alternatives considered

* **Allow every UDP-valid payload without PMTU input:** rejected because it
  cannot satisfy RFC 7011's IPFIX-over-UDP requirement.
* **Always cap at 464 bytes:** safe but unnecessarily prevents a knowledgeable
  operator from using a verified larger path budget.
* **Discover and adapt PMTU automatically:** deferred. It adds OS-specific
  socket behavior, mutable packing state, DNS/path races, and retry semantics
  that are not supported by the initial deterministic transport design.
* **Use the current DNS answer's family:** rejected because a later family
  change could invalidate a previously accepted payload without a config
  change.

## Evidence

* [RFC 7011 §10.3.3](https://www.rfc-editor.org/rfc/rfc7011.html#section-10.3.3)
* [Collector component design](../design-docs/collector-component.md)
* [Protocol state and transport design](../design-docs/protocol-state-transport.md)
* [ADR 0004: destination-local UDP state](0004-destination-local-udp-state.md)
