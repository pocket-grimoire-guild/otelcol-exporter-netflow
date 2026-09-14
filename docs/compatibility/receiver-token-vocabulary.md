# Receiver network token vocabulary

Status: versioned compatibility artifact for the `contrib-netflowreceiver-v0.160.0` schema profile (2026-09-03).

This document is the exact token vocabulary emitted for the receiver's
`network.transport` and `network.type` attributes. It is normative for
exporter configuration that consumes this profile: do not infer names, numbers,
or protocol families that are not stated here.

## Pinned profile and sources

The profile is **`contrib-netflowreceiver-v0.160.0`**, defined by Collector
Contrib `v0.160.0` at immutable commit
[`982f20b8a8e8a2569fab3e27cf8b008e8a5080c1`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver).
Its receiver module requires goflow2/v2 `v2.2.6` ([pinned
`go.mod`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/go.mod#L1-L8));
the resolved goflow2 source is immutable commit
[`c9824f41bcad11d4490a668ed5270b03056d8217`](https://github.com/netsampler/goflow2/tree/c9824f41bcad11d4490a668ed5270b03056d8217).

The receiver's [`etypeNames map`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L21-L34),
[`transportProtocolNames map`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L36-L184),
and lookup functions
([`getEtypeName`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L195-L200),
[`getTransportName`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L202-L207))
are the source of truth. Parsed records write both attributes through these
lookups ([parser assignment](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/982f20b8a8e8a2569fab3e27cf8b008e8a5080c1/receiver/netflowreceiver/parser.go#L244-L246)).

## Exporter configuration boundary

* `protocol_identifiers` may select only an exact token↔uint8 pair from the
  `network.transport` table below. Matching is exact: preserve the listed
  lower-case spelling and number, with no aliases, case folding, name/number
  inference, or numeric recovery from `unknown`.
* `unknown` has no protocol-number pair and is forbidden in
  `protocol_identifiers`. An input record carrying `network.transport =
  "unknown"` must be rejected as unsupported rather than assigned a guessed
  number.
* `network_type_versions` is a separate IP-version map and accepts only the
  exact pairs `ipv4:4` and `ipv6:6`. It does not reconstruct an EtherType
  from a `network.type` token. Any other token (including `arp`, `snmp`,
  or `unknown`) is rejected by this option; an `ethernetType` value requires
  separately retained numeric EtherType provenance.

## `network.transport`: token↔uint8 protocol number

The table is copied exactly from `transportProtocolNames`. Every uint8 value
from 0 through 145 appears once, and every listed token is unique. The
receiver's numeric protocol 0 is **`hopopt`**, not `unknown`.

| uint8 protocol number | parser token |
| ---: | --- |
| 0 | `hopopt` |
| 1 | `icmp` |
| 2 | `igmp` |
| 3 | `ggp` |
| 4 | `ipv4` |
| 5 | `st` |
| 6 | `tcp` |
| 7 | `cbt` |
| 8 | `egp` |
| 9 | `igp` |
| 10 | `bbn-rcc-mon` |
| 11 | `nvp-ii` |
| 12 | `pup` |
| 13 | `argus` |
| 14 | `emcon` |
| 15 | `xnet` |
| 16 | `chaos` |
| 17 | `udp` |
| 18 | `mux` |
| 19 | `dcn-meas` |
| 20 | `hmp` |
| 21 | `prm` |
| 22 | `xns-idp` |
| 23 | `trunk-1` |
| 24 | `trunk-2` |
| 25 | `leaf-1` |
| 26 | `leaf-2` |
| 27 | `rdp` |
| 28 | `irtp` |
| 29 | `iso-tp4` |
| 30 | `netblt` |
| 31 | `mfe-nsp` |
| 32 | `merit-inp` |
| 33 | `dccp` |
| 34 | `3pc` |
| 35 | `idpr` |
| 36 | `xtp` |
| 37 | `ddp` |
| 38 | `idpr-cmtp` |
| 39 | `tp++` |
| 40 | `il` |
| 41 | `ipv6` |
| 42 | `sdrp` |
| 43 | `ipv6-route` |
| 44 | `ipv6-frag` |
| 45 | `idrp` |
| 46 | `rsvp` |
| 47 | `gre` |
| 48 | `dsr` |
| 49 | `bna` |
| 50 | `esp` |
| 51 | `ah` |
| 52 | `i-nlsp` |
| 53 | `swipe` |
| 54 | `narp` |
| 55 | `min-ipv4` |
| 56 | `tlsp` |
| 57 | `skip` |
| 58 | `ipv6-icmp` |
| 59 | `ipv6-nonxt` |
| 60 | `ipv6-opts` |
| 61 | `any-host-internal-protocol` |
| 62 | `cftp` |
| 63 | `any-local-network` |
| 64 | `sat-expak` |
| 65 | `kryptolan` |
| 66 | `rvd` |
| 67 | `ippc` |
| 68 | `any-distributed-file-system` |
| 69 | `sat-mon` |
| 70 | `visa` |
| 71 | `ipcv` |
| 72 | `cpnx` |
| 73 | `cphb` |
| 74 | `wsn` |
| 75 | `pvp` |
| 76 | `br-sat-mon` |
| 77 | `sun-nd` |
| 78 | `wb-mon` |
| 79 | `wb-expak` |
| 80 | `iso-ip` |
| 81 | `vmtp` |
| 82 | `secure-vmtp` |
| 83 | `vines` |
| 84 | `iptm` |
| 85 | `nsfnet-igp` |
| 86 | `dgp` |
| 87 | `tcf` |
| 88 | `eigrp` |
| 89 | `ospfigp` |
| 90 | `sprite-rpc` |
| 91 | `larp` |
| 92 | `mtp` |
| 93 | `ax.25` |
| 94 | `ipip` |
| 95 | `micp` |
| 96 | `scc-sp` |
| 97 | `etherip` |
| 98 | `encap` |
| 99 | `any-private-encryption-scheme` |
| 100 | `gmtp` |
| 101 | `ifmp` |
| 102 | `pnni` |
| 103 | `pim` |
| 104 | `aris` |
| 105 | `scps` |
| 106 | `qnx` |
| 107 | `a/n` |
| 108 | `ipcomp` |
| 109 | `snp` |
| 110 | `compaq-peer` |
| 111 | `ipx-in-ip` |
| 112 | `vrrp` |
| 113 | `pgm` |
| 114 | `any-0-hop-protocol` |
| 115 | `l2tp` |
| 116 | `ddx` |
| 117 | `iatp` |
| 118 | `stp` |
| 119 | `srp` |
| 120 | `uti` |
| 121 | `smp` |
| 122 | `sm` |
| 123 | `ptp` |
| 124 | `isis over ipv4` |
| 125 | `fire` |
| 126 | `crtp` |
| 127 | `crudp` |
| 128 | `sscopmce` |
| 129 | `iplt` |
| 130 | `sps` |
| 131 | `pipe` |
| 132 | `sctp` |
| 133 | `fc` |
| 134 | `rsvp-e2e-ignore` |
| 135 | `mobility header` |
| 136 | `udplite` |
| 137 | `mpls-in-ip` |
| 138 | `manet` |
| 139 | `hip` |
| 140 | `shim6` |
| 141 | `wesp` |
| 142 | `rohc` |
| 143 | `ethernet` |
| 144 | `aggfrag` |
| 145 | `nsh` |

## `network.type`: token↔EtherType

The table is copied exactly from `etypeNames`. EtherType values are shown as
the hexadecimal uint32 literals used by the pinned parser; each token and
number appears once. The map intentionally contains 11 entries.

| parser token | EtherType (hexadecimal uint32 literal) |
| --- | ---: |
| `arp` | `0x806` |
| `ipv4` | `0x800` |
| `snmp` | `0x814c` |
| `ipv6` | `0x86dd` |
| `mpls` | `0x8847` |
| `eapol` | `0x888e` |
| `lldp` | `0x88cc` |
| `macsec` | `0x88e5` |
| `mvrp` | `0x88f5` |
| `ptp` | `0x88f7` |
| `6lowpan` | `0xa0ed` |

## Unknown lookup behavior

* `getTransportName(proto)` returns the listed token for protocol numbers
  0..145. Every other uint32 value returns the literal `unknown`; the
  receiver still writes `network.transport` with that token.
* `getEtypeName(etype)` returns the listed token for the 11 EtherTypes above.
  Zero and every other uint32 value return the literal `unknown`; the
  receiver still writes `network.type` with that token.
* `unknown` is not a reverse mapping. It does not preserve the original
  protocol number or EtherType, so an exporter cannot recover one from the
  token. Unknown values are therefore unsupported by the exact-pair
  configuration rules above.
