# F3 observer fixtures

`wireproof_runtime.observers` is a pure, fixture-only normalization boundary. It
does not create an EvidenceBundle, report `REAL`, invoke GoBGP or Docker, parse
pcaps, or claim packet forwarding/conformance. A `PASS` therefore means only
that supplied fixture values passed the stated parser or comparison rule.

The frozen JSON v1 GoBGP envelope has exactly `source` and `routes` keys. A
route has exactly `family`, `type`, `rd`, `route_targets`, `next_hops`,
`withdraw`, and `best`. `family` is `l2vpn_evpn`, type is 1 through 255, route
targets and next hops have no duplicates, and source provenance is excluded from
route-snapshot equality. Empty, malformed, missing-source, duplicate-source, or
mismatched fixture inputs produce `UNKNOWN`; there is no quorum rule.

Canonical RD is `<decimal-asn-or-canonical-ipv4>:<decimal>` and canonical RT is
`target:<decimal-asn-or-canonical-ipv4>:<decimal>`. Decimal components have no
leading zero (except `0`); IPv4 addresses use canonical dotted decimal. Next
hops are IP addresses. Withdraws have no next hops; advertisements have one or
more. An expectation may leave `best` unset, which deliberately does not impose
a best-path equality predicate.

VXLAN parsing accepts only an eight-byte UDP payload header: I flag set, all
reserved bytes zero, VNI 0..16777215, and final reserved byte zero. It records a
SHA-256 digest of those raw eight bytes plus immutable `CaptureRef` provenance;
it does not parse full captures.

`parse_captured_vxlan_ethernet_frame` additionally accepts one supplied raw
Ethernet-II frame as structural fixture evidence. It permits zero, one, or two
outer `0x8100`/`0x88A8` VLAN tags; IPv4 with a non-fragmented UDP payload; or
IPv6 with UDP directly in its base header. Its UDP destination must be 4789 and
its VXLAN header follows the same eight-byte rule above. On success it records
outer MACs, VLAN wire values, IP endpoints, UDP ports/checksum field, VNI, and
the raw inner Ethernet frame with SHA-256 identities. It does not validate any
checksum, parse pcaps, reassemble fragments, support IPv6 extensions, invoke a
runtime, or claim forwarding/conformance. `PASS` means only structural parsing.
