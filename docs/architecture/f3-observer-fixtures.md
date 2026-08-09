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
it does not parse full packets or captures.
