"""Pure, fixture-only parsers for independent EVPN and VXLAN observations.

This module deliberately has no network client, container integration, pcap reader,
or EvidenceBundle dependency.  A ``PASS`` comparison means only that supplied
fixtures normalized to the same values; it is never a runtime/conformance claim.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum


class ObservationResult(StrEnum):
    PASS = "PASS"
    UNKNOWN = "UNKNOWN"


class ObservationReason(StrEnum):
    MALFORMED_INPUT = "MALFORMED_INPUT"
    MISSING_SOURCE = "MISSING_SOURCE"
    DUPLICATE_SOURCE = "DUPLICATE_SOURCE"
    DUPLICATE_ROUTE = "DUPLICATE_ROUTE"
    IMPLEMENTATION_DIVERGENCE = "IMPLEMENTATION_DIVERGENCE"


_DECIMAL = r"(?:0|[1-9][0-9]*)"
_RD = re.compile(rf"(?:{_DECIMAL}|(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){{3}}):{_DECIMAL}\Z")
_RT = re.compile(
    rf"target:(?:{_DECIMAL}|(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){{3}}):{_DECIMAL}\Z"
)
_ROUTE_KEYS = frozenset({"family", "type", "rd", "route_targets", "next_hops", "withdraw", "best"})


def _canonical_rd(value: object) -> bool:
    if not isinstance(value, str) or not _RD.fullmatch(value):
        return False
    administrator, assigned = value.rsplit(":", maxsplit=1)
    try:
        if "." in administrator:
            ipaddress.IPv4Address(administrator)
        else:
            int(administrator)
        int(assigned)
    except ValueError:
        return False
    return True


def _canonical_rt(value: object) -> bool:
    if not isinstance(value, str) or not _RT.fullmatch(value):
        return False
    _, administrator, assigned = value.split(":")
    try:
        if "." in administrator:
            ipaddress.IPv4Address(administrator)
        else:
            int(administrator)
        int(assigned)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, order=True)
class EvpnRoute:
    """One normalized GoBGP EVPN route, including its fixture-only best marker."""

    family: str
    type: int
    rd: str
    route_targets: tuple[str, ...]
    next_hops: tuple[str, ...]
    withdraw: bool
    best: bool

    def __post_init__(self) -> None:
        if self.family != "l2vpn_evpn" or type(self.type) is not int or not 1 <= self.type <= 255:
            raise ValueError("route must be l2vpn_evpn with type 1..255")
        if not _canonical_rd(self.rd) or not all(
            _canonical_rt(item) for item in self.route_targets
        ):
            raise ValueError("RD and RT values must use canonical syntax")
        if len(set(self.route_targets)) != len(self.route_targets):
            raise ValueError("duplicate route target")
        if len(set(self.next_hops)) != len(self.next_hops):
            raise ValueError("duplicate next hop")
        try:
            for next_hop in self.next_hops:
                if not isinstance(next_hop, str):
                    raise ValueError
                ipaddress.ip_address(next_hop)
        except ValueError as error:
            raise ValueError("next hops must be IP addresses") from error
        if type(self.withdraw) is not bool or type(self.best) is not bool:
            raise ValueError("withdraw and best must be booleans")
        if self.withdraw != (not self.next_hops):
            raise ValueError("withdraw routes have no hops; advertisements have at least one")


@dataclass(frozen=True)
class EvpnRouteExpectation:
    """A route expectation. ``best=None`` intentionally does not constrain best."""

    route: EvpnRoute
    best: bool | None = None

    def __post_init__(self) -> None:
        if self.best is not None and type(self.best) is not bool:
            raise ValueError("best expectation must be bool or None")

    def matches(self, route: EvpnRoute) -> bool:
        same_route = (
            self.route.family,
            self.route.type,
            self.route.rd,
            self.route.route_targets,
            self.route.next_hops,
            self.route.withdraw,
        ) == (
            route.family,
            route.type,
            route.rd,
            route.route_targets,
            route.next_hops,
            route.withdraw,
        )
        return same_route and (self.best is None or route.best is self.best)


@dataclass(frozen=True)
class GoBgpSnapshot:
    """A source-tagged, unordered, duplicate-free route fixture snapshot."""

    source: str = field(compare=False)
    routes: frozenset[EvpnRoute] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.source or not isinstance(self.source, str) or not self.routes:
            raise ValueError("snapshot requires a non-empty source and at least one route")


@dataclass(frozen=True)
class ObservationOutcome:
    result: ObservationResult
    reasons: tuple[ObservationReason, ...] = ()

    def __post_init__(self) -> None:
        if self.result is ObservationResult.PASS and self.reasons:
            raise ValueError("PASS has no reasons")
        if self.result is ObservationResult.UNKNOWN and not self.reasons:
            raise ValueError("UNKNOWN requires a reason")


@dataclass(frozen=True)
class GoBgpParseResult:
    outcome: ObservationOutcome
    snapshot: GoBgpSnapshot | None = None


def _unknown(reason: ObservationReason) -> GoBgpParseResult:
    return GoBgpParseResult(ObservationOutcome(ObservationResult.UNKNOWN, (reason,)))


def parse_gobgp_fixture(payload: str | bytes | bytearray) -> GoBgpParseResult:
    """Parse the frozen JSON-v1 ``{source,routes}`` observer envelope without raising."""
    try:
        document = json.loads(payload)
        if not isinstance(document, dict) or set(document) != {"source", "routes"}:
            return _unknown(ObservationReason.MALFORMED_INPUT)
        source, routes = document["source"], document["routes"]
        if not isinstance(source, str) or not source:
            return _unknown(ObservationReason.MISSING_SOURCE)
        if not isinstance(routes, list) or not routes:
            return _unknown(ObservationReason.MALFORMED_INPUT)
        parsed: list[EvpnRoute] = []
        for item in routes:
            if not isinstance(item, dict) or set(item) != _ROUTE_KEYS:
                return _unknown(ObservationReason.MALFORMED_INPUT)
            route = EvpnRoute(
                family=item["family"],
                type=item["type"],
                rd=item["rd"],
                route_targets=tuple(item["route_targets"]),
                next_hops=tuple(item["next_hops"]),
                withdraw=item["withdraw"],
                best=item["best"],
            )
            parsed.append(route)
        if len(set(parsed)) != len(parsed):
            return _unknown(ObservationReason.DUPLICATE_ROUTE)
        return GoBgpParseResult(
            ObservationOutcome(ObservationResult.PASS), GoBgpSnapshot(source, frozenset(parsed))
        )
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return _unknown(ObservationReason.MALFORMED_INPUT)


def compare_gobgp_snapshots(
    expected: tuple[GoBgpSnapshot, ...], observed: tuple[GoBgpSnapshot, ...]
) -> ObservationOutcome:
    """Compare fixture snapshots without quorum; source is provenance, not equality."""
    if not expected or not observed:
        return ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.MISSING_SOURCE,))
    if any(not snapshot.source or not snapshot.routes for snapshot in expected + observed):
        return ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.MISSING_SOURCE,))
    expected_sources = [snapshot.source for snapshot in expected]
    observed_sources = [snapshot.source for snapshot in observed]
    if len(expected_sources) != len(set(expected_sources)) or len(observed_sources) != len(
        set(observed_sources)
    ):
        return ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.DUPLICATE_SOURCE,))
    if {snapshot.routes for snapshot in expected} != {snapshot.routes for snapshot in observed}:
        return ObservationOutcome(
            ObservationResult.UNKNOWN, (ObservationReason.IMPLEMENTATION_DIVERGENCE,)
        )
    return ObservationOutcome(ObservationResult.PASS)


@dataclass(frozen=True)
class CaptureRef:
    """Immutable capture provenance; no packet-parser or forwarding assertion is implied."""

    identifier: str
    digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.identifier, str)
            or not self.identifier
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest)
        ):
            raise ValueError("capture reference requires identifier and lowercase sha256 digest")


@dataclass(frozen=True)
class VxlanHeader:
    vni: int
    raw_digest: str
    capture: CaptureRef


@dataclass(frozen=True)
class VxlanParseResult:
    outcome: ObservationOutcome
    header: VxlanHeader | None = None


def parse_vxlan_udp_payload(payload: bytes, capture: CaptureRef) -> VxlanParseResult:
    """Validate only the exact eight-byte VXLAN UDP payload header, never a pcap."""
    digest = hashlib.sha256(payload).hexdigest() if isinstance(payload, bytes) else ""
    if not isinstance(payload, bytes) or not isinstance(capture, CaptureRef) or len(payload) != 8:
        return VxlanParseResult(
            ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.MALFORMED_INPUT,))
        )
    flags, reserved_a, vni_bytes, reserved_b = payload[0], payload[1:4], payload[4:7], payload[7]
    vni = int.from_bytes(vni_bytes, "big")
    if (
        flags != 0x08
        or reserved_a != b"\x00\x00\x00"
        or reserved_b != 0
        or not 0 <= vni <= 16_777_215
    ):
        return VxlanParseResult(
            ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.MALFORMED_INPUT,))
        )
    return VxlanParseResult(
        ObservationOutcome(ObservationResult.PASS), VxlanHeader(vni, f"sha256:{digest}", capture)
    )


@dataclass(frozen=True)
class VlanTag:
    """One observed outer 802.1Q/802.1ad tag, kept as its wire values."""

    tpid: int
    tci: int


@dataclass(frozen=True)
class CapturedVxlanEthernetFrame:
    """Structural facts from one supplied Ethernet frame, not a forwarding assertion."""

    outer_destination_mac: str
    outer_source_mac: str
    vlan_tags: tuple[VlanTag, ...]
    ip_version: int
    ip_source: str
    ip_destination: str
    udp_source_port: int
    udp_destination_port: int
    udp_checksum: int
    vxlan: VxlanHeader
    inner_ethernet_frame: bytes
    inner_ethernet_sha256: str


@dataclass(frozen=True)
class CapturedVxlanEthernetFrameParseResult:
    """Result with frame identity retained even when structural parsing is UNKNOWN."""

    outcome: ObservationOutcome
    capture: CaptureRef | None
    frame_sha256: str | None
    frame_len: int | None
    frame: CapturedVxlanEthernetFrame | None = None


def _captured_unknown(frame: object, capture: object) -> CapturedVxlanEthernetFrameParseResult:
    digest = f"sha256:{hashlib.sha256(frame).hexdigest()}" if isinstance(frame, bytes) else None
    return CapturedVxlanEthernetFrameParseResult(
        ObservationOutcome(ObservationResult.UNKNOWN, (ObservationReason.MALFORMED_INPUT,)),
        capture if isinstance(capture, CaptureRef) else None,
        digest,
        len(frame) if isinstance(frame, bytes) else None,
    )


def _mac(raw: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in raw)


def parse_captured_vxlan_ethernet_frame(
    frame: bytes, capture: CaptureRef
) -> CapturedVxlanEthernetFrameParseResult:
    """Parse one Ethernet-II VXLAN frame structurally; PASS is never runtime conformance.

    IPv4 options are accepted but fragments are not.  IPv6 extension headers,
    fragmentation, reassembly, checksums, and pcap/container handling are intentionally
    outside this fixture-only parser.
    """
    if not isinstance(frame, bytes) or not isinstance(capture, CaptureRef) or len(frame) < 14:
        return _captured_unknown(frame, capture)
    try:
        destination, source = _mac(frame[:6]), _mac(frame[6:12])
        offset, ether_type = 14, int.from_bytes(frame[12:14], "big")
        tags: list[VlanTag] = []
        while ether_type in (0x8100, 0x88A8):
            if len(tags) == 2 or len(frame) < offset + 4:
                return _captured_unknown(frame, capture)
            tags.append(VlanTag(ether_type, int.from_bytes(frame[offset : offset + 2], "big")))
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4

        if ether_type == 0x0800:
            if len(frame) < offset + 20:
                return _captured_unknown(frame, capture)
            version_ihl = frame[offset]
            ihl = (version_ihl & 0x0F) * 4
            total_length = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            flags_fragment = int.from_bytes(frame[offset + 6 : offset + 8], "big")
            if (
                version_ihl >> 4 != 4
                or ihl < 20
                or total_length < ihl + 8
                or offset + total_length > len(frame)
                or frame[offset + 9] != 17
                or flags_fragment & 0xBFFF
            ):
                return _captured_unknown(frame, capture)
            ip_version = 4
            ip_source = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
            ip_destination = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
            udp_offset, ip_payload_length = offset + ihl, total_length - ihl
        elif ether_type == 0x86DD:
            if len(frame) < offset + 40 or frame[offset] >> 4 != 6 or frame[offset + 6] != 17:
                return _captured_unknown(frame, capture)
            ip_payload_length = int.from_bytes(frame[offset + 4 : offset + 6], "big")
            if ip_payload_length < 8 or offset + 40 + ip_payload_length > len(frame):
                return _captured_unknown(frame, capture)
            ip_version = 6
            ip_source = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
            ip_destination = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
            udp_offset = offset + 40
        else:
            return _captured_unknown(frame, capture)

        udp_length = int.from_bytes(frame[udp_offset + 4 : udp_offset + 6], "big")
        if (
            udp_length < 16
            or udp_length != ip_payload_length
            or udp_offset + udp_length > len(frame)
        ):
            return _captured_unknown(frame, capture)
        udp_source = int.from_bytes(frame[udp_offset : udp_offset + 2], "big")
        udp_destination = int.from_bytes(frame[udp_offset + 2 : udp_offset + 4], "big")
        if udp_destination != 4789:
            return _captured_unknown(frame, capture)
        udp_payload = frame[udp_offset + 8 : udp_offset + udp_length]
        vxlan = parse_vxlan_udp_payload(udp_payload[:8], capture)
        inner = udp_payload[8:]
        if vxlan.header is None or len(inner) < 14:
            return _captured_unknown(frame, capture)
        return CapturedVxlanEthernetFrameParseResult(
            ObservationOutcome(ObservationResult.PASS),
            capture,
            f"sha256:{hashlib.sha256(frame).hexdigest()}",
            len(frame),
            CapturedVxlanEthernetFrame(
                destination,
                source,
                tuple(tags),
                ip_version,
                ip_source,
                ip_destination,
                udp_source,
                udp_destination,
                int.from_bytes(frame[udp_offset + 6 : udp_offset + 8], "big"),
                vxlan.header,
                inner,
                f"sha256:{hashlib.sha256(inner).hexdigest()}",
            ),
        )
    except ValueError:
        return _captured_unknown(frame, capture)
