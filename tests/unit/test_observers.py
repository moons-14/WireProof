import hashlib
import json
from collections.abc import Callable
from typing import cast

import pytest
import wireproof_runtime
import wireproof_runtime.observers as observers
from wireproof_runtime.observers import (
    CaptureRef,
    ObservationReason,
    ObservationResult,
    compare_gobgp_snapshots,
    parse_captured_vxlan_ethernet_frame,
    parse_gobgp_fixture,
    parse_vxlan_udp_payload,
)


def test_observer_api_is_available_from_package_root() -> None:
    expected = {
        "CaptureRef",
        "CapturedVxlanEthernetFrame",
        "CapturedVxlanEthernetFrameParseResult",
        "EvpnRoute",
        "EvpnRouteExpectation",
        "GoBgpParseResult",
        "GoBgpSnapshot",
        "ObservationOutcome",
        "ObservationReason",
        "ObservationResult",
        "VxlanHeader",
        "VxlanParseResult",
        "VlanTag",
        "compare_gobgp_snapshots",
        "parse_gobgp_fixture",
        "parse_captured_vxlan_ethernet_frame",
        "parse_vxlan_udp_payload",
    }
    assert {name for name in expected if hasattr(wireproof_runtime, name)} == expected
    for name in expected:
        assert getattr(wireproof_runtime, name) is getattr(observers, name)


def _payload(source: str = "gobgp-a") -> str:
    return json.dumps(
        {
            "source": source,
            "routes": [
                {
                    "family": "l2vpn_evpn",
                    "type": 2,
                    "rd": "65000:1",
                    "route_targets": ["target:65000:100"],
                    "next_hops": ["192.0.2.1"],
                    "withdraw": False,
                    "best": True,
                }
            ],
        }
    )


def _route_payload(**changes: object) -> str:
    document = json.loads(_payload())
    document["routes"][0].update(changes)
    return json.dumps(document)


def test_gobgp_fixture_normalizes_and_source_does_not_affect_equality() -> None:
    left = parse_gobgp_fixture(_payload("a")).snapshot
    right = parse_gobgp_fixture(_payload("b")).snapshot
    assert left is not None and right is not None and left == right
    assert compare_gobgp_snapshots((left,), (right,)).result is ObservationResult.PASS


def test_gobgp_public_parser_returns_unknown_for_invalid_contracts() -> None:
    duplicate = json.loads(_payload())
    duplicate["routes"].append(duplicate["routes"][0])
    assert (
        parse_gobgp_fixture('{"source":"x","routes":[],"extra":true}').outcome.result
        is ObservationResult.UNKNOWN
    )
    assert parse_gobgp_fixture(json.dumps(duplicate)).outcome.reasons == (
        ObservationReason.DUPLICATE_ROUTE,
    )
    assert parse_gobgp_fixture(_payload("")).outcome.reasons == (ObservationReason.MISSING_SOURCE,)


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"\xff", ObservationReason.MALFORMED_INPUT),
        ("[]", ObservationReason.MALFORMED_INPUT),
        ('{"source":1,"routes":[]}', ObservationReason.MISSING_SOURCE),
        (_route_payload(family="ipv4_unicast"), ObservationReason.MALFORMED_INPUT),
        (_route_payload(type=True), ObservationReason.MALFORMED_INPUT),
        (_route_payload(rd="65000:01"), ObservationReason.MALFORMED_INPUT),
        (_route_payload(route_targets=["target:65000:010"]), ObservationReason.MALFORMED_INPUT),
        (_route_payload(next_hops=["not-an-ip"]), ObservationReason.MALFORMED_INPUT),
        (
            _route_payload(route_targets=["target:65000:100", "target:65000:100"]),
            ObservationReason.MALFORMED_INPUT,
        ),
        (_route_payload(next_hops=["192.0.2.1", "192.0.2.1"]), ObservationReason.MALFORMED_INPUT),
        (_route_payload(withdraw=True), ObservationReason.MALFORMED_INPUT),
        (_route_payload(withdraw=False, next_hops=[]), ObservationReason.MALFORMED_INPUT),
    ],
)
def test_gobgp_parser_rejects_malformed_types_and_route_contracts(
    payload: str | bytes, reason: ObservationReason
) -> None:
    parsed = parse_gobgp_fixture(payload)
    assert parsed.outcome.result is ObservationResult.UNKNOWN
    assert parsed.outcome.reasons == (reason,)


def test_gobgp_divergence_and_duplicate_sources_are_unknown() -> None:
    first = parse_gobgp_fixture(_payload("same")).snapshot
    second = parse_gobgp_fixture(_payload("same")).snapshot
    assert first is not None and second is not None
    assert compare_gobgp_snapshots((first, second), (first,)).reasons == (
        ObservationReason.DUPLICATE_SOURCE,
    )
    divergent = parse_gobgp_fixture(_route_payload(rd="65000:2")).snapshot
    assert divergent is not None
    assert compare_gobgp_snapshots((first,), (divergent,)).reasons == (
        ObservationReason.IMPLEMENTATION_DIVERGENCE,
    )


def test_vxlan_accepts_only_exact_i_flag_header() -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    parsed = parse_vxlan_udp_payload(b"\x08\x00\x00\x00\x00\x01\x23\x00", capture)
    assert parsed.outcome.result is ObservationResult.PASS
    assert parsed.header is not None and parsed.header.vni == 291
    assert parsed.header.capture == capture
    assert (
        parsed.header.raw_digest
        == "sha256:" + hashlib.sha256(b"\x08\x00\x00\x00\x00\x01\x23\x00").hexdigest()
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"\x08\x00\x00\x00\x00\x01\x23",
        b"\x08\x00\x00\x00\x00\x01\x23\x00\x00",
        b"\x00\x00\x00\x00\x00\x01\x23\x00",
        b"\x08\x01\x00\x00\x00\x01\x23\x00",
        b"\x08\x00\x01\x00\x00\x01\x23\x00",
        b"\x08\x00\x00\x01\x00\x01\x23\x00",
        b"\x08\x00\x00\x00\x00\x01\x23\x01",
    ],
)
def test_vxlan_rejects_noncanonical_headers(payload: bytes) -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    assert parse_vxlan_udp_payload(payload, capture).outcome.reasons == (
        ObservationReason.MALFORMED_INPUT,
    )


@pytest.mark.parametrize("vni", [0, 16_777_215])
def test_vxlan_accepts_vni_boundaries(vni: int) -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    payload = b"\x08\x00\x00\x00" + vni.to_bytes(3, "big") + b"\x00"
    parsed = parse_vxlan_udp_payload(payload, capture)
    assert parsed.outcome.result is ObservationResult.PASS
    assert parsed.header is not None and parsed.header.vni == vni


def test_vxlan_rejects_non_capture_provenance() -> None:
    assert parse_vxlan_udp_payload(
        b"\x08\x00\x00\x00\x00\x01\x23\x00", cast(CaptureRef, "fixture")
    ).outcome.reasons == (ObservationReason.MALFORMED_INPUT,)


def test_capture_ref_requires_nonempty_string_identifier() -> None:
    with pytest.raises(ValueError, match="capture reference requires identifier"):
        CaptureRef(1, "sha256:" + "a" * 64)  # type: ignore[arg-type]


def _captured_frame(version: int, tags: tuple[tuple[int, int], ...] = (), vni: int = 291) -> bytes:
    inner = bytes.fromhex("0200000000020200000000010800") + b"inner"
    vxlan = b"\x08\x00\x00\x00" + vni.to_bytes(3, "big") + b"\x00" + inner
    udp = (
        (12345).to_bytes(2, "big")
        + (4789).to_bytes(2, "big")
        + (8 + len(vxlan)).to_bytes(2, "big")
        + bytes.fromhex("beef")
        + vxlan
    )
    if version == 4:
        ip = (
            bytes((0x45, 0))
            + (20 + len(udp)).to_bytes(2, "big")
            + b"\x00\x00\x00\x00\x40\x11\x00\x00"
            + bytes((192, 0, 2, 1, 198, 51, 100, 1))
            + udp
        )
        payload_type = 0x0800
    else:
        ip = (
            b"\x60\x00\x00\x00"
            + len(udp).to_bytes(2, "big")
            + b"\x11\x40"
            + bytes.fromhex("20010db8000000000000000000000001")
            + bytes.fromhex("20010db8000000000000000000000002")
            + udp
        )
        payload_type = 0x86DD
    ethernet = bytes.fromhex("02000000000a02000000000b")
    for tpid, tci in tags:
        ethernet += tpid.to_bytes(2, "big") + tci.to_bytes(2, "big")
    return ethernet + payload_type.to_bytes(2, "big") + ip


@pytest.mark.parametrize(
    "version,tags,vni",
    [(4, (), 0), (4, ((0x8100, 7),), 291), (6, ((0x88A8, 9), (0x8100, 10)), 16_777_215)],
)
def test_captured_vxlan_ethernet_frame_records_structural_facts(
    version: int, tags: tuple[tuple[int, int], ...], vni: int
) -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    raw = _captured_frame(version, tags, vni)
    parsed = parse_captured_vxlan_ethernet_frame(raw, capture)
    assert parsed.outcome.result is ObservationResult.PASS
    assert parsed.capture == capture and parsed.frame_len == len(raw)
    assert parsed.frame_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert parsed.frame is not None
    assert (parsed.frame.ip_version, parsed.frame.ip_source, parsed.frame.udp_destination_port) == (
        version,
        "192.0.2.1" if version == 4 else "2001:db8::1",
        4789,
    )
    assert tuple((tag.tpid, tag.tci) for tag in parsed.frame.vlan_tags) == tags
    assert parsed.frame.vxlan.vni == vni
    assert (
        parsed.frame.inner_ethernet_frame
        == bytes.fromhex("0200000000020200000000010800") + b"inner"
    )
    assert (
        parsed.frame.inner_ethernet_sha256
        == "sha256:" + hashlib.sha256(parsed.frame.inner_ethernet_frame).hexdigest()
    )


@pytest.mark.parametrize("flags_fragment", [0x8000, 0x2000, 0x0001])
def test_captured_vxlan_ethernet_frame_rejects_ipv4_reserved_or_fragment_flags(
    flags_fragment: int,
) -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    raw = _captured_frame(4)
    invalid = raw[:20] + flags_fragment.to_bytes(2, "big") + raw[22:]
    parsed = parse_captured_vxlan_ethernet_frame(invalid, capture)
    assert parsed.outcome.result is ObservationResult.UNKNOWN
    assert parsed.frame is None


def test_captured_vxlan_ethernet_frame_accepts_ipv4_df_flag() -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    raw = _captured_frame(4)
    df_only = raw[:20] + (0x4000).to_bytes(2, "big") + raw[22:]

    parsed = parse_captured_vxlan_ethernet_frame(df_only, capture)

    assert parsed.outcome.result is ObservationResult.PASS
    assert parsed.frame is not None


@pytest.mark.parametrize(
    "mutator",
    [
        lambda raw: raw[:12] + b"\x81\x00\x00\x01\x81\x00\x00\x02\x81\x00\x00\x03" + raw[12:],
        lambda raw: raw[:14] + bytes((0x44,)) + raw[15:],
        lambda raw: raw[:20] + b"\x20\x00" + raw[22:],
        lambda raw: raw[:36] + b"\x12\xb4" + raw[38:],
        lambda raw: raw[:38] + b"\x00\x08" + raw[40:],
        lambda raw: raw[:42] + b"\x00" + raw[43:],
        lambda raw: raw[:-6],
    ],
)
def test_captured_vxlan_ethernet_frame_rejects_malformed_boundaries(
    mutator: Callable[[bytes], bytes],
) -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    raw = _captured_frame(4)
    invalid = mutator(raw)
    parsed = parse_captured_vxlan_ethernet_frame(invalid, capture)
    assert parsed.outcome.result is ObservationResult.UNKNOWN
    assert parsed.frame is None and parsed.capture == capture
    assert parsed.frame_sha256 == "sha256:" + hashlib.sha256(invalid).hexdigest()


def test_captured_vxlan_ethernet_frame_rejects_ipv6_extensions() -> None:
    capture = CaptureRef("fixture", "sha256:" + "a" * 64)
    raw = _captured_frame(6)
    invalid = raw[:20] + b"\x3c" + raw[21:]
    assert (
        parse_captured_vxlan_ethernet_frame(invalid, capture).outcome.result
        is ObservationResult.UNKNOWN
    )


def test_captured_vxlan_ethernet_frame_requires_capture_ref() -> None:
    raw = _captured_frame(4)
    parsed = parse_captured_vxlan_ethernet_frame(raw, cast(CaptureRef, "bad"))
    assert parsed.outcome.result is ObservationResult.UNKNOWN
    assert (
        parsed.capture is None
        and parsed.frame_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()
    )
