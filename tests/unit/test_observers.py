import hashlib
import json
from typing import cast

import pytest
import wireproof_runtime
import wireproof_runtime.observers as observers
from wireproof_runtime.observers import (
    CaptureRef,
    ObservationReason,
    ObservationResult,
    compare_gobgp_snapshots,
    parse_gobgp_fixture,
    parse_vxlan_udp_payload,
)


def test_observer_api_is_available_from_package_root() -> None:
    expected = {
        "CaptureRef",
        "EvpnRoute",
        "EvpnRouteExpectation",
        "GoBgpParseResult",
        "GoBgpSnapshot",
        "ObservationOutcome",
        "ObservationReason",
        "ObservationResult",
        "VxlanHeader",
        "VxlanParseResult",
        "compare_gobgp_snapshots",
        "parse_gobgp_fixture",
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
    assert parsed.header.raw_digest == "sha256:" + hashlib.sha256(
        b"\x08\x00\x00\x00\x00\x01\x23\x00"
    ).hexdigest()


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
