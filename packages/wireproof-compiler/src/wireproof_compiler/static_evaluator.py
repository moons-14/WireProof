"""Deterministic, non-runtime evaluation of the closed negative-fixture set.

This adapter deliberately validates only mutations of a known-good semantic IR.
It is not an EVPN emulator and none of its output discharges an unexecuted
``TestPack`` requirement.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, TypedDict

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from wireproof_core import FeatureContract

from .compile import TestPack, TestPackClause, semantic_ir_hash


class StaticEvaluationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class FixtureMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mutation: str = Field(min_length=1)
    expected_error: str = Field(min_length=1)


class StaticEvaluationResult(BaseModel):
    """A local validator outcome, never runtime conformance evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: StaticEvaluationStatus
    evaluation_kind: str = "STATIC"
    fixture_source_identity: str
    rule_id: str
    validator_provenance: str = "wireproof-core.FeatureContract"
    baseline_semantic_ir_hash: str
    test_pack_canonical_hash: str
    test_pack_states: tuple[str, ...]
    detail: str


class _CommonResultFields(TypedDict):
    fixture_source_identity: str
    baseline_semantic_ir_hash: str
    test_pack_canonical_hash: str
    test_pack_states: tuple[str, ...]


_RULES = {
    "wrong_rt": "EVPN_RT_INTERSECTION evpn:tenant-a-l2",
    "wrong_vni": "DUPLICATE_VNI l3:11001/l2:10101",
    "cross_tenant_rt": "CROSS_TENANT_RT",
    "default_route_leak": "MANAGEMENT_DEFAULT_ROUTE_LEAK policy term",
    "missing_evpn_af": "EVPN_BGP_AF",
    "stale_fdb": "INVALID_FDB_REFERENCE",
    "asymmetric_vtep": "ASYMMETRIC_VTEP",
}

# These are closed fixture declarations, rather than comparisons with unstable
# Pydantic diagnostic text.  A fixture is useful only when it names the
# compiler obligation whose expected semantic object it intentionally breaks.
_FIXTURE_BINDINGS = {
    "wrong_rt": ("import/export RTs must intersect", "evpn", "tenant-a-l2", "name", "tenant-a-l2"),
    "wrong_vni": ("duplicate VNI", "vni", "l3:11001", "vni", 11001),
    "cross_tenant_rt": (
        "cross-tenant RT sharing requires a shared-service EVPN instance",
        "evpn",
        "tenant-b-l2",
        "name",
        "tenant-b-l2",
    ),
    "default_route_leak": (
        "management export policy permits default route",
        "bgp",
        "leaf1:65001->spine1:65000;af=ipv4-unicast",
        "local_node",
        "leaf1",
    ),
    "missing_evpn_af": (
        "EVPN participant requires l2vpn-evpn BGP session",
        "bgp",
        "leaf1:65001->spine1:65000;af=l2vpn-evpn",
        "local_node",
        "leaf1",
    ),
    "stale_fdb": ("stale FDB entry", "vni", "l2:10101", "vni", 10101),
    "asymmetric_vtep": ("asymmetric VTEP", "vni", "l2:10101", "vni", 10101),
}

_BINDING_GUARD = object()


@dataclass(frozen=True, slots=True, init=False)
class StaticEvaluationBinding:
    """Read-only association with artifacts from one completed compilation.

    The factory is the local trust boundary.  This prevents accidental public
    construction and mutation; it is not a security boundary against code that
    deliberately bypasses Python object protections.
    """

    _baseline_semantic_ir_hash: str
    _test_pack: TestPack
    _test_pack_canonical_hash: str
    _guard: object

    def __init__(
        self,
        baseline_semantic_ir_hash: str,
        test_pack: TestPack,
        test_pack_canonical_hash: str,
        guard: object,
    ) -> None:
        if guard is not _BINDING_GUARD:
            raise TypeError("StaticEvaluationBinding instances are factory-owned")
        object.__setattr__(self, "_baseline_semantic_ir_hash", baseline_semantic_ir_hash)
        object.__setattr__(self, "_test_pack", test_pack)
        object.__setattr__(self, "_test_pack_canonical_hash", test_pack_canonical_hash)
        object.__setattr__(self, "_guard", guard)


def bind_static_evaluation(compiled: Mapping[str, Any]) -> StaticEvaluationBinding:
    """Bind static evaluation to the exact compiler result without recompiling."""
    semantic_ir_hash = compiled.get("semantic_ir_hash")
    test_pack = compiled.get("test_pack")
    if not isinstance(semantic_ir_hash, str) or not isinstance(test_pack, TestPack):
        raise TypeError("compiled result has no static evaluation artifacts")
    if test_pack.semantic_ir_hash != semantic_ir_hash:
        raise ValueError("compiled TestPack semantic hash mismatch")
    return StaticEvaluationBinding(
        semantic_ir_hash, test_pack, test_pack.canonical_hash, _BINDING_GUARD
    )


def _bound_pack(binding: object) -> TestPack | None:
    if not isinstance(binding, StaticEvaluationBinding) or binding._guard is not _BINDING_GUARD:
        return None
    if (
        binding._test_pack.semantic_ir_hash != binding._baseline_semantic_ir_hash
        or binding._test_pack.canonical_hash != binding._test_pack_canonical_hash
    ):
        return None
    return binding._test_pack


def _common(binding: object, source_identity: str) -> _CommonResultFields:
    pack = _bound_pack(binding)
    return {
        "fixture_source_identity": source_identity,
        "baseline_semantic_ir_hash": pack.semantic_ir_hash if pack else "",
        "test_pack_canonical_hash": pack.canonical_hash if pack else "",
        "test_pack_states": tuple(clause.state for clause in pack.clauses) if pack else (),
    }


def _binding_error(binding: object, source_identity: str) -> StaticEvaluationResult | None:
    if _bound_pack(binding) is None:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_BINDING_INVALID",
            detail="static evaluator requires a trusted compiled binding",
            **_common(binding, source_identity),
        )
    return None


def _baseline_binding_error(
    baseline: FeatureContract, binding: object, source_identity: str
) -> StaticEvaluationResult | None:
    invalid = _binding_error(binding, source_identity)
    if invalid:
        return invalid
    assert isinstance(binding, StaticEvaluationBinding)
    if semantic_ir_hash(baseline) != binding._baseline_semantic_ir_hash:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_BINDING_BASELINE_MISMATCH",
            detail="baseline semantic fingerprint differs from the bound compilation",
            **_common(binding, source_identity),
        )
    return None


def _matches_clause(
    clause: TestPackClause, kind: str, identity: str, field: str, value: object
) -> bool:
    expected = clause.expected_condition.get("expected")
    return (
        clause.requirement_kind == kind
        and clause.source_identity == identity
        and clause.expected_condition.get("object_kind") == kind
        and isinstance(expected, dict)
        and expected.get(field) == value
    )


def _mutated_document(plan: FeatureContract, mutation: str) -> dict[str, Any]:
    document: dict[str, Any] = deepcopy(plan.model_dump(mode="json"))
    if mutation == "wrong_rt":
        document["evpn_instances"][0]["export_rts"] = ["target:65000:999"]
    elif mutation == "wrong_vni":
        document["l3_vnis"][0]["vni"] = document["l2_vnis"][0]["vni"]
    elif mutation == "cross_tenant_rt":
        document["evpn_instances"][1]["export_rts"] = ["target:65000:101"]
    elif mutation == "default_route_leak":
        document["management_export_policy"] = "tenant-export"
        document["prefix_sets"][0]["prefixes"] = ["0.0.0.0/0"]
        document["route_policies"][0]["terms"][0]["prefix_set"] = "default-only"
    elif mutation == "missing_evpn_af":
        document["bgp_sessions"][0]["address_families"] = ["ipv4-unicast"]
    elif mutation == "stale_fdb":
        document["static_fdb"] = [{"mac": "02:00:00:00:00:01", "vlan": 101, "vtep": "missing"}]
    elif mutation == "asymmetric_vtep":
        document["vteps"][0]["peers"] = ["leaf2"]
    else:
        raise KeyError(mutation)
    return document


def evaluate_static_fixture(
    baseline: FeatureContract, binding: StaticEvaluationBinding, fixture_path: Path
) -> StaticEvaluationResult:
    """Evaluate one declared negative mutation with the semantic validator only."""
    invalid = _baseline_binding_error(baseline, binding, str(fixture_path))
    if invalid:
        return invalid
    try:
        fixture_bytes = fixture_path.read_bytes()
    except OSError as exc:
        return _fixture_error_result(binding, str(fixture_path), type(exc).__name__)
    return evaluate_static_fixture_bytes(baseline, binding, fixture_bytes, str(fixture_path))


def _fixture_error_result(
    binding: object, source_identity: str, error: str
) -> StaticEvaluationResult:
    invalid = _binding_error(binding, source_identity)
    if invalid:
        return invalid
    return StaticEvaluationResult(
        status=StaticEvaluationStatus.UNKNOWN,
        rule_id="STATIC_FIXTURE_METADATA_INVALID",
        detail=f"fixture metadata rejected: {error}",
        **_common(binding, source_identity),
    )


def evaluate_static_fixture_bytes(
    baseline: FeatureContract,
    binding: StaticEvaluationBinding,
    fixture_bytes: bytes,
    source_identity: str,
) -> StaticEvaluationResult:
    """Evaluate fixture bytes already read and content-identified by the caller."""
    invalid = _baseline_binding_error(baseline, binding, source_identity)
    if invalid:
        return invalid
    common = _common(binding, source_identity)
    try:
        metadata = FixtureMetadata.model_validate(yaml.safe_load(fixture_bytes.decode("utf-8")))
    except (OSError, UnicodeError, ValidationError, yaml.YAMLError) as exc:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_METADATA_INVALID",
            detail=f"fixture metadata rejected: {type(exc).__name__}",
            **common,
        )
    rule_id = _RULES.get(metadata.mutation)
    fixture_binding = _FIXTURE_BINDINGS.get(metadata.mutation)
    if rule_id is None or fixture_binding is None:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_MUTATION_UNMAPPED",
            detail="fixture mutation has no closed static evaluator mapping",
            **common,
        )
    expected_error, kind, identity, field, value = fixture_binding
    if metadata.expected_error != expected_error:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_EXPECTATION_MISMATCH",
            detail="fixture expected_error does not match the closed mutation expectation",
            **common,
        )
    pack = _bound_pack(binding)
    assert pack is not None
    selected = [
        clause for clause in pack.clauses if _matches_clause(clause, kind, identity, field, value)
    ]
    if len(selected) != 1:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_CLAUSE_UNBOUND",
            detail=(
                "fixture mutation has no unique declared TestPack clause with matching semantics"
            ),
            **common,
        )
    try:
        FeatureContract.model_validate(_mutated_document(baseline, metadata.mutation))
    except ValidationError:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.FAIL,
            rule_id=rule_id,
            detail="mapped invalid mutation was rejected by the semantic validator",
            **common,
        )
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_EVALUATOR_ERROR",
            detail=f"evaluator could not validate mapped mutation: {type(exc).__name__}",
            **common,
        )
    return StaticEvaluationResult(
        status=StaticEvaluationStatus.UNKNOWN,
        rule_id="STATIC_MUTATION_NOT_REJECTED",
        detail="mapped mutation was not rejected; it cannot discharge a TestPack clause",
        **common,
    )


def evaluate_static_baseline(
    baseline: FeatureContract, binding: StaticEvaluationBinding, source_identity: str = "baseline"
) -> StaticEvaluationResult:
    """Record that the bound baseline itself is valid, without executing its pack."""
    invalid = _baseline_binding_error(baseline, binding, source_identity)
    if invalid:
        return invalid
    common = _common(binding, source_identity)
    return StaticEvaluationResult(
        status=StaticEvaluationStatus.PASS,
        rule_id="BASELINE_SEMANTIC_VALID",
        detail="baseline FeatureContract is valid; TestPack remains unexecuted",
        **common,
    )
