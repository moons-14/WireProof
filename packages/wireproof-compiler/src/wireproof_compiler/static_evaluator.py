"""Deterministic, non-runtime evaluation of the closed negative-fixture set.

This adapter deliberately validates only mutations of a known-good semantic IR.
It is not an EVPN emulator and none of its output discharges an unexecuted
``TestPack`` requirement.
"""

from __future__ import annotations

from copy import deepcopy
from enum import StrEnum
from pathlib import Path
from typing import Any, TypedDict

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from wireproof_core import FeatureContract

from .compile import TestPack, compile_test_pack


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
    baseline: FeatureContract, test_pack: TestPack, fixture_path: Path
) -> StaticEvaluationResult:
    """Evaluate one declared negative mutation with the semantic validator only."""
    compiled_pack = compile_test_pack(baseline)
    source = str(fixture_path)
    states = tuple(clause.state for clause in test_pack.clauses)
    common: _CommonResultFields = {
        "fixture_source_identity": source,
        "baseline_semantic_ir_hash": compiled_pack.semantic_ir_hash,
        "test_pack_canonical_hash": test_pack.canonical_hash,
        "test_pack_states": states,
    }
    if test_pack.semantic_ir_hash != compiled_pack.semantic_ir_hash:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="TEST_PACK_SEMANTIC_HASH_MISMATCH",
            detail="supplied TestPack is not bound to the baseline semantic IR",
            **common,
        )
    if test_pack.canonical_hash != compiled_pack.canonical_hash:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="TEST_PACK_CANONICAL_HASH_MISMATCH",
            detail="supplied TestPack does not match the canonical baseline compilation",
            **common,
        )
    try:
        metadata = FixtureMetadata.model_validate(
            yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, ValidationError, yaml.YAMLError) as exc:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_METADATA_INVALID",
            detail=f"fixture metadata rejected: {type(exc).__name__}",
            **common,
        )
    rule_id = _RULES.get(metadata.mutation)
    if rule_id is None:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="STATIC_FIXTURE_MUTATION_UNMAPPED",
            detail="fixture mutation has no closed static evaluator mapping",
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
    baseline: FeatureContract, test_pack: TestPack, source_identity: str = "baseline"
) -> StaticEvaluationResult:
    """Record that the bound baseline itself is valid, without executing its pack."""
    compiled_pack = compile_test_pack(baseline)
    common: _CommonResultFields = {
        "fixture_source_identity": source_identity,
        "baseline_semantic_ir_hash": compiled_pack.semantic_ir_hash,
        "test_pack_canonical_hash": test_pack.canonical_hash,
        "test_pack_states": tuple(clause.state for clause in test_pack.clauses),
    }
    if test_pack.semantic_ir_hash != compiled_pack.semantic_ir_hash:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="TEST_PACK_SEMANTIC_HASH_MISMATCH",
            detail="supplied TestPack is not bound to the baseline semantic IR",
            **common,
        )
    if test_pack.canonical_hash != compiled_pack.canonical_hash:
        return StaticEvaluationResult(
            status=StaticEvaluationStatus.UNKNOWN,
            rule_id="TEST_PACK_CANONICAL_HASH_MISMATCH",
            detail="supplied TestPack does not match the canonical baseline compilation",
            **common,
        )
    return StaticEvaluationResult(
        status=StaticEvaluationStatus.PASS,
        rule_id="BASELINE_SEMANTIC_VALID",
        detail="baseline FeatureContract is valid; TestPack remains unexecuted",
        **common,
    )
