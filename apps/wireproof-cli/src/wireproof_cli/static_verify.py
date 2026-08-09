"""Closed, non-runtime static verification command support."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from wireproof_compiler import (
    bind_static_evaluation,
    compile_plan,
    evaluate_static_baseline,
    evaluate_static_fixture_bytes,
)
from wireproof_core import FeatureContract
from wireproof_evidence import (
    CheckPhase,
    CheckResult,
    EvidenceBundle,
    EvidenceBundlePayload,
    EvidenceOwnership,
    EvidenceRequirements,
    ExecutionMode,
    RequiredCheck,
    Result,
    UnsupportedPlatformError,
    ensure_safe_evidence_root,
    persist_bundle,
)

_CLI_VERSION = "0.1.0"
_EVALUATOR_VERSION = "0.1.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(key: str, value: str) -> str:
    """Return one closed provenance token; values must be SHA-256 digests."""
    return f"{key}={value}"


def static_verify(
    plan_path: Path, fixture_path: Path | None, evidence_root: Path
) -> tuple[dict[str, Any], int]:
    """Run the static chain and persist its deliberately incomplete evidence bundle."""
    # Persistence validates the complete root path component-by-component and therefore
    # requires an absolute path.  Make relative roots absolute lexically: resolving
    # here would follow a user-provided symlink before the no-follow checks run.
    if not evidence_root.is_absolute():
        evidence_root = Path.cwd() / evidence_root
    try:
        plan_bytes = plan_path.read_bytes()
        plan = FeatureContract.model_validate(yaml.safe_load(plan_bytes.decode("utf-8")))
    except (OSError, UnicodeError, ValidationError, yaml.YAMLError) as exc:
        return {"status": "UNKNOWN", "diagnostic": f"plan rejected: {type(exc).__name__}"}, 2

    fixture_bytes: bytes | None = None
    fixture_hash: str | None = None
    if fixture_path is not None:
        try:
            fixture_bytes = fixture_path.read_bytes()
        except OSError as exc:
            return {
                "status": "UNKNOWN",
                "diagnostic": f"fixture unreadable: {type(exc).__name__}",
            }, 2
        fixture_hash = _sha256(fixture_bytes)

    compiled = compile_plan(plan)
    pack = compiled["test_pack"]
    binding = bind_static_evaluation(compiled)
    plan_hash = _sha256(plan_bytes)
    if fixture_bytes is None:
        static = evaluate_static_baseline(plan, binding, _identity("input_sha256", plan_hash))
    else:
        static = evaluate_static_fixture_bytes(
            plan, binding, fixture_bytes, _identity("fixture_sha256", fixture_hash or "")
        )

    static_result = Result(static.status.value)
    requirements = EvidenceRequirements(
        checks=(
            RequiredCheck(check_id="static-evaluation", phase=CheckPhase.SEMANTIC, applicable=True),
            RequiredCheck(check_id="runtime-e2e", phase=CheckPhase.TARGET, applicable=True),
        )
    )
    provenance = [
        _identity("input_sha256", plan_hash),
        _identity("semantic_ir_sha256", compiled["semantic_ir_hash"]),
        _identity("reference_artifact_sha256", compiled["reference_topology_hash"]),
        _identity("test_pack_sha256", pack.canonical_hash),
        _identity("evaluator_sha256", _sha256(_EVALUATOR_VERSION.encode())),
        _identity("cli_sha256", _sha256(_CLI_VERSION.encode())),
        _identity("requirements_sha256", requirements.canonical_hash),
    ]
    if fixture_hash is not None:
        provenance.append(_identity("fixture_sha256", fixture_hash))
    bundle = EvidenceBundle.create(
        requirements,
        EvidenceBundlePayload(
            ownership=EvidenceOwnership(
                change_id=plan_hash, run_id=pack.canonical_hash, producer="wireproof-static-verify"
            ),
            records=(
                CheckResult(
                    check_id="static-evaluation", phase=CheckPhase.SEMANTIC, result=static_result
                ),
                CheckResult(
                    check_id="runtime-e2e",
                    phase=CheckPhase.TARGET,
                    result=Result.UNKNOWN,
                    reason="unexecuted_by_static_command",
                ),
            ),
            provenance_clauses=tuple(provenance),
            unknowns=("unexecuted_by_static_command",),
            execution_mode=ExecutionMode.FAKE,
        ),
    )
    try:
        ensure_safe_evidence_root(evidence_root)
        bundle_path = persist_bundle(evidence_root, bundle)
    except (OSError, ValueError, UnsupportedPlatformError) as exc:
        return {
            "status": "UNKNOWN",
            "diagnostic": f"evidence persistence failed: {type(exc).__name__}",
        }, 74

    findings = bundle.structurally_complete(requirements)
    envelope = {
        "static": static.model_dump(mode="json"),
        "runtime": {"status": "UNEXECUTED", "reason": "unexecuted_by_static_command"},
        "promotion_eligible": False,
        "bundle": {
            "sha256": bundle.canonical_hash,
            "requirements_sha256": requirements.canonical_hash,
            "path": bundle_path.name,
            "structural_findings": [finding.model_dump(mode="json") for finding in findings],
        },
        "provenance": tuple(provenance + [_identity("bundle_sha256", bundle.canonical_hash)]),
    }
    return envelope, {Result.PASS: 0, Result.FAIL: 1, Result.UNKNOWN: 2}[static_result]
