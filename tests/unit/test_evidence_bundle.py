from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError
from wireproof_evidence import (
    CaptureRef,
    CaptureRole,
    CheckPhase,
    CheckResult,
    ClauseCoverage,
    CommandKind,
    CommandTranscript,
    ComponentProvenance,
    CoverageAxis,
    EvidenceBundle,
    EvidenceBundlePayload,
    EvidenceOwnership,
    EvidenceRequirements,
    ImageProvenance,
    Observation,
    RequiredCheck,
    Result,
    StructuralFindingCode,
    UnsupportedPlatformError,
    persist_bundle,
)


def requirements() -> EvidenceRequirements:
    return EvidenceRequirements(
        required_coverage=(CoverageAxis.CAPABILITY,),
        required_provenance_clauses=("EVPN_M1",),
        checks=(
            RequiredCheck(check_id="semantic", phase=CheckPhase.SEMANTIC, applicable=True),
            RequiredCheck(check_id="target-cli", phase=CheckPhase.TARGET, applicable=False),
        ),
    )


def bundle(result: Result = Result.PASS) -> EvidenceBundle:
    return EvidenceBundle.create(
        requirements(),
        EvidenceBundlePayload(
            ownership=EvidenceOwnership(change_id="change-1", run_id="run-1", producer="test"),
            records=(
                CheckResult(check_id="semantic", phase=CheckPhase.SEMANTIC, result=result),
                CheckResult(
                    check_id="target-cli", phase=CheckPhase.TARGET, result=Result.NOT_APPLICABLE
                ),
            ),
            coverage=(CoverageAxis.CAPABILITY,),
            provenance_clauses=("EVPN_M1",),
            images=(
                ImageProvenance(
                    reference="registry.example/wireproof/reference",
                    digest="sha256:" + "b" * 64,
                    version="1.0.0",
                    source_revision="abc123",
                ),
            ),
            components=(
                ComponentProvenance(
                    name="wireproof-reference",
                    version="1.0.0",
                    digest="sha256:" + "c" * 64,
                ),
            ),
        ),
    )


def test_canonical_requirements_bind_bundle_and_refs_are_content_addressed() -> None:
    evidence = bundle()
    capture = CaptureRef(
        sha256="a" * 64,
        media_type="application/vnd.tcpdump.pcap",
        size=12,
        role=CaptureRole.PACKET_CAPTURE,
    )
    assert evidence.requirements_hash == requirements().canonical_hash
    assert evidence.canonical_hash == hashlib.sha256(evidence.canonical_bytes).hexdigest()
    assert capture.sha256 == "a" * 64
    with pytest.raises(ValidationError):
        EvidenceBundle(
            requirements=requirements(), requirements_hash="b" * 64, payload=evidence.payload
        )


@pytest.mark.parametrize("result", [Result.UNKNOWN, Result.FAIL, Result.NOT_APPLICABLE])
def test_nonpassing_required_result_is_a_structural_finding(result: Result) -> None:
    findings = bundle(result).structurally_complete(requirements())
    assert StructuralFindingCode.CHECK_RESULT_NOT_PASS in {finding.code for finding in findings}


def test_requirements_and_results_are_closed_and_phase_bound() -> None:
    payload = bundle().payload
    incomplete = EvidenceBundle.create(requirements(), payload.model_copy(update={"records": ()}))
    assert StructuralFindingCode.MISSING_CHECK_RESULT in {
        finding.code for finding in incomplete.structurally_complete(requirements())
    }
    with pytest.raises(ValidationError, match="phase"):
        EvidenceBundle.create(
            requirements(),
            payload.model_copy(
                update={
                    "records": (
                        CheckResult(
                            check_id="semantic", phase=CheckPhase.TARGET, result=Result.PASS
                        ),
                    )
                }
            ),
        )
    with pytest.raises(ValidationError, match="undeclared"):
        EvidenceBundle.create(
            requirements(),
            payload.model_copy(
                update={
                    "records": (
                        CheckResult(
                            check_id="other", phase=CheckPhase.SEMANTIC, result=Result.PASS
                        ),
                    )
                }
            ),
        )


def test_transcript_is_closed_metadata_without_argv() -> None:
    assert CommandTranscript(kind=CommandKind.DEPLOY).kind is CommandKind.DEPLOY
    with pytest.raises(ValidationError, match="args"):
        CommandTranscript(kind=CommandKind.DEPLOY, args=())


def test_structural_completeness_links_axis_to_pass_observation_and_capture() -> None:
    evidence = bundle()
    capture = CaptureRef(
        sha256="a" * 64,
        media_type="application/vnd.tcpdump.pcap",
        size=12,
        role=CaptureRole.PACKET_CAPTURE,
    )
    complete = evidence.model_copy(
        update={
            "payload": evidence.payload.model_copy(
                update={
                    "captures": (capture,),
                    "observations": (
                        Observation(
                            check_id="semantic",
                            result=Result.PASS,
                            artifact_refs=(capture.sha256,),
                        ),
                    ),
                    "clause_coverage": (
                        ClauseCoverage(
                            clause_id="EVPN_M1",
                            axis=CoverageAxis.CAPABILITY,
                            check_ids=("semantic",),
                            artifact_refs=(capture.sha256,),
                        ),
                    ),
                }
            )
        }
    )
    assert complete.structurally_complete(requirements()) == ()
    codes = {finding.code for finding in evidence.structurally_complete(requirements())}
    assert StructuralFindingCode.MISSING_CLAUSE_COVERAGE in codes


def test_provenance_and_observation_links_are_strict() -> None:
    evidence = bundle()
    with pytest.raises(ValidationError, match="digest"):
        ComponentProvenance(name="reference", version="1", digest="not-a-digest")
    duplicate_observations = evidence.payload.model_copy(
        update={
            "observations": (
                Observation(check_id="semantic", result=Result.PASS),
                Observation(check_id="semantic", result=Result.PASS),
            )
        }
    )
    with pytest.raises(ValidationError, match="observation IDs"):
        EvidenceBundle.create(requirements(), duplicate_observations)
    missing = evidence.model_copy(
        update={"payload": evidence.payload.model_copy(update={"images": (), "components": ()})}
    )
    assert {
        StructuralFindingCode.MISSING_IMAGE_PROVENANCE,
        StructuralFindingCode.MISSING_COMPONENT_PROVENANCE,
    } <= {finding.code for finding in missing.structurally_complete(requirements())}


@pytest.mark.parametrize(
    "version",
    [
        "LATEST",
        "Mutable",
        "main",
        "master",
        "head",
        "edge",
        "stable",
        "current",
        "nightly",
        "snapshot",
        "dev",
        "devel",
        "ci",
        "abc",
        " 1.0.0",
        "1.0.0 ",
        " ",
        "",
    ],
)
def test_provenance_rejects_floating_versions(version: str) -> None:
    with pytest.raises(ValidationError):
        ImageProvenance(
            reference="registry.example/wireproof/reference",
            digest="sha256:" + "b" * 64,
            version=version,
            source_revision="abc123",
        )


@pytest.mark.parametrize(
    "version", ["LATEST", "Mutable", "main", "abc", " 1.0.0", "1.0.0 ", " ", ""]
)
def test_component_provenance_rejects_floating_versions(version: str) -> None:
    with pytest.raises(ValidationError):
        ComponentProvenance(
            name="wireproof-reference",
            version=version,
            digest="sha256:" + "c" * 64,
        )


def test_clause_capture_refs_may_use_union_of_linked_observation_refs() -> None:
    evidence = bundle()
    capture = CaptureRef(
        sha256="a" * 64,
        media_type="application/vnd.tcpdump.pcap",
        size=12,
        role=CaptureRole.PACKET_CAPTURE,
    )
    second_capture = capture.model_copy(update={"sha256": "b" * 64})
    payload = evidence.payload.model_copy(
        update={
            "captures": (capture, second_capture),
            "observations": (
                Observation(
                    check_id="semantic", result=Result.PASS, artifact_refs=("a" * 64, "b" * 64)
                ),
            ),
            "clause_coverage": (
                ClauseCoverage(
                    clause_id="EVPN_M1",
                    axis=CoverageAxis.CAPABILITY,
                    check_ids=("semantic",),
                    artifact_refs=("b" * 64,),
                ),
            ),
        }
    )
    findings = evidence.model_copy(update={"payload": payload}).structurally_complete(
        requirements()
    )
    assert findings == ()


def test_clause_capture_refs_must_be_linked_to_one_passing_observation() -> None:
    evidence = bundle()
    observation_capture = CaptureRef(
        sha256="a" * 64,
        media_type="application/vnd.tcpdump.pcap",
        size=12,
        role=CaptureRole.PACKET_CAPTURE,
    )
    clause_capture = CaptureRef(
        sha256="b" * 64,
        media_type="application/vnd.tcpdump.pcap",
        size=12,
        role=CaptureRole.PACKET_CAPTURE,
    )
    payload = evidence.payload.model_copy(
        update={
            "captures": (observation_capture, clause_capture),
            "observations": (
                Observation(
                    check_id="semantic",
                    result=Result.PASS,
                    artifact_refs=(observation_capture.sha256,),
                ),
            ),
            "clause_coverage": (
                ClauseCoverage(
                    clause_id="EVPN_M1",
                    axis=CoverageAxis.CAPABILITY,
                    check_ids=("semantic",),
                    artifact_refs=(clause_capture.sha256,),
                ),
            ),
        }
    )
    findings = evidence.model_copy(update={"payload": payload}).structurally_complete(
        requirements()
    )
    assert StructuralFindingCode.MISSING_CAPTURE_LINK in {finding.code for finding in findings}


def test_empty_linked_pass_observation_is_allowed_when_union_covers_clause() -> None:
    evidence = bundle()
    requirement_set = requirements().model_copy(
        update={
            "checks": tuple(
                RequiredCheck(check_id=check_id, phase=CheckPhase.SEMANTIC, applicable=True)
                for check_id in ("semantic-a", "semantic-b", "semantic-empty")
            )
            + (RequiredCheck(check_id="target-cli", phase=CheckPhase.TARGET, applicable=False),)
        }
    )
    captures = tuple(
        CaptureRef(
            sha256=ref,
            media_type="application/vnd.tcpdump.pcap",
            size=12,
            role=CaptureRole.PACKET_CAPTURE,
        )
        for ref in ("a" * 64, "b" * 64)
    )
    payload = evidence.payload.model_copy(
        update={
            "captures": captures,
            "records": tuple(
                CheckResult(check_id=check_id, phase=CheckPhase.SEMANTIC, result=Result.PASS)
                for check_id in ("semantic-a", "semantic-b", "semantic-empty")
            )
            + (
                CheckResult(
                    check_id="target-cli", phase=CheckPhase.TARGET, result=Result.NOT_APPLICABLE
                ),
            ),
            "observations": (
                Observation(check_id="semantic-a", result=Result.PASS, artifact_refs=("a" * 64,)),
                Observation(check_id="semantic-b", result=Result.PASS, artifact_refs=("b" * 64,)),
                Observation(check_id="semantic-empty", result=Result.PASS),
            ),
            "clause_coverage": (
                ClauseCoverage(
                    clause_id="EVPN_M1",
                    axis=CoverageAxis.CAPABILITY,
                    check_ids=("semantic-a", "semantic-b", "semantic-empty"),
                    artifact_refs=("b" * 64,),
                ),
            ),
        }
    )
    assert (
        EvidenceBundle.create(requirement_set, payload).structurally_complete(requirement_set) == ()
    )


def test_clause_capture_ref_outside_linked_observation_union_is_rejected() -> None:
    evidence = bundle()
    capture_refs = ("a" * 64, "b" * 64, "c" * 64)
    payload = evidence.payload.model_copy(
        update={
            "captures": tuple(
                CaptureRef(
                    sha256=ref,
                    media_type="application/vnd.tcpdump.pcap",
                    size=12,
                    role=CaptureRole.PACKET_CAPTURE,
                )
                for ref in capture_refs
            ),
            "observations": (
                Observation(
                    check_id="semantic", result=Result.PASS, artifact_refs=capture_refs[:2]
                ),
            ),
            "clause_coverage": (
                ClauseCoverage(
                    clause_id="EVPN_M1",
                    axis=CoverageAxis.CAPABILITY,
                    check_ids=("semantic",),
                    artifact_refs=(capture_refs[2],),
                ),
            ),
        }
    )
    findings = evidence.model_copy(update={"payload": payload}).structurally_complete(
        requirements()
    )
    assert StructuralFindingCode.MISSING_CAPTURE_LINK in {finding.code for finding in findings}


def test_persistence_is_atomic_create_only_and_rejects_unsafe_roots(tmp_path: Path) -> None:
    evidence = bundle()
    saved = persist_bundle(tmp_path, evidence)
    assert saved.name == f"{evidence.canonical_hash}.json"
    assert saved.read_bytes() == evidence.canonical_bytes
    with pytest.raises(FileExistsError):
        persist_bundle(tmp_path, evidence)
    with pytest.raises(ValueError, match="absolute"):
        persist_bundle(Path("relative"), evidence)
    with pytest.raises(ValueError, match="traversal"):
        persist_bundle(tmp_path / "..", evidence)
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        persist_bundle(link, evidence)
    assert not list(tmp_path.glob("*.tmp"))


def test_persistence_fails_closed_without_no_follow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr("wireproof_evidence.bundle.os.O_NOFOLLOW")
    with pytest.raises(UnsupportedPlatformError):
        persist_bundle(tmp_path, bundle())


def test_persistence_fails_closed_without_no_follow_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("wireproof_evidence.bundle.os.supports_follow_symlinks", frozenset())
    with pytest.raises(UnsupportedPlatformError):
        persist_bundle(tmp_path, bundle())
