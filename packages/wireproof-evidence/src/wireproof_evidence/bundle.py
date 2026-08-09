"""Canonical, create-only persistence for machine-readable evidence bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from wireproof_evidence import ExecutionMode, Result

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMMUTABLE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_FLOATING_VERSION_ALIASES = {
    "latest",
    "mutable",
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
}


def _validate_immutable_version(value: str) -> str:
    if (
        not _IMMUTABLE_VERSION.fullmatch(value)
        or not any(character.isdigit() for character in value)
        or value.casefold() in _FLOATING_VERSION_ALIASES
    ):
        raise ValueError("version must be a non-floating immutable version")
    return value


def canonical_json_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    """Return the only byte representation accepted for bundle identities."""
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _canonical_hash(value: BaseModel | dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class CoverageAxis(StrEnum):
    CAPABILITY = "capability"
    INTENT_CLAUSE = "intent_clause"
    INVARIANT = "invariant"
    POLICY_BRANCH = "policy_branch"
    EVPN_ROUTE_TYPE = "evpn_route_type"
    PACKET_CLASS = "packet_class"
    STATE_TRANSITION = "state_transition"
    FAILURE_SCENARIO = "failure_scenario"
    TARGET_COMMAND_PROVENANCE = "target_command_provenance"


class CaptureRole(StrEnum):
    PACKET_CAPTURE = "packet_capture"
    LOG = "log"
    CONFIG = "config"
    OBSERVATION = "observation"


class CheckPhase(StrEnum):
    SEMANTIC = "semantic"
    REFERENCE = "reference"
    TARGET = "target"


class EvidenceOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    change_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    producer: str = Field(min_length=1)


class CaptureRef(BaseModel):
    """A content-addressed external capture; bytes never live in the envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    sha256: str
    media_type: str = Field(min_length=1)
    size: int = Field(ge=0)
    role: CaptureRole

    @field_validator("sha256")
    @classmethod
    def lowercase_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value


_OCI_REFERENCE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ImageProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reference: str = Field(min_length=1)
    digest: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)

    @field_validator("version")
    @classmethod
    def immutable_version(cls, value: str) -> str:
        return _validate_immutable_version(value)

    @field_validator("reference")
    @classmethod
    def oci_reference(cls, value: str) -> str:
        if not _OCI_REFERENCE.fullmatch(value):
            raise ValueError("reference must be a canonical OCI repository reference")
        return value

    @field_validator("digest")
    @classmethod
    def oci_digest(cls, value: str) -> str:
        if not _OCI_DIGEST.fullmatch(value):
            raise ValueError("digest must be a sha256 OCI digest")
        return value


class ComponentProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    digest: str = Field(min_length=1)

    @field_validator("version")
    @classmethod
    def immutable_version(cls, value: str) -> str:
        return _validate_immutable_version(value)

    @field_validator("digest")
    @classmethod
    def oci_digest(cls, value: str) -> str:
        if not _OCI_DIGEST.fullmatch(value):
            raise ValueError("digest must be a sha256 OCI digest")
        return value


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    check_id: str = Field(min_length=1)
    result: Result
    artifact_refs: tuple[str, ...] = ()


class DeviationRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1)
    classification: str = Field(min_length=1)
    digest: str = Field(min_length=1)


class ClauseCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    clause_id: str = Field(min_length=1)
    axis: CoverageAxis
    check_ids: tuple[str, ...] = ()
    artifact_refs: tuple[str, ...] = ()


class CommandKind(StrEnum):
    DEPLOY = "DEPLOY"
    INSPECT = "INSPECT"
    DESTROY = "DESTROY"
    CAPTURE = "CAPTURE"
    OBSERVE = "OBSERVE"


class CommandTranscript(BaseModel):
    """Closed command metadata; command arguments are deliberately never recorded."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: CommandKind


class RequiredCheck(BaseModel):
    """A closed evidence obligation; applicability is explicit, never inferred."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    check_id: str = Field(min_length=1)
    phase: CheckPhase
    applicable: bool


class CheckResult(BaseModel):
    """The one result emitted for a declared promotion check."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    check_id: str = Field(min_length=1)
    phase: CheckPhase
    result: Result
    reason: str | None = None


class EvidenceRequirements(BaseModel):
    """Evidence requirements, intentionally hashed independently of observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    required_coverage: tuple[CoverageAxis, ...] = tuple(CoverageAxis)
    required_provenance_clauses: tuple[str, ...] = ()
    checks: tuple[RequiredCheck, ...] = ()

    @field_validator("required_provenance_clauses")
    @classmethod
    def unique_nonempty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value) or len(set(value)) != len(value):
            raise ValueError("requirements must contain unique nonempty values")
        return value

    @field_validator("checks")
    @classmethod
    def unique_check_ids(cls, value: tuple[RequiredCheck, ...]) -> tuple[RequiredCheck, ...]:
        if len({check.check_id for check in value}) != len(value):
            raise ValueError("required checks must have unique check_id values")
        return value

    @field_validator("required_coverage")
    @classmethod
    def unique_axes(cls, value: tuple[CoverageAxis, ...]) -> tuple[CoverageAxis, ...]:
        if len(set(value)) != len(value):
            raise ValueError("required coverage axes must be unique")
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def canonical_hash(self) -> str:
        return _canonical_hash(self)


class StructuralFindingCode(StrEnum):
    REQUIREMENTS_HASH_MISMATCH = "requirements_hash_mismatch"
    MISSING_CHECK_RESULT = "missing_check_result"
    CHECK_PHASE_MISMATCH = "check_phase_mismatch"
    CHECK_RESULT_NOT_PASS = "check_result_not_pass"
    MISSING_COVERAGE_AXIS = "missing_coverage_axis"
    MISSING_CLAUSE_COVERAGE = "missing_clause_coverage"
    MISSING_PASSING_OBSERVATION = "missing_passing_observation"
    MISSING_CAPTURE_LINK = "missing_capture_link"
    UNKNOWN_CAPTURE_REFERENCE = "unknown_capture_reference"
    MISSING_PROVENANCE_CLAUSE = "missing_provenance_clause"
    MISSING_IMAGE_PROVENANCE = "missing_image_provenance"
    MISSING_COMPONENT_PROVENANCE = "missing_component_provenance"


class StructuralFinding(BaseModel):
    """A non-promotional description of one missing structural evidence link."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    code: StructuralFindingCode
    axis: CoverageAxis | None = None
    check_id: str | None = None
    detail: str | None = None


class EvidenceBundlePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ownership: EvidenceOwnership
    records: tuple[CheckResult, ...] = ()
    coverage: tuple[CoverageAxis, ...] = ()
    provenance_clauses: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    captures: tuple[CaptureRef, ...] = ()
    transcript: tuple[CommandTranscript, ...] = ()
    execution_mode: ExecutionMode = ExecutionMode.FAKE
    images: tuple[ImageProvenance, ...] = ()
    components: tuple[ComponentProvenance, ...] = ()
    observations: tuple[Observation, ...] = ()
    deviations: tuple[DeviationRef, ...] = ()
    clause_coverage: tuple[ClauseCoverage, ...] = ()

    @field_validator("unknowns")
    @classmethod
    def unique_unknowns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value) or len(set(value)) != len(value):
            raise ValueError("unknowns must be unique nonempty values")
        return value

    @field_validator("provenance_clauses")
    @classmethod
    def unique_provenance(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value) or len(set(value)) != len(value):
            raise ValueError("provenance clauses must be unique nonempty values")
        return value


class EvidenceBundle(BaseModel):
    """An immutable envelope binding a requirements hash to observed payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["wireproof.evidence.bundle.v1"] = "wireproof.evidence.bundle.v1"
    requirements: EvidenceRequirements
    requirements_hash: str
    payload: EvidenceBundlePayload

    @field_validator("requirements_hash")
    @classmethod
    def valid_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("requirements_hash must be a lowercase sha256")
        return value

    @model_validator(mode="after")
    def binds_requirements(self) -> EvidenceBundle:
        if self.requirements_hash != self.requirements.canonical_hash:
            raise ValueError("requirements_hash does not bind requirements")
        requirements = {check.check_id: check for check in self.requirements.checks}
        seen = {record.check_id for record in self.payload.records}
        if len(seen) != len(self.payload.records):
            raise ValueError("bundle payload must not duplicate check results")
        observation_ids = {observation.check_id for observation in self.payload.observations}
        if len(observation_ids) != len(self.payload.observations):
            raise ValueError("bundle payload must not duplicate observation IDs")
        undeclared = seen - requirements.keys()
        if undeclared:
            raise ValueError("bundle result references an undeclared check")
        for record in self.payload.records:
            check = requirements[record.check_id]
            if record.phase is not check.phase:
                raise ValueError("check result phase does not match requirement")
        return self

    @classmethod
    def create(
        cls, requirements: EvidenceRequirements, payload: EvidenceBundlePayload
    ) -> EvidenceBundle:
        return cls(
            requirements=requirements,
            requirements_hash=requirements.canonical_hash,
            payload=payload,
        )

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    @property
    def canonical_hash(self) -> str:
        return _canonical_hash(self)

    def structurally_complete(
        self, requirements: EvidenceRequirements
    ) -> tuple[StructuralFinding, ...]:
        """Return every missing required evidence link; this makes no promotion claim."""
        findings: list[StructuralFinding] = []
        if self.requirements_hash != requirements.canonical_hash:
            findings.append(
                StructuralFinding(code=StructuralFindingCode.REQUIREMENTS_HASH_MISMATCH)
            )
            return tuple(findings)

        results = {record.check_id: record for record in self.payload.records}
        required_checks = {check.check_id: check for check in requirements.checks}
        for check in requirements.checks:
            if not check.applicable:
                continue
            record = results.get(check.check_id)
            if record is None:
                findings.append(
                    StructuralFinding(
                        code=StructuralFindingCode.MISSING_CHECK_RESULT, check_id=check.check_id
                    )
                )
            elif record.phase is not check.phase:
                findings.append(
                    StructuralFinding(
                        code=StructuralFindingCode.CHECK_PHASE_MISMATCH, check_id=check.check_id
                    )
                )
            elif record.result is not Result.PASS:
                findings.append(
                    StructuralFinding(
                        code=StructuralFindingCode.CHECK_RESULT_NOT_PASS, check_id=check.check_id
                    )
                )

        if not self.payload.images:
            findings.append(StructuralFinding(code=StructuralFindingCode.MISSING_IMAGE_PROVENANCE))
        if not self.payload.components:
            findings.append(
                StructuralFinding(code=StructuralFindingCode.MISSING_COMPONENT_PROVENANCE)
            )

        captures = {capture.sha256 for capture in self.payload.captures}
        observations = {
            observation.check_id: observation for observation in self.payload.observations
        }
        clauses_by_axis: dict[CoverageAxis, list[ClauseCoverage]] = {}
        for clause in self.payload.clause_coverage:
            clauses_by_axis.setdefault(clause.axis, []).append(clause)
        for axis in requirements.required_coverage:
            if axis not in self.payload.coverage:
                findings.append(
                    StructuralFinding(code=StructuralFindingCode.MISSING_COVERAGE_AXIS, axis=axis)
                )
            clauses = clauses_by_axis.get(axis, [])
            if not clauses:
                findings.append(
                    StructuralFinding(code=StructuralFindingCode.MISSING_CLAUSE_COVERAGE, axis=axis)
                )
                continue
            for clause in clauses:
                linked = [observations.get(check_id) for check_id in clause.check_ids]
                passing = [
                    item
                    for item in linked
                    if item is not None
                    and item.result is Result.PASS
                    and (required := required_checks.get(item.check_id)) is not None
                    and required.applicable
                    and (record := results.get(item.check_id)) is not None
                    and record.result is Result.PASS
                ]
                if not passing:
                    findings.append(
                        StructuralFinding(
                            code=StructuralFindingCode.MISSING_PASSING_OBSERVATION, axis=axis
                        )
                    )
                    continue
                observation_refs = [
                    ref for observation in passing for ref in observation.artifact_refs
                ]
                if not set(observation_refs).issubset(captures):
                    findings.append(
                        StructuralFinding(
                            code=StructuralFindingCode.UNKNOWN_CAPTURE_REFERENCE, axis=axis
                        )
                    )
                if not clause.artifact_refs:
                    findings.append(
                        StructuralFinding(
                            code=StructuralFindingCode.MISSING_CAPTURE_LINK, axis=axis
                        )
                    )
                elif not set(clause.artifact_refs).issubset(captures):
                    findings.append(
                        StructuralFinding(
                            code=StructuralFindingCode.UNKNOWN_CAPTURE_REFERENCE, axis=axis
                        )
                    )
                elif not set(clause.artifact_refs).issubset(observation_refs):
                    findings.append(
                        StructuralFinding(
                            code=StructuralFindingCode.MISSING_CAPTURE_LINK, axis=axis
                        )
                    )
        for provenance_clause in requirements.required_provenance_clauses:
            if provenance_clause not in self.payload.provenance_clauses:
                findings.append(
                    StructuralFinding(
                        code=StructuralFindingCode.MISSING_PROVENANCE_CLAUSE,
                        detail=provenance_clause,
                    )
                )
        return tuple(findings)


class UnsupportedPlatformError(RuntimeError):
    """Safe evidence persistence needs no-follow directory-FD primitives."""


def _require_safe_persistence_primitives() -> None:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "supports_follow_symlinks")
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.link not in os.supports_follow_symlinks
        or os.unlink not in os.supports_dir_fd
    ):
        raise UnsupportedPlatformError("safe evidence persistence is unsupported on this platform")


def _open_safe_root(root: Path) -> int:
    """Open each root component relative to its already verified parent descriptor."""
    if not root.is_absolute():
        raise ValueError("evidence root must be an absolute path")
    if ".." in root.parts:
        raise ValueError("evidence root must not contain traversal components")
    _require_safe_persistence_primitives()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(root.anchor, flags)
    try:
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise ValueError("evidence root must be an existing non-symlink directory") from error
    return descriptor


def persist_bundle(root: Path, bundle: EvidenceBundle) -> Path:
    """Atomically create a bundle by hash without following or replacing paths."""
    name = f"{bundle.canonical_hash}.json"
    data = bundle.canonical_bytes
    temp_name = f".{name}.{uuid.uuid4().hex}.tmp"
    _require_safe_persistence_primitives()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    directory = _open_safe_root(root)
    descriptor = -1
    try:
        descriptor = os.open(temp_name, flags, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_name, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.fsync(directory)
        return root / name
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temp_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def records_with_results(records: Iterable[CheckResult], result: Result) -> tuple[CheckResult, ...]:
    """Small typed query helper for consumers that need UNKNOWN evidence."""
    return tuple(record for record in records if record.result is result)
