"""Immutable, append-only evidence records for WireProof runs."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Result(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExecutionMode(StrEnum):
    FAKE = "FAKE"
    REAL = "REAL"


class ReasonCode(StrEnum):
    LAB_ENVIRONMENT_UNAVAILABLE = "LAB_ENVIRONMENT_UNAVAILABLE"
    IMAGE_REFERENCE_INVALID = "IMAGE_REFERENCE_INVALID"
    TRANSCRIPT_MISMATCH = "TRANSCRIPT_MISMATCH"
    DEPLOY_FAILED = "DEPLOY_FAILED"
    STATUS_FAILED = "STATUS_FAILED"
    TEST_TIMEOUT = "TEST_TIMEOUT"
    TEST_FAILED = "TEST_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    FAKE_EXECUTION = "FAKE_EXECUTION"
    REQUIRED_ORACLE_UNKNOWN = "REQUIRED_ORACLE_UNKNOWN"
    REAL_LAB_UNVERIFIED = "REAL_LAB_UNVERIFIED"


class EvidenceRecord(BaseModel):
    """A frozen record keyed by (change_id, run_id); callers append, never mutate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    change_id: str = Field(min_length=1)
    run_id: str = Field(default="lab-doctor", min_length=1)
    result: Result
    semantic_ir_hash: str
    reason_code: ReasonCode | None = None
    reason: str | None = None
    execution_mode: ExecutionMode = ExecutionMode.FAKE
    artifact_hashes: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    attempts: int = Field(default=0, ge=0)
    elapsed: float | None = Field(default=None, ge=0)
    history: tuple[str, ...] = ()
    coverage: tuple[str, ...] = ()
    provenance_clauses: tuple[str, ...] = ()
    image_reference: str | None = None
    component_versions: tuple[str, ...] = ()
    command_provenance: tuple[tuple[str, ...], ...] = ()

    @property
    def promotion_allowed(self) -> bool:
        return self.execution_mode is ExecutionMode.REAL and self.result is Result.PASS
