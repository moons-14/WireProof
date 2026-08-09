from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Result(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    change_id: str
    result: Result
    semantic_ir_hash: str
    reason: str | None = None
    provenance_clauses: tuple[str, ...] = ()
