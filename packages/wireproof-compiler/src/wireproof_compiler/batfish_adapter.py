"""Dependency-free, advisory-only contract for a future Batfish integration.

This module intentionally contains neither PyBatfish nor execution code.  It
models evidence received from an executor, but that evidence is never release
authority: callers must use the independent release policy for promotion.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _canonical_json(value: object) -> str:
    """Encode JSON-compatible input once, with a deterministic representation."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as error:
        raise ValueError("value must be JSON-compatible") from error


def _answer_hash(answer_json: str) -> str:
    return hashlib.sha256(answer_json.encode("utf-8")).hexdigest()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ParserStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED = "MALFORMED"


class QueryStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class QueryKind(StrEnum):
    BGP_SESSION_STATUS = "BGP_SESSION_STATUS"
    ROUTE_REACHABILITY = "ROUTE_REACHABILITY"
    EVPN_VXLAN_CONFIGURATION = "EVPN_VXLAN_CONFIGURATION"


class ConfigFile(_StrictModel):
    path: str = Field(min_length=1)
    content: str


class ParserCoverage(_StrictModel):
    path: str = Field(min_length=1)
    status: ParserStatus
    reason: str = ""

    @model_validator(mode="after")
    def require_reason_for_non_supported(self) -> ParserCoverage:
        if self.status is not ParserStatus.SUPPORTED and not self.reason:
            raise ValueError("non-supported parser coverage requires a reason")
        return self


class SnapshotRef(_StrictModel):
    """Immutable content identity for one named snapshot."""

    name: str = Field(pattern=r"^(baseline|candidate)$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SnapshotRequest(_StrictModel):
    name: str = Field(pattern=r"^(baseline|candidate)$")
    configs: tuple[ConfigFile, ...]
    parser_coverage: tuple[ParserCoverage, ...]

    @model_validator(mode="after")
    def complete_deterministic_snapshot(self) -> SnapshotRequest:
        paths = tuple(config.path for config in self.configs)
        coverage_paths = tuple(coverage.path for coverage in self.parser_coverage)
        if not paths or tuple(sorted(paths)) != paths or len(set(paths)) != len(paths):
            raise ValueError("snapshot configs must be non-empty, sorted, and unique")
        if coverage_paths != paths:
            raise ValueError("parser coverage must exactly cover sorted snapshot configs")
        return self

    @property
    def canonical_hash(self) -> str:
        return _answer_hash(_canonical_json(self.model_dump(mode="json")))

    @property
    def snapshot_ref(self) -> SnapshotRef:
        return SnapshotRef(name=self.name, sha256=self.canonical_hash)


class QueryRequest(_StrictModel):
    """One query with a stable public identifier and immutable JSON parameters."""

    query_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    kind: QueryKind
    parameters: Any

    @model_validator(mode="before")
    @classmethod
    def canonicalize_parameters(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and "parameters" in value:
            value = dict(value)
            value["parameters"] = _canonical_json(value["parameters"])
        return value

    @model_validator(mode="after")
    def require_nonempty_parameter_object(self) -> QueryRequest:
        if not isinstance(self.parameters, str):
            raise ValueError("query parameters must be canonical JSON")
        try:
            parsed = json.loads(self.parameters)
        except json.JSONDecodeError as error:  # pragma: no cover - validator normalizes input
            raise ValueError("parameters must be canonical JSON") from error
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("query parameters must be a non-empty JSON object")
        if self.parameters != _canonical_json(parsed):
            raise ValueError("query parameters must be canonical JSON")
        return self

    @property
    def canonical_hash(self) -> str:
        return _answer_hash(_canonical_json(self.model_dump(mode="json")))


class QueryPlan(_StrictModel):
    """The complete, ordered query plan expected for each snapshot."""

    queries: tuple[QueryRequest, ...]

    @model_validator(mode="after")
    def require_nonempty_unique_query_ids(self) -> QueryPlan:
        identifiers = tuple(query.query_id for query in self.queries)
        if not identifiers or len(set(identifiers)) != len(identifiers):
            raise ValueError("query plan must have non-empty unique query IDs")
        if tuple(sorted(identifiers)) != identifiers:
            raise ValueError("query plan IDs must be sorted canonically")
        return self

    @property
    def query_ids(self) -> tuple[str, ...]:
        return tuple(query.query_id for query in self.queries)


class QueryResult(_StrictModel):
    query_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,127}$")
    status: QueryStatus
    answer: Any = None
    answer_hash: str | None = None
    reason: str = ""
    provenance: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def canonicalize_answer(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and value.get("answer") is not None:
            value = dict(value)
            value["answer"] = _canonical_json(value["answer"])
        return value

    @model_validator(mode="after")
    def validate_answer_and_status(self) -> QueryResult:
        if self.status in (QueryStatus.ERROR, QueryStatus.UNKNOWN) and not self.reason:
            raise ValueError("error or unknown query result requires a reason")
        if self.answer is None:
            if self.answer_hash is not None:
                raise ValueError("null answer must not have an answer hash")
            return self
        if not isinstance(self.answer, str):
            raise ValueError("answer must be canonical JSON")
        try:
            parsed = json.loads(self.answer)
        except json.JSONDecodeError as error:  # pragma: no cover - validator normalizes input
            raise ValueError("answer must be canonical JSON") from error
        if self.answer != _canonical_json(parsed):
            raise ValueError("answer must be canonical JSON")
        expected_hash = _answer_hash(self.answer)
        if self.answer_hash != expected_hash:
            raise ValueError("answer hash must be the canonical answer JSON hash")
        return self


class SnapshotResult(_StrictModel):
    request: SnapshotRequest
    snapshot_ref: SnapshotRef
    query_plan: QueryPlan
    queries: tuple[QueryResult, ...]
    adapter_provenance: str = Field(min_length=1)

    @model_validator(mode="after")
    def exact_query_result_coverage(self) -> SnapshotResult:
        if self.snapshot_ref != self.request.snapshot_ref:
            raise ValueError("snapshot result reference must match the request content identity")
        actual = tuple(result.query_id for result in self.queries)
        if len(set(actual)) != len(actual) or set(actual) != set(self.query_plan.query_ids):
            raise ValueError(
                "snapshot results must have exactly one result for every planned query"
            )
        return self


class BatfishAdapter(Protocol):
    """Boundary for a future executor; its output remains advisory evidence."""

    def execute(self, request: SnapshotRequest, query_plan: QueryPlan) -> SnapshotResult: ...


class FakeBatfishAdapter:
    """Synthetic fixture adapter, deliberately unsuitable as a Batfish executor."""

    provenance = "wireproof.fake-batfish-adapter/v2;synthetic=true"

    def __init__(self, fixtures: Mapping[str, tuple[QueryStatus, object | None, str]]) -> None:
        self._fixtures = dict(fixtures)

    def execute(self, request: SnapshotRequest, query_plan: QueryPlan) -> SnapshotResult:
        results: list[QueryResult] = []
        for query in query_plan.queries:
            status, answer, reason = self._fixtures.get(
                query.query_id, (QueryStatus.UNKNOWN, None, "missing synthetic fixture")
            )
            results.append(
                QueryResult(
                    query_id=query.query_id,
                    status=status,
                    answer=answer,
                    answer_hash=None if answer is None else _answer_hash(_canonical_json(answer)),
                    reason=reason,
                    provenance=self.provenance,
                )
            )
        return SnapshotResult(
            request=request,
            snapshot_ref=request.snapshot_ref,
            query_plan=query_plan,
            queries=tuple(results),
            adapter_provenance=self.provenance,
        )


class ComparisonStatus(StrEnum):
    MATCH = "MATCH"
    DELTA = "DELTA"
    DEBT = "DEBT"


class QueryComparison(_StrictModel):
    query_id: str
    status: ComparisonStatus
    baseline: QueryResult | None = None
    candidate: QueryResult | None = None
    debt: tuple[str, ...] = ()
    reason: str = ""


class ComparisonCoverage(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class ComparisonResult(_StrictModel):
    coverage: ComparisonCoverage
    comparisons: tuple[QueryComparison, ...]


def _query_debt(label: str, result: QueryResult | None, parser_debt: bool) -> list[str]:
    if result is None:
        return [f"{label} result missing"]
    debt: list[str] = []
    if result.status in (QueryStatus.UNKNOWN, QueryStatus.ERROR):
        debt.append(f"{label} result is {result.status}")
    if result.answer is None:
        debt.append(f"{label} answer is null")
    if parser_debt:
        debt.append(f"{label} parser coverage is not supported")
    return debt


def _validate_comparison_inputs(baseline: SnapshotResult, candidate: SnapshotResult) -> None:
    """Require two distinct, correctly labelled snapshot evidences."""
    if baseline is candidate:
        raise ValueError("baseline and candidate snapshot results must be distinct")
    if baseline.snapshot_ref != baseline.request.snapshot_ref:
        raise ValueError(
            "baseline snapshot result reference must match the request content identity"
        )
    if candidate.snapshot_ref != candidate.request.snapshot_ref:
        raise ValueError(
            "candidate snapshot result reference must match the request content identity"
        )
    if baseline.request.name != "baseline" or baseline.snapshot_ref.name != "baseline":
        raise ValueError("baseline snapshot result must have the baseline role")
    if candidate.request.name != "candidate" or candidate.snapshot_ref.name != "candidate":
        raise ValueError("candidate snapshot result must have the candidate role")
    if (
        baseline.snapshot_ref == candidate.snapshot_ref
        or baseline.snapshot_ref.sha256 == candidate.snapshot_ref.sha256
    ):
        raise ValueError("baseline and candidate snapshot references must be distinct")


def compare_snapshots(baseline: SnapshotResult, candidate: SnapshotResult) -> ComparisonResult:
    """Compare plans exactly and retain every uncertainty as per-query debt."""
    _validate_comparison_inputs(baseline, candidate)
    baseline_ids = set(baseline.query_plan.query_ids)
    candidate_ids = set(candidate.query_plan.query_ids)
    expected_ids = tuple(sorted(baseline_ids | candidate_ids))
    base = {result.query_id: result for result in baseline.queries}
    cand = {result.query_id: result for result in candidate.queries}
    base_parser_debt = any(
        item.status is not ParserStatus.SUPPORTED for item in baseline.request.parser_coverage
    )
    candidate_parser_debt = any(
        item.status is not ParserStatus.SUPPORTED for item in candidate.request.parser_coverage
    )
    comparisons: list[QueryComparison] = []
    for query_id in expected_ids:
        before, after = base.get(query_id), cand.get(query_id)
        debt = _query_debt("baseline", before, base_parser_debt)
        debt.extend(_query_debt("candidate", after, candidate_parser_debt))
        if query_id not in baseline_ids or query_id not in candidate_ids:
            debt.append("query plan is asymmetric")
        if debt:
            comparisons.append(
                QueryComparison(
                    query_id=query_id,
                    status=ComparisonStatus.DEBT,
                    baseline=before,
                    candidate=after,
                    debt=tuple(debt),
                    reason="advisory evidence debt",
                )
            )
        elif before is not None and after is not None and (
            before.status,
            before.answer_hash,
            before.reason,
        ) == (
            after.status,
            after.answer_hash,
            after.reason,
        ):
            comparisons.append(
                QueryComparison(
                    query_id=query_id,
                    status=ComparisonStatus.MATCH,
                    baseline=before,
                    candidate=after,
                )
            )
        else:
            comparisons.append(
                QueryComparison(
                    query_id=query_id,
                    status=ComparisonStatus.DELTA,
                    baseline=before,
                    candidate=after,
                    reason="baseline/candidate query result differs",
                )
            )
    coverage = (
        ComparisonCoverage.COMPLETE
        if baseline_ids == candidate_ids
        else ComparisonCoverage.INCOMPLETE
    )
    return ComparisonResult(coverage=coverage, comparisons=tuple(comparisons))


class AssessmentAuthority(StrEnum):
    ADVISORY = "ADVISORY"


class BatfishAdvisoryAssessment(_StrictModel):
    assessment_authority: AssessmentAuthority = AssessmentAuthority.ADVISORY
    release_eligible: bool = False
    comparison: ComparisonResult
    debt: tuple[str, ...]

    @model_validator(mode="after")
    def remain_advisory_only(self) -> BatfishAdvisoryAssessment:
        if self.assessment_authority is not AssessmentAuthority.ADVISORY or self.release_eligible:
            raise ValueError("Batfish assessments are advisory and never release-eligible")
        return self


def assess_batfish_advisory(
    baseline: SnapshotResult, candidate: SnapshotResult
) -> BatfishAdvisoryAssessment:
    """Create visible static-analysis debt without making a promotion decision."""
    comparison = compare_snapshots(baseline, candidate)
    debt = sorted(
        f"{item.query_id}: {reason}" for item in comparison.comparisons for reason in item.debt
    )
    if comparison.coverage is ComparisonCoverage.INCOMPLETE:
        debt.append("query plan coverage is incomplete")
    return BatfishAdvisoryAssessment(comparison=comparison, debt=tuple(debt))
