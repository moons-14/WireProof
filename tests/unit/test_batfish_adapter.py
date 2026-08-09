import hashlib

import pytest
from pydantic import ValidationError

from wireproof_compiler import (  # isort: skip
    AssessmentAuthority,
    ComparisonCoverage,
    ComparisonStatus,
    ConfigFile,
    FakeBatfishAdapter,
    ParserStatus,
    ParserCoverage,
    QueryKind,
    QueryPlan,
    QueryRequest,
    QueryResult,
    QueryStatus,
    SnapshotRef,
    SnapshotRequest,
    SnapshotResult,
    assess_batfish_advisory,
    compare_snapshots,
)


def _snapshot(
    name: str = "baseline", *, parser: ParserStatus = ParserStatus.SUPPORTED
) -> SnapshotRequest:
    coverage = ParserCoverage(
        path="configs/leaf1.conf",
        status=parser,
        reason="" if parser is ParserStatus.SUPPORTED else "unsupported syntax",
    )
    return SnapshotRequest(
        name=name,
        configs=(ConfigFile(path="configs/leaf1.conf", content="router bgp 65001"),),
        parser_coverage=(coverage,),
    )


def _query(query_id: str = "bgp.leaf1") -> QueryRequest:
    return QueryRequest(
        query_id=query_id, kind=QueryKind.BGP_SESSION_STATUS, parameters={"node": "leaf1"}
    )


def _plan(*queries: QueryRequest) -> QueryPlan:
    return QueryPlan(queries=tuple(queries))


def test_query_plan_and_parameters_are_canonical_and_immutable() -> None:
    unordered = QueryRequest(
        query_id="route.a", kind=QueryKind.ROUTE_REACHABILITY, parameters={"b": [True, 1], "a": 1}
    )
    ordered = QueryRequest(
        query_id="route.a", kind=QueryKind.ROUTE_REACHABILITY, parameters={"a": 1, "b": [True, 1]}
    )
    assert unordered.parameters == '{"a":1,"b":[true,1]}'
    assert unordered.canonical_hash == ordered.canonical_hash
    with pytest.raises(ValidationError):
        unordered.parameters = "{}"
    with pytest.raises(ValidationError, match="unique query IDs"):
        _plan(_query(), _query())
    with pytest.raises(ValidationError, match="sorted canonically"):
        _plan(_query("z"), _query("a"))


def test_snapshot_reference_is_validated_and_distinct() -> None:
    baseline, candidate = _snapshot(), _snapshot("candidate")
    assert baseline.snapshot_ref.sha256 == baseline.canonical_hash
    assert baseline.snapshot_ref != candidate.snapshot_ref
    with pytest.raises(ValidationError):
        SnapshotRef(name="baseline", sha256="A" * 64)


def test_results_require_exact_plan_coverage_and_answer_hash_only() -> None:
    query = _query()
    result = QueryResult(
        query_id=query.query_id,
        status=QueryStatus.PASS,
        answer={"rows": [1, 2]},
        answer_hash=hashlib.sha256(b'{"rows":[1,2]}').hexdigest(),
        provenance="fixture",
    )
    assert result.answer == '{"rows":[1,2]}'
    assert result.answer_hash == hashlib.sha256(result.answer.encode()).hexdigest()
    with pytest.raises(ValidationError, match="answer hash"):
        QueryResult(
            query_id=query.query_id,
            status=QueryStatus.PASS,
            answer={},
            answer_hash="0" * 64,
            provenance="x",
        )
    with pytest.raises(ValidationError, match="null answer"):
        QueryResult(
            query_id=query.query_id,
            status=QueryStatus.PASS,
            answer_hash="0" * 64,
            provenance="x",
        )
    with pytest.raises(ValidationError, match="exactly one result"):
        SnapshotResult(
            request=_snapshot(),
            snapshot_ref=_snapshot().snapshot_ref,
            query_plan=_plan(query),
            queries=(),
            adapter_provenance="fixture",
        )


def test_fake_adapter_is_advisory_for_every_result_status() -> None:
    query = _query()
    for status in QueryStatus:
        reason = "fixture" if status in (QueryStatus.ERROR, QueryStatus.UNKNOWN) else ""
        result = FakeBatfishAdapter({query.query_id: (status, {"ok": True}, reason)}).execute(
            _snapshot(), _plan(query)
        )
        candidate = FakeBatfishAdapter({query.query_id: (status, {"ok": True}, reason)}).execute(
            _snapshot("candidate"), _plan(query)
        )
        assessment = assess_batfish_advisory(result, candidate)
        assert assessment.assessment_authority is AssessmentAuthority.ADVISORY
        assert assessment.release_eligible is False


def test_comparison_rejects_same_result_or_wrong_snapshot_roles() -> None:
    query = _query()
    baseline = FakeBatfishAdapter({query.query_id: (QueryStatus.PASS, {"ok": True}, "")}).execute(
        _snapshot(), _plan(query)
    )
    candidate = FakeBatfishAdapter({query.query_id: (QueryStatus.PASS, {"ok": True}, "")}).execute(
        _snapshot("candidate"), _plan(query)
    )
    second_baseline = FakeBatfishAdapter(
        {query.query_id: (QueryStatus.PASS, {"ok": True}, "")}
    ).execute(_snapshot(), _plan(query))

    with pytest.raises(ValueError, match="distinct"):
        compare_snapshots(baseline, baseline)
    with pytest.raises(ValueError, match="candidate role"):
        compare_snapshots(baseline, second_baseline)
    with pytest.raises(ValueError, match="baseline role"):
        compare_snapshots(candidate, baseline)
    same_ref = candidate.snapshot_ref.model_copy(update={"sha256": baseline.snapshot_ref.sha256})
    same_ref_candidate = candidate.model_copy(update={"snapshot_ref": same_ref})
    with pytest.raises(ValueError, match="candidate snapshot result reference"):
        compare_snapshots(baseline, same_ref_candidate)
    forged_ref_candidate = candidate.model_copy(
        update={
            "snapshot_ref": candidate.snapshot_ref.model_copy(
                update={"sha256": "f" * 64}
            )
        }
    )
    with pytest.raises(ValueError, match="candidate snapshot result reference"):
        compare_snapshots(baseline, forged_ref_candidate)
    with pytest.raises(ValueError, match="distinct"):
        assess_batfish_advisory(baseline, baseline)


def test_comparison_records_per_query_debt_for_unknown_null_parser_and_asymmetry() -> None:
    baseline_query, candidate_query = _query("bgp.leaf1"), _query("route.leaf1")
    baseline = FakeBatfishAdapter(
        {baseline_query.query_id: (QueryStatus.PASS, {"sessions": 1}, "")}
    ).execute(_snapshot(), _plan(baseline_query))
    candidate = FakeBatfishAdapter(
        {candidate_query.query_id: (QueryStatus.UNKNOWN, None, "parser gap")}
    ).execute(_snapshot("candidate", parser=ParserStatus.UNSUPPORTED), _plan(candidate_query))
    comparison = compare_snapshots(baseline, candidate)
    assert comparison.coverage is ComparisonCoverage.INCOMPLETE
    assert {item.query_id for item in comparison.comparisons} == {"bgp.leaf1", "route.leaf1"}
    assert all(item.status is ComparisonStatus.DEBT for item in comparison.comparisons)
    assert any("asymmetric" in debt for item in comparison.comparisons for debt in item.debt)
    assert any("UNKNOWN" in debt for item in comparison.comparisons for debt in item.debt)
    assert any("null" in debt for item in comparison.comparisons for debt in item.debt)
    assessment = assess_batfish_advisory(baseline, candidate)
    assert assessment.debt


def test_answer_hash_does_not_depend_on_snapshot_metadata() -> None:
    query = _query()
    fixtures = {query.query_id: (QueryStatus.PASS, {"sessions": 1}, "")}
    baseline = FakeBatfishAdapter(fixtures).execute(_snapshot(), _plan(query))
    candidate = FakeBatfishAdapter(fixtures).execute(_snapshot("candidate"), _plan(query))
    assert baseline.snapshot_ref.sha256 != candidate.snapshot_ref.sha256
    assert baseline.queries[0].answer_hash == candidate.queries[0].answer_hash
