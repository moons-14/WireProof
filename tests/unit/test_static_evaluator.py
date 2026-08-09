from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from wireproof_compiler import (
    StaticEvaluationStatus,
    bind_static_evaluation,
    compile_plan,
    compile_test_pack,
    evaluate_static_baseline,
    evaluate_static_fixture,
    load_plan,
)

BASELINE = load_plan(Path("examples/evpn-fabric.yaml"))
PACK = compile_test_pack(BASELINE)
BINDING = bind_static_evaluation(compile_plan(BASELINE))


def test_healthy_baseline_pack_is_unexecuted() -> None:
    result = evaluate_static_baseline(BASELINE, BINDING, "examples/evpn-fabric.yaml")
    assert result.status is StaticEvaluationStatus.PASS
    assert result.rule_id == "BASELINE_SEMANTIC_VALID"
    assert set(result.test_pack_states) == {"UNEXECUTED"}


def test_binding_rejects_an_unrelated_baseline_before_clause_evaluation() -> None:
    unrelated = BASELINE.model_copy(update={"clauses": ()})
    result = evaluate_static_baseline(unrelated, BINDING)
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "STATIC_BINDING_BASELINE_MISMATCH"


def test_binding_is_factory_owned_and_read_only() -> None:
    with pytest.raises(TypeError, match="factory-owned"):
        type(BINDING)("x", PACK, PACK.canonical_hash, object())
    with pytest.raises(FrozenInstanceError):
        BINDING._baseline_semantic_ir_hash = "x"  # type: ignore[misc]


def test_binding_is_reusable_without_recompiling() -> None:
    import wireproof_compiler.compile as compiler_module

    with patch.object(
        compiler_module, "compile_plan", wraps=compiler_module.compile_plan
    ) as compile_mock:
        binding = bind_static_evaluation(compiler_module.compile_plan(BASELINE))
        first = evaluate_static_baseline(BASELINE, binding)
        second = evaluate_static_baseline(BASELINE, binding)
    assert compile_mock.call_count == 1
    assert first == second


def test_every_closed_fixture_fails_the_mapped_static_rule() -> None:
    expected = {
        "wrong-rt.yaml": "EVPN_RT_INTERSECTION evpn:tenant-a-l2",
        "wrong-vni.yaml": "DUPLICATE_VNI l3:11001/l2:10101",
        "cross-tenant-rt.yaml": "CROSS_TENANT_RT",
        "default-route-leak.yaml": "MANAGEMENT_DEFAULT_ROUTE_LEAK policy term",
        "missing-evpn-af.yaml": "EVPN_BGP_AF",
        "stale-fdb.yaml": "INVALID_FDB_REFERENCE",
        "asymmetric-vtep.yaml": "ASYMMETRIC_VTEP",
    }
    for name, rule in expected.items():
        result = evaluate_static_fixture(BASELINE, BINDING, Path("tests/fixtures") / name)
        assert result.status is StaticEvaluationStatus.FAIL
        assert result.rule_id == rule
        assert result.evaluation_kind == "STATIC"
        assert result.validator_provenance == "wireproof-core.FeatureContract"
        assert result.baseline_semantic_ir_hash == PACK.semantic_ir_hash
        assert result.test_pack_canonical_hash == PACK.canonical_hash
        assert set(result.test_pack_states) == {"UNEXECUTED"}


def test_bad_metadata_and_unbound_pack_fail_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "bad.yaml"
    fixture.write_text(yaml.safe_dump({"mutation": "wrong_rt"}))
    bad_result = evaluate_static_fixture(BASELINE, BINDING, fixture)
    assert bad_result.rule_id == "STATIC_FIXTURE_METADATA_INVALID"
    result = evaluate_static_fixture(BASELINE, object(), Path("tests/fixtures/wrong-rt.yaml"))  # type: ignore[arg-type]
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "STATIC_BINDING_INVALID"


def test_untrusted_binding_fails_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.yaml"
    fixture.write_text(yaml.safe_dump({"mutation": "wrong_rt"}), encoding="utf-8")
    result = evaluate_static_fixture(BASELINE, object(), fixture)  # type: ignore[arg-type]
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "STATIC_BINDING_INVALID"


def test_non_utf8_fixture_fails_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "non-utf8.yaml"
    fixture.write_bytes(b"mutation: wrong_rt\n# \xff\n")
    result = evaluate_static_fixture(BASELINE, BINDING, fixture)
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "STATIC_FIXTURE_METADATA_INVALID"
