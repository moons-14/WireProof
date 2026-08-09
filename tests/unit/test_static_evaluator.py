from pathlib import Path

import yaml
from wireproof_compiler import (
    StaticEvaluationStatus,
    compile_test_pack,
    evaluate_static_baseline,
    evaluate_static_fixture,
    load_plan,
)
from wireproof_compiler import TestPack as CompiledTestPack

BASELINE = load_plan(Path("examples/evpn-fabric.yaml"))
PACK = compile_test_pack(BASELINE)


def test_healthy_baseline_pack_is_unexecuted() -> None:
    result = evaluate_static_baseline(BASELINE, PACK, "examples/evpn-fabric.yaml")
    assert result.status is StaticEvaluationStatus.PASS
    assert result.rule_id == "BASELINE_SEMANTIC_VALID"
    assert set(result.test_pack_states) == {"UNEXECUTED"}


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
        result = evaluate_static_fixture(BASELINE, PACK, Path("tests/fixtures") / name)
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
    bad_result = evaluate_static_fixture(BASELINE, PACK, fixture)
    assert bad_result.rule_id == "STATIC_FIXTURE_METADATA_INVALID"
    mismatched = CompiledTestPack(semantic_ir_hash="0" * 64, clauses=PACK.clauses)
    result = evaluate_static_fixture(BASELINE, mismatched, Path("tests/fixtures/wrong-rt.yaml"))
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "TEST_PACK_SEMANTIC_HASH_MISMATCH"


def test_pack_canonical_mismatch_fails_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.yaml"
    fixture.write_text(yaml.safe_dump({"mutation": "wrong_rt"}), encoding="utf-8")
    altered = CompiledTestPack(
        semantic_ir_hash=PACK.semantic_ir_hash,
        clauses=PACK.clauses,
        generator_identity="other-compiler",
    )
    result = evaluate_static_fixture(BASELINE, altered, fixture)
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "TEST_PACK_CANONICAL_HASH_MISMATCH"


def test_non_utf8_fixture_fails_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "non-utf8.yaml"
    fixture.write_bytes(b"mutation: wrong_rt\n# \xff\n")
    result = evaluate_static_fixture(BASELINE, PACK, fixture)
    assert result.status is StaticEvaluationStatus.UNKNOWN
    assert result.rule_id == "STATIC_FIXTURE_METADATA_INVALID"
