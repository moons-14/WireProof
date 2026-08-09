from pathlib import Path

from wireproof_compiler import compile_plan, load_plan
from wireproof_evidence import Result
from wireproof_runtime import lab_doctor

PLAN = Path("examples/evpn-fabric.yaml")


def test_compile_has_stable_provenance() -> None:
    compiled = compile_plan(load_plan(PLAN))
    assert compiled["reference_topology"]["provenance"]["clauses"] == ["EVPN_M1"]
    assert len(compiled["semantic_ir_hash"]) == 64


def test_lab_doctor_is_explicitly_unknown() -> None:
    result = lab_doctor()
    assert result.result is Result.UNKNOWN
    assert result.reason == "LAB_ENVIRONMENT_UNAVAILABLE"
