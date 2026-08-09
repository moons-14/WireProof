from pathlib import Path

from typer.testing import CliRunner
from wireproof_cli.main import app
from wireproof_compiler import ImageDeclaration, TopologyDeclaration, compile_plan, load_plan
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


def test_compiler_exposes_typed_immutable_runtime_declarations() -> None:
    compiled = compile_plan(load_plan(PLAN))
    assert isinstance(compiled["topology"], TopologyDeclaration)
    assert isinstance(compiled["image"], ImageDeclaration)
    assert compiled["topology"].model_config["frozen"]
    assert compiled["image"].model_config["frozen"]
    assert compiled["topology"].provenance_clauses == ("EVPN_M1",)


def test_compile_cli_serializes_typed_declarations() -> None:
    result = CliRunner().invoke(app, ["compile", str(PLAN)])
    assert result.exit_code == 0, result.output
    assert '"reference": "wireproof/reference:1@sha256:' in result.output
