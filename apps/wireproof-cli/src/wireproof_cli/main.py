from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

import typer
from wireproof_compiler import compile_plan, load_plan
from wireproof_evidence import Result
from wireproof_runtime import FrrSmokeRun, FrrSmokeState, SubprocessDockerExecutor, lab_doctor

app = typer.Typer(no_args_is_help=True)
lab = typer.Typer(no_args_is_help=True)
app.add_typer(lab, name="lab")


@app.command()
def compile(plan: Path) -> None:
    """Validate a Feature Contract and emit its pure reference topology."""
    compiled = compile_plan(load_plan(plan))
    typer.echo(
        json.dumps(
            {
                key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                for key, value in compiled.items()
            },
            indent=2,
            sort_keys=True,
        )
    )


@lab.command("compile")
def lab_compile(plan: Path) -> None:
    topology = compile_plan(load_plan(plan))["reference_topology"]
    typer.echo(json.dumps(topology, indent=2, sort_keys=True))


@lab.command("doctor")
def doctor() -> None:
    typer.echo(lab_doctor().model_dump_json())


_CHANGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def _result_value(record: object | None) -> str | None:
    result = getattr(record, "result", None)
    return result.value if isinstance(result, Result) else None


def _smoke_result(change_id: str) -> tuple[dict[str, object], bool]:
    """Run one fixed FRR lifecycle and return only its structured smoke evidence."""
    run = FrrSmokeRun(change_id, SubprocessDockerExecutor)
    up: object | None = None
    status: object | None = None
    down: object | None = None
    lifecycle_error = False
    try:
        up = run.up()
        if _result_value(up) == Result.PASS.value:
            status = run.status()
    except Exception:
        lifecycle_error = True
    finally:
        try:
            down = run.down()
        except Exception:
            lifecycle_error = True

    evidence = [record.model_dump(mode="json") for record in run.evidence]
    payload: dict[str, object] = {
        "run_id": run.run_id,
        "state": run.state.value,
        "up": _result_value(up),
        "status": _result_value(status),
        "down": _result_value(down),
        "execution_mode": "REAL",
        "smoke_scope": "docker-frr-process-only",
        "conformance": "UNKNOWN",
        "evidence": evidence,
    }
    succeeded = (
        not lifecycle_error
        and _result_value(up) == Result.PASS.value
        and _result_value(status) == Result.PASS.value
        and _result_value(down) == Result.PASS.value
        and run.state is FrrSmokeState.CLEANED
    )
    return payload, succeeded


@lab.command("frr-smoke")
def frr_smoke(
    change_id: str,
    repeat: Annotated[int, typer.Option(min=1, max=2)] = 1,
) -> None:
    """Run the fixed, isolated FRR process smoke lifecycle."""
    if not _CHANGE_ID.fullmatch(change_id):
        raise typer.BadParameter("must be a non-empty identifier without credentials")

    results: list[dict[str, object]] = []
    succeeded = True
    for _ in range(repeat):
        payload, run_succeeded = _smoke_result(change_id)
        results.append(payload)
        if not run_succeeded:
            succeeded = False
            break
    typer.echo(json.dumps(results, sort_keys=True, separators=(",", ":")))
    if not succeeded or len(results) != repeat:
        raise typer.Exit(1)
