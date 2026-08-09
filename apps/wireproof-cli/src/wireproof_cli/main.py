from __future__ import annotations

import json
from pathlib import Path

import typer
from wireproof_compiler import compile_plan, load_plan
from wireproof_runtime import lab_doctor

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
