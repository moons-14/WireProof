default:
    @just --list

bootstrap:
    uv sync --frozen

fmt:
    uv run ruff format .
    nix fmt

format-check:
    uv run --frozen ruff format --check .
    nixfmt --check flake.nix

lint:
    uv run --frozen ruff check .
    deadnix flake.nix
    statix check flake.nix

typecheck:
    PYTHONWARNINGS=error uv run --frozen mypy

test:
    PYTHONWARNINGS=error uv run --frozen pytest

check: format-check lint typecheck test

flake-check:
    nix flake check

lab-doctor:
    uv run wireproof lab doctor
