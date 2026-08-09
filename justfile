default:
    @just --list

bootstrap:
    uv sync --frozen

fmt:
    uv run ruff format .
    nix fmt

lint:
    uv run ruff check .
    deadnix flake.nix
    statix check flake.nix

typecheck:
    uv run mypy

test:
    uv run pytest

check: lint typecheck test

flake-check:
    nix flake check

lab-doctor:
    uv run wireproof lab doctor
