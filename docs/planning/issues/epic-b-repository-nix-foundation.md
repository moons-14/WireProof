# Epic B — Repository / Nix foundation

## Goal
Reproducible NixOS/uv monorepo foundation.

## Background
Nix owns tools; uv owns Python packages.

## Scope
flake/lock, uv workspace, CLI skeleton, just commands, Pure CI.

## Non-goals
Docker daemon management or lab execution.

## Dependencies
Blocked by Epic A; blocks Epic C and Epic E.

## Deliverables
Required root files and CI separation.

## Acceptance criteria
ENV-01, CI-01.

## Tests
Fresh checkout: `direnv allow`, `uv sync --frozen`, `just check`.

## Relevant documents
ADR-001, ADR-002, testing model.

---

Labels: `type:epic`, `area:nix`, `priority:p0`
