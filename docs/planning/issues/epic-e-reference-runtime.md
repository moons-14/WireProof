# Epic E — Reference runtime

## Goal
Compile and lifecycle a pinned Containerlab reference topology.

## Background
Virtual NOSes are optional.

## Scope
FRR/Linux output, Containerlab lifecycle, status/cleanup.

## Non-goals
Hardware or target configuration.

## Dependencies
Blocked by Epic B, Epic C, and F2; blocks Epic F, F3, F4, F5, and F6.

## Deliverables
`lab compile/up/status/down` equivalent.

## Acceptance criteria
LAB-01, IMG-01, CLEAN-01.

## Tests
Smoke lifecycle and no residual containers/networks/namespaces.

## Relevant documents
ADR-003, ADR-005.

---

Labels: `type:epic`, `area:runtime`, `priority:p0`
