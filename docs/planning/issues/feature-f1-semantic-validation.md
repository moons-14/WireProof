# Feature F1 — Semantic validation and symbolic invariants

## Goal
Reject invalid semantic designs before compilation.

## Background
M1 must detect invalid VNI/RD/RT/interface/VTEP/AF.

## Scope
Pydantic validation and limited solver invariants.

## Non-goals
General formal verification.

## Dependencies
Blocked by Epic C; blocks F2, F3, and F4.

## Deliverables
Validators with clause provenance.

## Acceptance criteria
VAL-01.

## Tests
Duplicate VNI/RD, invalid RT, missing references, and isolation constraints.

## Relevant documents
ADR-004, testing model.

---

Labels: `type:feature`, `area:core`, `priority:p0`, `status:ready-after-core`
