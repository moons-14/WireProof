# Feature F2 — Compiler and renderer non-interference

## Goal
Generate typed reference output and test pack from IR.

## Background
Target/reference compilers must not be coupled.

## Scope
Reference compilation, golden tests, tenant non-interference.

## Non-goals
Complete vendor CLI parser.

## Dependencies
Blocked by Epic C and F1; blocks Epic E and Epic F.

## Deliverables
Compiler artifacts and provenance maps.

## Acceptance criteria
ARCH-02, TEST-01.

## Tests
Golden fixtures and unrelated-tenant diff regression.

## Relevant documents
ADR-004, overview.

---

Labels: `type:feature`, `area:compiler`, `priority:p0`
