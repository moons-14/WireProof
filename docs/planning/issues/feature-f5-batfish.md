# Feature F5 — Batfish static validation

## Goal
Add supported static reachability/diff checks.

## Background
Static output complements runtime but has parser limits.

## Scope
Pinned runtime, snapshot capabilities, UNKNOWN mapping.

## Non-goals
Treating unparsed syntax as pass.

## Dependencies
Blocked by Epic B and Epic C; informs Epic F.

## Deliverables
Supported-query matrix and tests.

## Acceptance criteria
BF-01.

## Tests
Unsupported input returns UNKNOWN and blocks the required gate.

## Relevant documents
ADR-008.

---

Labels: `type:feature`, `area:batfish`, `priority:p1`
