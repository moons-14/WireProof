# Feature M2 — Target binding foundation (deferred)

## Goal
Safe typed stage lifecycle for Junos/FRR/EOS.

## Background
Device writes must follow proven virtual conformance.

## Scope
Fake targets, transcripts, transactional failure/rollback tests.

## Non-goals
M1 implementation or arbitrary SSH.

## Dependencies
Blocked by Epic F evidence promotion; blocks M3.

## Deliverables
Binding contract and fake transaction suite.

## Acceptance criteria
TARGET-01, SAFE-01.

## Tests
Timeout/disconnect/lock/partial apply/commit/read-back/rollback faults.

## Relevant documents
ADR-010, trust boundaries.

---

Labels: `type:feature`, `area:provider`, `priority:p2`, `status:blocked`
