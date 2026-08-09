# Feature F4 — Negative EVPN conformance

## Goal
Prove broken designs fail.

## Background
Passing normal traffic is insufficient.

## Scope
Wrong RT/VNI, missing RT-3/5, leaks, stale FDB, asymmetric VTEP.

## Non-goals
Target remediation.

## Dependencies
Blocked by Epic C, Epic E, F1, F2, and F3; blocks Epic F.

## Deliverables
Named negative fixtures/assertions.

## Acceptance criteria
NEG-01, TEST-01.

## Tests
Every fixture fails its intended clause deterministically.

## Relevant documents
Testing model.

---

Labels: `type:feature`, `area:evpn`, `priority:p0`
