# ADR-011: Batfish advisory evidence contract

**Decision:** the compiler exposes a dependency-free, advisory-only boundary
for future Batfish observations. It has no PyBatfish dependency and does not
execute containers, Java, or network tooling.

Every immutable snapshot request produces a lower-case SHA-256 `SnapshotRef`.
Baseline and candidate refs must be distinct. Each run supplies a non-empty,
sorted, unique `QueryPlan`; query IDs are stable and parameters are canonical,
immutable JSON. Results must contain exactly one result for every planned ID.

Answers are canonical JSON and their SHA-256 is calculated from that answer
alone: snapshot metadata, executor provenance, and status are excluded. A null
answer has no hash. The model validates supplied hashes, so an adapter cannot
make an unverified hash authoritative.

Comparison is exact and returns `COMPLETE` only for equal plans. It records
per-query debt for missing/asymmetric results, `UNKNOWN`, `ERROR`, null answers,
and unsupported parser coverage. This debt remains visible in the advisory
assessment.

`BatfishAdvisoryAssessment.assessment_authority` is always `ADVISORY` and
`release_eligible` is always `false`, regardless of observations. The former
release-gate API is replaced rather than retained as a misleading eligibility
surface. `FakeBatfishAdapter` is fixture-only and synthetic. A future executor
may implement `BatfishAdapter`, but cannot change this authority boundary.
