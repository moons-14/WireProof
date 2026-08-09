# ADR-008: Batfish role and UNKNOWN semantics

**Decision:** use PyBatfish only for supported static questions, with a pinned
runtime.  **Why:** static comparison adds value but parser coverage is bounded.
**Consequences:** unsupported syntax is `UNKNOWN`, never `PASS`; required
unknowns block promotion.
