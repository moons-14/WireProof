# ADR-007: OTG/Ixia-c traffic architecture

**Decision:** compile Traffic Flows to OTG/Ixia-c through snappi; do not build a
packet generator.  **Why:** reuse the standard API and retain traffic metrics.
**Consequences:** Ixia-c Community requires manual EULA acceptance; dependent
Lab work remains blocked until authorized and pinned.

The runtime package provides a pure typed declaration evaluator for the fixed
`ghcr.io/srl-labs/ixia-c-one:1.58.0-16@sha256:8a63a93bbd4c98bd2832e69689852ca13486be89bed02dc42a772e432f1203ab`.
`REQUEST_ACCEPT_EULA` records
invocation intent only: it is never legal acceptance, current authorization, a
license configuration, or a Docker permission. Caller-declared component
inventories must be independently pinned, but remain incomplete until separately
verified; assessments are always non-promotable and cannot permit mutation.
