# Epic C — Domain model

## Goal
Typed Feature Contract and Semantic IR.

## Background
All outputs require a vendor-neutral semantic source.

## Scope
Node/interface/link/VLAN/VRF/prefix/BGP/policy/VTEP/VNI/EVPN/RD/RT.

## Non-goals
Vendor serializer or live probes.

## Dependencies
Blocked by Epic A and Epic B; blocks Epic D, F1, F2, F5, and F6.

## Deliverables
Core package, clause provenance, validation API.

## Acceptance criteria
ARCH-02, VAL-01.

## Tests
Invalid duplicate/missing/incompatible examples fail.

## Relevant documents
ADR-004, testing model.

---

Labels: `type:epic`, `area:core`, `priority:p0`
