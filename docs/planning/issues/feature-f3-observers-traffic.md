# Feature F3 — Independent observers and traffic

## Goal
GoBGP/pcap/OTG observations and immutable image evidence.

## Background
FRR alone is not an oracle.

## Scope
GoBGP v4.5.0 build, pcap analysis, snappi integration, version/digest collection.

## Non-goals
Custom traffic generator.

## Dependencies
Blocked by Epic E; OTG path is blocked by manual Ixia-c EULA acceptance; blocks Epic F, F4, and F6.

## Deliverables
Oracle adapter contracts and evidence schema.

## Acceptance criteria
ORACLE-01, IMG-02, LIC-01, EVID-01.

## Tests
Disagreement becomes UNKNOWN; pcap header/VNI parsing.

## Relevant documents
ADR-006, ADR-007.

---

Labels: `type:feature`, `area:traffic`, `priority:p1`, `status:blocked`
