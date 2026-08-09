# GitHub issue dossier (pending remote creation)

The 23 required labels have been created. Issue IDs are unavailable because
external GitHub writes are not authorized in this environment. This file is the
reviewed local source of truth, not evidence that issues exist. When issues are
created, insert their observed IDs into the symbolic references below; do not
predict IDs or treat label creation as pending repair.

## Epic A — Architecture / Research

**Labels:** `type:epic`, `area:docs`, `priority:p0`, `status:ready`  
**Goal:** freeze evidence-backed M1 architecture.  
**Background:** vendor-emulation is not the product; M1 is virtual conformance.  
**Scope:** architecture, ADRs, source/pin/licence decisions, dependency graph.  
**Non-goals:** executable lab or target writes.  
**Dependencies:** none.  
**Blocked by:** —  
**Blocks:** Epic B.  
**Deliverables:** architecture package and ADRs.  
**Acceptance criteria:** ARCH-01, SAFE-01, IMG-01, IMG-02, LIC-01, TARGET-01.  
**Tests:** document-link and decision-consistency review.  
**Relevant documents:** `docs/architecture/*`, `docs/adr/*`.

## Epic B — Repository / Nix foundation

**Labels:** `type:epic`, `area:nix`, `priority:p0`  
**Goal:** reproducible NixOS/uv monorepo foundation.  
**Background:** Nix owns tools; uv owns Python packages.  
**Scope:** flake/lock, uv workspace, CLI skeleton, just commands, Pure CI.  
**Non-goals:** Docker daemon management or lab execution.  
**Dependencies:** Blocked by Epic A; blocks Core and Runtime.  
**Blocked by:** Epic A.  
**Blocks:** Epic C, Epic E.  
**Deliverables:** required root files and CI separation.  
**Acceptance criteria:** ENV-01, CI-01.  
**Tests:** fresh checkout: `direnv allow`, `uv sync --frozen`, `just check`.  
**Relevant documents:** ADR-001, ADR-002, testing model.

## Epic C — Domain model

**Labels:** `type:epic`, `area:core`, `priority:p0`  
**Goal:** typed Feature Contract and Semantic IR.  
**Background:** all outputs require a vendor-neutral semantic source.  
**Scope:** node/interface/link/VLAN/VRF/prefix/BGP/policy/VTEP/VNI/EVPN/RD/RT.  
**Non-goals:** vendor serializer or live probes.  
**Dependencies:** Blocked by Epic A and Epic B; blocks compiler and tests.  
**Blocked by:** Epic A, Epic B.  
**Blocks:** Epic D, F1, F2, F5, F6.  
**Deliverables:** core package, clause provenance, validation API.  
**Acceptance criteria:** ARCH-02, VAL-01.  
**Tests:** invalid duplicate/missing/incompatible examples fail.  
**Relevant documents:** ADR-004, testing model.

## Epic D — Capability evidence

**Labels:** `type:epic`, `area:capability`, `priority:p1`  
**Goal:** evidence-state model and fixture read-only probing.  
**Background:** documented support differs from realized behavior.  
**Scope:** state machine, evidence records, fake/fixture probe interface.  
**Non-goals:** every vendor adapter or target write.  
**Dependencies:** Blocked by Epic B and Epic C.  
**Blocked by:** Epic B, Epic C.  
**Blocks:** Epic F.  
**Deliverables:** capability model and fixture tests.  
**Acceptance criteria:** EVID-01, SAFE-01.  
**Tests:** state/provenance transition and unsupported tests.  
**Relevant documents:** ADR-009, trust boundaries.

## Epic E — Reference runtime

**Labels:** `type:epic`, `area:runtime`, `priority:p0`  
**Goal:** compile/lifecycle a pinned Containerlab reference topology.  
**Background:** virtual NOSes are optional.  
**Scope:** FRR/Linux output, Containerlab lifecycle, status/cleanup.  
**Non-goals:** hardware or target configuration.  
**Dependencies:** Blocked by Epic B, Epic C, and F2; blocks Epic F.  
**Blocked by:** Epic B, Epic C, F2.  
**Blocks:** Epic F, F3, F4, F5, F6.  
**Deliverables:** `lab compile/up/status/down` equivalent.  
**Acceptance criteria:** LAB-01, IMG-01, CLEAN-01.  
**Tests:** smoke lifecycle and no residual containers/networks/namespaces.  
**Relevant documents:** ADR-003, ADR-005.

## Epic F — EVPN/VXLAN conformance

**Labels:** `type:epic`, `area:evpn`, `area:vxlan`, `priority:p0`  
**Goal:** M1 two-spine/four-leaf virtual conformance.  
**Background:** this is the first end-to-end proof.  
**Scope:** multi-tenant symmetric-IRB, control/forwarding/failure tests, evidence.  
**Non-goals:** physical staging and vendor writes.  
**Dependencies:** Blocked by Epics C, D, E and child features below.  
**Blocked by:** Epic C, Epic D, Epic E, F3, F4, F5, F6.  
**Blocks:** M2.  
**Deliverables:** reproducible normal and broken-fixture results.  
**Acceptance criteria:** TEST-01, ORACLE-01, NEG-01, EVID-01, CLEAN-01.  
**Tests:** specified M1 acceptance matrix; deterministic rerun.  
**Relevant documents:** testing model, trust boundaries.

## Feature F1 — Semantic validation and symbolic invariants

**Labels:** `type:feature`, `area:core`, `priority:p0`, `status:ready-after-core`  
**Goal:** reject invalid semantic designs before compilation.  
**Background:** M1 must detect invalid VNI/RD/RT/interface/VTEP/AF.  
**Scope:** Pydantic validation and limited solver invariants.  
**Non-goals:** general formal verification.  
**Dependencies:** Blocked by Epic C; blocks F3/F4.  
**Blocked by:** Epic C.  
**Blocks:** F2, F3, F4.  
**Deliverables:** validators with clause provenance.  
**Acceptance criteria:** VAL-01.  
**Tests:** duplicate VNI/RD, invalid RT, missing references, isolation constraints.  
**Relevant documents:** ADR-004, testing model.

## Feature F2 — Compiler and renderer non-interference

**Labels:** `type:feature`, `area:compiler`, `priority:p0`  
**Goal:** generate typed reference output and test pack from IR.  
**Background:** target/reference compilers must not be coupled.  
**Scope:** reference compilation, golden tests, tenant non-interference.  
**Non-goals:** complete vendor CLI parser.  
**Dependencies:** Blocked by Epic C and F1; blocks Epic E/F.  
**Blocked by:** Epic C, F1.  
**Blocks:** Epic E, Epic F.  
**Deliverables:** compiler artifacts and provenance maps.  
**Acceptance criteria:** ARCH-02, TEST-01.  
**Tests:** golden fixtures and unrelated-tenant diff regression.  
**Relevant documents:** ADR-004, overview.

## Feature F3 — Independent observers and traffic

**Labels:** `type:feature`, `area:traffic`, `priority:p1`, `status:blocked`  
**Goal:** GoBGP/pcap/OTG observations and immutable image evidence.  
**Background:** FRR alone is not an oracle.  
**Scope:** GoBGP v4.5.0 build, pcap analysis, snappi integration, version/digest collection.  
**Non-goals:** custom traffic generator.  
**Dependencies:** Blocked by Epic E; OTG path blocked by manual Ixia-c EULA acceptance.  
**Blocked by:** Epic E, Ixia-c EULA acceptance.  
**Blocks:** Epic F, F4, F6.  
**Deliverables:** oracle adapter contracts and evidence schema.  
**Acceptance criteria:** ORACLE-01, IMG-02, LIC-01, EVID-01.  
**Tests:** disagreement becomes UNKNOWN; pcap header/VNI parsing.  
**Relevant documents:** ADR-006, ADR-007.

## Feature F4 — Negative EVPN conformance

**Labels:** `type:feature`, `area:evpn`, `priority:p0`  
**Goal:** prove broken designs fail.  
**Background:** passing normal traffic is insufficient.  
**Scope:** wrong RT/VNI, missing RT-3/5, leaks, stale FDB, asymmetric VTEP.  
**Non-goals:** target remediation.  
**Dependencies:** Blocked by Epics C/E and Features F1/F2/F3.  
**Blocked by:** Epic C, Epic E, F1, F2, F3.  
**Blocks:** Epic F.  
**Deliverables:** named negative fixtures/assertions.  
**Acceptance criteria:** NEG-01, TEST-01.  
**Tests:** every fixture fails its intended clause deterministically.  
**Relevant documents:** testing model.

## Feature F5 — Batfish static validation

**Labels:** `type:feature`, `area:batfish`, `priority:p1`  
**Goal:** add supported static reachability/diff checks.  
**Background:** static output complements runtime but has parser limits.  
**Scope:** pinned runtime, snapshot capabilities, UNKNOWN mapping.  
**Non-goals:** treating unparsed syntax as pass.  
**Dependencies:** Blocked by Epic B/C; informs Epic F.  
**Blocked by:** Epic B, Epic C.  
**Blocks:** Epic F.  
**Deliverables:** supported-query matrix and tests.  
**Acceptance criteria:** BF-01.  
**Tests:** unsupported input returns UNKNOWN and blocks required gate.  
**Relevant documents:** ADR-008.

## Feature F6 — Evidence and coverage

**Labels:** `type:feature`, `area:evidence`, `priority:p0`  
**Goal:** save machine-readable result/provenance/coverage.  
**Background:** promotion needs auditable evidence.  
**Scope:** hashes, versions/digests, observations, captures, unknowns and the nine coverage axes: capability, intent clause, invariant, policy branch, EVPN route type, packet class, state transition, failure scenario, and target-command provenance.  
**Non-goals:** long-term external evidence service.  
**Dependencies:** Blocked by Epic C/E; blocks Epic F promotion.  
**Blocked by:** Epic C, Epic E.  
**Blocks:** Epic F promotion.  
**Deliverables:** evidence schema and report store.  
**Acceptance criteria:** EVID-01, IMG-02.  
**Tests:** required UNKNOWN prevents promotion; all nine coverage axes and clause mapping are complete.  
**Relevant documents:** overview, trust boundaries.

## Feature M2 — Target binding foundation (deferred)

**Labels:** `type:feature`, `area:provider`, `priority:p2`, `status:blocked`  
**Goal:** safe typed stage lifecycle for Junos/FRR/EOS.  
**Background:** device writes must follow proven virtual conformance.  
**Scope:** fake targets, transcripts, transactional failure/rollback tests.  
**Non-goals:** M1 implementation or arbitrary SSH.  
**Dependencies:** Blocked by Epic F evidence promotion.  
**Blocked by:** Epic F evidence promotion.  
**Blocks:** M3.  
**Deliverables:** binding contract and fake transaction suite.  
**Acceptance criteria:** TARGET-01, SAFE-01.  
**Tests:** timeout/disconnect/lock/partial apply/commit/read-back/rollback faults.  
**Relevant documents:** ADR-010, trust boundaries.
