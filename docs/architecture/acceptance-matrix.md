# Milestone 1 acceptance matrix

This matrix is the gate contract for architecture and foundation work. A
criterion is `PASS` only when its artifact and check exist on the same commit.
Missing evidence, unresolved required `UNKNOWN`, or an unverified runtime claim
is `BLOCKED`; documentation alone does not satisfy runtime criteria.

| ID | Pass criteria | Block criteria |
|---|---|---|
| ARCH-01 | Closed loop, M1 boundary, and reference-versus-target separation are documented. | A boundary is ambiguous or M1 implies target writes. |
| ARCH-02 | Dependency direction and trust boundaries are documented and consistent. | Core depends on runtime/vendor tooling or an undocumented cross-boundary dependency exists. |
| SAFE-01 | No arbitrary device shell/write path exists; changes use controlled bindings and deviations return to plan. | Direct arbitrary CLI execution or ad-hoc continuation is allowed. |
| VAL-01 | Typed contracts validate identity, interface references, AF compatibility, VNI/RD/RT constraints, and required VTEPs. | Invalid fixtures are accepted or validation ownership is unspecified. |
| ENV-01 | Fresh NixOS checkout enters the declared environment with `direnv allow` or `nix develop`. | Manual global installation is required for the pure workflow. |
| IMG-01 | Every reference image has a fixed version and immutable digest in evidence. | `latest`, floating tags, or missing digest evidence is used. |
| IMG-02 | Runtime component versions and image provenance are recorded per run. | FRR/GoBGP/traffic/Batfish versions cannot be reconstructed. |
| LIC-01 | License and image/EULA decisions are recorded; Ixia-c is not silently activated. | A license or manual EULA requirement is omitted. |
| LAB-01 | Semantic IR deterministically generates a two-spine/four-leaf Containerlab topology with lifecycle and cleanup. | Topology is hand-authored only, lifecycle is non-repeatable, or residue remains. |
| TEST-01 | Underlay, EVPN/VXLAN, forwarding, isolation, and failure tests use convergence waits and preserve results. | Fixed sleeps are the only synchronization or required tests are absent. |
| ORACLE-01 | Applicable checks compare semantic, FRR, GoBGP, packet, and Batfish observations; disagreement is `UNKNOWN`/`IMPLEMENTATION_DIVERGENCE`. | FRR alone is truth or disagreement is voted to pass. |
| NEG-01 | Wrong RT/VNI, route leaks, stale FDB, and asymmetric-VTEP fixtures fail reliably. | A broken fixture passes or is silently downgraded. |
| EVID-01 | Evidence stores hashes, versions/digests, identity, observations, captures, unknowns, deviations, and coverage for capability, intent clause, invariant, policy branch, EVPN route type, packet class, state transition, failure scenario, and target-command provenance. | Results cannot be reproduced, provenance is missing, or a required coverage axis is absent. |
| CI-01 | Pure and Docker/Containerlab checks are separate; `just check` excludes lab requirements. | Pure CI requires a lab or lab failures are hidden. |
| CLEAN-01 | Repeated up/test/down runs are reproducible and leave no resource residue. | Cleanup or repeatability is unverified. |
| BF-01 | Supported Batfish checks run; unsupported syntax is `UNKNOWN` and blocks promotion. | Parser gaps are reported as `PASS`. |
| TARGET-01 | Target Stage is absent from M1 or remains read-only; physical activation is not implied. | M1 writes devices or promotes with required unknowns. |

This matrix is normative. Implementation issues may add tests but may not
weaken these criteria without an ADR update.
