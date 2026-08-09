# Testing and promotion model

## Compiled conformance

The compiler produces three siblings from one validated Semantic IR: target
config, Containerlab reference runtime config, and a test pack.  M1 validates
IPv4/IPv6, VLAN, VRF, BGP, policies, EVPN/VXLAN, L2VNI/L3VNI, symmetric IRB and
ECMP.  A fast deterministic pytest/Hypothesis profile is Pure CI; bounded
extended properties and Containerlab tests are Lab CI.

Tests use `eventually(condition, timeout)` and save convergence duration rather
than fixed sleeps.  Test packs cover underlay/BGP, RT-2/3/5, L2/L3 VNI,
symmetric IRB, ARP/ND, BUM, isolation, MAC mobility, withdrawal, uplink/leaf/
spine/VTEP failures and BGP restart.  Packet evidence validates outer Ethernet,
IP, UDP, VXLAN VNI, and inner packet. Coverage is recorded across all nine
required axes: capability, intent clause, invariant, policy branch, EVPN route
type, packet class, state transition, failure scenario, and target-command
provenance.

## Oracles and negative tests

For material EVPN claims, compare semantic expectation, FRR observation, GoBGP
observation, and packet observation where available; add Batfish static output
only when its parser supports the generated syntax.  Evidence identifies each
oracle and its limits.

M1 includes fixtures for wrong RT/VNI, absent RT-3/RT-5, default or
tenant-management leakage, wrong policy, stale FDB, and asymmetric VTEP.
Negative fixtures must fail their named assertion.  A renderer non-interference
test proves an unrelated tenant change cannot alter another tenant's semantic or
config output.

The closed F4 fixture adapter performs only deterministic semantic validation.
Its results are labelled `STATIC`: a healthy baseline is `PASS`, each mapped
invalid mutation is `FAIL`, and malformed fixtures, TestPack binding failures,
or unsupported mutations are `UNKNOWN`. It records source identity, rule,
validator provenance, semantic/TestPack hashes, and leaves every TestPack clause
`UNEXECUTED`. It makes no RT-3/RT-5, control-plane, forwarding, learning, or
packet-conformance claim; `stale_fdb` means an invalid static FDB reference.

## Promotion gates

1. **Semantic gate:** typed validation rejects duplicate VNI/RD, invalid RT,
   absent interface/VTEP, and incompatible AF.
2. **Pure gate:** formatter, lint, typecheck, unit, fast property, IR, and
   compiler-golden checks pass without Docker.
3. **Lab gate:** pinned images, lifecycle cleanup, convergence, independent
   observations, packet/traffic checks, and negative detection pass.
4. **Evidence gate:** required evidence is complete and no required item is
   `UNKNOWN`; all nine coverage axes are represented in the evidence.
5. **Later target gate:** only then is a dark-stage binding eligible; a
   deviation requires rollback and return to PLAN.

At present gates 3–4 are `UNKNOWN`: Docker socket access was denied and
Containerlab is unavailable in this environment.

## Pure-runtime lifecycle contract

Pure CI uses a closed, no-Docker fake runner only. Its commands are typed
`DEPLOY`, `INSPECT`, and `DESTROY` program-built argv values; it can never
promote a result. A run is label-scoped by both `managed_by=wireproof` and its
exact `run_id`, so cleanup preserves unlabelled and mismatched resources.
Lifecycle failures attempt cleanup, `CLEANUP_FAILED` is retryable with `down`,
and an already-cleaned `down` is a no-op. `eventually` receives monotonic time
and sleeping functions, records attempts/elapsed time, and uses no fixed sleep.
