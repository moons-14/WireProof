# WireProof architecture

## Purpose and Milestone 1 boundary

WireProof establishes this closed loop:

`PLAN → capability discovery → semantic compile → virtual conformance test → target dark stage → wiring → physical test → service activation`.

Milestone 1 ends at evidence-backed virtual conformance.  It must construct a
two-spine/four-leaf, multi-tenant EVPN/VXLAN reference fabric from a Feature
Contract and detect deliberately broken intent.  It has no target write path;
Target Stage, wiring, and activation are later milestones.

WireProof is not a NOS, an arbitrary-CLI agent, a vendor CLI parser, a BGP or
VXLAN implementation, a traffic generator, or a container orchestrator.

## Boundaries and dependency direction

`wireproof-core` contains pure Pydantic domain types and Feature Contract /
Semantic IR invariants.  It has no Docker, Containerlab, NOS, NetBox, or
Batfish dependency.  `capability`, `compiler`, and `evidence` depend only on
core.  `runtime` depends on core and consumes compiler output.  The CLI
composes those packages.  Provider packages are introduced only when a
milestone needs a real provider; M1's reference FRR/Linux compiler is runtime
implementation, not device emulation.

The development split is Nix for OS tools/runtime and uv workspaces for Python
dependencies.  Python 3.12 is selected; this avoids claiming unverified 3.13
compatibility for PyBatfish/snappi/device libraries.

## Authoritative inputs and outputs

Feature Contract clauses carry stable IDs.  Compiler output preserves each ID
as provenance through Semantic IR, target configuration, reference runtime
configuration, tests, and evidence.  A target renderer and reference compiler
are separate.  Renderers use typed vendor IR plus serializers, not templates as
the domain model.  Target renderers start later with Junos, FRR, and EOS.

Each result is `PASS`, `FAIL`, `UNKNOWN`, or `NOT_APPLICABLE`.  A required
`UNKNOWN` blocks promotion.  Unsupported Batfish syntax is `UNKNOWN`, never a
pass.  Divergent independent observations are `IMPLEMENTATION_DIVERGENCE` (or
`UNKNOWN`) and stop promotion; they are not majority-voted.

## Reference components and pin policy

Containerlab orchestrates Docker/OCI containers and Linux namespaces; the host
does not run the reference fabric as scattered processes.  FRR/Linux supplies
reference protocol and forwarding behavior, not vendor semantics.  GoBGP and
packet capture are independent observation paths.  OTG/Ixia-c with snappi is
the traffic architecture, not a custom packet generator.  Batfish is optional
static validation; parser gaps retain `UNKNOWN`.

All deployed images must have a version and immutable `@sha256` digest recorded
in evidence.  The current research pin is FRR `10.5.4` / upstream tag commit
`4cb6d9e`; its final runtime image digest is not yet resolved.  GoBGP is
source-pinned at `v4.5.0` and project-built.  Ixia-c Community requires manual
EULA acceptance and cannot be silently downloaded or activated.  Batfish must
be runtime-pinned when introduced.

Primary references: [Containerlab docs](https://containerlab.dev/),
[FRR 10.5.4 release](https://github.com/FRRouting/frr/releases/tag/frr-10.5.4),
[GoBGP v4.5.0](https://github.com/osrg/gobgp/releases/tag/v4.5.0),
[Open Traffic Generator](https://github.com/open-traffic-generator),
[Batfish docs](https://batfish.readthedocs.io/), and
[Nix flakes](https://nixos.wiki/wiki/Flakes).

The normative gate IDs and pass/block rules are in the
[acceptance matrix](acceptance-matrix.md). Dependency choices and deferred
provider clients are recorded in the [dependency assessment](dependency-assessment.md).
# Declarative test packs

The compiler also emits a canonical `TestPack` beside the reference-topology output.
It is a declarative requirement list derived from validated semantic IR: every clause is
explicitly `UNEXECUTED`, carries stable source identity/provenance, and has a structured
expected condition.  Its SHA-256 hash is over its exact canonical serialized bytes.

Test packs neither select or render a target nor contain runtime observations, diagnostics,
or results.  Executors and evidence producers add those concerns later; this sibling output
does not alter the reference artifact or existing compiler hashes.
