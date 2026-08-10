# WireProof

WireProof is a vendor-neutral network conformance harness.  It compiles a typed
Feature Contract into a Semantic IR and a reference-runtime topology; target
configuration and test-pack compilation are planned follow-on work. It does
**not** emulate every network operating system.

## Status

The foundation provides a Python 3.12 uv workspace, typed Semantic IR validation,
canonical hashes/provenance, pure topology compilation, and an FRR smoke
lifecycle. It does not yet provide a full Containerlab conformance lifecycle or
write to network devices. The manual Lab CI gate intentionally stops at
`wireproof lab doctor` until that runtime gate is available.

## Intended prerequisites (after Foundation is implemented)

NixOS (or Linux) Lab runners need Docker enabled by the operator (for example,
`virtualisation.docker.enable = true;`), Docker access for the runner account,
and a Containerlab-capable host. The repository provides Python 3.12, uv,
Containerlab, Docker client, inspection tools and developer commands through
`nix develop` / `direnv allow`; it never manages the Docker daemon or grants
host privileges.

Start with `direnv allow` (or `nix develop`), then `uv sync --frozen` and
`just check`. Compile the included contract with:

```sh
wireproof compile examples/evpn-fabric.yaml
wireproof lab compile examples/evpn-fabric.yaml
wireproof lab doctor
```

NixOS operators must enable the Docker daemon themselves, for example with
`virtualisation.docker.enable = true;`; WireProof never manages it. The current
FRR smoke lifecycle is not a claim of EVPN, VXLAN, BGP, forwarding, or packet
capture conformance. Containerlab lifecycle and Ixia-c/OTG traffic checks remain
gated; Ixia-c additionally requires manual EULA and licensing approval. See the
[release gates](docs/release.md) for CI runtime requirements and current limits.
The M1 gate contract is in the
[acceptance matrix](docs/architecture/acceptance-matrix.md), with dependency
selection recorded in the
[dependency assessment](docs/architecture/dependency-assessment.md).

On a trusted lab host only, the fixed Containerlab smoke may explicitly retry a
host privilege denial through a root-equivalent controller:

```sh
wireproof lab frr-smoke clab-ebgp-v4 --allow-privileged-controller --change-id change-123
```

This opt-in is per invocation, has no arbitrary Docker command or mount surface,
and remains `UNKNOWN` conformance evidence.
