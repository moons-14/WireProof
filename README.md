# WireProof

WireProof is a vendor-neutral network conformance harness.  It compiles a typed
Feature Contract into a Semantic IR and a reference-runtime topology; target
configuration and test-pack compilation are planned follow-on work. It does
**not** emulate every network operating system.

## Status

The foundation provides a Python 3.12 uv workspace, typed Semantic IR validation,
canonical hashes/provenance, and pure topology compilation. It intentionally does
not start Docker/Containerlab or write to devices: `wireproof lab doctor` returns
`UNKNOWN` with `LAB_ENVIRONMENT_UNAVAILABLE` until Lab CI is implemented.

## Intended prerequisites (after Foundation is implemented)

NixOS with Docker enabled by the operator (for example,
`virtualisation.docker.enable = true;`), access to the Docker socket, and a
Containerlab-capable host will be required for Lab CI.  The repository will
provide Python 3.12, uv, Containerlab, Docker client, inspection tools and
developer commands through `nix develop` / `direnv allow`; it will not manage
the Docker daemon.

Start with `direnv allow` (or `nix develop`), then `uv sync --frozen` and
`just check`. Compile the included contract with:

```sh
wireproof compile examples/evpn-fabric.yaml
wireproof lab compile examples/evpn-fabric.yaml
wireproof lab doctor
```

NixOS operators must enable the Docker daemon themselves, for example with
`virtualisation.docker.enable = true;`; WireProof never manages it. Lab image
digests, container lifecycle, FRR/GoBGP/OTG, and runtime conformance remain
unimplemented and therefore `UNKNOWN`.
The M1 gate contract is in the
[acceptance matrix](docs/architecture/acceptance-matrix.md), with dependency
selection recorded in the
[dependency assessment](docs/architecture/dependency-assessment.md).
