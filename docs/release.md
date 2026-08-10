# Release and CI gates

`Pure checks` runs on pull requests, pushes to `main`, and manual dispatch. It is
unprivileged, reads repository contents only, disables checkout credentials, and
uses commit-pinned actions. It validates the flake, performs a frozen `uv sync`,
and runs `just check` with Python warnings treated as errors.

`Lab gate` is manual only. It may run exclusively from the default branch of the
canonical repository, on a trusted self-hosted runner labelled
`self-hosted`, `linux`, and `wireproof-lab`, under the protected `lab`
environment. Concurrent lab runs for this repository are serialized.

The lab job currently runs `wireproof lab doctor`, stores its JSON result in the
workspace, and fails for `UNKNOWN` or every other non-`PASS` result. It does
not yet run a Containerlab `up` / test / `down` lifecycle. That lifecycle, with
evidence collection and cleanup verification, is the future contract; this gate
deliberately blocks before it is available.

## Operator requirements

Pure checks require no Docker access. Lab runners are operator-managed NixOS or
Linux hosts with a Docker daemon enabled by the operator, a Docker client usable
by the runner account, and Containerlab installed through the declared Nix
development environment. WireProof neither manages the Docker daemon nor grants
host privileges. Ixia-c / OTG traffic tests remain inactive until the applicable
manual EULA and licensing gate has been satisfied.

The exceptional privileged controller fallback is per invocation only: it needs
`--allow-privileged-controller` and a validated `--change-id` on the fixed
`clab-ebgp-v4` scenario. It is root-equivalent and must be used only on a trusted
operator-managed lab host; its evidence remains non-promotable (`UNKNOWN`).
