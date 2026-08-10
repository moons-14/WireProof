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

Pure checks require no Docker access. The fixed Containerlab eBGP-v4 scenario is
run manually by an operator as root with `sudo -- nix develop --command uv run
--locked wireproof lab frr-smoke clab-ebgp-v4 --repeat 1`. The CLI never elevates
privileges or invokes arbitrary `sudo` commands; start a second iteration only
after the first cleans up successfully. Its conformance remains `UNKNOWN`.
Ixia-c / OTG traffic tests remain inactive until the applicable manual EULA and
licensing gate has been satisfied.
