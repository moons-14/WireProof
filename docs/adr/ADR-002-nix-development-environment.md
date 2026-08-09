# ADR-002: Nix development environment

**Decision:** a flake will supply runtimes and developer tools; uv supplies
Python libraries.  `.envrc` is exactly `use flake`.  **Why:** reproducible NixOS
development without global tool installation.  **Consequences:** Docker daemon
is operator-managed and documented, not configured by the repository.
