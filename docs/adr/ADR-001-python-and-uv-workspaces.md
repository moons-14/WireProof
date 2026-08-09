# ADR-001: Python 3.12 and uv workspaces

**Decision:** use Python 3.12 and uv workspaces.  Keep core, capability,
compiler, evidence, runtime, and CLI as purposeful boundaries.  **Why:** the
network ecosystem is Python-oriented; 3.12 is the conservative baseline pending
verified support for optional packages.  **Consequences:** Python dependencies
are locked by uv; do not create empty provider packages.
