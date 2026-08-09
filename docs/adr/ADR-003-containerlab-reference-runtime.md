# ADR-003: Containerlab is the reference-runtime orchestrator

**Decision:** use Containerlab, Docker/OCI and namespaces for reference labs.
**Why:** it matches network topology lifecycle without inventing an orchestrator.
**Consequences:** Lab CI needs a suitable Docker host; Pure CI remains Docker-free.
