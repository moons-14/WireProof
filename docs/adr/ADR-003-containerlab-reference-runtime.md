# ADR-003: Containerlab is the reference-runtime orchestrator

**Decision:** use Containerlab, Docker/OCI and namespaces for reference labs.
**Why:** it matches network topology lifecycle without inventing an orchestrator.
**Consequences:** Lab CI needs a suitable Docker host; Pure CI remains Docker-free.

**Pure fallback:** a fake runner models only the closed lifecycle command contract
and produces non-promotable `FAKE` evidence. It neither probes Docker nor claims
Containerlab execution.

**Recorded reference artifact:** pure compilation emits an immutable canonical
`containerlab-0.59.0` artifact, not a deployable YAML file. It orders nodes,
links, and clauses lexicographically and binds the IR hash, the fixed FRR 10.5.4
commit `4cb6d9e`, and the pinned six-platform OCI index
`quay.io/frrouting/frr@sha256:17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78`.
Recorded dry plans have only typed DEPLOY/INSPECT/DESTROY commands and require
both `managed_by=wireproof` and `run_id` labels for cleanup selection. An
unavailable residue reinspection is `UNKNOWN`, never cleanup success.
