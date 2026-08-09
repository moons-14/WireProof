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

**Execution boundary:** cooperative in-process code may compose the lifecycle
with an executor and is not a sandbox. The CLI uses only the runtime scenario
factory, which fixes the real executor and preserves the closed command surface.

**Artifact cleanup boundary:** each generated run directory is private (`0700`) and
is removed only after a complete immutable inode manifest confirms exactly the
minted `n1`/`n2` directories, their `frr.conf` files, and topology file. Cleanup
uses descriptor-relative, no-follow operations and deletes only those listed
entries; an unexpected, replaced, linked, or special entry leaves the directory
for recovery and reports cleanup failure. This mitigates stale-path and
pre-existing replacement attacks. It does not claim safety against a concurrent
same-UID adversary that changes the tree after validation: that active race is
outside this cooperative-process threat boundary.

The manifest also binds each regular file's SHA-256 content, size, and expected
mode through a no-follow descriptor immediately before status, probe, or cleanup.
This detects pre-existing and observed replacements, but does not make a pathname
safe against a malicious same-UID rename or replacement between final validation
and Containerlab's pathname consumption or fd-relative removal. Strict protection
of that interval would require a privileged helper with a distinct UID; it is
future work and outside the M1 unprivileged threat boundary.
