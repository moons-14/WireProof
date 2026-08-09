# ADR-009: Capability evidence state machine

**Decision:** model capability as `UNKNOWN`, `DOCUMENTED`, `EXPOSED`,
`ACCEPTED`, `REALIZED`, `CONFORMANT`, or `UNSUPPORTED`; begin with fixtures and
read-only probes.  **Why:** documentation, acceptance, and observed behavior
are distinct.  **Consequences:** no blanket vendor-support claim.

Capability gates bind both a clause and an immutable capability identity. `UNKNOWN`
never satisfies a gate, including a gate whose stated minimum is `UNKNOWN`. Probe
descriptions use a closed probe kind and typed VNI/address-family selectors; they
cannot carry commands, hosts, or credentials. Fixture data is not capability evidence.

Terminal evidence (`CONFORMANT` or `UNSUPPORTED`) requires immutable authority provenance
(authority identifier, reference, and SHA-256 digest). This records supplied provenance only: local validation
does not verify a signature, grant promotion authority, or establish external trust.
`CONFORMANT` and `UNSUPPORTED` remain evidence states, not a local authorization to
promote any capability; an external verifier is required where that trust decision matters.
