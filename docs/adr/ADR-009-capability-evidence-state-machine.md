# ADR-009: Capability evidence state machine

**Decision:** model capability as `UNKNOWN`, `DOCUMENTED`, `EXPOSED`,
`ACCEPTED`, `REALIZED`, `CONFORMANT`, or `UNSUPPORTED`; begin with fixtures and
read-only probes.  **Why:** documentation, acceptance, and observed behavior
are distinct.  **Consequences:** no blanket vendor-support claim.
