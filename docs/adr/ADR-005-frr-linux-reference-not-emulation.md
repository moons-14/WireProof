# ADR-005: FRR/Linux is reference semantics, not device emulation

**Decision:** M1 uses FRR/Linux for standard control/forwarding behavior.
**Why:** virtual NOS availability must not determine validation coverage.
**Consequences:** physical vendor differences require capability evidence and
deviation handling; FRR success never proves target behavior.
