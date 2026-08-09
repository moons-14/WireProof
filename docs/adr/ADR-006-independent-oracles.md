# ADR-006: GoBGP and packet observation are independent oracles

**Decision:** compare Semantic expectations with FRR, GoBGP and packets where
available.  **Why:** avoid declaring FRR its own oracle.  **Consequences:**
unexplained disagreement is `UNKNOWN`/`IMPLEMENTATION_DIVERGENCE`, not majority pass.
