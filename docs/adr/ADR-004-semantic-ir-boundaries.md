# ADR-004: Semantic IR boundaries

**Decision:** core owns typed Feature Contract and Semantic IR; renderers and
runtime compilers are separate consumers.  **Why:** vendor-neutral semantics
must outlive vendor implementations.  **Consequences:** no Docker/NOS/Batfish
dependency in core, and provenance is retained clause-to-output.
