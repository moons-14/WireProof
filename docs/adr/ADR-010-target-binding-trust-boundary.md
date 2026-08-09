# ADR-010: Target Binding trust boundary

**Decision:** defer all target writes beyond M1 and expose typed bindings only
to a Change Controller.  **Why:** an LLM must not execute arbitrary target CLI.
**Consequences:** deviations stop/rollback/replan; M2 begins with fake targets
and recorded transcripts before Junos/FRR/EOS hardware paths.
