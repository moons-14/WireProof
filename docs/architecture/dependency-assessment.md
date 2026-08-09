# Dependency assessment

This is the M1 selection record. “Status” describes the research decision, not
an assertion that a dependency is installed or exercised. Maintenance evidence
is the upstream project/release activity reviewed during architecture research;
it must be refreshed before a runtime pin is accepted.

| Dependency | Problem | Maintenance evidence/status | License | Weight | Alternative | M1 decision |
|---|---|---|---|---|---|---|
| Pydantic v2 | Typed domain and validation | Active upstream; selected | MIT | Medium | dataclasses + validators | Select |
| Typer | Typed CLI surface | Active upstream; selected | MIT | Low | argparse | Select |
| pytest | Tests and fixtures | Active upstream; selected | MIT | Low | unittest | Select |
| Hypothesis | Bounded property tests | Active upstream; fast profile selected | MPL-2.0 | Medium | hand-written cases | Select |
| Ruff | Formatting/linting | Active upstream; selected | MIT | Low | Black + Flake8 | Select |
| mypy | Static typing | Active upstream; selected | MIT | Medium | Pyright | Select |
| PyBatfish | Static network validation | API/docs reviewed; runtime pin deferred | Apache-2.0 | High | no static oracle | Optional; UNKNOWN if unavailable |
| snappi | OTG traffic model/client | Active upstream; lab integration selected | MIT | Medium | vendor OTG client | Select for lab milestone |
| NetworkX | Graph/topology algorithms | Active upstream; use only where needed | BSD-3-Clause | Medium | stdlib graph code | Select if compiler needs it |
| httpx | Async HTTP transport | Active upstream; no M1 integration yet | BSD-3-Clause | Medium | urllib / requests | Defer |
| Scrapli / PyEZ / pyeapi / gNMI | Vendor/device transport | Provider-scoped review remains; no M1 target write path | Varies; verify before provider release | High | recorded adapters | Defer; not selected in M1 |

Nix owns the Python runtime and system tools; uv owns Python dependencies. Before
adding a package, record its exact version, license, native requirements, and
test boundary. Vendor clients remain deferred until provider transaction
semantics are specified.
