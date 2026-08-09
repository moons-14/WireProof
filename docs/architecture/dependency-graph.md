# Delivery dependency graph

```text
Architecture/research (this package)
 └─ Foundation: Nix + uv workspace + Pure CI
     └─ Core Feature Contract / Semantic IR
         ├─ Capability evidence model + fixture probe
         ├─ semantic validation + symbolic invariants
         ├─ reference compiler + golden tests
         ├─ test compiler + property tests
         └─ runtime lifecycle
             ├─ FRR/Linux fabric
             ├─ GoBGP observer
             ├─ OTG/Ixia-c (license gate)
             └─ Containerlab lifecycle
                 └─ EVPN/VXLAN conformance
             ├─ negative tests
             ├─ Batfish static checks (supported syntax only)
             ├─ evidence + coverage
             └─ M1 promotion gate
                 └─ M2 TargetBindings (Junos/FRR/EOS)
                     └─ M3 IX/UniFi/NFX providers
```

Only Foundation is ready immediately after architecture research. Core follows
Foundation; Capability and Compiler follow Core. Reference runtime waits for
Foundation and compiler contracts. Conformance waits for all runtime observation
components; Ixia-c work remains blocked until its EULA is accepted. Each transition uses
the promotion gates in [testing-model.md](testing-model.md), and any required
`UNKNOWN` blocks it.
