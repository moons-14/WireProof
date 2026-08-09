# Trust boundaries and deviation loop

The LLM may create a Change Plan, but never receives arbitrary
`ssh(host, command)`.  Capability discovery is read-only.  Writes belong only
to a Change Controller via a typed `NetworkBinding`; target bindings are not in
M1.  Evidence is immutable-by-change-ID output, including source hashes,
versions/digests, observations, captures, coverage, and unknowns.

Reference runtime trust does not extend to physical targets: FRR/Linux validates
standard behavior but is not proof of a QFX, EX, EOS, IX, UniFi, or NFX device.
GoBGP/packet observation reduce a single-implementation oracle risk but cannot
override an unexplained disagreement.

When a later target differs, controller execution must stop, rollback, write a
`PlatformDeviation`, and return to PLAN.  Required fields are vendor, model,
OS, hardware revision, license, feature, expected/observed state, target
config, logs, packet capture, classification, and regression test.  Classes:
`CAPABILITY_MISMATCH`, `SYNTAX_DIFFERENCE`, `SEMANTIC_DIFFERENCE`,
`FIRMWARE_BEHAVIOR`, `HARDWARE_LIMIT`, `LICENSE_LIMIT`, `RENDERER_BUG`,
`MODEL_BUG`, `TEST_BUG`, `PHYSICAL_FAILURE`.

No ad-hoc CLI append is permitted after deviation.  Correct Capability, Intent,
Semantic Model, Renderer, and Tests; rerun virtual conformance; then restage.
Physical activation is staged from optics/carrier through FEC/error counters,
LLDP/LACP, MTU/VLAN, underlay/BGP/EVPN/VXLAN and tenant services.
