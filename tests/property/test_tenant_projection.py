from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from wireproof_compiler import compile_test_pack, project_test_pack_for_tenant
from wireproof_core import FeatureContract
from wireproof_core.model import L2VNI, L3VNI, VRF, EVPNInstance


def _source() -> FeatureContract:
    return FeatureContract.model_validate(
        {
            "clauses": [{"id": "TENANT_SCOPE", "statement": "tenant scope is required"}],
            "nodes": [
                {"name": "leaf-a", "interfaces": [{"name": "eth1"}, {"name": "lo0"}]},
                {"name": "leaf-b", "interfaces": [{"name": "eth1"}, {"name": "lo0"}]},
            ],
            "links": [
                {
                    "a": {"node": "leaf-a", "interface": "eth1"},
                    "b": {"node": "leaf-b", "interface": "eth1"},
                }
            ],
            "vlans": [{"id": 100, "name": "global-vlan"}],
            "vrfs": [{"name": "a-vrf", "tenant": "tenant-a"}],
            "bgp_sessions": [
                {
                    "local_node": "leaf-a",
                    "remote_node": "leaf-b",
                    "local_as": 65001,
                    "remote_as": 65002,
                    "address_families": ["l2vpn-evpn"],
                }
            ],
            "vteps": [
                {"node": "leaf-a", "source_interface": "lo0", "peers": ["leaf-b"]},
                {"node": "leaf-b", "source_interface": "lo0", "peers": ["leaf-a"]},
            ],
            "evpn_instances": [
                {
                    "name": "a-evpn",
                    "tenant": "tenant-a",
                    "rd": "65001:100",
                    "import_rts": ["target:65001:100"],
                    "export_rts": ["target:65001:100"],
                }
            ],
            "l2_vnis": [{"vni": 10100, "vlan": 100, "evpn_instance": "a-evpn", "vtep": "leaf-a"}],
            "l3_vnis": [
                {"vni": 20100, "vrf": "a-vrf", "evpn_instance": "a-evpn", "vtep": "leaf-a"}
            ],
        }
    )


def _with_tenant_b(source: FeatureContract, vni: int, rd_suffix: int) -> FeatureContract:
    return source.model_copy(
        update={
            "vrfs": (*source.vrfs, VRF(name="b-vrf", tenant="tenant-b")),
            "evpn_instances": (
                *source.evpn_instances,
                EVPNInstance(
                    name="b-evpn",
                    tenant="tenant-b",
                    rd=f"65002:{rd_suffix}",
                    import_rts=frozenset({f"target:65002:{rd_suffix}"}),
                    export_rts=frozenset({f"target:65002:{rd_suffix}"}),
                ),
            ),
            "l2_vnis": (
                *source.l2_vnis,
                L2VNI(vni=vni, vlan=100, evpn_instance="b-evpn", vtep="leaf-a"),
            ),
            "l3_vnis": (
                *source.l3_vnis,
                L3VNI(
                    vni=vni + 1_000_000,
                    vrf="b-vrf",
                    evpn_instance="b-evpn",
                    vtep="leaf-a",
                ),
            ),
        }
    )


@settings(max_examples=25, derandomize=True, deadline=None)
@given(
    vni=st.integers(min_value=100_000, max_value=999_999),
    rd_suffix=st.integers(min_value=1, max_value=999_999),
)
def test_disjoint_tenant_extension_preserves_existing_projection(vni: int, rd_suffix: int) -> None:
    baseline = _source()
    extended = _with_tenant_b(_source(), vni, rd_suffix)

    assert project_test_pack_for_tenant(compile_test_pack(baseline), "tenant-a").clauses == (
        project_test_pack_for_tenant(compile_test_pack(extended), "tenant-a").clauses
    )


@settings(max_examples=25, derandomize=True, deadline=None)
@given(rd_suffix=st.integers(min_value=1, max_value=999_999))
def test_changing_existing_tenant_changes_its_projection(rd_suffix: int) -> None:
    baseline = _source()
    changed = _source()
    updated_evpn = changed.evpn_instances[0].model_copy(
        update={
            "rd": f"65001:{rd_suffix + 1000}",
            "import_rts": frozenset({f"target:65001:{rd_suffix + 1000}"}),
            "export_rts": frozenset({f"target:65001:{rd_suffix + 1000}"}),
        }
    )
    changed = changed.model_copy(
        update={"evpn_instances": (updated_evpn, *changed.evpn_instances[1:])}
    )

    assert project_test_pack_for_tenant(compile_test_pack(baseline), "tenant-a") != (
        project_test_pack_for_tenant(compile_test_pack(changed), "tenant-a")
    )
