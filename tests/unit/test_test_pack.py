from __future__ import annotations

import pytest
from wireproof_compiler import (
    TestPack,
    compile_plan,
    compile_test_pack,
    project_test_pack_for_tenant,
)
from wireproof_core import FeatureContract


def _plan() -> FeatureContract:
    return FeatureContract.model_validate(
        {
            "clauses": [{"id": "EVPN_BASE", "statement": "EVPN is required"}],
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
            "vlans": [{"id": 100, "name": "blue"}],
            "vrfs": [{"name": "blue", "tenant": "tenant-a"}],
            "bgp_sessions": [
                {
                    "local_node": "leaf-a",
                    "remote_node": "leaf-b",
                    "local_as": 65001,
                    "remote_as": 65002,
                    "address_families": ["ipv4-unicast", "l2vpn-evpn"],
                }
            ],
            "vteps": [
                {"node": "leaf-a", "source_interface": "lo0", "peers": ["leaf-b"]},
                {"node": "leaf-b", "source_interface": "lo0", "peers": ["leaf-a"]},
            ],
            "evpn_instances": [
                {
                    "name": "blue-evi",
                    "tenant": "tenant-a",
                    "rd": "65001:100",
                    "import_rts": ["target:65001:100"],
                    "export_rts": ["target:65001:100"],
                }
            ],
            "l2_vnis": [{"vni": 10100, "vlan": 100, "evpn_instance": "blue-evi", "vtep": "leaf-a"}],
            "l3_vnis": [
                {"vni": 20100, "vrf": "blue", "evpn_instance": "blue-evi", "vtep": "leaf-a"}
            ],
        }
    )


def test_test_pack_is_canonical_and_unexecuted() -> None:
    pack = compile_test_pack(_plan())
    assert pack.canonical_bytes == compile_test_pack(_plan()).canonical_bytes
    assert pack.canonical_hash == compile_test_pack(_plan()).canonical_hash
    assert [clause.id for clause in pack.clauses] == sorted(clause.id for clause in pack.clauses)
    assert {clause.requirement_kind for clause in pack.clauses} == {
        "vni",
        "rd",
        "evpn",
        "vrf",
        "vlan",
        "bgp",
    }
    assert all(clause.state == "UNEXECUTED" for clause in pack.clauses)
    assert all(clause.provenance_clauses == ("EVPN_BASE",) for clause in pack.clauses)
    assert "runtime" not in pack.canonical_bytes.decode()
    assert "result" not in pack.canonical_bytes.decode()


def test_test_pack_matches_semantically_reordered_plan() -> None:
    source = _plan().model_dump(mode="json")
    for key in (
        "nodes",
        "links",
        "vlans",
        "vrfs",
        "bgp_sessions",
        "vteps",
        "evpn_instances",
        "l2_vnis",
        "l3_vnis",
    ):
        source[key].reverse()
    reordered = FeatureContract.model_validate(source)
    assert (
        compile_test_pack(_plan()).canonical_bytes == compile_test_pack(reordered).canonical_bytes
    )


def test_test_pack_emits_a_distinct_bgp_clause_for_each_address_family() -> None:
    pack = compile_test_pack(_plan())
    bgp_clauses = [clause for clause in pack.clauses if clause.requirement_kind == "bgp"]

    assert len(bgp_clauses) == 2
    assert {clause.source_identity for clause in bgp_clauses} == {
        "leaf-a:65001->leaf-b:65002;af=ipv4-unicast",
        "leaf-a:65001->leaf-b:65002;af=l2vpn-evpn",
    }
    assert {
        tuple(clause.expected_condition["expected"]["address_families"])
        for clause in bgp_clauses
    } == {("ipv4-unicast",), ("l2vpn-evpn",)}


def test_contract_rejects_duplicate_bgp_peer_address_family() -> None:
    source = _plan().model_dump(mode="json")
    source["bgp_sessions"].append(source["bgp_sessions"][0])

    with pytest.raises(ValueError, match="duplicate BGP session peer address family"):
        FeatureContract.model_validate(source)


def test_compile_plan_preserves_existing_output_when_adding_sibling_pack() -> None:
    output = compile_plan(_plan())
    assert output["test_pack"] == compile_test_pack(_plan())
    assert output["reference_topology_hash"] == output["reference_artifact"].canonical_hash


def test_project_test_pack_for_tenant_is_immutable_and_excludes_global_obligations() -> None:
    pack = compile_test_pack(_plan())
    projected = project_test_pack_for_tenant(pack, " tenant-a ")

    assert projected is not pack
    assert projected.parent_canonical_hash == pack.canonical_hash
    assert projected.projection_tenant == "tenant-a"
    assert projected == project_test_pack_for_tenant(pack, "tenant-a")
    assert projected is project_test_pack_for_tenant(projected, "tenant-a")
    assert all(clause.tenant == "tenant-a" for clause in projected.clauses)
    assert all(clause.state == "UNEXECUTED" for clause in projected.clauses)
    assert {clause.requirement_kind for clause in projected.clauses} == {"vni", "rd", "evpn", "vrf"}
    assert {clause.source_identity for clause in projected.clauses} <= {
        clause.source_identity for clause in pack.clauses
    }


def test_projected_test_pack_rejects_mixed_tenant_or_global_clauses() -> None:
    pack = compile_test_pack(_plan())
    projected = project_test_pack_for_tenant(pack, "tenant-a")
    global_clause = next(clause for clause in pack.clauses if clause.tenant is None)

    with pytest.raises(ValueError, match="must match projection_tenant"):
        TestPack.model_validate(
            {
                **projected.model_dump(mode="json"),
                "clauses": [*projected.clauses, global_clause],
            }
        )


def test_test_pack_v1_artifacts_are_rejected() -> None:
    serialized = compile_test_pack(_plan()).model_dump(mode="json")
    serialized["schema_version"] = "wireproof-test-pack-1"

    with pytest.raises(ValueError, match="wireproof-test-pack-2"):
        TestPack.model_validate(serialized)


def test_tenant_projection_is_deterministic_for_semantically_reordered_input() -> None:
    source = _plan().model_dump(mode="json")
    for key in ("vrfs", "evpn_instances", "l2_vnis", "l3_vnis"):
        source[key].reverse()

    assert project_test_pack_for_tenant(compile_test_pack(_plan()), "tenant-a").canonical_bytes == (
        project_test_pack_for_tenant(
            compile_test_pack(FeatureContract.model_validate(source)), "tenant-a"
        ).canonical_bytes
    )


@pytest.mark.parametrize("tenant", ["", "   ", "unknown"])
def test_project_test_pack_for_tenant_rejects_unknown_or_blank_tenants(tenant: str) -> None:
    with pytest.raises(ValueError):
        project_test_pack_for_tenant(compile_test_pack(_plan()), tenant)
