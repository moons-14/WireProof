from __future__ import annotations

import pytest
from wireproof_compiler import compile_plan, compile_test_pack
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
