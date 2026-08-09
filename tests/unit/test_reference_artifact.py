from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError
from wireproof_compiler import (
    CONTAINERLAB_SCHEMA,
    FRR_IMAGE_REFERENCE,
    ContainerlabLink,
    ContainerlabNode,
    ContainerlabReferenceArtifact,
    compile_plan,
    load_plan,
)
from wireproof_core.model import RoutePolicy, RoutePolicyTerm
from wireproof_evidence import ExecutionMode, Result
from wireproof_runtime import (
    RecordedContainerlabAdapter,
    ResourceOwnership,
    RuntimeOperation,
)

PLAN = Path("examples/evpn-fabric.yaml")


def test_reference_artifact_is_canonical_pinned_and_complete() -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]

    assert artifact.artifact_schema == CONTAINERLAB_SCHEMA
    assert artifact.model_dump(mode="json", by_alias=True)["schema"] == CONTAINERLAB_SCHEMA
    assert len(artifact.nodes) == 6
    assert len(artifact.links) == 8
    assert artifact.provenance_clauses == ("EVPN_M1",)
    assert artifact.component_versions == (
        "containerlab=0.59.0",
        "frr=10.5.4",
        "frr_commit=4cb6d9e",
    )
    assert {node.image for node in artifact.nodes} == {FRR_IMAGE_REFERENCE}
    assert (
        artifact.canonical_hash
        == "edc2400179385809ad3f045b644db2d6f938a4b29e6a2c514448d1c839f05019"
    )
    assert (
        artifact.canonical_bytes
        == compile_plan(load_plan(PLAN))["reference_artifact"].canonical_bytes
    )
    with pytest.raises((TypeError, ValueError)):
        artifact.nodes += ()  # type: ignore[misc]


def test_reference_artifact_hash_ignores_ir_collection_order() -> None:
    plan = load_plan(PLAN)
    reordered = plan.model_copy(
        update={"nodes": tuple(reversed(plan.nodes)), "links": tuple(reversed(plan.links))}
    )

    assert (
        compile_plan(plan)["reference_artifact"].canonical_hash
        == compile_plan(reordered)["reference_artifact"].canonical_hash
    )


def test_direct_artifact_construction_normalizes_unordered_collections() -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    reordered = ContainerlabReferenceArtifact(
        nodes=tuple(reversed(artifact.nodes)),
        links=tuple(
            ContainerlabLink(endpoints=tuple(reversed(link.endpoints)))
            for link in reversed(artifact.links)
        ),
        semantic_ir_hash=artifact.semantic_ir_hash,
        provenance_clauses=tuple(reversed(artifact.provenance_clauses)),
    )

    assert reordered.canonical_bytes == artifact.canonical_bytes
    assert reordered.canonical_hash == artifact.canonical_hash
    assert tuple(node.name for node in reordered.nodes) == tuple(
        sorted(node.name for node in artifact.nodes)
    )


def test_serialized_artifact_mapping_normalizes_unordered_collections() -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    serialized = artifact.model_dump(mode="json", by_alias=True)
    reordered = {
        **serialized,
        "nodes": list(reversed(serialized["nodes"])),
        "links": [
            {**link, "endpoints": list(reversed(link["endpoints"]))}
            for link in reversed(serialized["links"])
        ],
        "provenance_clauses": list(reversed(serialized["provenance_clauses"])),
    }

    normalized = ContainerlabReferenceArtifact.model_validate(reordered)

    assert normalized.canonical_bytes == artifact.canonical_bytes
    assert normalized.canonical_hash == artifact.canonical_hash


@pytest.mark.parametrize(
    "update",
    (
        lambda artifact: {"nodes": artifact.nodes + (artifact.nodes[0],)},
        lambda artifact: {"links": artifact.links + (artifact.links[0],)},
        lambda artifact: {
            "links": artifact.links + (ContainerlabLink(endpoints=("leaf1:eth1", "leaf1:eth2")),)
        },
        lambda artifact: {"provenance_clauses": ("EVPN_M1", "EVPN_M1")},
        lambda artifact: {"semantic_ir_hash": "A" * 64},
        lambda artifact: {"semantic_ir_hash": "a" * 63},
    ),
)
def test_direct_artifact_rejects_noncanonical_identity_or_hash(
    update: Callable[[ContainerlabReferenceArtifact], dict[str, object]],
) -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    payload = artifact.model_dump()
    payload.update(update(artifact))

    with pytest.raises(ValueError):
        ContainerlabReferenceArtifact(**payload)


@pytest.mark.parametrize(
    "endpoints",
    (
        ("leaf1", "spine1:eth1"),
        ("leaf1:", "spine1:eth1"),
        (":eth1", "spine1:eth1"),
        ("leaf1:eth1:extra", "spine1:eth1"),
        ("leaf1:eth1", "missing:eth1"),
    ),
)
def test_reference_artifact_rejects_malformed_or_dangling_endpoints(
    endpoints: tuple[str, str],
) -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    payload = artifact.model_dump()
    payload["links"] = ({"endpoints": endpoints},)

    with pytest.raises(ValueError):
        ContainerlabReferenceArtifact(**payload)


@pytest.mark.parametrize(
    "field,value",
    (
        ("nodes", ("not-a-node",)),
        ("links", ("not-a-link",)),
        (
            "nodes",
            (
                {
                    "name": "leaf1",
                    "roles": "leaf",
                    "image": FRR_IMAGE_REFERENCE,
                },
            ),
        ),
        (
            "nodes",
            (
                {
                    "name": "leaf1",
                    "roles": {"role": "leaf"},
                    "image": FRR_IMAGE_REFERENCE,
                },
            ),
        ),
        ("links", ({"endpoints": {"a": "leaf1:eth1"}},)),
        ("provenance_clauses", "EVPN_M1"),
        ("provenance_clauses", {"clause": "EVPN_M1"}),
    ),
)
def test_reference_artifact_invalid_raw_collections_raise_validation_error(
    field: str, value: object
) -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    payload = artifact.model_dump()
    payload[field] = value

    with pytest.raises(ValidationError):
        ContainerlabReferenceArtifact(**payload)


def test_reference_artifact_rejects_unapproved_schema_or_component_tuple() -> None:
    artifact = compile_plan(load_plan(PLAN))["reference_artifact"]
    serialized = artifact.model_dump(mode="json", by_alias=True)

    with pytest.raises(ValueError):
        ContainerlabReferenceArtifact.model_validate(
            {**serialized, "schema": "containerlab-0.60.0"}
        )
    with pytest.raises(ValueError):
        ContainerlabReferenceArtifact.model_validate(
            {
                **serialized,
                "component_versions": [
                    "containerlab=0.59.0",
                    "frr=10.5.5",
                    "frr_commit=4cb6d9e",
                ],
            }
        )


def test_reference_artifact_hash_preserves_route_policy_term_order() -> None:
    plan = load_plan(PLAN)
    policy = RoutePolicy(
        name="ordered-policy",
        terms=(
            RoutePolicyTerm(name="first", action="deny"),
            RoutePolicyTerm(name="second", action="permit"),
        ),
    )
    reversed_policy = policy.model_copy(update={"terms": tuple(reversed(policy.terms))})
    first = plan.model_copy(update={"route_policies": (policy,)})
    second = plan.model_copy(update={"route_policies": (reversed_policy,)})

    assert compile_plan(first)["semantic_ir_hash"] != compile_plan(second)["semantic_ir_hash"]


@pytest.mark.parametrize(
    "image",
    [
        "quay.io/frrouting/frr:latest@sha256:" + "a" * 64,
        "quay.io/frrouting/frr:10.5.4",
        "quay.io/frrouting/frr@sha256:" + "0" * 64,
        "wireproof/reference:1@sha256:" + "0" * 64,
        "not-an-image",
    ],
)
def test_reference_nodes_reject_non_pinned_or_placeholder_images(image: str) -> None:
    with pytest.raises(ValueError):
        ContainerlabNode(name="leaf1", roles=("leaf",), image=image)


def test_recorded_adapter_is_closed_fake_only_and_preserves_mismatched_residue() -> None:
    ownership = ResourceOwnership("containerlab-lab", "clos-a", "wireproof", "run-a")
    adapter = RecordedContainerlabAdapter()
    plan = adapter.dry_plan(RuntimeOperation.DEPLOY, ownership)

    assert plan.execution_mode is ExecutionMode.FAKE
    assert not plan.promotion_allowed
    assert plan.commands[0].argv == ("wireproof-runtime", "deploy", "--run-id", "run-a")
    residue = adapter.inspect_residue(
        (
            ResourceOwnership("containerlab-lab", "other", "wireproof", "run-b"),
            ownership,
        ),
        ownership,
    )
    assert residue.result is Result.PASS
    assert residue.residues == (ownership,)
    assert not residue.cleanup_succeeded
    assert adapter.inspect_residue(None, ownership).result is Result.UNKNOWN


def test_recorded_ownership_requires_both_wireproof_labels() -> None:
    with pytest.raises(ValueError):
        ResourceOwnership("containerlab-lab", "clos-a", "other", "run-a")
