from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from wireproof_core import FeatureContract


class TopologyDeclaration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    nodes: tuple[str, ...]
    links: tuple[tuple[str, str], ...]
    provenance_clauses: tuple[str, ...]


class ImageDeclaration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    reference: str


FRR_IMAGE_REFERENCE = (
    "quay.io/frrouting/frr@sha256:17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
)
CONTAINERLAB_SCHEMA = "containerlab-0.59.0"


def _is_non_string_collection(value: object) -> bool:
    return isinstance(value, Collection) and not isinstance(value, (str, bytes, Mapping))


def _normalize_string_collection(value: object) -> object:
    if isinstance(value, Collection) and not isinstance(value, (str, bytes, Mapping)):
        collection = cast(Collection[object], value)
        if all(isinstance(item, str) for item in collection):
            return tuple(sorted(cast(Collection[str], collection)))
    return value


def _node_sort_key(node: object) -> str:
    if isinstance(node, ContainerlabNode):
        return node.name
    if isinstance(node, Mapping) and isinstance(node.get("name"), str):
        return cast(str, node["name"])
    return ""


def _link_sort_key(link: object) -> tuple[str, ...]:
    if isinstance(link, ContainerlabLink):
        return link.endpoints
    if isinstance(link, Mapping) and _is_non_string_collection(link.get("endpoints")):
        endpoints = link["endpoints"]
        if all(isinstance(endpoint, str) for endpoint in endpoints):
            return tuple(endpoints)
    return ()


def _parse_reference_endpoint(endpoint: str) -> tuple[str, str]:
    if endpoint.count(":") != 1:
        raise ValueError("reference artifact endpoints must be exact node:interface pairs")
    node_name, interface_name = endpoint.split(":", maxsplit=1)
    if not node_name or not interface_name:
        raise ValueError("reference artifact endpoints must be exact node:interface pairs")
    return node_name, interface_name


class ContainerlabNode(BaseModel):
    """A reference node; this is an artifact, not a deployable topology file."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str = Field(min_length=1)
    roles: tuple[str, ...]
    image: str

    @field_validator("image")
    @classmethod
    def require_pinned_frr(cls, value: str) -> str:
        if value != FRR_IMAGE_REFERENCE:
            raise ValueError("reference nodes require the pinned FRR 10.5.4 image index")
        return value


class ContainerlabLink(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    endpoints: tuple[str, str]


class ContainerlabReferenceArtifact(BaseModel):
    """Immutable, canonical description of the Containerlab reference target.

    Nodes, links, and clause IDs are sorted before construction.  Therefore a
    semantically reordered IR produces identical artifact bytes and hash.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    artifact_schema: str = Field(
        default=CONTAINERLAB_SCHEMA,
        serialization_alias="schema",
        validation_alias="schema",
    )
    name: str = "wireproof-reference"
    nodes: tuple[ContainerlabNode, ...]
    links: tuple[ContainerlabLink, ...]
    semantic_ir_hash: str
    provenance_clauses: tuple[str, ...]
    component_versions: tuple[
        Literal["containerlab=0.59.0"],
        Literal["frr=10.5.4"],
        Literal["frr_commit=4cb6d9e"],
    ] = (
        "containerlab=0.59.0",
        "frr=10.5.4",
        "frr_commit=4cb6d9e",
    )
    canonical_ordering: Literal["nodes,links,clauses:lexicographic"] = (
        "nodes,links,clauses:lexicographic"
    )

    @field_validator("artifact_schema")
    @classmethod
    def require_supported_schema(cls, value: str) -> str:
        if value != CONTAINERLAB_SCHEMA:
            raise ValueError("reference artifacts require the pinned Containerlab schema")
        return value

    @model_validator(mode="before")
    @classmethod
    def normalize_unordered_collections(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        normalized = dict(value)
        if _is_non_string_collection(normalized.get("nodes")):
            normalized["nodes"] = tuple(
                sorted(
                    (
                        node.model_copy(update={"roles": tuple(sorted(node.roles))})
                        if isinstance(node, ContainerlabNode)
                        else {
                            **node,
                            **(
                                {"roles": tuple(sorted(node["roles"]))}
                                if isinstance(node, Mapping)
                                and _is_non_string_collection(node.get("roles"))
                                and all(isinstance(role, str) for role in node["roles"])
                                else {}
                            ),
                        }
                        if isinstance(node, Mapping)
                        else node
                        for node in normalized["nodes"]
                    ),
                    key=_node_sort_key,
                )
            )
        if _is_non_string_collection(normalized.get("links")):
            normalized["links"] = tuple(
                sorted(
                    (
                        link.model_copy(update={"endpoints": tuple(sorted(link.endpoints))})
                        if isinstance(link, ContainerlabLink)
                        else {
                            **link,
                            **(
                                {"endpoints": tuple(sorted(link["endpoints"]))}
                                if isinstance(link, Mapping)
                                and _is_non_string_collection(link.get("endpoints"))
                                and all(isinstance(endpoint, str) for endpoint in link["endpoints"])
                                else {}
                            ),
                        }
                        if isinstance(link, Mapping)
                        else link
                        for link in normalized["links"]
                    ),
                    key=_link_sort_key,
                )
            )
        if "provenance_clauses" in normalized:
            normalized["provenance_clauses"] = _normalize_string_collection(
                normalized["provenance_clauses"]
            )
        return normalized

    @model_validator(mode="after")
    def validate_canonical_invariants(self) -> ContainerlabReferenceArtifact:
        node_names = tuple(node.name for node in self.nodes)
        link_endpoints = tuple(link.endpoints for link in self.links)
        if len(node_names) != len(set(node_names)):
            raise ValueError("reference artifact node identities must be unique")
        for endpoints in link_endpoints:
            parsed_endpoints = tuple(_parse_reference_endpoint(endpoint) for endpoint in endpoints)
            if parsed_endpoints[0][0] == parsed_endpoints[1][0]:
                raise ValueError("reference artifact links must connect distinct nodes")
            if any(node_name not in node_names for node_name, _ in parsed_endpoints):
                raise ValueError("reference artifact link endpoints must reference declared nodes")
        if len(link_endpoints) != len(set(link_endpoints)):
            raise ValueError("reference artifact links must be unique")
        if any(not clause for clause in self.provenance_clauses):
            raise ValueError("reference artifact provenance clauses must be nonempty")
        if len(self.provenance_clauses) != len(set(self.provenance_clauses)):
            raise ValueError("reference artifact provenance clauses must be unique")
        if re.fullmatch(r"[0-9a-f]{64}", self.semantic_ir_hash) is None:
            raise ValueError("semantic_ir_hash must be a lowercase SHA-256 digest")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json", by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def canonical_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _canonical_ir_hash(plan: FeatureContract) -> str:
    """Normalize unordered IR collections before binding them into an artifact."""

    def normalize(value: Any, path: tuple[str, ...] = ()) -> Any:
        if isinstance(value, dict):
            return {key: normalize(item, path + (key,)) for key, item in sorted(value.items())}
        if isinstance(value, (list, tuple)):
            normalized = [normalize(item, path) for item in value]
            if path[-1:] == ("terms",):
                return normalized
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
            )
        if isinstance(value, (set, frozenset)):
            normalized = [normalize(item, path) for item in value]
            return sorted(
                normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
            )
        return value

    payload = json.dumps(
        normalize(plan.model_dump(mode="json")), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class RuntimeMetadata(BaseModel):
    """Frozen compiler output required to make a runtime record reproducible."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    semantic_ir_hash: str
    reference_topology_hash: str
    provenance_clauses: tuple[str, ...]
    image: ImageDeclaration
    component_versions: tuple[str, ...]
    coverage: tuple[str, ...]


def load_plan(path: Path) -> FeatureContract:
    return FeatureContract.model_validate(yaml.safe_load(path.read_text()))


def compile_plan(plan: FeatureContract) -> dict[str, Any]:
    """Compile only immutable declarative reference topology; lifecycle belongs to runtime."""
    nodes = tuple(
        ContainerlabNode(name=node.name, roles=tuple(sorted(node.roles)), image=FRR_IMAGE_REFERENCE)
        for node in sorted(plan.nodes, key=lambda item: item.name)
    )
    links = tuple(
        ContainerlabLink(
            endpoints=cast(
                tuple[str, str],
                tuple(
                    sorted(
                        (f"{link.a.node}:{link.a.interface}", f"{link.b.node}:{link.b.interface}")
                    )
                ),
            )
        )
        for link in sorted(
            plan.links,
            key=lambda item: tuple(
                sorted((f"{item.a.node}:{item.a.interface}", f"{item.b.node}:{item.b.interface}"))
            ),
        )
    )
    clauses = tuple(sorted(clause.id for clause in plan.clauses))
    artifact = ContainerlabReferenceArtifact(
        nodes=nodes,
        links=links,
        semantic_ir_hash=_canonical_ir_hash(plan),
        provenance_clauses=clauses,
    )
    topology: dict[str, Any] = {
        "name": artifact.name,
        "nodes": [{"name": node.name, "roles": list(node.roles)} for node in artifact.nodes],
        "links": [{"endpoints": list(link.endpoints)} for link in artifact.links],
        "provenance": {"clauses": list(artifact.provenance_clauses)},
    }
    declaration = TopologyDeclaration(
        name=topology["name"],
        nodes=tuple(node.name for node in artifact.nodes),
        links=tuple(link.endpoints for link in artifact.links),
        provenance_clauses=artifact.provenance_clauses,
    )
    image = ImageDeclaration(reference=FRR_IMAGE_REFERENCE)
    semantic_ir_hash = artifact.semantic_ir_hash
    reference_topology_hash = artifact.canonical_hash
    runtime_metadata = RuntimeMetadata(
        semantic_ir_hash=semantic_ir_hash,
        reference_topology_hash=reference_topology_hash,
        provenance_clauses=declaration.provenance_clauses,
        image=image,
        component_versions=artifact.component_versions,
        coverage=("state_transition", "failure_scenario", "target_command_provenance"),
    )
    return {
        "semantic_ir_hash": semantic_ir_hash,
        "reference_topology": topology,
        "reference_topology_hash": reference_topology_hash,
        "reference_artifact": artifact,
        "topology": declaration,
        "image": image,
        "runtime_metadata": runtime_metadata,
    }
