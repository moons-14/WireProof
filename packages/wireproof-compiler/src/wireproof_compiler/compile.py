from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

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
TEST_PACK_SCHEMA: Literal["wireproof-test-pack-2"] = "wireproof-test-pack-2"


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


class TestPackClause(BaseModel):
    """A declarative requirement emitted by the compiler, never a test result."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"^test\.[a-z]+\.[0-9a-f]{16}$")
    state: Literal["UNEXECUTED"] = "UNEXECUTED"
    requirement_kind: Literal["vni", "rd", "evpn", "vrf", "vlan", "bgp"]
    source_identity: str = Field(min_length=1)
    tenant: str | None = None
    provenance_clauses: tuple[str, ...]
    expected_condition: dict[str, Any]

    @model_validator(mode="before")
    @classmethod
    def normalize_provenance(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and "provenance_clauses" in value:
            normalized = dict(value)
            normalized["provenance_clauses"] = _normalize_string_collection(
                normalized["provenance_clauses"]
            )
            return normalized
        return value

    @field_validator("tenant")
    @classmethod
    def normalize_tenant(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("tenant must be nonempty when specified")
        return normalized


class TestPack(BaseModel):
    """Canonical compiler output describing requirements for a future executor.

    A TestPack deliberately contains no target, execution, observation, or result
    data.  Those concerns belong to the runtime and evidence layers.
    """

    __test__: ClassVar[bool] = False

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["wireproof-test-pack-2"] = TEST_PACK_SCHEMA
    semantic_ir_hash: str
    clauses: tuple[TestPackClause, ...]
    canonical_ordering: Literal["clauses:id:lexicographic"] = "clauses:id:lexicographic"
    generator_identity: str | None = "wireproof-compiler"
    parent_canonical_hash: str | None = None
    projection_tenant: str | None = None

    @field_validator("projection_tenant")
    @classmethod
    def normalize_projection_tenant(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("projection_tenant must be nonempty when specified")
        return normalized

    @model_validator(mode="before")
    @classmethod
    def normalize_clauses(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and _is_non_string_collection(value.get("clauses")):
            normalized = dict(value)
            normalized["clauses"] = tuple(
                sorted(
                    value["clauses"],
                    key=lambda item: item.id if isinstance(item, TestPackClause) else item["id"],
                )
            )
            return normalized
        return value

    @model_validator(mode="after")
    def validate_canonical_invariants(self) -> TestPack:
        if re.fullmatch(r"[0-9a-f]{64}", self.semantic_ir_hash) is None:
            raise ValueError("semantic_ir_hash must be a lowercase SHA-256 digest")
        clause_ids = tuple(clause.id for clause in self.clauses)
        if len(clause_ids) != len(set(clause_ids)):
            raise ValueError("test pack clause identities must be unique")
        if (self.parent_canonical_hash is None) != (self.projection_tenant is None):
            raise ValueError("projection provenance fields must be specified together")
        if self.projection_tenant is not None and any(
            clause.tenant != self.projection_tenant for clause in self.clauses
        ):
            raise ValueError("projected test pack clauses must match projection_tenant")
        if (
            self.parent_canonical_hash is not None
            and re.fullmatch(r"[0-9a-f]{64}", self.parent_canonical_hash) is None
        ):
            raise ValueError("parent_canonical_hash must be a lowercase SHA-256 digest")
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
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


def semantic_ir_hash(plan: FeatureContract) -> str:
    """Return the canonical semantic fingerprint without compiling artifacts."""
    if not isinstance(plan, FeatureContract):
        raise TypeError("plan must be a FeatureContract")
    return _canonical_ir_hash(plan)


def _canonical_condition(value: Any) -> Any:
    """Turn a model payload into a deterministic JSON-compatible condition."""
    if isinstance(value, Mapping):
        return {key: _canonical_condition(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized = [_canonical_condition(item) for item in value]
        return sorted(
            normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
        )
    return value


def _test_pack_clause(
    kind: Literal["vni", "rd", "evpn", "vrf", "vlan", "bgp"],
    identity: str,
    source: Any,
    provenance: tuple[str, ...],
    tenant: str | None = None,
) -> TestPackClause:
    digest = hashlib.sha256(f"{kind}:{identity}".encode()).hexdigest()[:16]
    return TestPackClause(
        id=f"test.{kind}.{digest}",
        requirement_kind=kind,
        source_identity=identity,
        tenant=tenant,
        provenance_clauses=provenance,
        expected_condition={
            "object_kind": kind,
            "expected": _canonical_condition(source.model_dump(mode="python")),
        },
    )


def compile_test_pack(plan: FeatureContract) -> TestPack:
    """Compile validated semantic IR into canonical, unexecuted requirements."""
    if not isinstance(plan, FeatureContract):
        raise TypeError("compile_test_pack requires a validated FeatureContract")
    provenance = tuple(sorted(clause.id for clause in plan.clauses))
    evpn_tenants = {entry.name: entry.tenant for entry in plan.evpn_instances}
    vrf_tenants = {entry.name: entry.tenant for entry in plan.vrfs}
    clauses = [
        *(
            _test_pack_clause(
                "vni", f"l2:{entry.vni}", entry, provenance, evpn_tenants[entry.evpn_instance]
            )
            for entry in plan.l2_vnis
        ),
        *(
            _test_pack_clause("vni", f"l3:{entry.vni}", entry, provenance, vrf_tenants[entry.vrf])
            for entry in plan.l3_vnis
        ),
        *(
            _test_pack_clause("rd", entry.rd, entry, provenance, entry.tenant)
            for entry in plan.evpn_instances
        ),
        *(
            _test_pack_clause("evpn", entry.name, entry, provenance, entry.tenant)
            for entry in plan.evpn_instances
        ),
        *(
            _test_pack_clause("vrf", entry.name, entry, provenance, entry.tenant)
            for entry in plan.vrfs
        ),
        *(_test_pack_clause("vlan", str(entry.id), entry, provenance) for entry in plan.vlans),
        *(
            _test_pack_clause(
                "bgp",
                (
                    f"{entry.local_node}:{entry.local_as}"
                    f"->{entry.remote_node}:{entry.remote_as}"
                    f";af={address_family.value}"
                ),
                entry.model_copy(
                    update={"address_families": frozenset((address_family,))}
                ),
                provenance,
            )
            for entry in plan.bgp_sessions
            for address_family in sorted(entry.address_families, key=str)
        ),
    ]
    return TestPack(semantic_ir_hash=_canonical_ir_hash(plan), clauses=tuple(clauses))


def project_test_pack_for_tenant(pack: TestPack, tenant: str) -> TestPack:
    """Return the unexecuted tenant-scoped obligations from a canonical TestPack."""
    if not isinstance(pack, TestPack):
        raise TypeError("project_test_pack_for_tenant requires a TestPack")
    normalized_tenant = tenant.strip()
    if not normalized_tenant:
        raise ValueError("tenant must be nonempty")
    known_tenants = {clause.tenant for clause in pack.clauses if clause.tenant is not None}
    if normalized_tenant not in known_tenants:
        raise ValueError(f"unknown tenant: {normalized_tenant}")
    if pack.projection_tenant == normalized_tenant:
        return pack
    return TestPack(
        semantic_ir_hash=pack.semantic_ir_hash,
        clauses=tuple(clause for clause in pack.clauses if clause.tenant == normalized_tenant),
        generator_identity=pack.generator_identity,
        parent_canonical_hash=pack.canonical_hash,
        projection_tenant=normalized_tenant,
    )


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
        "test_pack": compile_test_pack(plan),
    }
