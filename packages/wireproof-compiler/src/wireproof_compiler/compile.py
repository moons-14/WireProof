from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict
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
    topology: dict[str, Any] = {
        "name": "wireproof-reference",
        "nodes": [{"name": node.name, "roles": sorted(node.roles)} for node in plan.nodes],
        "links": [
            {
                "endpoints": [
                    f"{link.a.node}:{link.a.interface}",
                    f"{link.b.node}:{link.b.interface}",
                ]
            }
            for link in plan.links
        ],
        "provenance": {"clauses": [clause.id for clause in plan.clauses]},
    }
    declaration = TopologyDeclaration(
        name=topology["name"],
        nodes=tuple(node["name"] for node in topology["nodes"]),
        links=tuple(tuple(link["endpoints"]) for link in topology["links"]),
        provenance_clauses=tuple(topology["provenance"]["clauses"]),
    )
    image = ImageDeclaration(reference="wireproof/reference:1@sha256:" + "0" * 64)
    encoded = json.dumps(topology, sort_keys=True, separators=(",", ":"))
    semantic_ir_hash = plan.canonical_hash()
    reference_topology_hash = hashlib.sha256(encoded.encode()).hexdigest()
    runtime_metadata = RuntimeMetadata(
        semantic_ir_hash=semantic_ir_hash,
        reference_topology_hash=reference_topology_hash,
        provenance_clauses=declaration.provenance_clauses,
        image=image,
        component_versions=("wireproof-reference=1",),
        coverage=("state_transition", "failure_scenario", "target_command_provenance"),
    )
    return {
        "semantic_ir_hash": semantic_ir_hash,
        "reference_topology": topology,
        "reference_topology_hash": reference_topology_hash,
        "topology": declaration,
        "image": image,
        "runtime_metadata": runtime_metadata,
    }
