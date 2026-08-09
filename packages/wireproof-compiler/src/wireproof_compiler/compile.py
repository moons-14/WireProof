from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from wireproof_core import FeatureContract


def load_plan(path: Path) -> FeatureContract:
    return FeatureContract.model_validate(yaml.safe_load(path.read_text()))


def compile_plan(plan: FeatureContract) -> dict[str, Any]:
    """Compile only declarative reference topology; lifecycle belongs to runtime."""
    topology = {
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
    encoded = json.dumps(topology, sort_keys=True, separators=(",", ":"))
    return {
        "semantic_ir_hash": plan.canonical_hash(),
        "reference_topology": topology,
        "reference_topology_hash": hashlib.sha256(encoded.encode()).hexdigest(),
    }
