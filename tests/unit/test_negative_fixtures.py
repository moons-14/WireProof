from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from wireproof_compiler import load_plan
from wireproof_core import FeatureContract


@pytest.mark.parametrize("fixture", sorted(Path("tests/fixtures").glob("*.yaml")))
def test_negative_fixture_is_detected(fixture: Path) -> None:
    mutation = yaml.safe_load(fixture.read_text())["mutation"]
    document = deepcopy(load_plan(Path("examples/evpn-fabric.yaml")).model_dump(mode="json"))
    if mutation == "wrong_rt":
        document["evpn_instances"][0]["export_rts"] = ["target:65000:999"]
    elif mutation == "wrong_vni":
        document["l3_vnis"][0]["vni"] = document["l2_vnis"][0]["vni"]
    elif mutation == "default_route_leak":
        for default_prefix in ("0.0.0.0/0", "::/0"):
            candidate = deepcopy(document)
            candidate["management_export_policy"] = "tenant-export"
            candidate["prefix_sets"][0]["prefixes"] = [default_prefix]
            candidate["route_policies"][0]["terms"][0]["prefix_set"] = "default-only"
            with pytest.raises(
                ValidationError, match="management export policy permits default route"
            ):
                FeatureContract.model_validate(candidate)
        return
    elif mutation == "cross_tenant_rt":
        document["evpn_instances"][1]["export_rts"] = ["target:65000:101"]
    elif mutation == "missing_evpn_af":
        document["bgp_sessions"][0]["address_families"] = ["ipv4-unicast"]
    elif mutation == "stale_fdb":
        document["static_fdb"] = [{"mac": "02:00:00:00:00:01", "vlan": 101, "vtep": "missing"}]
    elif mutation == "asymmetric_vtep":
        document["vteps"][0]["peers"] = ["leaf2"]
    else:
        raise AssertionError(mutation)
    with pytest.raises(ValidationError):
        FeatureContract.model_validate(document)


def test_shared_service_evpn_instance_may_share_a_route_target() -> None:
    document = deepcopy(load_plan(Path("examples/evpn-fabric.yaml")).model_dump(mode="json"))
    document["evpn_instances"][1].update(
        {
            "import_rts": ["target:65000:101"],
            "export_rts": ["target:65000:101"],
            "shared_service": True,
        }
    )

    FeatureContract.model_validate(document)


def test_l3vni_evpn_tenant_must_match_its_vrf() -> None:
    document = deepcopy(load_plan(Path("examples/evpn-fabric.yaml")).model_dump(mode="json"))
    document["evpn_instances"][2]["tenant"] = "b"

    with pytest.raises(ValidationError, match="must match VRF tenant"):
        FeatureContract.model_validate(document)
