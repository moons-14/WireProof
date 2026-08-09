from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError
from wireproof_core import FeatureContract


@given(st.integers(min_value=1, max_value=16_777_215))
def test_duplicate_vni_is_rejected(vni: int) -> None:
    base = {
        "nodes": [{"name": "l1", "interfaces": [{"name": "lo"}]}],
        "links": [],
        "vlans": [{"id": 1, "name": "one"}],
        "vrfs": [{"name": "v", "tenant": "t"}],
        "bgp_sessions": [],
        "vteps": [{"node": "l1", "source_interface": "lo"}],
        "evpn_instances": [
            {"name": "e", "rd": "1:1", "import_rts": ["target:1:1"], "export_rts": ["target:1:1"]}
        ],
        "l2_vnis": [{"vni": vni, "vlan": 1, "evpn_instance": "e", "vtep": "l1"}],
        "l3_vnis": [{"vni": vni, "vrf": "v", "evpn_instance": "e", "vtep": "l1"}],
    }
    try:
        FeatureContract.model_validate(base)
    except ValidationError:
        return
    raise AssertionError("duplicate VNI must fail")
