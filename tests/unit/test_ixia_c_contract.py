import pytest
from wireproof_evidence import Result
from wireproof_runtime import (
    IxiaCAssessment,
    IxiaCComponent,
    IxiaCComponentInventory,
    IxiaCContract,
    IxiaCDeclaredState,
    IxiaCEulaIntent,
    IxiaCInvocation,
    IxiaCReason,
)


def _component(name: str, value: str) -> IxiaCComponent:
    digest = "sha256:" + value * 64
    repository = f"example.invalid/{name}"
    return IxiaCComponent(repository, "1.0.0", digest, f"{repository}:1.0.0@{digest}")


def _declared_invocation(inventory: IxiaCComponentInventory) -> IxiaCInvocation:
    return IxiaCInvocation(
        eula_intent=IxiaCEulaIntent.REQUEST_ACCEPT_EULA,
        eula_authorization=IxiaCDeclaredState.DECLARED,
        entitlement=IxiaCDeclaredState.DECLARED,
        license_server=IxiaCDeclaredState.DECLARED,
        inventory=inventory,
    )


def test_contract_identity_is_the_approved_literal_pin() -> None:
    contract = IxiaCContract()

    assert contract.repository == "ghcr.io/srl-labs/ixia-c-one"
    assert contract.version == "1.58.0-16"
    assert (
        contract.digest == "sha256:8a63a93bbd4c98bd2832e69689852ca13486be89bed02dc42a772e432f1203ab"
    )


def test_assessment_restricts_shared_result_to_unknown_or_fail() -> None:
    with pytest.raises(ValueError, match="cannot pass"):
        IxiaCAssessment(Result.PASS, ())


def test_unknown_assessment_requires_a_direct_constructor_blocker() -> None:
    with pytest.raises(ValueError, match="require at least one blocker"):
        IxiaCAssessment(Result.UNKNOWN, ())


def test_exact_declaration_stays_unknown_without_current_eula_authorization() -> None:
    assessment = IxiaCContract().evaluate(
        IxiaCInvocation(eula_intent=IxiaCEulaIntent.REQUEST_ACCEPT_EULA)
    )

    assert assessment.result is Result.UNKNOWN
    assert assessment.promotable is False
    assert assessment.mutation_permitted is False
    assert IxiaCReason.IXIA_EULA_AUTHORIZATION_UNKNOWN in assessment.blockers


def test_all_declared_inputs_remain_unknown_pending_local_authorization() -> None:
    assessment = IxiaCContract().evaluate(
        _declared_invocation(IxiaCComponentInventory((_component("one", "a"),), True))
    )

    assert assessment.result is Result.UNKNOWN
    assert assessment.blockers == (IxiaCReason.IXIA_LOCAL_AUTHORIZATION_UNVERIFIED,)


@pytest.mark.parametrize("field", ["entitlement", "license_server"])
def test_unknown_entitlement_or_license_server_is_a_specific_blocker(field: str) -> None:
    invocation = _declared_invocation(IxiaCComponentInventory((_component("one", "a"),), True))
    invocation = IxiaCInvocation(
        eula_intent=invocation.eula_intent,
        eula_authorization=invocation.eula_authorization,
        entitlement=(
            IxiaCDeclaredState.UNKNOWN if field == "entitlement" else invocation.entitlement
        ),
        license_server=(
            IxiaCDeclaredState.UNKNOWN if field == "license_server" else invocation.license_server
        ),
        inventory=invocation.inventory,
    )

    assessment = IxiaCContract().evaluate(invocation)
    expected = (
        IxiaCReason.IXIA_ENTITLEMENT_UNKNOWN
        if field == "entitlement"
        else IxiaCReason.IXIA_LICENSE_SERVER_UNKNOWN
    )
    assert assessment.blockers == (IxiaCReason.IXIA_LOCAL_AUTHORIZATION_UNVERIFIED, expected)


def test_inventory_order_does_not_change_assessment_and_duplicates_are_rejected() -> None:
    first, second = _component("one", "a"), _component("two", "b")
    contract = IxiaCContract()

    forward = contract.evaluate(
        _declared_invocation(IxiaCComponentInventory((first, second), True))
    )
    reverse = contract.evaluate(
        _declared_invocation(IxiaCComponentInventory((second, first), True))
    )
    assert forward == reverse
    with pytest.raises(ValueError, match="unique"):
        IxiaCComponentInventory((first, first), True)


@pytest.mark.parametrize(
    ("repository", "version", "digest", "source"),
    [
        ("example.invalid/component", "latest", "sha256:" + "a" * 64, ""),
        ("example.invalid/component", "MAIN", "sha256:" + "a" * 64, ""),
        ("example.invalid/component", "stable", "sha256:" + "a" * 64, ""),
        ("Example.invalid/component", "1.0.0", "sha256:" + "a" * 64, ""),
        ("example.invalid/component", "1.0.0", "sha256:" + "A" * 64, ""),
        (
            "example.invalid/component",
            "1.0.0",
            "sha256:" + "a" * 64,
            "example.invalid/component:1.0.1@sha256:" + "a" * 64,
        ),
    ],
)
def test_components_reject_floating_or_noncanonical_oci_bindings(
    repository: str, version: str, digest: str, source: str
) -> None:
    if not source:
        source = f"{repository}:{version}@{digest}"
    with pytest.raises(ValueError):
        IxiaCComponent(repository, version, digest, source)


def test_unverified_or_empty_inventory_has_unknown_provenance() -> None:
    assessment = IxiaCContract().evaluate(_declared_invocation(IxiaCComponentInventory((), False)))

    assert assessment.blockers == (
        IxiaCReason.IXIA_LOCAL_AUTHORIZATION_UNVERIFIED,
        IxiaCReason.IXIA_COMPONENT_INVENTORY_UNVERIFIED,
        IxiaCReason.IXIA_COMPONENT_PROVENANCE_UNKNOWN,
    )


@pytest.mark.parametrize("intent", ["ACCEPT_EULA", "REQUEST_ACCEPT_EULA ", ""])
def test_bad_eula_intents_are_rejected(intent: str) -> None:
    with pytest.raises(ValueError, match="closed invocation intent"):
        IxiaCInvocation(eula_intent=intent)  # type: ignore[arg-type]


def test_serialization_is_secret_free_and_never_promotes() -> None:
    serialized = (
        IxiaCContract()
        .evaluate(IxiaCInvocation(eula_intent=IxiaCEulaIntent.REQUEST_ACCEPT_EULA))
        .to_dict()
    )

    assert serialized["promotable"] is False
    assert serialized["mutation_permitted"] is False
    assert "authorization" not in serialized
    assert "license_server" not in serialized
