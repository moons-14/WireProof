from __future__ import annotations

import pytest
from wireproof_capability import (
    AuthorityProvenance,
    CapabilityAssessment,
    CapabilityEvidence,
    CapabilityIdentity,
    CapabilityProbe,
    CapabilityProbeSelector,
    CapabilityState,
    EvidenceKind,
    EvidenceOrigin,
    FixtureCapabilityProbe,
    ProbeKind,
    assess_capability,
    capabilities_satisfy,
)
from wireproof_compiler import CapabilityRequirement

IDENTITY = CapabilityIdentity(
    vendor="frr", platform="linux", version="10.5.4", feature="evpn"
)
CLAUSE = "EVPN_BASE"


def _evidence(state: CapabilityState) -> CapabilityEvidence:
    kind, origin = {
        CapabilityState.DOCUMENTED: (EvidenceKind.DOCUMENTATION, EvidenceOrigin.DOCUMENTATION),
        CapabilityState.EXPOSED: (EvidenceKind.EXPOSURE, EvidenceOrigin.READ_ONLY_PROBE),
        CapabilityState.ACCEPTED: (EvidenceKind.ACCEPTANCE, EvidenceOrigin.ACCEPTANCE_TEST),
        CapabilityState.REALIZED: (EvidenceKind.REALIZATION, EvidenceOrigin.OBSERVATION),
        CapabilityState.CONFORMANT: (EvidenceKind.CONFORMANCE, EvidenceOrigin.CONFORMANCE_TEST),
        CapabilityState.UNSUPPORTED: (EvidenceKind.UNSUPPORTED, EvidenceOrigin.AUTHORITATIVE),
    }[state]
    authority = (
        AuthorityProvenance(
            authority_id="vendor-advisory",
            authority_reference="https://example.invalid/advisories/evpn",
            authority_digest="a" * 64,
        )
        if state in (CapabilityState.CONFORMANT, CapabilityState.UNSUPPORTED)
        else None
    )
    return CapabilityEvidence(
        identity=IDENTITY,
        clause_id=CLAUSE,
        kind=kind,
        origin=origin,
        observation="attested",
        authority=authority,
    )


def test_assessment_requires_matching_identity_clause_and_evidence_kind() -> None:
    with pytest.raises(ValueError, match="identity and clause_id"):
        CapabilityAssessment(
            identity=IDENTITY,
            clause_id=CLAUSE,
            state=CapabilityState.DOCUMENTED,
            evidence=_evidence(CapabilityState.DOCUMENTED).model_copy(
                update={"clause_id": "OTHER"}
            ),
        )
    with pytest.raises(ValueError, match="kind and origin"):
        CapabilityAssessment(
            identity=IDENTITY,
            clause_id=CLAUSE,
            state=CapabilityState.DOCUMENTED,
            evidence=_evidence(CapabilityState.EXPOSED),
        )


def test_transition_chain_is_adjacent_and_unsupported_is_authoritative_terminal() -> None:
    assessment = CapabilityAssessment(identity=IDENTITY, clause_id=CLAUSE)
    for state in (
        CapabilityState.DOCUMENTED,
        CapabilityState.EXPOSED,
        CapabilityState.ACCEPTED,
        CapabilityState.REALIZED,
        CapabilityState.CONFORMANT,
    ):
        assessment = assess_capability(assessment, _evidence(state), state)
    with pytest.raises(ValueError, match="terminal"):
        assess_capability(
            assessment, _evidence(CapabilityState.UNSUPPORTED), CapabilityState.UNSUPPORTED
        )

    unknown = CapabilityAssessment(identity=IDENTITY, clause_id=CLAUSE)
    with pytest.raises(ValueError, match="exactly one"):
        assess_capability(unknown, _evidence(CapabilityState.EXPOSED), CapabilityState.EXPOSED)
    unsupported = assess_capability(
        unknown, _evidence(CapabilityState.UNSUPPORTED), CapabilityState.UNSUPPORTED
    )
    assert unsupported.state is CapabilityState.UNSUPPORTED


def test_probes_are_declarative_and_fixture_origin_is_immutable() -> None:
    probe = CapabilityProbe(
        identity=IDENTITY,
        clause_id=CLAUSE,
        probe_kind=ProbeKind.PROTOCOL_STATE,
        selector=CapabilityProbeSelector(vni=100, address_family="l2vpn_evpn"),
        expected_observation="enabled",
    )
    assert set(probe.model_dump()) == {
        "identity", "clause_id", "probe_kind", "selector", "expected_observation"
    }
    with pytest.raises(ValueError, match="fixture probes"):
        FixtureCapabilityProbe(
            identity=IDENTITY,
            clause_id=CLAUSE,
            probe_kind=ProbeKind.FEATURE_SUPPORT,
            expected_observation="fixture-observation",
            fixture_name="evpn.yaml",
            origin=EvidenceOrigin.READ_ONLY_PROBE,
        )


def test_capability_requirements_are_canonical_declarations_and_pure_gates() -> None:
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=CapabilityState.EXPOSED
    )
    assert capabilities_satisfy((requirement,), ()) is False
    exposed = CapabilityAssessment(
        identity=IDENTITY,
        clause_id=CLAUSE,
        state=CapabilityState.EXPOSED,
        evidence=_evidence(CapabilityState.EXPOSED),
    )
    assert capabilities_satisfy((requirement,), (exposed,)) is True


def test_authoritative_evidence_requires_immutable_provenance() -> None:
    with pytest.raises(ValueError, match="requires authority provenance"):
        CapabilityEvidence(
            identity=IDENTITY,
            clause_id=CLAUSE,
            kind=EvidenceKind.UNSUPPORTED,
            origin=EvidenceOrigin.AUTHORITATIVE,
            observation="unsupported",
        )
    with pytest.raises(ValueError, match="reserved for authoritative"):
        CapabilityEvidence(
            identity=IDENTITY,
            clause_id=CLAUSE,
            kind=EvidenceKind.EXPOSURE,
            origin=EvidenceOrigin.READ_ONLY_PROBE,
            observation="present",
            authority=_evidence(CapabilityState.UNSUPPORTED).authority,
        )
    with pytest.raises(ValueError, match="fixture data"):
        CapabilityEvidence(
            identity=IDENTITY,
            clause_id=CLAUSE,
            kind=EvidenceKind.EXPOSURE,
            origin=EvidenceOrigin.FIXTURE,
            observation="fixture-only",
        )


def test_unknown_and_identity_mismatch_never_satisfy_requirement() -> None:
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=CapabilityState.UNKNOWN
    )
    unknown = CapabilityAssessment(identity=IDENTITY, clause_id=CLAUSE)
    assert capabilities_satisfy((requirement,), (unknown,)) is False
    mismatch = CapabilityAssessment(
        identity=IDENTITY.model_copy(update={"version": "10.5.5"}),
        clause_id=CLAUSE,
        state=CapabilityState.EXPOSED,
        evidence=_evidence(CapabilityState.EXPOSED).model_copy(
            update={"identity": IDENTITY.model_copy(update={"version": "10.5.5"})}
        ),
    )
    assert capabilities_satisfy((requirement,), (mismatch,)) is False


def test_duplicate_assessments_never_satisfy_regardless_of_state_or_identity() -> None:
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=CapabilityState.EXPOSED
    )
    conformant = CapabilityAssessment(
        identity=IDENTITY,
        clause_id=CLAUSE,
        state=CapabilityState.CONFORMANT,
        evidence=_evidence(CapabilityState.CONFORMANT),
    )
    mismatched_identity = IDENTITY.model_copy(update={"version": "10.5.5"})
    mismatched = CapabilityAssessment(
        identity=mismatched_identity,
        clause_id=CLAUSE,
        state=CapabilityState.EXPOSED,
        evidence=_evidence(CapabilityState.EXPOSED).model_copy(
            update={"identity": mismatched_identity}
        ),
    )
    assert capabilities_satisfy((requirement,), (conformant, mismatched)) is False
    assert capabilities_satisfy((requirement,), (mismatched, conformant)) is False
