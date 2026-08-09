from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from wireproof_capability import (
    AuthorityProvenance,
    CapabilityAssessment,
    CapabilityEvidence,
    CapabilityIdentity,
    CapabilityRequirement,
    CapabilityState,
    EvidenceKind,
    EvidenceOrigin,
    assess_capability,
    capabilities_satisfy,
)

IDENTITY = CapabilityIdentity(vendor="frr", platform="linux", version="10.5.4", feature="evpn")
CLAUSE = "EVPN_BASE"
SETTINGS = settings(max_examples=24, deadline=None, database=None)


def _evidence(
    state: CapabilityState, identity: CapabilityIdentity = IDENTITY
) -> CapabilityEvidence:
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
            authority_reference="https://example.invalid/advisory",
            authority_digest="b" * 64,
        )
        if state in (CapabilityState.CONFORMANT, CapabilityState.UNSUPPORTED)
        else None
    )
    return CapabilityEvidence(
        identity=identity,
        clause_id=CLAUSE,
        kind=kind,
        origin=origin,
        observation="attested",
        authority=authority,
    )


@SETTINGS
@given(
    st.sampled_from(
        (
            CapabilityState.EXPOSED,
            CapabilityState.ACCEPTED,
            CapabilityState.REALIZED,
            CapabilityState.CONFORMANT,
        )
    )
)
def test_unknown_only_advances_to_documented_or_authoritative_unsupported(
    target: CapabilityState,
) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        assess_capability(
            CapabilityAssessment(identity=IDENTITY, clause_id=CLAUSE), _evidence(target), target
        )


@SETTINGS
@given(
    st.sampled_from(
        tuple(state for state in CapabilityState if state is not CapabilityState.UNSUPPORTED)
    )
)
def test_unknown_assessment_always_blocks_a_requirement(minimum_state: CapabilityState) -> None:
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=minimum_state
    )
    assert not capabilities_satisfy(
        (requirement,), (CapabilityAssessment(identity=IDENTITY, clause_id=CLAUSE),)
    )


@SETTINGS
@given(st.text(alphabet="0123456789", min_size=1, max_size=4))
def test_identity_mismatch_always_blocks(version_suffix: str) -> None:
    mismatched = IDENTITY.model_copy(update={"version": f"99.{version_suffix}"})
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=CapabilityState.EXPOSED
    )
    assessment = CapabilityAssessment(
        identity=mismatched,
        clause_id=CLAUSE,
        state=CapabilityState.EXPOSED,
        evidence=_evidence(CapabilityState.EXPOSED, mismatched),
    )
    assert not capabilities_satisfy((requirement,), (assessment,))


def test_terminal_states_cannot_transition_and_fixture_cannot_be_authoritative() -> None:
    conformant = CapabilityAssessment(
        identity=IDENTITY,
        clause_id=CLAUSE,
        state=CapabilityState.CONFORMANT,
        evidence=_evidence(CapabilityState.CONFORMANT),
    )
    with pytest.raises(ValueError, match="terminal"):
        assess_capability(
            conformant, _evidence(CapabilityState.UNSUPPORTED), CapabilityState.UNSUPPORTED
        )
    with pytest.raises(ValueError, match="fixture data"):
        CapabilityEvidence(
            identity=IDENTITY,
            clause_id=CLAUSE,
            kind=EvidenceKind.UNSUPPORTED,
            origin=EvidenceOrigin.FIXTURE,
            observation="fixture",
            authority=AuthorityProvenance(
                authority_id="fixture",
                authority_reference="fixture://unsupported",
                authority_digest="c" * 64,
            ),
        )


@SETTINGS
@given(st.permutations((CapabilityState.EXPOSED, CapabilityState.CONFORMANT)))
def test_duplicate_assessment_clause_is_order_invariant(
    states: tuple[CapabilityState, CapabilityState],
) -> None:
    requirement = CapabilityRequirement(
        clause_id=CLAUSE, expected_identity=IDENTITY, minimum_state=CapabilityState.EXPOSED
    )
    assessments = tuple(
        CapabilityAssessment(
            identity=IDENTITY,
            clause_id=CLAUSE,
            state=state,
            evidence=_evidence(state),
        )
        for state in states
    )
    assert not capabilities_satisfy((requirement,), assessments)
