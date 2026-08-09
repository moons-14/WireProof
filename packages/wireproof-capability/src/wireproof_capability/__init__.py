"""Immutable, evidence-backed capability assessments.

This package deliberately models only declarations and state transitions.  It
does not contain transport, command, endpoint, or configuration APIs.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CapabilityState(StrEnum):
    UNKNOWN = "UNKNOWN"
    DOCUMENTED = "DOCUMENTED"
    EXPOSED = "EXPOSED"
    ACCEPTED = "ACCEPTED"
    REALIZED = "REALIZED"
    CONFORMANT = "CONFORMANT"
    UNSUPPORTED = "UNSUPPORTED"


_PROGRESSION = (
    CapabilityState.UNKNOWN,
    CapabilityState.DOCUMENTED,
    CapabilityState.EXPOSED,
    CapabilityState.ACCEPTED,
    CapabilityState.REALIZED,
    CapabilityState.CONFORMANT,
)


class EvidenceOrigin(StrEnum):
    FIXTURE = "FIXTURE"
    DOCUMENTATION = "DOCUMENTATION"
    READ_ONLY_PROBE = "READ_ONLY_PROBE"
    ACCEPTANCE_TEST = "ACCEPTANCE_TEST"
    OBSERVATION = "OBSERVATION"
    CONFORMANCE_TEST = "CONFORMANCE_TEST"
    AUTHORITATIVE = "AUTHORITATIVE"


class EvidenceKind(StrEnum):
    DOCUMENTATION = "DOCUMENTATION"
    EXPOSURE = "EXPOSURE"
    ACCEPTANCE = "ACCEPTANCE"
    REALIZATION = "REALIZATION"
    CONFORMANCE = "CONFORMANCE"
    UNSUPPORTED = "UNSUPPORTED"


class ProbeKind(StrEnum):
    """Closed set of declarative observations an executor may implement."""

    FEATURE_SUPPORT = "FEATURE_SUPPORT"
    PROTOCOL_STATE = "PROTOCOL_STATE"
    VERSION = "VERSION"


_REQUIRED_EVIDENCE: dict[CapabilityState, tuple[EvidenceKind, EvidenceOrigin]] = {
    CapabilityState.DOCUMENTED: (EvidenceKind.DOCUMENTATION, EvidenceOrigin.DOCUMENTATION),
    CapabilityState.EXPOSED: (EvidenceKind.EXPOSURE, EvidenceOrigin.READ_ONLY_PROBE),
    CapabilityState.ACCEPTED: (EvidenceKind.ACCEPTANCE, EvidenceOrigin.ACCEPTANCE_TEST),
    CapabilityState.REALIZED: (EvidenceKind.REALIZATION, EvidenceOrigin.OBSERVATION),
    CapabilityState.CONFORMANT: (EvidenceKind.CONFORMANCE, EvidenceOrigin.CONFORMANCE_TEST),
    CapabilityState.UNSUPPORTED: (EvidenceKind.UNSUPPORTED, EvidenceOrigin.AUTHORITATIVE),
}


class CapabilityIdentity(BaseModel):
    """Canonical identity of one feature on one implementation surface."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    version: str = Field(min_length=1)
    feature: str = Field(min_length=1)


class AuthorityProvenance(BaseModel):
    """Immutable reference to authority asserted by supplied evidence.

    This is provenance, not local cryptographic verification or promotion authority.
    An external verifier remains responsible for establishing trust in the referenced
    authority material.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    authority_id: str = Field(min_length=1)
    authority_reference: str = Field(min_length=1)
    authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class CapabilityEvidence(BaseModel):
    """Evidence that attests exactly one capability identity and clause."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: CapabilityIdentity
    clause_id: str = Field(min_length=1)
    kind: EvidenceKind
    origin: EvidenceOrigin
    observation: str = Field(min_length=1)
    authority: AuthorityProvenance | None = None

    @model_validator(mode="after")
    def require_authority_provenance_when_authoritative(self) -> CapabilityEvidence:
        if self.origin is EvidenceOrigin.FIXTURE:
            raise ValueError("fixture data cannot be capability evidence")
        requires_authority = (
            self.origin is EvidenceOrigin.AUTHORITATIVE
            or self.kind in (EvidenceKind.CONFORMANCE, EvidenceKind.UNSUPPORTED)
        )
        if requires_authority and self.authority is None:
            raise ValueError("authoritative or terminal evidence requires authority provenance")
        if not requires_authority and self.authority is not None:
            raise ValueError("authority provenance is reserved for authoritative evidence")
        return self


class CapabilityAssessment(BaseModel):
    """A state plus the evidence which justified its latest transition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: CapabilityIdentity
    clause_id: str = Field(min_length=1)
    state: CapabilityState = CapabilityState.UNKNOWN
    evidence: CapabilityEvidence | None = None

    @model_validator(mode="after")
    def require_evidence_for_known_states(self) -> CapabilityAssessment:
        if self.state is CapabilityState.UNKNOWN:
            if self.evidence is not None:
                raise ValueError("UNKNOWN assessments must not carry evidence")
            return self
        if self.evidence is None:
            raise ValueError("non-UNKNOWN assessments require evidence")
        if self.evidence.identity != self.identity or self.evidence.clause_id != self.clause_id:
            raise ValueError("evidence must attest the assessment identity and clause_id")
        expected_kind, expected_origin = _REQUIRED_EVIDENCE[self.state]
        if (self.evidence.kind, self.evidence.origin) != (expected_kind, expected_origin):
            raise ValueError("evidence kind and origin do not attest the assessment state")
        return self


class CapabilityProbeSelector(BaseModel):
    """Typed, non-executable selector for a capability probe."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vni: int | None = Field(default=None, ge=1, le=16_777_215)
    address_family: str | None = Field(
        default=None, pattern=r"^(ipv4_unicast|ipv6_unicast|l2vpn_evpn)$"
    )


class CapabilityProbe(BaseModel):
    """Declarative, read-only probe description; execution is outside this package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: CapabilityIdentity
    clause_id: str = Field(min_length=1)
    probe_kind: ProbeKind
    selector: CapabilityProbeSelector = Field(default_factory=CapabilityProbeSelector)
    expected_observation: str = Field(min_length=1)


class FixtureCapabilityProbe(CapabilityProbe):
    """A fixture-only probe.  Its origin cannot be promoted to a live source."""

    fixture_name: str = Field(min_length=1)
    origin: EvidenceOrigin = EvidenceOrigin.FIXTURE

    @model_validator(mode="after")
    def require_fixture_origin(self) -> FixtureCapabilityProbe:
        if self.origin is not EvidenceOrigin.FIXTURE:
            raise ValueError("fixture probes must retain FIXTURE origin")
        return self


class CapabilityRequirement(BaseModel):
    """A declarative gate for a compiler obligation, not a request to probe."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    clause_id: str = Field(min_length=1)
    expected_identity: CapabilityIdentity
    minimum_state: CapabilityState

    @model_validator(mode="after")
    def reject_terminal_requirement(self) -> CapabilityRequirement:
        if self.minimum_state is CapabilityState.UNSUPPORTED:
            raise ValueError("UNSUPPORTED cannot satisfy a capability requirement")
        return self


def assess_capability(
    prior: CapabilityAssessment,
    evidence: CapabilityEvidence,
    target_state: CapabilityState,
) -> CapabilityAssessment:
    """Apply one legal transition without probing or promoting evidence."""
    if prior.identity != evidence.identity or prior.clause_id != evidence.clause_id:
        raise ValueError("evidence must attest the prior assessment identity and clause_id")
    if target_state is CapabilityState.UNKNOWN:
        raise ValueError("capability state cannot transition to UNKNOWN")
    if prior.state in (CapabilityState.UNSUPPORTED, CapabilityState.CONFORMANT):
        raise ValueError("terminal capability state cannot transition")
    if target_state is CapabilityState.UNSUPPORTED:
        expected = _REQUIRED_EVIDENCE[target_state]
        if (evidence.kind, evidence.origin) != expected:
            raise ValueError("UNSUPPORTED requires authoritative unsupported evidence")
        return CapabilityAssessment(
            identity=prior.identity,
            clause_id=prior.clause_id,
            state=target_state,
            evidence=evidence,
        )
    expected_index = _PROGRESSION.index(prior.state) + 1
    if target_state is not _PROGRESSION[expected_index]:
        raise ValueError("capability transitions must advance exactly one state")
    expected = _REQUIRED_EVIDENCE[target_state]
    if (evidence.kind, evidence.origin) != expected:
        raise ValueError("evidence kind and origin do not attest the target state")
    return CapabilityAssessment(
        identity=prior.identity, clause_id=prior.clause_id, state=target_state, evidence=evidence
    )


def capabilities_satisfy(
    requirements: tuple[CapabilityRequirement, ...],
    assessments: tuple[CapabilityAssessment, ...],
) -> bool:
    """Return whether declared requirements are met; never changes assessments."""
    # A clause is assessed exactly once.  Refuse duplicate inputs instead of
    # letting dict construction make the result depend on list order.
    clause_ids = tuple(assessment.clause_id for assessment in assessments)
    if len(clause_ids) != len(set(clause_ids)):
        return False
    by_clause = {assessment.clause_id: assessment for assessment in assessments}
    for requirement in requirements:
        assessment = by_clause.get(requirement.clause_id)
        if (
            assessment is None
            or assessment.identity != requirement.expected_identity
            or assessment.state in (CapabilityState.UNKNOWN, CapabilityState.UNSUPPORTED)
        ):
            return False
        if _PROGRESSION.index(assessment.state) < _PROGRESSION.index(requirement.minimum_state):
            return False
    return True


__all__ = [
    "CapabilityAssessment",
    "CapabilityEvidence",
    "CapabilityIdentity",
    "CapabilityProbe",
    "CapabilityProbeSelector",
    "CapabilityRequirement",
    "CapabilityState",
    "AuthorityProvenance",
    "EvidenceKind",
    "EvidenceOrigin",
    "FixtureCapabilityProbe",
    "ProbeKind",
    "assess_capability",
    "capabilities_satisfy",
]
