"""Pure, non-operative Ixia-c runtime, license, and provenance contract."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from wireproof_evidence import Result

IXIA_C_REPOSITORY = "ghcr.io/srl-labs/ixia-c-one"
IXIA_C_VERSION = "1.58.0-16"
IXIA_C_DIGEST = "sha256:8a63a93bbd4c98bd2832e69689852ca13486be89bed02dc42a772e432f1203ab"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")


class IxiaCEulaIntent(StrEnum):
    """An invocation request; this is not a legal acceptance or authorization."""

    REQUEST_ACCEPT_EULA = "REQUEST_ACCEPT_EULA"


class IxiaCDeclaredState(StrEnum):
    UNKNOWN = "UNKNOWN"
    DECLARED = "DECLARED"


class IxiaCReason(StrEnum):
    IXIA_LOCAL_AUTHORIZATION_UNVERIFIED = "IXIA_LOCAL_AUTHORIZATION_UNVERIFIED"
    IXIA_EULA_AUTHORIZATION_UNKNOWN = "IXIA_EULA_AUTHORIZATION_UNKNOWN"
    IXIA_ENTITLEMENT_UNKNOWN = "IXIA_ENTITLEMENT_UNKNOWN"
    IXIA_LICENSE_SERVER_UNKNOWN = "IXIA_LICENSE_SERVER_UNKNOWN"
    IXIA_COMPONENT_INVENTORY_UNVERIFIED = "IXIA_COMPONENT_INVENTORY_UNVERIFIED"
    IXIA_COMPONENT_PROVENANCE_UNKNOWN = "IXIA_COMPONENT_PROVENANCE_UNKNOWN"


@dataclass(frozen=True)
class IxiaCComponent:
    """One caller-declared, independently pinned runtime component."""

    repository: str
    version: str
    digest: str
    source: str

    def __post_init__(self) -> None:
        if not _REPOSITORY.fullmatch(self.repository):
            raise ValueError("component repository must be canonical OCI syntax")
        if not _VERSION.fullmatch(self.version):
            raise ValueError("component version must be immutable and non-floating")
        if not _DIGEST.fullmatch(self.digest):
            raise ValueError("component digest must be sha256:<64 lowercase hex>")
        if self.source != f"{self.repository}:{self.version}@{self.digest}":
            raise ValueError("component source must exactly bind repository, version, and digest")


@dataclass(frozen=True)
class IxiaCComponentInventory:
    """Caller-declared inventory; primary identity alone never proves completeness."""

    components: tuple[IxiaCComponent, ...] = ()
    inventory_verified: bool = False

    def __post_init__(self) -> None:
        repositories = tuple(component.repository for component in self.components)
        if len(repositories) != len(set(repositories)):
            raise ValueError("component repositories must be unique")


@dataclass(frozen=True)
class IxiaCInvocation:
    eula_intent: IxiaCEulaIntent
    eula_authorization: IxiaCDeclaredState = IxiaCDeclaredState.UNKNOWN
    entitlement: IxiaCDeclaredState = IxiaCDeclaredState.UNKNOWN
    license_server: IxiaCDeclaredState = IxiaCDeclaredState.UNKNOWN
    inventory: IxiaCComponentInventory = IxiaCComponentInventory()

    def __post_init__(self) -> None:
        if not isinstance(self.eula_intent, IxiaCEulaIntent):
            raise ValueError("eula_intent must be a closed invocation intent")
        for state in (self.eula_authorization, self.entitlement, self.license_server):
            if not isinstance(state, IxiaCDeclaredState):
                raise ValueError("authorization and license inputs must be closed states")


@dataclass(frozen=True)
class IxiaCAssessment:
    """A deliberately non-promotable result with no controller or evidence handle."""

    result: Result
    blockers: tuple[IxiaCReason, ...]
    promotable: bool = False
    mutation_permitted: bool = False

    def __post_init__(self) -> None:
        if self.result not in (Result.UNKNOWN, Result.FAIL):
            raise ValueError("Ixia-c assessments cannot pass or be not applicable")
        if self.result is Result.UNKNOWN and not self.blockers:
            raise ValueError("UNKNOWN Ixia-c assessments require at least one blocker")
        if self.promotable or self.mutation_permitted:
            raise ValueError("Ixia-c contract assessments cannot promote or permit mutation")

    def to_dict(self) -> dict[str, object]:
        """Return a secret-free public representation suitable for serialization."""
        return {
            "result": self.result.value,
            "blockers": tuple(reason.value for reason in self.blockers),
            "promotable": self.promotable,
            "mutation_permitted": self.mutation_permitted,
        }


@dataclass(frozen=True)
class IxiaCContract:
    """The fixed Ixia-c identity and deterministic local evaluator."""

    repository: str = IXIA_C_REPOSITORY
    version: str = IXIA_C_VERSION
    digest: str = IXIA_C_DIGEST

    def __post_init__(self) -> None:
        if (self.repository, self.version, self.digest) != (
            IXIA_C_REPOSITORY,
            IXIA_C_VERSION,
            IXIA_C_DIGEST,
        ):
            raise ValueError("Ixia-c contract identity is fixed")

    def evaluate(self, invocation: IxiaCInvocation) -> IxiaCAssessment:
        """Evaluate declarations only; never contact, authorize, or configure anything."""
        blockers: list[IxiaCReason] = [IxiaCReason.IXIA_LOCAL_AUTHORIZATION_UNVERIFIED]
        if invocation.eula_authorization is IxiaCDeclaredState.UNKNOWN:
            blockers.append(IxiaCReason.IXIA_EULA_AUTHORIZATION_UNKNOWN)
        if invocation.entitlement is IxiaCDeclaredState.UNKNOWN:
            blockers.append(IxiaCReason.IXIA_ENTITLEMENT_UNKNOWN)
        if invocation.license_server is IxiaCDeclaredState.UNKNOWN:
            blockers.append(IxiaCReason.IXIA_LICENSE_SERVER_UNKNOWN)
        if not invocation.inventory.inventory_verified:
            blockers.append(IxiaCReason.IXIA_COMPONENT_INVENTORY_UNVERIFIED)
        if not invocation.inventory.components:
            blockers.append(IxiaCReason.IXIA_COMPONENT_PROVENANCE_UNKNOWN)
        return IxiaCAssessment(Result.UNKNOWN, tuple(blockers))
