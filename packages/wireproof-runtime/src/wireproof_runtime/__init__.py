"""No-Docker fake runtime contract and deterministic lifecycle state machine."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import InitVar, dataclass, field
from enum import StrEnum
from math import isfinite
from pathlib import Path

from wireproof_compiler import RuntimeMetadata
from wireproof_evidence import EvidenceRecord, ExecutionMode, ReasonCode, Result

from wireproof_runtime.clab_ebgp import ClabEbgpState as ClabEbgpState
from wireproof_runtime.clab_ebgp import ClabPreparationError as ClabPreparationError
from wireproof_runtime.clab_ebgp import ContainerlabEbgpRun as ContainerlabEbgpRun
from wireproof_runtime.clab_ebgp import (
    SubprocessContainerlabExecutor as _SubprocessContainerlabExecutor,
)
from wireproof_runtime.clab_ebgp import (
    _PrivilegedContainerlabExecutor,
    _PrivilegedControllerAuthorizer,
    _PrivilegedControllerPermit,
)
from wireproof_runtime.frr_smoke import DockerExecutor as DockerExecutor
from wireproof_runtime.frr_smoke import DockerResult as DockerResult
from wireproof_runtime.frr_smoke import FrrSmokeRun as FrrSmokeRun
from wireproof_runtime.frr_smoke import FrrSmokeState as FrrSmokeState
from wireproof_runtime.frr_smoke import SubprocessDockerExecutor as SubprocessDockerExecutor
from wireproof_runtime.ixia_c import IxiaCAssessment as IxiaCAssessment
from wireproof_runtime.ixia_c import IxiaCComponent as IxiaCComponent
from wireproof_runtime.ixia_c import IxiaCComponentInventory as IxiaCComponentInventory
from wireproof_runtime.ixia_c import IxiaCContract as IxiaCContract
from wireproof_runtime.ixia_c import IxiaCDeclaredState as IxiaCDeclaredState
from wireproof_runtime.ixia_c import IxiaCEulaIntent as IxiaCEulaIntent
from wireproof_runtime.ixia_c import IxiaCInvocation as IxiaCInvocation
from wireproof_runtime.ixia_c import IxiaCReason as IxiaCReason
from wireproof_runtime.observers import CapturedVxlanEthernetFrame as CapturedVxlanEthernetFrame
from wireproof_runtime.observers import (
    CapturedVxlanEthernetFrameParseResult as CapturedVxlanEthernetFrameParseResult,
)
from wireproof_runtime.observers import CaptureRef as CaptureRef
from wireproof_runtime.observers import EvpnRoute as EvpnRoute
from wireproof_runtime.observers import EvpnRouteExpectation as EvpnRouteExpectation
from wireproof_runtime.observers import GoBgpParseResult as GoBgpParseResult
from wireproof_runtime.observers import GoBgpSnapshot as GoBgpSnapshot
from wireproof_runtime.observers import ObservationOutcome as ObservationOutcome
from wireproof_runtime.observers import ObservationReason as ObservationReason
from wireproof_runtime.observers import ObservationResult as ObservationResult
from wireproof_runtime.observers import VlanTag as VlanTag
from wireproof_runtime.observers import VxlanHeader as VxlanHeader
from wireproof_runtime.observers import VxlanParseResult as VxlanParseResult
from wireproof_runtime.observers import compare_gobgp_snapshots as compare_gobgp_snapshots
from wireproof_runtime.observers import (
    parse_captured_vxlan_ethernet_frame as parse_captured_vxlan_ethernet_frame,
)
from wireproof_runtime.observers import parse_gobgp_fixture as parse_gobgp_fixture
from wireproof_runtime.observers import parse_vxlan_udp_payload as parse_vxlan_udp_payload

_IMAGE = re.compile(r"^[^@:\s]+(?:/[^@:\s]+)*:[^@\s]+@sha256:[0-9a-f]{64}$")


def new_containerlab_ebgp_run() -> ContainerlabEbgpRun:
    """Create the closed real-executor scenario used by the CLI."""
    return ContainerlabEbgpRun(_SubprocessContainerlabExecutor())


def _new_privileged_controller_authorizer() -> _PrivilegedControllerAuthorizer:
    """Create the non-global authorization registry for one CLI invocation."""
    return _PrivilegedControllerAuthorizer(Path.cwd())


def _new_privileged_containerlab_ebgp_run(
    authorizer: _PrivilegedControllerAuthorizer,
    permit: _PrivilegedControllerPermit,
    change_id: str,
    repo_root: Path,
) -> ContainerlabEbgpRun:
    if (
        type(authorizer) is not _PrivilegedControllerAuthorizer
        or type(permit) is not _PrivilegedControllerPermit
    ):
        raise ValueError("privileged controller authorization is unavailable")
    binding = authorizer.consume(permit, change_id, repo_root)
    return ContainerlabEbgpRun(_PrivilegedContainerlabExecutor(binding))


class ImageRef(str):
    def __new__(cls, value: str) -> ImageRef:
        if not _IMAGE.fullmatch(value) or ":latest@" in value:
            raise ValueError("image must be repo:version@sha256:<64 lowercase hex>")
        return str.__new__(cls, value)


class RuntimeOperation(StrEnum):
    DEPLOY = "DEPLOY"
    INSPECT = "INSPECT"
    DESTROY = "DESTROY"


@dataclass(frozen=True)
class ResourceOwnership:
    """The complete identity required before a recorded cleanup may select a resource."""

    kind: str
    identity: str
    managed_by: str
    run_id: str

    def __post_init__(self) -> None:
        if not self.kind or not self.identity or not self.run_id or self.managed_by != "wireproof":
            raise ValueError("ownership requires kind, identity, wireproof label, and run ID")


@dataclass(frozen=True)
class RuntimeCommand:
    operation: RuntimeOperation
    argv: tuple[str, ...]

    Operation = RuntimeOperation

    def __post_init__(self) -> None:
        if not isinstance(self.operation, RuntimeOperation):
            raise ValueError("runtime operation must be closed")
        expected = ("wireproof-runtime", self.operation.value.lower(), "--run-id")
        if len(self.argv) != 4 or self.argv[:3] != expected or not self.argv[3]:
            raise ValueError("runtime commands must use program-built argv")

    @classmethod
    def _make(cls, operation: RuntimeOperation, run_id: str) -> RuntimeCommand:
        if not run_id:
            raise ValueError("run_id is required")
        return cls(operation, ("wireproof-runtime", operation.value.lower(), "--run-id", run_id))

    @classmethod
    def deploy(cls, run_id: str) -> RuntimeCommand:
        return cls._make(RuntimeOperation.DEPLOY, run_id)

    @classmethod
    def inspect(cls, run_id: str) -> RuntimeCommand:
        return cls._make(RuntimeOperation.INSPECT, run_id)

    @classmethod
    def destroy(cls, run_id: str) -> RuntimeCommand:
        return cls._make(RuntimeOperation.DESTROY, run_id)


@dataclass(frozen=True)
class RecordedDryPlan:
    """A fake-only recording: it is intentionally not a Containerlab invocation."""

    ownership: ResourceOwnership
    commands: tuple[RuntimeCommand, ...]
    execution_mode: ExecutionMode = ExecutionMode.FAKE


@dataclass(frozen=True)
class ResidueInspection:
    result: Result
    residues: tuple[ResourceOwnership, ...] = ()

    @property
    def cleanup_succeeded(self) -> bool:
        return self.result is Result.PASS and not self.residues


class RecordedContainerlabAdapter:
    """Closed dry-plan adapter; it records intent and never calls Containerlab or a shell."""

    def dry_plan(
        self, operation: RuntimeOperation, ownership: ResourceOwnership
    ) -> RecordedDryPlan:
        command = RuntimeCommand._make(operation, ownership.run_id)
        return RecordedDryPlan(ownership=ownership, commands=(command,))

    def inspect_residue(
        self,
        resources: tuple[ResourceOwnership, ...] | None,
        ownership: ResourceOwnership,
    ) -> ResidueInspection:
        if resources is None:
            return ResidueInspection(Result.UNKNOWN)
        residues = tuple(
            resource
            for resource in resources
            if resource.managed_by == "wireproof" and resource.run_id == ownership.run_id
        )
        return ResidueInspection(Result.PASS, residues)


class CommandRunner:
    def run(self, command: RuntimeCommand) -> bool:
        raise NotImplementedError


@dataclass
class FakeRunner(CommandRunner):
    fail_operations: set[RuntimeOperation] = field(default_factory=set)
    resources: list[dict[str, str]] = field(default_factory=list)
    transcript: list[RuntimeCommand] = field(default_factory=list)

    def run(self, command: RuntimeCommand) -> bool:
        self.transcript.append(command)
        if command.operation in self.fail_operations:
            return False
        if command.operation is RuntimeOperation.DEPLOY:
            self.resources.append(
                {
                    "kind": "containerlab-lab",
                    "identity": command.argv[-1],
                    "managed_by": "wireproof",
                    "run_id": command.argv[-1],
                }
            )
        elif command.operation is RuntimeOperation.DESTROY:
            run_id = command.argv[-1]
            self.resources[:] = [
                resource
                for resource in self.resources
                if not (
                    resource.get("managed_by") == "wireproof" and resource.get("run_id") == run_id
                )
            ]
        return True


class LabState(StrEnum):
    NEW = "NEW"
    DEPLOYING = "DEPLOYING"
    RUNNING = "RUNNING"
    TESTING = "TESTING"
    TEST_FAILED = "TEST_FAILED"
    FAILED = "FAILED"
    CLEANING = "CLEANING"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    CLEANED = "CLEANED"


@dataclass(frozen=True)
class EventuallyResult:
    succeeded: bool
    attempts: int
    elapsed: float


def eventually(
    predicate: Callable[[], bool],
    *,
    timeout: float,
    interval: float,
    monotonic: Callable[[], float],
    sleeper: Callable[[float], None],
) -> EventuallyResult:
    if not isfinite(timeout) or not isfinite(interval) or timeout <= 0 or interval <= 0:
        raise ValueError("timeout and interval must be finite positive values")
    start = monotonic()
    attempts = 0
    while True:
        attempts += 1
        if predicate():
            return EventuallyResult(True, attempts, monotonic() - start)
        elapsed = monotonic() - start
        if elapsed >= timeout:
            return EventuallyResult(False, attempts, elapsed)
        sleeper(min(interval, timeout - elapsed))


@dataclass
class LabRun:
    change_id: str
    run_id: str
    runner: CommandRunner
    metadata: InitVar[RuntimeMetadata]
    state: LabState = LabState.NEW
    _metadata: RuntimeMetadata = field(init=False, repr=False)
    _evidence: list[EvidenceRecord] = field(default_factory=list, init=False, repr=False)
    _state_history: list[LabState] = field(default_factory=lambda: [LabState.NEW], init=False)
    _image: ImageRef | None = field(default=None, init=False)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "metadata" or (name == "_metadata" and hasattr(self, "_metadata")):
            raise AttributeError("runtime metadata is immutable")
        if name == "_image" and getattr(self, "_image", None) is not None:
            raise AttributeError("runtime image is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name == "_metadata":
            raise AttributeError("runtime metadata is immutable")
        if name == "_image":
            raise AttributeError("runtime image is immutable")
        object.__delattr__(self, name)

    def __post_init__(self, metadata: RuntimeMetadata) -> None:
        if not self.change_id or not self.run_id:
            raise ValueError("change_id and run_id are required")
        self._metadata = metadata
        object.__setattr__(self, "_image", ImageRef(self._metadata.image.reference))

    @property
    def evidence(self) -> tuple[EvidenceRecord, ...]:
        """Immutable snapshot of append-only records."""
        return tuple(self._evidence)

    def _set_state(self, state: LabState) -> None:
        self.state = state
        self._state_history.append(state)

    def _record(
        self,
        result: Result,
        reason: ReasonCode | None = None,
        attempts: int = 0,
        elapsed: float | None = None,
        command: RuntimeCommand | None = None,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            change_id=self.change_id,
            run_id=self.run_id,
            result=result,
            semantic_ir_hash=self._metadata.semantic_ir_hash,
            reason_code=reason,
            execution_mode=ExecutionMode.FAKE,
            attempts=attempts,
            elapsed=elapsed,
            history=tuple(item.value for item in self._state_history),
            image_reference=str(self._image) if self._image is not None else None,
            artifact_hashes=(self._metadata.reference_topology_hash,),
            provenance_clauses=self._metadata.provenance_clauses,
            component_versions=self._metadata.component_versions,
            coverage=self._metadata.coverage,
            command_kinds=(command.operation.value,) if command is not None else (),
        )
        self._evidence.append(record)
        return record

    def up(self, image: ImageRef | str) -> EvidenceRecord:
        image = ImageRef(image)
        if self.state is not LabState.NEW:
            raise RuntimeError("a run cannot be re-entered; create a new run")
        if image != self._image:
            raise ValueError("image must match immutable compiled metadata")
        self._set_state(LabState.DEPLOYING)
        command = RuntimeCommand.deploy(self.run_id)
        if self.runner.run(command):
            self._set_state(LabState.RUNNING)
            return self._record(Result.PASS, command=command)
        self._set_state(LabState.FAILED)
        record = self._record(Result.FAIL, ReasonCode.DEPLOY_FAILED, command=command)
        self._cleanup(force=True)
        return record

    def status(self) -> EvidenceRecord:
        if self.state is not LabState.RUNNING:
            raise RuntimeError("status requires RUNNING")
        command = RuntimeCommand.inspect(self.run_id)
        if self.runner.run(command):
            return self._record(Result.PASS, command=command)
        self._set_state(LabState.FAILED)
        record = self._record(Result.FAIL, ReasonCode.STATUS_FAILED, command=command)
        self._cleanup(force=True)
        return record

    def test(self, predicate: Callable[[], bool] | EventuallyResult) -> EvidenceRecord:
        if self.state is not LabState.RUNNING:
            raise RuntimeError("test requires RUNNING")
        self._set_state(LabState.TESTING)
        result = (
            predicate
            if isinstance(predicate, EventuallyResult)
            else EventuallyResult(predicate(), 1, 0)
        )
        if result.succeeded:
            self._set_state(LabState.RUNNING)
            return self._record(Result.PASS, attempts=result.attempts, elapsed=result.elapsed)
        self._set_state(LabState.TEST_FAILED)
        record = self._record(
            Result.FAIL, ReasonCode.TEST_FAILED, attempts=result.attempts, elapsed=result.elapsed
        )
        self._cleanup(force=True)
        return record

    def _cleanup(self, *, force: bool) -> EvidenceRecord:
        resources = getattr(self.runner, "resources", [])
        has_target = any(
            resource.get("managed_by") == "wireproof" and resource.get("run_id") == self.run_id
            for resource in resources
        )
        if not force and not has_target:
            self._set_state(LabState.CLEANED)
            return self._record(Result.PASS)
        self._set_state(LabState.CLEANING)
        command = RuntimeCommand.destroy(self.run_id)
        if self.runner.run(command):
            self._set_state(LabState.CLEANED)
            return self._record(Result.PASS, command=command)
        self._set_state(LabState.CLEANUP_FAILED)
        return self._record(Result.FAIL, ReasonCode.CLEANUP_FAILED, command=command)

    def down(self) -> EvidenceRecord:
        if self.state is LabState.CLEANED:
            return self._record(Result.PASS)
        allowed = {
            LabState.NEW,
            LabState.DEPLOYING,
            LabState.RUNNING,
            LabState.TEST_FAILED,
            LabState.FAILED,
            LabState.CLEANUP_FAILED,
        }
        if self.state not in allowed:
            raise RuntimeError("down is not available in the current state")
        return self._cleanup(force=False)


def lab_doctor() -> EvidenceRecord:
    """M1 foundation intentionally never probes or controls Docker."""
    return EvidenceRecord(
        change_id="lab-doctor",
        result=Result.UNKNOWN,
        semantic_ir_hash="uncompiled",
        reason_code=ReasonCode.LAB_ENVIRONMENT_UNAVAILABLE,
        reason="LAB_ENVIRONMENT_UNAVAILABLE",
    )
