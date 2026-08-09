"""Direct-Docker, single-container FRR smoke lifecycle.

This adapter deliberately has no process implementation: callers inject a typed
executor.  It is consequently suitable for exact argv transcript tests without
giving the runtime a shell or a broad Docker-selection capability.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast
from uuid import UUID, uuid4

from wireproof_evidence import EvidenceRecord, ExecutionMode, ReasonCode, Result

FRR_IMAGE = (
    "quay.io/frrouting/frr:10.5.4@sha256:"
    "17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
)
FRR_CACHE_IMAGE = (
    "quay.io/frrouting/frr@sha256:17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
)
FRR_PLATFORM = "linux/amd64"
_MANAGED = "io.wireproof.managed"
_RUN_ID = "io.wireproof.run_id"
_CHANGE_ID = "io.wireproof.change_id"
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class DockerResult:
    """Structured executor result; diagnostic streams are intentionally absent."""

    ok: bool
    container_id: str | None = None
    image_id: str | None = None
    repo_digests: tuple[str, ...] = ()
    platform: str | None = None
    labels: tuple[tuple[str, str], ...] = ()
    running: bool | None = None


class DockerExecutor(Protocol):
    @property
    def execution_mode(self) -> ExecutionMode: ...

    def execute(self, argv: tuple[str, ...]) -> DockerResult: ...


@dataclass
class SubprocessDockerExecutor:
    """The sole real-mode adapter, bound to one smoke owner and its container."""

    run_id: str
    change_id: str
    timeout_seconds: float = 30.0
    _container_id: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and greater than zero")
        try:
            if str(UUID(self.run_id)) != self.run_id or not self.change_id:
                raise ValueError
        except ValueError as error:
            raise ValueError("run_id must be a UUID and change_id is required") from error

    @property
    def execution_mode(self) -> ExecutionMode:
        return ExecutionMode.REAL

    def execute(self, argv: tuple[str, ...]) -> DockerResult:
        if not _is_allowed_docker_argv(argv, self.run_id, self.change_id, self._container_id):
            return DockerResult(False)
        try:
            completed = subprocess.run(
                argv,
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            result = DockerResult(
                False,
                container_id=(
                    _container_id_from_stdout(error.stdout)
                    if argv[:3] == ("docker", "run", "--platform")
                    else None
                ),
            )
            self._register_container(result.container_id)
            return result
        except OSError:
            return DockerResult(False)
        if completed.returncode != 0:
            result = DockerResult(
                False,
                container_id=(
                    _container_id_from_stdout(completed.stdout)
                    if argv[:3] == ("docker", "run", "--platform")
                    else None
                ),
            )
            self._register_container(result.container_id)
            return result
        if argv[:3] == ("docker", "image", "inspect"):
            try:
                image = json.loads(completed.stdout)[0]
                return DockerResult(
                    True,
                    image_id=image.get("Id"),
                    repo_digests=tuple(image.get("RepoDigests") or ()),
                    platform=f"{image.get('Os')}/{image.get('Architecture')}",
                )
            except (AttributeError, IndexError, TypeError, json.JSONDecodeError):
                return DockerResult(False)
        if argv[:2] == ("docker", "inspect"):
            try:
                container = json.loads(completed.stdout)[0]
                labels = container.get("Config", {}).get("Labels") or {}
                state = container.get("State")
                running = state.get("Running") if isinstance(state, dict) else None
                return DockerResult(
                    True,
                    labels=tuple(labels.items()),
                    running=running if type(running) is bool else None,
                )
            except (IndexError, KeyError, AttributeError, TypeError, json.JSONDecodeError):
                return DockerResult(False)
        if argv[:3] == ("docker", "run", "--platform"):
            result = DockerResult(True, container_id=_container_id_from_stdout(completed.stdout))
            self._register_container(result.container_id)
            return result
        return DockerResult(True)

    def _register_container(self, container_id: str | None) -> None:
        if _is_container_id(container_id):
            self._container_id = container_id


def _is_container_id(value: str | None) -> bool:
    return value is not None and _CONTAINER_ID.fullmatch(value) is not None


def _container_id_from_stdout(value: str | bytes | None) -> str | None:
    """Accept only a complete Docker run ID and discard all diagnostic output."""
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _is_container_id(candidate) else None


def _is_allowed_docker_argv(
    argv: tuple[str, ...], run_id: str, change_id: str, container_id: str | None
) -> bool:
    """Accept only the fixed lifecycle grammar constructed by this module."""
    if argv == ("docker", "image", "inspect", FRR_CACHE_IMAGE):
        return True
    if argv == ("docker", "pull", "--platform", FRR_PLATFORM, FRR_IMAGE):
        return True
    if len(argv) == 3 and argv[:2] == ("docker", "inspect"):
        return container_id is not None and argv[2] == container_id
    if len(argv) == 4 and argv[:3] == ("docker", "rm", "--force"):
        return container_id is not None and argv[3] == container_id
    if len(argv) != 16 or argv[:4] != ("docker", "run", "--platform", FRR_PLATFORM):
        return False
    if (
        argv[4:12]
        != (
            "--detach",
            "--network",
            "none",
            "--name",
            argv[8],
            "--label",
            f"{_MANAGED}=true",
            "--label",
        )
        or argv[13] != "--label"
        or argv[15] != FRR_IMAGE
    ):
        return False
    return (
        argv[8] == f"wireproof-frr-smoke-{run_id}"
        and argv[12] == f"{_RUN_ID}={run_id}"
        and argv[14] == f"{_CHANGE_ID}={change_id}"
    )


class FrrSmokeState(StrEnum):
    NEW = "NEW"
    PREFLIGHTED = "PREFLIGHTED"
    CACHE_VERIFIED = "CACHE_VERIFIED"
    PULLED = "PULLED"
    RUNNING = "RUNNING"
    INSPECTED = "INSPECTED"
    CLEANING = "CLEANING"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    CLEANED = "CLEANED"


def _image_argv() -> tuple[str, ...]:
    return ("docker", "image", "inspect", FRR_CACHE_IMAGE)


def _image_matches(result: DockerResult) -> bool:
    return result.ok and result.platform == FRR_PLATFORM and FRR_CACHE_IMAGE in result.repo_digests


@dataclass
class FrrSmokeRun:
    """Strict one-shot smoke owner. It never lists, prunes, or selects by prefix."""

    change_id: str
    executor: DockerExecutor | type[SubprocessDockerExecutor]
    uuid_factory: Callable[[], str | UUID] = uuid4
    state: FrrSmokeState = field(default=FrrSmokeState.NEW, init=False)
    run_id: str = field(init=False)
    container_name: str = field(init=False)
    container_id: str | None = field(default=None, init=False)
    resolved_image_id: str | None = field(default=None, init=False)
    transcript: list[tuple[str, ...]] = field(default_factory=list, init=False)
    _evidence: list[EvidenceRecord] = field(default_factory=list, init=False, repr=False)
    _history: list[FrrSmokeState] = field(
        default_factory=lambda: [FrrSmokeState.NEW], init=False, repr=False
    )

    def __post_init__(self) -> None:
        if not self.change_id:
            raise ValueError("trusted change_id is required")
        try:
            self.run_id = str(UUID(str(self.uuid_factory())))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("uuid_factory must return a UUID run ID") from error
        self.container_name = f"wireproof-frr-smoke-{self.run_id}"
        if self.executor is SubprocessDockerExecutor:
            self.executor = SubprocessDockerExecutor(self.run_id, self.change_id)

    @property
    def evidence(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._evidence)

    @property
    def history(self) -> tuple[FrrSmokeState, ...]:
        return tuple(self._history)

    def _set_state(self, state: FrrSmokeState) -> None:
        self.state = state
        self._history.append(state)

    def _execute(self, argv: tuple[str, ...]) -> DockerResult:
        self.transcript.append(argv)
        return cast(DockerExecutor, self.executor).execute(argv)

    def _record(self, result: Result, reason: ReasonCode | None = None) -> EvidenceRecord:
        execution_mode = (
            ExecutionMode.REAL
            if type(self.executor) is SubprocessDockerExecutor
            else ExecutionMode.FAKE
        )
        record = EvidenceRecord(
            change_id=self.change_id,
            run_id=self.run_id,
            result=result,
            semantic_ir_hash="frr-smoke-v1",
            reason_code=reason,
            reason="FRR smoke lifecycle only; not EVPN or conformance evidence",
            execution_mode=execution_mode,
            history=tuple(state.value for state in self._history),
            image_reference=FRR_IMAGE,
            artifact_hashes=(self.resolved_image_id,) if self.resolved_image_id else (),
        )
        self._evidence.append(record)
        return record

    def _preflight(self) -> bool:
        first = self._execute(_image_argv())
        if _image_matches(first):
            self.resolved_image_id = first.image_id
            self._set_state(FrrSmokeState.PREFLIGHTED)
            self._set_state(FrrSmokeState.CACHE_VERIFIED)
            return True
        pulled = self._execute(("docker", "pull", "--platform", FRR_PLATFORM, FRR_IMAGE))
        if not pulled.ok:
            return False
        self._set_state(FrrSmokeState.PREFLIGHTED)
        self._set_state(FrrSmokeState.PULLED)
        verified = self._execute(_image_argv())
        if _image_matches(verified):
            self.resolved_image_id = verified.image_id
            return True
        return False

    def up(self) -> EvidenceRecord:
        if self.state is not FrrSmokeState.NEW:
            raise RuntimeError("up retry is prohibited; create a new smoke run")
        if not self._preflight():
            return self._record(Result.FAIL, ReasonCode.IMAGE_REFERENCE_INVALID)
        self._set_state(FrrSmokeState.RUNNING)
        result = self._execute(
            (
                "docker",
                "run",
                "--platform",
                FRR_PLATFORM,
                "--detach",
                "--network",
                "none",
                "--name",
                self.container_name,
                "--label",
                f"{_MANAGED}=true",
                "--label",
                f"{_RUN_ID}={self.run_id}",
                "--label",
                f"{_CHANGE_ID}={self.change_id}",
                FRR_IMAGE,
            )
        )
        if _is_container_id(result.container_id):
            # Docker can create a container before reporting a failed run or timeout.
            # Retain only a valid opaque ID so cleanup can prove ownership before removal.
            self.container_id = result.container_id
        if not result.ok or self.container_id is None:
            return self._record(Result.FAIL, ReasonCode.DEPLOY_FAILED)
        return self._record(Result.PASS)

    def status(self) -> EvidenceRecord:
        if self.state is not FrrSmokeState.RUNNING or not self.container_id:
            raise RuntimeError("status requires RUNNING")
        result = self._execute(("docker", "inspect", self.container_id))
        expected = ((_MANAGED, "true"), (_RUN_ID, self.run_id), (_CHANGE_ID, self.change_id))
        owned = result.ok and all(item in result.labels for item in expected)
        if owned and result.running is True:
            self._set_state(FrrSmokeState.INSPECTED)
            return self._record(Result.PASS)
        if result.ok and not owned:
            # A positive inspection proved this is not ours: deletion is forbidden.
            self._set_state(FrrSmokeState.CLEANUP_FAILED)
            return self._record(Result.FAIL, ReasonCode.STATUS_FAILED)
        self._cleanup()
        return self._record(Result.FAIL, ReasonCode.STATUS_FAILED)

    def _cleanup(self) -> EvidenceRecord:
        if self.state is FrrSmokeState.CLEANED:
            return self._record(Result.PASS)
        if self.container_id is None:
            if self.state in {
                FrrSmokeState.NEW,
                FrrSmokeState.PREFLIGHTED,
                FrrSmokeState.CACHE_VERIFIED,
                FrrSmokeState.PULLED,
            }:
                self._set_state(FrrSmokeState.CLEANED)
                return self._record(Result.PASS)
            self._set_state(FrrSmokeState.CLEANUP_FAILED)
            return self._record(Result.FAIL, ReasonCode.CLEANUP_FAILED)
        self._set_state(FrrSmokeState.CLEANING)
        inspected = self._execute(("docker", "inspect", self.container_id))
        expected = ((_MANAGED, "true"), (_RUN_ID, self.run_id), (_CHANGE_ID, self.change_id))
        if not inspected.ok or not all(item in inspected.labels for item in expected):
            self._set_state(FrrSmokeState.CLEANUP_FAILED)
            return self._record(Result.FAIL, ReasonCode.CLEANUP_FAILED)
        removed = self._execute(("docker", "rm", "--force", self.container_id))
        if removed.ok:
            self._set_state(FrrSmokeState.CLEANED)
            return self._record(Result.PASS)
        self._set_state(FrrSmokeState.CLEANUP_FAILED)
        return self._record(Result.FAIL, ReasonCode.CLEANUP_FAILED)

    def down(self) -> EvidenceRecord:
        return self._cleanup()
