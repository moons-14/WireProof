from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest
from wireproof_evidence import ExecutionMode, ReasonCode, Result
from wireproof_runtime import DockerResult, FrrSmokeRun, FrrSmokeState, SubprocessDockerExecutor
from wireproof_runtime.frr_smoke import FRR_CACHE_IMAGE, FRR_IMAGE, FRR_PLATFORM

CONTAINER_ID = "a" * 64


@dataclass
class Executor:
    results: list[DockerResult]
    argv: list[tuple[str, ...]] = field(default_factory=list)

    @property
    def execution_mode(self) -> ExecutionMode:
        return ExecutionMode.FAKE

    def execute(self, argv: tuple[str, ...]) -> DockerResult:
        self.argv.append(argv)
        return self.results.pop(0)


def cached_image() -> DockerResult:
    return DockerResult(
        True, image_id="sha256:image", repo_digests=(FRR_CACHE_IMAGE,), platform=FRR_PLATFORM
    )


def owned_container() -> DockerResult:
    return DockerResult(
        True,
        labels=(
            ("io.wireproof.managed", "true"),
            ("io.wireproof.run_id", "00000000-0000-0000-0000-000000000001"),
            ("io.wireproof.change_id", "change-1"),
        ),
        running=True,
    )


def test_cache_run_inspect_and_id_only_cleanup_transcript() -> None:
    executor = Executor(
        [
            cached_image(),
            DockerResult(True, container_id=CONTAINER_ID),
            owned_container(),
            owned_container(),
            DockerResult(True),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().result is Result.PASS
    assert run.status().result is Result.PASS
    assert run.down().result is Result.PASS
    assert executor.argv == [
        ("docker", "image", "inspect", FRR_CACHE_IMAGE),
        (
            "docker",
            "run",
            "--platform",
            "linux/amd64",
            "--detach",
            "--network",
            "none",
            "--name",
            "wireproof-frr-smoke-00000000-0000-0000-0000-000000000001",
            "--label",
            "io.wireproof.managed=true",
            "--label",
            "io.wireproof.run_id=00000000-0000-0000-0000-000000000001",
            "--label",
            "io.wireproof.change_id=change-1",
            FRR_IMAGE,
        ),
        ("docker", "inspect", CONTAINER_ID),
        ("docker", "inspect", CONTAINER_ID),
        ("docker", "rm", "--force", CONTAINER_ID),
    ]
    assert run.state is FrrSmokeState.CLEANED
    assert run.evidence[-1].execution_mode is ExecutionMode.FAKE
    assert "EVPN" not in run.evidence[-1].reason.upper().replace("NOT EVPN", "")


def test_pull_is_rechecked_and_mismatch_never_runs() -> None:
    executor = Executor(
        [
            DockerResult(False),
            DockerResult(True),
            DockerResult(True, repo_digests=(FRR_CACHE_IMAGE,), platform="linux/arm64"),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().reason_code is ReasonCode.IMAGE_REFERENCE_INVALID
    assert not any(argv[:2] == ("docker", "run") for argv in executor.argv)


def test_collision_or_unowned_inspection_never_removes_and_cleanup_is_failed() -> None:
    executor = Executor(
        [
            cached_image(),
            DockerResult(True, container_id=CONTAINER_ID),
            DockerResult(True, labels=(("io.wireproof.managed", "true"),)),
            DockerResult(True, labels=(("io.wireproof.managed", "true"),)),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )
    run.up()

    assert run.status().reason_code is ReasonCode.STATUS_FAILED
    assert not any(argv[:3] == ("docker", "rm", "--force") for argv in executor.argv)
    assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
    assert executor.argv[-1] == ("docker", "inspect", CONTAINER_ID)


def test_cleanup_failure_retries_and_up_cannot_retry() -> None:
    executor = Executor(
        [
            cached_image(),
            DockerResult(True, container_id=CONTAINER_ID),
            owned_container(),
            DockerResult(False),
            owned_container(),
            DockerResult(True),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )
    run.up()
    assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
    assert run.state is FrrSmokeState.CLEANUP_FAILED
    assert run.down().result is Result.PASS
    with pytest.raises(RuntimeError, match="up retry"):
        run.up()


def test_pull_and_run_use_platform_and_run_reference() -> None:
    executor = Executor(
        [DockerResult(False), DockerResult(True), cached_image(), DockerResult(False)]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().reason_code is ReasonCode.DEPLOY_FAILED
    assert executor.argv[:3] == [
        ("docker", "image", "inspect", FRR_CACHE_IMAGE),
        ("docker", "pull", "--platform", FRR_PLATFORM, FRR_IMAGE),
        ("docker", "image", "inspect", FRR_CACHE_IMAGE),
    ]


def test_uuid_run_id_and_concrete_executor_mode() -> None:
    with pytest.raises(ValueError, match="UUID"):
        FrrSmokeRun("change-1", Executor([]), uuid_factory=lambda: "u1")
    assert (
        SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1").execution_mode
        is ExecutionMode.REAL
    )


@pytest.mark.parametrize("timeout_seconds", [0, -1, float("inf"), float("-inf"), float("nan")])
def test_concrete_executor_rejects_non_positive_or_non_finite_timeouts(
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="finite and greater than zero"):
        SubprocessDockerExecutor(
            "00000000-0000-0000-0000-000000000001", "change-1", timeout_seconds
        )


def test_injected_executor_cannot_claim_real_evidence() -> None:
    class RealClaimingExecutor(Executor):
        @property
        def execution_mode(self) -> ExecutionMode:
            return ExecutionMode.REAL

    executor = RealClaimingExecutor([cached_image(), DockerResult(True, container_id=CONTAINER_ID)])
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().execution_mode is ExecutionMode.FAKE


def test_concrete_executor_rejects_arbitrary_argv_without_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("subprocess must not be invoked")

    monkeypatch.setattr("wireproof_runtime.frr_smoke.subprocess.run", forbidden)
    executor = SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1")
    assert not executor.execute(("docker", "ps")).ok


def test_concrete_executor_rejects_an_external_container_after_registering_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "00000000-0000-0000-0000-000000000001"
    executor = SubprocessDockerExecutor(run_id, "change-1")
    run_argv = (
        "docker",
        "run",
        "--platform",
        FRR_PLATFORM,
        "--detach",
        "--network",
        "none",
        "--name",
        f"wireproof-frr-smoke-{run_id}",
        "--label",
        "io.wireproof.managed=true",
        "--label",
        f"io.wireproof.run_id={run_id}",
        "--label",
        "io.wireproof.change_id=change-1",
        FRR_IMAGE,
    )
    monkeypatch.setattr(
        "wireproof_runtime.frr_smoke.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=CONTAINER_ID),
    )
    assert executor.execute(run_argv).container_id == CONTAINER_ID

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("subprocess must not be invoked")

    monkeypatch.setattr("wireproof_runtime.frr_smoke.subprocess.run", forbidden)
    assert not executor.execute(("docker", "inspect", "b" * 64)).ok
    assert not executor.execute(("docker", "rm", "--force", "b" * 64)).ok


@pytest.mark.parametrize("running", [False, None])
def test_exited_or_unknown_container_state_fails_status_then_cleans_owned_container(
    running: bool | None,
) -> None:
    executor = Executor(
        [
            cached_image(),
            DockerResult(True, container_id=CONTAINER_ID),
            DockerResult(True, labels=owned_container().labels, running=running),
            owned_container(),
            DockerResult(True),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().result is Result.PASS
    assert run.status().reason_code is ReasonCode.STATUS_FAILED
    assert run.state is FrrSmokeState.CLEANED


def test_concrete_executor_converts_oserror_and_malformed_inspect_to_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("docker unavailable")

    monkeypatch.setattr("wireproof_runtime.frr_smoke.subprocess.run", os_error)
    executor = SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1")
    assert not executor.execute(("docker", "image", "inspect", FRR_CACHE_IMAGE)).ok

    monkeypatch.setattr(
        "wireproof_runtime.frr_smoke.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="{}"),
    )
    executor = SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1")
    assert not executor.execute(("docker", "inspect", CONTAINER_ID)).ok


def test_invalid_container_id_never_selects_cleanup_target() -> None:
    executor = Executor([cached_image(), DockerResult(True, container_id="short")])
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().reason_code is ReasonCode.DEPLOY_FAILED
    assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
    assert run.state is FrrSmokeState.CLEANUP_FAILED
    assert not any(argv[:2] in {("docker", "inspect"), ("docker", "rm")} for argv in executor.argv)


def test_failed_run_with_valid_id_is_inspected_then_removed_only_when_owned() -> None:
    executor = Executor(
        [
            cached_image(),
            DockerResult(False, container_id=CONTAINER_ID),
            owned_container(),
            DockerResult(True),
        ]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    assert run.up().reason_code is ReasonCode.DEPLOY_FAILED
    assert run.container_id == CONTAINER_ID
    assert run.down().result is Result.PASS
    assert executor.argv[-2:] == [
        ("docker", "inspect", CONTAINER_ID),
        ("docker", "rm", "--force", CONTAINER_ID),
    ]


def test_failed_run_with_valid_id_never_removes_without_ownership_proof() -> None:
    executor = Executor(
        [cached_image(), DockerResult(False, container_id=CONTAINER_ID), DockerResult(True)]
    )
    run = FrrSmokeRun(
        "change-1", executor, uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )

    run.up()
    assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
    assert not any(argv[:3] == ("docker", "rm", "--force") for argv in executor.argv)


@pytest.mark.parametrize("stdout", [CONTAINER_ID, CONTAINER_ID.encode()])
def test_concrete_executor_retains_only_valid_id_from_failed_or_timed_out_run(
    monkeypatch: pytest.MonkeyPatch, stdout: str | bytes
) -> None:
    run_argv = (
        "docker",
        "run",
        "--platform",
        FRR_PLATFORM,
        "--detach",
        "--network",
        "none",
        "--name",
        "wireproof-frr-smoke-00000000-0000-0000-0000-000000000001",
        "--label",
        "io.wireproof.managed=true",
        "--label",
        "io.wireproof.run_id=00000000-0000-0000-0000-000000000001",
        "--label",
        "io.wireproof.change_id=change-1",
        FRR_IMAGE,
    )
    monkeypatch.setattr(
        "wireproof_runtime.frr_smoke.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=stdout),
    )
    executor = SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1")
    assert executor.execute(run_argv) == DockerResult(False, container_id=CONTAINER_ID)

    error = subprocess.TimeoutExpired(run_argv, 30, output=stdout)
    monkeypatch.setattr(
        "wireproof_runtime.frr_smoke.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    executor = SubprocessDockerExecutor("00000000-0000-0000-0000-000000000001", "change-1")
    assert executor.execute(run_argv) == DockerResult(False, container_id=CONTAINER_ID)


def test_cleanup_with_unknown_running_state_and_no_id_fails_closed() -> None:
    run = FrrSmokeRun(
        "change-1", Executor([]), uuid_factory=lambda: "00000000-0000-0000-0000-000000000001"
    )
    run._set_state(FrrSmokeState.RUNNING)

    assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
    assert run.state is FrrSmokeState.CLEANUP_FAILED
