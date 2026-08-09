from __future__ import annotations

from dataclasses import dataclass

import pytest
from wireproof_compiler import ImageDeclaration, RuntimeMetadata
from wireproof_evidence import ExecutionMode, ReasonCode, Result
from wireproof_runtime import (
    EventuallyResult,
    FakeRunner,
    ImageRef,
    LabRun,
    LabState,
    RuntimeCommand,
    RuntimeOperation,
    eventually,
)

IMAGE = "repo:1.0@sha256:" + "a" * 64


def metadata() -> RuntimeMetadata:
    return RuntimeMetadata(
        semantic_ir_hash="b" * 64,
        reference_topology_hash="c" * 64,
        provenance_clauses=("EVPN_M1",),
        image=ImageDeclaration(reference=IMAGE),
        component_versions=("wireproof-reference=1",),
        coverage=("state_transition", "failure_scenario", "target_command_provenance"),
    )


def test_fake_happy_path_transcript_and_fake_cannot_promote() -> None:
    runner = FakeRunner()
    run = LabRun("change-1", "run-1", runner, metadata())

    assert run.up(IMAGE).result is Result.PASS
    assert run.evidence[-1].image_reference == IMAGE
    assert run.state is LabState.RUNNING
    assert run.test(lambda: True).result is Result.PASS
    assert run.down().result is Result.PASS
    assert run.state is LabState.CLEANED  # type: ignore[comparison-overlap]
    assert runner.transcript == [
        RuntimeCommand.deploy("run-1"),
        RuntimeCommand.destroy("run-1"),
    ]
    assert run.evidence[-1].execution_mode is ExecutionMode.FAKE
    assert not run.evidence[-1].promotion_allowed
    assert run.evidence[0].semantic_ir_hash == "b" * 64
    assert run.evidence[0].artifact_hashes == ("c" * 64,)
    assert run.evidence[0].provenance_clauses == ("EVPN_M1",)
    assert run.evidence[0].component_versions == ("wireproof-reference=1",)
    assert run.evidence[0].coverage == (
        "state_transition",
        "failure_scenario",
        "target_command_provenance",
    )
    assert run.evidence[0].command_provenance == (RuntimeCommand.deploy("run-1").argv,)


@pytest.mark.parametrize("operation", list(RuntimeCommand.Operation))
def test_operation_failure_attempts_cleanup_and_cleanup_can_retry(
    operation: RuntimeOperation,
) -> None:
    runner = FakeRunner(fail_operations={operation})
    run = LabRun("change-1", "run-1", runner, metadata())
    run.up(ImageRef(IMAGE))

    if operation is RuntimeCommand.Operation.INSPECT:
        assert run.status().reason_code is ReasonCode.STATUS_FAILED
        assert run.state is LabState.CLEANED
        assert run.evidence[1].history == ("NEW", "DEPLOYING", "RUNNING", "FAILED")
        assert RuntimeCommand.destroy("run-1") in runner.transcript
        return
    if operation is RuntimeCommand.Operation.DESTROY:
        assert run.down().reason_code is ReasonCode.CLEANUP_FAILED
        assert run.state is LabState.CLEANUP_FAILED
        runner.fail_operations.clear()
        assert run.down().result is Result.PASS
        assert run.state is LabState.CLEANED  # type: ignore[comparison-overlap]
    else:
        assert run.state is LabState.CLEANED
        assert run.evidence[0].reason_code is ReasonCode.DEPLOY_FAILED
        assert RuntimeCommand.destroy("run-1") in runner.transcript


def test_mismatch_resources_are_preserved_and_cleaned_down_is_noop() -> None:
    runner = FakeRunner(resources=[{"managed_by": "other", "run_id": "run-1"}])
    run = LabRun("change-1", "run-1", runner, metadata())
    assert run.down().result is Result.PASS
    assert run.state is LabState.CLEANED
    assert runner.transcript == []
    assert run.down().result is Result.PASS
    assert runner.resources == [{"managed_by": "other", "run_id": "run-1"}]


@pytest.mark.parametrize(
    "value", ["repo:tag", "repo:latest", "repo@sha256:" + "a" * 64, "repo:tag@sha256:" + "A" * 64]
)
def test_image_ref_rejects_non_immutable_values(value: str) -> None:
    with pytest.raises(ValueError):
        ImageRef(value)


@dataclass
class Clock:
    now: float = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_eventually_has_injected_time_success_timeout_and_boundaries() -> None:
    clock = Clock()
    attempts = iter([False, True])
    success = eventually(
        lambda: next(attempts),
        timeout=1,
        interval=0.5,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )
    assert (success.succeeded, success.attempts, success.elapsed) == (True, 2, 0.5)
    timeout = eventually(
        lambda: False, timeout=1, interval=0.5, monotonic=clock.monotonic, sleeper=clock.sleep
    )
    assert (timeout.succeeded, timeout.attempts, timeout.elapsed) == (False, 3, 1.0)
    with pytest.raises(ValueError):
        eventually(
            lambda: True, timeout=0, interval=1, monotonic=clock.monotonic, sleeper=clock.sleep
        )
    with pytest.raises(ValueError):
        eventually(
            lambda: True,
            timeout=float("inf"),
            interval=1,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )


def test_test_failure_attempts_cleanup() -> None:
    runner = FakeRunner()
    run = LabRun("change-1", "run-1", runner, metadata())
    run.up(ImageRef(IMAGE))
    assert run.test(lambda: False).reason_code is ReasonCode.TEST_FAILED
    assert run.state is LabState.CLEANED
    assert runner.transcript[-1] == RuntimeCommand.destroy("run-1")


def test_test_evidence_retains_convergence_attempts_and_elapsed() -> None:
    run = LabRun("change-1", "run-1", FakeRunner(), metadata())
    run.up(IMAGE)
    record = run.test(EventuallyResult(succeeded=False, attempts=3, elapsed=1.0))
    assert (record.attempts, record.elapsed) == (3, 1.0)
    assert record.history == ("NEW", "DEPLOYING", "RUNNING", "TESTING", "TEST_FAILED")


@pytest.mark.parametrize("change_id,run_id", [("", "run-1"), ("change-1", "")])
def test_lab_run_requires_nonempty_identities(change_id: str, run_id: str) -> None:
    with pytest.raises(ValueError):
        LabRun(change_id, run_id, FakeRunner(), metadata())


def test_evidence_snapshot_cannot_be_mutated_and_metadata_image_is_bound() -> None:
    run = LabRun("change-1", "run-1", FakeRunner(), metadata())
    with pytest.raises(AttributeError):
        getattr(run.evidence, "append")(  # noqa: B009
            object()
        )
    assert not hasattr(LabRun, "evidence_record")
    with pytest.raises(ValueError, match="immutable compiled metadata"):
        run.up("repo:2.0@sha256:" + "a" * 64)


def test_runtime_metadata_cannot_be_reassigned_between_records() -> None:
    run = LabRun("change-1", "run-1", FakeRunner(), metadata())
    first = run.up(IMAGE)
    with pytest.raises(AttributeError, match="runtime metadata is immutable"):
        run.metadata = metadata()  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="runtime metadata is immutable"):
        run._metadata = metadata()  # type: ignore[misc]
    second = run.status()
    assert second.semantic_ir_hash == first.semantic_ir_hash


def test_bound_metadata_and_image_cannot_be_deleted_or_rebound() -> None:
    run = LabRun("change-1", "run-1", FakeRunner(), metadata())
    with pytest.raises(AttributeError, match="runtime metadata is immutable"):
        del run._metadata  # type: ignore[misc]
    with pytest.raises(AttributeError, match="runtime metadata is immutable"):
        run._metadata = metadata()  # type: ignore[misc]
    with pytest.raises(AttributeError, match="runtime image is immutable"):
        del run._image  # type: ignore[misc]
    with pytest.raises(AttributeError, match="runtime image is immutable"):
        run._image = ImageRef("repo:2.0@sha256:" + "b" * 64)  # type: ignore[misc]
    assert run.up(IMAGE).image_reference == IMAGE


def test_public_lifecycle_records_always_carry_compiled_provenance() -> None:
    run = LabRun("change-1", "run-1", FakeRunner(), metadata())
    records = (run.up(IMAGE), run.status(), run.down())
    assert all(record.semantic_ir_hash == metadata().semantic_ir_hash for record in records)
    assert all(record.provenance_clauses == metadata().provenance_clauses for record in records)


def test_runtime_command_is_closed_and_program_built() -> None:
    assert RuntimeCommand.deploy("run-1").argv == (
        "wireproof-runtime",
        "deploy",
        "--run-id",
        "run-1",
    )
    with pytest.raises(ValueError):
        RuntimeCommand("shell", ("sh", "-c", "unsafe"))  # type: ignore[arg-type]
