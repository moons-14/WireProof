from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from pytest import MonkeyPatch
from typer.testing import CliRunner
from wireproof_cli import main
from wireproof_evidence import ExecutionMode, ReasonCode, Result
from wireproof_runtime import FrrSmokeState, clab_ebgp
from wireproof_runtime.clab_ebgp import ClabPreflightFailure, ClabResult


class _FakeRun:
    created: list[str] = []
    fail_up = False

    def __init__(self, change_id: str, executor: object) -> None:
        assert executor is main.SubprocessDockerExecutor
        self.created.append(change_id)
        self.run_id = f"run-{len(self.created)}"
        self.state = FrrSmokeState.NEW
        self.evidence: tuple[object, ...] = ()
        self.down_calls = 0

    @staticmethod
    def _record(result: Result) -> SimpleNamespace:
        return SimpleNamespace(result=result)

    def up(self) -> SimpleNamespace:
        if self.fail_up:
            return self._record(Result.FAIL)
        self.state = FrrSmokeState.RUNNING
        return self._record(Result.PASS)

    def status(self) -> SimpleNamespace:
        self.state = FrrSmokeState.INSPECTED
        return self._record(Result.PASS)

    def down(self) -> SimpleNamespace:
        self.down_calls += 1
        self.state = FrrSmokeState.CLEANED
        return self._record(Result.PASS)


def test_frr_smoke_emits_fixed_real_lifecycle_results(monkeypatch: MonkeyPatch) -> None:
    _FakeRun.created = []
    _FakeRun.fail_up = False
    monkeypatch.setattr(main, "FrrSmokeRun", _FakeRun)

    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "change-1", "--repeat", "2"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert _FakeRun.created == ["change-1", "change-1"]
    assert [item["run_id"] for item in payload] == ["run-1", "run-2"]
    assert all(item["state"] == "CLEANED" for item in payload)
    assert all(item["up"] == item["status"] == item["down"] == "PASS" for item in payload)
    assert all(item["execution_mode"] == ExecutionMode.REAL.value for item in payload)
    assert all(item["smoke_scope"] == "docker-frr-process-only" for item in payload)
    assert all(item["conformance"] == "UNKNOWN" for item in payload)


def test_frr_smoke_cleans_up_and_stops_before_second_run_on_failure(
    monkeypatch: MonkeyPatch,
) -> None:
    _FakeRun.created = []
    _FakeRun.fail_up = True
    monkeypatch.setattr(main, "FrrSmokeRun", _FakeRun)

    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "change-1", "--repeat", "2"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert _FakeRun.created == ["change-1"]
    assert payload[0]["up"] == "FAIL"
    assert payload[0]["down"] == "PASS"
    assert payload[0]["state"] == "CLEANED"


def test_frr_smoke_rejects_invalid_repeat_and_change_id() -> None:
    runner = CliRunner()
    assert runner.invoke(main.app, ["lab", "frr-smoke", "change-1", "--repeat", "3"]).exit_code != 0
    assert runner.invoke(main.app, ["lab", "frr-smoke", "user:secret"]).exit_code != 0


def test_clab_ebgp_v4_emits_closed_real_records(monkeypatch: MonkeyPatch) -> None:
    class FakeClabRun:
        created = 0

        def __init__(self) -> None:
            self.__class__.created += 1
            self.run_id = f"clab-{self.created}"
            self.lab_name = f"wp-ebgp-{self.created}"
            self.state = SimpleNamespace(value="PREPARED")
            self.deploy_attempted = False
            self.resolved_repo_digest = (
                "quay.io/frrouting/frr:10.5.4@sha256:"
                "17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
            )

        def up(self) -> bool:
            self.deploy_attempted = True
            self.state = SimpleNamespace(value="DEPLOYED")
            return True

        def status(self) -> bool:
            self.state = SimpleNamespace(value="VERIFIED")
            return True

        def down(self) -> bool:
            self.state = SimpleNamespace(value="CLEANED")
            return True

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", FakeClabRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4", "--repeat", "2"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [item["run_id"] for item in payload] == ["clab-1", "clab-2"]
    assert all(item["state"] == "CLEANED" for item in payload)
    assert all(item["scope"] == "containerlab-frr-ebgp-v4-only" for item in payload)


def test_clab_preflight_failure_emits_one_json_failure_record(monkeypatch: MonkeyPatch) -> None:
    class FailedPreflightRun:
        run_id = "clab-1"
        lab_name = "wp-ebgp-1"
        deploy_attempted = False
        resolved_repo_digest = None

        def __init__(self) -> None:
            self.state = SimpleNamespace(value="PREPARED")

        def up(self) -> bool:
            return False

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", FailedPreflightRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4", "--repeat", "2"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert len(payload) == 1
    assert payload[0]["up"] == payload[0]["status"] == payload[0]["down"] == "FAIL"
    assert payload[0]["state"] == "PREPARED"


def test_clab_preflight_failure_is_closed_and_contains_no_diagnostics(
    monkeypatch: MonkeyPatch,
) -> None:
    class FailedPreflightRun:
        run_id = "clab-1"
        lab_name = "wp-ebgp-1"
        deploy_attempted = False
        resolved_repo_digest = None
        failure = ClabPreflightFailure(code=ReasonCode.LAB_ENVIRONMENT_UNAVAILABLE)

        def __init__(self) -> None:
            self.state = SimpleNamespace(value="PREPARED")

        def up(self) -> bool:
            return False

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", FailedPreflightRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4"])
    assert result.exit_code == 1
    payload = json.loads(result.output)[0]
    assert payload["failure"] == {
        "code": "LAB_ENVIRONMENT_UNAVAILABLE",
        "stage": "PREFLIGHT",
        "resource_mutation": False,
    }


def test_clab_privilege_preflight_failure_is_closed(
    monkeypatch: MonkeyPatch,
) -> None:
    class FailedPreflightRun:
        run_id = "clab-privilege"
        lab_name = "wp-ebgp-privilege"
        deploy_attempted = False
        resolved_repo_digest = None
        failure = ClabPreflightFailure(code=ReasonCode.LAB_PRIVILEGE_UNAVAILABLE)

        def __init__(self) -> None:
            self.state = SimpleNamespace(value="PREPARED")

        def up(self) -> bool:
            return False

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", FailedPreflightRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4"])
    assert result.exit_code == 1
    payload = json.loads(result.output)[0]
    assert payload["failure"] == {
        "code": "LAB_PRIVILEGE_UNAVAILABLE",
        "stage": "PREFLIGHT",
        "resource_mutation": False,
    }


def test_clab_prepare_failure_emits_json_without_artifact_residue(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError()

    class GoodPreflightExecutor:
        def preflight(self) -> ClabResult:
            return ClabResult(
                True,
                version="0.59.0",
                platform="linux/amd64",
                repo_digest=(
                    "quay.io/frrouting/frr@sha256:"
                    "17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
                ),
            )

    def new_good_preflight_run() -> clab_ebgp.ContainerlabEbgpRun:
        return clab_ebgp.ContainerlabEbgpRun(GoodPreflightExecutor())

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", new_good_preflight_run)
    monkeypatch.setattr(clab_ebgp, "_write_owned_text", fail_write)

    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload[0]["up"] == payload[0]["status"] == payload[0]["down"] == "FAIL"
    assert list(tmp_path.glob(".wireproof/runs/*")) == []


def test_clab_cleanup_failure_includes_recovery_locator_only(monkeypatch: MonkeyPatch) -> None:
    class CleanupFailedRun:
        run_id = "clab-1"
        lab_name = "wp-ebgp-1"
        deploy_attempted = True
        resolved_repo_digest = "digest"
        artifact = Path("/tmp/wireproof-clab-ebgp-1/topology.clab.yml")
        recovery_destroy_command = (
            "containerlab",
            "destroy",
            "--topo",
            "/tmp/wireproof-clab-ebgp-1/topology.clab.yml",
            "--name",
            "wp-ebgp-1",
            "--cleanup",
        )

        def __init__(self) -> None:
            self.state = SimpleNamespace(value="PREPARED")

        def up(self) -> bool:
            return True

        def status(self) -> bool:
            return True

        def down(self) -> bool:
            self.state = SimpleNamespace(value="CLEANUP_FAILED")
            return False

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", CleanupFailedRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)[0]
    assert payload["recovery_topology_path"] == "/tmp/wireproof-clab-ebgp-1/topology.clab.yml"
    assert payload["recovery_destroy_command"] == list(CleanupFailedRun.recovery_destroy_command)


def test_clab_cleanup_failure_without_safe_recovery_command_is_structured(
    monkeypatch: MonkeyPatch,
) -> None:
    class CleanupFailedRun:
        run_id = "clab-1"
        lab_name = "wp-ebgp-1"
        deploy_attempted = True
        resolved_repo_digest = "digest"
        artifact = Path("/tmp/wireproof-clab-ebgp-1/topology.clab.yml")
        recovery_destroy_command = None

        def __init__(self) -> None:
            self.state = SimpleNamespace(value="PREPARED")

        def up(self) -> bool:
            return True

        def status(self) -> bool:
            return True

        def down(self) -> bool:
            self.state = SimpleNamespace(value="CLEANUP_FAILED")
            return False

    monkeypatch.setattr(main, "new_containerlab_ebgp_run", CleanupFailedRun)
    result = CliRunner().invoke(main.app, ["lab", "frr-smoke", "clab-ebgp-v4"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)[0]
    assert payload["recovery_topology_path"] == "/tmp/wireproof-clab-ebgp-1/topology.clab.yml"
    assert payload["recovery_destroy_command"] is None
