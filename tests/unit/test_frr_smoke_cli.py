from __future__ import annotations

import json
from types import SimpleNamespace

from _pytest.monkeypatch import MonkeyPatch
from typer.testing import CliRunner
from wireproof_cli import main
from wireproof_evidence import ExecutionMode, Result
from wireproof_runtime import FrrSmokeState


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
