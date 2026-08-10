from __future__ import annotations

import json
from pathlib import Path

import pytest
import wireproof_runtime
from wireproof_runtime import clab_ebgp
from wireproof_runtime.clab_ebgp import (
    FRR_EBGP_REPO_DIGEST,
    ClabResult,
    ContainerlabEbgpRun,
)

_CONTROLLER_ID = "a" * 64


class FakeExecutor:
    def __init__(
        self, *, preflight: ClabResult | None = None, probes: tuple[str, ...] = ()
    ) -> None:
        self.preflight_result = preflight or ClabResult(
            True,
            version="0.59.0",
            platform="linux/amd64",
            repo_digest=FRR_EBGP_REPO_DIGEST,
        )
        self.probes = list(probes)
        self.argv: list[tuple[str, ...]] = []
        self.deploy_ok = True
        self.destroy_ok = True

    def preflight(self) -> ClabResult:
        return self.preflight_result

    def _mint_run_artifact(self, topology: Path, lab_name: str) -> clab_ebgp._RunArtifact:
        return clab_ebgp._RunArtifact(topology, lab_name)

    def _execute(
        self,
        artifact: clab_ebgp._RunArtifact,
        operation: clab_ebgp._ContainerlabOperation,
        node: str | None = None,
    ) -> ClabResult:
        argv = artifact.argv(operation, node)
        self.argv.append(argv)
        if argv[1] == "exec":
            return ClabResult(True, self.probes.pop(0))
        if argv[1] == "deploy":
            return ClabResult(self.deploy_ok)
        if argv[1] == "destroy":
            return ClabResult(self.destroy_ok)
        return ClabResult(True)


@pytest.fixture(autouse=True)
def repository_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Each run-root test operates in an isolated repository-shaped directory."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)


def _peer(peer: str, local: int, remote: int) -> str:
    return json.dumps(
        {
            "peers": {
                peer: {
                    "state": "Established",
                    "peerState": "OK",
                    "localAs": local,
                    "remoteAs": remote,
                }
            }
        }
    )


def test_runtime_root_hides_the_real_containerlab_executor() -> None:
    assert not hasattr(wireproof_runtime, "ContainerlabExecutor")
    assert not hasattr(wireproof_runtime, "SubprocessContainerlabExecutor")
    run = wireproof_runtime.new_containerlab_ebgp_run()
    assert isinstance(run, ContainerlabEbgpRun)
    assert not hasattr(run, "executor")


def test_nonroot_preflight_returns_privilege_failure_before_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("preflight must not invoke commands as non-root")

    monkeypatch.setattr(clab_ebgp.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(clab_ebgp.shutil, "which", unexpected)
    monkeypatch.setattr(clab_ebgp.subprocess, "run", unexpected)

    result = clab_ebgp.SubprocessContainerlabExecutor().preflight()

    assert result.failure is not None
    assert result.failure.code.value == "LAB_PRIVILEGE_UNAVAILABLE"
