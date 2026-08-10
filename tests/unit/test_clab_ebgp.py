from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import wireproof_runtime
from wireproof_evidence import ReasonCode
from wireproof_runtime import clab_ebgp
from wireproof_runtime.clab_ebgp import (
    CONTAINERLAB_VERSION,
    FRR_EBGP_REPO_DIGEST,
    ClabEbgpState,
    ClabPreflightFailure,
    ClabResult,
    ContainerlabEbgpRun,
    SubprocessContainerlabExecutor,
)

_CONTROLLER_ID = "a" * 64


def _controller_docker(
    executor: clab_ebgp._PrivilegedContainerlabExecutor, *, mode: str = "happy"
) -> list[tuple[str, ...]]:
    """Install a closed Docker transcript; it never contacts a daemon."""
    calls: list[tuple[str, ...]] = []
    created: tuple[str, ...] | None = None
    image_inspects = 0

    def completed(
        argv: tuple[str, ...], code: int = 0, output: str = ""
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, code, output, "")

    def docker(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        nonlocal created, image_inspects
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            image_inspects += 1
            if mode == "repo-digest-mismatch" and image_inspects > 1:
                return completed(argv, output="foreign@sha256:" + "b" * 64 + "\n")
            return completed(argv, output=clab_ebgp.CONTAINERLAB_CONTROLLER_REPO_DIGEST + "\n")
        if argv[:3] == ("docker", "container", "inspect"):
            target = argv[3]
            if target.startswith("wp-clabctl-"):
                return completed(argv, 0 if mode == "collision" else 1)
            if created is None or target != _CONTROLLER_ID:
                return completed(argv, 1)
            if mode == "ownership-mismatch":
                return completed(argv, output="[]")
            name = created[created.index("--name") + 1]
            labels = {
                created[index + 1].split("=", 1)[0]: created[index + 1].split("=", 1)[1]
                for index, value in enumerate(created)
                if value == "--label"
            }
            if mode == "label-mismatch":
                labels["io.wireproof.managed"] = "false"
            return completed(
                argv,
                output=json.dumps(
                    [
                        {
                            "Id": _CONTROLLER_ID,
                            "Name": f"/{name}",
                            "Config": {
                                "Labels": labels,
                                "Image": clab_ebgp.CONTAINERLAB_CONTROLLER_IMAGE,
                            },
                        }
                    ]
                ),
            )
        if argv[:2] == ("docker", "create"):
            created = argv
            return completed(
                argv, output=("bad-id" if mode == "malformed-id" else _CONTROLLER_ID) + "\n"
            )
        if argv[:3] == ("docker", "start", "-a"):
            if mode == "timeout":
                raise subprocess.TimeoutExpired(argv, 1)
            return completed(argv, 1 if mode == "nonzero" else 0)
        if argv[:3] == ("docker", "rm", "-f"):
            return completed(argv, 1 if mode == "cleanup-failure" else 0)
        raise AssertionError(f"unexpected Docker command: {argv!r}")

    executor._docker = docker  # type: ignore[method-assign]
    executor._mount_prerequisites = lambda: True  # type: ignore[method-assign]
    return calls


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
    assert not hasattr(wireproof_runtime, "PrivilegedContainerlabExecutor")
    assert not hasattr(wireproof_runtime, "new_privileged_containerlab_ebgp_run")


def test_privileged_controller_rejects_direct_construction_without_cli_capability(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authorization"):
        clab_ebgp._PrivilegedContainerlabExecutor("change-1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="authorization"):
        wireproof_runtime._new_privileged_containerlab_ebgp_run(  # type: ignore[call-arg]
            object(), object(), "change-1", tmp_path
        )
    assert not hasattr(wireproof_runtime, "new_privileged_containerlab_ebgp_run")


def test_privileged_controller_authorizer_consumes_only_issued_exact_permits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        clab_ebgp.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("no Docker")),
    )
    authorizer = clab_ebgp._PrivilegedControllerAuthorizer(tmp_path)
    permit = authorizer.issue("change-1")
    assert isinstance(
        wireproof_runtime._new_privileged_containerlab_ebgp_run(
            authorizer, permit, "change-1", tmp_path
        ),
        ContainerlabEbgpRun,
    )
    for forged, change_id, root in (
        (permit, "change-1", tmp_path),
        (clab_ebgp._PrivilegedControllerPermit(), "change-1", tmp_path),
        (authorizer.issue("change-2"), "change-1", tmp_path),
        (authorizer.issue("change-3"), "change-3", tmp_path / "wrong-root"),
    ):
        with pytest.raises(ValueError, match="authorization"):
            wireproof_runtime._new_privileged_containerlab_ebgp_run(
                authorizer, forged, change_id, root
            )


def test_privileged_controller_authorizer_allows_exactly_one_simultaneous_consume(
    tmp_path: Path,
) -> None:
    authorizer = clab_ebgp._PrivilegedControllerAuthorizer(tmp_path)
    permit = authorizer.issue("change-1")
    results: list[str] = []

    def consume() -> None:
        try:
            wireproof_runtime._new_privileged_containerlab_ebgp_run(
                authorizer, permit, "change-1", tmp_path
            )
            results.append("success")
        except ValueError:
            results.append("denial")

    first = threading.Thread(target=consume)
    second = threading.Thread(target=consume)
    first.start()
    second.start()
    first.join()
    second.join()
    assert sorted(results) == ["denial", "success"]


@pytest.mark.parametrize(
    "source",
    ["/var/run/docker.sock", "/var/run/netns", "/etc/hosts", "/var/lib/docker/containers"],
)
@pytest.mark.parametrize("mode", ["missing", "wrong-type"])
def test_privileged_controller_mount_prerequisite_blocks_docker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: str, mode: str
) -> None:
    path = Path(source)
    monkeypatch.setattr(clab_ebgp, "_FIXED_CONTROLLER_MOUNTS", ((path, stat.S_IFDIR),))

    def lstat(_self: Path) -> SimpleNamespace:
        if mode == "missing":
            raise FileNotFoundError()
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o644)

    monkeypatch.setattr(Path, "lstat", lstat)
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    executor._docker = lambda _argv: (_ for _ in ()).throw(AssertionError("no Docker"))  # type: ignore[method-assign]
    result = executor.preflight()
    assert result.failure == ClabPreflightFailure(
        ReasonCode.LAB_CONTROLLER_MOUNT_PREREQUISITE_FAILED
    )


def test_privileged_controller_revalidates_mounts_before_each_docker_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    enabled = True
    calls: list[tuple[str, ...]] = []
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    executor._mount_prerequisites = lambda: enabled  # type: ignore[method-assign]

    def docker_run(argv: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, clab_ebgp.CONTAINERLAB_CONTROLLER_REPO_DIGEST + "\n", ""
        )

    monkeypatch.setattr(clab_ebgp.subprocess, "run", docker_run)
    assert executor.preflight().ok
    enabled = False
    with pytest.raises(clab_ebgp._ControllerMountPrerequisiteError):
        executor._docker(("docker", "create", "must-not-run"))
    assert len(calls) == 1


def test_privileged_controller_rejects_repo_and_artifact_mapping_mismatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    foreign_repo = tmp_path / "foreign-repo"
    foreign_repo.mkdir()
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", foreign_repo)
    )
    calls = _controller_docker(executor)
    assert not ContainerlabEbgpRun(executor).up()
    assert not any(argv[:2] == ("docker", "create") for argv in calls)

    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    calls = _controller_docker(executor)
    escaped = tmp_path.parent / "escaped-artifact"
    escaped.mkdir(exist_ok=True)
    topology = escaped / "topology.clab.yml"
    topology.write_text("name: escaped\n")
    artifact = executor._mint_run_artifact(topology, "wp-ebgp-escaped")
    object.__setattr__(artifact, "identity", clab_ebgp._ArtifactIdentity(0, 0))
    monkeypatch.setattr(clab_ebgp, "_artifact_is_intact", lambda *_args: True)
    assert not executor._execute(artifact, clab_ebgp._ContainerlabOperation.DEPLOY).ok
    assert not calls


@pytest.mark.parametrize(
    ("mode", "created", "removed"),
    [
        ("collision", False, False),
        ("malformed-id", True, False),
        ("ownership-mismatch", True, False),
        ("label-mismatch", True, False),
        ("repo-digest-mismatch", True, False),
        ("timeout", True, True),
        ("nonzero", True, True),
        ("cleanup-failure", True, True),
    ],
)
def test_privileged_controller_refuses_or_cleans_only_the_exact_id(
    tmp_path: Path, mode: str, created: bool, removed: bool
) -> None:
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    calls = _controller_docker(executor, mode=mode)
    run = ContainerlabEbgpRun(executor)

    assert not run.up()
    create_calls = [argv for argv in calls if argv[:2] == ("docker", "create")]
    rm_calls = [argv for argv in calls if argv[:3] == ("docker", "rm", "-f")]
    assert bool(create_calls) is created
    assert bool(rm_calls) is removed
    assert all(argv == ("docker", "rm", "-f", _CONTROLLER_ID) for argv in rm_calls)
    assert not any(
        "--all" in argv or any("wp-clabctl-" in part for part in argv[3:]) for argv in rm_calls
    )


def test_privileged_controller_happy_path_uses_closed_create_start_and_exact_cleanup(
    tmp_path: Path,
) -> None:
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    calls = _controller_docker(executor)
    run = ContainerlabEbgpRun(executor)

    assert run.up() and run.down()
    create_calls = [argv for argv in calls if argv[:2] == ("docker", "create")]
    start_calls = [argv for argv in calls if argv[:3] == ("docker", "start", "-a")]
    rm_calls = [argv for argv in calls if argv[:3] == ("docker", "rm", "-f")]
    assert len(create_calls) == len(start_calls) == len(rm_calls) == 2
    assert all(argv == ("docker", "start", "-a", _CONTROLLER_ID) for argv in start_calls)
    assert all(argv == ("docker", "rm", "-f", _CONTROLLER_ID) for argv in rm_calls)
    create = create_calls[0]
    assert create[create.index("--platform") + 1] == "linux/amd64"
    assert (
        "--privileged" in create
        and ("--network", "host")
        == create[create.index("--network") : create.index("--network") + 2]
    )
    assert "/usr/bin/containerlab" in create
    assert "--rm" not in create and "--env" not in create


def test_closed_lifecycle_artifact_and_exact_argv() -> None:
    executor = FakeExecutor(
        probes=(_peer("192.0.2.1", 65001, 65002), _peer("192.0.2.0", 65002, 65001))
    )
    run = ContainerlabEbgpRun(executor)
    assert run.up() and run.status()
    artifact_dir = run.artifact_dir
    assert artifact_dir is not None and artifact_dir.exists()
    assert "192.0.2.0/31" in (artifact_dir / "n1" / "frr.conf").read_text()
    assert "network" not in (artifact_dir / "n1" / "frr.conf").read_text()
    assert run.down()
    assert run.state is ClabEbgpState.CLEANED
    assert not artifact_dir.exists()
    assert executor.argv[0][:2] == ("containerlab", "deploy")
    assert executor.argv[-1][-1] == "--cleanup"


def test_bad_preflight_never_deploys() -> None:
    executor = FakeExecutor(
        preflight=ClabResult(
            True,
            version="0.58.0",
            platform="linux/amd64",
            repo_digest=FRR_EBGP_REPO_DIGEST,
        )
    )
    assert not ContainerlabEbgpRun(executor).up()
    assert executor.argv == []


def test_preflight_rejects_non_linux_amd64_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.host_platform, "system", lambda: "Darwin")
    monkeypatch.setattr(clab_ebgp.host_platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        clab_ebgp.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    result = executor.preflight()

    assert result.failure == ClabPreflightFailure(ReasonCode.LAB_PLATFORM_UNSUPPORTED)


def test_malformed_probe_fails_and_cleanup_is_exact() -> None:
    executor = FakeExecutor(probes=("{}",))
    run = ContainerlabEbgpRun(executor)
    assert run.up() and not run.status() and run.down()
    assert executor.argv[-1][1:] == (
        "destroy",
        "--topo",
        str(run.artifact),
        "--name",
        run.lab_name,
        "--cleanup",
    )


def test_down_after_cleaned_is_noop() -> None:
    executor = FakeExecutor(
        probes=(_peer("192.0.2.1", 65001, 65002), _peer("192.0.2.0", 65002, 65001))
    )
    run = ContainerlabEbgpRun(executor)
    assert run.up() and run.status() and run.down()
    count = len(executor.argv)
    assert run.down() and len(executor.argv) == count


def test_failed_deploy_still_gets_one_exact_destroy_and_removes_artifact() -> None:
    executor = FakeExecutor()
    executor.deploy_ok = False
    run = ContainerlabEbgpRun(executor)
    assert not run.up()
    artifact_dir = run.artifact_dir
    assert artifact_dir is not None and not artifact_dir.exists()
    assert run.state is ClabEbgpState.CLEANED
    assert run.failure == ClabPreflightFailure(
        ReasonCode.DEPLOY_FAILED, stage="DEPLOY", resource_mutation=True
    )
    assert [argv[1] for argv in executor.argv] == ["deploy", "destroy"]
    assert not artifact_dir.exists()
    assert run.down()
    assert [argv[1] for argv in executor.argv] == ["deploy", "destroy"]


def test_destroy_failure_preserves_artifact_for_recovery() -> None:
    executor = FakeExecutor()
    executor.destroy_ok = False
    run = ContainerlabEbgpRun(executor)
    assert run.up()
    artifact_dir = run.artifact_dir
    assert artifact_dir is not None
    assert not run.down()
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert run.failure == ClabPreflightFailure(
        ReasonCode.CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
    )
    assert artifact_dir.exists()
    assert run.recovery_destroy_command == (
        "containerlab",
        "destroy",
        "--topo",
        str(run.artifact),
        "--name",
        run.lab_name,
        "--cleanup",
    )


def test_privileged_controller_destroy_failure_has_controller_only_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = clab_ebgp._PrivilegedContainerlabExecutor(
        clab_ebgp._PrivilegedControllerBinding("change-1", tmp_path)
    )
    monkeypatch.setattr(
        executor,
        "preflight",
        lambda: ClabResult(
            True,
            version=CONTAINERLAB_VERSION,
            platform="linux/amd64",
            repo_digest=FRR_EBGP_REPO_DIGEST,
        ),
    )
    monkeypatch.setattr(
        executor,
        "_execute",
        lambda _artifact, operation, _node=None: ClabResult(
            operation is clab_ebgp._ContainerlabOperation.DEPLOY
        ),
    )
    run = ContainerlabEbgpRun(executor)
    assert run.up() and not run.down()
    assert run.failure == ClabPreflightFailure(
        ReasonCode.LAB_DESTROY_FAILED, stage="CLEANUP", resource_mutation=True
    )


def test_prepare_failure_removes_only_its_own_artifact_and_clears_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise clab_ebgp.ClabPreparationError("failed")

    # Keep fault injection at the descriptor-relative writer so the production
    # path remains protected from path traversal and link following.
    monkeypatch.setattr(clab_ebgp, "_write_owned_text_at", fail_write)
    run = ContainerlabEbgpRun(FakeExecutor())

    with pytest.raises(clab_ebgp.ClabPreparationError):
        run.prepare()

    assert run.artifact_dir is None
    assert not (tmp_path / ".wireproof" / "runs" / run.run_id).exists()


def test_successful_prepare_is_idempotent_without_new_preflight_or_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = FakeExecutor()
    preflight_calls = 0
    original_preflight = executor.preflight

    def preflight() -> ClabResult:
        nonlocal preflight_calls
        preflight_calls += 1
        return original_preflight()

    monkeypatch.setattr(executor, "preflight", preflight)
    run = ContainerlabEbgpRun(executor)

    assert run.prepare()
    artifact_dir = run.artifact_dir
    artifact = run.artifact
    assert run.prepare()

    assert preflight_calls == 1
    assert executor.argv == []
    assert run.artifact_dir is artifact_dir
    assert run.artifact == artifact


def test_executor_rejects_non_run_artifact_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(
        clab_ebgp.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )
    assert not executor._execute(object(), clab_ebgp._ContainerlabOperation.DEPLOY).ok  # type: ignore[arg-type]


def test_executor_rejects_forged_run_artifact_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(
        clab_ebgp.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    forged = clab_ebgp._RunArtifact(Path("/tmp/forged.clab.yml"), "forged")

    assert not executor._execute(forged, clab_ebgp._ContainerlabOperation.DEPLOY).ok


def test_run_rejects_caller_provided_lab_identity() -> None:
    with pytest.raises(TypeError):
        ContainerlabEbgpRun(FakeExecutor(), lab_name="forged")  # type: ignore[call-arg]


def test_local_artifact_removal_failure_is_reported_and_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    artifact_dir = run.artifact_dir
    assert artifact_dir is not None
    monkeypatch.setattr(clab_ebgp, "_remove_owned_run_directory", lambda *_: False)
    assert not run.down()
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert run.failure == ClabPreflightFailure(
        ReasonCode.LAB_ARTIFACT_CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
    )
    assert artifact_dir.exists()


def test_run_artifacts_use_the_repo_local_private_root_and_are_ignored() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())

    assert run.prepare()
    assert run.artifact_dir == Path.cwd() / ".wireproof" / "runs" / run.run_id
    assert stat.S_IMODE(run.artifact_dir.stat().st_mode) == 0o700
    assert run.artifact.is_file()
    assert ".wireproof/" in (Path(__file__).parents[2] / ".gitignore").read_text()


def test_run_root_rejects_a_symlinked_wireproof_directory(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    (tmp_path / ".wireproof").symlink_to(target, target_is_directory=True)

    with pytest.raises(clab_ebgp.ClabPreparationError):
        ContainerlabEbgpRun(FakeExecutor()).prepare()


def test_prepare_fails_closed_when_no_follow_primitive_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delattr(clab_ebgp.os, "O_NOFOLLOW")

    run = ContainerlabEbgpRun(FakeExecutor())

    with pytest.raises(clab_ebgp.ClabPreparationError):
        run.prepare()

    assert run.failure == ClabPreflightFailure(
        ReasonCode.LAB_ENVIRONMENT_UNAVAILABLE, stage="PREPARE", resource_mutation=False
    )
    assert not (tmp_path / ".wireproof").exists()


def test_run_root_rejects_an_existing_directory_owned_by_another_uid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".wireproof" / "runs").mkdir(parents=True)
    real_uid = os.getuid()
    monkeypatch.setattr(clab_ebgp.os, "getuid", lambda: real_uid + 1)

    with pytest.raises(clab_ebgp.ClabPreparationError):
        ContainerlabEbgpRun(FakeExecutor()).prepare()


def test_prepare_rejects_a_symlink_swapped_into_an_open_run_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "outside.conf"
    target.write_text("must remain unchanged")
    original_write = clab_ebgp._write_owned_text_at

    def swap_then_write(parent_fd: int, name: str, contents: str) -> None:
        if name == "frr.conf":
            os.symlink(target, name, dir_fd=parent_fd)
        original_write(parent_fd, name, contents)

    monkeypatch.setattr(clab_ebgp, "_write_owned_text_at", swap_then_write)
    run = ContainerlabEbgpRun(FakeExecutor())

    with pytest.raises(clab_ebgp.ClabPreparationError):
        run.prepare()

    assert target.read_text() == "must remain unchanged"
    assert run.artifact_dir is None
    assert not (tmp_path / ".wireproof" / "runs" / run.run_id).exists()


def test_uuid_collision_never_reuses_an_existing_run_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed = UUID("00000000-0000-4000-8000-000000000001")
    monkeypatch.setattr(clab_ebgp, "uuid4", lambda: fixed)
    first = ContainerlabEbgpRun(FakeExecutor())
    assert first.prepare()
    second = ContainerlabEbgpRun(FakeExecutor())

    with pytest.raises(clab_ebgp.ClabPreparationError):
        second.prepare()

    assert first.artifact_dir is not None and first.artifact_dir.exists()


def test_recovery_command_requires_the_retained_regular_topology() -> None:
    executor = FakeExecutor()
    executor.destroy_ok = False
    run = ContainerlabEbgpRun(executor)
    assert run.up() and not run.down()
    run.artifact.unlink()

    assert run.recovery_destroy_command is None


def test_recovery_command_rejects_a_symlinked_topology_after_cleanup_failure(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    executor.destroy_ok = False
    run = ContainerlabEbgpRun(executor)
    assert run.up() and not run.down()
    target = tmp_path / "malicious-topology.clab.yml"
    target.write_text("name: malicious\n")
    run.artifact.unlink()
    run.artifact.symlink_to(target)

    assert run.recovery_destroy_command is None


def test_topology_bind_uses_json_safe_yaml_string_for_quoted_repo_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    quoted_repo = tmp_path / 'repo"quote'
    quoted_repo.mkdir()
    (quoted_repo / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    (quoted_repo / ".git").mkdir()
    monkeypatch.chdir(quoted_repo)

    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.prepare()
    assert run.artifact_dir is not None
    topology = run.artifact.read_text()
    expected = json.dumps(str(run.artifact_dir / "n1" / "frr.conf") + ":/etc/frr/frr.conf:ro")
    assert expected in topology


def test_status_fails_closed_when_deployed_artifact_capability_is_missing() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    run._run_artifact = None

    assert not run.status()
    assert run.failure == ClabPreflightFailure(
        ReasonCode.STATUS_FAILED, stage="STATUS", resource_mutation=True
    )


def test_topology_replacement_blocks_status_with_closed_failure() -> None:
    executor = FakeExecutor(probes=(_peer("192.0.2.1", 65001, 65002),))
    run = ContainerlabEbgpRun(executor)
    assert run.up()
    run.artifact.unlink()
    run.artifact.write_text("name: replacement\n")

    assert not run.status()
    assert run.failure == ClabPreflightFailure(
        ReasonCode.STATUS_FAILED, stage="STATUS", resource_mutation=True
    )
    assert executor.argv == [executor.argv[0]]


def test_cleanup_never_removes_a_replaced_run_directory() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    original = run.artifact_dir.with_name(run.artifact_dir.name + "-original")
    run.artifact_dir.rename(original)
    run.artifact_dir.mkdir(mode=0o700)
    marker = run.artifact_dir / "must-not-delete"
    marker.write_text("replacement")

    assert not run.down()
    assert marker.read_text() == "replacement"
    assert original.exists()


def test_cleanup_refuses_swapped_expected_directory_and_preserves_foreign_content() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    original = run.artifact_dir / "n1"
    foreign = run.artifact_dir / "n1-foreign"
    original.rename(foreign)
    (run.artifact_dir / "n1").mkdir(mode=0o700)
    marker = run.artifact_dir / "n1" / "foreign"
    marker.write_text("do not remove")

    assert not run.down()
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert marker.read_text() == "do not remove"
    assert foreign.exists()


def test_cleanup_refuses_replaced_frr_configuration_and_preserves_tree() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    config = run.artifact_dir / "n2" / "frr.conf"
    config.unlink()
    config.write_text("foreign configuration")

    assert not run.down()
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert config.read_text() == "foreign configuration"
    assert run.artifact_dir.exists()


def test_manifest_rejects_content_change_even_when_identity_metadata_matches() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    identity = run._artifact_identity
    assert identity is not None
    forged_manifest = tuple(
        (*entry[:-1], "f" * 64) if entry[0] == ("n2", "frr.conf") else entry
        for entry in identity.manifest
    )
    forged = clab_ebgp._ArtifactIdentity(
        identity.directory_device, identity.directory_inode, forged_manifest
    )

    assert not clab_ebgp._artifact_is_intact(run.artifact_dir, forged)  # type: ignore[arg-type]
    assert run.artifact_dir is not None and run.artifact_dir.exists()


def test_fifo_replacement_fails_closed_without_blocking_or_deletion() -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    config = run.artifact_dir / "n1" / "frr.conf"
    config.unlink()
    os.mkfifo(config, mode=0o600)

    assert not run.status()
    assert not run.down()
    assert config.is_fifo()
    assert run.artifact_dir.exists()


@pytest.mark.parametrize("relative", [("foreign",), ("n1", "foreign")])
def test_cleanup_refuses_unexpected_manifest_entry_and_preserves_tree(
    relative: tuple[str, ...],
) -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    foreign = run.artifact_dir.joinpath(*relative)
    foreign.write_text("do not remove")

    assert not run.down()
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert foreign.read_text() == "do not remove"
    assert run.artifact_dir.exists()


def test_cleanup_preserves_replacement_when_final_rmdir_cannot_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = ContainerlabEbgpRun(FakeExecutor())
    assert run.up()
    assert run.artifact_dir is not None
    artifact_dir = run.artifact_dir
    original_rmdir = clab_ebgp.os.rmdir

    def replace_then_fail(
        name: str | bytes | os.PathLike[str] | os.PathLike[bytes], **kwargs: object
    ) -> None:
        if name == artifact_dir.name and kwargs.get("dir_fd") is not None:
            replacement = artifact_dir.with_name(artifact_dir.name + "-original")
            artifact_dir.rename(replacement)
            artifact_dir.mkdir(mode=0o700)
            (artifact_dir / "must-not-delete").write_text("replacement")
            raise OSError("replacement won the final-name race")
        original_rmdir(name, **kwargs)

    monkeypatch.setattr(clab_ebgp.os, "rmdir", replace_then_fail)

    assert not run.down()
    assert (artifact_dir / "must-not-delete").read_text() == "replacement"


def test_prepare_exception_has_closed_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        clab_ebgp, "_secure_run_directory", lambda *_: (_ for _ in ()).throw(OSError("secret"))
    )
    run = ContainerlabEbgpRun(FakeExecutor())

    with pytest.raises(clab_ebgp.ClabPreparationError):
        run.prepare()

    assert run.failure == ClabPreflightFailure(
        ReasonCode.LAB_ENVIRONMENT_UNAVAILABLE, stage="PREPARE", resource_mutation=False
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("containerlab", ReasonCode.LAB_CONTAINERLAB_NOT_FOUND),
        ("docker", ReasonCode.LAB_DOCKER_NOT_FOUND),
    ],
)
def test_preflight_missing_tool_is_granular(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    expected: ReasonCode,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(
        clab_ebgp.shutil,
        "which",
        lambda candidate: None if candidate == command else "/bin/tool",
    )
    result = executor.preflight()
    assert result.failure == ClabPreflightFailure(expected)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("version_nonzero", ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
        ("version_oserror", ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
        ("version_timeout", ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
        ("image_nonzero", ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED),
        ("image_oserror", ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED),
        ("image_timeout", ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED),
    ],
)
def test_preflight_command_failures_are_closed_and_coded(
    monkeypatch: pytest.MonkeyPatch, failure: str, expected: ReasonCode
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 0
        stdout = "version: 0.59.0\n"

    calls = 0

    def run(*_args: object, **_kwargs: object) -> Completed:
        nonlocal calls
        calls += 1
        is_version = calls == 1
        if failure == "version_nonzero" and is_version:
            Completed.returncode = 1
        elif failure == "image_nonzero" and not is_version:
            Completed.returncode = 1
        elif (failure == "version_oserror" and is_version) or (
            failure == "image_oserror" and not is_version
        ):
            raise OSError("secret")
        elif (failure == "version_timeout" and is_version) or (
            failure == "image_timeout" and not is_version
        ):
            raise clab_ebgp.subprocess.TimeoutExpired("secret", 1)
        return Completed()

    monkeypatch.setattr(clab_ebgp.subprocess, "run", run)
    result = executor.preflight()
    assert result.failure == ClabPreflightFailure(expected)
    assert result.stdout == ""


@pytest.mark.parametrize(
    "stderr, expected",
    [
        (
            "containerlab requires sudo privileges to run",
            ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED,
        ),
        (
            "Error: containerlab requires sudo privileges to run\n",
            ReasonCode.LAB_PRIVILEGE_UNAVAILABLE,
        ),
        ("containerlab requires sudo privileges", ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
    ],
)
def test_preflight_classifies_only_exact_containerlab_privilege_diagnostic(
    monkeypatch: pytest.MonkeyPatch, stderr: str, expected: ReasonCode
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 1
        stdout = ""

        def __init__(self) -> None:
            self.stderr = stderr

    calls = 0

    def run(*_args: object, **_kwargs: object) -> Completed:
        nonlocal calls
        calls += 1
        if calls == 1:
            result = Completed()
            result.returncode = 0
            result.stdout = "version: 0.59.0\n"
            result.stderr = ""
            return result
        if calls == 2:
            result = Completed()
            result.returncode = 0
            result.stdout = FRR_EBGP_REPO_DIGEST + "\n"
            result.stderr = ""
            return result
        return Completed()

    monkeypatch.setattr(clab_ebgp.subprocess, "run", run)
    result = executor.preflight()
    assert result.failure == ClabPreflightFailure(expected)
    assert result.stdout == ""


def test_privilege_preflight_failure_prevents_artifact_and_deploy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 1
        stdout = ""
        stderr = "Error: containerlab requires sudo privileges to run\n"

    def run(*args: object, **_kwargs: object) -> Completed:
        if args[0] == ("containerlab", "inspect", "--all"):
            return Completed()
        result = Completed()
        result.returncode = 0
        result.stderr = ""
        result.stdout = (
            "version: 0.59.0\n"
            if args[0] == ("containerlab", "version")
            else FRR_EBGP_REPO_DIGEST + "\n"
        )
        return result

    monkeypatch.setattr(clab_ebgp.subprocess, "run", run)
    executor = SubprocessContainerlabExecutor()
    run = ContainerlabEbgpRun(executor)
    assert not run.up()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_PRIVILEGE_UNAVAILABLE)
    assert run.artifact_dir is None
    assert not run.deploy_attempted


def test_preflight_inspect_uses_exact_closed_argv_and_accepts_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")
    calls: list[tuple[str, ...]] = []

    class Completed:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    responses = iter(
        (
            Completed("version: 0.59.0\n"),
            Completed(FRR_EBGP_REPO_DIGEST + "\n"),
            Completed(""),
        )
    )

    def run(argv: tuple[str, ...], **_kwargs: object) -> Completed:
        calls.append(argv)
        return next(responses)

    monkeypatch.setattr(clab_ebgp.subprocess, "run", run)
    assert executor.preflight().ok
    assert calls == [
        ("containerlab", "version"),
        (
            "docker",
            "image",
            "inspect",
            clab_ebgp.FRR_EBGP_IMAGE,
            "--format",
            "{{index .RepoDigests 0}}",
        ),
        ("containerlab", "inspect", "--all"),
    ]


def test_defensive_privilege_deploy_failure_has_no_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PrivilegeExecutor(FakeExecutor):
        def _execute(
            self,
            artifact: clab_ebgp._RunArtifact,
            operation: clab_ebgp._ContainerlabOperation,
            node: str | None = None,
        ) -> ClabResult:
            if operation is clab_ebgp._ContainerlabOperation.DEPLOY:
                return ClabResult(
                    False,
                    failure=ClabPreflightFailure(ReasonCode.LAB_PRIVILEGE_UNAVAILABLE),
                )
            return super()._execute(artifact, operation, node)

    run = ContainerlabEbgpRun(PrivilegeExecutor())
    assert not run.up()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_PRIVILEGE_UNAVAILABLE)
    assert not run.deploy_attempted
    assert run.artifact_dir is None


def test_defensive_privilege_deploy_cleanup_failure_preserves_recovery_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PrivilegeExecutor(FakeExecutor):
        def _execute(
            self,
            artifact: clab_ebgp._RunArtifact,
            operation: clab_ebgp._ContainerlabOperation,
            node: str | None = None,
        ) -> ClabResult:
            if operation is clab_ebgp._ContainerlabOperation.DEPLOY:
                return ClabResult(
                    False,
                    failure=ClabPreflightFailure(ReasonCode.LAB_PRIVILEGE_UNAVAILABLE),
                )
            return super()._execute(artifact, operation, node)

    monkeypatch.setattr(clab_ebgp, "_remove_owned_run_directory", lambda *_: False)
    run = ContainerlabEbgpRun(PrivilegeExecutor())
    assert not run.up()
    assert run.failure == ClabPreflightFailure(
        ReasonCode.CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
    )
    assert run.state is ClabEbgpState.CLEANUP_FAILED
    assert run.artifact_dir is not None and run.artifact_dir.exists()
    assert run.recovery_destroy_command is not None


@pytest.mark.parametrize(
    "output",
    [
        "",
        "Version: 0.59.0\n",
        "version: v0.59.0\n",
        "version: 0.59\n",
        "version: 0.59.0 extra\n",
        "xversion: 0.59.0\n",
        "version: 0.59.0\nversion: 0.59.0\n",
    ],
)
def test_preflight_rejects_invalid_or_ambiguous_version_banner(
    monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    monkeypatch.setattr(
        clab_ebgp.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(output),
    )
    assert executor.preflight().failure == ClabPreflightFailure(
        ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED
    )


def test_preflight_parses_real_multiline_containerlab_banner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    responses = iter(
        (
            Completed("containerlab version\n    version: 0.59.0\ncommit: abc\n"),
            Completed(FRR_EBGP_REPO_DIGEST + "\n"),
            Completed(""),
        )
    )
    monkeypatch.setattr(clab_ebgp.subprocess, "run", lambda *_args, **_kwargs: next(responses))
    assert executor.preflight() == ClabResult(
        True,
        version="0.59.0",
        platform="linux/amd64",
        repo_digest=FRR_EBGP_REPO_DIGEST,
    )


def test_preflight_parses_actual_containerlab_059_banner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    responses = iter(
        (
            Completed(
                "\x1b[1;36mcontainerlab version\x1b[0m\n    version: 0.59.0\n     commit: v0.59.0\n"
            ),
            Completed(FRR_EBGP_REPO_DIGEST + "\n"),
            Completed(""),
        )
    )
    monkeypatch.setattr(clab_ebgp.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert executor.preflight() == ClabResult(
        True,
        version="0.59.0",
        platform="linux/amd64",
        repo_digest=FRR_EBGP_REPO_DIGEST,
    )


@pytest.mark.parametrize(
    ("version_output", "digest_output", "expected"),
    [
        (
            "version: 0.58.0\n",
            FRR_EBGP_REPO_DIGEST + "\n",
            ReasonCode.LAB_CONTAINERLAB_VERSION_MISMATCH,
        ),
        (
            "version: 0.59.0\n",
            "quay.io/frrouting/frr@sha256:wrong\n",
            ReasonCode.LAB_FRR_IMAGE_REPO_DIGEST_MISMATCH,
        ),
    ],
)
def test_preflight_pin_mismatches_are_granular(
    monkeypatch: pytest.MonkeyPatch,
    version_output: str,
    digest_output: str,
    expected: ReasonCode,
) -> None:
    executor = SubprocessContainerlabExecutor()
    monkeypatch.setattr(clab_ebgp.shutil, "which", lambda _: "/bin/tool")

    class Completed:
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    responses = iter((Completed(version_output), Completed(digest_output)))
    monkeypatch.setattr(clab_ebgp.subprocess, "run", lambda *_args, **_kwargs: next(responses))
    assert executor.preflight().failure == ClabPreflightFailure(expected)


def test_bad_pin_tuple_retains_closed_failure_without_mutation() -> None:
    executor = FakeExecutor(
        preflight=ClabResult(
            True,
            version="0.58.0",
            platform="linux/amd64",
            repo_digest=FRR_EBGP_REPO_DIGEST,
        )
    )
    run = ContainerlabEbgpRun(executor)
    assert not run.prepare()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_MISMATCH)
    assert run.state is ClabEbgpState.PREPARED
    assert not run.deploy_attempted and not run.destroy_attempted and run.artifact_dir is None


@pytest.mark.parametrize("field", ["version", "platform", "repo_digest"])
def test_prepare_rejects_invalid_fake_preflight_protocol_without_mutation(field: str) -> None:
    result = ClabResult(
        True,
        version=CONTAINERLAB_VERSION,
        platform="linux/amd64",
        repo_digest=FRR_EBGP_REPO_DIGEST,
    )
    object.__setattr__(result, field, 1)
    run = ContainerlabEbgpRun(FakeExecutor(preflight=result))
    assert not run.prepare()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
    assert run.state is ClabEbgpState.PREPARED
    assert not run.deploy_attempted and not run.destroy_attempted and run.artifact_dir is None


@pytest.mark.parametrize("ok", [1, "yes", object()])
def test_prepare_rejects_non_bool_preflight_ok_without_mutation(ok: object) -> None:
    result = ClabResult(
        True,
        version=CONTAINERLAB_VERSION,
        platform="linux/amd64",
        repo_digest=FRR_EBGP_REPO_DIGEST,
    )
    object.__setattr__(result, "ok", ok)
    run = ContainerlabEbgpRun(FakeExecutor(preflight=result))

    assert not run.prepare()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
    assert run.state is ClabEbgpState.PREPARED
    assert not run.deploy_attempted and not run.destroy_attempted and run.artifact_dir is None


@pytest.mark.parametrize(
    "failure",
    [
        None,
        object(),
        ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID),
        ClabPreflightFailure(ReasonCode.LAB_PLATFORM_UNSUPPORTED, stage="DEPLOY"),
        ClabPreflightFailure(ReasonCode.LAB_PLATFORM_UNSUPPORTED, resource_mutation=True),
    ],
)
def test_prepare_rejects_invalid_preflight_failure_payload_without_mutation(
    failure: object,
) -> None:
    result = ClabResult(False, failure=failure)  # type: ignore[arg-type]
    run = ContainerlabEbgpRun(FakeExecutor(preflight=result))

    assert not run.prepare()
    assert run.failure == ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
    assert run.state is ClabEbgpState.PREPARED
    assert not run.deploy_attempted and not run.destroy_attempted and run.artifact_dir is None
