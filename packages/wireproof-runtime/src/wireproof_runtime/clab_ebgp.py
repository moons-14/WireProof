"""Closed Containerlab eBGP-v4 smoke lifecycle (CLAB-EBGP-V4-V1)."""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from wireproof_evidence import ReasonCode

FRR_EBGP_IMAGE = (
    "quay.io/frrouting/frr:10.5.4@sha256:"
    "17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
)
FRR_EBGP_REPO_DIGEST = (
    "quay.io/frrouting/frr@sha256:17a66aa754b4f60d58fae6cf3c357b62cfb574beb2a4cacd26d50e3df8440b78"
)
CONTAINERLAB_VERSION = "0.59.0"
_PROBE = "vtysh -c 'show ip bgp summary json'"
_ANSI_ESCAPE_PATTERN = r"\x1b\[[0-?]*[ -/]*[@-~]"
_CONTAINERLAB_VERSION_PATTERN = r"(?m)^[\t ]*version:[\t ]*([0-9]+\.[0-9]+\.[0-9]+)[\t ]*$"
_PREFLIGHT_FAILURE_CODES = frozenset(
    {
        ReasonCode.LAB_PLATFORM_UNSUPPORTED,
        ReasonCode.LAB_CONTAINERLAB_NOT_FOUND,
        ReasonCode.LAB_DOCKER_NOT_FOUND,
        ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED,
        ReasonCode.LAB_PRIVILEGE_UNAVAILABLE,
        ReasonCode.LAB_CONTAINERLAB_VERSION_MISMATCH,
        ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED,
        ReasonCode.LAB_FRR_IMAGE_REPO_DIGEST_MISMATCH,
    }
)


class ClabEbgpState(StrEnum):
    PREPARED = "PREPARED"
    DEPLOYED = "DEPLOYED"
    VERIFIED = "VERIFIED"
    CLEANED = "CLEANED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


class ClabPreparationError(RuntimeError):
    """The run-owned Containerlab artifact could not be constructed."""


_ManifestEntry = tuple[tuple[str, ...], int, int, int, int, int, str]


@dataclass(frozen=True)
class _ArtifactIdentity:
    """Immutable, complete private-tree manifest minted after artifact creation."""

    directory_device: int
    directory_inode: int
    manifest: tuple[_ManifestEntry, ...] = ()


_MANIFEST_LAYOUT = (
    (("n1",), stat.S_IFDIR),
    (("n1", "frr.conf"), stat.S_IFREG),
    (("n2",), stat.S_IFDIR),
    (("n2", "frr.conf"), stat.S_IFREG),
    (("topology.clab.yml",), stat.S_IFREG),
)


def _validated_directory(path: Path) -> None:
    """Accept only a real directory owned by this user, never a link."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ClabPreparationError("run root is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ClabPreparationError("run root is unsafe")


_REQUIRED_DIR_FD_OPERATIONS = (os.open, os.mkdir, os.stat, os.rmdir, os.unlink)


def _require_safe_filesystem_primitives() -> None:
    """Refuse artifact mutation unless descriptor-relative safety is available."""
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or any(operation not in os.supports_dir_fd for operation in _REQUIRED_DIR_FD_OPERATIONS)
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ClabPreparationError("safe filesystem primitives are unavailable")


def _directory_flags() -> int:
    _require_safe_filesystem_primitives()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_directory_at(parent_fd: int, name: str, *, private: bool = True) -> int:
    """Open an owned directory without ever resolving a link in that component."""
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
        info = os.fstat(descriptor)
    except OSError as exc:
        raise ClabPreparationError("run root is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or (
        private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700)
    ):
        os.close(descriptor)
        raise ClabPreparationError("run root is unsafe")
    return descriptor


def _open_directory_path(path: Path, *, private: bool = False) -> int:
    """Traverse an absolute directory one no-follow component at a time."""
    if not path.is_absolute():
        raise ClabPreparationError("repository root is invalid")
    descriptor = os.open("/", _directory_flags())
    try:
        for component in path.parts[1:]:
            next_descriptor = _open_directory_at(descriptor, component, private=private)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _ensure_private_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ClabPreparationError("run root is unavailable") from exc
    return _open_directory_at(parent_fd, name)


def _write_owned_text_at(parent_fd: int, name: str, contents: str) -> None:
    _require_safe_filesystem_primitives()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(contents)
    except OSError as exc:
        raise ClabPreparationError("failed to construct Containerlab artifact") from exc


def _open_run_directory(run_dir: Path) -> int:
    """Re-open a minted run only through its private, no-follow ancestors."""
    repo_fd = _open_directory_path(run_dir.parents[2])
    try:
        wireproof_fd = _open_directory_at(repo_fd, ".wireproof")
        try:
            runs_fd = _open_directory_at(wireproof_fd, "runs")
            try:
                return _open_directory_at(runs_fd, run_dir.name)
            finally:
                os.close(runs_fd)
        finally:
            os.close(wireproof_fd)
    finally:
        os.close(repo_fd)


def _artifact_identity(run_dir: Path, *, require_topology: bool = True) -> _ArtifactIdentity:
    """Mint or validate a complete no-follow manifest for the private artifact."""
    run_fd = _open_run_directory(run_dir)
    try:
        directory = os.fstat(run_fd)
        if not require_topology:
            return _ArtifactIdentity(directory.st_dev, directory.st_ino)
        manifest = _read_artifact_manifest(run_fd)
    finally:
        os.close(run_fd)
    return _ArtifactIdentity(directory.st_dev, directory.st_ino, manifest)


def _read_artifact_manifest(run_fd: int) -> tuple[_ManifestEntry, ...]:
    """Require the minted layout and bind regular files by content and mode."""
    expected_root = {"n1", "n2", "topology.clab.yml"}
    try:
        if {entry.name for entry in os.scandir(run_fd)} != expected_root:
            raise ClabPreparationError("run artifact is unsafe")
        manifest: list[_ManifestEntry] = []
        for components, expected_kind in _MANIFEST_LAYOUT:
            parent_fd = run_fd
            opened: list[int] = []
            try:
                for component in components[:-1]:
                    child_fd = _open_directory_at(parent_fd, component)
                    opened.append(child_fd)
                    parent_fd = child_fd
                name = components[-1]
                if expected_kind == stat.S_IFDIR:
                    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if stat.S_IFMT(info.st_mode) != expected_kind:
                        raise ClabPreparationError("run artifact is unsafe")
                    child_fd = _open_directory_at(parent_fd, name)
                    try:
                        if {entry.name for entry in os.scandir(child_fd)} != {"frr.conf"}:
                            raise ClabPreparationError("run artifact is unsafe")
                    finally:
                        os.close(child_fd)
                    manifest.append(
                        (
                            components,
                            expected_kind,
                            info.st_dev,
                            info.st_ino,
                            0,
                            stat.S_IMODE(info.st_mode),
                            "",
                        )
                    )
                else:
                    # Bind the bytes through the descriptor that is validated immediately
                    # before status/probe/cleanup; path metadata alone is not sufficient.
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=parent_fd,
                    )
                    try:
                        opened_info = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened_info.st_mode)
                            or stat.S_IMODE(opened_info.st_mode) != 0o600
                        ):
                            raise ClabPreparationError("run artifact is unsafe")
                        digest = hashlib.sha256()
                        size = 0
                        while chunk := os.read(descriptor, 1024 * 1024):
                            digest.update(chunk)
                            size += len(chunk)
                    finally:
                        os.close(descriptor)
                    manifest.append(
                        (
                            components,
                            expected_kind,
                            opened_info.st_dev,
                            opened_info.st_ino,
                            size,
                            stat.S_IMODE(opened_info.st_mode),
                            digest.hexdigest(),
                        )
                    )
            finally:
                for descriptor in reversed(opened):
                    os.close(descriptor)
        return tuple(manifest)
    except OSError as exc:
        raise ClabPreparationError("run artifact is unavailable") from exc


def _artifact_is_intact(run_dir: Path, identity: _ArtifactIdentity) -> bool:
    if not identity.manifest:
        return False
    try:
        return _artifact_identity(run_dir) == identity
    except ClabPreparationError:
        return False


def _remove_owned_run_directory(run_dir: Path, identity: _ArtifactIdentity) -> bool:
    """Remove only the exact minted root, never a replacement at its pathname."""
    try:
        repo_fd = _open_directory_path(run_dir.parents[2])
        try:
            wireproof_fd = _open_directory_at(repo_fd, ".wireproof")
            try:
                runs_fd = _open_directory_at(wireproof_fd, "runs")
                try:
                    info = os.stat(run_dir.name, dir_fd=runs_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o700
                        or (info.st_dev, info.st_ino)
                        != (identity.directory_device, identity.directory_inode)
                    ):
                        return False
                    run_fd = _open_directory_at(runs_fd, run_dir.name)
                    try:
                        opened = os.fstat(run_fd)
                        if (opened.st_dev, opened.st_ino) != (
                            identity.directory_device,
                            identity.directory_inode,
                        ):
                            return False
                        if identity.manifest:
                            if _read_artifact_manifest(run_fd) != identity.manifest:
                                return False
                            _remove_manifest_entries(run_fd)
                        else:
                            _remove_incomplete_artifact_entries(run_fd)
                    finally:
                        os.close(run_fd)
                    # The private parent descriptor pins all ancestors; final removal
                    # remains descriptor-relative and is refused on any syscall error.
                    final = os.stat(run_dir.name, dir_fd=runs_fd, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(final.st_mode)
                        or final.st_uid != os.getuid()
                        or stat.S_IMODE(final.st_mode) != 0o700
                        or (final.st_dev, final.st_ino)
                        != (identity.directory_device, identity.directory_inode)
                    ):
                        return False
                    os.rmdir(run_dir.name, dir_fd=runs_fd)
                    return True
                finally:
                    os.close(runs_fd)
            finally:
                os.close(wireproof_fd)
        finally:
            os.close(repo_fd)
    except (ClabPreparationError, OSError):
        return False


def _remove_manifest_entries(run_fd: int) -> None:
    """Delete only the validated immutable manifest; never discover descendants."""
    for directory in ("n1", "n2"):
        directory_fd = _open_directory_at(run_fd, directory)
        try:
            os.unlink("frr.conf", dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        os.rmdir(directory, dir_fd=run_fd)
    os.unlink("topology.clab.yml", dir_fd=run_fd)


def _remove_incomplete_artifact_entries(run_fd: int) -> None:
    """Discard an unminted construction attempt through its fixed, closed layout."""
    names = {entry.name for entry in os.scandir(run_fd)}
    if not names <= {"n1", "n2", "topology.clab.yml"}:
        raise ClabPreparationError("run artifact is unsafe")
    for directory in ("n1", "n2"):
        if directory not in names:
            continue
        directory_fd = _open_directory_at(run_fd, directory)
        try:
            children = {entry.name for entry in os.scandir(directory_fd)}
            if not children <= {"frr.conf"}:
                raise ClabPreparationError("run artifact is unsafe")
            if "frr.conf" in children:
                os.unlink("frr.conf", dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        os.rmdir(directory, dir_fd=run_fd)
    if "topology.clab.yml" in names:
        os.unlink("topology.clab.yml", dir_fd=run_fd)


def _secure_run_directory(run_id: str) -> Path:
    """Create one private run directory below the current repository's fixed root."""
    try:
        repo = Path.cwd().resolve(strict=True)
    except OSError as exc:
        raise ClabPreparationError("repository root is unavailable") from exc
    repo_fd = _open_directory_path(repo)
    try:
        try:
            pyproject = os.stat("pyproject.toml", dir_fd=repo_fd, follow_symlinks=False)
            git_marker = os.stat(".git", dir_fd=repo_fd, follow_symlinks=False)
        except OSError as exc:
            raise ClabPreparationError("repository root is invalid") from exc
        if not stat.S_ISREG(pyproject.st_mode) or not (
            stat.S_ISREG(git_marker.st_mode) or stat.S_ISDIR(git_marker.st_mode)
        ):
            raise ClabPreparationError("repository root is invalid")
        wireproof_fd = _ensure_private_directory(repo_fd, ".wireproof")
        try:
            runs_fd = _ensure_private_directory(wireproof_fd, "runs")
            try:
                try:
                    os.mkdir(run_id, mode=0o700, dir_fd=runs_fd)
                except FileExistsError as exc:
                    raise ClabPreparationError("run directory collision") from exc
                run_fd = _open_directory_at(runs_fd, run_id)
                os.close(run_fd)
            finally:
                os.close(runs_fd)
        finally:
            os.close(wireproof_fd)
    finally:
        os.close(repo_fd)
    return repo / ".wireproof" / "runs" / run_id


def _write_owned_text(path: Path, contents: str) -> None:
    """Write a new private artifact without following or replacing a filesystem entry."""
    _require_safe_filesystem_primitives()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(contents)
    except OSError as exc:
        raise ClabPreparationError("failed to construct Containerlab artifact") from exc


@dataclass(frozen=True)
class ClabPreflightFailure:
    code: ReasonCode
    stage: str = "PREFLIGHT"
    resource_mutation: bool = False


class _ContainerlabOperation(StrEnum):
    DEPLOY = "deploy"
    DESTROY = "destroy"
    PROBE = "probe"


@dataclass(frozen=True)
class ClabResult:
    ok: bool
    stdout: str = ""
    version: str | None = None
    platform: str | None = None
    repo_digest: str | None = None
    failure: ClabPreflightFailure | None = None


@dataclass(frozen=True)
class _RunArtifact:
    """Private capability minted only after this run's artifact is complete."""

    topology: Path
    lab_name: str
    identity: _ArtifactIdentity | None = field(default=None, repr=False, compare=False)
    _capability: object = field(default_factory=object, repr=False, compare=False)

    def argv(self, operation: _ContainerlabOperation, node: str | None = None) -> tuple[str, ...]:
        if operation is _ContainerlabOperation.DEPLOY:
            return ("containerlab", "deploy", "--topo", str(self.topology), "--name", self.lab_name)
        if operation is _ContainerlabOperation.DESTROY:
            return (
                "containerlab",
                "destroy",
                "--topo",
                str(self.topology),
                "--name",
                self.lab_name,
                "--cleanup",
            )
        if operation is _ContainerlabOperation.PROBE and node in {"n1", "n2"}:
            return (
                "containerlab",
                "exec",
                "--topo",
                str(self.topology),
                "--name",
                self.lab_name,
                "--node",
                node,
                "--cmd",
                _PROBE,
            )
        raise ValueError("closed Containerlab operation is invalid")


class ContainerlabExecutor(Protocol):
    def preflight(self) -> ClabResult: ...

    def _mint_run_artifact(self, topology: Path, lab_name: str) -> _RunArtifact: ...

    def _execute(
        self, artifact: _RunArtifact, operation: _ContainerlabOperation, node: str | None = None
    ) -> ClabResult: ...


@dataclass
class SubprocessContainerlabExecutor:
    """The real executor has no caller-controlled command surface."""

    timeout_seconds: float = 60.0
    _registered_artifacts: dict[int, object] = field(default_factory=dict, init=False, repr=False)

    def _mint_run_artifact(self, topology: Path, lab_name: str) -> _RunArtifact:
        artifact = _RunArtifact(topology, lab_name)
        self._registered_artifacts[id(artifact)] = artifact._capability
        return artifact

    def preflight(self) -> ClabResult:
        machine = host_platform.machine().lower()
        if host_platform.system() != "Linux" or machine not in {"x86_64", "amd64"}:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_PLATFORM_UNSUPPORTED),
            )
        if os.geteuid() != 0:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_PRIVILEGE_UNAVAILABLE),
            )
        if shutil.which("containerlab") is None:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_NOT_FOUND),
            )
        if shutil.which("docker") is None:
            return ClabResult(False, failure=ClabPreflightFailure(ReasonCode.LAB_DOCKER_NOT_FOUND))
        try:
            version = subprocess.run(
                ("containerlab", "version"),
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
            )
        if version.returncode != 0:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
            )
        version_stdout = re.sub(_ANSI_ESCAPE_PATTERN, "", version.stdout)
        matches = re.findall(_CONTAINERLAB_VERSION_PATTERN, version_stdout)
        if len(matches) != 1:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
            )
        if matches[0] != CONTAINERLAB_VERSION:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_MISMATCH),
            )
        try:
            image = subprocess.run(
                (
                    "docker",
                    "image",
                    "inspect",
                    FRR_EBGP_IMAGE,
                    "--format",
                    "{{index .RepoDigests 0}}",
                ),
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED),
            )
        if image.returncode != 0:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_FRR_IMAGE_INSPECT_FAILED),
            )
        repo_digest = image.stdout.strip()
        if repo_digest != FRR_EBGP_REPO_DIGEST:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_FRR_IMAGE_REPO_DIGEST_MISMATCH),
            )
        try:
            inspect = subprocess.run(
                ("containerlab", "inspect", "--all"),
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
            )
        if inspect.returncode != 0:
            return ClabResult(
                False,
                failure=ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_CHECK_FAILED),
            )
        return ClabResult(
            True,
            version=matches[0],
            platform="linux/amd64",
            repo_digest=repo_digest,
        )

    def _execute(
        self, artifact: _RunArtifact, operation: _ContainerlabOperation, node: str | None = None
    ) -> ClabResult:
        if (
            not isinstance(artifact, _RunArtifact)
            or not isinstance(operation, _ContainerlabOperation)
            or self._registered_artifacts.get(id(artifact)) is not artifact._capability
        ):
            return ClabResult(False)
        if artifact.identity is None or not _artifact_is_intact(
            artifact.topology.parent, artifact.identity
        ):
            return ClabResult(False)
        try:
            argv = artifact.argv(operation, node)
        except ValueError:
            return ClabResult(False)
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, check=False, timeout=self.timeout_seconds
            )
        except (OSError, subprocess.TimeoutExpired):
            return ClabResult(False)
        return ClabResult(completed.returncode == 0, completed.stdout)


def _frr(local: str, peer: str, asn: int, peer_as: int, router_id: str) -> str:
    return f"""frr defaults traditional
service integrated-vtysh-config
!
interface eth1
 ip address {local}/31
!
router bgp {asn}
 bgp router-id {router_id}
 neighbor {peer} remote-as {peer_as}
!
"""


@dataclass
class ContainerlabEbgpRun:
    _executor: ContainerlabExecutor
    run_id: str = field(default_factory=lambda: str(uuid4()), init=False)
    lab_name: str = field(default_factory=lambda: f"wp-ebgp-{uuid4()}", init=False)
    artifact_dir: Path | None = field(default=None, init=False)
    _run_artifact: _RunArtifact | None = field(default=None, init=False, repr=False)
    _artifact_identity: _ArtifactIdentity | None = field(default=None, init=False, repr=False)
    deploy_attempted: bool = field(default=False, init=False)
    destroy_attempted: bool = field(default=False, init=False)
    state: ClabEbgpState = field(default=ClabEbgpState.PREPARED, init=False)
    resolved_repo_digest: str | None = field(default=None, init=False)
    failure: ClabPreflightFailure | None = field(default=None, init=False)

    def prepare(self) -> bool:
        if self._run_artifact is not None:
            return True
        check = self._executor.preflight()
        if not isinstance(check, ClabResult):
            self.failure = ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
            return False
        if type(check.ok) is not bool:
            self.failure = ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
            return False
        if not check.ok:
            if not (
                isinstance(check.failure, ClabPreflightFailure)
                and check.failure.stage == "PREFLIGHT"
                and check.failure.resource_mutation is False
                and check.failure.code in _PREFLIGHT_FAILURE_CODES
            ):
                self.failure = ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
            else:
                self.failure = check.failure
            return False
        if check.failure is not None or not all(
            isinstance(value, str) for value in (check.version, check.platform, check.repo_digest)
        ):
            self.failure = ClabPreflightFailure(ReasonCode.LAB_PREFLIGHT_PROTOCOL_INVALID)
            return False
        if check.platform != "linux/amd64":
            self.failure = ClabPreflightFailure(ReasonCode.LAB_PLATFORM_UNSUPPORTED)
            return False
        if check.version != CONTAINERLAB_VERSION:
            self.failure = ClabPreflightFailure(ReasonCode.LAB_CONTAINERLAB_VERSION_MISMATCH)
            return False
        if check.repo_digest != FRR_EBGP_REPO_DIGEST:
            self.failure = ClabPreflightFailure(ReasonCode.LAB_FRR_IMAGE_REPO_DIGEST_MISMATCH)
            return False
        self.failure = None
        self.resolved_repo_digest = check.repo_digest
        identity: _ArtifactIdentity | None = None
        try:
            _require_safe_filesystem_primitives()
            artifact_dir = _secure_run_directory(self.run_id)
            self.artifact_dir = artifact_dir
            identity = _artifact_identity(artifact_dir, require_topology=False)
            run_fd = _open_run_directory(artifact_dir)
            try:
                n1_fd = _ensure_private_directory(run_fd, "n1")
                n2_fd = _ensure_private_directory(run_fd, "n2")
                try:
                    _write_owned_text_at(
                        n1_fd, "frr.conf", _frr("192.0.2.0", "192.0.2.1", 65001, 65002, "1.1.1.1")
                    )
                    _write_owned_text_at(
                        n2_fd, "frr.conf", _frr("192.0.2.1", "192.0.2.0", 65002, 65001, "2.2.2.2")
                    )
                finally:
                    os.close(n1_fd)
                    os.close(n2_fd)
                _write_owned_text_at(run_fd, "topology.clab.yml", self._topology())
            finally:
                os.close(run_fd)
            topology = artifact_dir / "topology.clab.yml"
            if topology.parent != artifact_dir or not topology.is_relative_to(artifact_dir):
                raise ClabPreparationError("run artifact escaped its directory")
            identity = _artifact_identity(artifact_dir)
            self._run_artifact = self._executor._mint_run_artifact(topology, self.lab_name)
            object.__setattr__(self._run_artifact, "identity", identity)
            self._artifact_identity = identity
        except Exception as exc:
            cleanup_dir = self.artifact_dir
            if cleanup_dir is not None and identity is None:
                try:
                    identity = _artifact_identity(cleanup_dir, require_topology=False)
                except ClabPreparationError:
                    pass
            if cleanup_dir is not None and identity is not None:
                _remove_owned_run_directory(cleanup_dir, identity)
            self.artifact_dir = None
            self._run_artifact = None
            self._artifact_identity = None
            self.failure = ClabPreflightFailure(
                ReasonCode.LAB_ENVIRONMENT_UNAVAILABLE, stage="PREPARE", resource_mutation=False
            )
            raise ClabPreparationError("failed to construct Containerlab artifact") from exc
        return True

    def _topology(self) -> str:
        if self.artifact_dir is None:
            raise ClabPreparationError("run artifact is unavailable")
        return f"""name: {self.lab_name}
topology:
  nodes:
    n1:
      kind: linux
      image: {FRR_EBGP_IMAGE}
      restart-policy: no
      image-pull-policy: IfNotPresent
      binds: [{json.dumps(str(self.artifact_dir / "n1" / "frr.conf") + ":/etc/frr/frr.conf:ro")}]
    n2:
      kind: linux
      image: {FRR_EBGP_IMAGE}
      restart-policy: no
      image-pull-policy: IfNotPresent
      binds: [{json.dumps(str(self.artifact_dir / "n2" / "frr.conf") + ":/etc/frr/frr.conf:ro")}]
  links:
    - endpoints: [\"n1:eth1\", \"n2:eth1\"]
"""

    @property
    def artifact(self) -> Path:
        if self._run_artifact is None:
            raise RuntimeError("artifact not prepared")
        return self._run_artifact.topology

    @property
    def recovery_destroy_command(self) -> tuple[str, ...] | None:
        if self.state is not ClabEbgpState.CLEANUP_FAILED or self._run_artifact is None:
            return None
        if self.artifact_dir is None or self._run_artifact.topology.parent != self.artifact_dir:
            return None
        if self._artifact_identity is None or not _artifact_is_intact(
            self.artifact_dir, self._artifact_identity
        ):
            return None
        return self._run_artifact.argv(_ContainerlabOperation.DESTROY)

    def up(self) -> bool:
        if self.state is not ClabEbgpState.PREPARED or not self.prepare():
            return False
        if self._run_artifact is None:
            self.failure = ClabPreflightFailure(
                ReasonCode.DEPLOY_FAILED, stage="DEPLOY", resource_mutation=True
            )
            return False
        if (
            self._artifact_identity is None
            or self.artifact_dir is None
            or not _artifact_is_intact(self.artifact_dir, self._artifact_identity)
        ):
            self.failure = ClabPreflightFailure(
                ReasonCode.DEPLOY_FAILED, stage="DEPLOY", resource_mutation=True
            )
            return False
        deploy_result = self._executor._execute(self._run_artifact, _ContainerlabOperation.DEPLOY)
        # Cleanup is required even when the closed deploy command reports failure.
        self.deploy_attempted = True
        if not deploy_result.ok:
            deploy_failure = ClabPreflightFailure(
                ReasonCode.DEPLOY_FAILED, stage="DEPLOY", resource_mutation=True
            )
            self.failure = deploy_failure
            if self.down():
                self.failure = deploy_failure
            return False
        self.state = ClabEbgpState.DEPLOYED
        return True

    def status(self) -> bool:
        if self.state is not ClabEbgpState.DEPLOYED:
            return False
        if self._run_artifact is None:
            self.failure = ClabPreflightFailure(
                ReasonCode.STATUS_FAILED, stage="STATUS", resource_mutation=True
            )
            return False
        for node, peer, local_as, remote_as in (
            ("n1", "192.0.2.1", 65001, 65002),
            ("n2", "192.0.2.0", 65002, 65001),
        ):
            if (
                self._artifact_identity is None
                or self.artifact_dir is None
                or not _artifact_is_intact(self.artifact_dir, self._artifact_identity)
            ):
                self.failure = ClabPreflightFailure(
                    ReasonCode.STATUS_FAILED, stage="STATUS", resource_mutation=True
                )
                return False
            result = self._executor._execute(self._run_artifact, _ContainerlabOperation.PROBE, node)
            if not result.ok or not _established(result.stdout, peer, local_as, remote_as):
                self.failure = ClabPreflightFailure(
                    ReasonCode.STATUS_FAILED, stage="STATUS", resource_mutation=True
                )
                return False
        self.state = ClabEbgpState.VERIFIED
        return True

    def down(self) -> bool:
        if self.state is ClabEbgpState.CLEANED:
            return True
        if not self.deploy_attempted:
            return False
        if self.destroy_attempted:
            return False
        self.destroy_attempted = True
        if self._run_artifact is None:
            self.state = ClabEbgpState.CLEANUP_FAILED
            self.failure = ClabPreflightFailure(
                ReasonCode.CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
            )
            return False
        if (
            self._artifact_identity is None
            or self.artifact_dir is None
            or not _artifact_is_intact(self.artifact_dir, self._artifact_identity)
        ):
            self.state = ClabEbgpState.CLEANUP_FAILED
            self.failure = ClabPreflightFailure(
                ReasonCode.CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
            )
            return False
        destroyed = self._executor._execute(self._run_artifact, _ContainerlabOperation.DESTROY).ok
        if not destroyed:
            self.state = ClabEbgpState.CLEANUP_FAILED
            self.failure = ClabPreflightFailure(
                ReasonCode.CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
            )
            return False
        artifact_dir = self.artifact_dir
        identity = self._artifact_identity
        if (
            artifact_dir is None
            or identity is None
            or not _remove_owned_run_directory(artifact_dir, identity)
        ):
            self.state = ClabEbgpState.CLEANUP_FAILED
            self.failure = ClabPreflightFailure(
                ReasonCode.LAB_ARTIFACT_CLEANUP_FAILED, stage="CLEANUP", resource_mutation=True
            )
            return False
        self.state = ClabEbgpState.CLEANED
        self.failure = None
        return True


def _established(stdout: str, peer: str, local_as: int, remote_as: int) -> bool:
    try:
        data = json.loads(stdout)
        p = data["peers"][peer]
        return (
            p["state"] == "Established"
            and p["peerState"] == "OK"
            and int(p["localAs"]) == local_as
            and int(p["remoteAs"]) == remote_as
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


# Compatibility spelling kept internal to this closed smoke adapter.
ClabEbgpRun = ContainerlabEbgpRun
