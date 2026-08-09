import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import wireproof_cli.static_verify as static_verify_module
import yaml
from typer.testing import CliRunner
from wireproof_cli.main import app
from wireproof_evidence import EvidenceBundle

PLAN = Path("examples/evpn-fabric.yaml")
UNSAFE_TEST_FILESYSTEM_REASON = (
    "unsafe test filesystem ownership; descriptor policy covered by unit tests"
)


def _real_ancestors_are_safe(
    path: Path,
    *,
    stat_fn: Callable[[Path], Any] = os.stat,
    effective_uid: int | None = None,
) -> bool:
    """Check real ancestors only to decide whether an integration test is available."""
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate = Path(os.path.abspath(candidate))
    uid = os.geteuid() if effective_uid is None else effective_uid
    while True:
        try:
            info = stat_fn(candidate)
        except FileNotFoundError:
            pass
        else:
            owner_is_trusted = info.st_uid in {uid, 0}
            writable_by_untrusted = info.st_mode & 0o022
            sticky_trusted = bool(info.st_mode & stat.S_ISVTX) and owner_is_trusted
            if not owner_is_trusted or (writable_by_untrusted and not sticky_trusted):
                return False
        if candidate == Path(candidate.anchor):
            return True
        candidate = candidate.parent


def _skip_if_unsafe_test_filesystem(path: Path) -> None:
    if not _real_ancestors_are_safe(path):
        pytest.skip(UNSAFE_TEST_FILESYSTEM_REASON)


def _invoke(tmp_path: Path, *args: str):
    return CliRunner().invoke(
        app, ["verify", "static", str(PLAN), "--evidence-root", str(tmp_path), *args]
    )


def test_static_verify_baseline_persists_an_incomplete_bundle(tmp_path: Path) -> None:
    _skip_if_unsafe_test_filesystem(tmp_path)
    result = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert envelope["static"]["status"] == "PASS"
    assert envelope["runtime"] == {
        "status": "UNEXECUTED",
        "reason": "unexecuted_by_static_command",
    }
    assert envelope["promotion_eligible"] is False
    assert envelope["bundle"]["structural_findings"]
    assert {item["check_id"] for item in envelope["bundle"]["structural_findings"]} >= {
        "runtime-e2e"
    }
    persisted = tmp_path / envelope["bundle"]["path"]
    bundle = json.loads(persisted.read_text())
    assert bundle["payload"]["records"][1] == {
        "check_id": "runtime-e2e",
        "phase": "target",
        "result": "UNKNOWN",
        "reason": "unexecuted_by_static_command",
    }
    assert all("=" in item and "/" not in item for item in envelope["provenance"])


def test_static_verify_default_relative_root_persists_from_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    plan_path = PLAN.resolve()
    monkeypatch.chdir(tmp_path)
    persisted: list[tuple[Path, EvidenceBundle]] = []

    def save(root: Path, bundle: EvidenceBundle) -> Path:
        persisted.append((root, bundle))
        return root / f"{bundle.canonical_hash}.json"

    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(static_verify_module, "persist_bundle", save)
    result = CliRunner().invoke(app, ["verify", "static", str(plan_path)])

    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert persisted[0][0] == tmp_path / "evidence"
    assert envelope["bundle"]["path"] == f"{persisted[0][1].canonical_hash}.json"
    assert persisted[0][1].payload.records[1].result.value == "UNKNOWN"


def test_static_verify_creates_a_fresh_absolute_evidence_root(tmp_path: Path) -> None:
    _skip_if_unsafe_test_filesystem(tmp_path)
    root = tmp_path / "fresh" / "evidence"
    root.parent.mkdir(mode=0o700)
    result = _invoke(root)

    assert result.exit_code == 0, result.output
    assert root.stat().st_mode & 0o777 == 0o700
    assert len(list(root.glob("*.json"))) == 1


@pytest.mark.parametrize("owner", [1000, 0])
def test_real_ancestors_accepts_trusted_or_root_owner(owner: int) -> None:
    info = type("Stat", (), {"st_uid": owner, "st_mode": stat.S_IFDIR | 0o755})()
    assert _real_ancestors_are_safe(
        Path("/trusted/child"), stat_fn=lambda _: info, effective_uid=1000
    )


def test_real_ancestors_rejects_foreign_owner() -> None:
    info = type("Stat", (), {"st_uid": 2000, "st_mode": stat.S_IFDIR | 0o755})()
    assert not _real_ancestors_are_safe(
        Path("/foreign/child"), stat_fn=lambda _: info, effective_uid=1000
    )


def test_static_verify_relative_root_keeps_malformed_fixture_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    plan_path = PLAN.resolve()
    fixture = tmp_path / "bad.yaml"
    fixture.write_text(yaml.safe_dump({"mutation": "wrong_rt"}), encoding="utf-8")
    (tmp_path / "evidence").mkdir(mode=0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(
        static_verify_module,
        "persist_bundle",
        lambda root, bundle: root / f"{bundle.canonical_hash}.json",
    )
    result = CliRunner().invoke(
        app,
        [
            "verify",
            "static",
            str(plan_path),
            "--fixture",
            str(fixture),
            "--evidence-root",
            "evidence",
        ],
    )

    assert result.exit_code == 2, result.output
    envelope = json.loads(result.output)
    assert envelope["bundle"]["path"].endswith(".json")


def test_static_verify_rejects_symlinked_evidence_root_without_writing_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "evidence-link"
    link.symlink_to(target, target_is_directory=True)

    result = _invoke(link)

    assert result.exit_code == 74, result.output
    envelope = json.loads(result.output)
    assert envelope == {
        "status": "UNKNOWN",
        "diagnostic": "evidence persistence failed: ValueError",
    }
    assert not list(target.iterdir())


def test_static_verify_unsupported_persistence_is_closed(tmp_path: Path, monkeypatch) -> None:
    def unsupported(*_args, **_kwargs):
        raise static_verify_module.UnsupportedPlatformError("descriptor unavailable")

    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(static_verify_module, "persist_bundle", unsupported)
    result = _invoke(tmp_path)

    assert result.exit_code == 74, result.output
    assert json.loads(result.output) == {
        "status": "UNKNOWN",
        "diagnostic": "evidence persistence failed: UnsupportedPlatformError",
    }
    assert not list(tmp_path.iterdir())


def test_static_verify_wrong_rt_is_static_fail(tmp_path: Path, monkeypatch) -> None:
    # Keep static-result coverage independent of host ancestry ownership.
    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(
        static_verify_module,
        "persist_bundle",
        lambda root, bundle: root / f"{bundle.canonical_hash}.json",
    )
    result = _invoke(tmp_path, "--fixture", "tests/fixtures/wrong-rt.yaml")
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["static"]["status"] == "FAIL"


def test_static_verify_compiles_the_plan_once(tmp_path: Path, monkeypatch) -> None:
    calls = 0
    original = static_verify_module.compile_plan

    def counted(plan):
        nonlocal calls
        calls += 1
        return original(plan)

    monkeypatch.setattr(static_verify_module, "compile_plan", counted)
    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(
        static_verify_module,
        "persist_bundle",
        lambda root, bundle: root / f"{bundle.canonical_hash}.json",
    )
    result = _invoke(tmp_path, "--fixture", "tests/fixtures/wrong-rt.yaml")
    assert result.exit_code == 1, result.output
    assert calls == 1


def test_static_verify_malformed_fixture_is_unknown_and_persisted(
    tmp_path: Path, monkeypatch
) -> None:
    fixture = tmp_path / "bad.yaml"
    fixture.write_text(yaml.safe_dump({"mutation": "wrong_rt"}), encoding="utf-8")
    monkeypatch.setattr(static_verify_module, "ensure_safe_evidence_root", lambda _: None)
    monkeypatch.setattr(
        static_verify_module,
        "persist_bundle",
        lambda root, bundle: root / f"{bundle.canonical_hash}.json",
    )
    result = _invoke(tmp_path, "--fixture", str(fixture))
    assert result.exit_code == 2, result.output
    envelope = json.loads(result.output)
    assert envelope["static"]["status"] == "UNKNOWN"
    assert envelope["bundle"]["path"].endswith(".json")


def test_static_verify_rejects_malformed_plan_without_bundle(tmp_path: Path) -> None:
    plan = tmp_path / "bad-plan.yaml"
    plan.write_text("not: a valid contract", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["verify", "static", str(plan), "--evidence-root", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "bundle" not in json.loads(result.output)
    assert not list(tmp_path.glob("*.json"))
