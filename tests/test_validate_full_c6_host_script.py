"""Tests for the repository-only strict artifact validation command."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest


def _load_validation_script() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "validate-artifact-contract-host.py"
    )
    spec = importlib.util.spec_from_file_location(
        "rextio_artifact_contract_host_validation",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATION_SCRIPT = _load_validation_script()


def test_manual_validation_public_surface_uses_semantic_artifact_terms() -> None:
    script_path = Path(VALIDATION_SCRIPT.__file__).resolve()
    source = script_path.read_text(encoding="utf-8")
    help_text = VALIDATION_SCRIPT._parser().format_help()

    assert script_path.name == "validate-artifact-contract-host.py"
    assert "REXTIO_ARTIFACT_CONTRACT_E2E" in source
    assert "REXTIO_ARTIFACT_CONTRACT_WHEEL" in source
    assert "REXTIO_FULL_C6" not in source
    assert "Full C6" not in help_text
    assert "C5" not in help_text
    assert "C6" not in help_text


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _clean_repository(root: Path) -> Path:
    repository = root / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "artifact-test@example.invalid")
    _git(repository, "config", "user.name", "Artifact contract test")
    (repository / ".gitignore").write_text("build/\ndist/\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("tracked HEAD bytes\n", encoding="utf-8")
    executable = repository / "tracked-tool"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    _git(repository, "add", ".gitignore", "tracked.txt", "tracked-tool")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository


def test_stage_tracked_head_uses_clean_snapshot_without_touching_ignored_builds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _clean_repository(tmp_path)
    stale_build = repository / "build" / "lib" / "stale.py"
    stale_build.parent.mkdir(parents=True)
    stale_build.write_text("stale = True\n", encoding="utf-8")
    stale_dist = repository / "dist" / "old.whl"
    stale_dist.parent.mkdir()
    stale_dist.write_bytes(b"old wheel")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    monkeypatch.setattr(VALIDATION_SCRIPT, "PROJECT_ROOT", repository)

    commit = VALIDATION_SCRIPT._stage_tracked_head(snapshot)

    assert commit == _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
    assert (snapshot / "tracked.txt").read_text(encoding="utf-8") == "tracked HEAD bytes\n"
    assert os.access(snapshot / "tracked-tool", os.X_OK)
    assert not (snapshot / ".git").exists()
    assert not (snapshot / "build").exists()
    assert not (snapshot / "dist").exists()
    assert stale_build.read_text(encoding="utf-8") == "stale = True\n"
    assert stale_dist.read_bytes() == b"old wheel"


@pytest.mark.parametrize("dirty_kind", ("modified", "staged", "untracked"))
def test_stage_tracked_head_rejects_every_dirty_worktree_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dirty_kind: str,
) -> None:
    repository = _clean_repository(tmp_path)
    if dirty_kind == "modified":
        (repository / "tracked.txt").write_text("modified bytes\n", encoding="utf-8")
    elif dirty_kind == "staged":
        (repository / "tracked.txt").write_text("staged bytes\n", encoding="utf-8")
        _git(repository, "add", "tracked.txt")
    else:
        (repository / "untracked.txt").write_text("untracked bytes\n", encoding="utf-8")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    monkeypatch.setattr(VALIDATION_SCRIPT, "PROJECT_ROOT", repository)

    with pytest.raises(
        VALIDATION_SCRIPT.PreflightError,
        match="requires a clean Git worktree and index",
    ):
        VALIDATION_SCRIPT._stage_tracked_head(snapshot)
