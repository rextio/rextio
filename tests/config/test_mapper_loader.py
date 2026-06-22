from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from rextio.config.schema import MapperConfig
from rextio.mappers.loader import MapperError, load_mapper_registry
from rextio.targets.models import TargetSpec


def test_load_mapper_registry_activates_matching_mapper(tmp_path: Path) -> None:
    _write_mapper(
        tmp_path / "mappers" / "numpy-rust",
        """
[mapper]
id = "numpy-rust"
name = "Python NumPy to rust-numpy"
source_language = "python"
target_language = "rust"
target_versions = ["stable"]
rules = ["numpy.ndarray"]

[mapper.target_build_options]
binding = "pyo3"
""",
    )

    registry = load_mapper_registry(
        tmp_path,
        MapperConfig(
            paths=("mappers/numpy-rust",),
            enabled=("numpy-rust",),
        ),
        TargetSpec(
            language="rust",
            version="stable",
            build_options={"binding": "pyo3"},
        ),
    )

    assert [mapper.id for mapper in registry.discovered] == ["numpy-rust"]
    assert [mapper.id for mapper in registry.active] == ["numpy-rust"]
    assert registry.repository is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for mapper repository tests")
def test_load_mapper_registry_downloads_public_git_repository(tmp_path: Path) -> None:
    repository = tmp_path / "mapper-repository"
    project = tmp_path / "project"
    project.mkdir()
    _write_mapper(
        repository / "mappers" / "rust-basic",
        """
[mapper]
id = "rust-basic"
name = "Rust basic mapper"
source_language = "python"
target_language = "rust"
rules = ["python.basic"]
""",
    )
    _git(repository, "init")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.email=rextio@example.invalid",
        "-c",
        "user.name=Rextio Test",
        "commit",
        "-m",
        "add mapper",
    )

    registry = load_mapper_registry(
        project,
        MapperConfig(
            repository=str(repository),
            enabled=("rust-basic",),
        ),
        TargetSpec(language="rust"),
    )

    assert registry.repository == str(repository)
    assert registry.repository_path is not None
    assert registry.repository_path.exists()
    assert [mapper.id for mapper in registry.discovered] == ["rust-basic"]
    assert [mapper.id for mapper in registry.active] == ["rust-basic"]
    assert registry.active[0].path.is_relative_to(registry.repository_path)


def test_load_mapper_registry_filters_by_target_version(tmp_path: Path) -> None:
    _write_mapper(
        tmp_path / "mappers" / "mojo-dev",
        """
[mapper]
id = "mojo-dev"
target_language = "mojo"
target_versions = ["25.1"]
""",
    )

    registry = load_mapper_registry(
        tmp_path,
        MapperConfig(paths=("mappers/mojo-dev",)),
        TargetSpec(language="mojo", version="25.2"),
    )

    assert [mapper.id for mapper in registry.discovered] == ["mojo-dev"]
    assert registry.active == ()


def test_load_mapper_registry_rejects_missing_enabled_mapper(tmp_path: Path) -> None:
    _write_mapper(
        tmp_path / "mappers" / "numpy-rust",
        """
[mapper]
id = "numpy-rust"
target_language = "rust"
""",
    )

    with pytest.raises(MapperError, match=r"enabled mapper was not discovered"):
        load_mapper_registry(
            tmp_path,
            MapperConfig(paths=("mappers/numpy-rust",), enabled=("missing",)),
            TargetSpec(language="rust"),
        )


def test_load_mapper_registry_rejects_mapper_without_manifest(tmp_path: Path) -> None:
    (tmp_path / "mappers" / "empty").mkdir(parents=True)

    with pytest.raises(MapperError, match=r"does not contain a manifest"):
        load_mapper_registry(
            tmp_path,
            MapperConfig(paths=("mappers/empty",)),
            TargetSpec(language="rust"),
        )


def _write_mapper(path: Path, manifest: str) -> None:
    path.mkdir(parents=True)
    (path / "rextio-mapper.toml").write_text(manifest, encoding="utf-8")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
