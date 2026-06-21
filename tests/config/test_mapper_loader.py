from __future__ import annotations

from pathlib import Path

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
            repository="https://example.invalid/rextio-mappers",
        ),
        TargetSpec(
            language="rust",
            version="stable",
            build_options={"binding": "pyo3"},
        ),
    )

    assert [mapper.id for mapper in registry.discovered] == ["numpy-rust"]
    assert [mapper.id for mapper in registry.active] == ["numpy-rust"]
    assert registry.repository == "https://example.invalid/rextio-mappers"


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

