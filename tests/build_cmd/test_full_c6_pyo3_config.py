from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import sys

import pytest

from rextio.build.full_c6_pyo3_config import (
    FULL_C6_PYO3_CONFIG_NAME,
    FullC6Pyo3ConfigError,
    FullC6Pyo3ConfigIdentity,
    bind_full_c6_pyo3_environment,
    capture_full_c6_pyo3_config,
    materialize_full_c6_pyo3_config,
    verify_full_c6_pyo3_config,
)


def _identity(target: str = "aarch64-apple-darwin") -> FullC6Pyo3ConfigIdentity:
    content = (
        b"implementation=CPython\n"
        b"version=3.11\n"
        b"shared=true\n"
        b"pointer_width=64\n"
        b"build_flags=\n"
        b"suppress_build_script_link_lines=true\n"
    )
    return FullC6Pyo3ConfigIdentity(
        target_triple=target,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        content=content,
    )


def test_identity_is_path_free_and_target_bound() -> None:
    identity = _identity()
    receipt = identity.to_dict()

    assert receipt["implementation"] == "CPython"
    assert receipt["version"] == "3.11"
    assert receipt["pointer_width"] == 64
    assert "content" not in receipt
    assert "executable" not in receipt
    assert "/" not in identity.content.decode()
    assert _identity("x86_64-unknown-linux-gnu").digest != identity.digest


def test_identity_rejects_noncanonical_or_path_bearing_content() -> None:
    identity = _identity()
    with pytest.raises(ValueError, match="not canonical"):
        FullC6Pyo3ConfigIdentity(
            target_triple=identity.target_triple,
            sha256=hashlib.sha256(identity.content + b"lib_dir=/tmp\n").hexdigest(),
            size=len(identity.content) + len(b"lib_dir=/tmp\n"),
            content=identity.content + b"lib_dir=/tmp\n",
        )


def test_capture_validates_frozen_runtime() -> None:
    machine = platform.machine().lower()
    target = (
        "aarch64-apple-darwin"
        if sys.platform == "darwin" and machine in {"arm64", "aarch64"}
        else "x86_64-unknown-linux-gnu"
    )
    if sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 11):
        identity = capture_full_c6_pyo3_config(target)
        assert identity == _identity(target)
        other = (
            "x86_64-unknown-linux-gnu"
            if target == "aarch64-apple-darwin"
            else "aarch64-apple-darwin"
        )
        with pytest.raises(FullC6Pyo3ConfigError, match="differs"):
            capture_full_c6_pyo3_config(other)
    with pytest.raises(FullC6Pyo3ConfigError, match="unsupported"):
        capture_full_c6_pyo3_config("aarch64-unknown-linux-gnu")


def test_materialize_verify_and_bind_removes_discovery(tmp_path: Path) -> None:
    identity = _identity()
    path = materialize_full_c6_pyo3_config(tmp_path, identity)

    assert path == tmp_path / FULL_C6_PYO3_CONFIG_NAME
    assert path.read_bytes() == identity.content
    assert path.stat().st_mode & 0o777 == 0o600
    verify_full_c6_pyo3_config(path, identity)

    environment = bind_full_c6_pyo3_environment(
        {
            "PATH": "/bound/bin",
            "PYO3_PYTHON": "/host/python",
            "PYO3_CROSS": "1",
            "PYO3_ENVIRONMENT_SIGNATURE": "ambient",
            "PYO3_USE_ABI3_FORWARD_COMPATIBILITY": "1",
            "PYO3_USE_STABLE_ABI_FORWARD_COMPATIBILITY": "1",
            "PYO3_FUTURE_DISCOVERY_CHANNEL": "1",
            "_PYTHON_SYSCONFIGDATA_NAME": "host_override",
            "CONDA_PREFIX": "/host/conda",
            "VIRTUAL_ENV": "/host/venv",
        },
        config_path=path,
        identity=identity,
    )
    assert environment == {
        "PATH": "/bound/bin",
        "PYO3_CONFIG_FILE": str(path),
        "PYO3_ENVIRONMENT_SIGNATURE": identity.digest,
    }


def test_materialization_rejects_existing_file_and_symlink_root(tmp_path: Path) -> None:
    identity = _identity()
    (tmp_path / FULL_C6_PYO3_CONFIG_NAME).write_bytes(b"attacker")
    with pytest.raises(FullC6Pyo3ConfigError, match="materialized"):
        materialize_full_c6_pyo3_config(tmp_path, identity)

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(FullC6Pyo3ConfigError, match="unsafe"):
        materialize_full_c6_pyo3_config(linked, identity)


def test_verify_rejects_changed_linked_or_hardlinked_config(tmp_path: Path) -> None:
    identity = _identity()
    path = materialize_full_c6_pyo3_config(tmp_path, identity)
    path.write_bytes(identity.content.replace(b"true", b"fals"))
    with pytest.raises(FullC6Pyo3ConfigError, match="changed"):
        verify_full_c6_pyo3_config(path, identity)

    path.unlink()
    source = tmp_path / "source"
    source.write_bytes(identity.content)
    os.link(source, path)
    with pytest.raises(FullC6Pyo3ConfigError, match="unsafe"):
        verify_full_c6_pyo3_config(path, identity)

    path.unlink()
    path.symlink_to(source)
    with pytest.raises(FullC6Pyo3ConfigError, match="verified"):
        verify_full_c6_pyo3_config(path, identity)


def test_bind_requires_absolute_verified_config(tmp_path: Path) -> None:
    identity = _identity()
    with pytest.raises(FullC6Pyo3ConfigError, match="absolute"):
        bind_full_c6_pyo3_environment(
            {}, config_path=Path(FULL_C6_PYO3_CONFIG_NAME), identity=identity
        )
    with pytest.raises(FullC6Pyo3ConfigError, match="verified"):
        bind_full_c6_pyo3_environment({}, config_path=tmp_path / "missing", identity=identity)
