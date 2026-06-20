from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def fake_cargo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(
        """#!/usr/bin/env python3
from pathlib import Path

release = Path.cwd() / "target" / "release"
release.mkdir(parents=True, exist_ok=True)
for name in (
    "lib_rextio_native.dylib",
    "lib_rextio_native.so",
    "_rextio_native.dll",
    "_rextio_native.pyd",
):
    (release / name).write_bytes(b"fake native library")
""",
        encoding="utf-8",
    )
    cargo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return cargo
