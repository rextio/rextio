from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_editable_install_cli_smoke(
    tmp_path: Path,
    fake_cargo: Path,
) -> None:
    venv_dir = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True).create(venv_dir)
    python = _venv_bin(venv_dir, "python")
    rextio = _venv_bin(venv_dir, "rextio")
    env = os.environ.copy()

    _run([str(python), "-m", "pip", "install", "-e", str(REPO_ROOT)], env=env)

    project_root = tmp_path / "smoke_project"
    _run([str(rextio), "init", "--project-root", str(project_root)], env=env)
    (project_root / "rextio.toml").write_text(
        """
[build]
native_backend = "rust"
fallback_backend = "cpython"

[rust]
binding = "pyo3"
build_tool = "cargo"

[fallback]
nuitka = "experimental"

[policy]
native_marker = "decorator"
require_type_hints = true
allow_dynamic_features = false
boundary_warnings = true
""",
        encoding="utf-8",
    )
    source = project_root / "src" / "smoke_pkg" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    check = _run([str(rextio), "check", str(project_root), "--json"], env=env)
    check_data = json.loads(check.stdout)
    assert check_data["accepted_native"] == ["smoke_pkg.math_ops.add"]

    build = _run([str(rextio), "build", str(project_root), "--fallback=cpython"], env=env)
    assert "Rextio build" in build.stdout
    assert (project_root / ".rextio" / "build" / "python").exists()
    wheels = sorted((project_root / "dist").glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        assert "smoke_pkg/math_ops.py" in archive.namelist()

    bench = _run(
        [
            str(rextio),
            "bench",
            "smoke_pkg.math_ops.add",
            "--project-root",
            str(project_root),
        ],
        env=env,
    )
    assert "Rextio bench smoke_pkg.math_ops.add" in bench.stdout
    assert (project_root / ".rextio" / "reports" / "bench.json").exists()

    clean = _run([str(rextio), "clean", str(project_root)], env=env)
    assert "Rextio clean" in clean.stdout
    assert not (project_root / ".rextio" / "build").exists()
    assert not (project_root / ".rextio" / "generated").exists()
    assert not (project_root / ".rextio" / "reports").exists()


def _venv_bin(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        suffix = ".exe" if name in {"python", "rextio"} else ""
        return venv_dir / "Scripts" / f"{name}{suffix}"
    return venv_dir / "bin" / name


def _run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
