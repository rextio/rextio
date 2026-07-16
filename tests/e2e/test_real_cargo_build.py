from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main
from rextio.runtime import native_loader


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_imports_native_and_preserves_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "e2e_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(x: int) -> int:
    return x + 10

@rextio.native
def rejected(x: int) -> int:
    return helper(x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    build_python = tmp_path / ".rextio" / "build" / "python"
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    report = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    # `rejected` now survives natively through the scalar boundary call to
    # the unmarked helper; the name is kept to pin that the OLD rejection no
    # longer happens.
    assert report["accepted_native_count"] == 2
    assert report["rejected_native_count"] == 0
    assert report["native_build"]["tool"] == "cargo"
    assert report["native_build"]["status"] == "built"
    assert Path(report["native_build"]["installed_path"]).exists()

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    for module_name in ("_rextio_native", "e2e_app.math_ops", "e2e_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)

    native_module = importlib.import_module("_rextio_native")
    assert native_module.e2e_app__math_ops__add(2, 3) == 5

    module = importlib.import_module("e2e_app.math_ops")
    assert module.add(2, 3) == 5
    # Runs natively with an in-process boundary call into `helper`.
    assert module.rejected(5) == 15

    real_native_loader = native_loader.load_native_function

    def injected_native_loader(*, module_name: str, function_name: str):
        if function_name == "e2e_app__math_ops__add":
            return lambda a, b: a + b + 100
        return real_native_loader(module_name=module_name, function_name=function_name)

    # Native bindings now live in the wrapper's isolated bootstrap closure, so
    # inject at loader construction time instead of mutating a module-global
    # implementation detail that no longer exists.
    monkeypatch.setattr(native_loader, "load_native_function", injected_native_loader)
    for module_name in ("e2e_app.math_ops", "e2e_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)
    module = importlib.import_module("e2e_app.math_ops")
    assert module.add(2, 3) == 105

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    assert module.add(2, 3) == 5

    wheels = sorted((tmp_path / "dist").glob("*.whl"))
    assert len(wheels) == 1
    wheel_venv = tmp_path / "wheel_venv"
    env = os.environ.copy()
    _create_venv(wheel_venv, env)
    wheel_python = _venv_bin(wheel_venv, "python")
    _run([str(wheel_python), "-m", "pip", "install", str(wheels[0])], env=env)
    _run(
        [
            str(wheel_python),
            "-c",
            (
                "import importlib\n"
                "native = importlib.import_module('_rextio_native')\n"
                "assert native.e2e_app__math_ops__add(2, 3) == 5\n"
                "from e2e_app import math_ops\n"
                "assert math_ops.add(2, 3) == 5\n"
                "assert math_ops.rejected(5) == 15\n"
            ),
        ],
        env=env,
    )
    _run(
        [
            str(wheel_python),
            "-c",
            "from e2e_app import math_ops\nassert math_ops.add(2, 3) == 5\n",
        ],
        env={**env, "REXTIO_NATIVE_MODE": "fallback"},
    )


def _venv_bin(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        suffix = ".exe" if name == "python" else ""
        return venv_dir / "Scripts" / f"{name}{suffix}"
    return venv_dir / "bin" / name


def _create_venv(venv_dir: Path, env: dict[str, str]) -> None:
    base_python = getattr(sys, "_base_executable", sys.executable) or sys.executable
    _run([base_python, "-m", "venv", str(venv_dir)], env=env)


def _run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
