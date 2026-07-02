from __future__ import annotations

import zipfile
import sys
import sysconfig
from pathlib import Path

from rextio.build.wheel_builder import build_artifact_wheel


def test_build_artifact_wheel_is_deterministic_and_records_files(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    dist_dir = tmp_path / "dist"
    (python_dir / "pkg").mkdir(parents=True)
    (python_dir / "pkg" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (python_dir / "pkg" / "mod.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    first = build_artifact_wheel(tmp_path / "Demo Project", python_dir, dist_dir)
    first_bytes = Path(first.path or "").read_bytes()
    second = build_artifact_wheel(tmp_path / "Demo Project", python_dir, dist_dir)
    second_bytes = Path(second.path or "").read_bytes()

    assert first.status == "built"
    assert second.status == "built"
    assert first.path == second.path
    assert first_bytes == second_bytes
    assert Path(first.path or "").name == "demo_project-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(first.path or "") as archive:
        names = set(archive.namelist())
        record = archive.read("demo_project-0.1.0.dist-info/RECORD").decode("utf-8")

    assert "pkg/__init__.py" in names
    assert "pkg/mod.py" in names
    assert "demo_project-0.1.0.dist-info/METADATA" in names
    assert "demo_project-0.1.0.dist-info/WHEEL" in names
    assert "demo_project-0.1.0.dist-info/RECORD" in names
    assert "pkg/mod.py,sha256=" in record


def test_build_artifact_wheel_uses_platform_tag_for_native_extension(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    dist_dir = tmp_path / "dist"
    python_dir.mkdir()
    native_name = f"_rextio_native.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so"
    (python_dir / native_name).write_bytes(b"fake native extension")

    result = build_artifact_wheel(tmp_path / "Native Project", python_dir, dist_dir)

    python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    expected_name = f"native_project-0.1.0-{python_tag}-{python_tag}-{platform_tag}.whl"
    assert Path(result.path or "").name == expected_name
    with zipfile.ZipFile(result.path or "") as archive:
        wheel = archive.read("native_project-0.1.0.dist-info/WHEEL").decode("utf-8")

    assert "Root-Is-Purelib: false" in wheel
    assert f"Tag: {python_tag}-{python_tag}-{platform_tag}" in wheel

def test_nuitka_compiled_modules_ship_without_shadowed_py(tmp_path: Path) -> None:
    # After a nuitka fallback build the tree holds `module.py` AND its compiled
    # `module.so` sibling. The import system prefers the extension, so the .py
    # is dead weight in the wheel and exposes the source; it must be excluded.
    # Modules kept plain (external accelerators) have no compiled sibling and
    # keep their .py. The wheel tag must be platform-specific: it carries
    # binaries even though no _rextio_native extension exists.
    python_dir = tmp_path / "python"
    (python_dir / "hb").mkdir(parents=True)
    (python_dir / "hb" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "hb" / "plain.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (python_dir / "hb" / "plain.so").write_bytes(b"fake extension")
    (python_dir / "hb" / "plain2.py").write_text("def g():\n    return 2\n", encoding="utf-8")
    (python_dir / "hb" / "kernels.py").write_text(
        "from numba import njit\n\n@njit\ndef total(n):\n    return n\n", encoding="utf-8"
    )

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    assert "py3-none-any" not in result.path  # platform tag required
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "hb/plain.so" in names
    assert "hb/plain.py" not in names  # shadowed source excluded
    assert "hb/plain2.py" in names  # prefix-similar module is NOT shadowed
    assert "hb/kernels.py" in names  # accelerated module keeps its source
    assert "hb/__init__.py" in names
    record = [name for name in names if name.endswith("RECORD")]
    assert record  # metadata still written

def test_ctypes_payload_does_not_shadow_its_python_wrapper(tmp_path: Path) -> None:
    # A .dylib/.dll next to a same-stem .py is a ctypes payload, not an
    # importable extension module (EXTENSION_SUFFIXES only has .so/.pyd):
    # the wrapper .py must stay in the wheel, while the platform tag still
    # applies (the wheel carries platform-specific content).
    python_dir = tmp_path / "python"
    (python_dir / "pkg").mkdir(parents=True)
    (python_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "pkg" / "libfoo.py").write_text("# ctypes wrapper\n", encoding="utf-8")
    (python_dir / "pkg" / "libfoo.native.dylib").write_bytes(b"payload")

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    assert "py3-none-any" not in result.path
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "pkg/libfoo.py" in names  # wrapper survives
    assert "pkg/libfoo.native.dylib" in names
