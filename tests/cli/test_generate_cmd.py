from __future__ import annotations

import json

import pytest
from pathlib import Path
from typing import Any

from rextio.cli.main import main


def test_generate_never_emits_exempt_functions_to_rust(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1

def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["generate", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    rust_source = (
        tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs"
    ).read_text(encoding="utf-8")
    fallback_source = (
        tmp_path / ".rextio" / "generated" / "python" / "_fallback_app.py"
    ).read_text(encoding="utf-8")

    assert exit_code == 0
    assert "fn app__add(a: i64, b: i64) -> PyResult<i64>" in rust_source
    assert "keep_python" not in rust_source
    assert "def keep_python" in fallback_source


def test_generate_writes_sources_without_running_rust_or_nuitka_builds(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(xs: list[int]) -> int:
    return xs[0] + 1

@rextio.native
def rejected(xs: list[int]) -> int:
    return helper(xs)
""",
        encoding="utf-8",
    )

    exit_code = main(["generate", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()
    rust_dir = tmp_path / ".rextio" / "generated" / "rust"
    python_dir = tmp_path / ".rextio" / "generated" / "python"
    rust_source = rust_dir / "src" / "lib.rs"
    wrapper = python_dir / "app.py"
    fallback = python_dir / "_fallback_app.py"
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "Rextio generate" in captured.out
    assert "fallback: nuitka" in captured.out
    assert "native source: generated" in captured.out
    assert report["status"] == "generated"
    assert report["fallback"] == "nuitka"
    assert report["native_source"]["status"] == "generated"
    assert report["accepted_native_count"] == 1
    assert report["rejected_native_count"] == 1
    assert rust_source.exists()
    assert "fn app__add(a: i64, b: i64) -> PyResult<i64>" in rust_source.read_text(
        encoding="utf-8"
    )
    assert "fn rejected" not in rust_source.read_text(encoding="utf-8")
    assert wrapper.exists()
    assert fallback.exists()
    assert "def add(a: int, b: int) -> int:" in wrapper.read_text(encoding="utf-8")
    assert "def rejected" in fallback.read_text(encoding="utf-8")
    assert not (tmp_path / ".rextio" / "build").exists()
    assert not (tmp_path / "dist").exists()
    assert not list(tmp_path.rglob("*.so"))


def test_generate_writes_rust_importable_crate_source_without_building(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "generate",
            str(tmp_path),
            "--rust-importable",
            "--rust-crate-name=demo_rust",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    rust_crate = tmp_path / ".rextio" / "generated" / "rust_crate"
    lib_source = (rust_crate / "src" / "lib.rs").read_text(encoding="utf-8")

    assert exit_code == 0
    assert "rust crate source: generated" in captured.out
    assert report["status"] == "generated"
    assert report["rust_crate_source"]["status"] == "generated"
    assert report["rust_crate_source"]["path"] == str(rust_crate / "src" / "lib.rs")
    assert 'name = "demo_rust"' in (rust_crate / "Cargo.toml").read_text(encoding="utf-8")
    assert "pub fn app__add(a: i64, b: i64) -> Result<i64, RextioError>" in lib_source
    assert not (tmp_path / ".rextio" / "build").exists()
    assert not (tmp_path / "dist").exists()


def test_generate_embeds_fallback_threshold(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["generate", str(tmp_path), "--fallback-threshold=3"])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    wrapper_source = (
        tmp_path / ".rextio" / "generated" / "python" / "app.py"
    ).read_text(encoding="utf-8")

    assert exit_code == 0
    assert "boundary fallback threshold: 3" in captured.out
    assert report["boundary_fallback_threshold"] == 3
    assert 'boundary_fallback_required("app.add", 3)' in wrapper_source


def test_generate_uses_configured_fallback_and_threshold(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "nuitka"
fallback_threshold = 9
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["generate", str(tmp_path)])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    wrapper_source = (
        tmp_path / ".rextio" / "generated" / "python" / "app.py"
    ).read_text(encoding="utf-8")

    assert exit_code == 0
    assert "fallback: nuitka" in captured.out
    assert "boundary fallback threshold: 9" in captured.out
    assert report["fallback"] == "nuitka"
    assert report["boundary_fallback_threshold"] == 9
    assert 'boundary_fallback_required("app.add", 9)' in wrapper_source


class FakeEntryPoint:
    def __init__(self, name: str, payload: Any) -> None:
        self.name = name
        self._payload = payload

    def load(self) -> Any:
        return self._payload


class FakeEntryPoints(tuple):
    def select(self, *, group: str) -> tuple[FakeEntryPoint, ...]:
        if group == "rextio.plugins":
            return tuple(self)
        return ()


def test_generate_reports_target_and_active_plugin(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "rextio.plugins.loader.metadata.entry_points",
        lambda: FakeEntryPoints(
            (
                FakeEntryPoint(
                    "numpy-rust",
                    {
                        "target_language": "rust",
                        "target_versions": ["stable"],
                        "target_build_options": {"binding": "pyo3"},
                    },
                ),
            )
        ),
    )
    (tmp_path / "rextio.toml").write_text(
        """
[target]
version = "stable"

[target.build_options]
binding = "pyo3"

[plugins]
enabled = ["numpy-rust"]
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    # [target].version has no effect in 0.1.0 (reserved): the warning is an
    # expected side effect of this fixture, asserted here instead of leaking
    # into the run summary.
    with pytest.warns(RuntimeWarning, match="no effect in 0.1.0"):
        exit_code = main(["generate", str(tmp_path)])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "target language: rust" in captured.out
    assert "target version: stable" in captured.out
    assert "active plugins: 1" in captured.out
    assert report["target"]["spec"]["language"] == "rust"
    assert report["target"]["spec"]["version"] == "stable"
    assert report["target"]["plugins"]["active"][0]["id"] == "numpy-rust"


def test_generate_rejects_unsupported_native_backend_from_config(tmp_path: Path, capsys) -> None:
    # rust is the only accepted native_backend in 0.1.0: a config carrying
    # anything else fails at load time with a clear configuration error
    # instead of reaching codegen.
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )
    (tmp_path / "rextio.toml").write_text(
        """
[build]
native_backend = "zig"
""",
        encoding="utf-8",
    )

    exit_code = main(["generate", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Generate failed while loading configuration" in captured.err
    assert "unsupported config value for [build].native_backend" in captured.err
    assert '"rust"' in captured.err
