from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import rextio.build.orchestrator as orchestrator
import rextio.cli.build_cmd as build_cmd
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.models import ArtifactKind, FallbackStrategy
from rextio.artifacts.profiles import rust_crate_profile
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.executable_builder import ExecutableBuildResult
from rextio.cli.main import main
from rextio.codegen.rust.generator import RustCodegenError
from rextio.plugins.capabilities import StandalonePluginContext
from rextio.plugins.loader import PluginError


def _fake_built_rust_executable(
    crate_dir: Path,
    dist_dir: Path,
    binary_name: str,
    entrypoint: str,
    *,
    timeout: float,
    toolchain=None,
) -> ExecutableBuildResult:
    dist_dir.mkdir(parents=True, exist_ok=True)
    binary = dist_dir / binary_name
    binary.write_text("fake binary", encoding="utf-8")
    return ExecutableBuildResult(
        status="built",
        path=str(binary),
        message="ok",
        entrypoint=entrypoint,
        backend="rust",
    )


def test_fallback_only_profile_planning_does_not_probe_host(monkeypatch) -> None:
    def unexpected():
        pytest.fail("fallback-only artifact planning must not resolve a Rust target triple")

    monkeypatch.setattr(orchestrator, "detect_host_target_triple", unexpected)

    assert (
        orchestrator._generate_artifact_profiles(
            "cpython", native_extension=False, rust_importable=False
        )
        == ()
    )


def test_pre_resolved_standalone_context_must_match_planned_profile() -> None:
    expected = rust_crate_profile("aarch64-apple-darwin")
    wrong = rust_crate_profile("x86_64-unknown-linux-gnu")
    context = StandalonePluginContext(
        profile=wrong,
        capabilities={},
        capable_qualnames=frozenset(),
    )
    plan = SimpleNamespace(artifact_profiles=(expected,))

    with pytest.raises(PluginError, match="context profile mismatch"):
        orchestrator._ensure_standalone_contexts(
            plan,
            SimpleNamespace(),
            seed={ArtifactKind.RUST_CRATE: context},
        )


def test_build_reports_unavailable_host_artifact_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fake_cargo: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )

    def unsupported_host() -> str:
        raise ValueError("unsupported host architecture 'armv7l'")

    monkeypatch.setattr(orchestrator, "detect_host_target_triple", unsupported_host)

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 1
    assert "RXT060 Artifact profile planning failed" in captured.err
    assert report["status"] == "artifact-profile-unavailable"
    assert report["error"]["code"] == "RXT060"
    from rextio.contract import TOOLING_CONTRACT_VERSION

    assert report["contract_version"] == TOOLING_CONTRACT_VERSION
    assert (tmp_path / ".rextio" / "reports" / "check.json").exists()


def test_rust_executable_preflight_reports_unavailable_host_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app.py").write_text(
        "def main(argv: list[str]) -> int:\n    return len(argv) - 1\n",
        encoding="utf-8",
    )

    def unsupported_host() -> str:
        raise orchestrator.ArtifactProfilePlanningError(
            "RXT060 Artifact profile planning failed. Cause: unsupported armv7l host"
        )

    monkeypatch.setattr(build_cmd, "detect_host_target_triple", unsupported_host)

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--executable-backend=rust",
            "--executable-fallback=error",
            "--entrypoint=app:main",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 1
    assert "RXT060 Artifact profile planning failed" in captured.err
    assert report["status"] == "artifact-profile-unavailable"
    assert report["error"]["code"] == "RXT060"
    assert (
        orchestrator._build_artifact_profiles(
            "cpython",
            FallbackStrategy.PYTHON_SUBPROCESS,
            executable_entrypoint=None,
            executable_backend="zipapp",
            native_extension=False,
            rust_importable=False,
        )
        == ()
    )


def test_open_error_closure_reports_all_edges_before_any_cargo(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def alpha(value: int) -> int:
    return value + 1

@rextio.exempt
def zeta(value: int) -> int:
    return value + 2

@rextio.native
def worker(value: int) -> int:
    return alpha(value) + zeta(value)

@rextio.native
def main(argv: list[str]) -> int:
    return worker(len(argv))
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    executable_analysis = analyze_project(
        tmp_path, native_marker="decorator", delegate_fallback=True
    )

    def unexpected(*args, **kwargs):
        pytest.fail("Cargo/native generation must not run for an open error closure")

    monkeypatch.setattr(orchestrator, "_generate_and_build_native", unexpected)
    monkeypatch.setattr(orchestrator, "build_rust_executable", unexpected)

    result = orchestrator.build_hybrid_artifact(
        tmp_path,
        analysis,
        "cpython",
        executable_entrypoint="app:main",
        executable_backend="rust",
        executable_analysis=executable_analysis,
        executable_fallback=FallbackStrategy.ERROR,
    )

    assert result.executable_build.status == "failed"
    closure = result.executable_build.to_dict()["closure"]
    assert closure["status"] == "open"
    assert [edge["callee"] for edge in closure["fallback_edges"]] == [
        "app.alpha",
        "app.zeta",
    ]
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["executable_build"]["closure"] == closure
    assert not ArtifactLayout(tmp_path).rust_bin_dir.exists()


@pytest.mark.parametrize("strategy", list(FallbackStrategy))
def test_unavailable_entrypoint_fails_before_build_and_removes_stale_outputs(
    tmp_path: Path,
    monkeypatch,
    strategy: FallbackStrategy,
) -> None:
    (tmp_path / "app.py").write_text(
        "import rextio\n@rextio.native\ndef main(argv: list[str]) -> int:\n    return 0\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)
    for path in (
        layout.build_dir / "stale",
        layout.rust_dir / "stale",
        layout.rust_bin_dir / "stale",
        layout.python_dir / "stale",
        layout.dist_dir / "missing_main.runtime" / "stale",
        layout.dist_dir / "stale-crate-rust-crate" / "stale",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stale", encoding="utf-8")
    for name in ("missing_main", "missing_main.exe"):
        (layout.dist_dir / name).write_text("stale", encoding="utf-8")
    wheel = layout.dist_dir / f"{tmp_path.name.lower()}-0.1.0-py3-none-any.whl"
    wheel.write_text("stale", encoding="utf-8")
    keep = layout.dist_dir / "keep-me.txt"
    keep.write_text("keep", encoding="utf-8")

    def unexpected(*args, **kwargs):
        pytest.fail("native generation/Cargo must not run for unavailable entrypoint")

    monkeypatch.setattr(orchestrator, "_generate_and_build_native", unexpected)
    monkeypatch.setattr(orchestrator, "build_rust_executable", unexpected)

    result = orchestrator.build_hybrid_artifact(
        tmp_path,
        analysis,
        "cpython",
        executable_entrypoint="missing:main",
        executable_backend="rust",
        executable_analysis=analysis,
        executable_fallback=strategy,
        rust_crate_name="stale-crate",
    )

    closure = result.executable_build.to_dict()["closure"]
    assert result.executable_build.status == "failed"
    assert closure["status"] == "unavailable"
    assert closure["profile"]["target_triple"] != "host"
    assert "Fallback sidecars cannot replace" in result.executable_build.message
    assert not layout.build_dir.exists()
    assert not layout.rust_dir.exists()
    assert not layout.rust_bin_dir.exists()
    assert not layout.python_dir.exists()
    assert not wheel.exists()
    assert not (layout.dist_dir / "stale-crate-rust-crate").exists()
    assert not (layout.dist_dir / "missing_main").exists()
    assert not (layout.dist_dir / "missing_main.exe").exists()
    assert not (layout.dist_dir / "missing_main.runtime").exists()
    assert keep.read_text(encoding="utf-8") == "keep"


def test_closed_error_closure_builds_without_runtime_sidecar(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def main(argv: list[str]) -> int:
    return len(argv)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)
    monkeypatch.setattr(orchestrator, "build_rust_executable", _fake_built_rust_executable)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        FallbackStrategy.ERROR,
        build_timeout=30,
    )

    assert result.status == "built"
    assert result.to_dict()["closure"]["status"] == "closed"
    assert result.to_dict()["closure"]["strategy"] == "error"
    assert not (layout.dist_dir / "app_main.runtime").exists()
    assert "serde_json" not in (layout.rust_bin_dir / "Cargo.toml").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("strategy", "expects_nuitka"),
    [
        (FallbackStrategy.PYTHON_SUBPROCESS, False),
        (FallbackStrategy.NUITKA_SIDECAR, True),
    ],
)
def test_canonical_sidecar_strategies_reuse_existing_dispatchers(
    tmp_path: Path, monkeypatch, strategy: FallbackStrategy, expects_nuitka: bool
) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def label(value: str) -> str:
    return value.lower()

@rextio.native
def main(argv: list[str]) -> int:
    return len(label(argv[0]))
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)
    nuitka_calls: list[set[str]] = []
    monkeypatch.setattr(orchestrator, "build_rust_executable", _fake_built_rust_executable)

    def fake_nuitka(runtime_dir, allowed_qualnames, timeout, toolchain=None):
        nuitka_calls.append(set(allowed_qualnames))
        return None

    monkeypatch.setattr(orchestrator, "_build_nuitka_dispatcher", fake_nuitka)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        strategy,
        build_timeout=30,
    )

    assert result.status == "built"
    assert (layout.dist_dir / "app_main.runtime").is_dir()
    assert bool(nuitka_calls) is expects_nuitka
    assert result.to_dict()["closure"]["strategy"] == strategy.value


def test_build_generates_rust_project_for_accepted_native_only(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
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

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    rust_dir = tmp_path / ".rextio" / "generated" / "rust"
    python_dir = tmp_path / ".rextio" / "generated" / "python"
    build_python_dir = tmp_path / ".rextio" / "build" / "python"
    dist_dir = tmp_path / "dist"
    lib_rs = rust_dir / "src" / "lib.rs"
    app_py = python_dir / "app.py"
    fallback_app_py = python_dir / "_fallback_app.py"
    build_report = tmp_path / ".rextio" / "reports" / "build.json"

    assert exit_code == 0
    assert "generated Rust project" in captured.out
    assert "generated Python package tree" in captured.out
    assert "build artifact" in captured.out
    assert (rust_dir / "Cargo.toml").exists()
    assert (rust_dir / ".cargo" / "config.toml").exists()
    assert (rust_dir / "pyproject.toml").exists()
    assert lib_rs.exists()
    assert "fn app__add(a: i64, b: i64) -> PyResult<i64>" in lib_rs.read_text(encoding="utf-8")
    assert "fn rejected" not in lib_rs.read_text(encoding="utf-8")
    assert app_py.exists()
    assert fallback_app_py.exists()
    assert (build_python_dir / "app.py").exists()
    assert (build_python_dir / "_fallback_app.py").exists()
    assert (build_python_dir / "rextio" / "__init__.py").exists()
    assert (build_python_dir / "rextio" / "runtime" / "flags.py").exists()
    wrapper_source = app_py.read_text(encoding="utf-8")
    assert wrapper_source.startswith("# Generated by Rextio. Do not edit manually.")
    assert "_rextio_builtin_globals().update(_rextio_public_exports)" in wrapper_source
    assert "def add(a: int, b: int) -> int:" in wrapper_source
    assert "def rejected" not in wrapper_source
    assert "def rejected" in fallback_app_py.read_text(encoding="utf-8")
    data = json.loads(build_report.read_text(encoding="utf-8"))
    assert data["status"] == "built"
    assert data["accepted_native_count"] == 1
    assert data["rejected_native_count"] == 1
    assert data["generated_python"] == str(python_dir)
    assert data["build_python"] == str(build_python_dir)
    assert data["native_build"]["status"] == "built"
    assert Path(data["native_build"]["installed_path"]).exists()
    assert data["wheel_build"]["status"] == "built"
    assert Path(data["wheel_build"]["path"]).exists()
    assert Path(data["wheel_build"]["path"]).is_relative_to(dist_dir)
    assert "wheel artifact" in captured.out
    with zipfile.ZipFile(data["wheel_build"]["path"]) as archive:
        names = set(archive.namelist())
    assert "app.py" in names
    assert "_fallback_app.py" in names
    assert "rextio/runtime/flags.py" in names
    assert any(name.endswith(".dist-info/WHEEL") for name in names)
    assert any(name.endswith(".dist-info/RECORD") for name in names)


def test_build_enables_experimental_embedding_only_when_requested(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
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

def helper(x: float) -> float:
    return x * 2.0

@rextio.native
def compute(x: float) -> float:
    return helper(x) + 1.0
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--embed-helpers",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    rust_dir = tmp_path / ".rextio" / "generated" / "rust"
    lib_rs = (rust_dir / "src" / "lib.rs").read_text(encoding="utf-8")

    assert exit_code == 0
    assert "experimental helper embedding: enabled" in captured.out
    assert "embedding candidates: 1" in captured.out
    assert report["accepted_native_count"] == 1
    assert report["rejected_native_count"] == 0
    assert report["embedding_candidate_count"] == 1
    # The embedded helper compiles as a plain internal native function -
    # callable from native code, not exported, no extra dependencies.
    assert "fn app__helper(" in lib_rs
    assert "wrap_pyfunction!(app__compute" in lib_rs
    assert "wrap_pyfunction!(app__helper" not in lib_rs


def test_build_no_embed_helpers_cli_option_overrides_environment(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    monkeypatch.setenv("REXTIO_EMBED_HELPERS", "true")
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

def helper(x: int) -> int:
    return x * 2

@rextio.native
def compute(x: int) -> int:
    return helper(x) + 1
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython", "--no-embed-helpers"])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0
    assert "experimental helper embedding: disabled" in captured.out
    # With embedding disabled the helper is not embedded, but the marked
    # caller survives natively through the scalar boundary-call path.
    assert report["accepted_native_count"] == 2
    assert report["rejected_native_count"] == 0
    assert report["embedding_candidate_count"] == 0


def test_rust_executable_delegate_analysis_embeds_helpers(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
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

def helper(x: float) -> float:
    return x * 2.0

@rextio.native
def main(argv: list[str]) -> int:
    value = helper(1.0)
    return len(argv)
""",
        encoding="utf-8",
    )
    captured_executable_analysis = None

    def fake_build_hybrid_artifact(*args, **kwargs):
        nonlocal captured_executable_analysis
        captured_executable_analysis = kwargs["executable_analysis"]
        layout = ArtifactLayout(tmp_path)
        layout.reports_dir.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            accepted_native_count=1,
            rejected_native_count=0,
            plan=SimpleNamespace(native=SimpleNamespace(embedded_functions=[])),
            layout=layout,
            native_build=SimpleNamespace(status="skipped", message="ok", installed_path=None),
            rust_crate_build=SimpleNamespace(
                status="skipped",
                message="ok",
                crate_path=None,
                artifact_path=None,
            ),
            fallback_build=SimpleNamespace(status="built", message="ok"),
            executable_build=SimpleNamespace(status="skipped", message="ok", path=None),
            wheel_build=SimpleNamespace(path=None),
            plugin_crate_dependencies=(),
            artifact_evidence=None,
        )

    monkeypatch.setattr("rextio.cli.build_cmd.build_hybrid_artifact", fake_build_hybrid_artifact)

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--embed-helpers",
            "--executable-backend=rust",
            "--entrypoint=app:main",
        ]
    )

    capsys.readouterr()
    assert exit_code == 0
    assert captured_executable_analysis is not None
    functions = {
        function.name: function
        for module in captured_executable_analysis.modules
        for function in module.functions
    }
    # With embedding enabled, the unmarked scalar helper compiles INTO the binary
    # (an embedding candidate the native caller may use) instead of being
    # delegated per call over IPC.
    assert functions["helper"].is_embedding_candidate
    assert functions["main"].accepted
    assert functions["main"].delegated_call_targets == set()


def test_build_generates_rust_importable_crate_artifact(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b

def add_twice(a: int, b: int) -> int:
    return add(a, b) * 2
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--rust-build-tool=cargo",
            "--rust-importable",
            "--rust-crate-name=demo_rust",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    generated_crate = tmp_path / ".rextio" / "generated" / "rust_crate"
    dist_crate = tmp_path / "dist" / "demo_rust-rust-crate"
    lib_rs = dist_crate / "src" / "lib.rs"
    lib_source = lib_rs.read_text(encoding="utf-8")

    assert exit_code == 0
    assert "rust importable crate: built" in captured.out
    assert "rust crate source artifact:" in captured.out
    assert "rust crate build artifact:" in captured.out
    assert report["status"] == "built"
    assert report["rust_crate_build"]["status"] == "built"
    assert report["rust_crate_build"]["crate_path"] == str(dist_crate)
    assert Path(report["rust_crate_build"]["artifact_path"]).exists()
    assert (generated_crate / "Cargo.toml").exists()
    assert 'name = "demo_rust"' in (dist_crate / "Cargo.toml").read_text(encoding="utf-8")
    assert "pub fn app__add(a: i64, b: i64) -> Result<i64, RextioError>" in lib_source
    assert "pub fn app__add_twice(a: i64, b: i64) -> Result<i64, RextioError>" in lib_source
    assert "return Ok(__rextio_checked_mul(app__add(a.clone(), b.clone())?, 2)?);" in lib_source
    assert "pyo3" not in lib_source


def test_build_embeds_fallback_threshold(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython", "--fallback-threshold=4"])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    wrapper_source = (tmp_path / ".rextio" / "build" / "python" / "app.py").read_text(
        encoding="utf-8"
    )

    assert exit_code == 0
    assert "boundary fallback threshold: 4" in captured.out
    assert report["boundary_fallback_threshold"] == 4
    assert '_rextio_dispatch_capture_4("app.add", 4)' in wrapper_source


def test_build_uses_configured_threshold_and_executable_options(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "cpython"
fallback_threshold = 6

[rust]
build_tool = "cargo"

[executable]
entrypoint = "demo_cli.app:main"
name = "config-tool"
backend = "zipapp"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "demo_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
def main() -> int:
    print("config executable ok")
    return 0

def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path)])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    executable = tmp_path / "dist" / "config-tool.pyz"
    wrapper_source = (tmp_path / ".rextio" / "build" / "python" / "demo_cli" / "app.py").read_text(
        encoding="utf-8"
    )

    assert exit_code == 0
    assert "boundary fallback threshold: 6" in captured.out
    assert "executable backend: zipapp" in captured.out
    assert report["boundary_fallback_threshold"] == 6
    assert report["executable_build"]["path"] == str(executable)
    assert report["executable_build"]["entrypoint"] == "demo_cli.app:main"
    assert '_rextio_dispatch_capture_4("demo_cli.app.add", 6)' in wrapper_source


def test_build_cli_overrides_environment_and_config_options(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "8")
    monkeypatch.setenv("REXTIO_EXECUTABLE_ENTRYPOINT", "demo_cli.app:main")
    monkeypatch.setenv("REXTIO_EXECUTABLE_NAME", "env-tool")
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_threshold = 6

[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "demo_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
def main() -> int:
    return 0

def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback-threshold=4",
            "--executable-name=cli-tool",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "boundary fallback threshold: 4" in captured.out
    assert report["boundary_fallback_threshold"] == 4
    assert report["executable_build"]["path"] == str(tmp_path / "dist" / "cli-tool.pyz")
    assert report["executable_build"]["entrypoint"] == "demo_cli.app:main"


def test_build_generates_zipapp_executable(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    package = tmp_path / "src" / "demo_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
def main() -> int:
    print("zipapp ok")
    return 0
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--entrypoint=demo_cli.app:main",
            "--executable-name=demo-tool",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    executable = tmp_path / "dist" / "demo-tool.pyz"

    assert exit_code == 0
    assert "executable artifact: built" in captured.out
    assert "executable backend: zipapp" in captured.out
    assert f"executable: {executable}" in captured.out
    assert report["executable_build"]["status"] == "built"
    assert report["executable_build"]["backend"] == "zipapp"
    assert report["executable_build"]["path"] == str(executable)
    assert report["executable_build"]["entrypoint"] == "demo_cli.app:main"
    completed = subprocess.run(
        [sys.executable, str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "zipapp ok"


def test_build_generates_nuitka_standalone_executable(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "demo_nuitka_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """
def main() -> int:
    print("nuitka ok")
    return 0
""",
        encoding="utf-8",
    )
    fake_nuitka = _fake_executable_nuitka(tmp_path)
    monkeypatch.setenv("PATH", f"{fake_nuitka.parent}{os.pathsep}{fake_cargo.parent}")

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--entrypoint=demo_nuitka_cli.app:main",
            "--executable-name=demo-nuitka",
            "--executable-backend=nuitka",
            "--nuitka-mode=standalone",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    executable = tmp_path / "dist" / "demo-nuitka.dist" / "demo-nuitka"

    assert exit_code == 0
    assert "executable artifact: built" in captured.out
    assert "executable backend: nuitka" in captured.out
    assert report["executable_build"]["status"] == "built"
    assert report["executable_build"]["backend"] == "nuitka"
    assert report["executable_build"]["path"] == str(executable)
    assert report["executable_build"]["command"]
    assert "--standalone" in report["executable_build"]["command"]


def test_build_reports_missing_nuitka_for_executable(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    monkeypatch.setenv("PATH", f"{fake_cargo.parent}{os.pathsep}{Path(sys.executable).parent}")
    original_which = shutil.which

    def without_nuitka(name: str) -> str | None:
        if name == "nuitka":
            return None
        return original_which(name)

    monkeypatch.setattr("rextio.build.executable_builder.shutil.which", without_nuitka)
    (tmp_path / "app.py").write_text(
        """
def main() -> int:
    return 0
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--entrypoint=app:main",
            "--executable-backend=nuitka",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 1
    assert "Nuitka is not installed" in captured.err
    assert report["status"] == "executable-build-failed"
    assert report["executable_build"]["backend"] == "nuitka"


def test_build_reports_invalid_zipapp_entrypoint(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        """
def main() -> int:
    return 0
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--entrypoint=not-a-module"])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 1
    assert "executable artifact: failed" in captured.out
    assert "Use module:function" in captured.err
    assert report["status"] == "executable-build-failed"
    assert report["executable_build"]["status"] == "failed"


def test_build_fails_fast_when_rust_toolchain_is_missing(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    build_report = tmp_path / ".rextio" / "reports" / "build.json"

    # With no toolchain on PATH the build fails fast at the preflight check,
    # before any analysis or codegen, with actionable install guidance.
    assert exit_code == 1
    assert "RXT060 Build prerequisites are missing" in captured.err
    assert "Rust toolchain" in captured.err
    assert not build_report.exists()


def test_build_pure_python_project_succeeds_without_rust_toolchain(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
    # decorator-only discovery with no @rextio.native functions -> no native build.
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def helper(x: int) -> int:
    return x + 1
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    # A pure-Python project still builds its CPython fallback artifact even with
    # no Rust toolchain available; the native build is simply skipped.
    assert exit_code == 0
    assert report["native_build"]["status"] == "skipped"


def test_build_uses_maturin_when_available(
    tmp_path: Path,
    fake_cargo: Path,
    fake_maturin: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "maturin"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    data = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "rust build tool: maturin" in captured.out
    assert data["native_build"]["tool"] == "maturin"
    assert Path(data["native_build"]["installed_path"]).exists()


def test_build_respects_cargo_build_tool_config(
    tmp_path: Path,
    fake_cargo: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    data = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "rust build tool: cargo" in captured.out
    assert data["native_build"]["tool"] == "cargo"


def test_build_uses_configured_fallback_backend_when_argument_is_omitted(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "nuitka"
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

    exit_code = main(["build", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Nuitka fallback was requested, but Nuitka is not installed." in captured.err


def test_build_fallback_argument_overrides_config(
    tmp_path: Path,
    fake_cargo: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "nuitka"

[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    data = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "fallback: cpython" in captured.out
    assert data["fallback"] == "cpython"


def test_build_reports_unsupported_configured_fallback_backend(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "unsupported"
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Build failed while loading configuration." in captured.err
    assert "unsupported config value for [build].fallback_backend" in captured.err


def test_build_reports_unsupported_native_backend(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
native_backend = "llvm"
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Build failed while loading configuration." in captured.err
    assert "unsupported config value for [build].native_backend" in captured.err


def test_build_respects_boundary_warnings_policy(
    tmp_path: Path,
    fake_cargo: Path,
    capsys,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[policy]
boundary_warnings = false
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def score_one(x: float) -> float:
    return x * 2.0

def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(score_one(x))
    return out
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    check_report = tmp_path / ".rextio" / "reports" / "check.json"
    data = json.loads(check_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert data["accepted_native"] == ["app.score_one"]
    assert data["diagnostics"] == []


def test_build_reports_clear_error_when_nuitka_is_missing(
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

    exit_code = main(["build", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Build failed while preparing Nuitka fallback." in captured.err
    assert "Nuitka fallback was requested, but Nuitka is not installed." in captured.err
    assert "rextio build --fallback=cpython" in captured.err


def test_build_invokes_nuitka_when_requested_and_available(
    tmp_path: Path,
    fake_cargo: Path,
    fake_nuitka: Path,
    capsys,
) -> None:
    # `add` is auto-discovered as native (default native_marker="auto"), so the
    # build compiles a crate; stub cargo (like the sibling build tests) so this
    # fast-suite test exercises the Nuitka fallback path without a real, flaky
    # cargo+pyo3 compile (mod-proposal P1-10 — real toolchains belong in tests/e2e).
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    data = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "fallback: nuitka" in captured.out
    assert "fallback packaging: built" in captured.out
    assert data["fallback_build"]["backend"] == "nuitka"
    assert data["fallback_build"]["status"] == "built"
    assert data["fallback_build"]["command"]
    assert data["fallback_build"]["compiled_artifacts"]
    assert fake_nuitka.with_name("nuitka.log").exists()


def test_build_reports_codegen_failure_and_keeps_fallback(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch,
    capsys,
) -> None:
    # Stub cargo so the native preflight passes deterministically (the build is
    # only here to exercise the codegen-failure path, which is monkeypatched
    # below); avoids a real toolchain dependency in the fast suite (P1-10).
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    def fail_codegen(_module_ir, **_kwargs):
        raise RustCodegenError("synthetic codegen failure")

    monkeypatch.setattr(orchestrator, "generate_rust_module", fail_codegen)

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    python_dir = tmp_path / ".rextio" / "generated" / "python"
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    data = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert "RXT050 Codegen failure" in captured.err
    assert data["status"] == "codegen-failed"
    assert data["native_build"]["tool"] == "codegen"
    assert (python_dir / "app.py").exists()
    assert (python_dir / "_fallback_app.py").exists()


def test_rust_executable_hybrid_runtime_uses_entry_reachable_delegation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def fallback_label(value: str) -> str:
    return value.lower()

@rextio.native
def main(argv: list[str]) -> int:
    return len(argv)

@rextio.native
def unused(argv: list[str]) -> int:
    label = fallback_label(argv[0])
    return len(label)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def fake_build(crate_dir, dist_dir, binary_name, entrypoint, *, timeout, toolchain=None):
        dist_dir.mkdir(parents=True, exist_ok=True)
        binary = dist_dir / binary_name
        binary.write_text("fake binary", encoding="utf-8")
        return ExecutableBuildResult(
            status="built",
            path=str(binary),
            message="ok",
            entrypoint=entrypoint,
            backend="rust",
        )

    monkeypatch.setattr(orchestrator, "build_rust_executable", fake_build)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        "source",
        build_timeout=30,
    )

    assert result.status == "built"
    cargo_toml = (layout.rust_bin_dir / "Cargo.toml").read_text(encoding="utf-8")
    main_rs = (layout.rust_bin_src_dir / "main.rs").read_text(encoding="utf-8")
    assert "serde_json" not in cargo_toml
    assert "app__main" in main_rs
    assert "app__unused" not in main_rs
    assert not (layout.dist_dir / "app_main.runtime").exists()


def test_rust_executable_runs_authorized_initializer_before_main(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)
    monkeypatch.setattr(orchestrator, "build_rust_executable", _fake_built_rust_executable)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        FallbackStrategy.ERROR,
        build_timeout=30,
    )

    assert result.status == "built"
    closure = result.to_dict()["closure"]
    assert closure["module_initializers"] == ["app.__rextio_top_level__"]
    main_rs = (layout.rust_bin_src_dir / "main.rs").read_text(encoding="utf-8")
    init_call = "if let Err(err) = app____rextio_top_level()"
    assert main_rs.index(init_call) < main_rs.index("std::env::args_os()")
    assert main_rs.index(init_call) < main_rs.index("match app__main(argv)")


@pytest.mark.parametrize("strategy", list(FallbackStrategy))
def test_initializer_blocker_fails_before_cargo_for_every_strategy(
    tmp_path: Path,
    monkeypatch,
    strategy: FallbackStrategy,
) -> None:
    (tmp_path / "app.py").write_text(
        "seed: int = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def unexpected(*args, **kwargs):
        pytest.fail("Cargo must not run for an unavailable module initializer")

    monkeypatch.setattr(orchestrator, "build_rust_executable", unexpected)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        strategy,
        build_timeout=30,
    )

    assert result.status == "failed"
    assert result.to_dict()["closure"]["status"] == "unavailable"
    assert "module initializer" in result.message
    assert not layout.rust_bin_dir.exists()


def test_rust_executable_nuitka_dispatcher_failure_cleans_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def slugify(value: str) -> str:
    return value.lower()

@rextio.native
def main(argv: list[str]) -> int:
    label = slugify(argv[0])
    return len(label)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def fake_build(crate_dir, dist_dir, binary_name, entrypoint, *, timeout, toolchain=None):
        dist_dir.mkdir(parents=True, exist_ok=True)
        binary = dist_dir / binary_name
        binary.write_text("fake binary", encoding="utf-8")
        return ExecutableBuildResult(
            status="built",
            path=str(binary),
            message="ok",
            entrypoint=entrypoint,
            backend="rust",
        )

    monkeypatch.setattr(orchestrator, "build_rust_executable", fake_build)
    monkeypatch.setattr(
        orchestrator,
        "_build_nuitka_dispatcher",
        lambda runtime_dir, allowed_qualnames, timeout, toolchain=None: "synthetic nuitka failure",
    )

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        "nuitka",
        build_timeout=30,
    )

    assert result.status == "failed"
    assert "synthetic nuitka failure" in result.message
    assert not (layout.dist_dir / "app_main").exists()
    assert not (layout.dist_dir / "app_main.runtime").exists()


def test_hybrid_runtime_rejects_dispatcher_module_collision(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "_rextio_dispatcher.py").write_text(
        """
import rextio

@rextio.exempt
def slugify(value: str) -> str:
    return value.lower()

@rextio.native
def main(argv: list[str]) -> int:
    label = slugify(argv[0])
    return len(label)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def fake_build(crate_dir, dist_dir, binary_name, entrypoint, *, timeout, toolchain=None):
        dist_dir.mkdir(parents=True, exist_ok=True)
        binary = dist_dir / binary_name
        binary.write_text("fake binary", encoding="utf-8")
        return ExecutableBuildResult(
            status="built",
            path=str(binary),
            message="ok",
            entrypoint=entrypoint,
            backend="rust",
        )

    monkeypatch.setattr(orchestrator, "build_rust_executable", fake_build)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "_rextio_dispatcher:main",
        None,
        None,
        "source",
        build_timeout=30,
    )

    assert result.status == "failed"
    assert "conflicts with the generated dispatcher" in result.message
    assert not (layout.dist_dir / "_rextio_dispatcher_main").exists()
    assert not (layout.dist_dir / "_rextio_dispatcher_main.runtime").exists()


def test_hybrid_runtime_rejects_dispatcher_package_collision(tmp_path: Path) -> None:
    # The PACKAGE form (`_rextio_dispatcher/__init__.py`) does not overwrite the
    # generated `_rextio_dispatcher.py` file, but Python's import machinery prefers
    # the package over the sibling module of the same name, so it must be rejected
    # just like the file form.
    package = tmp_path / "_rextio_dispatcher"
    package.mkdir()
    (package / "__init__.py").write_text(
        """
import rextio

@rextio.exempt
def slugify(value: str) -> str:
    return value.lower()
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio
from _rextio_dispatcher import slugify

@rextio.native
def main(argv: list[str]) -> int:
    return len(slugify(argv[0]))
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)

    with pytest.raises(RustCodegenError, match="conflicts with the generated dispatcher"):
        orchestrator._write_hybrid_runtime(
            tmp_path / "out.runtime", analysis, {"_rextio_dispatcher.slugify"}
        )


def test_hybrid_runtime_rejects_stdlib_shadowing_module(tmp_path: Path) -> None:
    # Council round 8 (qwen): runtime_dir is sys.path[0] at dispatch time, so a
    # project module named after a module the dispatcher imports (json/os/sys/
    # importlib/types) - or the rextio package - would shadow it and crash the
    # dispatcher on its first request.
    (tmp_path / "json.py").write_text(
        """
import rextio

@rextio.exempt
def parse(value: str) -> int:
    return len(value)
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio
from json import parse

@rextio.native
def main(argv: list[str]) -> int:
    return parse(argv[0])
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)

    with pytest.raises(RustCodegenError, match="shadows a name the fallback dispatcher"):
        orchestrator._write_hybrid_runtime(tmp_path / "out.runtime", analysis, {"json.parse"})


def test_entry_reachable_graph_captures_transitive_delegation(tmp_path: Path) -> None:
    # `main -> process (accepted native) -> slugify (delegated)`: the reachable-graph
    # walk must push the native hop and record the second-hop delegated callee, so
    # codegen emits the IPC call and the dispatcher allow-list accepts it. A revert
    # that dropped the native-hop traversal would orphan the delegated call.
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def slugify(text: str) -> str:
    return text.lower()

@rextio.native
def process(text: str) -> int:
    s = slugify(text)
    return len(s)

@rextio.native
def main(argv: list[str]) -> int:
    return process(argv[0])
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)

    reachable, delegated = orchestrator._entrypoint_reachable_native_graph(analysis, "app.main")

    assert "app.main" in reachable
    assert "app.process" in reachable  # the native intermediate hop is walked
    assert delegated == {"app.slugify": "str"}  # the second-hop delegation is recorded


def _fake_executable_nuitka(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "fake-executable-nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        f"""#!{sys.executable}
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("2.4.8")
    sys.exit(0)
out = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output-dir=")))
name = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output-filename="))
out.mkdir(parents=True, exist_ok=True)
if "--onefile" in args:
    target = out / name
else:
    target = out / f"{{name}}.dist" / name
    target.parent.mkdir(parents=True, exist_ok=True)
target.write_text("#!/usr/bin/env python3\\nprint('fake nuitka executable')\\n", encoding="utf-8")
target.chmod(0o755)
""",
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    return nuitka


def test_native_build_failure_still_produces_a_fallback_wheel(tmp_path: Path) -> None:
    from rextio.build.artifact_layout import ArtifactLayout
    from rextio.build.cargo_builder import NativeBuildResult
    from rextio.fallback.build_result import FallbackBuildResult

    layout = ArtifactLayout(tmp_path)
    layout.build_python_dir.mkdir(parents=True, exist_ok=True)
    (layout.build_python_dir / "mod.py").write_text("x = 1\n", encoding="utf-8")

    native = NativeBuildResult(status="failed", tool="cargo", message="native build failed")
    fallback = FallbackBuildResult(status="built", backend="cpython", message="ok")

    result = orchestrator._build_wheel_artifact(tmp_path, layout, native, fallback)

    # The hybrid still works via the Python fallback, so packaging produces a
    # pure-Python (py3-none-any) fallback wheel rather than skipping.
    assert result.status == "built"
    assert result.path is not None
    assert result.path.endswith("-py3-none-any.whl")


def test_hybrid_nuitka_runtime_rejects_delegated_accelerated_functions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # A Nuitka-compiled dispatcher cannot serve a delegated numba function (no
    # bytecode for the accelerator, no accelerator bundled): the build must fail
    # early with guidance toward --hybrid-runtime=source.
    (tmp_path / "app.py").write_text(
        """
import rextio
from numba import njit

@njit
def scale(x: int) -> int:
    return x * 2

@rextio.native
def main(argv: list[str]) -> int:
    return scale(len(argv))
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def fake_build(crate_dir, dist_dir, binary_name, entrypoint, *, timeout, toolchain=None):
        dist_dir.mkdir(parents=True, exist_ok=True)
        binary = dist_dir / binary_name
        binary.write_text("fake binary", encoding="utf-8")
        return ExecutableBuildResult(
            status="built",
            path=str(binary),
            message="ok",
            entrypoint=entrypoint,
            backend="rust",
        )

    monkeypatch.setattr(orchestrator, "build_rust_executable", fake_build)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        "nuitka",
        build_timeout=30,
    )

    assert result.status == "failed"
    assert "project module(s) app use" in result.message
    assert "--hybrid-runtime=source" in result.message


def test_hybrid_nuitka_runtime_rejects_transitively_accelerated_modules(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The delegated function is PLAIN, but it imports a sibling module that uses
    # numba. Every project module ships in the hybrid runtime and Nuitka follows
    # imports from the delegated module into the sibling, so the compiled
    # dispatcher would still break the accelerated function at first call: the
    # guard must scan the whole runtime tree, not just delegated qualnames.
    (tmp_path / "kernels.py").write_text(
        """
from numba import njit

@njit
def scale(x: int) -> int:
    return x * 2
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio
import kernels

def lookup(x: int) -> int:
    return kernels.scale(x) + 1

@rextio.native
def main(argv: list[str]) -> int:
    return lookup(len(argv))
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    layout = ArtifactLayout(tmp_path)

    def fake_build(crate_dir, dist_dir, binary_name, entrypoint, *, timeout, toolchain=None):
        dist_dir.mkdir(parents=True, exist_ok=True)
        binary = dist_dir / binary_name
        binary.write_text("fake binary", encoding="utf-8")
        return ExecutableBuildResult(
            status="built",
            path=str(binary),
            message="ok",
            entrypoint=entrypoint,
            backend="rust",
        )

    monkeypatch.setattr(orchestrator, "build_rust_executable", fake_build)

    result = orchestrator._build_rust_executable_artifact(
        layout,
        analysis,
        "app:main",
        None,
        None,
        "nuitka",
        build_timeout=30,
    )

    assert result.status == "failed"
    assert "kernels" in result.message
    assert "--hybrid-runtime=source" in result.message


def test_build_rejects_pre_2_nuitka_before_analysis(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    # The CLI-level gate fires before project analysis: no reports are written.
    bin_dir = tmp_path / "old-nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        '#!/bin/sh\nif [ "$1" = --version ]; then echo 1.9.7; exit 0; fi\n',
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )

    exit_code = main(["build", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Nuitka 1.9.7 is too old" in captured.err
    assert not (tmp_path / ".rextio").exists()


def test_pre_2_nuitka_fails_the_hybrid_dispatcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The hybrid-runtime dispatcher path enforces the Nuitka >= 2.0 floor too.
    from rextio.build.orchestrator import _build_nuitka_dispatcher

    _old_nuitka_on_path(tmp_path, monkeypatch)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    error = _build_nuitka_dispatcher(runtime_dir, {"app.f"}, timeout=30.0)

    assert error is not None
    assert "Nuitka 1.9.7 is too old" in error
    assert ">= 2.0" in error


def _old_nuitka_on_path(tmp_path: Path, monkeypatch) -> None:
    bin_dir = tmp_path / "old-nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        '#!/bin/sh\nif [ "$1" = --version ]; then echo 1.9.7; exit 0; fi\n',
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    # Prepend rather than replace: the fake still shadows any real nuitka by
    # PATH order, while tools the build may legitimately need (python3 for
    # env-shebang fakes, cargo) stay resolvable.
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_build_rejects_pre_2_nuitka_for_executable_backend_before_analysis(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    # --executable-backend=nuitka fails as fast as --fallback=nuitka does.
    _old_nuitka_on_path(tmp_path, monkeypatch)
    (tmp_path / "app.py").write_text("def main() -> int:\n    return 0\n", encoding="utf-8")

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--entrypoint=app:main",
            "--executable-backend=nuitka",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "RXT060 Build failed while preparing the Nuitka toolchain." in captured.err
    assert "Nuitka 1.9.7 is too old" in captured.err
    assert not (tmp_path / ".rextio").exists()


def test_hybrid_runtime_with_old_nuitka_is_not_gated_before_analysis(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    # The rust-executable hybrid runtime only invokes Nuitka when analysis
    # finds delegated fallback calls, so an old Nuitka on PATH must NOT
    # reject the build up front - a no-delegation build never touches
    # Nuitka (and proceeds fine with no Nuitka installed at all). The
    # dispatcher builder enforces the floor at the point of real use
    # (see test_pre_2_nuitka_fails_the_hybrid_dispatcher).
    _old_nuitka_on_path(tmp_path, monkeypatch)
    # Put the fake cargo ahead of any real one; the old-nuitka bin stays first.
    bin_dir = tmp_path / "old-nuitka-bin"
    monkeypatch.setenv(
        "PATH", f"{bin_dir}{os.pathsep}{fake_cargo.parent}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    (tmp_path / "app.py").write_text("def main() -> int:\n    return 0\n", encoding="utf-8")

    # The exit code is deliberately not pinned: this test proves only that
    # the pre-analysis gate does not fire; the build may still fail later
    # for unrelated reasons (the fake cargo emits no runnable binary).
    main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--entrypoint=app:main",
            "--executable-backend=rust",
            "--hybrid-runtime=nuitka",
        ]
    )

    captured = capsys.readouterr()
    assert "RXT060 Build failed while preparing the Nuitka toolchain." not in captured.err
    assert "Nuitka 1.9.7 is too old" not in captured.err
    assert (tmp_path / ".rextio").exists()  # analysis ran


def test_nuitka_backend_without_entrypoint_is_not_gated(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    # Without an entrypoint the executable is skipped entirely, so an old
    # Nuitka must not fire the version gate on a plain cpython-fallback build.
    _old_nuitka_on_path(tmp_path, monkeypatch)
    # Untyped on purpose: no native candidates, so requires_native_build()
    # is False, the orchestrator skips the cargo build, and the only way to
    # fail early would be the (unwanted) version gate.
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    main(["build", str(tmp_path), "--fallback=cpython", "--executable-backend=nuitka"])

    captured = capsys.readouterr()
    assert "Nuitka 1.9.7 is too old" not in captured.err
    assert (tmp_path / ".rextio").exists()  # analysis ran


def test_configured_cargo_path_that_does_not_exist_fails_preflight(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    # A configured tool never silently falls back to PATH.
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )

    exit_code = main(["build", str(tmp_path), f"--cargo={tmp_path / 'nowhere'}"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "does not exist" in captured.err


def test_python_minor_version_mismatch_fails_before_analysis(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    fake_py = tmp_path / "py" / "bin" / "python3"
    fake_py.parent.mkdir(parents=True)
    fake_py.write_text("#!/bin/sh\necho 3.2.0 cpython\n", encoding="utf-8")
    fake_py.chmod(0o755)
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )

    exit_code = main(["build", str(tmp_path), f"--python={tmp_path / 'py'}"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "3.2" in captured.err
    assert not (tmp_path / ".rextio").exists()


def test_nuitka_version_pin_mismatch_fails_the_gate(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    bin_dir = tmp_path / "nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        '#!/bin/sh\nif [ "$1" = --version ]; then echo 2.4.8; exit 0; fi\n',
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    exit_code = main(["build", str(tmp_path), "--fallback=nuitka", "--nuitka-version=2.6"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "does not satisfy" in captured.err
    assert not (tmp_path / ".rextio").exists()


def test_toolchain_python_becomes_the_delegation_default(tmp_path: Path) -> None:
    from rextio.build.orchestrator import _delegation_python
    from rextio.config.schema import ToolchainConfig

    fake_py = tmp_path / "py" / "bin" / "python3"
    fake_py.parent.mkdir(parents=True)
    fake_py.write_text("#!/bin/sh\necho Python 3.11.9\n", encoding="utf-8")
    fake_py.chmod(0o755)

    toolchain = ToolchainConfig(python=str(tmp_path / "py"))
    assert _delegation_python(None, toolchain) == str(fake_py)
    # Explicit [executable] python still wins over the toolchain default.
    assert _delegation_python("/opt/other/python3", toolchain) == "/opt/other/python3"
    assert _delegation_python(None, None) == "python3"


def test_pinned_maturin_missing_fails_instead_of_cargo_fallback(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    # A maturin pin is strict for a native build: the maturin-missing ->
    # cargo fallback must not silently bypass it.
    monkeypatch.setenv("PATH", str(fake_cargo.parent))
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--rust-build-tool=maturin",
            "--maturin-version=1.7",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "pinned" in captured.err
    assert "maturin" in captured.err


def test_cargo_pin_is_not_probed_for_pure_python_builds(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    # No native candidates -> the cargo pin (and cargo itself) is irrelevant,
    # even when cargo is entirely absent.
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    (tmp_path / "empty-bin").mkdir()
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    exit_code = main(["build", str(tmp_path), "--cargo-version=1.85"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "1.85" not in captured.err


def test_nuitka_pin_is_enforced_at_the_hybrid_dispatcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The hybrid path is deliberately not pre-gated, so the pin must hold at
    # the point of real use.
    from rextio.build.orchestrator import _build_nuitka_dispatcher
    from rextio.config.schema import ToolchainConfig

    bin_dir = tmp_path / "nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        '#!/bin/sh\nif [ "$1" = --version ]; then echo 2.4.8; exit 0; fi\n',
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    error = _build_nuitka_dispatcher(
        runtime_dir, {"app.f"}, 30.0, ToolchainConfig(nuitka_version="2.6")
    )

    assert error is not None
    assert "does not satisfy" in error


def test_cargo_pin_holds_on_the_delegate_only_rust_executable(
    tmp_path: Path,
    monkeypatch,
    capsys,
    fake_cargo: Path,
) -> None:
    # Council-51 counterexample: an exempt helper leaves the MAIN analysis
    # with zero accepted natives (requires_native_build() is False), yet the
    # rust executable backend still compiles a bin crate with cargo. The pin
    # must hold at the point of use even though the CLI native-build gate
    # never ran.
    monkeypatch.setenv("PATH", str(fake_cargo.parent))
    (tmp_path / "app.py").write_text(
        "import rextio\n"
        "\n"
        "@rextio.exempt\n"
        "def helper(x: int) -> int:\n"
        "    return x + 1\n"
        "\n"
        "def main(argv: list[str]) -> int:\n"
        "    return helper(2)\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--executable-backend=rust",
            "--entrypoint=app:main",
            "--cargo-version=99.9",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "99.9" in captured.err


def test_build_and_generate_report_include_contract_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Additive contract_version must appear on success and failure report dicts."""
    from rextio.artifacts.profiles import (
        detect_host_target_triple as real_detect_host_target_triple,
    )
    from rextio.contract import TOOLING_CONTRACT_VERSION

    assert TOOLING_CONTRACT_VERSION == "2.8.0"

    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )

    # Failure path: artifact-profile-unavailable build report.
    def unsupported_host() -> str:
        raise ValueError("unsupported host architecture 'armv7l'")

    monkeypatch.setattr(orchestrator, "detect_host_target_triple", unsupported_host)
    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 1
    build_fail = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert build_fail["status"] == "artifact-profile-unavailable"
    assert build_fail["contract_version"] == TOOLING_CONTRACT_VERSION

    # Failure path: generate artifact-profile report.
    assert main(["generate", str(tmp_path), "--fallback=cpython"]) == 1
    gen_fail = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    assert gen_fail["status"] == "artifact-profile-unavailable"
    assert gen_fail["contract_version"] == TOOLING_CONTRACT_VERSION
    capsys.readouterr()

    # Success path: generate.json after a normal generate (host restored).
    monkeypatch.setattr(orchestrator, "detect_host_target_triple", real_detect_host_target_triple)
    assert main(["generate", str(tmp_path), "--fallback=cpython"]) == 0
    gen_ok = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    assert gen_ok.get("status") in {None, "generated"} or "native_source" in gen_ok
    assert gen_ok["contract_version"] == TOOLING_CONTRACT_VERSION

    # Parse-failure path: analysis-failed report also carries contract_version.
    bad_project = tmp_path / "parse_fail"
    bad_project.mkdir()
    (bad_project / "bad.py").write_text("def broken(\n", encoding="utf-8")
    assert main(["build", str(bad_project), "--fallback=cpython"]) == 1
    parse_fail = json.loads(
        (bad_project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert parse_fail["status"] == "analysis-failed"
    assert parse_fail["contract_version"] == TOOLING_CONTRACT_VERSION
