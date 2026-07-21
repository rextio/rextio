from __future__ import annotations

import hashlib
import importlib
import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_module
from rextio.codegen.rust.cargo import render_cargo_toml
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.ir.lowering import lower_project
from rextio.source.external_analysis import (
    ExternalSourceNativePlan,
    ExternalSourceSnapshot,
    analyze_external_source_snapshot,
)
from rextio.source.models import SourceModule, SourceOrigin


PACKAGE = "demo_pkg"
DIST = "demo-pkg"
VERSION = "1.0.0"
EXTERNAL_SOURCE = b"""\
def affine(x: int) -> int:
    return x + 1

def unused(x: int) -> int:
    return x * 2
"""


def _external_plan() -> ExternalSourceNativePlan:
    module = SourceModule(
        module_name=PACKAGE,
        path=f"distributions/{DIST}/{PACKAGE}/__init__.py",
        is_package_init=True,
        source_origin=SourceOrigin.DISTRIBUTION,
        sha256=hashlib.sha256(EXTERNAL_SOURCE).hexdigest(),
        dependency_depth=1,
        distribution=DIST,
        version=VERSION,
        license="MIT",
    )
    return analyze_external_source_snapshot(
        ExternalSourceSnapshot(module=module, source_bytes=EXTERNAL_SOURCE)
    )


def _analysis(tmp_path: Path, source: str):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(source, encoding="utf-8")
    return analyze_project(project, imports_config=_imports())


def _imports() -> ImportsConfig:
    return ImportsConfig(
        packages={
            PACKAGE: ImportPackagePolicy(
                policy="try-native",
                max_depth=1,
                distribution=DIST,
                version=VERSION,
            )
        }
    )


def test_final_direct_aliases_link_only_reachable_private_external_helper(
    tmp_path: Path,
) -> None:
    analysis = _analysis(
        tmp_path,
        """\
import demo_pkg as p
from demo_pkg import affine as f

def through_module(x: int) -> int:
    return p.affine(x)

def through_symbol(x: int) -> int:
    return f(x)
""",
    )
    try:
        linkage = importlib.import_module("rextio.source.external_linkage")
    except ModuleNotFoundError:
        linkage = None
    assert linkage is not None, "C5.2 external linkage module is not implemented"

    registry = linkage.build_external_native_registry(
        analysis,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    assert tuple(call.target for call in registry.linked_calls) == (
        "demo_pkg.affine",
        "demo_pkg.affine",
    )
    assert tuple(call.caller_qualname for call in registry.linked_calls) == (
        "app.through_module",
        "app.through_symbol",
    )
    assert tuple(function.qualname for function in registry.private_functions) == (
        "demo_pkg.affine",
    )
    assert registry.private_functions[0].embedded is True
    assert "demo_pkg" not in {module.module_name for module in analysis.modules}
    assert registry.resolve("app.through_module", 5, 11) == "demo_pkg.affine"
    assert registry.resolve("app.through_symbol", 8, 11) == "demo_pkg.affine"


def test_registry_drives_strict_reanalysis_lowering_and_private_rust_codegen(
    tmp_path: Path,
) -> None:
    first = _analysis(
        tmp_path,
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    registry = linkage.build_external_native_registry(
        first,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    strict = analyze_project(
        first.project_root,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    assert [function.qualname for function in strict.accepted_native_functions] == ["app.calculate"]
    module_ir = lower_project(strict, external_native_registry=registry)
    assert [function.qualname for function in module_ir.functions] == [
        "demo_pkg.affine",
        "app.calculate",
    ]
    rust = generate_rust_module(module_ir)
    assert rust.count("demo_pkg__affine(") == 2
    assert "wrap_pyfunction!(app__calculate, m)" in rust
    assert "wrap_pyfunction!(demo_pkg__affine, m)" not in rust


def test_registry_rejects_project_source_drift_before_private_ir_composition(
    tmp_path: Path,
) -> None:
    first = _analysis(
        tmp_path,
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    registry = linkage.build_external_native_registry(
        first,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    (first.project_root / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x) + 1
""",
        encoding="utf-8",
    )
    changed = analyze_project(
        first.project_root,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    assert changed.accepted_native_functions == []
    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        lower_project(changed, external_native_registry=registry)


def test_registry_rejects_new_function_value_escape_during_strict_reanalysis(
    tmp_path: Path,
) -> None:
    first = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    registry = linkage.build_external_native_registry(
        first,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    (first.project_root / "app.py").write_text(
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)

exported = f
""",
        encoding="utf-8",
    )
    changed = analyze_project(
        first.project_root,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        lower_project(changed, external_native_registry=registry)


def test_generated_module_runs_exact_external_runtime_guard_before_exports(
    tmp_path: Path,
) -> None:
    first = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    plans = (_external_plan(),)
    registry = linkage.build_external_native_registry(
        first,
        plans,
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    strict = analyze_project(
        first.project_root,
        imports_config=_imports(),
        external_native_registry=registry,
    )
    module_ir = lower_project(strict, external_native_registry=registry)
    guard = linkage.build_external_runtime_guard(registry, plans)

    ordinary = generate_rust_module(module_ir)
    guarded = generate_rust_module(module_ir, external_runtime_guard=guard)

    assert ordinary == generate_rust_module(module_ir, external_runtime_guard=None)
    assert ordinary != guarded
    assert '"demo-pkg"' in guarded
    assert '"1.0.0"' in guarded
    assert hashlib.sha256(EXTERNAL_SOURCE).hexdigest() in guarded
    assert '"demo_pkg"' in guarded
    assert '"demo_pkg.affine"' in guarded
    assert "importlib.metadata" in guarded
    assert "std::fs::read" in guarded
    assert "is_instance_of::<pyo3::types::PyFunction>" in guarded
    source_read = guarded.index("std::fs::read(&expected_path_0)")
    external_import = guarded.index('PyModule::import(py, "demo_pkg")')
    assert source_read < external_import
    guard_call = guarded.index("__rextio_verify_external_source(m.py())?")
    first_export = guarded.index("m.add_function(")
    assert guard_call < first_export


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required")
def test_generated_external_runtime_guard_compiles_with_supported_pyo3(
    tmp_path: Path,
) -> None:
    first = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    plans = (_external_plan(),)
    registry = linkage.build_external_native_registry(
        first,
        plans,
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    strict = analyze_project(
        first.project_root,
        imports_config=_imports(),
        external_native_registry=registry,
    )
    module_ir = lower_project(strict, external_native_registry=registry)
    guard = linkage.build_external_runtime_guard(registry, plans)

    crate = tmp_path / "guard-crate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(render_cargo_toml(), encoding="utf-8")
    (crate / "src" / "lib.rs").write_text(
        generate_rust_module(module_ir, external_runtime_guard=guard),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["cargo", "check", "--quiet"],
        cwd=crate,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_external_runtime_guard_models_reject_codegen_injection() -> None:
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(ValueError, match="callable identity"):
        linkage.ExternalRuntimeCallable(
            name="affine",
            qualname="demo_pkg.affine",
            first_line='1); panic!("injected")',
        )
    callable_identity = linkage.ExternalRuntimeCallable(
        name="affine",
        qualname="demo_pkg.affine",
        first_line=1,
    )
    with pytest.raises(ValueError, match="module identity"):
        linkage.ExternalRuntimeModule(
            module_name="demo_pkg",
            source_member="../escape.py",
            source_sha256="0" * 64,
            callables=(callable_identity,),
        )


@pytest.mark.parametrize(
    "source",
    (
        """\
from demo_pkg import affine as f
f = abs

def calculate(x: int) -> int:
    return f(x)
""",
        """\
if True:
    from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
        """\
from demo_pkg import affine as f
del f

def calculate(x: int) -> int:
    return f(x)
""",
        """\
from demo_pkg import *

def calculate(x: int) -> int:
    return affine(x)
""",
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return getattr(p, "affine")(x)
""",
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    f = abs
    return f(x)
""",
        """\
import demo_pkg as p
p.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x, x)
""",
        """\
from demo_pkg import affine as f

def calculate(x: str) -> int:
    return f(x)
""",
    ),
)
def test_registry_rejects_ambiguous_or_incompatible_external_calls(
    tmp_path: Path,
    source: str,
) -> None:
    analysis = _analysis(tmp_path, source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(linkage.ExternalLinkageError, match="external-linkage-"):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_rejects_tampered_external_plan(tmp_path: Path) -> None:
    linkage = importlib.import_module("rextio.source.external_linkage")
    plan = _external_plan()
    object.__setattr__(plan, "semantic_sha256", "0" * 64)
    analysis = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-analysis-stale",
    ):
        linkage.build_external_native_registry(
            analysis,
            (plan,),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "source",
    (
        """\
from demo_pkg import affine as f
exported = f

def calculate(x: int) -> int:
    return f(x)
""",
        """\
import demo_pkg as p
dynamic = getattr(p, "affine")

def calculate(x: int) -> int:
    return p.affine(x)
""",
        """\
from demo_pkg import affine as f

def escape() -> object:
    return f

def calculate(x: int) -> int:
    return f(x)
""",
    ),
)
def test_registry_rejects_external_function_value_escape(
    tmp_path: Path,
    source: str,
) -> None:
    analysis = _analysis(tmp_path, source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-escaped|no-reachable-helper)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_rejects_duplicate_caller_qualname(tmp_path: Path) -> None:
    analysis = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)

def calculate(x: int) -> int:
    return f(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-caller-duplicate",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_rejects_duplicate_call_position(tmp_path: Path) -> None:
    analysis = _analysis(
        tmp_path,
        """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
    )
    function = analysis.modules[0].functions[0]
    function.calls.append(function.calls[0])
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-call-position-duplicate",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_rejects_project_module_shadowing_external_package(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "demo_pkg.py").write_text(
        """\
def affine(x: int) -> int:
    return x + 99
""",
        encoding="utf-8",
    )
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-shadow",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )
