from __future__ import annotations

import ast
import base64
import hashlib
import importlib
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.generator import generate_rust_module
from rextio.codegen.rust.cargo import render_cargo_config_toml, render_cargo_toml
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.ir.lowering import lower_project
from rextio.source.external import MAX_FILE_BYTES
from rextio.source.external_analysis import (
    ExternalSourceNativePlan,
    ExternalSourceSnapshot,
    analyze_external_source_snapshot,
)
from rextio.source.models import SourceModule, SourceOrigin
from rextio.source.wheel_authority import (
    SourceWheelArchiveIdentity,
    SourceWheelEntryIdentity,
    VerifiedSourceWheel,
    detect_source_wheel_license_payloads,
)


PACKAGE = "demo_pkg"
DIST = "demo-pkg"
VERSION = "1.0.0"
EXTERNAL_SOURCE = b"""\
def affine(x: int) -> int:
    return x + 1

def unused(x: int) -> int:
    return x * 2
"""
EXTERNAL_METADATA = b"Metadata-Version: 2.4\nName: demo-pkg\nVersion: 1.0.0\n"
EXTERNAL_WHEEL = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
EXTERNAL_LICENSE = b"test license payload"
DIST_INFO = "demo_pkg-1.0.0.dist-info"


def _record_digest(payload: bytes) -> str:
    return (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
        .decode("ascii")
        .rstrip("=")
    )


def _external_record() -> bytes:
    rows = (
        (f"{PACKAGE}/__init__.py", _record_digest(EXTERNAL_SOURCE), len(EXTERNAL_SOURCE)),
        (f"{DIST_INFO}/METADATA", _record_digest(EXTERNAL_METADATA), len(EXTERNAL_METADATA)),
        (f"{DIST_INFO}/WHEEL", _record_digest(EXTERNAL_WHEEL), len(EXTERNAL_WHEEL)),
        (f"{DIST_INFO}/licenses/LICENSE", _record_digest(EXTERNAL_LICENSE), len(EXTERNAL_LICENSE)),
        (f"{DIST_INFO}/RECORD", "", ""),
    )
    return "".join(f"{name},{digest},{size}\n" for name, digest, size in rows).encode()


def _runtime_record() -> bytes:
    rows = (
        (f"{PACKAGE}/__init__.py", _record_digest(EXTERNAL_SOURCE), len(EXTERNAL_SOURCE)),
        (f"{DIST_INFO}/METADATA", _record_digest(EXTERNAL_METADATA), len(EXTERNAL_METADATA)),
        (f"{DIST_INFO}/RECORD", "", ""),
    )
    return "".join(f"{name},{digest},{size}\n" for name, digest, size in rows).encode()


def _wheel_entry(path: str, payload: bytes) -> SourceWheelEntryIdentity:
    return SourceWheelEntryIdentity(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        compressed_size=len(payload),
        crc32="00000000",
        unix_mode=stat.S_IFREG | 0o644,
    )


def _verified_wheel() -> VerifiedSourceWheel:
    record = _external_record()
    payloads = {
        f"{PACKAGE}/__init__.py": EXTERNAL_SOURCE,
        f"{DIST_INFO}/METADATA": EXTERNAL_METADATA,
        f"{DIST_INFO}/RECORD": record,
        f"{DIST_INFO}/WHEEL": EXTERNAL_WHEEL,
        f"{DIST_INFO}/licenses/LICENSE": EXTERNAL_LICENSE,
    }
    license_paths = (f"{DIST_INFO}/licenses/LICENSE",)
    license_payloads = (EXTERNAL_LICENSE,)
    return VerifiedSourceWheel(
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
        license_observed="MIT",
        archive=SourceWheelArchiveIdentity(
            "demo_pkg-1.0.0-py3-none-any.whl",
            "0" * 64,
            1,
        ),
        entries=tuple(_wheel_entry(path, payloads[path]) for path in sorted(payloads)),
        source_entry_paths=(f"{PACKAGE}/__init__.py",),
        metadata_entry_paths=tuple(
            sorted(
                (
                    f"{DIST_INFO}/METADATA",
                    f"{DIST_INFO}/RECORD",
                    f"{DIST_INFO}/WHEEL",
                    *license_paths,
                )
            )
        ),
        license_entry_paths=license_paths,
        snapshots=(_external_plan().snapshot,),
        license_payloads=license_payloads,
        license_detection=detect_source_wheel_license_payloads(
            license_paths,
            license_payloads,
        ),
    )


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


def test_project_and_external_functions_cannot_share_one_native_symbol(
    tmp_path: Path,
) -> None:
    external_module = "demo.pkg"
    external_package = "demo"
    external_plan = analyze_external_source_snapshot(
        ExternalSourceSnapshot(
            module=SourceModule(
                module_name=external_module,
                path=f"distributions/{DIST}/demo/pkg.py",
                is_package_init=False,
                source_origin=SourceOrigin.DISTRIBUTION,
                sha256=hashlib.sha256(EXTERNAL_SOURCE).hexdigest(),
                dependency_depth=1,
                distribution=DIST,
                version=VERSION,
                license="MIT",
            ),
            source_bytes=EXTERNAL_SOURCE,
        )
    )
    imports = ImportsConfig(
        packages={
            external_package: ImportPackagePolicy(
                policy="try-native",
                max_depth=1,
                distribution=DIST,
                version=VERSION,
            )
        }
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "demo__pkg.py").write_text(
        """\
from demo.pkg import affine as f

def affine(x: int) -> int:
    return x + 2

def calculate(x: int) -> int:
    return f(x) + affine(x)
""",
        encoding="utf-8",
    )
    first = analyze_project(project, imports_config=imports)
    linkage = importlib.import_module("rextio.source.external_linkage")
    registry = linkage.build_external_native_registry(
        first,
        (external_plan,),
        package=external_package,
        distribution=DIST,
        version=VERSION,
    )
    strict = analyze_project(
        project,
        imports_config=imports,
        external_native_registry=registry,
    )

    module_ir = lower_project(strict, external_native_registry=registry)

    with pytest.raises(
        RustCodegenError,
        match=(
            "native Rust symbol collision: 'demo.pkg.affine', "
            "'demo__pkg.affine' all lower to 'demo__pkg__affine'"
        ),
    ):
        generate_rust_module(module_ir)


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
    guard = linkage.build_external_runtime_guard(registry, plans, _verified_wheel())

    assert guard.dist_info_root == DIST_INFO
    assert guard.metadata_member == f"{DIST_INFO}/METADATA"
    assert guard.metadata_sha256 == hashlib.sha256(EXTERNAL_METADATA).hexdigest()
    assert guard.metadata_size == len(EXTERNAL_METADATA)
    assert guard.record_member == f"{DIST_INFO}/RECORD"

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
    assert 'link_name = "openat"' in guarded
    assert '.open(std::path::Path::new("/"))' in guarded
    assert ".open(path)" not in guarded
    assert "for component in raw[1..].split('/')" in guarded
    assert "__rextio_open_external_at(&directory, component, true)?" in guarded
    assert "__rextio_open_external_root(root)?" in guarded
    assert "__rextio_open_external_at(&directory, part" in guarded
    assert "__REXTIO_O_NOFOLLOW" in guarded
    assert "__REXTIO_O_NONBLOCK" in guarded
    assert "flags |= __REXTIO_O_NONBLOCK" in guarded
    assert "before.nlink() != 1" in guarded
    assert "before.dev() != after.dev()" in guarded
    assert "before.ino() != after.ino()" in guarded
    assert ".take(maximum_size + 1)" in guarded
    assert "if !root_path.is_absolute()" in guarded
    assert 'distribution.getattr("files")' not in guarded
    assert 'distribution.getattr("metadata")' not in guarded
    assert 'distribution.getattr("version")' not in guarded
    assert 'call_method1("read_text"' not in guarded
    assert "installed_members" not in guarded
    assert "__REXTIO_EXTERNAL_RECORD_MAX_BYTES" in guarded
    assert "__REXTIO_EXTERNAL_RECORD_MAX_ROWS" in guarded
    assert "__rextio_parse_external_record" in guarded
    assert f'"{DIST_INFO}/METADATA"' in guarded
    assert f'"{DIST_INFO}/RECORD"' in guarded
    assert 'PyModule::import(py, "demo_pkg")' not in guarded
    assert "is_instance_of::<pyo3::types::PyFunction>" not in guarded
    assert 'getattr("__code__")' not in guarded
    assert 'getattr("__file__")' not in guarded
    guard_call = guarded.index("__rextio_verify_external_source(m.py())?")
    first_export = guarded.index("m.add_function(")
    assert guard_call < first_export


def test_external_runtime_guard_never_executes_preloaded_external_module(
    tmp_path: Path,
) -> None:
    """A poisoned sys.modules entry is irrelevant because no external import exists."""
    linkage = importlib.import_module("rextio.source.external_linkage")
    guard = linkage.build_external_runtime_guard(
        linkage.build_external_native_registry(
            _analysis(
                tmp_path,
                """\
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
            ),
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        ),
        (_external_plan(),),
        _verified_wheel(),
    )

    rendered = importlib.import_module(
        "rextio.codegen.rust.external_runtime_guard"
    ).render_external_runtime_guard(guard)

    assert 'PyModule::import(py, "demo_pkg")' not in rendered
    assert 'getattr("affine")' not in rendered
    assert "_signed_callable_0_0" in rendered


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
    guard = linkage.build_external_runtime_guard(registry, plans, _verified_wheel())

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
        env={**os.environ, "PYO3_PYTHON": sys.executable},
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.fixture(scope="module")
def compiled_external_runtime_guard(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is required")
    root = tmp_path_factory.mktemp("external-runtime-guard")
    first = _analysis(
        root,
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
    guard = linkage.build_external_runtime_guard(registry, plans, _verified_wheel())
    crate = root / "crate"
    (crate / "src").mkdir(parents=True)
    (crate / ".cargo").mkdir()
    (crate / "Cargo.toml").write_text(render_cargo_toml(), encoding="utf-8")
    (crate / ".cargo" / "config.toml").write_text(
        render_cargo_config_toml(),
        encoding="utf-8",
    )
    (crate / "src" / "lib.rs").write_text(
        generate_rust_module(module_ir, external_runtime_guard=guard),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=crate,
        env={**os.environ, "PYO3_PYTHON": sys.executable},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    native_suffix = ".dylib" if sys.platform == "darwin" else ".so"
    artifact = crate / "target" / "debug" / f"lib_rextio_native{native_suffix}"
    assert artifact.is_file()
    extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    assert isinstance(extension_suffix, str) and extension_suffix
    extension = root / f"_rextio_native{extension_suffix}"
    shutil.copyfile(artifact, extension)
    return extension


@pytest.mark.parametrize(
    ("source_kind", "root_kind", "expect_success"),
    (
        ("regular", "canonical", True),
        ("symlink", "canonical", False),
        ("hardlink", "canonical", False),
        pytest.param(
            "fifo",
            "canonical",
            False,
            marks=pytest.mark.skipif(
                not hasattr(os, "mkfifo"),
                reason="FIFO creation is POSIX-only",
            ),
        ),
        ("changed", "canonical", False),
        ("record-missing", "canonical", False),
        ("record-duplicate", "canonical", False),
        ("record-alias", "canonical", False),
        ("record-malformed", "canonical", False),
        ("record-too-many", "canonical", False),
        ("record-oversized", "canonical", False),
        ("regular", "root-symlink", False),
        ("regular", "ancestor-symlink", False),
    ),
    ids=(
        "canonical",
        "source-symlink",
        "source-hardlink",
        "source-fifo",
        "source-changed",
        "record-missing",
        "record-duplicate",
        "record-alias",
        "record-malformed",
        "record-too-many",
        "record-oversized",
        "root-symlink",
        "ancestor-symlink",
    ),
)
def test_compiled_runtime_guard_rejects_unsafe_source_without_external_execution(
    tmp_path: Path,
    compiled_external_runtime_guard: Path,
    source_kind: str,
    root_kind: str,
    expect_success: bool,
) -> None:
    physical_parent = tmp_path / "physical-parent"
    site = physical_parent / "site-packages"
    package = site / PACKAGE
    dist_info = site / "demo_pkg-1.0.0.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    source = package / "__init__.py"
    if source_kind in {"symlink", "hardlink"}:
        payload = tmp_path / "exact-source.py"
        payload.write_bytes(EXTERNAL_SOURCE)
        if source_kind == "symlink":
            source.symlink_to(payload)
        else:
            os.link(payload, source)
    elif source_kind == "fifo":
        os.mkfifo(source)
    elif source_kind == "changed":
        source.write_bytes(EXTERNAL_SOURCE.replace(b"x + 1", b"x - 1"))
    else:
        source.write_bytes(EXTERNAL_SOURCE)
    (dist_info / "METADATA").write_bytes(EXTERNAL_METADATA)
    record = _runtime_record()
    source_row = record.splitlines(keepends=True)[0]
    if source_kind == "record-missing":
        record = b"".join(record.splitlines(keepends=True)[1:])
    elif source_kind == "record-duplicate":
        record = source_row + record
    elif source_kind == "record-alias":
        record = record.replace(b"demo_pkg/__init__.py", b"DEMO_PKG/__INIT__.PY")
    elif source_kind == "record-malformed":
        record = b"demo_pkg/__init__.py,only-two-fields\n"
    elif source_kind == "record-too-many":
        record += b"".join(
            f"extra/{index}.py,,\n".encode("ascii") for index in range(4094)
        )
    elif source_kind == "record-oversized":
        record = b"x" * (8 * 1024 * 1024 + 1)
    (dist_info / "RECORD").write_bytes(record)
    runtime_site = site
    if root_kind == "root-symlink":
        runtime_site = tmp_path / "site-packages-alias"
        runtime_site.symlink_to(site, target_is_directory=True)
    elif root_kind == "ancestor-symlink":
        alias = tmp_path / "parent-alias"
        alias.symlink_to(physical_parent, target_is_directory=True)
        runtime_site = alias / site.name
    marker = tmp_path / "external-python-was-touched"
    script = f"""
import importlib.util
from pathlib import Path
import sys
import types

marker = Path({str(marker)!r})
class Poison(types.ModuleType):
    def __getattribute__(self, name):
        if name in {{"__file__", "__dict__", "affine"}}:
            marker.write_text(name, encoding="utf-8")
        return super().__getattribute__(name)

sys.modules["demo_pkg"] = Poison("demo_pkg")
sys.path.insert(0, {str(runtime_site)!r})
spec = importlib.util.spec_from_file_location(
    "_rextio_native", {str(compiled_external_runtime_guard)!r}
)
loaded = False
failure = None
try:
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded = True
except BaseException as error:
    failure = repr(error)
if loaded != {expect_success!r}:
    raise SystemExit(f"unexpected load result: loaded={{loaded}} failure={{failure}}")
if not loaded and "RXT060 external source runtime identity verification failed" not in (failure or ""):
    raise SystemExit(f"unexpected guard failure: {{failure}}")
if marker.exists():
    raise SystemExit(f"external module was touched: {{marker.read_text()}}")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=5 if source_kind == "fifo" else 30,
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
            source_size=1,
            callables=(callable_identity,),
        )

    for invalid_size in (0, MAX_FILE_BYTES + 1):
        with pytest.raises(ValueError, match="module identity"):
            linkage.ExternalRuntimeModule(
                module_name="demo_pkg",
                source_member="demo_pkg/__init__.py",
                source_sha256="0" * 64,
                source_size=invalid_size,
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


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            """\
import demo_pkg as p
p.__dict__["affine"] = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-dict-subscript-assign",
        ),
        pytest.param(
            """\
import demo_pkg as p
del p.__dict__["affine"]

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-dict-subscript-delete",
        ),
        pytest.param(
            """\
import demo_pkg as p
p.__dict__.update({"affine": abs})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-dict-update",
        ),
        pytest.param(
            """\
import demo_pkg
demo_pkg.__dict__["affine"] = abs

def calculate(x: int) -> int:
    return demo_pkg.affine(x)
""",
            id="direct-module-dict-subscript-assign",
        ),
        pytest.param(
            """\
import demo_pkg
del demo_pkg.__dict__["affine"]

def calculate(x: int) -> int:
    return demo_pkg.affine(x)
""",
            id="direct-module-dict-subscript-delete",
        ),
        pytest.param(
            """\
import demo_pkg
demo_pkg.__dict__.update({"affine": abs})

def calculate(x: int) -> int:
    return demo_pkg.affine(x)
""",
            id="direct-module-dict-update",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f
f.__globals__["f"] = abs

def calculate(x: int) -> int:
    return f(x)
""",
            id="callable-globals-subscript-assign",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f
del f.__globals__["f"]

def calculate(x: int) -> int:
    return f(x)
""",
            id="callable-globals-subscript-delete",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f
f.__globals__.update({"f": abs})

def calculate(x: int) -> int:
    return f(x)
""",
            id="callable-globals-update",
        ),
        pytest.param(
            """\
import demo_pkg as p
vars(p)["affine"] = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="vars-module-mutation",
        ),
        pytest.param(
            """\
import demo_pkg as p
escaped = vars(p)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="vars-module-escape",
        ),
        pytest.param(
            """\
import demo_pkg as p
setattr(p, "affine", abs)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="setattr-module",
        ),
        pytest.param(
            """\
import demo_pkg as p
delattr(p, "affine")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="delattr-module",
        ),
        pytest.param(
            """\
import demo_pkg
setattr(demo_pkg, "affine", abs)

def calculate(x: int) -> int:
    return demo_pkg.affine(x)
""",
            id="setattr-direct-module",
        ),
        pytest.param(
            """\
import demo_pkg
delattr(demo_pkg, "affine")

def calculate(x: int) -> int:
    return demo_pkg.affine(x)
""",
            id="delattr-direct-module",
        ),
        pytest.param(
            """\
import importlib
import demo_pkg as p
importlib.reload(p)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="importlib-reload-module",
        ),
        pytest.param(
            """\
from importlib import reload as reload_module
import demo_pkg as p
reload_module(p)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="importlib-reload-alias",
        ),
        pytest.param(
            """\
import demo_pkg as p
retained = [p]

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-container-retention",
        ),
        pytest.param(
            """\
import demo_pkg as p
retained = [None]
retained[0] = p

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-subscript-retention",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f
retained = {"callable": f}

def calculate(x: int) -> int:
    return f(x)
""",
            id="callable-container-retention",
        ),
        pytest.param(
            """\
import demo_pkg as p

def retain(value: object) -> None:
    return None

retain(p)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="module-arbitrary-call-argument",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f

def retain(value: object) -> None:
    return None

retain(f)

def calculate(x: int) -> int:
    return f(x)
""",
            id="callable-arbitrary-call-argument",
        ),
        pytest.param(
            """\
import demo_pkg as p
globals()["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="globals-subscript-rebind",
        ),
        pytest.param(
            """\
import demo_pkg as p
globals().update({"p": object()})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="globals-update-rebind",
        ),
        pytest.param(
            """\
import demo_pkg as p
namespace = locals()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="locals-namespace-escape",
        ),
        pytest.param(
            """\
import demo_pkg as p
locals()["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="locals-namespace-mutation",
        ),
        pytest.param(
            """\
import demo_pkg as p
namespace = vars()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="vars-namespace-escape",
        ),
        pytest.param(
            """\
import demo_pkg as p
vars().update({"p": object()})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="vars-namespace-mutation",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p
sys.modules["demo_pkg"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-modules-rebind",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p
del sys.modules["demo_pkg"]

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-modules-delete",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p
sys.modules.update({"demo_pkg": object()})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-modules-update",
        ),
        pytest.param(
            """\
import builtins
import demo_pkg as p
builtins.__dict__["__import__"]("demo_pkg")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="builtins-dict-import",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p
sys.__dict__["modules"]["demo_pkg"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-dict-modules-rebind",
        ),
        pytest.param(
            """\
import importlib
import demo_pkg as p
importlib.__dict__["reload"](p)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="importlib-dict-reload",
        ),
        pytest.param(
            """\
import builtins
import demo_pkg as p
getattr(builtins, "__dict__")["globals"]()["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="getattr-builtins-dict",
        ),
        pytest.param(
            """\
import builtins
import demo_pkg as p
object.__getattribute__(builtins, "__dict__")["globals"]()["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="object-getattribute-builtins-dict",
        ),
        pytest.param(
            """\
import demo_pkg as p
exec("p = object()")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="exec-rebind",
        ),
        pytest.param(
            """\
import demo_pkg as p
eval("globals().__setitem__('p', object())")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="eval-rebind",
        ),
    ),
)
def test_registry_rejects_indirect_external_binding_mutation_or_escape(
    tmp_path: Path,
    source: str,
) -> None:
    analysis = _analysis(tmp_path, source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            """\
from demo_pkg import affine as f

def mutate() -> None:
    global f
    from builtins import abs as f

def calculate(x: int) -> int:
    return f(x)
""",
            id="global-import-from-rebind",
        ),
        pytest.param(
            """\
import demo_pkg as p

def mutate() -> None:
    global p
    import builtins as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="global-import-rebind",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f

def mutate() -> None:
    global f
    def f(x: int) -> int:
        return x

def calculate(x: int) -> int:
    return f(x)
""",
            id="global-function-rebind",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f

def mutate() -> None:
    global f
    class f:
        pass

def calculate(x: int) -> int:
    return f(x)
""",
            id="global-class-rebind",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f

def mutate() -> None:
    global f
    try:
        raise ValueError
    except Exception as f:
        pass

def calculate(x: int) -> int:
    return f(x)
""",
            id="global-exception-rebind",
        ),
        pytest.param(
            """\
from demo_pkg import affine as f

def mutate(value: object) -> None:
    global f
    match value:
        case f:
            pass

def calculate(x: int) -> int:
    return f(x)
""",
            id="global-pattern-rebind",
        ),
    ),
)
def test_registry_rejects_non_name_global_binders_of_external_alias(
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


def test_external_binding_binder_gate_rejects_nonlocal_alias() -> None:
    linkage = importlib.import_module("rextio.source.external_linkage")
    tree = ast.parse(
        """\
def outer() -> object:
    f = object()
    def mutate() -> None:
        nonlocal f
        from builtins import abs as f
    return mutate
"""
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-target-escaped",
    ):
        linkage._require_no_sensitive_non_name_binders(tree, frozenset({"f"}))


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            """\
import sys
import demo_pkg as p

def mutate() -> None:
    sys._getframe().f_globals["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-getframe-globals",
        ),
        pytest.param(
            """\
from inspect import currentframe as frame
import demo_pkg as p

def mutate() -> None:
    frame().f_globals.update({"p": object()})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="inspect-currentframe-globals",
        ),
        pytest.param(
            """\
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    anchor.__globals__["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="project-callable-globals",
        ),
        pytest.param(
            """\
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    getattr(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="getattr-project-callable-globals",
        ),
        pytest.param(
            """\
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    object.__getattribute__(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="object-getattribute-project-callable-globals",
        ),
        pytest.param(
            """\
import demo_pkg as p

def mutate() -> None:
    try:
        1 / 0
    except Exception as error:
        error.__traceback__.tb_frame.f_globals["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="traceback-frame-globals",
        ),
        pytest.param(
            """\
import inspect
import demo_pkg as p

def mutate() -> None:
    inspect.stack()[0].frame.f_globals["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="inspect-stack-frame-globals",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p

def mutate() -> None:
    next(iter(sys._current_frames().values())).f_globals["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-current-frames-globals",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p

def mutate() -> None:
    try:
        1 / 0
    except Exception:
        sys.exc_info()[2].tb_frame.f_globals["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-exc-info-traceback-frame",
        ),
        pytest.param(
            """\
import sys
import demo_pkg as p

def trace(frame: object, event: str, argument: object) -> object:
    frame.f_globals["p"] = object()
    return trace

def mutate() -> None:
    sys.settrace(trace)

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="sys-settrace-frame-callback",
        ),
        pytest.param(
            """\
from operator import attrgetter
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    attrgetter("__globals__")(anchor)["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="operator-attrgetter-callable-globals",
        ),
        pytest.param(
            """\
import inspect
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    inspect.getmodule(anchor).p = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="inspect-getmodule-owner",
        ),
        pytest.param(
            """\
import inspect
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)

def mutate() -> None:
    inspect.getclosurevars(calculate).globals["p"] = object()
""",
            id="inspect-getclosurevars-globals",
        ),
        pytest.param(
            """\
import inspect
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    dict(inspect.getmembers(anchor))["__globals__"]["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="inspect-getmembers-callable-globals",
        ),
        pytest.param(
            """\
import inspect
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    inspect.getattr_static(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="inspect-getattr-static-callable-globals",
        ),
        pytest.param(
            """\
from operator import methodcaller
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    methodcaller("__getattribute__", "__globals__")(anchor)["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="operator-methodcaller-callable-globals",
        ),
        pytest.param(
            """\
import gc
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    for namespace in gc.get_referrers(anchor):
        if isinstance(namespace, dict):
            namespace["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="gc-referrers-module-namespace",
        ),
        pytest.param(
            """\
import ctypes
import demo_pkg as p

def mutate() -> object:
    return ctypes.pythonapi.PyEval_GetFrame

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="ctypes-pythonapi-frame",
        ),
    ),
)
def test_registry_rejects_indirect_frame_and_callable_namespace_routes(
    tmp_path: Path,
    source: str,
) -> None:
    analysis = _analysis(tmp_path, source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "source",
    (
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __dict__ as namespace

def mutate() -> None:
    namespace["affine"] = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="external-module-dict-mutation",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __dict__ as namespace

def mutate() -> None:
    namespace.update({"affine": abs})

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="external-module-dict-update",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __dict__ as namespace

def escaped() -> object:
    return namespace

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="external-module-dict-escape",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __globals__ as namespace

def escaped() -> object:
    return namespace

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="external-module-globals-escape",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __dict__ as unused_namespace

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="unused-external-module-dict-binding",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import __builtins__ as unused_namespace

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="unused-external-builtins-binding",
        ),
        pytest.param(
            """\
import demo_pkg as p
from demo_pkg import unused as leaked_callable

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="unused-external-callable-binding",
        ),
        pytest.param(
            """\
import demo_pkg as unused_module
from demo_pkg import affine as f

def calculate(x: int) -> int:
    return f(x)
""",
            id="unused-external-module-binding",
        ),
    ),
)
def test_registry_rejects_imported_external_namespace_containers(
    tmp_path: Path,
    source: str,
) -> None:
    analysis = _analysis(tmp_path, source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "mutator_source",
    (
        pytest.param("import app\napp.p = object()\n", id="attribute-assign"),
        pytest.param(
            'import app\napp.__dict__["p"] = object()\n',
            id="module-dict-assign",
        ),
        pytest.param(
            'import app\nsetattr(app, "p", object())\n',
            id="setattr-assign",
        ),
        pytest.param(
            """\
from app import p as sibling

def mutate() -> None:
    sibling.affine = abs
""",
            id="imported-sibling-mutation",
        ),
        pytest.param("import app\nretained = app\n", id="owner-module-escape"),
        pytest.param(
            """\
from app import __dict__ as namespace

def mutate() -> None:
    namespace["p"] = object()
""",
            id="owner-namespace-mutation",
        ),
        pytest.param("import app\n", id="unused-owner-module-binding"),
    ),
)
def test_registry_rejects_cross_project_module_external_binding_mutation_or_escape(
    tmp_path: Path,
    mutator_source: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "mutator.py").write_text(mutator_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    ("bridge_source", "mutator_source"),
    (
        pytest.param(
            "from importlib import import_module as recover\n",
            """\
from bridge import recover

def mutate() -> None:
    recover("demo_pkg")
""",
            id="importlib-import-module",
        ),
        pytest.param(
            "from builtins import globals as recover\n",
            """\
from bridge import recover

def mutate() -> None:
    recover()
""",
            id="builtins-globals",
        ),
        pytest.param(
            "from builtins import vars as recover\n",
            """\
from bridge import recover

def mutate() -> None:
    recover()
""",
            id="builtins-vars",
        ),
        pytest.param(
            "from sys import modules as loaded_modules\n",
            """\
from bridge import loaded_modules

def mutate() -> None:
    loaded_modules["demo_pkg"].affine = abs
""",
            id="sys-modules",
        ),
        pytest.param(
            "from pkgutil import get_loader as recover\n",
            """\
from bridge import recover

def mutate() -> None:
    recover("demo_pkg")
""",
            id="pkgutil-get-loader",
        ),
        pytest.param(
            "from importlib.util import find_spec as recover\n",
            """\
from bridge import recover

def mutate() -> None:
    recover("demo_pkg")
""",
            id="importlib-find-spec",
        ),
        pytest.param(
            "def anchor() -> int:\n    return 0\n",
            """\
from bridge import __builtins__ as namespace

def mutate() -> None:
    namespace["__import__"]("demo_pkg").affine = abs
""",
            id="implicit-module-builtins",
        ),
        pytest.param(
            "def anchor() -> int:\n    return 0\n",
            """\
from bridge import __dict__ as namespace

def mutate() -> None:
    namespace["__builtins__"]["__import__"]("demo_pkg").affine = abs
""",
            id="implicit-module-dict",
        ),
    ),
)
def test_registry_rejects_cross_project_dynamic_capability_reexports(
    tmp_path: Path,
    bridge_source: str,
    mutator_source: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "bridge.py").write_text(bridge_source, encoding="utf-8")
    (project / "mutator.py").write_text(mutator_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    ("package_source", "mutator_source"),
    (
        pytest.param(
            "from .bridge import __builtins__ as namespace\n",
            """\
from pkg import namespace

def mutate() -> None:
    namespace["__import__"]("demo_pkg").affine = abs
""",
            id="builtins",
        ),
        pytest.param(
            "from .bridge import __dict__ as namespace\n",
            """\
from pkg import namespace

def mutate() -> None:
    namespace["__builtins__"]["__import__"]("demo_pkg").affine = abs
""",
            id="dict-nested-builtins",
        ),
    ),
)
def test_registry_rejects_package_init_multihop_implicit_namespace_reexports(
    tmp_path: Path,
    package_source: str,
    mutator_source: str,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (package / "bridge.py").write_text(
        "def anchor() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(package_source, encoding="utf-8")
    (project / "mutator.py").write_text(mutator_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_keeps_direct_project_call_through_external_owner_module(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "consumer.py").write_text(
        """\
import app

def run(x: int) -> int:
    return app.calculate(x)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    registry = linkage.build_external_native_registry(
        analysis,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    assert tuple(call.caller_qualname for call in registry.linked_calls) == ("app.calculate",)


@pytest.mark.parametrize(
    "consumer_body",
    (
        pytest.param("retained = pkg.app\n", id="direct-retention"),
        pytest.param("retained = [pkg.app]\n", id="list-retention"),
        pytest.param("retained = {'module': pkg.app}\n", id="dict-retention"),
    ),
)
def test_registry_rejects_package_root_escape_of_sensitive_project_module(
    tmp_path: Path,
    consumer_body: str,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "consumer.py").write_text(
        f"import pkg.app\n{consumer_body}",
        encoding="utf-8",
    )
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_keeps_exact_project_call_through_sensitive_package_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "consumer.py").write_text(
        """\
import pkg.app

def run(x: int) -> int:
    return pkg.app.calculate(x)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    registry = linkage.build_external_native_registry(
        analysis,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    assert tuple(call.caller_qualname for call in registry.linked_calls) == ("pkg.app.calculate",)


def test_registry_fresh_analysis_rechecks_cross_project_binding_slots(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    mutator = project / "mutator.py"
    mutator.write_text(
        """\
def untouched() -> int:
    return 0
""",
        encoding="utf-8",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    initial = analyze_project(project, imports_config=_imports())
    registry = linkage.build_external_native_registry(
        initial,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    mutator.write_text(
        """\
import app

def mutate() -> None:
    app.p = object()
""",
        encoding="utf-8",
    )
    changed = analyze_project(
        project,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        registry.require_fresh_analysis(changed)


@pytest.mark.parametrize(
    "mutator_source",
    (
        pytest.param(
            """\
def mutate() -> None:
    import demo_pkg as q
    q.affine = abs
""",
            id="function-local-import",
        ),
        pytest.param(
            """\
class Holder:
    import demo_pkg as q

def mutate() -> None:
    Holder.q.affine = abs
""",
            id="class-body-import",
        ),
        pytest.param(
            """\
if True:
    import demo_pkg as q

retained = q
""",
            id="conditional-import",
        ),
        pytest.param(
            """\
from demo_pkg import *
retained = affine
""",
            id="star-import",
        ),
    ),
)
def test_registry_rejects_sensitive_imports_outside_exact_module_body(
    tmp_path: Path,
    mutator_source: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "mutator.py").write_text(mutator_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(linkage.ExternalLinkageError, match="external-linkage-"):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "bridge_source",
    (
        pytest.param("from . import app\n", id="unused-owner"),
        pytest.param(
            "from .app import __dict__ as namespace\n",
            id="namespace-container",
        ),
        pytest.param(
            """\
from . import app as old
retained = old
import builtins as old
""",
            id="nonfinal-retention",
        ),
        pytest.param(
            """\
def mutate() -> None:
    from . import app
    app.p = object()
""",
            id="function-local-relative",
        ),
    ),
)
def test_registry_rejects_relative_sensitive_import_escape(
    tmp_path: Path,
    bridge_source: str,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (package / "bridge.py").write_text(bridge_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(linkage.ExternalLinkageError, match="external-linkage-"):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


def test_registry_keeps_final_relative_project_call(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (package / "consumer.py").write_text(
        """\
from . import app

def run(x: int) -> int:
    return app.calculate(x)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    registry = linkage.build_external_native_registry(
        analysis,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    assert tuple(call.caller_qualname for call in registry.linked_calls) == (
        "pkg.app.calculate",
    )


@pytest.mark.parametrize(
    "reflection_source",
    (
        pytest.param(
            """\
import builtins
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    builtins.getattr(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="qualified-builtins-getattr",
        ),
        pytest.param(
            """\
from builtins import getattr as fetch
import demo_pkg as p

def anchor() -> int:
    return 0

def mutate() -> None:
    fetch(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="aliased-builtins-getattr",
        ),
        pytest.param(
            """\
import importlib
import demo_pkg as p

def mutate() -> None:
    q = importlib.__import__("demo_pkg")
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="qualified-importlib-dunder-import",
        ),
        pytest.param(
            """\
from importlib import __import__ as load
import demo_pkg as p

def mutate() -> None:
    q = load("demo_pkg")
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="aliased-importlib-dunder-import",
        ),
    ),
)
def test_registry_rejects_resolved_reflection_and_import_machinery(
    tmp_path: Path,
    reflection_source: str,
) -> None:
    analysis = _analysis(tmp_path, reflection_source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-(?:target-mutated|target-escaped|dynamic-namespace)",
    ):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "escape_source",
    (
        pytest.param(
            """\
from builtins import getattr as g
import demo_pkg as p
h = g

def anchor() -> int:
    return 0

def mutate() -> None:
    h(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="getattr-import-alias-chain",
        ),
        pytest.param(
            """\
import demo_pkg as p
h = getattr

def anchor() -> int:
    return 0

def mutate() -> None:
    h(anchor, "__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="getattr-builtin-alias-chain",
        ),
        pytest.param(
            """\
import functools
import demo_pkg as p

def anchor() -> int:
    return 0

h = functools.partial(getattr, anchor)

def mutate() -> None:
    h("__globals__")["p"] = object()

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="getattr-partial",
        ),
        pytest.param(
            """\
import importlib.util
import demo_pkg as p

def mutate() -> None:
    spec = importlib.util.find_spec("demo_pkg")
    spec.loader.load_module("demo_pkg")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="importlib-util-loader",
        ),
        pytest.param(
            """\
from importlib import util as u
import demo_pkg as p
find = u.find_spec

def mutate() -> None:
    find("demo_pkg").loader.load_module("demo_pkg")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="importlib-util-alias-chain",
        ),
        pytest.param(
            """\
import demo_pkg as p

def mutate() -> None:
    __loader__.load_module("demo_pkg")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="implicit-loader",
        ),
        pytest.param(
            """\
import demo_pkg as p

def mutate() -> None:
    __spec__.loader.load_module("demo_pkg")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="implicit-spec-loader",
        ),
        pytest.param(
            """\
import pkgutil
import demo_pkg as p

def mutate() -> None:
    pkgutil.resolve_name("demo_pkg.affine")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="pkgutil-resolve-name",
        ),
        pytest.param(
            """\
import pydoc
import demo_pkg as p

def mutate() -> None:
    pydoc.locate("demo_pkg.affine")

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="pydoc-locate",
        ),
        pytest.param(
            """\
import pkgutil
import demo_pkg as p

def mutate() -> None:
    loader = pkgutil.get_loader("demo_pkg")
    q = loader.load_module("demo_pkg")
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="pkgutil-get-loader",
        ),
        pytest.param(
            """\
import _frozen_importlib_external as bootstrap
import demo_pkg as p

def mutate() -> None:
    spec = bootstrap.PathFinder.find_spec("demo_pkg")
    q = spec.loader.load_module("demo_pkg")
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="frozen-path-finder",
        ),
        pytest.param(
            """\
import pkgutil
import demo_pkg as p

def mutate() -> None:
    q = pkgutil.importlib.import_module("demo_pkg")
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="pkgutil-importlib-reexport",
        ),
        pytest.param(
            """\
import os
import demo_pkg as p

def mutate() -> None:
    q = os.sys.modules["demo_pkg"]
    q.affine = abs

def calculate(x: int) -> int:
    return p.affine(x)
""",
            id="os-sys-modules-reexport",
        ),
    ),
)
def test_registry_rejects_capability_aliases_and_broader_import_machinery(
    tmp_path: Path,
    escape_source: str,
) -> None:
    analysis = _analysis(tmp_path, escape_source)
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(linkage.ExternalLinkageError, match="external-linkage-"):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "consumer_source",
    (
        pytest.param(
            """\
import app

def run(app: object) -> object:
    return app.calculate(1)
""",
            id="function-parameter",
        ),
        pytest.param(
            """\
import app
runner = lambda app: app.calculate(1)
""",
            id="lambda-parameter",
        ),
        pytest.param(
            """\
import app

def outer() -> object:
    def inner(app: object) -> object:
        return app.calculate(1)
    return inner
""",
            id="nested-function-parameter",
        ),
    ),
)
def test_registry_rejects_scope_shadowed_project_call_allowance(
    tmp_path: Path,
    consumer_source: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    (project / "consumer.py").write_text(consumer_source, encoding="utf-8")
    analysis = analyze_project(project, imports_config=_imports())
    linkage = importlib.import_module("rextio.source.external_linkage")

    with pytest.raises(linkage.ExternalLinkageError, match="external-linkage-target-escaped"):
        linkage.build_external_native_registry(
            analysis,
            (_external_plan(),),
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
        )


@pytest.mark.parametrize(
    "changed_mutator",
    (
        pytest.param(
            """\
def mutate() -> None:
    import demo_pkg as q
    q.affine = abs
""",
            id="nested-sensitive-import",
        ),
        pytest.param(
            """\
import importlib

def mutate() -> None:
    q = importlib.__import__("demo_pkg")
    q.affine = abs
""",
            id="resolved-dynamic-import",
        ),
        pytest.param(
            """\
import pkgutil

def mutate() -> None:
    loader = pkgutil.get_loader("demo_pkg")
    q = loader.load_module("demo_pkg")
    q.affine = abs
""",
            id="pkgutil-get-loader",
        ),
        pytest.param(
            """\
import _frozen_importlib_external as bootstrap

def mutate() -> None:
    spec = bootstrap.PathFinder.find_spec("demo_pkg")
    q = spec.loader.load_module("demo_pkg")
    q.affine = abs
""",
            id="frozen-path-finder",
        ),
        pytest.param(
            """\
import pkgutil

def mutate() -> None:
    q = pkgutil.importlib.import_module("demo_pkg")
    q.affine = abs
""",
            id="pkgutil-importlib-reexport",
        ),
        pytest.param(
            """\
import os

def mutate() -> None:
    q = os.sys.modules["demo_pkg"]
    q.affine = abs
""",
            id="os-sys-modules-reexport",
        ),
    ),
)
def test_registry_fresh_analysis_rechecks_import_occurrences_and_reflection(
    tmp_path: Path,
    changed_mutator: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    mutator = project / "mutator.py"
    mutator.write_text("def untouched() -> int:\n    return 0\n", encoding="utf-8")
    linkage = importlib.import_module("rextio.source.external_linkage")
    initial = analyze_project(project, imports_config=_imports())
    registry = linkage.build_external_native_registry(
        initial,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    mutator.write_text(changed_mutator, encoding="utf-8")
    changed = analyze_project(
        project,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        registry.require_fresh_analysis(changed)


def test_registry_fresh_analysis_rechecks_project_reexported_loader_capability(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    bridge = project / "bridge.py"
    bridge.write_text("def recover() -> None:\n    return None\n", encoding="utf-8")
    mutator = project / "mutator.py"
    mutator.write_text("def untouched() -> int:\n    return 0\n", encoding="utf-8")
    linkage = importlib.import_module("rextio.source.external_linkage")
    initial = analyze_project(project, imports_config=_imports())
    registry = linkage.build_external_native_registry(
        initial,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    bridge.write_text(
        "from importlib import import_module as recover\n",
        encoding="utf-8",
    )
    mutator.write_text(
        """\
from bridge import recover

def mutate() -> None:
    recover("demo_pkg").affine = abs
""",
        encoding="utf-8",
    )
    changed = analyze_project(
        project,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        registry.require_fresh_analysis(changed)


@pytest.mark.parametrize(
    ("package_source", "mutator_source"),
    (
        pytest.param(
            "from .bridge import __builtins__ as namespace\n",
            """\
from pkg import namespace

def mutate() -> None:
    namespace["__import__"]("demo_pkg").affine = abs
""",
            id="builtins",
        ),
        pytest.param(
            "from .bridge import __dict__ as namespace\n",
            """\
from pkg import namespace

def mutate() -> None:
    namespace["__builtins__"]["__import__"]("demo_pkg").affine = abs
""",
            id="dict-nested-builtins",
        ),
    ),
)
def test_registry_fresh_analysis_rechecks_implicit_namespace_reexports(
    tmp_path: Path,
    package_source: str,
    mutator_source: str,
) -> None:
    project = tmp_path / "project"
    package = project / "pkg"
    package.mkdir(parents=True)
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    package_init = package / "__init__.py"
    package_init.write_text("", encoding="utf-8")
    (package / "bridge.py").write_text(
        "def anchor() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    mutator = project / "mutator.py"
    mutator.write_text("def untouched() -> int:\n    return 0\n", encoding="utf-8")
    linkage = importlib.import_module("rextio.source.external_linkage")
    initial = analyze_project(project, imports_config=_imports())
    registry = linkage.build_external_native_registry(
        initial,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )

    package_init.write_text(package_source, encoding="utf-8")
    mutator.write_text(mutator_source, encoding="utf-8")
    changed = analyze_project(
        project,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        registry.require_fresh_analysis(changed)


def test_registry_fresh_analysis_rechecks_parameter_shadowing(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
        encoding="utf-8",
    )
    consumer = project / "consumer.py"
    consumer.write_text(
        """\
import app

def run(x: int) -> int:
    return app.calculate(x)
""",
        encoding="utf-8",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")
    initial = analyze_project(project, imports_config=_imports())
    registry = linkage.build_external_native_registry(
        initial,
        (_external_plan(),),
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
    )
    consumer.write_text(
        """\
import app

def run(app: object) -> object:
    return app.calculate(1)
""",
        encoding="utf-8",
    )
    changed = analyze_project(
        project,
        imports_config=_imports(),
        external_native_registry=registry,
    )

    with pytest.raises(
        linkage.ExternalLinkageError,
        match="external-linkage-project-analysis-stale",
    ):
        registry.require_fresh_analysis(changed)


def test_registry_keeps_clean_direct_module_and_callable_leaf_calls(
    tmp_path: Path,
) -> None:
    analysis = _analysis(
        tmp_path,
        """\
import demo_pkg as p
from demo_pkg import affine as f

def through_module(x: int) -> int:
    return p.affine(x)

def through_callable(x: int) -> int:
    return f(x)
""",
    )
    linkage = importlib.import_module("rextio.source.external_linkage")

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
