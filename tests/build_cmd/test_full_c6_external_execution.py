"""Adversarial tests for the C5.2 to Full C6 production execution bridge."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import inspect
import json
from pathlib import Path
import runpy
import sys
from typing import Any

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.analyzer.models import ProjectAnalysis
from rextio.build import full_c6_executor as executor
from rextio.build import full_c6_external_execution as external_execution
from rextio.build import full_c6_toolchain_support as support_closure
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    collect_full_c6_cargo_dependency_workspace,
    compute_full_c6_cargo_vendor_tree_sha256,
)
from rextio.build.full_c6_executor import (
    FULL_C6_NATIVE_DRIVER_MANIFEST,
    FullC6NativeExecutionAuthority,
    FullC6NativeToolPaths,
    validate_full_c6_native_execution_authority,
)
from rextio.build.full_c6_external_execution import (
    FullC6ExternalExecutionError,
    execute_full_c6_external_build,
)
from rextio.build.full_c6_host_inputs import collect_full_c6_analysis_scope
from rextio.build.full_c6_pipeline import (
    FullC6ExternalPreflightResult,
    prepare_full_c6_external_build,
)
from rextio.build.full_c6_toolchain_support import (
    FullC6ToolchainSupportPlan,
    generate_full_c6_toolchain_support_lock,
)
from rextio.build.toolchain_identity import (
    ArgvIdentity,
    BuildToolchainIdentity,
    RextioIdentity,
    capture_cargo_sources,
    capture_environment_identity,
    capture_tool_identity,
)
from rextio.build.input_closure import ExactFileIdentity
from rextio.build.toolchain_support_lock import ToolchainSupportLock
from rextio.config.schema import (
    BuildConfig,
    ImportPackagePolicy,
    ImportsConfig,
    PluginConfig,
    RextioConfig,
)
from rextio.targets.plan import create_target_plan
from rextio.source.external_linkage import ExternalNativeRegistry


_THIS_DIR = Path(__file__).parent
_SOURCE_TESTS = runpy.run_path(
    str(_THIS_DIR.parent / "source" / "test_source_lock_v2.py")
)
_EXECUTOR_TESTS = runpy.run_path(str(_THIS_DIR / "test_full_c6_executor.py"))
_CARGO_TESTS = runpy.run_path(str(_THIS_DIR / "test_full_c6_cargo_workspace.py"))
_SUPPORT_TESTS = runpy.run_path(
    str(_THIS_DIR / "test_full_c6_toolchain_support_discovery.py")
)
_STRICT_BUILD = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
)
_DEPENDENCIES = (
    ("base64", "0.22.0", "1" * 64),
    ("chrono", "0.4.0", "2" * 64),
    ("log", "0.4.0", "3" * 64),
    ("pyo3", "0.29.0", "4" * 64),
    ("sha2", "0.10.0", "5" * 64),
)


@dataclass(frozen=True)
class _ExecutionInputs:
    preflight: FullC6ExternalPreflightResult
    config: RextioConfig
    roots: tuple[Path, Path]
    base_environment: dict[str, str]
    toolchain: BuildToolchainIdentity
    native_tools: FullC6NativeToolPaths
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt
    toolchain_support_plan: FullC6ToolchainSupportPlan
    toolchain_support_lock: ToolchainSupportLock
    cargo_lock: bytes


def _project_preflight(
    tmp_path: Path,
    *,
    build_overrides: dict[str, object] | None = None,
) -> tuple[FullC6ExternalPreflightResult, RextioConfig]:
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
    (project / "pyproject.toml").write_text(
        """\
[project]
name = "demo-project"
version = "0.1.0"
license = "MIT"
license-files = ["LICENSE"]
""",
        encoding="utf-8",
    )
    (project / "LICENSE").write_text("MIT project license\n", encoding="utf-8")
    signed = _SOURCE_TESTS["_write_signed"](project / "authority")
    _scope_lock, scope_workspace = _cargo_workspace(project)
    build_values: dict[str, object] = {
        "artifact_evidence_policy": "required",
        "artifact_distribution_policy": "full-c6-required",
        "artifact_source_lock_manifest": signed.lock_path.relative_to(project).as_posix(),
        "artifact_source_lock_signature": signed.signature_path.relative_to(project).as_posix(),
        "artifact_trusted_public_key": signed.key_path.relative_to(project).as_posix(),
        "artifact_trusted_public_key_sha256": signed.key_hash,
        "artifact_signing_request_output": "state/request.json",
        "artifact_cargo_lock": "Cargo.lock",
        "artifact_cargo_lock_sha256": scope_workspace.cargo_sources.lock_file.sha256,
        "artifact_cargo_vendor": "cargo-vendor",
        "artifact_cargo_vendor_sha256": scope_workspace.vendor_tree_sha256,
        **(build_overrides or {}),
    }
    config = RextioConfig(
        build=BuildConfig(  # type: ignore[arg-type]
            **build_values,
        ),
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive=signed.wheel_path.relative_to(project).as_posix(),
                    source_archive_sha256=signed.wheel_sha256,
                )
            }
        ),
    )
    target_plan = create_target_plan(project, config)
    analysis_scope = collect_full_c6_analysis_scope(project, config=config)

    def analyze(
        registry: ExternalNativeRegistry | None = None,
    ) -> ProjectAnalysis:
        result = analyze_project(
            project,
            boundary_warnings=config.policy.boundary_warnings,
            native_marker=config.policy.native_marker,
            target_language=target_plan.spec.language,
            native_top_level=config.policy.native_top_level,
            imports_config=config.imports,
            active_plugins=target_plan.plugins.active,
            plugin_registry=target_plan.plugins,
            plugin_config=config,
            embedding_enabled=config.embedding.enabled,
            external_native_registry=registry,
            full_c6_analysis_scope=analysis_scope,
        )
        result.external_source_plan = signed.plan
        return result

    initial = analyze()
    preflight = prepare_full_c6_external_build(
        project_root=project,
        initial_analysis=initial,
        config=config,
        analysis_scope=analysis_scope,
        reanalyze=analyze,
    )
    return preflight, config


def _cargo_workspace(
    tmp_path: Path,
    *,
    root_package: str = "rextio_generated_native",
    omitted_dependency: str | None = None,
) -> tuple[Path, FullC6CargoDependencyWorkspaceReceipt]:
    lock = tmp_path / "Cargo.lock"
    root_dependencies = [
        name for name, _version, _checksum in _DEPENDENCIES if name != omitted_dependency
    ]
    package_rows = [
        "version = 4",
        "",
        "[[package]]",
        f'name = "{root_package}"',
        'version = "0.1.0"',
        "dependencies = [",
        *(f' "{name}",' for name in root_dependencies),
        "]",
    ]
    for name, version, checksum in _DEPENDENCIES:
        if name == omitted_dependency:
            continue
        package_rows.extend(
            (
                "",
                "[[package]]",
                f'name = "{name}"',
                f'version = "{version}"',
                'source = "registry+https://github.com/rust-lang/crates.io-index"',
                f'checksum = "{checksum}"',
            )
        )
    lock.write_text("\n".join(package_rows) + "\n", encoding="utf-8")
    sources = capture_cargo_sources(lock, root_package=root_package)
    vendor = tmp_path / "cargo-vendor"
    write_vendor_package = _CARGO_TESTS["_write_vendor_package"]
    for name, version, checksum in _DEPENDENCIES:
        if name == omitted_dependency:
            continue
        write_vendor_package(
            vendor,
            name=name,
            version=version,
            checksum=checksum,
            directory=f"{name}-{version}",
        )
    receipt = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )
    return lock, receipt


def _toolchain(
    tmp_path: Path,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    toolchain_support_plan: FullC6ToolchainSupportPlan,
    toolchain_support_lock: ToolchainSupportLock,
) -> tuple[FullC6NativeToolPaths, dict[str, str], BuildToolchainIdentity]:
    tool_dir = tmp_path / "native-tools"
    tool_dir.mkdir()
    for name in ("cargo", "rustc", "linker", "otool"):
        path = tool_dir / name
        path.write_bytes(f"#!/bin/sh\n# {name}\n".encode())
        path.chmod(0o755)
    native_tools = FullC6NativeToolPaths(
        python=Path(sys.executable).resolve(),
        cargo=(tool_dir / "cargo").resolve(),
        rustc=(tool_dir / "rustc").resolve(),
        linker=(tool_dir / "linker").resolve(),
    )
    environment = {"PATH": str(tool_dir.resolve())}
    rextio_file = ExactFileIdentity(
        "rextio/__init__.py",
        "rextio-python-source",
        "6" * 64,
        1,
        False,
    )
    toolchain = BuildToolchainIdentity(
        python=capture_tool_identity(
            "python", native_tools.python, reported_version="1.0.0"
        ),
        rextio=RextioIdentity(
            version="0.1.4",
            files=(rextio_file,),
            content_digest="7" * 64,
        ),
        cargo=capture_tool_identity(
            "cargo", native_tools.cargo, reported_version="1.0.0"
        ),
        rustc=capture_tool_identity(
            "rustc", native_tools.rustc, reported_version="1.0.0"
        ),
        linker=capture_tool_identity(
            "linker", native_tools.linker, reported_version="1.0.0"
        ),
        inspectors=(
            capture_tool_identity(
                "otool", tool_dir / "otool", reported_version="1.0.0"
            ),
        ),
        argv=ArgvIdentity(_STRICT_BUILD),
        environment=capture_environment_identity(environment),
        cargo_sources=cargo_workspace.cargo_sources,
        support_plan_sha256=toolchain_support_plan.digest,
        support_lock_raw_sha256=toolchain_support_lock.raw_sha256,
        support_lock_merkle_sha256=toolchain_support_lock.merkle_sha256,
    )
    return native_tools, environment, toolchain


def _inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    root_package: str = "rextio_generated_native",
    omitted_dependency: str | None = None,
    build_overrides: dict[str, object] | None = None,
) -> _ExecutionInputs:
    preflight, config = _project_preflight(
        tmp_path,
        build_overrides=build_overrides,
    )
    original_analyze = external_execution.analyze_project
    trusted_plan = preflight.analysis.external_source_plan

    def synthetic_external_inventory(*args: Any, **kwargs: Any) -> Any:
        fresh = original_analyze(*args, **kwargs)
        # The synthetic SourceLock fixture is not installed as a distribution;
        # model the analyzer observing that same exact installed-source plan.
        fresh.external_source_plan = trusted_plan
        return fresh

    monkeypatch.setattr(
        external_execution,
        "analyze_project",
        synthetic_external_inventory,
    )
    lock, workspace = _cargo_workspace(
        tmp_path,
        root_package=root_package,
        omitted_dependency=omitted_dependency,
    )
    support_plan = _SUPPORT_TESTS["_fixed_plan"](
        tmp_path / "toolchain-support",
    )
    support_lock = generate_full_c6_toolchain_support_lock(support_plan)
    native_tools, environment, toolchain = _toolchain(
        tmp_path,
        workspace,
        support_plan,
        support_lock,
    )
    _EXECUTOR_TESTS["_use_fixed_pyo3_profile"].__wrapped__(monkeypatch)

    def retain_support_plan(plan: object, *_args: object, **_kwargs: object) -> object:
        return plan

    monkeypatch.setattr(
        executor,
        "_require_native_toolchain_support",
        retain_support_plan,
    )
    monkeypatch.setattr(
        executor,
        "_require_native_toolchain_support_critical",
        retain_support_plan,
    )
    _EXECUTOR_TESTS["_install_successful_native_run"](
        monkeypatch,
        executor,
    )
    roots = _EXECUTOR_TESTS["_roots"](tmp_path)
    return _ExecutionInputs(
        preflight=preflight,
        config=config,
        roots=roots,
        base_environment=environment,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=workspace,
        toolchain_support_plan=support_plan,
        toolchain_support_lock=support_lock,
        cargo_lock=lock.read_bytes(),
    )


def _execute(inputs: _ExecutionInputs) -> FullC6NativeExecutionAuthority:
    return execute_full_c6_external_build(
        inputs.preflight,
        config=inputs.config,
        first_quarantine_root=inputs.roots[0],
        second_quarantine_root=inputs.roots[1],
        base_environment=inputs.base_environment,
        source_date_epoch=1,
        toolchain=inputs.toolchain,
        native_tools=inputs.native_tools,
        cargo_workspace=inputs.cargo_workspace,
        toolchain_support_plan=inputs.toolchain_support_plan,
        toolchain_support_lock=inputs.toolchain_support_lock,
    )


def _fail_before_executor(
    inputs: _ExecutionInputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("native executor must not be reached")

    monkeypatch.setattr(executor, "execute_full_c6_native_two_build", forbidden)
    with pytest.raises(FullC6ExternalExecutionError, match="RXT060"):
        _execute(inputs)
    assert called is False


def test_external_call_reaches_exact_guarded_rust_and_native_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    analyzed_scopes: list[object] = []
    reanalyze = external_execution.analyze_project

    def observe_scope(*args: Any, **kwargs: Any) -> Any:
        analyzed_scopes.append(kwargs["full_c6_analysis_scope"])
        return reanalyze(*args, **kwargs)

    monkeypatch.setattr(external_execution, "analyze_project", observe_scope)
    native_execute = executor.execute_full_c6_native_two_build
    support_calls = 0

    def observe_support(*args: Any, **kwargs: Any) -> Any:
        nonlocal support_calls
        support_calls += 1
        assert kwargs["toolchain_support_plan"] is inputs.toolchain_support_plan
        assert kwargs["toolchain_support_lock"] is inputs.toolchain_support_lock
        return native_execute(*args, **kwargs)

    monkeypatch.setattr(
        executor,
        "execute_full_c6_native_two_build",
        observe_support,
    )

    authority = _execute(inputs)

    assert analyzed_scopes == [inputs.preflight.context.analysis_scope]
    assert support_calls == 1
    assert validate_full_c6_native_execution_authority(authority)
    assert authority.authorizes_distribution is False
    source_root = inputs.preflight.analysis.project_root / ".rextio/generated/rust"
    rust = (source_root / "src/lib.rs").read_bytes()
    assert rust.count(b"demo_pkg__affine") >= 2
    assert b"demo_pkg__affine(x.clone())?" in rust
    assert b"__rextio_verify_external_source" in rust
    assert b"demo-pkg" in rust and b"1.0.0" in rust
    expected = {
        "src/lib.rs": rust,
        "Cargo.lock": inputs.cargo_lock,
        FULL_C6_NATIVE_DRIVER_MANIFEST: (
            source_root / FULL_C6_NATIVE_DRIVER_MANIFEST
        ).read_bytes(),
    }
    frozen = {
        item.logical_name: item
        for item in authority.frozen_tree.entries
        if item.kind == "file"
    }
    for logical_name, payload in expected.items():
        assert frozen[logical_name].sha256 == hashlib.sha256(payload).hexdigest()
        assert frozen[logical_name].size == len(payload)
    public = json.dumps(authority.to_dict(), sort_keys=True)
    assert str(tmp_path) not in public
    assert inputs.cargo_lock.decode() not in public


def test_public_factory_has_no_raw_generation_or_execution_override() -> None:
    parameters = inspect.signature(execute_full_c6_external_build).parameters
    assert set(parameters) == {
        "preflight",
        "config",
        "first_quarantine_root",
        "second_quarantine_root",
        "base_environment",
        "source_date_epoch",
        "toolchain",
        "native_tools",
        "cargo_workspace",
        "toolchain_support_plan",
        "toolchain_support_lock",
    }
    assert not {
        "registry",
        "runtime_guard",
        "cargo_lock",
        "generated_rust",
        "generated_python",
        "build",
        "command_factory",
        "callback",
    }.intersection(parameters)


@pytest.mark.parametrize(
    "replacement",
    (
        "return p.affine(x) + 1\n",
        "return p.affine(x) if x else 0\n",
        "return p.affine(str(x))\n",
    ),
)
def test_fresh_reanalysis_rejects_project_call_or_body_drift_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    app = inputs.preflight.analysis.project_root / "app.py"
    source = app.read_text(encoding="utf-8")
    app.write_text(source.replace("return p.affine(x)\n", replacement), encoding="utf-8")

    _fail_before_executor(inputs, monkeypatch)


@pytest.mark.parametrize("field", ("linked_calls", "private_functions"))
def test_empty_or_tampered_linkage_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    registry = inputs.preflight.context.registry
    object.__setattr__(registry, field, ())

    _fail_before_executor(inputs, monkeypatch)


@pytest.mark.parametrize(
    "field,value",
    (
        ("accepted", False),
        ("boundary_call_targets", ("fallback.fn",)),
        ("plugin_type_keys", ("demo/type",)),
    ),
)
def test_fallback_boundary_or_plugin_caller_route_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    original = external_execution.analyze_project

    def tampered_analysis(*args: Any, **kwargs: Any) -> Any:
        analysis = original(*args, **kwargs)
        function = analysis.accepted_native_functions[0]
        setattr(function, field, value)
        return analysis

    monkeypatch.setattr(external_execution, "analyze_project", tampered_analysis)
    _fail_before_executor(inputs, monkeypatch)


def test_missing_runtime_guard_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    object.__setattr__(inputs.preflight.context.runtime_guard, "modules", ())

    _fail_before_executor(inputs, monkeypatch)


def test_generated_rust_tamper_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    original = external_execution._orchestrator.generate_source_artifact

    def tampered(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        (result.layout.rust_src_dir / "lib.rs").write_text("// substituted\n")
        return result

    monkeypatch.setattr(
        external_execution._orchestrator,
        "generate_source_artifact",
        tampered,
    )
    _fail_before_executor(inputs, monkeypatch)


@pytest.mark.parametrize("root_package,omitted", (("other-root", None), ("rextio_generated_native", "sha2")))
def test_cargo_lock_root_and_dependency_coverage_fail_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_package: str,
    omitted: str | None,
) -> None:
    inputs = _inputs(
        tmp_path,
        monkeypatch,
        root_package=root_package,
        omitted_dependency=omitted,
    )

    _fail_before_executor(inputs, monkeypatch)


def test_toolchain_and_workspace_lock_mismatch_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    other_root = tmp_path / "other"
    other_root.mkdir()
    _, other_workspace = _cargo_workspace(other_root, omitted_dependency="sha2")
    native_tools, environment, mismatched = _toolchain(
        other_root,
        other_workspace,
        inputs.toolchain_support_plan,
        inputs.toolchain_support_lock,
    )
    inputs = _ExecutionInputs(
        preflight=inputs.preflight,
        config=inputs.config,
        roots=inputs.roots,
        base_environment=environment,
        toolchain=mismatched,
        native_tools=native_tools,
        cargo_workspace=inputs.cargo_workspace,
        toolchain_support_plan=inputs.toolchain_support_plan,
        toolchain_support_lock=inputs.toolchain_support_lock,
        cargo_lock=inputs.cargo_lock,
    )

    _fail_before_executor(inputs, monkeypatch)


def test_toolchain_support_digest_mismatch_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    inputs = replace(
        inputs,
        toolchain=replace(inputs.toolchain, support_plan_sha256="f" * 64),
    )

    _fail_before_executor(inputs, monkeypatch)


def test_external_support_boundary_revalidates_critical_leaves_without_full_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    critical_calls = 0
    full_walk_calls = 0
    revalidate = external_execution.revalidate_full_c6_toolchain_support_plan

    def observe_critical(plan: object) -> object:
        nonlocal critical_calls
        critical_calls += 1
        return revalidate(plan)

    def forbidden_full_walk(*_args: object, **_kwargs: object) -> bool:
        nonlocal full_walk_calls
        full_walk_calls += 1
        raise AssertionError("external boundary must not repeat the full support walk")

    monkeypatch.setattr(
        external_execution,
        "revalidate_full_c6_toolchain_support_plan",
        observe_critical,
    )
    monkeypatch.setattr(
        support_closure,
        "verify_full_c6_toolchain_support_lock",
        forbidden_full_walk,
    )

    assert external_execution._require_external_toolchain_support(
        inputs.toolchain_support_plan,
        inputs.toolchain_support_lock,
        toolchain=inputs.toolchain,
    ) is inputs.toolchain_support_plan
    assert critical_calls == 1
    assert full_walk_calls == 0


@pytest.mark.parametrize("drift", ("marker", "target", "plugin", "package"))
def test_config_or_target_drift_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    config = inputs.config
    if drift == "marker":
        config = replace(config, policy=replace(config.policy, native_marker="decorator"))
    elif drift == "target":
        config = replace(config, build=replace(config.build, native_backend="python"))
    elif drift == "plugin":
        config = replace(config, plugins=PluginConfig(enabled=("unknown",)))
    else:
        package = config.imports.packages["demo_pkg"]
        config = replace(
            config,
            imports=ImportsConfig(
                packages={"demo_pkg": replace(package, version="1.0.1")}
            ),
        )
    inputs = replace(inputs, config=config)

    _fail_before_executor(inputs, monkeypatch)


@pytest.mark.parametrize(
    "field,value",
    (
        ("artifact_cargo_lock_sha256", "9" * 64),
    ),
)
def test_full_config_snapshot_rejects_non_analysis_field_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    original = external_execution.create_target_plan

    def mutate_after_target_resolution(*args: Any, **kwargs: Any) -> Any:
        target_plan = original(*args, **kwargs)
        object.__setattr__(inputs.config.build, field, value)
        return target_plan

    monkeypatch.setattr(
        external_execution,
        "create_target_plan",
        mutate_after_target_resolution,
    )

    _fail_before_executor(inputs, monkeypatch)


@pytest.mark.parametrize("injection", ("external-source", "symlink", "native-binary"))
def test_generated_python_unsafe_material_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    injection: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    original = external_execution._orchestrator.generate_source_artifact

    def injected(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        python_root = result.layout.python_dir
        if injection == "external-source":
            package = python_root / "demo_pkg"
            package.mkdir()
            (package / "__init__.py").write_text("# forbidden copy\n")
        elif injection == "symlink":
            (python_root / "linked.py").symlink_to(python_root / "app.py")
        else:
            (python_root / "untrusted.so").write_bytes(b"native")
        return result

    monkeypatch.setattr(
        external_execution._orchestrator,
        "generate_source_artifact",
        injected,
    )
    _fail_before_executor(inputs, monkeypatch)
