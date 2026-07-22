"""Adversarial tests for the strict Full C6 two-build executor."""

from __future__ import annotations

import copy
import io
import json
import hashlib
import os
import pickle
import stat
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


STRICT_BUILD = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
)


def _pyo3_identity(target: str = "aarch64-apple-darwin"):
    from rextio.build.full_c6_pyo3_config import FullC6Pyo3ConfigIdentity

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


@pytest.fixture(autouse=True)
def _use_fixed_pyo3_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    import rextio.build.full_c6_executor as executor

    monkeypatch.setattr(executor, "capture_full_c6_pyo3_config", _pyo3_identity)
    support_plan = SimpleNamespace(macos_platform_anchor=None)
    sandbox_plan = SimpleNamespace(
        engine="macos-sandbox-exec-v1",
        digest="7" * 64,
    )
    monkeypatch.setattr(
        executor,
        "_require_native_toolchain_support",
        lambda *_args, **_kwargs: support_plan,
    )
    monkeypatch.setattr(
        executor,
        "_require_native_toolchain_support_critical",
        lambda *_args, **_kwargs: support_plan,
    )
    monkeypatch.setattr(
        executor,
        "_native_read_sandbox_plan",
        lambda **_kwargs: sandbox_plan,
    )
    monkeypatch.setattr(
        executor,
        "prepare_full_c6_sandbox_launch",
        lambda _plan, command, **_kwargs: executor.FullC6SandboxLaunch(
            command=tuple(command),
            preexec_fn=None,
            profile_sha256="8" * 64,
            pass_fds=(),
            seccomp_sha256=None,
            seccomp_lease=None,
        ),
    )


def _project(tmp_path: Path, *, lock: bool = True) -> Path:
    root = tmp_path / "generated-project"
    source = root / "src"
    source.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    if lock:
        (root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
    (source / "lib.rs").write_text("pub fn answer() -> i64 { 42 }\n", encoding="utf-8")
    return root


def _macos_diagnostic_plan():
    from rextio.build.full_c6_read_sandbox import (
        FullC6ReadSandboxPlan,
        SandboxPathRule,
    )

    paths = {
        "build": Path("/private/var/rextio-c6-diagnostic-build"),
        "project": Path("/private/rextio-c6-diagnostic-project"),
        "toolchain": Path("/opt/rextio-c6-diagnostic/rustc"),
        "support": Path("/opt/rextio-c6-diagnostic/pyo3-config"),
    }
    rules = tuple(
        sorted(
            (
                SandboxPathRule(
                    path=paths["build"],
                    access="read-write",
                    logical_role="build-root",
                ),
                SandboxPathRule(
                    path=paths["project"],
                    access="read",
                    logical_role="project-root",
                ),
                SandboxPathRule(
                    path=paths["toolchain"],
                    access="read-execute",
                    logical_role="toolchain-rustc",
                ),
                SandboxPathRule(
                    path=paths["support"],
                    access="read",
                    logical_role="support-pyo3-config",
                ),
            ),
            key=lambda item: (
                item.logical_role,
                item.access,
                os.fsencode(item.path),
            ),
        )
    )
    return (
        FullC6ReadSandboxPlan(
            target_triple="aarch64-apple-darwin",
            engine="macos-sandbox-exec-v1",
            rules=rules,
            platform_anchor_sha256="9" * 64,
        ),
        paths,
    )


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (
            "bwrap: Creating new namespace failed: Operation not permitted",
            "native-bwrap-user-namespace-denied",
        ),
        (
            "bwrap: Can't bind mount /private/source on /target: No such file or directory",
            "native-bwrap-bind-path-missing",
        ),
        (
            "bwrap: Can't mkdir parents for /private/target: No such file or directory",
            "native-bwrap-bind-path-missing",
        ),
        ("bwrap: Can't mount tmpfs on /newroot: Invalid argument", "native-bwrap-mount-failed"),
        ("bwrap: execvp /private/cargo: No such file or directory", "native-bwrap-exec-failed"),
        ("bwrap: Can't install seccomp filter: Invalid argument", "native-bwrap-seccomp-failed"),
        ("bwrap: private unclassified detail", "native-sandbox-bubblewrap"),
        ("error: failed to get `demo` as a dependency", "native-cargo-dependency-config"),
        ("error: rustc 1.92.0 is not supported", "native-rustc"),
        ("error: linking with `cc` failed: exit status: 1", "native-linker"),
        (
            "error: failed to run custom build command for `pyo3-ffi v0.24.0`",
            "native-pyo3",
        ),
        ("error: access failed: Permission denied", "native-permission"),
        ("error: input failed: No such file or directory", "native-missing-path"),
        ("error[E0308]: mismatched types\nerror: could not compile `demo`", "native-compile"),
        ("opaque private failure", None),
    ],
)
def test_native_sandbox_stderr_classifier_returns_only_static_categories(
    stderr: str,
    expected: str | None,
) -> None:
    import rextio.build.full_c6_executor as executor

    assert executor._classify_native_sandbox_stderr(stderr) == expected


@pytest.mark.parametrize(
    "stage",
    (
        "cpython-runtime",
        "environment-argv",
        "environment-argv-unexpected-lc-ctype",
        "environment-argv-closed-set",
        "environment-argv-fixed-value",
        "environment-argv-variable-value",
        "environment-argv-malformed-row",
        "environment-argv-argv-shape",
        "environment-argv-environment-digest",
        "environment-argv-malformed-argument",
        "environment-argv-payload-executable",
        "pyo3-config",
        "descriptors",
        "landlock",
        "cargo-exec",
    ),
)
def test_native_sandbox_stderr_classifier_accepts_exact_launcher_stage_only(
    stage: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    marker = f"Rextio Full C6 Linux launcher failed closed: {stage}\n"

    assert executor._classify_native_sandbox_stderr(marker) == (
        f"linux-launcher-{stage}"
    )
    assert executor._classify_native_sandbox_stderr(
        marker + "permission denied"
    ) is None
    assert executor._classify_native_sandbox_stderr(
        marker.replace(stage, "private-arbitrary-stage")
    ) is None
    assert executor._classify_native_sandbox_stderr(marker.upper()) is None


def test_native_sandbox_stderr_error_never_retains_private_input() -> None:
    import rextio.build.full_c6_executor as executor

    private = "/private/runner/project secret"
    error = executor._native_sandbox_stderr_error(f"bwrap: {private}")

    assert error is not None
    assert str(error) == "strict native sandbox build failed: native-sandbox-bubblewrap"
    assert private not in str(error)


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("sandbox-apply", "native-macos-permission-sandbox-apply"),
        ("mach-lookup", "native-macos-permission-mach-lookup"),
        ("sysctl", "native-macos-permission-sysctl-cpu-count"),
        ("build", "native-macos-permission-build-root"),
        ("project", "native-macos-permission-project-root"),
        ("toolchain", "native-macos-permission-toolchain"),
        ("support", "native-macos-permission-support"),
        ("dev", "native-macos-permission-denied-dev"),
        ("private-var", "native-macos-permission-denied-private-var"),
        ("library", "native-macos-permission-denied-library"),
        ("preboot", "native-macos-permission-denied-preboot"),
        ("unmatched", "native-macos-permission-unmatched"),
    ),
)
def test_native_sandbox_stderr_classifier_returns_bounded_macos_categories(
    case: str,
    expected: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    plan, paths = _macos_diagnostic_plan()
    diagnostics = {
        "sandbox-apply": "sandbox-exec: sandbox_apply: Operation not permitted",
        "mach-lookup": (
            "Sandbox: cargo(42) deny(1) mach-lookup "
            "com.example.private-service"
        ),
        "sysctl": "Sandbox: cargo(42) deny(1) sysctl-read hw.ncpu",
        "build": f"Sandbox: cargo(42) deny(1) file-write {paths['build']}/target",
        "project": f"Sandbox: cargo(42) deny(1) file-read {paths['project']}/src",
        "toolchain": f"Sandbox: cargo(42) deny(1) process-exec {paths['toolchain']}",
        "support": f"Sandbox: cargo(42) deny(1) file-read {paths['support']}",
        "dev": "Sandbox: cargo(42) deny(1) file-read /dev/null",
        "private-var": "Sandbox: cargo(42) deny(1) file-read /private/var/db/private",
        "library": "Sandbox: cargo(42) deny(1) file-read /Library/Private/file",
        "preboot": (
            "Sandbox: cargo(42) deny(1) file-read "
            "/System/Volumes/Preboot/private"
        ),
        "unmatched": "error: access to an unknown capability: Permission denied",
    }

    assert (
        executor._classify_native_sandbox_stderr(
            diagnostics[case],
            sandbox_plan=plan,
            target_triple="aarch64-apple-darwin",
        )
        == expected
    )


def test_native_sandbox_stderr_macos_categories_require_exact_plan_and_target() -> None:
    import rextio.build.full_c6_executor as executor

    plan, _paths = _macos_diagnostic_plan()
    stderr = "error: access failed: Permission denied"
    forged = SimpleNamespace(
        target_triple="aarch64-apple-darwin",
        engine="macos-sandbox-exec-v1",
        rules=plan.rules,
    )

    assert executor._classify_native_sandbox_stderr(stderr) == "native-permission"
    assert (
        executor._classify_native_sandbox_stderr(
            stderr,
            sandbox_plan=forged,
            target_triple="aarch64-apple-darwin",
        )
        == "native-permission"
    )
    assert (
        executor._classify_native_sandbox_stderr(
            stderr,
            sandbox_plan=plan,
            target_triple="x86_64-unknown-linux-gnu",
        )
        == "native-permission"
    )


def test_native_sandbox_stderr_macos_classifier_is_bounded_and_path_exact() -> None:
    import rextio.build.full_c6_executor as executor

    plan, paths = _macos_diagnostic_plan()

    def classify(stderr: str) -> str | None:
        return executor._classify_native_sandbox_stderr(
            stderr,
            sandbox_plan=plan,
            target_triple="aarch64-apple-darwin",
        )

    assert classify("x" * (64 * 1024) + "\nPermission denied") == (
        "native-permission"
    )
    assert classify("😀" * 20_000 + "\nPermission denied") == "native-permission"
    assert classify("x" * (64 * 1024) + "\nerror[E0308]: mismatched types") == (
        "native-compile"
    )
    assert classify(
        "Permission denied\nnearby detail\noutside context\n"
        f"{paths['build']}/target"
    ) == "native-macos-permission-unmatched"
    assert classify(
        f"Sandbox: cargo(42) deny(1) file-write {paths['build']}-evil/target"
    ) == "native-macos-permission-denied-private-var"


def test_native_sandbox_stderr_macos_context_has_strict_preceding_line_bound() -> None:
    import rextio.build.full_c6_executor as executor

    plan, paths = _macos_diagnostic_plan()

    def classify(stderr: str) -> str | None:
        return executor._classify_native_sandbox_stderr(
            stderr,
            sandbox_plan=plan,
            target_triple="aarch64-apple-darwin",
        )

    path_line = f"error: failed to open {paths['build']}/target"
    assert classify(f"{path_line}\n\nCaused by:\nPermission denied") == (
        "native-macos-permission-build-root"
    )
    assert classify(
        f"{path_line}\n\nwhile compiling dependency\nCaused by:\nPermission denied"
    ) == "native-macos-permission-unmatched"


def test_native_sandbox_stderr_macos_error_contains_only_static_category() -> None:
    import rextio.build.full_c6_executor as executor

    plan, _paths = _macos_diagnostic_plan()
    private_service = "com.example.private-service"
    injected_reason = "native-macos-permission-owner-controlled"
    error = executor._native_sandbox_stderr_error(
        f"Permission denied: {injected_reason} {private_service}",
        sandbox_plan=plan,
        target_triple="aarch64-apple-darwin",
    )

    assert error is not None
    assert str(error) == (
        "strict native sandbox build failed: native-macos-permission-unmatched"
    )
    assert error.args == (str(error),)
    assert injected_reason not in str(error)
    assert private_service not in str(error)


def _external_contract():
    from rextio.build.wheel_builder import (
        ExternalWheelContract,
        ExternalWheelMemberIdentity,
    )
    paths = (
        "vendor-1.0.dist-info/METADATA",
        "vendor-1.0.dist-info/RECORD",
        "vendor-1.0.dist-info/WHEEL",
        "vendor-1.0.dist-info/licenses/LICENSE",
        "vendor/__init__.py",
    )
    return ExternalWheelContract(
        package="vendor",
        distribution="vendor",
        version="1.0",
        source_members=("vendor/__init__.py",),
        external_members=tuple(
            ExternalWheelMemberIdentity(
                path=path,
                sha256=hashlib.sha256(path.encode()).hexdigest(),
                size=len(path),
            )
            for path in paths
        ),
    )


def _output_license_contract():
    from rextio.build.full_c6_output_license import (
        OutputWheelLicenseContract,
        OutputWheelLicenseFile,
    )

    return OutputWheelLicenseContract(
        expression="MIT",
        files=(
            OutputWheelLicenseFile(
                path="LICENSE",
                data=b"MIT license for the generated output\n",
            ),
        ),
    )


def _native_inputs(tmp_path: Path, project: Path):
    from rextio.build.input_closure import ExactFileIdentity
    from rextio.build.full_c6_cargo_workspace import (
        collect_full_c6_cargo_dependency_workspace,
        compute_full_c6_cargo_vendor_tree_sha256,
    )
    from rextio.build.full_c6_executor import FullC6NativeToolPaths
    from rextio.build.toolchain_identity import (
        ArgvIdentity,
        BuildToolchainIdentity,
        RextioIdentity,
        capture_cargo_sources,
        capture_environment_identity,
        capture_tool_identity,
    )

    tool_dir = tmp_path / "native-tools"
    tool_dir.mkdir(parents=True, exist_ok=True)
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
    base_environment = {"PATH": str(tool_dir.resolve())}

    def exact(name: str, role: str, digest: str, *, executable: bool = False):
        return ExactFileIdentity(name, role, digest, 1, executable)

    rextio_file = exact("rextio/__init__.py", "rextio-python-source", "2" * 64)
    cargo_sources = capture_cargo_sources(project / "Cargo.lock", root_package="demo")
    vendor = tmp_path / "native-vendor"
    package = vendor / "demo-dep-1.2.3"
    (package / "src").mkdir(parents=True)
    files = {
        "Cargo.toml": (
            b'[package]\nname = "demo-dep"\nversion = "1.2.3"\n'
            b'license = "MIT"\nlicense-file = "LICENSE"\n'
        ),
        "LICENSE": b"MIT license evidence\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
    }
    for relative, payload in files.items():
        path = package.joinpath(*relative.split("/"))
        path.write_bytes(payload)
        path.chmod(0o644)
    (package / ".cargo-checksum.json").write_text(
        json.dumps(
            {
                "files": {
                    name: hashlib.sha256(payload).hexdigest()
                    for name, payload in sorted(files.items())
                },
                "package": "a" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    cargo_workspace = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=project / "Cargo.lock",
        cargo_sources=cargo_sources,
        expected_vendor_tree_sha256=pin,
    )
    toolchain = BuildToolchainIdentity(
        python=capture_tool_identity(
            "python",
            native_tools.python,
            reported_version="1.0.0",
        ),
        rextio=RextioIdentity(
            version="0.1.4",
            files=(rextio_file,),
            content_digest="3" * 64,
        ),
        cargo=capture_tool_identity(
            "cargo",
            native_tools.cargo,
            reported_version="1.0.0",
        ),
        rustc=capture_tool_identity(
            "rustc",
            native_tools.rustc,
            reported_version="1.0.0",
        ),
        linker=capture_tool_identity(
            "linker",
            native_tools.linker,
            reported_version="1.0.0",
        ),
        inspectors=(
            capture_tool_identity(
                "otool",
                tool_dir / "otool",
                reported_version="1.0.0",
            ),
        ),
        argv=ArgvIdentity(STRICT_BUILD),
        environment=capture_environment_identity(base_environment),
        cargo_sources=cargo_sources,
        support_plan_sha256="4" * 64,
        support_lock_raw_sha256="5" * 64,
        support_lock_merkle_sha256="6" * 64,
    )
    return native_tools, base_environment, toolchain, cargo_workspace


def _native_project(tmp_path: Path, *, target: str = "aarch64-apple-darwin"):
    from rextio.build.full_c6_executor import full_c6_native_driver_manifest_bytes

    root = _project(tmp_path)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n'
        '\n[dependencies]\ndemo-dep = "=1.2.3"\n',
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        'version = 4\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\n'
        'dependencies = ["demo-dep"]\n\n'
        '[[package]]\nname = "demo-dep"\nversion = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "' + "a" * 64 + '"\n',
        encoding="utf-8",
    )
    package = root / "python-staging" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 42\n", encoding="utf-8")
    (root / "rextio.full-c6-native-driver.json").write_bytes(
        full_c6_native_driver_manifest_bytes(
            target_triple=target,
            distribution_name="demo-artifact",
            cargo_argv=STRICT_BUILD,
            external_contract=_external_contract(),
            output_license_contract=_output_license_contract(),
        )
    )
    return root


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    roots = (tmp_path / "quarantine-one", tmp_path / "quarantine-two")
    for root in roots:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    return roots


def _install_successful_native_run(
    monkeypatch: pytest.MonkeyPatch,
    executor: object,
    *,
    artifact_bytes: bytes = b"sealed-native-extension",
) -> None:
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, **_kwargs):
        artifact = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
            / "lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(artifact_bytes)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)


def _outputs(root: Path, *, wheel: bytes = b"reproducible-wheel"):
    from rextio.build.reproducibility import ReproducibilityBuildOutputs

    output = root / "output"
    output.mkdir()
    wheel_path = output / "demo.whl"
    sbom = output / "sbom.json"
    provenance = output / "provenance.json"
    wheel_path.write_bytes(wheel)
    sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    provenance.write_text('{"buildType":"rextio/full-c6","externalParameters":{}}', encoding="utf-8")
    return ReproducibilityBuildOutputs(wheel_path, sbom, provenance)


def test_executor_freezes_two_independent_copies_and_returns_path_free_receipt(
    tmp_path: Path,
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    calls = []

    def build(request):
        calls.append(request)
        assert request.context.ordinal == len(calls)
        assert request.context.inherit_env is False
        assert request.cargo_argv == STRICT_BUILD
        environment = request.context.environment_dict()
        assert environment["CARGO_NET_OFFLINE"] == "true"
        assert environment["SOURCE_DATE_EPOCH"] == "1"
        assert environment["LANG"] == environment["LC_ALL"] == "C"
        assert environment["TZ"] == "UTC"
        assert "RUSTC_WRAPPER" not in environment
        assert "HTTP_PROXY" not in environment
        assert Path(environment["HOME"]).is_relative_to(request.context.build_root)
        assert Path(environment["CARGO_HOME"]).is_relative_to(request.context.build_root)
        assert Path(environment["CARGO_TARGET_DIR"]).is_relative_to(
            request.context.build_root
        )
        remaps = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        assert len(remaps) == 2
        assert all(item.startswith("--remap-path-prefix=") for item in remaps)
        assert stat.S_IMODE(request.context.project_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(
            request.context.project_root.joinpath("Cargo.toml").stat().st_mode
        ) == 0o644
        return _outputs(request.context.build_root)

    receipt = execute_full_c6_two_build(
        source,
        *roots,
        build=build,
        cargo_command=STRICT_BUILD,
        base_environment={"PATH": "/usr/bin:/bin"},
        source_date_epoch=1,
    )

    assert len(calls) == 2
    assert receipt.reproducibility.reproducible is True
    assert receipt.authorizes_distribution is False
    assert receipt.complete_for_scope is True
    assert receipt.frozen_tree.cargo_lock_generated is False
    assert {item.logical_name for item in receipt.frozen_tree.entries} >= {
        "Cargo.lock",
        "Cargo.toml",
        "src",
        "src/lib.rs",
    }
    assert receipt.invocations[0].argv_sha256 == receipt.invocations[1].argv_sha256
    for invocation in receipt.invocations:
        assert invocation.sandbox_engine is None
        assert invocation.sandbox_plan_sha256 is None
        assert invocation.sandbox_profile_sha256 is None
        assert invocation.sandbox_seccomp_sha256 is None
    callback_with_sandbox = tuple(
        replace(
            invocation,
            sandbox_engine="macos-sandbox-exec-v1",
            sandbox_plan_sha256="a" * 64,
            sandbox_profile_sha256="b" * 64,
        )
        for invocation in receipt.invocations
    )
    with pytest.raises(ValueError, match="cannot claim sandbox"):
        replace(receipt, invocations=callback_with_sandbox)
    serialized = json.dumps(receipt.to_dict(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert str(source) not in repr(receipt)

    first_file = calls[0].context.project_root / "src" / "lib.rs"
    second_file = calls[1].context.project_root / "src" / "lib.rs"
    assert (first_file.stat().st_dev, first_file.stat().st_ino) != (
        second_file.stat().st_dev,
        second_file.stat().st_ino,
    )


def test_executor_receipt_is_stable_across_fresh_private_roots(
    tmp_path: Path,
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    source = _project(tmp_path)
    observed_environments: list[dict[str, str]] = []

    def build(request):
        observed_environments.append(request.context.environment_dict())
        return _outputs(request.context.build_root)

    receipts = []
    for name in ("signing", "publication"):
        lifecycle_root = tmp_path / name
        lifecycle_root.mkdir()
        receipts.append(
            execute_full_c6_two_build(
                source,
                *_roots(lifecycle_root),
                build=build,
                cargo_command=STRICT_BUILD,
                base_environment={"PATH": "/usr/bin:/bin"},
                source_date_epoch=1,
            )
        )

    assert observed_environments[0]["CARGO_HOME"] != observed_environments[2][
        "CARGO_HOME"
    ]
    assert observed_environments[0]["CARGO_ENCODED_RUSTFLAGS"] != (
        observed_environments[2]["CARGO_ENCODED_RUSTFLAGS"]
    )
    assert receipts[0].invocations == receipts[1].invocations
    assert receipts[0].digest == receipts[1].digest

    changed_root = tmp_path / "changed-caller-environment"
    changed_root.mkdir()
    changed = execute_full_c6_two_build(
        source,
        *_roots(changed_root),
        build=build,
        cargo_command=STRICT_BUILD,
        base_environment={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        source_date_epoch=1,
    )
    assert changed.digest != receipts[0].digest


def test_executor_rejects_owned_environment_tamper_before_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _project(tmp_path)
    original = executor._build_environment

    def tampered_environment(*args, **kwargs):
        environment = original(*args, **kwargs)
        environment["HOME"] = str(tmp_path / "attacker-home")
        return environment

    monkeypatch.setattr(executor, "_build_environment", tampered_environment)

    with pytest.raises(
        executor.FullC6ExecutorError,
        match="executor-owned environment changed",
    ):
        executor.execute_full_c6_two_build(
            source,
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=1,
        )


def test_missing_lock_is_generated_once_offline_and_frozen_into_both_copies(
    tmp_path: Path,
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    source = _project(tmp_path, lock=False)
    roots = _roots(tmp_path)
    lock_calls = []
    observed_locks: list[bytes] = []

    def generate_lock(request):
        lock_calls.append(request)
        assert request.cargo_argv == ("cargo", "generate-lockfile", "--offline")
        assert request.inherit_env is False
        assert request.environment_dict()["CARGO_NET_OFFLINE"] == "true"
        (request.project_root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )

    def build(request):
        observed_locks.append((request.context.project_root / "Cargo.lock").read_bytes())
        return _outputs(request.context.build_root)

    receipt = execute_full_c6_two_build(
        source,
        *roots,
        build=build,
        cargo_command=STRICT_BUILD,
        lock_generator=generate_lock,
        source_date_epoch=7,
    )

    assert len(lock_calls) == 1
    assert len(observed_locks) == 2 and observed_locks[0] == observed_locks[1]
    assert receipt.frozen_tree.cargo_lock_generated is True
    assert not (source / "Cargo.lock").exists()


def test_command_factory_runs_twice_with_closed_bounded_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.full_c6_executor import FullC6BuildCommand

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    runs = []

    def fake_run(command, *, cwd, timeout, env, inherit_env, max_output_bytes):
        runs.append((command, cwd, timeout, dict(env), inherit_env, max_output_bytes))
        root = Path(cwd).parent
        _outputs(root)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)

    def command_factory(_context):
        return FullC6BuildCommand(
            argv=STRICT_BUILD,
            unsigned_wheel="output/demo.whl",
            sbom_json="output/sbom.json",
            provenance_input_json="output/provenance.json",
        )

    receipt = executor.execute_full_c6_two_build(
        source,
        *roots,
        command_factory=command_factory,
        base_environment={"PATH": "/usr/bin:/bin"},
        source_date_epoch=3,
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    assert len(runs) == 2
    for command, cwd, timeout, environment, inherit_env, output_bound in runs:
        assert tuple(command) == STRICT_BUILD
        assert Path(cwd).name == "project"
        assert timeout == 30
        assert environment["CARGO_NET_OFFLINE"] == "true"
        assert inherit_env is False
        assert output_bound == 4096
    assert receipt.reproducibility.reproducible is True


def test_native_orchestrator_builds_and_verifies_identical_external_wheels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.wheel_builder import verify_external_wheel_contract

    source = _native_project(tmp_path)
    roots = _roots(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    runs = []
    captures = []

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def capture_once(target_triple: str):
        captures.append(target_triple)
        return _pyo3_identity(target_triple)

    monkeypatch.setattr(executor, "capture_full_c6_pyo3_config", capture_once)

    def fake_run(command, *, cwd, timeout, env, inherit_env, max_output_bytes):
        project = Path(cwd)
        vendor_file = project / "vendor/demo-dep-1.2.3/src/lib.rs"
        config = project / ".cargo/config.toml"
        config_path = Path(env["PYO3_CONFIG_FILE"])
        runs.append(
            (
                tuple(command),
                project,
                dict(env),
                inherit_env,
                (vendor_file.stat().st_dev, vendor_file.stat().st_ino),
                (config_path.stat().st_dev, config_path.stat().st_ino),
            )
        )
        assert config.read_text(encoding="utf-8").endswith("offline = true\n")
        assert env["CARGO_BUILD_TARGET"] == "aarch64-apple-darwin"
        assert (
            env["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"]
            == str(native_tools.linker)
        )
        assert "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER" not in env
        assert "PYO3_PYTHON" not in env
        assert set(name for name in env if name.startswith("PYO3_")) == {
            "PYO3_CONFIG_FILE",
            "PYO3_ENVIRONMENT_SIGNATURE",
        }
        assert config_path.parent != Path(cwd).parent
        assert not config_path.is_relative_to(Path(cwd).parent)
        assert config_path.read_bytes() == _pyo3_identity().content
        assert env["PYO3_ENVIRONMENT_SIGNATURE"] == _pyo3_identity().digest
        assert env["RUSTC"] == str(native_tools.rustc)
        assert f"linker={native_tools.linker}" in env["CARGO_ENCODED_RUSTFLAGS"]
        tmpdir = Path(env["TMPDIR"])
        assert tmpdir == Path(cwd).parent / "tmp"
        assert stat.S_IMODE(tmpdir.stat().st_mode) == 0o700
        artifact = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
            / "lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"deterministic-native-extension")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    receipt = executor.execute_full_c6_native_two_build(
        source,
        *roots,
        base_environment=base_environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_output_license_contract(),
    )

    assert len(runs) == 2
    assert captures == ["aarch64-apple-darwin"]
    assert all(item[0] == STRICT_BUILD and item[3] is False for item in runs)
    assert runs[0][4] != runs[1][4]
    assert runs[0][2]["TMPDIR"] != runs[1][2]["TMPDIR"]
    assert receipt.execution_driver == executor.FULL_C6_NATIVE_EXECUTION_DRIVER
    assert receipt.execution_driver == "rextio-native-orchestrator-v1"
    assert receipt.postprocessor == executor.FULL_C6_NATIVE_POSTPROCESSOR
    assert receipt.target_triple == "aarch64-apple-darwin"
    assert receipt.pyo3_config_sha256 == _pyo3_identity().sha256
    assert receipt.pyo3_config_size == _pyo3_identity().size
    assert receipt.pyo3_config_profile_sha256 == _pyo3_identity().digest
    assert receipt.invocations[0].environment == receipt.invocations[1].environment
    tmpdir_binding = next(
        item
        for item in receipt.invocations[0].environment
        if item.name == "TMPDIR"
    )
    assert tmpdir_binding.value_sha256 == hashlib.sha256(
        b"/rextio/build/tmp"
    ).hexdigest()
    for invocation in receipt.invocations:
        assert invocation.sandbox_engine == "macos-sandbox-exec-v1"
        assert invocation.sandbox_plan_sha256 == "7" * 64
        assert invocation.sandbox_profile_sha256 == "8" * 64
        assert invocation.sandbox_seccomp_sha256 is None
    executor_receipt = receipt.executor_receipt
    mismatched_profile_contract = replace(
        executor_receipt.invocations[1],
        sandbox_profile_sha256="9" * 64,
    )
    with pytest.raises(ValueError, match="profile contracts differ"):
        replace(
            executor_receipt,
            invocations=(
                executor_receipt.invocations[0],
                mismatched_profile_contract,
            ),
        )
    mismatched_plan = replace(
        executor_receipt.invocations[1],
        sandbox_plan_sha256="6" * 64,
    )
    with pytest.raises(ValueError, match="sandbox plans differ"):
        replace(
            executor_receipt,
            invocations=(executor_receipt.invocations[0], mismatched_plan),
        )
    assert runs[0][2]["PYO3_CONFIG_FILE"] == runs[1][2]["PYO3_CONFIG_FILE"]
    assert runs[0][5] == runs[1][5]
    assert not Path(runs[0][2]["PYO3_CONFIG_FILE"]).exists()
    assert receipt.postprocessor_manifest_sha256 == hashlib.sha256(
        (source / executor.FULL_C6_NATIVE_DRIVER_MANIFEST).read_bytes()
    ).hexdigest()
    assert receipt.reproducibility.reproducible is True
    public = receipt.to_dict()
    assert public["cargo_workspace_sha256"] == cargo_workspace.digest
    assert public["cargo_vendor_layout"] == cargo_workspace.vendor_layout
    assert public["cargo_vendor_tree_sha256"] == cargo_workspace.vendor_tree_sha256
    assert public["cargo_executor_config"] == cargo_workspace.executor_config.to_dict()
    assert public["pyo3_config_profile"] == _pyo3_identity().to_dict()
    serialized_public = json.dumps(public, sort_keys=True)
    assert "wheel_bytes" not in serialized_public
    assert "PYO3_CONFIG_FILE" not in serialized_public
    assert all(str(root) not in serialized_public for root in roots)

    wheels = []
    for root in roots:
        wheel = next((root / "verified-output").glob("*.whl"))
        wheels.append(wheel.read_bytes())
        verified = verify_external_wheel_contract(wheel, _external_contract())
        assert verified.wheel_sha256 == receipt.reproducibility.wheel_sha256
        for name in (
            "rextio.preliminary-sbom.json",
            "rextio.preliminary-provenance-input.json",
        ):
            data = (root / "verified-output" / name).read_bytes()
            document = json.loads(data)
            assert data == json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            if name.endswith("sbom.json"):
                posture = document["rextio"]
            else:
                posture = document
            assert posture["authority"] == "non-authorizing"
            assert posture["distribution_authorized"] is False
    assert wheels[0] == wheels[1]


@pytest.mark.parametrize("fail_final_rewalk", (False, True))
def test_native_executor_performs_exactly_two_full_support_rewalks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_final_rewalk: bool,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    support_plan = SimpleNamespace(macos_platform_anchor=None)
    full_rewalks: list[int] = []

    def full_rewalk(*_args, **_kwargs):
        full_rewalks.append(len(full_rewalks) + 1)
        if fail_final_rewalk and len(full_rewalks) == 2:
            raise executor.FullC6ExecutorError(
                "simulated final support mutation"
            )
        return support_plan

    monkeypatch.setattr(executor, "_require_native_toolchain_support", full_rewalk)
    if fail_final_rewalk:
        with pytest.raises(
            executor.FullC6ExecutorError,
            match="final support mutation",
        ):
            executor.execute_full_c6_native_two_build(
                source,
                *_roots(tmp_path),
                base_environment=base_environment,
                source_date_epoch=1,
                toolchain=toolchain,
                native_tools=native_tools,
                cargo_workspace=cargo_workspace,
                output_license_contract=_output_license_contract(),
            )
    else:
        authority = executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )
        assert authority.executor_receipt.execution_driver == (
            executor.FULL_C6_NATIVE_EXECUTION_DRIVER
        )
    assert full_rewalks == [1, 2]


def test_native_executor_rejects_pyo3_config_changed_by_cargo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)

    def mutate_config(command, *, env, **_kwargs):
        config_path = Path(env["PYO3_CONFIG_FILE"])
        config_path.chmod(0o600)
        config_path.write_bytes(b"stale-config")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", mutate_config)
    with pytest.raises(executor.FullC6ExecutorError, match="PyO3 config became stale"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_executor_normalizes_pyo3_support_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    real_temporary_directory = executor.tempfile.TemporaryDirectory

    class CleanupFailure:
        def __init__(self, *args, **kwargs) -> None:
            self._directory = real_temporary_directory(*args, **kwargs)

        def __enter__(self):
            return self._directory.__enter__()

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self._directory.__exit__(exc_type, exc_value, traceback)
            raise OSError("simulated cleanup failure")

    monkeypatch.setattr(executor.tempfile, "TemporaryDirectory", CleanupFailure)
    with pytest.raises(
        executor.FullC6ExecutorError,
        match="read-only PyO3 support material failed closed",
    ):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_pyo3_support_root_rejects_identical_inode_replacement(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    support_root = tmp_path / "pyo3-support"
    support_root.mkdir(mode=0o700)
    identity = _pyo3_identity()
    config_path = executor.materialize_full_c6_pyo3_config(
        support_root,
        identity,
    )
    executor._seal_native_pyo3_config(config_path, identity)
    root_identity = os.lstat(support_root)
    config_identity = os.lstat(config_path)
    executor._verify_native_pyo3_support_root(
        support_root,
        root_identity,
        config_path=config_path,
        config_identity=config_identity,
        expected=identity,
    )

    config_path.unlink()
    config_path.write_bytes(identity.content)
    config_path.chmod(0o400)
    with pytest.raises(executor.FullC6ExecutorError, match="support config changed"):
        executor._verify_native_pyo3_support_root(
            support_root,
            root_identity,
            config_path=config_path,
            config_identity=config_identity,
            expected=identity,
        )


def test_native_pyo3_support_root_rejects_same_inode_metadata_drift(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    support_root = tmp_path / "pyo3-support"
    support_root.mkdir(mode=0o700)
    identity = _pyo3_identity()
    config_path = executor.materialize_full_c6_pyo3_config(
        support_root,
        identity,
    )
    executor._seal_native_pyo3_config(config_path, identity)
    root_identity = os.lstat(support_root)
    config_identity = os.lstat(config_path)

    os.utime(
        config_path,
        ns=(config_identity.st_atime_ns, config_identity.st_mtime_ns - 1_000_000_000),
        follow_symlinks=False,
    )
    changed = os.lstat(config_path)
    assert (changed.st_dev, changed.st_ino, changed.st_size) == (
        config_identity.st_dev,
        config_identity.st_ino,
        config_identity.st_size,
    )
    assert config_path.read_bytes() == identity.content
    assert (changed.st_mtime_ns, changed.st_ctime_ns) != (
        config_identity.st_mtime_ns,
        config_identity.st_ctime_ns,
    )

    with pytest.raises(executor.FullC6ExecutorError, match="support config changed"):
        executor._verify_native_pyo3_support_root(
            support_root,
            root_identity,
            config_path=config_path,
            config_identity=config_identity,
            expected=identity,
        )


def test_native_linux_seccomp_boundary_hashes_live_descriptor_bytes(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    payload = executor.linux_full_c6_seccomp_program()
    path = tmp_path / "seccomp.bpf"
    path.write_bytes(payload)
    descriptor = os.open(path, os.O_RDWR)
    lease = SimpleNamespace(fileno=lambda: descriptor)
    launch = object.__new__(executor.FullC6SandboxLaunch)
    object.__setattr__(launch, "command", ("sandbox",))
    object.__setattr__(launch, "preexec_fn", None)
    object.__setattr__(launch, "profile_sha256", "8" * 64)
    object.__setattr__(launch, "pass_fds", (descriptor,))
    object.__setattr__(launch, "seccomp_sha256", hashlib.sha256(payload).hexdigest())
    object.__setattr__(launch, "seccomp_lease", lease)
    try:
        assert executor._verify_native_linux_seccomp_launch(launch) == hashlib.sha256(
            payload
        ).hexdigest()
        os.ftruncate(descriptor, len(payload) - 1)
        with pytest.raises(executor.FullC6ExecutorError, match="bytes or identity"):
            executor._verify_native_linux_seccomp_launch(launch)
    finally:
        os.close(descriptor)


def test_native_executor_normalizes_sandbox_launch_construction_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )

    def reject_launch(*_args, **_kwargs):
        raise ValueError("simulated malformed launch")

    monkeypatch.setattr(executor, "prepare_full_c6_sandbox_launch", reject_launch)
    with pytest.raises(executor.FullC6ExecutorError, match="macOS read sandbox"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


@pytest.mark.parametrize("channel", ("PYO3_PYTHON", "PYO3_FUTURE_DISCOVERY"))
def test_native_executor_rejects_residual_or_additive_pyo3_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    real_bind = executor.bind_full_c6_pyo3_environment

    def bind_with_residual(*args, **kwargs):
        environment = real_bind(*args, **kwargs)
        environment[channel] = "ambient-override"
        return environment

    monkeypatch.setattr(
        executor,
        "bind_full_c6_pyo3_environment",
        bind_with_residual,
    )
    with pytest.raises(executor.FullC6ExecutorError, match="residual PyO3"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_receipt_cannot_omit_or_forge_pyo3_profile_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    authority = executor.execute_full_c6_native_two_build(
        source,
        *_roots(tmp_path),
        base_environment=base_environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_output_license_contract(),
    )

    receipt = authority.executor_receipt
    with pytest.raises(ValueError, match="PyO3 config profile"):
        replace(receipt, pyo3_config_profile_sha256=None)
    original = receipt.pyo3_config_profile_sha256
    object.__setattr__(receipt, "pyo3_config_profile_sha256", "0" * 64)
    assert not executor.validate_full_c6_native_execution_authority(authority)
    object.__setattr__(receipt, "pyo3_config_profile_sha256", original)
    assert executor.validate_full_c6_native_execution_authority(authority)


@pytest.mark.parametrize(
    "linker_variable",
    (
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    ),
)
def test_native_orchestrator_rejects_caller_linker_environment_override(
    tmp_path: Path,
    linker_variable: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )

    with pytest.raises(executor.FullC6ExecutorError, match="cannot override"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment={
                **base_environment,
                linker_variable: str(native_tools.linker),
            },
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("PWD", "/private/owner/project"),
        ("TMPDIR", "/private/owner/tmp"),
    ),
)
def test_executor_rejects_caller_owned_path_override(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _project(tmp_path)
    with pytest.raises(executor.FullC6ExecutorError, match="cannot override"):
        executor.execute_full_c6_two_build(
            source,
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            base_environment={name: value},
            source_date_epoch=1,
        )


def test_macos_native_tmpdir_requires_exact_private_directory_mode(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    build_root = tmp_path / "build"
    build_root.mkdir(mode=0o700)
    tmpdir = build_root / "tmp"
    tmpdir.mkdir(mode=0o700)
    environment = {"TMPDIR": str(tmpdir)}

    executor._verify_macos_native_tmpdir(environment, build_root=build_root)
    tmpdir.chmod(0o755)
    with pytest.raises(executor.FullC6ExecutorError, match="directory changed"):
        executor._verify_macos_native_tmpdir(environment, build_root=build_root)


@pytest.mark.parametrize(
    ("target_triple", "active", "inactive"),
    (
        (
            "aarch64-apple-darwin",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        ),
        (
            "x86_64-unknown-linux-gnu",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        ),
    ),
)
def test_native_linker_environment_binds_only_the_active_captured_linker(
    tmp_path: Path,
    target_triple: str,
    active: str,
    inactive: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path, target=target_triple)
    native_tools, base_environment, toolchain, _cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    environment = {
        **base_environment,
        "CARGO_ENCODED_RUSTFLAGS": "--remap-path-prefix=/one=/rextio/project\x1f"
        "--remap-path-prefix=/two=/rextio/build",
    }

    executor._bind_native_environment(
        environment,
        native_tools=native_tools,
        target_triple=target_triple,
    )

    assert environment[active] == str(native_tools.linker)
    assert inactive not in environment
    executor._verify_native_toolchain_invocation(
        STRICT_BUILD,
        environment=environment,
        toolchain=toolchain,
        native_tools=native_tools,
        target_triple=target_triple,
        require_owned_environment=True,
    )


def test_linux_payload_environment_projects_receipted_runtime_topology(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build import full_c6_linux_launcher as launcher
    from rextio.build.full_c6_toolchain_support import (
        FullC6SupportNamespaceMapping,
    )

    host = tmp_path.resolve()
    rows = {
        "toolchain-ar": ("/rextio/toolchain/bin/ar", "file"),
        "toolchain-ld": ("/rextio/toolchain/bin/ld", "file"),
        "toolchain-linker": ("/rextio/toolchain/bin/linker", "file"),
        "toolchain-ranlib": ("/rextio/toolchain/bin/ranlib", "file"),
        "toolchain-rustc": ("/rextio/toolchain/bin/rustc", "file"),
        "support-gcc-toolchain": ("/rextio/support/gcc-toolchain", "tree"),
        "support-python-library-root": (
            "/rextio/support/python-library-root",
            "tree",
        ),
        "support-runtime-libs": ("/x86_64-linux-gnu", "tree"),
    }
    mappings = tuple(
        FullC6SupportNamespaceMapping(
            logical_role=role,
            host_path=host / role,
            virtual_path=PurePosixPath(virtual_path),
            kind=kind,
        )
        for role, (virtual_path, kind) in rows.items()
    )
    by_role = {mapping.logical_role: mapping for mapping in mappings}
    environment = {**launcher._FIXED_ENVIRONMENT, "SOURCE_DATE_EPOCH": "0"}
    for name, role in executor._LINUX_NATIVE_PAYLOAD_ROLES.items():
        environment[name] = str(by_role[role].host_path)
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        (
            "--remap-path-prefix=/host/project=/rextio/project",
            "--remap-path-prefix=/host/build=/rextio/build",
            "-C",
            f"linker={by_role['toolchain-linker'].host_path}",
        )
    )

    projected = executor._linux_native_payload_environment(
        environment,
        support_plan=SimpleNamespace(namespace_mappings=mappings),
    )

    assert projected["LD_LIBRARY_PATH"].split(":") == [
        "/rextio/toolchain/lib",
        "/rextio/python/lib",
        "/rextio/support/python-library-root",
        "/x86_64-linux-gnu",
    ]
    assert projected["PATH"] == (
        "/rextio/toolchain/bin:/rextio/python/bin"
    )
    assert projected["PWD"] == "/rextio/project"
    assert projected["LIBRARY_PATH"].split(":") == [
        "/rextio/support/gcc-toolchain",
        "/x86_64-linux-gnu",
    ]
    assert projected["TMPDIR"] == "/tmp"
    assert all(
        "/rextio/support/runtime-libs" not in value
        for value in projected.values()
    )


def test_native_linker_flags_bind_reproducible_macho_identity_only_on_macos(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    linker = (tmp_path / "tool" / "linker").resolve()
    assert executor._native_linker_rustflags(
        linker,
        "aarch64-apple-darwin",
    ) == (
        "-C",
        f"linker={linker}",
        "-C",
        "link-arg=-undefined",
        "-C",
        "link-arg=dynamic_lookup",
        "-C",
        "link-arg=-Wl,-install_name,@rpath/lib_rextio_native.dylib",
    )
    assert executor._native_linker_rustflags(
        linker,
        "x86_64-unknown-linux-gnu",
    ) == ("-C", f"linker={linker}")


@pytest.mark.parametrize(
    ("target_triple", "expected"),
    (
        ("aarch64-apple-darwin", ".cpython-311-darwin.so"),
        (
            "x86_64-unknown-linux-gnu",
            ".cpython-311-x86_64-linux-gnu.so",
        ),
    ),
)
def test_native_extension_suffix_is_target_fixed_not_ambient(
    target_triple: str,
    expected: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    assert executor._full_c6_extension_suffix(target_triple) == expected
    with pytest.raises(executor.FullC6ExecutorError, match="unsupported"):
        executor._full_c6_extension_suffix("aarch64-unknown-linux-gnu")


@pytest.mark.parametrize(
    "mutation",
    ("missing-install-name", "wrong-install-name", "forbidden-no-uuid", "extra-flag"),
)
def test_native_owned_macho_linker_flags_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, _cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    environment = {
        **base_environment,
        "CARGO_ENCODED_RUSTFLAGS": "--remap-path-prefix=/one=/rextio/project\x1f"
        "--remap-path-prefix=/two=/rextio/build",
    }
    executor._bind_native_environment(
        environment,
        native_tools=native_tools,
        target_triple="aarch64-apple-darwin",
    )
    flags = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
    install_name = "link-arg=-Wl,-install_name,@rpath/lib_rextio_native.dylib"
    if mutation == "missing-install-name":
        flags.remove(install_name)
    elif mutation == "wrong-install-name":
        flags[flags.index(install_name)] = (
            "link-arg=-Wl,-install_name,@rpath/lib_other.dylib"
        )
    elif mutation == "forbidden-no-uuid":
        flags.extend(("-C", "link-arg=-Wl,-no_uuid"))
    else:
        flags.extend(("-C", "link-arg=-Wl,-headerpad_max_install_names"))
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)

    with pytest.raises(executor.FullC6ExecutorError, match="linker selection changed"):
        executor._verify_native_toolchain_invocation(
            STRICT_BUILD,
            environment=environment,
            toolchain=toolchain,
            native_tools=native_tools,
            target_triple="aarch64-apple-darwin",
            require_owned_environment=True,
        )


@pytest.mark.parametrize(
    "mutation",
    ("missing", "wrong-path", "same-name-shadow", "both-targets"),
)
def test_native_linker_environment_binding_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, _cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    environment = {
        **base_environment,
        "CARGO_ENCODED_RUSTFLAGS": "--remap-path-prefix=/one=/rextio/project\x1f"
        "--remap-path-prefix=/two=/rextio/build",
    }
    executor._bind_native_environment(
        environment,
        native_tools=native_tools,
        target_triple="aarch64-apple-darwin",
    )
    active = "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"
    inactive = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"
    if mutation == "missing":
        environment.pop(active)
    elif mutation == "wrong-path":
        environment[active] = str(native_tools.rustc)
    elif mutation == "same-name-shadow":
        shadow = tmp_path / "shadow" / native_tools.linker.name
        shadow.parent.mkdir()
        shadow.write_bytes(native_tools.linker.read_bytes())
        shadow.chmod(0o755)
        environment[active] = str(shadow.resolve())
    else:
        environment[inactive] = str(native_tools.linker)

    match = "inactive native linker" if mutation == "both-targets" else "owned environment"
    with pytest.raises(executor.FullC6ExecutorError, match=match):
        executor._verify_native_toolchain_invocation(
            STRICT_BUILD,
            environment=environment,
            toolchain=toolchain,
            native_tools=native_tools,
            target_triple="aarch64-apple-darwin",
            require_owned_environment=True,
        )


def test_native_authority_is_process_sealed_noncopyable_and_bytes_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    authority = executor.execute_full_c6_native_two_build(
        source,
        *_roots(tmp_path),
        base_environment=base_environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_output_license_contract(),
    )

    assert type(authority) is executor.FullC6NativeExecutionAuthority
    assert executor.validate_full_c6_native_execution_authority(authority)
    assert authority.authorizes_distribution is False
    public = authority.to_dict()
    assert len(public["wheel_captures"]) == 2
    assert public["wheel_captures"][0]["wheel_sha256"] == (
        authority.reproducibility.wheel_sha256
    )
    assert public["driver_manifest_sha256"] == authority.postprocessor_manifest_sha256
    assert public["wheel_filename"] == authority.wheel_filename
    assert public["external_wheel_contract"]["requirement"] == "vendor==1.0"
    assert public["output_license_contract"]["file_count"] == 1
    assert len(public["output_license_verifications"]) == 2
    serialized = json.dumps(public, sort_keys=True)
    assert "sealed-native-extension" not in serialized
    assert "MIT license for the generated output" not in serialized
    assert "data_hex" not in serialized
    assert "wheel_bytes" not in serialized
    with pytest.raises(TypeError):
        executor.FullC6NativeExecutionAuthority()
    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        copy.deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)

    filename = authority._wheel_filename  # type: ignore[attr-defined]
    object.__setattr__(authority, "_wheel_filename", "../substituted.whl")
    assert not executor.validate_full_c6_native_execution_authority(authority)
    object.__setattr__(authority, "_wheel_filename", filename)
    assert executor.validate_full_c6_native_execution_authority(authority)

    retained = authority._sbom_payloads  # type: ignore[attr-defined]
    object.__setattr__(authority, "_sbom_payloads", (b"{}", retained[1]))
    assert not executor.validate_full_c6_native_execution_authority(authority)
    with pytest.raises(executor.FullC6ExecutorError, match="stale"):
        authority.to_dict()


def test_native_authority_retains_exact_toolchain_object_and_seals_its_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    authority = executor.execute_full_c6_native_two_build(
        source,
        *_roots(tmp_path),
        base_environment=base_environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_output_license_contract(),
    )

    material = executor._validated_full_c6_native_output_material(authority)
    assert authority._toolchain is toolchain
    assert material.toolchain is toolchain
    assert authority.to_dict()["toolchain_sha256"] == toolchain.digest
    assert "_validated_full_c6_native_output_material" not in executor.__all__
    assert "_native_authority_seal_payload" not in executor.__all__

    equal_but_distinct = replace(toolchain)
    assert equal_but_distinct == toolchain
    assert equal_but_distinct is not toolchain
    object.__setattr__(authority, "_toolchain", equal_but_distinct)
    assert not executor.validate_full_c6_native_execution_authority(authority)
    with pytest.raises(executor.FullC6ExecutorError, match="stale"):
        executor._validated_full_c6_native_output_material(authority)

    object.__setattr__(authority, "_toolchain", toolchain)
    assert executor.validate_full_c6_native_execution_authority(authority)
    assert executor._validated_full_c6_native_output_material(authority).toolchain is toolchain


def test_native_executor_rejects_manifest_license_tamper_and_caller_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.full_c6_output_license import OutputWheelLicenseContract

    tamper_root = tmp_path / "manifest-tamper"
    source = _native_project(tamper_root)
    manifest_path = source / executor.FULL_C6_NATIVE_DRIVER_MANIFEST
    manifest = json.loads(manifest_path.read_bytes())
    license_file = manifest["output_wheel_license_contract"]["files"][0]
    license_file["data_hex"] = "00" + license_file["data_hex"][2:]
    manifest_path.write_bytes(
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    )
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tamper_root,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    with pytest.raises(executor.FullC6ExecutorError, match="manifest|license"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tamper_root),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )

    mismatch_root = tmp_path / "caller-mismatch"
    source = _native_project(mismatch_root)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        mismatch_root,
        source,
    )
    roots = _roots(mismatch_root)
    with pytest.raises(executor.FullC6ExecutorError, match="exact output license"):
        executor.execute_full_c6_native_two_build(
            source,
            *roots,
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=object(),  # type: ignore[arg-type]
        )
    mismatched = OutputWheelLicenseContract(
        expression="Apache-2.0",
        files=_output_license_contract().files,
    )
    with pytest.raises(executor.FullC6ExecutorError, match="differs from the frozen"):
        executor.execute_full_c6_native_two_build(
            source,
            *roots,
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=mismatched,
        )


def test_native_executor_rejects_output_license_byte_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.wheel_builder import ExternalWheelCapture

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    real_capture = executor.capture_external_wheel_contract

    def capture_with_stale_license(wheel_path, contract, **kwargs):
        capture = real_capture(wheel_path, contract, **kwargs)
        if Path(wheel_path).parent.name != "output":
            return capture
        changed = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(capture.wheel_bytes), "r") as source_archive:
            with zipfile.ZipFile(changed, "w") as changed_archive:
                for info in source_archive.infolist():
                    payload = source_archive.read(info)
                    if info.filename.endswith(".dist-info/licenses/LICENSE"):
                        payload = b"stale substituted license payload\n"
                    changed_archive.writestr(info, payload)
        wheel_bytes = changed.getvalue()
        return ExternalWheelCapture(
            verification=replace(
                capture.verification,
                wheel_sha256=hashlib.sha256(wheel_bytes).hexdigest(),
            ),
            wheel_bytes=wheel_bytes,
            native_member=capture.native_member,
        )

    monkeypatch.setattr(
        executor,
        "capture_external_wheel_contract",
        capture_with_stale_license,
    )
    with pytest.raises(executor.FullC6ExecutorError, match="wheel contract"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_executor_rejects_stale_or_nonreceipt_cargo_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    _install_successful_native_run(monkeypatch, executor)
    with pytest.raises(executor.FullC6ExecutorError, match="process-sealed"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=object(),  # type: ignore[arg-type]
            output_license_contract=_output_license_contract(),
        )

    source = _native_project(tmp_path / "stale")
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path / "stale",
        source,
    )
    object.__setattr__(cargo_workspace, "vendor_tree_sha256", "0" * 64)
    with pytest.raises(executor.FullC6ExecutorError, match="process-sealed"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path / "stale"),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_executor_rejects_vendor_mutation_after_cargo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, **_kwargs):
        artifact = (
            Path(cwd).parent
            / "target/aarch64-apple-darwin/release/lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"native")
        (Path(cwd) / "vendor/demo-dep-1.2.3/src/lib.rs").write_bytes(b"mutated")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    with pytest.raises(executor.FullC6ExecutorError, match="materialized project tree changed"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_rejects_missing_or_noncanonical_driver_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    for case in ("missing", "noncanonical"):
        case_root = tmp_path / case
        source = _native_project(case_root)
        manifest = source / executor.FULL_C6_NATIVE_DRIVER_MANIFEST
        if case == "missing":
            manifest.unlink()
        else:
            manifest.write_bytes(manifest.read_bytes() + b"\n")
        native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
            case_root,
            source,
        )
        with pytest.raises(executor.FullC6ExecutorError, match="manifest|missing"):
            executor.execute_full_c6_native_two_build(
                source,
                *_roots(case_root),
                base_environment=base_environment,
                source_date_epoch=1,
                toolchain=toolchain,
                native_tools=native_tools,
                cargo_workspace=cargo_workspace,
                output_license_contract=_output_license_contract(),
            )


def test_native_orchestrator_rejects_cargo_or_staging_boundary_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    source = _native_project(tmp_path / "missing-artifact")
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path / "missing-artifact",
        source,
    )
    monkeypatch.setattr(
        executor,
        "run_build_tool",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    with pytest.raises(executor.FullC6ExecutorError, match="artifact"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path / "missing-artifact"),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )

    source = _native_project(tmp_path / "external-source")
    external = source / "python-staging" / "vendor"
    external.mkdir()
    (external / "__init__.py").write_text("forbidden = True\n", encoding="utf-8")
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path / "external-source",
        source,
    )

    def build_artifact(command, *, cwd, **_kwargs):
        artifact = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
            / "lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"native")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", build_artifact)
    with pytest.raises(executor.FullC6ExecutorError, match="wheel contract|source"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path / "external-source"),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


@pytest.mark.parametrize("role", ("cargo", "rustc", "linker"))
def test_native_orchestrator_rejects_mismatched_concrete_tool_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    replacement = tmp_path / "native-tools" / f"other-{role}"
    replacement.write_bytes(f"#!/bin/sh\n# other {role}\n".encode())
    replacement.chmod(0o755)
    native_tools = replace(native_tools, **{role: replacement.resolve()})
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )

    with pytest.raises(executor.FullC6ExecutorError, match=role):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_binds_current_python_and_base_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.toolchain_identity import capture_tool_identity

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    source = _native_project(tmp_path / "python")
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path / "python",
        source,
    )
    fake_python = native_tools.cargo
    fake_python_identity = capture_tool_identity(
        "python",
        fake_python,
        reported_version="1.0.0",
    )
    with pytest.raises(executor.FullC6ExecutorError, match="current Python"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path / "python"),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=replace(toolchain, python=fake_python_identity),
            native_tools=replace(native_tools, python=fake_python),
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )

    source = _native_project(tmp_path / "environment")
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path / "environment",
        source,
    )
    changed_environment = {
        "PATH": f"{base_environment['PATH']}{os.pathsep}/usr/bin"
    }
    with pytest.raises(executor.FullC6ExecutorError, match="base environment"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path / "environment"),
            base_environment=changed_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


@pytest.mark.parametrize("reserved_root", (".cargo", ".Cargo", "vendor", "Vendor"))
def test_native_orchestrator_rejects_frozen_cargo_selector_config(
    tmp_path: Path,
    reserved_root: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    cargo_config = source / reserved_root / "config.toml"
    cargo_config.parent.mkdir()
    cargo_config.write_text(
        '[build]\nrustc = "/unbound/rustc"\n',
        encoding="utf-8",
    )
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )

    with pytest.raises(executor.FullC6ExecutorError, match="Cargo config"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_rejects_symlinked_artifact_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, **_kwargs):
        build_root = Path(cwd).parent
        outside = build_root / "outside-release"
        outside.mkdir()
        (outside / "lib_rextio_native.dylib").write_bytes(b"native")
        target = build_root / "target" / "aarch64-apple-darwin"
        target.mkdir()
        try:
            (target / "release").symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are unavailable")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    with pytest.raises(executor.FullC6ExecutorError, match="symlink"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_rejects_concurrent_artifact_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )
    release_path: Path | None = None

    def fake_run(command, *, cwd, **_kwargs):
        nonlocal release_path
        release_path = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
        )
        release_path.mkdir(parents=True)
        (release_path / "lib_rextio_native.dylib").write_bytes(b"trusted-native")
        outside = Path(cwd).parent / "substitute-release"
        outside.mkdir()
        (outside / "lib_rextio_native.dylib").write_bytes(b"substituted-native")
        return subprocess.CompletedProcess(command, 0, "", "")

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if (
            not swapped
            and path == "lib_rextio_native.dylib"
            and dir_fd is not None
            and release_path is not None
        ):
            swapped = True
            pinned = release_path.with_name("release-pinned")
            release_path.rename(pinned)
            try:
                release_path.symlink_to(
                    release_path.parents[2] / "substitute-release",
                    target_is_directory=True,
                )
            except (NotImplementedError, OSError):
                pytest.skip("symlinks are unavailable")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    monkeypatch.setattr(executor.os, "open", swapping_open)
    with pytest.raises(executor.FullC6ExecutorError, match="directory changed|symlink"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )
    assert swapped


@pytest.mark.parametrize(
    "location",
    ("project", "build-root", "ancestor", "cargo-home"),
)
def test_native_orchestrator_rechecks_cargo_config_discovery_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )

    def fake_run(command, *, cwd, env, **_kwargs):
        if location == "project":
            config = Path(cwd) / ".cargo" / "config.toml"
        elif location == "build-root":
            config = Path(cwd).parent / ".cargo" / "config"
        elif location == "ancestor":
            config = Path(cwd).parent.parent / ".cargo" / "config.toml"
        else:
            config = Path(env["CARGO_HOME"]) / "config.toml"
        config.parent.mkdir(exist_ok=True)
        config.write_text('[build]\nrustc = "/unbound/rustc"\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    with pytest.raises(executor.FullC6ExecutorError, match="Cargo config"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_rejects_cargo_config_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    cargo_directory = tmp_path / ".cargo"
    cargo_directory.mkdir()
    (cargo_directory / "config.toml").write_text(
        '[build]\nrustc = "/unbound/rustc"\n',
        encoding="utf-8",
    )
    substitute = tmp_path / "cargo-config-substitute"
    substitute.mkdir()
    (substitute / "config.toml").write_text(
        '[build]\nrustc = "/other/rustc"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and path == "config.toml" and dir_fd is not None:
            swapped = True
            cargo_directory.rename(tmp_path / ".cargo-pinned")
            try:
                cargo_directory.symlink_to(substitute, target_is_directory=True)
            except (NotImplementedError, OSError):
                pytest.skip("symlinks are unavailable")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(executor.os, "open", swapping_open)
    with pytest.raises(executor.FullC6ExecutorError, match="directory changed|Cargo config"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )
    assert swapped


def test_native_orchestrator_requires_empty_cargo_home_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    real_environment = executor._build_environment

    def populated_environment(*args, **kwargs):
        environment = real_environment(*args, **kwargs)
        (Path(environment["CARGO_HOME"]) / "unbound-state").write_text(
            "unexpected\n",
            encoding="utf-8",
        )
        return environment

    monkeypatch.setattr(executor, "_build_environment", populated_environment)
    with pytest.raises(executor.FullC6ExecutorError, match="CARGO_HOME must be empty"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_rejects_wheel_member_different_from_cargo_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, **_kwargs):
        artifact = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
            / "lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"cargo-native")
        return subprocess.CompletedProcess(command, 0, "", "")

    real_builder = executor.build_artifact_wheel

    def mismatched_builder(project_root, python_dir, dist_dir, **kwargs):
        (Path(python_dir) / "_rextio_native.cpython-311-test.so").write_bytes(
            b"different-native"
        )
        return real_builder(project_root, python_dir, dist_dir, **kwargs)

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    monkeypatch.setattr(executor, "build_artifact_wheel", mismatched_builder)
    with pytest.raises(executor.FullC6ExecutorError, match="wheel contract"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=_output_license_contract(),
        )


def test_native_orchestrator_materializes_the_exact_captured_wheel_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    roots = _roots(tmp_path)
    native_tools, base_environment, toolchain, cargo_workspace = _native_inputs(
        tmp_path,
        source,
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda _target: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, **_kwargs):
        artifact = (
            Path(cwd).parent
            / "target"
            / "aarch64-apple-darwin"
            / "release"
            / "lib_rextio_native.dylib"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"captured-native")
        return subprocess.CompletedProcess(command, 0, "", "")

    real_capture = executor.capture_external_wheel_contract

    def swap_after_capture(wheel_path, contract, **kwargs):
        capture = real_capture(wheel_path, contract, **kwargs)
        path = Path(wheel_path)
        if path.parent.name == "output":
            path.write_bytes(b"replacement-after-verification")
        return capture

    monkeypatch.setattr(executor, "run_build_tool", fake_run)
    monkeypatch.setattr(
        executor,
        "capture_external_wheel_contract",
        swap_after_capture,
    )
    receipt = executor.execute_full_c6_native_two_build(
        source,
        *roots,
        base_environment=base_environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_output_license_contract(),
    )

    for root in roots:
        assert next((root / "output").glob("*.whl")).read_bytes() == (
            b"replacement-after-verification"
        )
        verified = next((root / "verified-output").glob("*.whl"))
        assert hashlib.sha256(verified.read_bytes()).hexdigest() == (
            receipt.reproducibility.wheel_sha256
        )


@pytest.mark.parametrize(
    "command",
    (
        ("cargo", "build", "--release"),
        ("cargo", "build", "--release", "--locked", "--offline"),
        ("cargo", "build", "--release", "--locked", "--offline", "--frozen", "--config", "net.offline=false"),
        ("not-cargo", "build", "--locked", "--offline", "--frozen"),
    ),
)
def test_executor_rejects_missing_or_boundary_changing_strict_flags(
    tmp_path: Path,
    command: tuple[str, ...],
) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    with pytest.raises(FullC6ExecutorError, match="strict|Cargo"):
        execute_full_c6_two_build(
            _project(tmp_path),
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=command,
            source_date_epoch=0,
        )


@pytest.mark.parametrize(
    "environment",
    (
        {"CARGO_NET_OFFLINE": "false"},
        {"HTTP_PROXY": "http://127.0.0.1:8080"},
        {"RUSTC_WRAPPER": "ccache"},
        {"not_allowlisted": "value"},
    ),
)
def test_executor_rejects_environment_override_or_leakage(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    with pytest.raises(FullC6ExecutorError, match="environment|override|proxy|wrapper"):
        execute_full_c6_two_build(
            _project(tmp_path),
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            base_environment=environment,
            source_date_epoch=0,
        )


def test_executor_rejects_unsafe_quarantine_roots(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    first, second = _roots(tmp_path)
    first.chmod(0o755)
    with pytest.raises(FullC6ExecutorError, match="0700"):
        execute_full_c6_two_build(
            source,
            first,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    first.chmod(0o700)
    (first / "existing").write_text("unsafe", encoding="utf-8")
    with pytest.raises(FullC6ExecutorError, match="empty"):
        execute_full_c6_two_build(
            source,
            first,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    (first / "existing").unlink()
    link = tmp_path / "quarantine-link"
    try:
        link.symlink_to(first, target_is_directory=True)
    except (NotImplementedError, OSError):
        return
    with pytest.raises(FullC6ExecutorError, match="symlink|real"):
        execute_full_c6_two_build(
            source,
            link,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_executor_rejects_source_symlinks_hardlinks_and_special_files(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    symlink = source / "linked.rs"
    try:
        symlink.symlink_to(source / "src" / "lib.rs")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(FullC6ExecutorError, match="symlink"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    symlink.unlink()
    hardlink = source / "hardlinked.rs"
    os.link(source / "src" / "lib.rs", hardlink)
    with pytest.raises(FullC6ExecutorError, match="hardlink"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    hardlink.unlink()
    if hasattr(os, "mkfifo"):
        fifo = source / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(FullC6ExecutorError, match="non-regular"):
            execute_full_c6_two_build(
                source,
                *roots,
                build=lambda request: _outputs(request.context.build_root),
                cargo_command=STRICT_BUILD,
                source_date_epoch=0,
            )


def test_executor_rejects_source_or_project_mutation(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    calls = 0

    def mutate_source(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            (source / "src" / "lib.rs").write_text("mutated\n", encoding="utf-8")
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="source tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_source,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "other")
    roots = _roots(tmp_path / "other")

    def mutate_copy(request):
        (request.context.project_root / "src" / "lib.rs").write_text(
            "mutated copy\n", encoding="utf-8"
        )
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="materialized project tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_copy,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "root-mode")
    roots = _roots(tmp_path / "root-mode")

    def weaken_root(request):
        request.context.build_root.chmod(0o755)
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="quarantine root changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=weaken_root,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "cross-build")
    roots = _roots(tmp_path / "cross-build")
    first_project = None

    def mutate_prior_copy(request):
        nonlocal first_project
        if first_project is None:
            first_project = request.context.project_root
        else:
            (first_project / "src" / "lib.rs").write_text(
                "mutated after first build\n", encoding="utf-8"
            )
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="materialized project tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_prior_copy,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_executor_rejects_nonreproducible_builds_and_hardlinked_outputs(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)

    def different(request):
        return _outputs(
            request.context.build_root,
            wheel=f"wheel-{request.context.ordinal}".encode(),
        )

    with pytest.raises(FullC6ExecutorError, match="wheel bytes"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=different,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "hardlink-case")
    roots = _roots(tmp_path / "hardlink-case")

    def hardlinked(request):
        outputs = _outputs(request.context.build_root)
        outputs.sbom_json.unlink()
        os.link(outputs.unsigned_wheel, outputs.sbom_json)
        return outputs

    with pytest.raises(FullC6ExecutorError, match="hardlink|independent"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=hardlinked,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_lock_generation_may_only_add_lockfile(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path, lock=False)
    roots = _roots(tmp_path)

    def malicious_lock_generator(request):
        (request.project_root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (request.project_root / "Cargo.toml").write_text("changed\n", encoding="utf-8")

    with pytest.raises(FullC6ExecutorError, match="outside Cargo.lock"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            lock_generator=malicious_lock_generator,
            source_date_epoch=0,
        )
    assert list(roots[0].iterdir()) == []


@pytest.mark.parametrize(
    "overrides",
    (
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"max_output_bytes": 0},
        {"max_output_bytes": 16 * 1024 * 1024 + 1},
        {"source_date_epoch": -1},
    ),
)
def test_executor_rejects_unbounded_time_output_or_epoch(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    arguments = {
        "build": lambda request: _outputs(request.context.build_root),
        "cargo_command": STRICT_BUILD,
        "source_date_epoch": 0,
        **overrides,
    }
    with pytest.raises((ValueError, RuntimeError), match="bound|timeout|SOURCE_DATE_EPOCH"):
        execute_full_c6_two_build(_project(tmp_path), *_roots(tmp_path), **arguments)
