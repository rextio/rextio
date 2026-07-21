"""Adversarial tests for the strict Full C6 two-build executor."""

from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest


STRICT_BUILD = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
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


def _native_inputs(tmp_path: Path, lock_data: bytes):
    from rextio.build.input_closure import ExactFileIdentity
    from rextio.build.full_c6_executor import FullC6NativeToolPaths
    from rextio.build.toolchain_identity import (
        ArgvIdentity,
        BuildToolchainIdentity,
        CargoSourcesIdentity,
        RextioIdentity,
        capture_environment_identity,
        capture_tool_identity,
    )

    tool_dir = tmp_path / "native-tools"
    tool_dir.mkdir(parents=True)
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
        cargo_sources=CargoSourcesIdentity(
            root_package="demo",
            lock_file=ExactFileIdentity(
                "cargo/Cargo.lock",
                "cargo-lockfile",
                hashlib.sha256(lock_data).hexdigest(),
                len(lock_data),
                False,
            ),
            packages=(),
        ),
    )
    return native_tools, base_environment, toolchain


def _native_project(tmp_path: Path, *, target: str = "aarch64-apple-darwin"):
    from rextio.build.full_c6_executor import full_c6_native_driver_manifest_bytes

    root = _project(tmp_path)
    package = root / "python-staging" / "app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 42\n", encoding="utf-8")
    (root / "rextio.full-c6-native-driver.json").write_bytes(
        full_c6_native_driver_manifest_bytes(
            target_triple=target,
            distribution_name="demo-artifact",
            cargo_argv=STRICT_BUILD,
            external_contract=_external_contract(),
        )
    )
    return root


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    roots = (tmp_path / "quarantine-one", tmp_path / "quarantine-two")
    for root in roots:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    return roots


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
    serialized = json.dumps(receipt.to_dict(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert str(source) not in repr(receipt)

    first_file = calls[0].context.project_root / "src" / "lib.rs"
    second_file = calls[1].context.project_root / "src" / "lib.rs"
    assert (first_file.stat().st_dev, first_file.stat().st_ino) != (
        second_file.stat().st_dev,
        second_file.stat().st_ino,
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
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )
    runs = []

    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda: ".cpython-311-test.so",
    )

    def fake_run(command, *, cwd, timeout, env, inherit_env, max_output_bytes):
        runs.append((tuple(command), Path(cwd), dict(env), inherit_env))
        assert env["CARGO_BUILD_TARGET"] == "aarch64-apple-darwin"
        assert env["PYO3_PYTHON"] == str(native_tools.python)
        assert env["RUSTC"] == str(native_tools.rustc)
        assert f"linker={native_tools.linker}" in env["CARGO_ENCODED_RUSTFLAGS"]
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
    )

    assert len(runs) == 2
    assert all(item[0] == STRICT_BUILD and item[3] is False for item in runs)
    assert receipt.execution_driver == executor.FULL_C6_NATIVE_EXECUTION_DRIVER
    assert receipt.execution_driver == "rextio-native-orchestrator-v1"
    assert receipt.postprocessor == executor.FULL_C6_NATIVE_POSTPROCESSOR
    assert receipt.target_triple == "aarch64-apple-darwin"
    assert receipt.postprocessor_manifest_sha256 == hashlib.sha256(
        (source / executor.FULL_C6_NATIVE_DRIVER_MANIFEST).read_bytes()
    ).hexdigest()
    assert receipt.reproducibility.reproducible is True

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
        native_tools, base_environment, toolchain = _native_inputs(
            case_root,
            (source / "Cargo.lock").read_bytes(),
        )
        with pytest.raises(executor.FullC6ExecutorError, match="manifest|missing"):
            executor.execute_full_c6_native_two_build(
                source,
                *_roots(case_root),
                base_environment=base_environment,
                source_date_epoch=1,
                toolchain=toolchain,
                native_tools=native_tools,
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
        lambda: ".cpython-311-test.so",
    )

    source = _native_project(tmp_path / "missing-artifact")
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path / "missing-artifact",
        (source / "Cargo.lock").read_bytes(),
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
        )

    source = _native_project(tmp_path / "external-source")
    external = source / "python-staging" / "vendor"
    external.mkdir()
    (external / "__init__.py").write_text("forbidden = True\n", encoding="utf-8")
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path / "external-source",
        (source / "Cargo.lock").read_bytes(),
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
        )


@pytest.mark.parametrize("role", ("cargo", "rustc", "linker"))
def test_native_orchestrator_rejects_mismatched_concrete_tool_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
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
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path / "python",
        (source / "Cargo.lock").read_bytes(),
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
        )

    source = _native_project(tmp_path / "environment")
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path / "environment",
        (source / "Cargo.lock").read_bytes(),
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
        )


def test_native_orchestrator_rejects_frozen_cargo_selector_config(
    tmp_path: Path,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    cargo_config = source / ".cargo" / "config.toml"
    cargo_config.parent.mkdir()
    cargo_config.write_text(
        '[build]\nrustc = "/unbound/rustc"\n',
        encoding="utf-8",
    )
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )

    with pytest.raises(executor.FullC6ExecutorError, match="Cargo config"):
        executor.execute_full_c6_native_two_build(
            source,
            *_roots(tmp_path),
            base_environment=base_environment,
            source_date_epoch=1,
            toolchain=toolchain,
            native_tools=native_tools,
        )


def test_native_orchestrator_rejects_symlinked_artifact_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda: ".cpython-311-test.so",
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
        )


def test_native_orchestrator_rejects_concurrent_artifact_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda: ".cpython-311-test.so",
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
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
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
        )


def test_native_orchestrator_rejects_cargo_config_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
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
        )
    assert swapped


def test_native_orchestrator_requires_empty_cargo_home_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
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
        )


def test_native_orchestrator_rejects_wheel_member_different_from_cargo_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda: ".cpython-311-test.so",
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
        )


def test_native_orchestrator_materializes_the_exact_captured_wheel_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor

    source = _native_project(tmp_path)
    roots = _roots(tmp_path)
    native_tools, base_environment, toolchain = _native_inputs(
        tmp_path,
        (source / "Cargo.lock").read_bytes(),
    )
    monkeypatch.setattr(
        executor,
        "detect_host_target_triple",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        executor,
        "_full_c6_extension_suffix",
        lambda: ".cpython-311-test.so",
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
