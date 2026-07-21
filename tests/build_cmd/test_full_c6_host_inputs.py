"""Focused adversarial tests for strict Full C6 host prerequisites."""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pickle
import stat
import sys
from types import SimpleNamespace

import pytest

from rextio.__about__ import __version__
from rextio.analyzer.project_scanner import scan_python_files
from rextio.build import full_c6_host_inputs as host_inputs
from rextio.build import full_c6_native_output, full_c6_pipeline, full_c6_production
from rextio.build.full_c6_host_inputs import (
    FULL_C6_CARGO_ARGUMENTS,
    FULL_C6_SOURCE_DATE_EPOCH,
    FullC6AnalysisScope,
    FullC6HostInputsError,
    collect_full_c6_analysis_scope,
    collect_full_c6_host_prerequisites,
    require_full_c6_analysis_scope,
)
from rextio.build.full_c6_cargo_workspace import (
    compute_full_c6_cargo_vendor_tree_sha256,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.toolchain_identity import capture_argv_identity
from rextio.build.input_closure import ExactFileIdentity
from rextio.build.toolchain_identity import ToolIdentity
from rextio.config.schema import BuildConfig, RextioConfig, ToolchainConfig


def _record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return f"sha256={encoded}"


def _write_record_install(
    tmp_path: Path,
    *,
    rows: list[tuple[str, bytes]] | None = None,
) -> tuple[Path, Path, Path]:
    root = (tmp_path / "site-packages").resolve()
    package = root / "rextio"
    dist_info = root / f"rextio-{__version__}.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    members = rows or [
        ("rextio/__init__.py", b"from .__about__ import __version__\n"),
        ("rextio/__about__.py", f'__version__ = "{__version__}"\n'.encode()),
        ("rextio/build.py", b"VALUE = 1\n"),
    ]
    record_rows: list[list[str]] = []
    for logical, data in members:
        path = root.joinpath(*Path(logical).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        record_rows.append([logical, _record_hash(data), str(len(data))])
    record = dist_info / "RECORD"
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerows(record_rows)
    writer.writerow([f"{dist_info.name}/RECORD", "", ""])
    record.write_text(stream.getvalue(), encoding="utf-8")
    return root, record, package / "__init__.py"


def _capture_fixture(tmp_path: Path):
    root, record, module = _write_record_install(tmp_path)
    return host_inputs._capture_record_backed_rextio_identity(
        distribution_root=root,
        record_path=record,
        module_file=module,
        version=__version__,
    )


def test_record_backed_inventory_captures_every_installed_member(tmp_path: Path) -> None:
    identity = _capture_fixture(tmp_path)

    assert identity.version == __version__
    assert tuple(item.logical_name for item in identity.files) == (
        "rextio/__about__.py",
        "rextio/__init__.py",
        "rextio/build.py",
    )


@pytest.mark.parametrize("mutation", ["missing", "unrecorded", "symlink", "hardlink"])
def test_record_inventory_rejects_incomplete_or_aliased_source(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    source = root / "rextio" / "build.py"
    if mutation == "missing":
        source.unlink()
    elif mutation == "unrecorded":
        (root / "rextio" / "extra.py").write_text("VALUE = 2\n", encoding="utf-8")
    elif mutation == "symlink":
        source.unlink()
        target = tmp_path / "outside.py"
        target.write_text("VALUE = 1\n", encoding="utf-8")
        source.symlink_to(target)
    else:
        alias = tmp_path / "source-alias.py"
        os.link(source, alias)

    with pytest.raises(FullC6HostInputsError):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


@pytest.mark.parametrize(
    "row",
    [
        "rextio/../escape.py",
        "rextio/Thing.py",
    ],
)
def test_record_inventory_rejects_escape_and_casefold_alias(
    tmp_path: Path,
    row: str,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    existing = (root / "rextio" / "build.py").read_bytes()
    lines = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    lines.insert(-1, [row, _record_hash(existing), str(len(existing))])
    if row.endswith("Thing.py"):
        lines.insert(-1, ["rextio/thing.py", _record_hash(existing), str(len(existing))])
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(lines)
    record.write_text(stream.getvalue(), encoding="utf-8")

    with pytest.raises(FullC6HostInputsError, match="escaped|alias"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_rejects_running_module_from_elsewhere(tmp_path: Path) -> None:
    root, record, _module = _write_record_install(tmp_path)
    outside = tmp_path / "outside-init.py"
    outside.write_text("", encoding="utf-8")

    with pytest.raises(FullC6HostInputsError, match="running Rextio"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=outside,
            version=__version__,
        )


def test_installed_inventory_rejects_editable_distribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, record, _module = _write_record_install(tmp_path)

    class EditableDistribution:
        version = __version__
        metadata = {"Name": "rextio"}
        files = (Path(record.relative_to(root)),)

        @staticmethod
        def read_text(name: str) -> str | None:
            assert name == "direct_url.json"
            return json.dumps({"dir_info": {"editable": True}})

        @staticmethod
        def locate_file(path: object) -> Path:
            return root / str(path)

    monkeypatch.setattr(host_inputs.metadata, "distribution", lambda _name: EditableDistribution())

    with pytest.raises(FullC6HostInputsError, match="editable"):
        host_inputs._capture_installed_rextio_identity()


def test_project_root_requires_raw_absolute_nofollow_path(tmp_path: Path) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    with pytest.raises(FullC6HostInputsError, match="raw lexical absolute"):
        host_inputs._open_raw_project_root(Path("project"))

    alias = tmp_path / "alias"
    alias.symlink_to(project)
    with pytest.raises(FullC6HostInputsError, match="symlink"):
        host_inputs._open_raw_project_root(alias.resolve(strict=False).parent / alias.name)


def test_inherited_environment_is_reduced_to_two_discovery_values() -> None:
    result = host_inputs._validate_inherited_environment(
        {
            "PATH": "/tools",
            "RUSTUP_HOME": "/rustup",
            "CC": "attacker-cc",
            "RUSTFLAGS": "--cfg attacker",
            "HTTP_PROXY": "http://proxy.invalid",
            "TOKEN": "secret",
        }
    )

    assert result == {"PATH": "/tools", "RUSTUP_HOME": "/rustup"}


def _host_config(**build_overrides: object) -> RextioConfig:
    values: dict[str, object] = {
        "artifact_signing_request_output": (
            "state/rextio.full-c6-final-authorization-request.json"
        ),
        **build_overrides,
    }
    return RextioConfig(build=BuildConfig(**values))  # type: ignore[arg-type]


def _write_cargo_workspace(
    project: Path,
    *,
    extra_files: dict[str, bytes] | None = None,
) -> tuple[Path, Path, str, str]:
    lock = project / "Cargo.lock"
    lock.write_text(
        """\
version = 4

[[package]]
name = "rextio_generated_native"
version = "0.1.0"

[[package]]
name = "demo-dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
        encoding="utf-8",
    )
    vendor = project / "vendor"
    package = vendor / "demo-dep-1.2.3"
    (package / "src").mkdir(parents=True)
    files = {
        "Cargo.toml": (
            b'[package]\nname = "demo-dep"\nversion = "1.2.3"\n'
            b'license = "MIT"\nlicense-file = "LICENSE"\n'
        ),
        "LICENSE": b"MIT license evidence\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
        **(extra_files or {}),
    }
    for relative, data in files.items():
        path = package.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
    checksum = {
        "files": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(files.items())
        },
        "package": "a" * 64,
    }
    (package / ".cargo-checksum.json").write_text(
        json.dumps(checksum, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return (
        lock,
        vendor,
        hashlib.sha256(lock.read_bytes()).hexdigest(),
        compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )


def _analysis_scope_fixture(
    tmp_path: Path,
    *,
    extra_files: dict[str, bytes] | None = None,
) -> tuple[Path, RextioConfig, FullC6AnalysisScope, Path, Path]:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    (project / "app.py").write_text("VALUE: int = 1\n", encoding="utf-8")
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(
        project,
        extra_files=extra_files,
    )
    config = _host_config(
        artifact_distribution_policy="full-c6-required",
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    scope = collect_full_c6_analysis_scope(project, config=config)
    return project, config, scope, lock, vendor


def test_analysis_scope_excludes_only_verified_vendor_python(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(
        tmp_path,
        extra_files={"etc/libc-util.py": b"async = 1\n"},
    )
    helper = vendor / "demo-dep-1.2.3" / "etc" / "libc-util.py"
    adjacent = project / "cargo-vendor-shadow" / "helper.py"
    adjacent.parent.mkdir()
    adjacent.write_text("VALUE = 3\n", encoding="utf-8")

    assert helper in scan_python_files(project)
    strict_files = scan_python_files(
        project,
        full_c6_analysis_scope=scope,
        full_c6_config=config,
    )
    assert strict_files == [project / "app.py", adjacent]

    ignored = project / "ignored.py"
    ignored.write_text("VALUE = 2\n", encoding="utf-8")
    (project / ".rextioignore").write_text("ignored.py\n", encoding="utf-8")
    ordinary = scan_python_files(project)
    assert ignored not in ordinary
    assert helper in ordinary


@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_analysis_scope_rejects_every_present_rextioignore(
    tmp_path: Path,
    kind: str,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    config = _host_config(
        artifact_distribution_policy="full-c6-required",
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    ignore = project / ".rextioignore"
    if kind == "file":
        ignore.write_text("vendor/\n", encoding="utf-8")
    elif kind == "directory":
        ignore.mkdir()
    else:
        ignore.symlink_to("missing-ignore-target")

    with pytest.raises(FullC6HostInputsError, match="forbids"):
        collect_full_c6_analysis_scope(project, config=config)


def test_analysis_scope_is_exact_typed_root_and_config_authority(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)

    assert type(scope) is FullC6AnalysisScope
    assert require_full_c6_analysis_scope(
        scope,
        project_root=project,
        config=config,
    ) == vendor
    with pytest.raises(TypeError, match="verified Cargo authority"):
        FullC6AnalysisScope()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(scope)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(scope)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(scope)
    with pytest.raises(FullC6HostInputsError, match="invalid"):
        require_full_c6_analysis_scope(vendor, project_root=project, config=config)
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(
            scope,
            project_root=project,
            config=RextioConfig(build=config.build),
        )
    other = (tmp_path / "other").resolve()
    other.mkdir()
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=other, config=config)

    object.__setattr__(scope, "_seal", b"forged")
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


@pytest.mark.parametrize("mutation", ("vendor-bytes", "lock-bytes", "vendor-replace"))
def test_analysis_scope_revalidates_cargo_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, config, scope, lock, vendor = _analysis_scope_fixture(tmp_path)
    if mutation == "vendor-bytes":
        (vendor / "demo-dep-1.2.3" / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 { 7 }\n",
            encoding="utf-8",
        )
    elif mutation == "lock-bytes":
        lock.write_text(lock.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    else:
        moved = project / "old-vendor"
        vendor.rename(moved)
        vendor.mkdir()

    with pytest.raises(FullC6HostInputsError):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


@pytest.mark.parametrize("joint_vendor_update", (False, True))
def test_analysis_scope_rejects_changed_config_pin_even_if_vendor_matches(
    tmp_path: Path,
    joint_vendor_update: bool,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)
    new_pin = "0" * 64
    if joint_vendor_update:
        source = vendor / "demo-dep-1.2.3" / "src" / "lib.rs"
        payload = b"pub fn answer() -> u32 { 100 }\n"
        source.write_bytes(payload)
        checksum_path = vendor / "demo-dep-1.2.3" / ".cargo-checksum.json"
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        checksum["files"]["src/lib.rs"] = hashlib.sha256(payload).hexdigest()
        checksum_path.write_text(
            json.dumps(checksum, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        new_pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    object.__setattr__(config.build, "artifact_cargo_vendor_sha256", new_pin)

    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


def test_analysis_scan_fails_when_vendor_changes_between_validations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)
    original = host_inputs.require_full_c6_analysis_scope
    calls = 0

    def race(value: object, *, project_root: Path, config: RextioConfig) -> Path:
        nonlocal calls
        result = original(value, project_root=project_root, config=config)
        calls += 1
        if calls == 1:
            (vendor / "demo-dep-1.2.3" / "src" / "lib.rs").write_text(
                "pub fn answer() -> u32 { 9 }\n",
                encoding="utf-8",
            )
        return result

    monkeypatch.setattr(host_inputs, "require_full_c6_analysis_scope", race)
    with pytest.raises(FullC6HostInputsError):
        scan_python_files(
            project,
            full_c6_analysis_scope=scope,
            full_c6_config=config,
        )
    assert calls == 1


def test_configured_cargo_workspace_requires_exact_lock_and_vendor_pins(
    tmp_path: Path,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    config = _host_config(
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )

    workspace = host_inputs._collect_configured_cargo_workspace(project, config)
    assert validate_full_c6_cargo_dependency_workspace_receipt(workspace)
    assert workspace.cargo_sources is not None
    assert workspace.cargo_sources.lock_file.sha256 == lock_sha256
    assert workspace.vendor_tree_sha256 == vendor_sha256

    changed_lock = _host_config(
        artifact_cargo_lock="Cargo.lock",
        artifact_cargo_lock_sha256="0" * 64,
        artifact_cargo_vendor="vendor",
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    with pytest.raises(FullC6HostInputsError, match="Cargo.lock SHA-256"):
        host_inputs._collect_configured_cargo_workspace(project, changed_lock)

    changed_vendor = _host_config(
        artifact_cargo_lock="Cargo.lock",
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor="vendor",
        artifact_cargo_vendor_sha256="0" * 64,
    )
    with pytest.raises(FullC6HostInputsError, match="Cargo vendor SHA-256"):
        host_inputs._collect_configured_cargo_workspace(project, changed_vendor)


def test_toolchain_retains_workspace_sources_and_reprobes_exact_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    workspace = host_inputs._collect_configured_cargo_workspace(
        project,
        _host_config(
            artifact_cargo_lock=lock.name,
            artifact_cargo_lock_sha256=lock_sha256,
            artifact_cargo_vendor=vendor.name,
            artifact_cargo_vendor_sha256=vendor_sha256,
        ),
    )
    tools = project / "tools"
    tools.mkdir()
    paths: dict[str, Path] = {}
    for name in ("python", "cargo", "rustc", "linker", "otool"):
        path = tools / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        paths[name] = path
    rextio_identity = _capture_fixture(tmp_path / "install")
    probes: list[str] = []

    monkeypatch.setattr(host_inputs, "_resolve_python", lambda _config: paths["python"])
    monkeypatch.setattr(
        host_inputs,
        "_resolve_required_tool",
        lambda _name, _configured: paths["cargo"],
    )
    monkeypatch.setattr(
        host_inputs,
        "_resolve_actual_rust_tools",
        lambda _cargo, **_kwargs: (paths["cargo"], paths["rustc"]),
    )
    monkeypatch.setattr(
        host_inputs,
        "_resolve_executable",
        lambda path: {
            Path("/usr/bin/clang"): paths["linker"],
            Path("/usr/bin/otool"): paths["otool"],
        }.get(path, path),
    )
    monkeypatch.setattr(
        host_inputs,
        "_minimal_build_environment",
        lambda _cargo: {"PATH": str(tools)},
    )

    def probe(path: Path, **_kwargs: object) -> str:
        name = path.name
        probes.append(name)
        return {
            "python": "Python 3.11.9",
            "cargo": "cargo 1.85.0",
            "rustc": "rustc 1.85.0",
            "linker": "clang 16.0.0",
            "otool": "otool 1000.0.0",
        }[name]

    monkeypatch.setattr(host_inputs, "_probe_version", probe)
    monkeypatch.setattr(
        host_inputs,
        "_probe_rustc_host",
        lambda _path, **_kwargs: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        host_inputs,
        "_capture_installed_rextio_identity",
        lambda: rextio_identity,
    )

    def capture(name: str, path: Path, *, reported_version: str) -> ToolIdentity:
        return ToolIdentity(
            name=name,
            executable=ExactFileIdentity(
                logical_name=f"toolchain/{name}",
                role="toolchain-executable",
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                size=path.stat().st_size,
                executable=True,
            ),
            reported_version=reported_version,
        )

    monkeypatch.setattr(host_inputs, "capture_tool_identity", capture)
    monkeypatch.setattr(host_inputs, "verify_tool_identity", lambda _path, _identity: None)
    monkeypatch.setattr(host_inputs.sys, "executable", str(paths["python"]))
    config = RextioConfig(
        toolchain=ToolchainConfig(python_version="==3.11.9", cargo_version="1.85")
    )

    native_tools, identity, environment = host_inputs._collect_toolchain(
        root=project,
        config=config,
        target_triple="aarch64-apple-darwin",
        inherited={},
        cargo_workspace=workspace,
    )

    assert identity.cargo_sources is workspace.cargo_sources
    assert identity.argv.values == ("cargo", *FULL_C6_CARGO_ARGUMENTS)
    assert native_tools.cargo == paths["cargo"]
    assert environment == {"PATH": str(tools)}
    assert probes == [
        "python",
        "cargo",
        "rustc",
        "linker",
        "otool",
        "python",
        "cargo",
        "rustc",
        "linker",
        "otool",
    ]


def _write_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_rustup_proxy_tree(
    tmp_path: Path,
    *,
    nested_proxy: bool = True,
) -> tuple[Path, Path, Path]:
    tools = (tmp_path / "rustup-tools").resolve()
    tools.mkdir()
    rustup = tools / "rustup"
    cargo_proxy = tools / "cargo"
    if nested_proxy:
        rustup_init = _write_executable(tools / "rustup-init")
        rustup.symlink_to(rustup_init.name)
    else:
        _write_executable(rustup)
    cargo_proxy.symlink_to(rustup.name)
    cargo = _write_executable(tools / "actual-cargo")
    rustc = _write_executable(tools / "actual-rustc")
    return cargo_proxy, cargo, rustc


def test_rustup_proxy_chain_selects_stable_regular_tools_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(tmp_path)
    selections = iter((cargo, rustc, cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    assert host_inputs._resolve_actual_rust_tools(
        cargo_proxy,
        root=tmp_path.resolve(),
        config=RextioConfig(),
        inherited={},
    ) == (cargo, rustc)


def test_regular_rustup_proxy_selects_stable_regular_tools_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(
        tmp_path,
        nested_proxy=False,
    )
    selections = iter((cargo, rustc, cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    assert host_inputs._resolve_actual_rust_tools(
        cargo_proxy,
        root=tmp_path.resolve(),
        config=RextioConfig(),
        inherited={},
    ) == (cargo, rustc)


def test_non_rustup_cargo_symlink_is_rejected(tmp_path: Path) -> None:
    tools = (tmp_path / "non-rustup-tools").resolve()
    tools.mkdir()
    shim = _write_executable(tools / "cargo-shim")
    cargo_proxy = tools / "cargo"
    cargo_proxy.symlink_to(shim.name)

    with pytest.raises(FullC6HostInputsError, match="non-rustup"):
        host_inputs._resolve_actual_rust_tools(
            cargo_proxy,
            root=tmp_path.resolve(),
            config=RextioConfig(),
            inherited={},
        )


def test_rustup_selection_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(tmp_path)
    changed_cargo = _write_executable(cargo.parent / "changed-cargo")
    selections = iter((cargo, rustc, changed_cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    with pytest.raises(FullC6HostInputsError, match="ambiguous"):
        host_inputs._resolve_actual_rust_tools(
            cargo_proxy,
            root=tmp_path.resolve(),
            config=RextioConfig(),
            inherited={},
        )


def test_rustup_which_rejects_multiple_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rustup = _write_executable((tmp_path / "rustup").resolve())
    first = _write_executable((tmp_path / "first").resolve())
    second = _write_executable((tmp_path / "second").resolve())
    monkeypatch.setattr(
        host_inputs,
        "run_build_tool",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"{first}\n{second}\n",
            stderr="",
        ),
    )

    with pytest.raises(FullC6HostInputsError, match="failed closed"):
        host_inputs._rustup_which(
            rustup,
            "cargo",
            root=tmp_path.resolve(),
            environment={},
        )


def test_context_owns_two_fresh_quarantines_and_cleans_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    native_tools = object()
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (native_tools, toolchain, {"PATH": "/tools"}),
    )

    with collect_full_c6_host_prerequisites(
        project,
        config=_host_config(),
        inherited_environment={"PATH": "/ignored", "TOKEN": "secret"},
    ) as prerequisites:
        first = prerequisites.first_quarantine_root
        second = prerequisites.second_quarantine_root
        assert first != second
        assert (first.stat().st_dev, first.stat().st_ino) != (
            second.stat().st_dev,
            second.stat().st_ino,
        )
        assert stat.S_IMODE(first.stat().st_mode) == 0o700
        assert prerequisites.source_date_epoch == FULL_C6_SOURCE_DATE_EPOCH
        assert prerequisites.base_environment == {"PATH": "/tools"}
        assert prerequisites.production_arguments()["cargo_workspace"] is workspace
        assert prerequisites.toolchain.cargo_sources is workspace.cargo_sources
        assert stat.S_IMODE(prerequisites.state_directory.stat().st_mode) == 0o700
        assert prerequisites.state_directory == project / "state"
        assert not (project / "dist").exists()
        (first / "leftover").write_text("safe cleanup", encoding="utf-8")

        object.__setattr__(prerequisites, "_toolchain", object())
        sealed_accessors = (
            lambda: prerequisites.project_root,
            lambda: prerequisites.config,
            lambda: prerequisites.target_triple,
            lambda: prerequisites.source_date_epoch,
            lambda: prerequisites.toolchain,
            lambda: prerequisites.native_tools,
            lambda: prerequisites.cargo_workspace,
            lambda: prerequisites.first_quarantine_root,
            lambda: prerequisites.second_quarantine_root,
            lambda: prerequisites.state_directory,
            lambda: prerequisites.base_environment,
            prerequisites.production_arguments,
        )
        for access in sealed_accessors:
            with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
                access()

        object.__setattr__(prerequisites, "_toolchain", toolchain)
        object.__setattr__(prerequisites, "_project_root", object())
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.project_root
        object.__setattr__(prerequisites, "_project_root", project)

        # Direct mutation of the otherwise-private transition state must not
        # bypass real quarantine deletion or make context exit skip cleanup.
        prerequisites._lease.quarantine_cleaned = True
        prerequisites._lease.publication_authority = object()
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.project_root
        prerequisites._lease.quarantine_cleaned = False
        prerequisites._lease.publication_authority = None
        assert prerequisites.project_root == project

    assert not first.parent.exists()
    with pytest.raises(FullC6HostInputsError, match="lease has ended"):
        _ = prerequisites.project_root


def test_fixed_cargo_argv_is_the_only_native_build_shape() -> None:
    identity = capture_argv_identity(("cargo", *FULL_C6_CARGO_ARGUMENTS))

    assert identity.values == (
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--frozen",
    )


def test_publication_plan_requires_valid_final_authority_and_real_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    (project / "key.bin").write_bytes(b"k" * 32)
    (project / "signature.json").write_text("{}", encoding="utf-8")
    config = _host_config(
        artifact_trusted_public_key="key.bin",
        artifact_final_signature="signature.json",
    )
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (object(), toolchain, {"PATH": "/tools"}),
    )
    monkeypatch.setattr(
        full_c6_production,
        "validate_full_c6_production_authority",
        lambda _authority: True,
    )
    remove_quarantines = host_inputs._remove_private_quarantine_container
    cleanup_calls = 0

    def tracked_cleanup(
        container: Path,
        binding: host_inputs._DirectoryBinding,
    ) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        remove_quarantines(container, binding)

    monkeypatch.setattr(
        host_inputs,
        "_remove_private_quarantine_container",
        tracked_cleanup,
    )

    with collect_full_c6_host_prerequisites(project, config=config) as prerequisites:
        first_quarantine = prerequisites.first_quarantine_root
        second_quarantine = prerequisites.second_quarantine_root
        wheel = prerequisites.state_directory / "native" / "demo-0.1.0-cp311-macosx.whl"
        wheel.parent.mkdir(mode=0o700)
        wheel.write_bytes(b"wheel")
        transaction = object()
        monkeypatch.setattr(
            full_c6_native_output,
            "full_c6_native_output_wheel_path",
            lambda _transaction: wheel,
        )
        material = SimpleNamespace(
            lifecycle=SimpleNamespace(status="publication-required"),
            project_root=project,
            config=config,
            cargo_workspace=workspace,
            native_output_transaction=transaction,
        )
        authority = object.__new__(full_c6_production.FullC6ProductionAuthority)
        object.__setattr__(authority, "_material", material)
        object.__setattr__(authority, "_transaction_seal", b"test")

        assert not (project / "dist").exists()
        with pytest.raises(FullC6HostInputsError, match="prepublication cleanup"):
            prerequisites.derive_publication_plan(authority)
        prerequisites.complete_prepublication_cleanup(authority)
        prerequisites.complete_prepublication_cleanup(authority)
        assert cleanup_calls == 1
        replaced_authority = object.__new__(
            full_c6_production.FullC6ProductionAuthority
        )
        object.__setattr__(replaced_authority, "_material", material)
        object.__setattr__(replaced_authority, "_transaction_seal", b"replacement")
        with pytest.raises(FullC6HostInputsError, match="authority changed"):
            prerequisites.complete_prepublication_cleanup(replaced_authority)
        assert not first_quarantine.parent.exists()
        assert not second_quarantine.exists()
        with pytest.raises(FullC6HostInputsError, match="cleanup is complete"):
            _ = prerequisites.first_quarantine_root
        plan = prerequisites.derive_publication_plan(authority)
        assert plan.wheel_filename == wheel.name
        assert plan.bundle_name == f"{wheel.name.removesuffix('.whl')}.full-c6"
        assert (project / "dist").is_dir()
        assert str(project) not in repr(plan)
        assert not hasattr(plan, "to_dict")
        adapter = object()

        def adapter_factory(**values: object) -> object:
            assert values["authority"] is authority
            assert values["bundle_name"] == plan.bundle_name
            return adapter

        monkeypatch.setattr(
            full_c6_pipeline,
            "_full_c6_atomic_publication_adapter",
            adapter_factory,
        )
        assert plan.atomic_adapter() is adapter
        with pytest.raises(TypeError):
            pickle.dumps(prerequisites)

        object.__setattr__(plan, "_subject_path", object())
        for access in (lambda: plan.wheel_filename, lambda: plan.bundle_name, plan.atomic_adapter):
            with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
                access()
        object.__setattr__(plan, "_subject_path", wheel)

        material.lifecycle.status = "signing-required"
        with pytest.raises(FullC6HostInputsError, match="publication-required"):
            prerequisites.derive_publication_plan(authority)

    with pytest.raises(FullC6HostInputsError, match="lease has ended"):
        _ = plan.wheel_filename
    assert cleanup_calls == 1
    prerequisites._lease.active = True
    with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
        _ = prerequisites.project_root
    with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
        _ = plan.wheel_filename


def test_publication_plan_rejects_invalid_or_foreign_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (object(), toolchain, {}),
    )

    with collect_full_c6_host_prerequisites(project, config=_host_config()) as prerequisites:
        with pytest.raises(FullC6HostInputsError, match="valid production authority"):
            prerequisites.complete_prepublication_cleanup(object())


def test_post_cleanup_revalidation_failure_is_not_retried_on_context_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    config = _host_config()
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    monkeypatch.setattr(
        host_inputs,
        "_require_supported_host",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (object(), toolchain, {}),
    )
    monkeypatch.setattr(
        full_c6_production,
        "validate_full_c6_production_authority",
        lambda _authority: True,
    )
    cleanup_calls = 0
    remove_quarantines = host_inputs._remove_private_quarantine_container

    with collect_full_c6_host_prerequisites(project, config=config) as prerequisites:
        quarantine_container = prerequisites.first_quarantine_root.parent
        state_directory = prerequisites.state_directory
        material = SimpleNamespace(
            lifecycle=SimpleNamespace(status="publication-required"),
            project_root=project,
            config=config,
            cargo_workspace=workspace,
        )
        authority = object.__new__(full_c6_production.FullC6ProductionAuthority)
        object.__setattr__(authority, "_material", material)
        object.__setattr__(authority, "_transaction_seal", b"test")

        def cleanup_then_change_state(
            container: Path,
            binding: host_inputs._DirectoryBinding,
        ) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            remove_quarantines(container, binding)
            state_directory.chmod(0o755)

        monkeypatch.setattr(
            host_inputs,
            "_remove_private_quarantine_container",
            cleanup_then_change_state,
        )
        with pytest.raises(FullC6HostInputsError, match="directory changed"):
            prerequisites.complete_prepublication_cleanup(authority)
        assert cleanup_calls == 1
        assert not quarantine_container.exists()
        assert not (project / "dist").exists()

    assert cleanup_calls == 1


@pytest.mark.skipif(
    platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11),
    reason="real host gate is intentionally CPython 3.11-only",
)
def test_real_host_probe_is_availability_gated() -> None:
    """Keep the real OS probe optional; synthetic tests remain host-independent."""
    try:
        target = host_inputs._require_supported_host()
    except FullC6HostInputsError:
        pytest.skip("this runner is outside the supported Full C6 host pair")
    assert target in {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
