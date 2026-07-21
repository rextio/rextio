"""Focused tests for fixed-profile Full C6 support discovery."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import pickle

import pytest

from rextio.build import full_c6_toolchain_support as support
from rextio.build.full_c6_read_sandbox import MacOSPlatformAnchor
from rextio.build.toolchain_identity import capture_tool_identity
from rextio.build.toolchain_support_lock import (
    ToolchainSupportLockError,
    create_toolchain_support_locator,
    generate_toolchain_support_lock,
)


LINUX = "x86_64-unknown-linux-gnu"
MACOS = "aarch64-apple-darwin"


def _file(path: Path, data: bytes = b"fixture", *, executable: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755 if executable else 0o644)
    return path.resolve()


def _tree(path: Path, *, member: str = "member") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _file(path / member, path.name.encode("utf-8"))
    return path.resolve()


def _fixed_plan(
    tmp_path: Path,
    *,
    target_triple: str = LINUX,
) -> support.FullC6ToolchainSupportPlan:
    manifests, roots = support.expected_full_c6_toolchain_support_roles(
        target_triple
    )
    material = tmp_path / "material"
    manifest_locators = tuple(
        create_toolchain_support_locator(
            logical_role=role,
            path=_file(
                material
                / "manifests"
                / (
                    (
                        support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME
                        if target_triple == LINUX
                        else "Python"
                    )
                    if role == "python-runtime-library"
                    else role
                ),
                role.encode("utf-8"),
            ),
            kind="file",
        )
        for role in manifests
    )
    root_locators = tuple(
        create_toolchain_support_locator(
            logical_role=role,
            path=_tree(material / "roots" / role),
            kind="tree",
        )
        for role in roots
    )
    python = _file(material / "tools" / "python3.11", executable=True)
    rust_sysroot = next(
        item._absolute_path
        for item in root_locators
        if item.logical_role == "rust-sysroot"
    )
    cargo = _file(rust_sysroot / "bin" / "cargo", executable=True)
    rustc = _file(rust_sysroot / "bin" / "rustc", executable=True)
    linker = _file(material / "tools" / "linker", executable=True)
    inspector = _file(material / "tools" / "inspector", executable=True)
    runtime_leaf = _file(material / "runtime" / "libc.so.6")
    anchor = (
        MacOSPlatformAnchor(
            authenticated_snapshot_id="a" * 64,
            snapshot_uuid="12345678-1234-1234-1234-123456789abc",
            os_build="25A123",
            provider="fixture-provider-v1",
        )
        if target_triple == MACOS
        else None
    )
    locators = (*manifest_locators, *root_locators)
    return support._new_plan(
        target_triple=target_triple,
        python=python,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        inspector=inspector,
        manifests=manifest_locators,
        roots=root_locators,
        base_environment={"PATH": "/tools"},
        anchor=anchor,
        elf_runtime_files=(runtime_leaf,) if target_triple == LINUX else (),
        critical_paths=(
            python,
            linker,
            inspector,
            runtime_leaf,
            *(item._absolute_path for item in locators),
        ),
        platform_inspector_identity=(
            capture_tool_identity(
                "otool",
                inspector,
                reported_version="fixture otool",
            )
            if target_triple == MACOS
            else None
        ),
    )


def test_fixed_roles_generation_verification_and_namespace_round_trip(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    lock = support.generate_full_c6_toolchain_support_lock(plan)

    assert tuple(item.logical_role for item in lock.manifests) == (
        support.LINUX_MANIFEST_ROLES
    )
    assert tuple(item.logical_role for item in lock.roots) == support.LINUX_ROOT_ROLES
    assert support.verify_full_c6_toolchain_support_lock(plan, lock) is True
    mappings = {item.logical_role: item for item in plan.namespace_mappings}
    assert mappings["toolchain-python311"].virtual_path.as_posix() == (
        "/rextio/toolchain/bin/python3.11"
    )
    assert mappings["toolchain-python311-stdlib"].virtual_path.as_posix() == (
        "/rextio/toolchain/lib/python3.11"
    )
    assert mappings["support-landlock-launcher"].virtual_path.as_posix() == (
        "/rextio/support/rextio/full_c6_linux_launcher.py"
    )
    assert mappings["support-runtime-libs"].virtual_path.as_posix() == (
        "/rextio/support/runtime-libs"
    )
    assert mappings["support-gcc-toolchain"].virtual_path.as_posix() == (
        "/rextio/support/gcc-toolchain"
    )
    assert mappings["support-python-library-root"].virtual_path.as_posix() == (
        "/rextio/support/python-library-root"
    )
    assert mappings[
        "toolchain-python311-runtime-library"
    ].virtual_path.as_posix() == (
        "/rextio/toolchain/lib/libpython3.11.so.1.0"
    )
    assert mappings["runtime-loader-mirror"].virtual_path.as_posix() == (
        "/lib64/ld-linux-x86-64.so.2"
    )
    assert mappings["toolchain-rust-sysroot"].virtual_path.as_posix() == (
        "/rextio/toolchain"
    )
    for role in ("ar", "cargo", "ld", "linker", "ranlib", "rustc"):
        assert mappings[f"toolchain-{role}"].virtual_path.as_posix() == (
            f"/rextio/toolchain/bin/{role}"
        )
    ordered_roles = [item.logical_role for item in plan.namespace_mappings]
    assert ordered_roles.index("toolchain-rust-sysroot") < ordered_roles.index(
        "toolchain-cargo"
    )
    assert plan.macos_platform_anchor is None


def test_macos_plan_exposes_exact_sealed_platform_anchor(tmp_path: Path) -> None:
    plan = _fixed_plan(tmp_path, target_triple=MACOS)

    assert plan.macos_platform_anchor is plan._anchor
    assert plan.platform_anchor is plan.macos_platform_anchor
    assert plan.macos_platform_anchor is not None
    assert plan.macos_platform_anchor.digest == plan.platform_anchor_sha256


@pytest.mark.parametrize("attack", ("missing", "extra", "wrong-kind", "wrong-target"))
def test_lock_role_kind_and_target_drift_fails_before_rewalk(
    tmp_path: Path,
    attack: str,
) -> None:
    plan = _fixed_plan(tmp_path)
    manifests = list(plan.manifest_locators)
    roots = list(plan.root_locators)
    target = LINUX
    if attack == "missing":
        manifests.pop()
    elif attack == "extra":
        manifests.append(
            create_toolchain_support_locator(
                logical_role="unexpected-support",
                path=_file(tmp_path / "unexpected"),
                kind="file",
            )
        )
    elif attack == "wrong-kind":
        replaced = roots.pop()
        manifests.append(
            create_toolchain_support_locator(
                logical_role=replaced.logical_role,
                path=_file(tmp_path / "reclassified"),
                kind="file",
            )
        )
    else:
        target = MACOS
        with pytest.raises(
            ToolchainSupportLockError,
            match="dispositions are missing",
        ):
            generate_toolchain_support_lock(
                target_triple=target,
                manifests=manifests,
                roots=roots,
            )
        return
    lock = generate_toolchain_support_lock(
        target_triple=target,
        manifests=manifests,
        roots=roots,
    )

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="roles, kinds, or target",
    ):
        support.verify_full_c6_toolchain_support_lock(plan, lock)


def test_changed_deep_support_bytes_are_detected_by_explicit_rewalk(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    lock = support.generate_full_c6_toolchain_support_lock(plan)
    rust = next(
        item
        for item in plan.root_locators
        if item.logical_role == "rust-sysroot"
    )
    (rust._absolute_path / "member").write_bytes(b"changed deeply")

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="support bytes differ",
    ):
        support.verify_full_c6_toolchain_support_lock(plan, lock)


def test_plan_access_is_cheap_but_stage_revalidation_detects_tool_mutation(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    linker = plan.linker_path
    linker.write_bytes(b"changed linker")

    assert support.require_full_c6_toolchain_support_plan(plan) is plan
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="critical support path changed",
    ):
        support.revalidate_full_c6_toolchain_support_plan(plan)


def test_plan_is_immutable_nonserializable_sealed_and_path_private(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    rendered = repr(plan)
    assert str(tmp_path) not in rendered
    assert all(str(tmp_path) not in repr(item) for item in plan.namespace_mappings)
    with pytest.raises(TypeError, match="immutable"):
        setattr(plan, "extra", object())
    with pytest.raises(TypeError, match="copied"):
        copy.copy(plan)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(plan)

    object.__setattr__(plan, "_target_triple", MACOS)
    with pytest.raises(support.FullC6ToolchainSupportError, match="seal is invalid"):
        support.require_full_c6_toolchain_support_plan(plan)


def test_python_runtime_discovery_requires_exact_cpython311_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python = _file(tmp_path / "bin" / "python3.11", executable=True)
    stdlib = _tree(tmp_path / "lib" / "python3.11")
    _file(stdlib / "encodings" / "__init__.py")
    _tree(stdlib / "lib-dynload", member="_ctypes.so")
    library = _file(tmp_path / "lib" / "libpython3.11.so")
    document = {
        "executable": os.fspath(python),
        "implementation": "cpython",
        "major": 3,
        "minor": 11,
        "isolated": 1,
        "no_site": 1,
        "stdlib": os.fspath(stdlib),
        "platstdlib": os.fspath(stdlib),
        "libdir": os.fspath(library.parent),
        "ldlibrary": library.name,
        "framework": "",
        "framework_install_dir": "",
    }
    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )

    assert support._discover_python_runtime(
        python,
        cwd=tmp_path,
        environment={},
    ) == (stdlib, library)
    document["minor"] = 12
    with pytest.raises(support.FullC6ToolchainSupportError, match="3.11"):
        support._discover_python_runtime(
            python,
            cwd=tmp_path,
            environment={},
        )


def test_macos_rejects_command_line_tools_and_usr_bin_clang_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    developer = tmp_path / "Xcode.app" / "Contents" / "Developer"
    monkeypatch.setattr(support, "MACOS_DEVELOPER_DIR", developer)
    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: "/Library/Developer/CommandLineTools",
    )
    with pytest.raises(support.FullC6ToolchainSupportError, match="Xcode.app"):
        support.resolve_full_c6_linker_and_inspector(
            target_triple=MACOS,
            cwd=tmp_path,
        )

    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: os.fspath(developer),
    )
    monkeypatch.setattr(
        support,
        "_stable_absolute_output",
        lambda *_args, **_kwargs: Path("/usr/bin/clang"),
    )
    with pytest.raises(support.FullC6ToolchainSupportError, match="not canonical"):
        support.resolve_full_c6_linker_and_inspector(
            target_triple=MACOS,
            cwd=tmp_path,
        )


def test_macos_platform_tool_keeps_hardlink_out_of_generic_support_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _file(tmp_path / "otool-image", executable=True)
    anchored_path = tmp_path / "otool"
    os.link(original, anchored_path)
    monkeypatch.setattr(support, "MACOS_OTOOL", anchored_path)

    with pytest.raises(support.FullC6ToolchainSupportError, match="aliased"):
        support._require_real_file(anchored_path, executable=True)
    assert support._require_platform_anchored_macos_tool(
        anchored_path
    ) == anchored_path


def test_xcode_ranlib_symlink_is_sealed_separately_from_implementation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_bin = tmp_path / "Xcode.app" / "usr" / "bin"
    implementation = _file(tool_bin / "libtool", executable=True)
    ranlib = tool_bin / "ranlib"
    ranlib.symlink_to(implementation.name)
    monkeypatch.setattr(
        support,
        "_stable_absolute_output",
        lambda *_args, **_kwargs: ranlib,
    )

    assert support._xcrun_tool(
        "ranlib",
        cwd=tmp_path,
        environment={},
        root=tool_bin,
        allow_symlink=True,
    ) == ranlib
    binding = support._capture_path_binding(ranlib, kind="symlink")
    assert binding.raw_sha256 is not None
    with pytest.raises(support.FullC6ToolchainSupportError, match="unexpected"):
        support._xcrun_tool(
            "ranlib",
            cwd=tmp_path,
            environment={},
            root=tool_bin,
        )


def test_linux_missing_exact_bwrap_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = {
        name: _file(tmp_path / name, executable=True)
        for name in ("python", "cargo", "rustc", "linker", "readelf")
    }
    monkeypatch.setattr(
        support,
        "resolve_full_c6_linker_and_inspector",
        lambda **_kwargs: (tools["linker"], tools["readelf"]),
    )
    monkeypatch.setattr(support, "LINUX_BWRAP", tmp_path / "missing-bwrap")

    with pytest.raises(support.FullC6ToolchainSupportError, match="unavailable"):
        support._discover_linux_support(
            cwd=tmp_path,
            python=tools["python"],
            cargo=tools["cargo"],
            rustc=tools["rustc"],
            linker=tools["linker"],
            inspector=tools["readelf"],
        )


def test_linux_elf_runtime_follows_interp_and_needed_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    seed = _file(tmp_path / "python3.11", executable=True)
    inspector = _file(tmp_path / "readelf", executable=True)
    loader = _file(runtime / "ld-linux-x86-64.so.2", executable=True)
    liba = _file(runtime / "liba.so")
    libc = _file(runtime / "libc.so.6")

    def output(command: list[str], **_kwargs: object) -> str:
        image = Path(command[-1])
        if "-l" in command:
            return (
                f"[Requesting program interpreter: {loader}]\n"
                if image == seed
                else "no interpreter\n"
            )
        needed = {
            seed: "liba.so",
            liba: "libc.so.6",
        }.get(image)
        return f"Shared library: [{needed}]\n" if needed is not None else "none\n"

    monkeypatch.setattr(support, "_stable_output", output)
    files, observed_loader = support._discover_linux_elf_runtime(
        seeds=(seed,),
        inspector=inspector,
        runtime_root=runtime.resolve(),
        search_roots=(runtime.resolve(),),
        cwd=tmp_path,
        environment={},
    )

    assert observed_loader == loader
    assert files == tuple(sorted((loader, liba, libc), key=os.fspath))


def test_linux_elf_runtime_resolves_fixed_multi_root_dependency_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_root = _tree(tmp_path / "system", member="system-member")
    python_root = _tree(tmp_path / "python-root", member="python-member")
    rust_root = _tree(tmp_path / "rust-root", member="rust-member")
    seed = _file(tmp_path / "python3.11", executable=True)
    inspector = _file(tmp_path / "readelf", executable=True)
    loader = _file(system_root / "ld-linux-x86-64.so.2", executable=True)
    libpython = _file(python_root / support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME)
    librust = _file(rust_root / "librust_support.so")

    def output(command: list[str], **_kwargs: object) -> str:
        image = Path(command[-1])
        if "-l" in command:
            return (
                f"[Requesting program interpreter: {loader}]\n"
                if image == seed
                else "no interpreter\n"
            )
        needed = {
            seed: support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME,
            libpython: "librust_support.so",
        }.get(image)
        return f"Shared library: [{needed}]\n" if needed is not None else "none\n"

    monkeypatch.setattr(support, "_stable_output", output)
    files, observed_loader = support._discover_linux_elf_runtime(
        seeds=(seed,),
        inspector=inspector,
        runtime_root=system_root,
        search_roots=(system_root, python_root, rust_root),
        cwd=tmp_path,
        environment={},
    )

    assert observed_loader == loader
    assert files == tuple(sorted((loader, libpython, librust), key=os.fspath))


def test_linux_needed_resolution_rejects_ambiguous_distinct_files(
    tmp_path: Path,
) -> None:
    first = _tree(tmp_path / "first")
    second = _tree(tmp_path / "second")
    _file(first / "libsame.so", b"first")
    _file(second / "libsame.so", b"second")

    with pytest.raises(support.FullC6ToolchainSupportError, match="ambiguous"):
        support._resolve_linux_needed_dependency("libsame.so", (first, second))


def test_linux_needed_resolution_rejects_escape_and_missing(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "root")
    outside = _file(tmp_path / "outside" / "libescape.so")
    (root / "libescape.so").symlink_to(outside)

    with pytest.raises(support.FullC6ToolchainSupportError, match="escaped"):
        support._resolve_linux_needed_dependency("libescape.so", (root,))
    with pytest.raises(support.FullC6ToolchainSupportError, match="missing"):
        support._resolve_linux_needed_dependency("libmissing.so", (root,))


def test_linux_needed_resolution_deduplicates_repeated_canonical_root(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "root")
    dependency = _file(root / "libsame.so")

    assert support._resolve_linux_needed_dependency(
        "libsame.so",
        (root, root),
    ) == dependency


def test_namespace_mapping_rejects_noncanonical_role_destination(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="mapping is invalid"):
        support.FullC6SupportNamespaceMapping(
            logical_role="toolchain-python311",
            host_path=_file(tmp_path / "python", executable=True),
            virtual_path=support.FULL_C6_TOOLCHAIN_SUPPORT_VIRTUAL_ROOT / "python",
            kind="file",
        )
