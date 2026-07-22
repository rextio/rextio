from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pickle
import stat
import ctypes
import sys
from types import SimpleNamespace
import unicodedata

import pytest

from rextio.build import toolchain_support_lock as support_lock
from rextio.build.toolchain_support_lock import (
    TOOLCHAIN_SUPPORT_LOCK_DOMAIN,
    TOOLCHAIN_SUPPORT_LOCK_KIND,
    TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION,
    TOOLCHAIN_SUPPORT_SCOPE,
    ToolchainSupportLock,
    ToolchainSupportLockError,
    ToolchainSupportLocator,
    capture_toolchain_support_file,
    capture_toolchain_support_tree,
    create_toolchain_support_locator,
    generate_toolchain_support_lock,
    load_toolchain_support_lock,
    parse_toolchain_support_lock,
    verify_toolchain_support_lock,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _set_test_xattr(path: Path, name: bytes, value: bytes) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), "setxattr")
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(value)
    if sys.platform == "darwin":
        result = function(os.fsencode(path), name, buffer, len(value), 0, 0)
    elif sys.platform == "linux":
        result = function(os.fsencode(path), name, buffer, len(value), 0)
    else:
        pytest.skip("xattr fixture is only available on the two supported hosts")
    if result != 0:
        pytest.skip(f"test filesystem rejected xattrs with errno {ctypes.get_errno()}")


def _inputs(tmp_path: Path):
    manifest = tmp_path / "python-config.txt"
    manifest.write_bytes(b"implementation=cpython\nversion=3.11\n")
    root = tmp_path / "support-root"
    root.mkdir()
    include = root / "include"
    include.mkdir()
    (include / "Python.h").write_bytes(b"/* pinned */\n")
    (root / "libpython.link").symlink_to("include/Python.h")
    manifest_locator = create_toolchain_support_locator(
        logical_role="python-abi-config",
        path=manifest,
        kind="file",
    )
    root_locator = create_toolchain_support_locator(
        logical_role="python-support-root",
        path=root,
        kind="tree",
    )
    return manifest, root, manifest_locator, root_locator


def _lock(tmp_path: Path) -> tuple[ToolchainSupportLock, object, object]:
    _manifest, _root, manifest_locator, root_locator = _inputs(tmp_path)
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )
    return lock, manifest_locator, root_locator


def _macos_projected_inputs(
    tmp_path: Path,
    *,
    python_layout: str = "homebrew",
    xcode_layout: str = "modern",
) -> tuple[
    list[ToolchainSupportLocator],
    list[ToolchainSupportLocator],
    Path,
    Path,
    Path,
]:
    python_root = (
        tmp_path
        / "prefix"
        / "a"
        / "b"
        / "c"
        / "d"
        / "e"
        / "f"
        / "g"
        / "h"
        / "Frameworks"
        / "Python.framework"
        / "Versions"
        / "3.11"
        / "lib"
        / "python3.11"
    )
    python_root.mkdir(parents=True)
    (python_root / "encodings.py").write_bytes(b"# fixed runtime\n")
    config = python_root / "config-3.11-darwin"
    config.mkdir()
    python_library = python_root.parents[1] / "Python"
    python_library.write_bytes(b"fixed framework runtime")
    (config / "libpython3.11.a").symlink_to("../../../Python")
    (config / "libpython3.11.dylib").symlink_to("../../../Python")
    site_packages = python_root / "site-packages"
    if python_layout == "homebrew":
        site_target_text = "../../../../../../../../../lib/python3.11/site-packages"
        site_target = (python_root / site_target_text).resolve(strict=False)
        site_target.mkdir(parents=True)
        site_packages.symlink_to(site_target_text)
    elif python_layout == "actions":
        site_packages.mkdir()
        (site_packages / "README.txt").write_bytes(
            b"Package installation directory for GitHub Actions CPython.\n"
        )
    else:
        raise AssertionError(f"unsupported Python fixture layout: {python_layout}")

    sdk = tmp_path / "MacOSX.sdk"
    sound = (
        sdk
        / "System"
        / "Library"
        / "Frameworks"
        / "SoundAnalysis.framework"
        / "Versions"
        / "A"
        / "SoundAnalysis.tbd"
    )
    sound.parent.mkdir(parents=True)
    sound.write_bytes(b"sound analysis")
    swift = sdk / "usr" / "lib" / "swift"
    swift.mkdir(parents=True)
    sound_target = (
        "../../..//System/Library/Frameworks/SoundAnalysis.framework/"
        "Versions/A/SoundAnalysis.tbd"
    )
    if xcode_layout == "modern":
        (swift / "libswiftSoundAnalysis.tbd").symlink_to(sound_target)
        (swift / "libswiftSoundAnalysis_Private.tbd").symlink_to(sound_target)
    elif xcode_layout == "xcode-16.4":
        sound_bytes = b"--- !tapi-tbd\ntbd-version: 4\n"
        (swift / "libswiftSoundAnalysis.tbd").write_bytes(sound_bytes)
        (swift / "libswiftSoundAnalysis_Private.tbd").write_bytes(sound_bytes)
    else:
        raise AssertionError(f"unsupported Xcode fixture layout: {xcode_layout}")
    veclib_target = (
        sdk
        / "System"
        / "Library"
        / "Frameworks"
        / "Accelerate.framework"
        / "Versions"
        / "A"
        / "Frameworks"
        / "vecLib.framework"
    )
    veclib_target.mkdir(parents=True)
    (veclib_target / "module.map").write_bytes(b"veclib")
    (sdk / "System" / "Library" / "Frameworks" / "vecLib.framework").symlink_to(
        "Accelerate.framework//Versions/A/Frameworks/vecLib.framework"
    )

    manifests = [
        create_toolchain_support_locator(
            logical_role="python-runtime-library",
            path=python_library,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="python-runtime",
            path=python_root,
            kind="tree",
        ),
        create_toolchain_support_locator(
            logical_role="xcode-sdk",
            path=sdk,
            kind="tree",
        ),
    ]
    return manifests, roots, python_root, sdk, sound


def _linux_cross_root_inputs(
    tmp_path: Path,
) -> tuple[
    list[ToolchainSupportLocator],
    list[ToolchainSupportLocator],
    Path,
    Path,
]:
    manifest = tmp_path / "linux-toolchain.manifest"
    manifest.write_bytes(b"gcc=13\nglibc=2.39\n")
    lib_root = tmp_path / "usr" / "lib"
    gcc_root = lib_root / "gcc" / "x86_64-linux-gnu" / "13"
    runtime_root = lib_root / "x86_64-linux-gnu"
    gcc_root.mkdir(parents=True)
    runtime_root.mkdir(parents=True)
    (runtime_root / "libasan.so.8").write_bytes(b"bound runtime support\n")
    (gcc_root / "libasan.so").symlink_to(
        "../../../x86_64-linux-gnu/libasan.so.8"
    )
    manifests = [
        create_toolchain_support_locator(
            logical_role="linux-toolchain-manifest",
            path=manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="linux-gcc-support",
            path=gcc_root,
            kind="tree",
        ),
        create_toolchain_support_locator(
            logical_role="linux-runtime-support",
            path=runtime_root,
            kind="tree",
        ),
    ]
    return manifests, roots, gcc_root, runtime_root


_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS = {
    "libLLVM-18.so": "libLLVM.so.18.1",
    "libLLVM.so.18.1": "../llvm-18/lib/libLLVM.so.1",
    "libclang-cpp.so.16": "../llvm-16/lib/libclang-cpp.so.16",
    "libclang-cpp.so.17": "../llvm-17/lib/libclang-cpp.so.17",
    "libclang-cpp.so.18": "../llvm-18/lib/libclang-cpp.so.18.1",
    "libclang-cpp.so.18.1": "../llvm-18/lib/libclang-cpp.so.18.1",
    "libpython3.12.a": (
        "../python3.12/config-3.12-x86_64-linux-gnu/libpython3.12.a"
    ),
}
_LINUX_UNMAPPED_SYMLINK_FINAL_TARGETS = {
    "libLLVM-18.so": "llvm-18/lib/libLLVM.so.1",
    "libLLVM.so.18.1": "llvm-18/lib/libLLVM.so.1",
    "libclang-cpp.so.16": "llvm-16/lib/libclang-cpp.so.16",
    "libclang-cpp.so.17": "llvm-17/lib/libclang-cpp.so.17",
    "libclang-cpp.so.18": "llvm-18/lib/libclang-cpp.so.18.1",
    "libclang-cpp.so.18.1": "llvm-18/lib/libclang-cpp.so.18.1",
    "libpython3.12.a": (
        "python3.12/config-3.12-x86_64-linux-gnu/libpython3.12.a"
    ),
}
_LINUX_GCC_LTO_RELATIVE_PATH = "liblto_plugin.so"
_LINUX_GCC_LTO_RAW_TARGET = (
    "../../../../libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so"
)


def _linux_gcc_lto_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_lto: bool = True,
    raw_target: str = _LINUX_GCC_LTO_RAW_TARGET,
    extra_alias: bool = False,
) -> tuple[
    list[ToolchainSupportLocator],
    list[ToolchainSupportLocator],
    Path,
    Path,
]:
    manifests, roots, gcc_root, runtime_root = _linux_cross_root_inputs(tmp_path)
    if include_lto:
        (gcc_root / _LINUX_GCC_LTO_RELATIVE_PATH).symlink_to(raw_target)
    if extra_alias:
        (gcc_root / "liblto_plugin-13.so").symlink_to(
            _LINUX_GCC_LTO_RAW_TARGET
        )
    policy_key = ("x86_64-unknown-linux-gnu", "linux-gcc-support")
    production_rows = support_lock._FIXED_SYMLINK_DISPOSITIONS[policy_key]
    assert len(production_rows) == 1
    assert production_rows[0].relative_path == _LINUX_GCC_LTO_RELATIVE_PATH
    assert production_rows[0].raw_link_target == _LINUX_GCC_LTO_RAW_TARGET
    assert production_rows[0].resolved_path_sha256 == (
        support_lock._locator_path_digest(
            Path(
                "/usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so"
            )
        )
    )
    assert support_lock._LINUX_GCC_UNMAPPED_SYMLINK_ROOT == Path(
        "/usr/lib/gcc/x86_64-linux-gnu/13"
    )
    assert (
        support_lock._LINUX_GCC_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256
        == support_lock._locator_path_digest(
            Path("/usr/lib/gcc/x86_64-linux-gnu/13")
        )
    )
    resolved = (
        tmp_path
        / "usr"
        / "libexec"
        / "gcc"
        / "x86_64-linux-gnu"
        / "13"
        / "liblto_plugin.so"
    )
    cloned_rows = tuple(
        replace(
            row,
            resolved_path_sha256=support_lock._locator_path_digest(resolved),
        )
        for row in production_rows
    )
    monkeypatch.setattr(
        support_lock,
        "_FIXED_SYMLINK_DISPOSITIONS",
        {
            **support_lock._FIXED_SYMLINK_DISPOSITIONS,
            policy_key: cloned_rows,
        },
    )
    monkeypatch.setattr(
        support_lock,
        "_LINUX_GCC_UNMAPPED_SYMLINK_ROOT",
        gcc_root,
    )
    monkeypatch.setattr(
        support_lock,
        "_LINUX_GCC_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(gcc_root),
    )
    return manifests, roots, gcc_root, runtime_root


def _linux_unmapped_virtual_target_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    included_paths: frozenset[str] | None = None,
    raw_overrides: dict[str, str] | None = None,
    extra_symlink: tuple[str, str] | None = None,
) -> tuple[list[ToolchainSupportLocator], list[ToolchainSupportLocator], Path]:
    manifest = tmp_path / "linux-toolchain.manifest"
    manifest.write_bytes(b"ubuntu=24.04\nrunner=github-hosted\n")
    runtime_root = tmp_path / "usr" / "lib" / "x86_64-linux-gnu"
    runtime_root.mkdir(parents=True)
    selected = (
        frozenset(_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS)
        if included_paths is None
        else included_paths
    )
    assert selected <= frozenset(_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS)
    for relative_path in sorted(selected):
        raw_target = (raw_overrides or {}).get(
            relative_path,
            _LINUX_UNMAPPED_SYMLINK_RAW_TARGETS[relative_path],
        )
        (runtime_root / relative_path).symlink_to(raw_target)
    if extra_symlink is not None:
        extra_path, extra_target = extra_symlink
        (runtime_root / extra_path).symlink_to(extra_target)

    policy_key = ("x86_64-unknown-linux-gnu", "linux-runtime-support")
    production_rows = support_lock._FIXED_SYMLINK_DISPOSITIONS[policy_key]
    assert {
        row.relative_path: row.raw_link_target for row in production_rows
    } == _LINUX_UNMAPPED_SYMLINK_RAW_TARGETS
    cloned_rows = tuple(
        replace(
            row,
            resolved_path_sha256=support_lock._locator_path_digest(
                runtime_root.parent
                / _LINUX_UNMAPPED_SYMLINK_FINAL_TARGETS[row.relative_path]
            ),
        )
        for row in production_rows
    )
    monkeypatch.setattr(
        support_lock,
        "_FIXED_SYMLINK_DISPOSITIONS",
        {**support_lock._FIXED_SYMLINK_DISPOSITIONS, policy_key: cloned_rows},
    )
    monkeypatch.setattr(
        support_lock,
        "_LINUX_UNMAPPED_SYMLINK_ROOT",
        runtime_root,
    )
    monkeypatch.setattr(
        support_lock,
        "_LINUX_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(runtime_root),
    )
    manifests = [
        create_toolchain_support_locator(
            logical_role="linux-toolchain-manifest",
            path=manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="linux-runtime-support",
            path=runtime_root,
            kind="tree",
        )
    ]
    return manifests, roots, runtime_root


def _refresh_unmapped_forgery_merkles(
    document: dict[str, object],
    *,
    runtime_root: Path,
) -> bytes:
    roots = document["roots"]
    manifests = document["manifests"]
    assert isinstance(roots, list) and len(roots) == 1
    assert isinstance(manifests, list)
    root = roots[0]
    assert isinstance(root, dict)
    dispositions = root["symlink_dispositions"]
    assert isinstance(dispositions, list) and len(dispositions) == 7
    for disposition in dispositions:
        assert isinstance(disposition, dict)
        receipt = SimpleNamespace(**disposition)
        disposition["merkle_sha256"] = support_lock._symlink_disposition_merkle(
            receipt
        )

    descriptor = os.open(runtime_root, os.O_RDONLY)
    try:
        root_xattrs = support_lock._capture_fd_xattrs(
            descriptor,
            budget=support_lock._XattrBudget(
                remaining_count=support_lock.MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS,
                remaining_bytes=(
                    support_lock.MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES
                ),
            ),
        )
        _entries, root_merkle = support_lock._build_tree_merkle(
            logical_role=root["logical_role"],
            locator_path_sha256=root["locator_path_sha256"],
            root_mode=root["root_mode"],
            root_metadata_sha256=root["root_metadata_sha256"],
            root_xattrs=root_xattrs,
            entries=(),
            symlink_dispositions=tuple(
                SimpleNamespace(**item) for item in dispositions
            ),
        )
    finally:
        os.close(descriptor)
    root["merkle_sha256"] = root_merkle
    document["merkle_sha256"] = support_lock._sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-aggregate.v2",
            "scope": document["scope"],
            "manifest_count": document["manifest_count"],
            "root_count": document["root_count"],
            "member_count": document["member_count"],
            "total_bytes": document["total_bytes"],
            "xattr_count": document["xattr_count"],
            "xattr_bytes": document["xattr_bytes"],
            "manifests": [
                {
                    "logical_role": item["logical_role"],
                    "merkle_sha256": item["merkle_sha256"],
                }
                for item in manifests
            ],
            "roots": [
                {
                    "logical_role": item["logical_role"],
                    "merkle_sha256": item["merkle_sha256"],
                }
                for item in roots
            ],
        }
    )
    return _canonical(document)


def test_generation_is_canonical_path_free_aggregate_and_round_trips(
    tmp_path: Path,
) -> None:
    manifest, root, manifest_locator, root_locator = _inputs(tmp_path)

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )
    document = json.loads(lock.canonical_bytes)

    assert TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION == 5
    assert TOOLCHAIN_SUPPORT_LOCK_DOMAIN.endswith("support-lock.v5")
    assert document["kind"] == TOOLCHAIN_SUPPORT_LOCK_KIND
    assert document["schema_version"] == TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION
    assert document["domain"] == TOOLCHAIN_SUPPORT_LOCK_DOMAIN
    assert document["scope"] == {
        "artifact_kind": "host-cdylib",
        "profile": TOOLCHAIN_SUPPORT_SCOPE,
        "python_implementation": "cpython",
        "python_version": "3.11",
        "rust_binding": "pyo3",
        "target_triple": "aarch64-apple-darwin",
    }
    assert document["manifests"][0]["raw_sha256"] == hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()
    assert document["roots"][0]["member_count"] == 3
    assert document["roots"][0]["file_count"] == 1
    assert document["roots"][0]["directory_count"] == 1
    assert document["roots"][0]["symlink_count"] == 1
    assert document["roots"][0]["symlink_disposition_count"] == 0
    assert document["roots"][0]["symlink_dispositions"] == []
    assert document["roots"][0]["hardlink_disposition_count"] == 0
    assert document["roots"][0]["hardlink_dispositions"] == []
    assert document["roots"][0]["mode_disposition_count"] == 0
    assert document["roots"][0]["mode_dispositions"] == []
    assert document["roots"][0]["casefold_disposition_count"] == 0
    assert document["roots"][0]["casefold_dispositions"] == []
    assert "entries" not in document["roots"][0]
    assert str(manifest).encode() not in lock.canonical_bytes
    assert str(root).encode() not in lock.canonical_bytes
    assert lock.canonical_bytes == _canonical(document)
    assert lock.raw_sha256 == hashlib.sha256(lock.canonical_bytes).hexdigest()

    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=[manifest_locator],
        roots=[root_locator],
    )


def test_macos_fixed_symlink_dispositions_are_closed_and_cross_bound(
    tmp_path: Path,
) -> None:
    manifests, roots, python_root, sdk, _sound = _macos_projected_inputs(
        tmp_path
    )
    with pytest.raises(ToolchainSupportLockError, match="escapes"):
        capture_toolchain_support_tree(roots[0])
    with pytest.raises(ToolchainSupportLockError, match="noncanonical"):
        capture_toolchain_support_tree(roots[1])

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    by_role = {item.logical_role: item for item in lock.roots}
    python_dispositions = by_role["python-runtime"].symlink_dispositions
    sdk_dispositions = by_role["xcode-sdk"].symlink_dispositions
    assert len(python_dispositions) == 3
    assert len(sdk_dispositions) == 3
    assert {
        item.disposition for item in python_dispositions
    } == {
        "bind-external-manifest",
        "deny-isolated-site-packages",
    }
    manifest_merkle = lock.manifests[0].merkle_sha256
    assert all(
        item.external_manifest_merkle_sha256 == manifest_merkle
        for item in python_dispositions
        if item.disposition == "bind-external-manifest"
    )
    assert all(
        item.resolved_relative_path is not None
        and "//" not in (item.canonical_link_target or "")
        for item in sdk_dispositions
    )
    assert str(python_root).encode() not in lock.canonical_bytes
    assert str(sdk).encode() not in lock.canonical_bytes
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )


def test_macos_actions_python_runtime_directory_variant_is_fully_bound(
    tmp_path: Path,
) -> None:
    manifests, roots, python_root, _sdk, _sound = _macos_projected_inputs(
        tmp_path,
        python_layout="actions",
    )

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    python_receipt = next(
        item for item in lock.roots if item.logical_role == "python-runtime"
    )
    assert {
        item.relative_path for item in python_receipt.symlink_dispositions
    } == {
        "config-3.11-darwin/libpython3.11.a",
        "config-3.11-darwin/libpython3.11.dylib",
    }
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )

    (python_root / "site-packages" / "README.txt").write_bytes(b"changed\n")
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            parsed,
            manifests=manifests,
            roots=roots,
        )


def test_macos_xcode_16_4_regular_sound_analysis_variant_is_fully_bound(
    tmp_path: Path,
) -> None:
    manifests, roots, _python_root, sdk, _sound = _macos_projected_inputs(
        tmp_path,
        xcode_layout="xcode-16.4",
    )

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    sdk_receipt = next(
        item for item in lock.roots if item.logical_role == "xcode-sdk"
    )
    assert {
        item.relative_path for item in sdk_receipt.symlink_dispositions
    } == {"System/Library/Frameworks/vecLib.framework"}
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )

    (sdk / "usr" / "lib" / "swift" / "libswiftSoundAnalysis.tbd").write_bytes(
        b"changed\n"
    )
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            parsed,
            manifests=manifests,
            roots=roots,
        )


@pytest.mark.parametrize(
    "attack",
    ("missing", "directory", "wrong-symlink-target", "extra-disposition"),
)
def test_macos_xcode_16_4_sound_analysis_variant_drift_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    manifests, roots, _python_root, sdk, _sound = _macos_projected_inputs(
        tmp_path,
        xcode_layout="xcode-16.4",
    )
    swift = sdk / "usr" / "lib" / "swift"
    sound = swift / "libswiftSoundAnalysis.tbd"
    sound.unlink()
    if attack == "directory":
        sound.mkdir()
    elif attack == "wrong-symlink-target":
        sound.symlink_to("../../../System/Library/Frameworks/Unexpected.tbd")
    elif attack == "extra-disposition":
        sound.symlink_to(
            "../../..//System/Library/Frameworks/SoundAnalysis.framework/"
            "Versions/A/SoundAnalysis.tbd"
        )

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )


@pytest.mark.parametrize("attack", ("missing", "file", "symlink-target"))
def test_macos_actions_python_runtime_directory_variant_drift_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    manifests, roots, python_root, _sdk, _sound = _macos_projected_inputs(
        tmp_path,
        python_layout="actions",
    )
    site_packages = python_root / "site-packages"
    (site_packages / "README.txt").unlink()
    site_packages.rmdir()
    if attack == "file":
        site_packages.write_bytes(b"not a directory\n")
    elif attack == "symlink-target":
        site_packages.symlink_to("config-3.11-darwin")

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )


@pytest.mark.parametrize("attack", ("missing", "target", "resolution", "extra"))
def test_macos_fixed_symlink_disposition_drift_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    manifests, roots, python_root, sdk, sound = _macos_projected_inputs(
        tmp_path
    )
    if attack == "missing":
        (python_root / "site-packages").unlink()
    elif attack == "target":
        alias = python_root / "config-3.11-darwin" / "libpython3.11.a"
        alias.unlink()
        alias.symlink_to("../../Python")
    elif attack == "resolution":
        sound.unlink()
    else:
        (sdk / "unexpected-sdk-alias").symlink_to("bad//target")

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )


def test_linux_target_and_locator_order_are_deterministic(tmp_path: Path) -> None:
    manifest_a = tmp_path / "a.manifest"
    manifest_b = tmp_path / "b.manifest"
    manifest_a.write_bytes(b"a")
    manifest_b.write_bytes(b"b")
    root_a = tmp_path / "a-root"
    root_b = tmp_path / "b-root"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "a").write_bytes(b"a")
    (root_b / "b").write_bytes(b"b")
    manifests = [
        create_toolchain_support_locator(
            logical_role="manifest-b", path=manifest_b, kind="file"
        ),
        create_toolchain_support_locator(
            logical_role="manifest-a", path=manifest_a, kind="file"
        ),
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="root-b", path=root_b, kind="tree"
        ),
        create_toolchain_support_locator(
            logical_role="root-a", path=root_a, kind="tree"
        ),
    ]

    first = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    second = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=list(reversed(manifests)),
        roots=list(reversed(roots)),
    )

    assert first == second
    assert [item.logical_role for item in first.manifests] == [
        "manifest-a",
        "manifest-b",
    ]
    assert [item.logical_role for item in first.roots] == ["root-a", "root-b"]


def test_linux_github_runner_unmapped_symlinks_are_denied_and_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
    )

    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    runtime = lock.roots[0]
    assert runtime.logical_role == "linux-runtime-support"
    assert runtime.symlink_count == 7
    assert runtime.symlink_disposition_count == 7
    assert runtime.member_count == 7
    assert runtime.symlink_dispositions == tuple(
        sorted(
            runtime.symlink_dispositions,
            key=lambda item: (item.relative_path.casefold(), item.relative_path),
        )
    )
    receipts = {
        item.relative_path: item for item in runtime.symlink_dispositions
    }
    assert set(receipts) == set(_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS)
    for relative_path, receipt in receipts.items():
        assert receipt.disposition == "deny-unmapped-virtual-target"
        assert (
            receipt.raw_link_target
            == _LINUX_UNMAPPED_SYMLINK_RAW_TARGETS[relative_path]
        )
        assert receipt.canonical_link_target is None
        assert receipt.external_manifest_role is None
        assert receipt.external_manifest_merkle_sha256 is None
        assert receipt.external_support_root_role is None
        assert receipt.external_support_root_merkle_sha256 is None
        assert receipt.resolved_relative_path is None
        assert receipt.resolved_path_sha256 == support_lock._locator_path_digest(
            runtime_root.parent
            / _LINUX_UNMAPPED_SYMLINK_FINAL_TARGETS[relative_path]
        )

    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )


def test_linux_unmapped_symlink_policy_has_exact_production_targets() -> None:
    rows = support_lock._FIXED_SYMLINK_DISPOSITIONS[
        ("x86_64-unknown-linux-gnu", "linux-runtime-support")
    ]
    by_path = {row.relative_path: row for row in rows}
    assert set(by_path) == set(_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS)
    for relative_path, row in by_path.items():
        assert row.disposition == "deny-unmapped-virtual-target"
        assert (
            row.raw_link_target
            == _LINUX_UNMAPPED_SYMLINK_RAW_TARGETS[relative_path]
        )
        assert row.canonical_link_target is None
        assert row.external_manifest_role is None
        assert row.resolved_path_sha256 == support_lock._locator_path_digest(
            Path("/usr/lib")
            / _LINUX_UNMAPPED_SYMLINK_FINAL_TARGETS[relative_path]
        )


def test_linux_minimal_runtime_variant_needs_no_unmapped_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
        included_paths=frozenset(),
    )
    (runtime_root / "ordinary-runtime.so").write_bytes(b"ordinary runtime\n")

    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )

    runtime = lock.roots[0]
    assert runtime.member_count == 1
    assert runtime.file_count == 1
    assert runtime.symlink_count == 0
    assert runtime.symlink_disposition_count == 0
    assert runtime.symlink_dispositions == ()
    assert verify_toolchain_support_lock(
        lock,
        manifests=manifests,
        roots=roots,
    )


@pytest.mark.parametrize("included_count", range(1, 7))
def test_linux_unmapped_symlink_partial_topologies_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    included_count: int,
) -> None:
    included = frozenset(
        sorted(_LINUX_UNMAPPED_SYMLINK_RAW_TARGETS)[:included_count]
    )
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
        included_paths=included,
    )

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


def test_linux_unmapped_symlink_extra_fixed_like_alias_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
        extra_symlink=(
            "libclang-cpp.so.19",
            "../llvm-19/lib/libclang-cpp.so.19",
        ),
    )

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


def test_linux_unmapped_symlink_raw_target_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
        raw_overrides={
            "libclang-cpp.so.18": "../llvm-18/lib/libclang-cpp.so.18.2"
        },
    )

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


@pytest.mark.parametrize("near_miss", ("target", "role", "root"))
def test_linux_unmapped_symlinks_require_exact_profile_and_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    near_miss: str,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
    )
    target_triple = "x86_64-unknown-linux-gnu"
    candidate_roots = roots
    if near_miss == "target":
        target_triple = "aarch64-unknown-linux-gnu"
    elif near_miss == "role":
        candidate_roots = [
            create_toolchain_support_locator(
                logical_role="linux-runtime-other",
                path=runtime_root,
                kind="tree",
            )
        ]
    else:
        other_root = runtime_root.parent / "other-x86_64-linux-gnu"
        other_root.mkdir()
        for relative_path, raw_target in (
            _LINUX_UNMAPPED_SYMLINK_RAW_TARGETS.items()
        ):
            (other_root / relative_path).symlink_to(raw_target)
        candidate_roots = [
            create_toolchain_support_locator(
                logical_role="linux-runtime-support",
                path=other_root,
                kind="tree",
            )
        ]

    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple=target_triple,
            manifests=manifests,
            roots=candidate_roots,
        )


def test_linux_unmapped_symlink_mutation_fails_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
    )
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    alias = runtime_root / "libclang-cpp.so.17"
    alias.unlink()
    alias.symlink_to("../llvm-17/lib/libclang-cpp.so.17.1")

    with pytest.raises(ToolchainSupportLockError):
        verify_toolchain_support_lock(
            lock,
            manifests=manifests,
            roots=roots,
        )


def test_parser_rejects_unmapped_resolved_digest_forgery_with_fresh_merkles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
    )
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    baseline = json.loads(lock.canonical_bytes)
    assert (
        _refresh_unmapped_forgery_merkles(
            baseline,
            runtime_root=runtime_root,
        )
        == lock.canonical_bytes
    )

    forged = json.loads(lock.canonical_bytes)
    disposition = forged["roots"][0]["symlink_dispositions"][0]
    disposition["resolved_path_sha256"] = "f" * 64
    forged_bytes = _refresh_unmapped_forgery_merkles(
        forged,
        runtime_root=runtime_root,
    )
    assert forged["roots"][0]["merkle_sha256"] != lock.roots[0].merkle_sha256
    assert forged["merkle_sha256"] != lock.merkle_sha256

    with pytest.raises(ToolchainSupportLockError):
        parse_toolchain_support_lock(
            forged_bytes,
            expected_raw_sha256=hashlib.sha256(forged_bytes).hexdigest(),
        )


def test_parser_rejects_unmapped_name_and_shape_forgery_with_fresh_merkles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, runtime_root = _linux_unmapped_virtual_target_inputs(
        tmp_path,
        monkeypatch,
    )
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )

    for mutation in ("name", "shape"):
        forged = json.loads(lock.canonical_bytes)
        disposition = forged["roots"][0]["symlink_dispositions"][0]
        if mutation == "name":
            disposition["disposition"] = "deny-isolated-site-packages"
        else:
            disposition["canonical_link_target"] = "libLLVM.so.18.1"
        forged_bytes = _refresh_unmapped_forgery_merkles(
            forged,
            runtime_root=runtime_root,
        )
        assert (
            forged["roots"][0]["merkle_sha256"]
            != lock.roots[0].merkle_sha256
        )
        assert forged["merkle_sha256"] != lock.merkle_sha256

        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                forged_bytes,
                expected_raw_sha256=hashlib.sha256(forged_bytes).hexdigest(),
            )


def test_linux_gcc_cross_root_symlink_is_bound_and_input_order_invariant(
    tmp_path: Path,
) -> None:
    manifests, roots, gcc_root, runtime_root = _linux_cross_root_inputs(tmp_path)

    first = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    second = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=list(reversed(manifests)),
        roots=list(reversed(roots)),
    )

    assert first.canonical_bytes == second.canonical_bytes
    assert [item.logical_role for item in first.roots] == [
        "linux-gcc-support",
        "linux-runtime-support",
    ]
    gcc_receipt, runtime_receipt = first.roots
    assert gcc_receipt.symlink_disposition_count == 1
    disposition = gcc_receipt.symlink_dispositions[0]
    assert disposition.disposition == "bind-external-support-root"
    assert disposition.relative_path == "libasan.so"
    assert disposition.raw_link_target == (
        "../../../x86_64-linux-gnu/libasan.so.8"
    )
    assert disposition.canonical_link_target is None
    assert disposition.external_manifest_role is None
    assert disposition.external_manifest_merkle_sha256 is None
    assert disposition.external_support_root_role == "linux-runtime-support"
    assert (
        disposition.external_support_root_merkle_sha256
        == runtime_receipt.merkle_sha256
    )
    assert disposition.resolved_relative_path == "libasan.so.8"
    assert str(gcc_root).encode() not in first.canonical_bytes
    assert str(runtime_root).encode() not in first.canonical_bytes
    assert parse_toolchain_support_lock(
        first.canonical_bytes,
        expected_raw_sha256=first.raw_sha256,
    ) == first
    assert verify_toolchain_support_lock(
        first,
        manifests=manifests,
        roots=list(reversed(roots)),
    )


def test_linux_gcc13_lto_unmapped_alias_coexists_with_runtime_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, gcc_root, _runtime_root = _linux_gcc_lto_inputs(
        tmp_path,
        monkeypatch,
    )
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    gcc_receipt = next(
        item for item in lock.roots if item.logical_role == "linux-gcc-support"
    )
    receipts = {
        item.relative_path: item for item in gcc_receipt.symlink_dispositions
    }
    assert gcc_receipt.symlink_count == 2
    assert gcc_receipt.symlink_disposition_count == 2
    assert receipts["libasan.so"].disposition == "bind-external-support-root"
    lto = receipts[_LINUX_GCC_LTO_RELATIVE_PATH]
    assert lto.disposition == "deny-unmapped-virtual-target"
    assert lto.raw_link_target == _LINUX_GCC_LTO_RAW_TARGET
    assert lto.canonical_link_target is None
    assert lto.external_manifest_role is None
    assert lto.external_manifest_merkle_sha256 is None
    assert lto.external_support_root_role is None
    assert lto.external_support_root_merkle_sha256 is None
    assert lto.resolved_relative_path is None
    assert lto.resolved_path_sha256 == support_lock._locator_path_digest(
        gcc_root.parents[3]
        / "libexec"
        / "gcc"
        / "x86_64-linux-gnu"
        / "13"
        / "liblto_plugin.so"
    )
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )


def test_linux_gcc13_minimal_variant_omits_lto_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _gcc_root, _runtime_root = _linux_gcc_lto_inputs(
        tmp_path,
        monkeypatch,
        include_lto=False,
    )
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    gcc_receipt = next(
        item for item in lock.roots if item.logical_role == "linux-gcc-support"
    )
    assert tuple(
        item.relative_path for item in gcc_receipt.symlink_dispositions
    ) == ("libasan.so",)


@pytest.mark.parametrize("mutation", ("extra", "drift"))
def test_linux_gcc13_lto_topology_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    manifests, roots, _gcc_root, _runtime_root = _linux_gcc_lto_inputs(
        tmp_path,
        monkeypatch,
        raw_target=(
            "../../../../libexec/gcc/x86_64-linux-gnu/14/liblto_plugin.so"
            if mutation == "drift"
            else _LINUX_GCC_LTO_RAW_TARGET
        ),
        extra_alias=mutation == "extra",
    )
    with pytest.raises(ToolchainSupportLockError):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


def test_linux_runtime_exact_casefold_topology_is_bound_without_double_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _gcc_root, runtime_root = _linux_cross_root_inputs(tmp_path)
    left = "collision-left"
    right = "collision-right"
    directories: list[Path] = []
    for index in range(10):
        directory = runtime_root / f"collision-{index:02d}"
        directory.mkdir()
        (directory / left).write_bytes(f"left-{index}\n".encode())
        (directory / right).write_bytes(f"right-{index}\n".encode())
        directories.append(directory)
    real_alias = support_lock._alias

    def synthetic_alias(value: str) -> str:
        for raw_name in (left, right):
            if value == raw_name:
                return "synthetic-collision"
            suffix = f"/{raw_name}"
            if value.endswith(suffix):
                return real_alias(value[: -len(suffix)]) + "/synthetic-collision"
        return real_alias(value)

    monkeypatch.setattr(support_lock, "_alias", synthetic_alias)
    expected_groups = tuple(
        sorted(
            (
                support_lock._RawCasefoldGroup(
                    group_sha256=support_lock._sha256(
                        {
                            "domain": (
                                "rextio.full-c6-linux-folded-name-group.v1"
                            ),
                            "directory_relative_path": directory.name,
                            "folded_key": "synthetic-collision",
                            "member_names": [left, right],
                        }
                    ),
                    member_count=2,
                )
                for directory in directories
            ),
            key=lambda item: item.group_sha256,
        )
    )
    real_topology = support_lock._linux_casefold_topology_sha256
    expected_synthetic_topology = real_topology(expected_groups)

    def policy_topology(
        groups: tuple[object, ...],
    ) -> str:
        observed = real_topology(groups)
        if observed == expected_synthetic_topology:
            return support_lock._LINUX_CASEFOLD_TOPOLOGY_SHA256
        return observed

    monkeypatch.setattr(
        support_lock,
        "_linux_casefold_topology_sha256",
        policy_topology,
    )

    wrong_role = create_toolchain_support_locator(
        logical_role="linux-runtime-other",
        path=runtime_root,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="alias|outside"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=[wrong_role],
        )
    with pytest.raises(ToolchainSupportLockError, match="alias|outside"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=[roots[1]],
        )

    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    runtime = next(
        item for item in lock.roots if item.logical_role == "linux-runtime-support"
    )
    assert runtime.member_count == 31
    assert runtime.file_count == 21
    assert runtime.directory_count == 10
    assert runtime.casefold_disposition_count == 1
    receipt = runtime.casefold_dispositions[0]
    assert receipt.group_count == 10
    assert receipt.member_count == 20
    assert (
        receipt.topology_sha256
        == support_lock._LINUX_CASEFOLD_TOPOLOGY_SHA256
    )
    assert left.encode() not in lock.canonical_bytes
    assert right.encode() not in lock.canonical_bytes
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(
        parsed,
        manifests=manifests,
        roots=roots,
    )

    for mutation in ("missing", "extra", "stale"):
        document = lock.to_dict()
        casefold_document = document["roots"][1]["casefold_dispositions"][0]
        if mutation == "missing":
            del casefold_document["topology_sha256"]
        elif mutation == "extra":
            casefold_document["raw_member_names"] = [left, right]
        else:
            casefold_document["topology_sha256"] = "0" * 64
        encoded = _canonical(document)
        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                encoded,
                expected_raw_sha256=hashlib.sha256(encoded).hexdigest(),
            )

    (directories[-1] / right).unlink()
    with pytest.raises(ToolchainSupportLockError, match="topology"):
        verify_toolchain_support_lock(
            parsed,
            manifests=manifests,
            roots=roots,
        )


def test_linux_cross_root_target_mutation_fails_verification(tmp_path: Path) -> None:
    manifests, roots, _gcc_root, runtime_root = _linux_cross_root_inputs(tmp_path)
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )

    (runtime_root / "libasan.so.8").write_bytes(b"changed runtime support\n")

    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            lock,
            manifests=manifests,
            roots=roots,
        )


def test_linux_cross_root_requires_exact_target_role_and_closed_fields(
    tmp_path: Path,
) -> None:
    manifests, roots, _gcc_root, runtime_root = _linux_cross_root_inputs(tmp_path)
    wrong_role = create_toolchain_support_locator(
        logical_role="linux-runtime-other",
        path=runtime_root,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="escapes"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=[roots[0], wrong_role],
        )

    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    for field, value in (
        ("external_support_root_role", "linux-runtime-other"),
        ("external_support_root_merkle_sha256", "0" * 64),
        ("resolved_relative_path", "other.so"),
    ):
        stale = lock.to_dict()
        disposition = stale["roots"][0]["symlink_dispositions"][0]
        disposition[field] = value
        stale_bytes = _canonical(stale)
        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                stale_bytes,
                expected_raw_sha256=hashlib.sha256(stale_bytes).hexdigest(),
            )

    for mutation in ("missing", "extra"):
        open_document = lock.to_dict()
        disposition = open_document["roots"][0]["symlink_dispositions"][0]
        if mutation == "missing":
            del disposition["external_support_root_role"]
        else:
            disposition["ambient_support_root"] = "/tmp/runtime"
        open_bytes = _canonical(open_document)
        with pytest.raises(ToolchainSupportLockError, match="schema"):
            parse_toolchain_support_lock(
                open_bytes,
                expected_raw_sha256=hashlib.sha256(open_bytes).hexdigest(),
            )


def test_linux_cross_root_rejects_overlapping_and_aliased_root_locators(
    tmp_path: Path,
) -> None:
    manifests, roots, gcc_root, _runtime_root = _linux_cross_root_inputs(tmp_path)
    nested = gcc_root / "nested"
    nested.mkdir()
    (nested / "member").write_bytes(b"nested\n")
    nested_locator = create_toolchain_support_locator(
        logical_role="linux-runtime-support",
        path=nested,
        kind="tree",
    )
    alias_locator = create_toolchain_support_locator(
        logical_role="linux-runtime-support",
        path=gcc_root,
        kind="tree",
    )

    for target in (nested_locator, alias_locator):
        with pytest.raises(ToolchainSupportLockError, match="overlap|alias"):
            generate_toolchain_support_lock(
                target_triple="x86_64-unknown-linux-gnu",
                manifests=manifests,
                roots=[roots[0], target],
            )


def test_linux_cross_root_allows_existing_nested_nonedge_roots(
    tmp_path: Path,
) -> None:
    manifests, roots, _gcc_root, _runtime_root = _linux_cross_root_inputs(tmp_path)
    python_library_root = tmp_path / "python" / "lib"
    python_runtime = python_library_root / "python3.11"
    python_runtime.mkdir(parents=True)
    (python_runtime / "encodings.py").write_bytes(b"# runtime\n")
    nested_roots = [
        create_toolchain_support_locator(
            logical_role="linux-python-library-support",
            path=python_library_root,
            kind="tree",
        ),
        create_toolchain_support_locator(
            logical_role="python-runtime",
            path=python_runtime,
            kind="tree",
        ),
    ]

    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=[*roots, *nested_roots],
    )

    assert {item.logical_role for item in lock.roots} == {
        "linux-gcc-support",
        "linux-python-library-support",
        "linux-runtime-support",
        "python-runtime",
    }


def test_linux_cross_root_rejects_inode_aliased_edge_endpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifests, roots, gcc_root, _runtime_root = _linux_cross_root_inputs(tmp_path)
    shared_fd = os.open(gcc_root, os.O_RDONLY)
    shared_stamp = support_lock._stamp(os.fstat(shared_fd))

    def open_same_inode(
        _path: Path,
    ) -> list[tuple[int, int | None, str | None, object]]:
        return [(os.dup(shared_fd), None, None, shared_stamp)]

    monkeypatch.setattr(support_lock, "_open_directory_chain", open_same_inode)
    try:
        with pytest.raises(ToolchainSupportLockError, match="overlap|alias"):
            support_lock._validate_external_support_root_isolation(
                source=roots[0],
                target=roots[1],
            )
    finally:
        os.close(shared_fd)


def test_linux_cross_root_rejects_other_escape_and_standalone_capture(
    tmp_path: Path,
) -> None:
    manifests, roots, gcc_root, _runtime_root = _linux_cross_root_inputs(tmp_path)
    with pytest.raises(ToolchainSupportLockError, match="escapes"):
        capture_toolchain_support_tree(roots[0])

    (gcc_root / "libasan.so").unlink()
    outside = tmp_path / "usr" / "lib" / "outside.so"
    outside.write_bytes(b"not runtime support\n")
    (gcc_root / "libasan.so").symlink_to("../../../outside.so")

    with pytest.raises(ToolchainSupportLockError, match="exact runtime root"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


def test_large_tree_serializes_only_one_bounded_aggregate(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"manifest")
    root = tmp_path / "root"
    root.mkdir()
    for index in range(128):
        (root / f"member-{index:03d}").write_bytes(str(index).encode())
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[
            create_toolchain_support_locator(
                logical_role="manifest", path=manifest, kind="file"
            )
        ],
        roots=[
            create_toolchain_support_locator(
                logical_role="sdk-root", path=root, kind="tree"
            )
        ],
    )

    assert lock.roots[0].member_count == 128
    assert len(lock.canonical_bytes) < 2_000
    assert b"member-000" not in lock.canonical_bytes


def test_merkle_builder_handles_thousands_of_directories_without_pairwise_scans() -> None:
    entries = tuple(
        support_lock._ToolchainSupportTreeEntry(
            relative_path=f"directory-{index:04d}",
            kind="directory",
            mode=0o755,
            metadata_sha256="1" * 64,
            xattr_count=0,
            xattr_bytes=0,
            xattrs_sha256="2" * 64,
            size=0,
            raw_sha256=None,
            link_target=None,
            merkle_sha256="0" * 64,
        )
        for index in range(4_096)
    )

    rebuilt, digest = support_lock._build_tree_merkle(
        logical_role="large-sdk-root",
        locator_path_sha256="3" * 64,
        root_mode=0o755,
        root_metadata_sha256="4" * 64,
        root_xattrs=support_lock._XattrReceipt(
            count=0,
            total_bytes=0,
            merkle_sha256="5" * 64,
        ),
        entries=entries,
    )

    assert len(rebuilt) == 4_096
    assert len({item.merkle_sha256 for item in rebuilt}) == 4_096
    assert len(digest) == 64


def test_locator_paths_are_private_absolute_and_not_serializable(tmp_path: Path) -> None:
    file_path = tmp_path / "manifest"
    file_path.write_bytes(b"manifest")
    locator = create_toolchain_support_locator(
        logical_role="manifest", path=file_path, kind="file"
    )

    assert str(file_path) not in repr(locator)
    assert "path=<private>" in repr(locator)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(locator)
    with pytest.raises(ToolchainSupportLockError, match="absolute"):
        create_toolchain_support_locator(
            logical_role="manifest", path="relative/file", kind="file"
        )
    with pytest.raises(ToolchainSupportLockError, match="lexically"):
        create_toolchain_support_locator(
            logical_role="manifest", path="/tmp/../tmp/file", kind="file"
        )
    decomposed = unicodedata.normalize("NFD", "/tmp/café/file")
    with pytest.raises(ToolchainSupportLockError, match="NFC"):
        create_toolchain_support_locator(
            logical_role="manifest", path=decomposed, kind="file"
        )


def test_opaque_locator_path_and_stable_metadata_are_bound(tmp_path: Path) -> None:
    first = tmp_path / "first.manifest"
    second = tmp_path / "second.manifest"
    first.write_bytes(b"same bytes")
    second.write_bytes(b"same bytes")
    first.chmod(0o644)
    second.chmod(0o644)
    first_receipt = capture_toolchain_support_file(
        create_toolchain_support_locator(
            logical_role="manifest", path=first, kind="file"
        )
    )
    second_receipt = capture_toolchain_support_file(
        create_toolchain_support_locator(
            logical_role="manifest", path=second, kind="file"
        )
    )

    assert first_receipt.raw_sha256 == second_receipt.raw_sha256
    assert first_receipt.locator_path_sha256 != second_receipt.locator_path_sha256
    assert first_receipt.metadata_sha256 != second_receipt.metadata_sha256

    first.chmod(0o600)
    changed = capture_toolchain_support_file(
        create_toolchain_support_locator(
            logical_role="manifest", path=first, kind="file"
        )
    )
    assert changed.metadata_sha256 != first_receipt.metadata_sha256
    assert changed.merkle_sha256 != first_receipt.merkle_sha256


@pytest.mark.parametrize(
    "target",
    ["x86_64-apple-darwin", "aarch64-unknown-linux-gnu", "wasm32-wasi"],
)
def test_scope_rejects_targets_outside_the_two_fixed_hosts(
    tmp_path: Path,
    target: str,
) -> None:
    _manifest, _root, manifest_locator, root_locator = _inputs(tmp_path)
    with pytest.raises(ToolchainSupportLockError, match="fixed host profile"):
        generate_toolchain_support_lock(
            target_triple=target,
            manifests=[manifest_locator],
            roots=[root_locator],
        )


def test_parser_rejects_wrong_pin_duplicate_keys_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)

    with pytest.raises(ToolchainSupportLockError, match="does not match"):
        parse_toolchain_support_lock(
            lock.canonical_bytes,
            expected_raw_sha256="0" * 64,
        )

    duplicate = b'{"kind":"a","kind":"b"}'
    with pytest.raises(ToolchainSupportLockError, match="duplicate"):
        parse_toolchain_support_lock(
            duplicate,
            expected_raw_sha256=hashlib.sha256(duplicate).hexdigest(),
        )

    noncanonical = json.dumps(lock.to_dict(), indent=2).encode()
    with pytest.raises(ToolchainSupportLockError, match="not canonical"):
        parse_toolchain_support_lock(
            noncanonical,
            expected_raw_sha256=hashlib.sha256(noncanonical).hexdigest(),
        )


def test_parser_rejects_open_schema_and_stale_aggregate(tmp_path: Path) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)
    open_document = lock.to_dict()
    open_document["ambient_path"] = "/tmp/toolchain"
    open_bytes = _canonical(open_document)
    with pytest.raises(ToolchainSupportLockError, match="schema"):
        parse_toolchain_support_lock(
            open_bytes,
            expected_raw_sha256=hashlib.sha256(open_bytes).hexdigest(),
        )

    stale = lock.to_dict()
    stale["total_bytes"] = lock.total_bytes + 1
    stale_bytes = _canonical(stale)
    with pytest.raises(ToolchainSupportLockError, match="summary"):
        parse_toolchain_support_lock(
            stale_bytes,
            expected_raw_sha256=hashlib.sha256(stale_bytes).hexdigest(),
        )


def test_v5_tree_disposition_schema_rejects_v4_missing_extra_and_stale_fields(
    tmp_path: Path,
) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)

    v4 = lock.to_dict()
    v4["schema_version"] = 4
    v4["domain"] = "rextio.full-c6-toolchain-support-lock.v4"
    v4_bytes = _canonical(v4)
    with pytest.raises(ToolchainSupportLockError, match="identity"):
        parse_toolchain_support_lock(
            v4_bytes,
            expected_raw_sha256=hashlib.sha256(v4_bytes).hexdigest(),
        )

    for mutation in ("missing", "extra"):
        document = lock.to_dict()
        tree = document["roots"][0]
        if mutation == "missing":
            del tree["hardlink_dispositions"]
        else:
            tree["ambient_dispositions"] = []
        encoded = _canonical(document)
        with pytest.raises(ToolchainSupportLockError, match="schema"):
            parse_toolchain_support_lock(
                encoded,
                expected_raw_sha256=hashlib.sha256(encoded).hexdigest(),
            )

    stale = lock.to_dict()
    stale["roots"][0]["casefold_disposition_count"] = 1
    stale_bytes = _canonical(stale)
    with pytest.raises(ToolchainSupportLockError, match="noncanonical"):
        parse_toolchain_support_lock(
            stale_bytes,
            expected_raw_sha256=hashlib.sha256(stale_bytes).hexdigest(),
        )


def test_secure_load_round_trip_and_rejects_link_aliases(tmp_path: Path) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)
    lock_path = tmp_path / "support.lock.json"
    lock_path.write_bytes(lock.canonical_bytes)
    locator = create_toolchain_support_locator(
        logical_role="support-lock", path=lock_path, kind="file"
    )
    assert load_toolchain_support_lock(
        locator,
        expected_raw_sha256=lock.raw_sha256,
    ) == lock

    symlink_path = tmp_path / "support-symlink.json"
    symlink_path.symlink_to(lock_path.name)
    symlink_locator = create_toolchain_support_locator(
        logical_role="support-lock", path=symlink_path, kind="file"
    )
    with pytest.raises(ToolchainSupportLockError):
        load_toolchain_support_lock(
            symlink_locator,
            expected_raw_sha256=lock.raw_sha256,
        )

    symlink_path.unlink()
    try:
        os.link(lock_path, tmp_path / "support-hardlink.json")
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    hardlink_locator = create_toolchain_support_locator(
        logical_role="support-lock",
        path=tmp_path / "support-hardlink.json",
        kind="file",
    )
    with pytest.raises(ToolchainSupportLockError, match="single-link"):
        load_toolchain_support_lock(
            hardlink_locator,
            expected_raw_sha256=lock.raw_sha256,
        )


def test_verification_detects_manifest_and_tree_changes(tmp_path: Path) -> None:
    manifest, root, manifest_locator, root_locator = _inputs(tmp_path)
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )

    manifest.write_bytes(b"changed manifest")
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator],
            roots=[root_locator],
        )

    manifest.write_bytes(b"implementation=cpython\nversion=3.11\n")
    (root / "extra").write_bytes(b"extra")
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator],
            roots=[root_locator],
        )
    (root / "extra").unlink()
    (root / "include" / "Python.h").write_bytes(b"changed")
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator],
            roots=[root_locator],
        )


def test_verification_detects_missing_extra_and_wrong_kind_roles(tmp_path: Path) -> None:
    manifest, _root, manifest_locator, root_locator = _inputs(tmp_path)
    second = tmp_path / "second.manifest"
    second.write_bytes(b"second")
    second_locator = create_toolchain_support_locator(
        logical_role="second-manifest", path=second, kind="file"
    )
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator, second_locator],
        roots=[root_locator],
    )

    with pytest.raises(ToolchainSupportLockError, match="roles or kinds"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator],
            roots=[root_locator],
        )
    extra = tmp_path / "extra.manifest"
    extra.write_bytes(b"extra")
    extra_locator = create_toolchain_support_locator(
        logical_role="extra-manifest", path=extra, kind="file"
    )
    with pytest.raises(ToolchainSupportLockError, match="roles or kinds"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator, second_locator, extra_locator],
            roots=[root_locator],
        )
    wrong_role = create_toolchain_support_locator(
        logical_role="renamed-manifest", path=manifest, kind="file"
    )
    with pytest.raises(ToolchainSupportLockError, match="roles or kinds"):
        verify_toolchain_support_lock(
            lock,
            manifests=[wrong_role, second_locator],
            roots=[root_locator],
        )


def test_unrelated_file_outside_a_support_root_does_not_change_it(tmp_path: Path) -> None:
    _manifest, _root, manifest_locator, root_locator = _inputs(tmp_path)
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )
    (tmp_path / "outside-root").write_bytes(b"not support input")
    assert verify_toolchain_support_lock(
        lock,
        manifests=[manifest_locator],
        roots=[root_locator],
    )


def test_xattr_names_values_and_aggregate_bytes_are_bound(tmp_path: Path) -> None:
    manifest, root, manifest_locator, root_locator = _inputs(tmp_path)
    _set_test_xattr(manifest, b"com.rextio.manifest", b"manifest-xattr")
    _set_test_xattr(
        root / "include" / "Python.h",
        b"com.rextio.header",
        b"header-xattr",
    )
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )

    assert lock.manifests[0].xattr_count >= 1
    assert lock.roots[0].xattr_count >= 1
    assert lock.xattr_count == (
        lock.manifests[0].xattr_count + lock.roots[0].xattr_count
    )
    assert lock.xattr_bytes >= len(b"manifest-xattr") + len(b"header-xattr")

    _set_test_xattr(manifest, b"com.rextio.manifest", b"changed-xattr")
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            lock,
            manifests=[manifest_locator],
            roots=[root_locator],
        )


def test_xattr_count_budget_stops_before_the_late_value_callback() -> None:
    callbacks: list[tuple[bytes, int]] = []
    budget = support_lock._XattrBudget(remaining_count=1, remaining_bytes=16)

    def read_value(name: bytes, maximum: int) -> bytes:
        callbacks.append((name, maximum))
        return b"value"

    with pytest.raises(ToolchainSupportLockError, match="remaining budget"):
        support_lock._capture_xattrs(
            list_names=lambda: (b"first", b"second"),
            read_value=read_value,
            budget=budget,
        )

    assert callbacks == [(b"first", 11)]
    assert budget.remaining_count == 0
    assert budget.remaining_bytes == 6


def test_xattr_byte_budget_bounds_the_late_value_read() -> None:
    queries: list[tuple[bytes, int]] = []
    reads: list[bytes] = []
    values = {b"a": b"x", b"b": b"xx"}
    budget = support_lock._XattrBudget(remaining_count=2, remaining_bytes=4)

    def read_value(name: bytes, maximum: int) -> bytes:
        queries.append((name, maximum))
        value = values[name]
        if len(value) > maximum:
            raise ToolchainSupportLockError(
                "toolchain support xattr value exceeds the remaining budget"
            )
        reads.append(name)
        return value

    with pytest.raises(ToolchainSupportLockError, match="remaining budget"):
        support_lock._capture_xattrs(
            list_names=lambda: (b"a", b"b"),
            read_value=read_value,
            budget=budget,
        )

    assert queries == [(b"a", 3), (b"b", 1)]
    assert reads == [b"a"]
    assert budget.remaining_count == 1
    assert budget.remaining_bytes == 2


def test_fd_xattr_rejects_queried_size_before_allocating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allocations: list[int] = []

    def fake_fgetxattr(*_args: object) -> int:
        return 8

    def reject_allocation(size: int) -> ctypes.Array[ctypes.c_char]:
        allocations.append(size)
        raise AssertionError("xattr value buffer must not be allocated")

    monkeypatch.setattr(
        support_lock,
        "_libc_xattr_function",
        lambda _name: fake_fgetxattr,
    )
    monkeypatch.setattr(ctypes, "create_string_buffer", reject_allocation)

    with pytest.raises(ToolchainSupportLockError, match="remaining budget"):
        support_lock._read_fd_xattr(
            7,
            b"bounded",
            maximum_value_bytes=4,
        )

    assert allocations == []


def test_lock_xattr_count_budget_is_shared_across_multiple_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"manifest")
    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    root_a.mkdir()
    root_b.mkdir()
    member_a = root_a / "member"
    member_b = root_b / "member"
    member_a.write_bytes(b"a")
    member_b.write_bytes(b"b")
    prefix = b"user.rextio" if sys.platform == "linux" else b"com.rextio"
    _set_test_xattr(member_a, prefix + b".root-a", b"a")
    _set_test_xattr(member_b, prefix + b".root-b", b"b")
    manifest_locator = create_toolchain_support_locator(
        logical_role="manifest",
        path=manifest,
        kind="file",
    )
    root_a_locator = create_toolchain_support_locator(
        logical_role="root-a",
        path=root_a,
        kind="tree",
    )
    root_b_locator = create_toolchain_support_locator(
        logical_role="root-b",
        path=root_b,
        kind="tree",
    )
    manifest_receipt = capture_toolchain_support_file(manifest_locator)
    root_a_receipt = capture_toolchain_support_tree(root_a_locator)
    root_b_receipt = capture_toolchain_support_tree(root_b_locator)
    shared_limit = manifest_receipt.xattr_count + max(
        root_a_receipt.xattr_count,
        root_b_receipt.xattr_count,
    )
    assert (
        manifest_receipt.xattr_count
        + root_a_receipt.xattr_count
        + root_b_receipt.xattr_count
        > shared_limit
    )
    monkeypatch.setattr(
        support_lock,
        "MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS",
        shared_limit,
    )

    with pytest.raises(ToolchainSupportLockError, match="remaining budget"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[manifest_locator],
            roots=[root_b_locator, root_a_locator],
        )


@pytest.mark.parametrize(
    ("constant_name", "field_name"),
    [
        ("MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS", "xattr_count"),
        ("MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES", "xattr_bytes"),
    ],
)
def test_parser_rejects_xattr_aggregate_over_the_lock_wide_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant_name: str,
    field_name: str,
) -> None:
    manifest, _root, manifest_locator, root_locator = _inputs(tmp_path)
    prefix = b"user.rextio" if sys.platform == "linux" else b"com.rextio"
    _set_test_xattr(manifest, prefix + b".manifest", b"manifest-xattr")
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[manifest_locator],
        roots=[root_locator],
    )
    observed = getattr(lock, field_name)
    assert type(observed) is int and observed > 0
    monkeypatch.setattr(support_lock, constant_name, observed - 1)

    with pytest.raises(ToolchainSupportLockError, match="summary"):
        parse_toolchain_support_lock(
            lock.canonical_bytes,
            expected_raw_sha256=lock.raw_sha256,
        )


def test_contained_symlink_is_bound_and_escape_broken_and_cycle_are_rejected(
    tmp_path: Path,
) -> None:
    contained = tmp_path / "contained"
    contained.mkdir()
    (contained / "target").write_bytes(b"target")
    (contained / "alias").symlink_to("target")
    receipt = capture_toolchain_support_tree(
        create_toolchain_support_locator(
            logical_role="contained-root", path=contained, kind="tree"
        )
    )
    assert receipt.symlink_count == 1

    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    escaping = tmp_path / "escaping"
    escaping.mkdir()
    (escaping / "alias").symlink_to("../outside")
    with pytest.raises(ToolchainSupportLockError, match="escapes"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="escaping-root", path=escaping, kind="tree"
            )
        )

    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "alias").symlink_to("missing")
    with pytest.raises(ToolchainSupportLockError, match="broken"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="broken-root", path=broken, kind="tree"
            )
        )

    cycle = tmp_path / "cycle"
    cycle.mkdir()
    (cycle / "a").symlink_to("b")
    (cycle / "b").symlink_to("a")
    with pytest.raises(ToolchainSupportLockError, match="cycle"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="cycle-root", path=cycle, kind="tree"
            )
        )


def test_tree_rejects_casefold_alias_special_file_and_hardlink(tmp_path: Path) -> None:
    aliases = tmp_path / "aliases"
    aliases.mkdir()
    (aliases / "straße").write_bytes(b"one")
    (aliases / "STRASSE").write_bytes(b"two")
    if len(os.listdir(aliases)) != 2:
        pytest.skip("filesystem does not permit the casefold-alias fixture")
    with pytest.raises(ToolchainSupportLockError, match="alias"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="alias-root", path=aliases, kind="tree"
            )
        )

    special = tmp_path / "special"
    special.mkdir()
    try:
        os.mkfifo(special / "fifo")
    except (AttributeError, OSError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")
    with pytest.raises(ToolchainSupportLockError, match="special"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="special-root", path=special, kind="tree"
            )
        )

    hardlinks = tmp_path / "hardlinks"
    hardlinks.mkdir()
    original = hardlinks / "original"
    original.write_bytes(b"shared")
    try:
        os.link(original, hardlinks / "alias")
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    with pytest.raises(ToolchainSupportLockError, match="hardlink"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="hardlink-root", path=hardlinks, kind="tree"
            )
        )


def test_tree_member_mode_diagnostic_is_exact_bounded_and_path_opaque(
    tmp_path: Path,
) -> None:
    manifest, root, manifest_locator, root_locator = _inputs(tmp_path)
    secret_name = "relative-secret-mode-member"
    member = root / "include" / secret_name
    member.write_bytes(b"mode diagnostic")
    member.chmod(0o4755)
    if stat.S_IMODE(member.lstat().st_mode) != 0o4755:
        pytest.skip("test filesystem did not preserve the set-user-ID mode bit")

    with pytest.raises(ToolchainSupportLockError) as captured:
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[manifest_locator],
            roots=[root_locator],
        )

    relative_path = f"include/{secret_name}"
    expected_path_sha256 = hashlib.sha256(
        _canonical(
            {
                "domain": (
                    "rextio.full-c6-toolchain-support-"
                    "mode-diagnostic-path.v1"
                ),
                "relative_path": relative_path,
            }
        )
    ).hexdigest()
    message = str(captured.value)
    assert message == (
        "toolchain support permission mode is invalid "
        "(target_triple=aarch64-apple-darwin, "
        "logical_role=python-support-root, kind=regular, "
        f"relative_path_sha256={expected_path_sha256}, mode=4755)"
    )
    assert len(message.encode("utf-8")) <= 512
    assert secret_name not in message
    assert str(root) not in message
    assert str(manifest) not in message
    assert str(tmp_path) not in message


def test_tree_member_mode_diagnostic_leaves_ordinary_mode_validation_unchanged() -> None:
    assert (
        support_lock._validate_tree_member_mode(
            target_triple="x86_64-unknown-linux-gnu",
            logical_role="linux-runtime-support",
            relative_path="ordinary-member",
            full_mode=stat.S_IFREG | 0o755,
        )
        == 0o755
    )
    with pytest.raises(
        ToolchainSupportLockError,
        match="^toolchain support permission mode is invalid$",
    ):
        support_lock._validate_mode(0o4755)


def test_manifest_mode_diagnostic_is_exact_bounded_and_path_opaque(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "absolute-secret-manifest"
    manifest.write_bytes(b"mode diagnostic")
    manifest.chmod(0o4755)
    if stat.S_IMODE(manifest.lstat().st_mode) != 0o4755:
        pytest.skip("test filesystem did not preserve the set-user-ID mode bit")
    locator = create_toolchain_support_locator(
        logical_role="secret-manifest-role",
        path=manifest,
        kind="file",
    )

    with pytest.raises(ToolchainSupportLockError) as captured:
        capture_toolchain_support_file(locator)

    expected_path_sha256 = support_lock._locator_path_digest(manifest)
    message = str(captured.value)
    assert message == (
        "toolchain support permission mode is invalid "
        "(origin=manifest-observation, target_triple=unscoped, "
        "logical_role=secret-manifest-role, kind=regular, "
        f"locator_path_sha256={expected_path_sha256}, mode=4755)"
    )
    assert len(message.encode("utf-8")) <= 512
    assert manifest.name not in message
    assert str(manifest) not in message
    assert str(tmp_path) not in message


def test_generated_mode_context_leaves_parsed_receipt_error_generic(
    tmp_path: Path,
) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)
    document = json.loads(lock.canonical_bytes)
    document["manifests"][0]["mode"] = 0o4755
    raw = _canonical(document)

    with pytest.raises(
        ToolchainSupportLockError,
        match="^toolchain support permission mode is invalid$",
    ):
        parse_toolchain_support_lock(
            raw,
            expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_tree_root_mode_diagnostic_is_exact_bounded_and_path_opaque(
    tmp_path: Path,
) -> None:
    manifest, root, manifest_locator, root_locator = _inputs(tmp_path)
    root.chmod(0o2755)
    if stat.S_IMODE(root.lstat().st_mode) != 0o2755:
        pytest.skip("test filesystem did not preserve the set-group-ID mode bit")

    with pytest.raises(ToolchainSupportLockError) as captured:
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=[manifest_locator],
            roots=[root_locator],
        )

    expected_path_sha256 = support_lock._locator_path_digest(root)
    message = str(captured.value)
    assert message == (
        "toolchain support permission mode is invalid "
        "(target_triple=x86_64-unknown-linux-gnu, "
        "logical_role=python-support-root, kind=root, "
        f"locator_path_sha256={expected_path_sha256}, mode=2755)"
    )
    assert len(message.encode("utf-8")) <= 512
    assert str(root) not in message
    assert str(manifest) not in message
    assert str(tmp_path) not in message


def _linux_mode_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[ToolchainSupportLocator], list[ToolchainSupportLocator], Path, Path]:
    manifest = tmp_path / "linux.manifest"
    manifest.write_bytes(b"linux=fixed\n")
    root = tmp_path / "usr" / "lib" / "x86_64-linux-gnu"
    member = root / "utempter" / "utempter"
    member.parent.mkdir(parents=True)
    member.write_bytes(b"fixed setgid helper\n")
    member.chmod(0o2755)
    if stat.S_IMODE(member.lstat().st_mode) != 0o2755:
        pytest.skip("test filesystem did not preserve the set-group-ID mode bit")
    monkeypatch.setattr(
        support_lock,
        "_LINUX_MODE_DISPOSITION_ROOT",
        root,
    )
    monkeypatch.setattr(
        support_lock,
        "_LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(root),
    )
    manifests = [
        create_toolchain_support_locator(
            logical_role="linux-manifest",
            path=manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="linux-runtime-support",
            path=root,
            kind="tree",
        )
    ]
    return manifests, roots, root, member


def test_linux_exact_mode_disposition_is_bound_once_without_double_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, root, member = _linux_mode_inputs(tmp_path, monkeypatch)
    lock = generate_toolchain_support_lock(
        target_triple="x86_64-unknown-linux-gnu",
        manifests=manifests,
        roots=roots,
    )
    tree = lock.roots[0]
    assert tree.member_count == 2
    assert tree.file_count == 1
    assert tree.directory_count == 1
    assert tree.total_bytes == member.stat().st_size
    assert tree.mode_disposition_count == 1
    receipt = tree.mode_dispositions[0]
    assert receipt.mode == 0o2755
    assert receipt.kind == "regular"
    assert (
        receipt.support_root_locator_path_sha256
        == support_lock._locator_path_digest(root)
    )
    assert (
        receipt.relative_path_sha256
        == support_lock._relative_mode_path_digest("utempter/utempter")
    )
    assert receipt.raw_sha256 == hashlib.sha256(member.read_bytes()).hexdigest()
    assert len(receipt.full_stamp_sha256) == 64
    assert len(receipt.metadata_sha256) == 64
    assert len(receipt.member_receipt_sha256) == 64
    assert b"utempter/utempter" not in lock.canonical_bytes
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(parsed, manifests=manifests, roots=roots)

    omitted = lock.to_dict()
    omitted["roots"][0]["mode_disposition_count"] = 0
    omitted["roots"][0]["mode_dispositions"] = []
    omitted_bytes = _canonical(omitted)
    with pytest.raises(ToolchainSupportLockError, match="presence"):
        parse_toolchain_support_lock(
            omitted_bytes,
            expected_raw_sha256=hashlib.sha256(omitted_bytes).hexdigest(),
        )

    for mutation in ("missing", "extra", "stale", "bool"):
        document = lock.to_dict()
        mode = document["roots"][0]["mode_dispositions"][0]
        if mutation == "missing":
            del mode["member_receipt_sha256"]
        elif mutation == "extra":
            mode["relative_path"] = "utempter/utempter"
        elif mutation == "stale":
            mode["metadata_sha256"] = "0" * 64
        else:
            mode["mode"] = True
        encoded = _canonical(document)
        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                encoded,
                expected_raw_sha256=hashlib.sha256(encoded).hexdigest(),
            )


def test_linux_mode_disposition_rejects_every_policy_near_miss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _root, member = _linux_mode_inputs(tmp_path, monkeypatch)
    with pytest.raises(ToolchainSupportLockError, match="permission mode"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )
    wrong_role = create_toolchain_support_locator(
        logical_role="linux-runtime-other",
        path=roots[0]._absolute_path,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="permission mode"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=[wrong_role],
        )
    other_root = tmp_path / "other-runtime-root"
    other_member = other_root / "utempter" / "utempter"
    other_member.parent.mkdir(parents=True)
    other_member.write_bytes(b"wrong-root helper\n")
    other_member.chmod(0o2755)
    other_locator = create_toolchain_support_locator(
        logical_role="linux-runtime-support",
        path=other_root,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="permission mode"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=[other_locator],
        )
    member.chmod(0o4755)
    with pytest.raises(ToolchainSupportLockError, match="permission mode"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )
    member.chmod(0o755)
    with pytest.raises(ToolchainSupportLockError, match="presence"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )


def test_tree_hardlink_diagnostic_is_bounded_and_path_opaque(tmp_path: Path) -> None:
    secret_root = tmp_path / "absolute-secret-support-root"
    secret_root.mkdir()
    first_relative_path = "relative-secret-alias"
    original = secret_root / "relative-secret-original"
    original.write_bytes(b"shared")
    try:
        os.link(original, secret_root / first_relative_path)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")

    with pytest.raises(ToolchainSupportLockError) as captured:
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="diagnostic-root", path=secret_root, kind="tree"
            )
        )

    message = str(captured.value)
    expected_path_sha256 = hashlib.sha256(
        _canonical(
            {
                "domain": (
                    "rextio.full-c6-toolchain-support-"
                    "hardlink-diagnostic-path.v1"
                ),
                "relative_path": first_relative_path,
            }
        )
    ).hexdigest()
    assert "logical_role=diagnostic-root" in message
    assert f"relative_path_sha256={expected_path_sha256}" in message
    observed = original.stat()
    assert f"st_uid={observed.st_uid}" in message
    assert f"st_gid={observed.st_gid}" in message
    assert f"st_mode={observed.st_mode}" in message
    assert "st_nlink=2" in message
    assert "in_root_inode_observation_count=1" in message
    assert first_relative_path not in message
    assert original.name not in message
    assert str(secret_root) not in message
    assert str(tmp_path) not in message


def _xcode_topology_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    list[ToolchainSupportLocator],
    list[ToolchainSupportLocator],
    Path,
    Path,
    tuple[Path, ...],
]:
    app = tmp_path / "Xcode.app"
    root = (
        app
        / "Contents"
        / "Developer"
        / "Toolchains"
        / "XcodeDefault.xctoolchain"
        / "usr"
        / "lib"
        / "clang"
        / "17"
    )
    include = root / "include"
    include.mkdir(parents=True)
    first = include / "first.h"
    second = include / "second.h"
    first.write_bytes(b"first fixed topology member\n")
    second.write_bytes(b"second fixed topology member\n")
    aliases = app / "Aliases"
    aliases.mkdir()
    alias_paths = (
        aliases / "first-one",
        aliases / "first-two",
        aliases / "second-one",
    )
    try:
        os.link(first, alias_paths[0])
        os.link(first, alias_paths[1])
        os.link(second, alias_paths[2])
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    version_manifest = app / "Contents" / "version.plist"
    version_manifest.write_bytes(b"synthetic Xcode version 17\n")

    def topology_digest(domain: str, value: dict[str, object]) -> str:
        return support_lock._xcode_topology_sha256(domain, value)

    policy_groups: list[str] = []
    for support_path, group_paths in (
        (first, (first, alias_paths[0], alias_paths[1])),
        (second, (second, alias_paths[2])),
    ):
        support_relative = support_path.relative_to(root).as_posix()
        alias_digests = sorted(
            topology_digest(
                "rextio.full-c6-xcode-hardlink-topology-alias-path.v1",
                {"app_relative_path": item.relative_to(app).as_posix()},
            )
            for item in group_paths
        )
        support_digest = topology_digest(
            "rextio.full-c6-xcode-hardlink-topology-support-path.v1",
            {"support_relative_path": support_relative},
        )
        policy_groups.append(
            topology_digest(
                "rextio.full-c6-xcode-hardlink-topology-policy-group.v1",
                {
                    "support_relative_path_sha256s": [support_digest],
                    "link_count": len(group_paths),
                    "alias_count": len(group_paths),
                    "alias_path_sha256s": alias_digests,
                },
            )
        )
    policy_merkle = topology_digest(
        "rextio.full-c6-xcode-hardlink-topology-policy.v1",
        {"policy_group_sha256s": sorted(policy_groups)},
    )
    monkeypatch.setattr(support_lock, "_XCODE_APP_BOUNDARY", app)
    monkeypatch.setattr(support_lock, "_XCODE_RESOURCE_ROOT", root)
    monkeypatch.setattr(
        support_lock,
        "_XCODE_RESOURCE_ROOT_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(root),
    )
    monkeypatch.setattr(
        support_lock,
        "_XCODE_VERSION_MANIFEST",
        version_manifest,
    )
    monkeypatch.setattr(
        support_lock,
        "_XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(version_manifest),
    )
    monkeypatch.setattr(
        support_lock,
        "_XCODE_VERSION_MANIFEST_RAW_SHA256",
        hashlib.sha256(version_manifest.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_GROUP_COUNT", 2)
    monkeypatch.setattr(
        support_lock,
        "_XCODE_HARDLINK_SUPPORT_MEMBER_COUNT",
        2,
    )
    monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_ALIAS_COUNT", 5)
    monkeypatch.setattr(
        support_lock,
        "_XCODE_HARDLINK_POLICY_MERKLE_SHA256",
        policy_merkle,
    )
    manifests = [
        create_toolchain_support_locator(
            logical_role="xcode-version-plist",
            path=version_manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="xcode-clang-resource",
            path=root,
            kind="tree",
        )
    ]
    return manifests, roots, app, root, (first, second, *alias_paths)


def _xcode_multiple_support_path_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    logical_role: str = "xcode-clang-resource",
) -> tuple[
    list[ToolchainSupportLocator],
    list[ToolchainSupportLocator],
    Path,
    Path,
    tuple[Path, ...],
]:
    app = tmp_path / "Xcode.app"
    if logical_role == "xcode-clang-resource":
        root = (
            app
            / "Contents"
            / "Developer"
            / "Toolchains"
            / "XcodeDefault.xctoolchain"
            / "usr"
            / "lib"
            / "clang"
            / "17"
        )
    else:
        assert logical_role == "xcode-sdk"
        root = (
            app
            / "Contents"
            / "Developer"
            / "Platforms"
            / "MacOSX.platform"
            / "Developer"
            / "SDKs"
            / "MacOSX.sdk"
        )
    include = root / "include"
    include.mkdir(parents=True)
    first = include / "first.h"
    second = include / "second.h"
    external_alias = app / "Aliases" / "third.h"
    external_alias.parent.mkdir()
    first.write_bytes(b"shared fixed topology member\n")
    try:
        os.link(first, second)
        os.link(first, external_alias)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    version_manifest = app / "Contents" / "version.plist"
    version_manifest.write_bytes(b"synthetic Xcode version 17\n")

    support_digests = sorted(
        support_lock._xcode_topology_sha256(
            "rextio.full-c6-xcode-hardlink-topology-support-path.v1",
            {"support_relative_path": path.relative_to(root).as_posix()},
        )
        for path in (first, second)
    )
    alias_digests = sorted(
        support_lock._xcode_topology_sha256(
            "rextio.full-c6-xcode-hardlink-topology-alias-path.v1",
            {"app_relative_path": path.relative_to(app).as_posix()},
        )
        for path in (first, second, external_alias)
    )
    policy_group = support_lock._xcode_topology_sha256(
        "rextio.full-c6-xcode-hardlink-topology-policy-group.v1",
        {
            "support_relative_path_sha256s": support_digests,
            "link_count": 3,
            "alias_count": 3,
            "alias_path_sha256s": alias_digests,
        },
    )
    policy_merkle = support_lock._xcode_topology_sha256(
        "rextio.full-c6-xcode-hardlink-topology-policy.v1",
        {"policy_group_sha256s": [policy_group]},
    )
    monkeypatch.setattr(support_lock, "_XCODE_APP_BOUNDARY", app)
    if logical_role == "xcode-clang-resource":
        monkeypatch.setattr(support_lock, "_XCODE_RESOURCE_ROOT", root)
        monkeypatch.setattr(
            support_lock,
            "_XCODE_RESOURCE_ROOT_LOCATOR_PATH_SHA256",
            support_lock._locator_path_digest(root),
        )
    else:
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_HARDLINK_ROLE",
            "xcode-sdk",
            raising=False,
        )
        monkeypatch.setattr(support_lock, "_XCODE_SDK_ROOT", root, raising=False)
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_ROOT_LOCATOR_PATH_SHA256",
            support_lock._locator_path_digest(root),
            raising=False,
        )
        policy_key = ("aarch64-apple-darwin", "xcode-sdk")
        monkeypatch.setattr(
            support_lock,
            "_FIXED_SYMLINK_DISPOSITIONS",
            {**support_lock._FIXED_SYMLINK_DISPOSITIONS, policy_key: ()},
        )
        monkeypatch.setattr(
            support_lock,
            "_MACOS_XCODE_SDK_MODERN_DISPOSITION_PATHS",
            frozenset(),
        )
        monkeypatch.setattr(
            support_lock,
            "_MACOS_XCODE_SDK_16_4_DISPOSITION_PATHS",
            frozenset(),
        )
    monkeypatch.setattr(support_lock, "_XCODE_VERSION_MANIFEST", version_manifest)
    monkeypatch.setattr(
        support_lock,
        "_XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256",
        support_lock._locator_path_digest(version_manifest),
    )
    monkeypatch.setattr(
        support_lock,
        "_XCODE_VERSION_MANIFEST_RAW_SHA256",
        hashlib.sha256(version_manifest.read_bytes()).hexdigest(),
    )
    if logical_role == "xcode-clang-resource":
        monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_GROUP_COUNT", 1)
        monkeypatch.setattr(
            support_lock,
            "_XCODE_HARDLINK_SUPPORT_MEMBER_COUNT",
            2,
        )
        monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_ALIAS_COUNT", 3)
        monkeypatch.setattr(
            support_lock,
            "_XCODE_HARDLINK_POLICY_MERKLE_SHA256",
            policy_merkle,
        )
    else:
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_HARDLINK_GROUP_COUNT",
            1,
            raising=False,
        )
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_HARDLINK_SUPPORT_MEMBER_COUNT",
            2,
            raising=False,
        )
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_HARDLINK_ALIAS_COUNT",
            3,
            raising=False,
        )
        monkeypatch.setattr(
            support_lock,
            "_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256",
            policy_merkle,
            raising=False,
        )
    manifests = [
        create_toolchain_support_locator(
            logical_role="xcode-version-plist",
            path=version_manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role=logical_role,
            path=root,
            kind="tree",
        )
    ]
    return manifests, roots, app, root, (first, second, external_alias)


def test_xcode_topology_accepts_exact_multiple_support_paths_per_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, _root, paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
    )

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )

    tree = lock.roots[0]
    receipt = tree.hardlink_dispositions[0]
    assert tree.file_count == 2
    assert tree.total_bytes == sum(path.stat().st_size for path in paths[:2])
    assert receipt.group_count == 1
    assert receipt.support_member_count == 2
    assert receipt.alias_count == 3
    assert verify_toolchain_support_lock(lock, manifests=manifests, roots=roots)


def test_frozen_xcode_sdk_hardlink_policy_constants_are_exact() -> None:
    assert getattr(support_lock, "_XCODE_SDK_HARDLINK_ROLE", None) == "xcode-sdk"
    assert getattr(support_lock, "_XCODE_SDK_ROOT", None) == Path(
        "/Applications/Xcode.app/Contents/Developer/Platforms/"
        "MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    )
    assert (
        getattr(support_lock, "_XCODE_SDK_ROOT_LOCATOR_PATH_SHA256", None)
        == "06a2a3aad7cf447c6c6606bfbffc69f1de90229943e1b7d73e4b0534c73c35d0"
    )
    assert getattr(support_lock, "_XCODE_SDK_HARDLINK_GROUP_COUNT", None) == 4_626
    assert (
        getattr(support_lock, "_XCODE_SDK_HARDLINK_SUPPORT_MEMBER_COUNT", None)
        == 8_605
    )
    assert getattr(support_lock, "_XCODE_SDK_HARDLINK_ALIAS_COUNT", None) == 24_430
    assert (
        getattr(support_lock, "_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256", None)
        == "6e5221cfc1d3ff7ca60fdae6b6f6bcc9b126af9dc62e57b4d0242368a018e4b8"
    )
    assert support_lock._XCODE_HARDLINK_MAX_GROUPS == 4_626
    assert support_lock._XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP == 128


def test_xcode_hardlink_policy_rejects_a_truncated_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        support_lock,
        "_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256",
        "6e5221cfc1d3ff7ca60fdae6b6f6bcc9b126af9dc62e57b4d0242368a018e4",
    )

    with pytest.raises(
        ToolchainSupportLockError,
        match="Xcode hardlink policy Merkle SHA-256 must be a lowercase SHA-256 digest",
    ):
        support_lock._fixed_xcode_hardlink_policies()


def test_exact_xcode_sdk_topology_is_selected_and_round_trips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, root, _paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
        logical_role="xcode-sdk",
    )

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )

    receipt = lock.roots[0].hardlink_dispositions[0]
    assert receipt.resource_root_locator_path_sha256 == (
        support_lock._locator_path_digest(root)
    )
    assert receipt.group_count == 1
    assert receipt.support_member_count == 2
    assert receipt.alias_count == 3
    topology = support_lock._scan_xcode_hardlink_topology(
        support_root=root,
        app_boundary=support_lock._XCODE_APP_BOUNDARY,
    )
    assert topology.groups[0].support_relative_paths == (
        "include/first.h",
        "include/second.h",
    )
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(parsed, manifests=manifests, roots=roots)


def test_xcode_sdk_topology_consumes_two_plans_and_reopens_every_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, root, paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
        logical_role="xcode-sdk",
    )
    real_from_topology = support_lock._AllowedHardlinkPlan.from_topology.__func__
    plans: list[object] = []

    def tracked_plan(cls: type[object], topology: object):
        plan = real_from_topology(cls, topology)
        plans.append(plan)
        return plan

    monkeypatch.setattr(
        support_lock._AllowedHardlinkPlan,
        "from_topology",
        classmethod(tracked_plan),
    )
    real_scan = support_lock._scan_xcode_hardlink_topology
    scans = 0

    def tracked_scan(*, support_root: Path, app_boundary: Path):
        nonlocal scans
        scans += 1
        return real_scan(
            support_root=support_root,
            app_boundary=app_boundary,
        )

    monkeypatch.setattr(
        support_lock,
        "_scan_xcode_hardlink_topology",
        tracked_scan,
    )
    real_reopen = support_lock._open_xcode_topology_regular
    reopened: list[tuple[Path, str]] = []

    def tracked_reopen(
        *, boundary: Path, relative_path: str, expected: object
    ) -> None:
        reopened.append((boundary, relative_path))
        real_reopen(
            boundary=boundary,
            relative_path=relative_path,
            expected=expected,
        )

    monkeypatch.setattr(
        support_lock,
        "_open_xcode_topology_regular",
        tracked_reopen,
    )

    generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )

    assert scans == 2
    assert len(plans) == 2
    assert plans[0] is not plans[1]
    assert all(not plan.entries for plan in plans)
    assert set(reopened) == {
        (root, paths[0].relative_to(root).as_posix()),
        (root, paths[1].relative_to(root).as_posix()),
        *((app, path.relative_to(app).as_posix()) for path in paths),
    }


def test_xcode_sdk_topology_root_count_digest_version_and_bound_drift_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, root, _paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
        logical_role="xcode-sdk",
    )

    for name, value in (
        ("_XCODE_SDK_HARDLINK_GROUP_COUNT", 2),
        ("_XCODE_SDK_HARDLINK_SUPPORT_MEMBER_COUNT", 3),
        ("_XCODE_SDK_HARDLINK_ALIAS_COUNT", 4),
        ("_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256", "0" * 64),
    ):
        with monkeypatch.context() as scoped:
            scoped.setattr(support_lock, name, value)
            with pytest.raises(ToolchainSupportLockError, match="topology"):
                generate_toolchain_support_lock(
                    target_triple="aarch64-apple-darwin",
                    manifests=manifests,
                    roots=roots,
                )

    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_XCODE_SDK_ROOT_LOCATOR_PATH_SHA256",
            "0" * 64,
        )
        with pytest.raises(ToolchainSupportLockError, match="hardlink"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )

    with monkeypatch.context() as scoped:
        scoped.setattr(support_lock, "_XCODE_VERSION_MANIFEST_RAW_SHA256", "0" * 64)
        with pytest.raises(ToolchainSupportLockError, match="manifest differs"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )

    with monkeypatch.context() as scoped:
        scoped.setattr(support_lock, "_XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP", 2)
        with pytest.raises(ToolchainSupportLockError, match="alias bound"):
            support_lock._scan_xcode_hardlink_topology(
                support_root=root,
                app_boundary=app,
            )


def test_xcode_sdk_policy_mismatch_diagnostic_is_exact_and_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, root, paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
        logical_role="xcode-sdk",
    )
    policy_digest = support_lock._XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256

    with monkeypatch.context() as scoped:
        scoped.setattr(support_lock, "_XCODE_SDK_HARDLINK_GROUP_COUNT", 2)
        with pytest.raises(ToolchainSupportLockError) as captured:
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )

    message = str(captured.value)
    assert message == (
        "toolchain support Xcode hardlink topology differs from policy "
        "(logical_role=xcode-sdk, "
        "observed_group_count=1, expected_group_count=2, "
        "observed_support_member_count=2, expected_support_member_count=2, "
        "observed_alias_count=3, expected_alias_count=3, "
        f"observed_policy_merkle_sha256={policy_digest}, "
        f"expected_policy_merkle_sha256={policy_digest})"
    )
    assert str(tmp_path) not in message
    assert str(app) not in message
    assert str(root) not in message
    assert all(path.name not in message for path in paths)


def test_xcode_sdk_final_reopen_rejects_a_different_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifests, _roots, app, root, _paths = _xcode_multiple_support_path_inputs(
        tmp_path,
        monkeypatch,
        logical_role="xcode-sdk",
    )
    topology = support_lock._scan_xcode_hardlink_topology(
        support_root=root,
        app_boundary=app,
    )

    with pytest.raises(ToolchainSupportLockError, match="outside the exact profile"):
        support_lock._reopen_xcode_hardlink_topology(
            topology,
            support_root=root.parent,
            app_boundary=app,
        )


def test_exact_xcode_topology_is_root_scoped_bound_and_not_double_counted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, root, paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    tree = lock.roots[0]
    assert tree.member_count == 3
    assert tree.file_count == 2
    assert tree.directory_count == 1
    assert tree.total_bytes == sum(item.stat().st_size for item in paths[:2])
    assert tree.hardlink_disposition_count == 1
    receipt = tree.hardlink_dispositions[0]
    assert receipt.group_count == receipt.support_member_count == 2
    assert receipt.alias_count == 5
    assert (
        receipt.resource_root_locator_path_sha256
        == support_lock._locator_path_digest(root)
    )
    assert receipt.version_manifest_role == "xcode-version-plist"
    assert (
        receipt.version_manifest_raw_sha256
        == lock.manifests[0].raw_sha256
    )
    assert (
        receipt.version_manifest_merkle_sha256
        == lock.manifests[0].merkle_sha256
    )
    assert len(receipt.observation_merkle_sha256) == 64
    for path in paths:
        assert path.name.encode() not in lock.canonical_bytes
    assert str(app).encode() not in lock.canonical_bytes
    parsed = parse_toolchain_support_lock(
        lock.canonical_bytes,
        expected_raw_sha256=lock.raw_sha256,
    )
    assert parsed == lock
    assert verify_toolchain_support_lock(parsed, manifests=manifests, roots=roots)

    omitted = lock.to_dict()
    omitted["roots"][0]["hardlink_disposition_count"] = 0
    omitted["roots"][0]["hardlink_dispositions"] = []
    omitted_bytes = _canonical(omitted)
    with pytest.raises(ToolchainSupportLockError, match="topology disposition is missing"):
        parse_toolchain_support_lock(
            omitted_bytes,
            expected_raw_sha256=hashlib.sha256(omitted_bytes).hexdigest(),
        )

    for mutation in ("missing", "extra", "stale", "bool"):
        document = lock.to_dict()
        topology = document["roots"][0]["hardlink_dispositions"][0]
        if mutation == "missing":
            del topology["observation_merkle_sha256"]
        elif mutation == "extra":
            topology["raw_alias_paths"] = [str(paths[-1])]
        elif mutation == "stale":
            topology["version_manifest_merkle_sha256"] = "0" * 64
        else:
            topology["group_count"] = True
        encoded = _canonical(document)
        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                encoded,
                expected_raw_sha256=hashlib.sha256(encoded).hexdigest(),
            )


def test_parser_rejects_xcode_version_manifest_locator_drift_with_fresh_merkle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, _root, _paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    expected_manifest = manifests[0]._absolute_path
    foreign_manifest = expected_manifest.with_name("foreign-version.plist")
    foreign_manifest.write_bytes(expected_manifest.read_bytes())
    foreign_locator = create_toolchain_support_locator(
        logical_role="xcode-version-plist",
        path=foreign_manifest,
        kind="file",
    )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_XCODE_VERSION_MANIFEST",
            foreign_manifest,
        )
        scoped.setattr(
            support_lock,
            "_XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256",
            support_lock._locator_path_digest(foreign_manifest),
        )
        foreign_lock = generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[foreign_locator],
            roots=roots,
        )

    assert (
        foreign_lock.manifests[0].locator_path_sha256
        != support_lock._XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256
    )
    with pytest.raises(
        ToolchainSupportLockError,
        match="topology policy changed",
    ):
        parse_toolchain_support_lock(
            foreign_lock.canonical_bytes,
            expected_raw_sha256=foreign_lock.raw_sha256,
        )


def test_xcode_topology_rejects_policy_near_misses_and_outside_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, _root, paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_GROUP_COUNT", 3)
    with pytest.raises(ToolchainSupportLockError, match="topology"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )
    monkeypatch.setattr(support_lock, "_XCODE_HARDLINK_GROUP_COUNT", 2)
    outside = tmp_path / "outside-alias"
    os.link(paths[0], outside)
    with pytest.raises(ToolchainSupportLockError, match="alias count"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )
    outside.unlink()
    in_root_alias = roots[0]._absolute_path / "include" / "duplicate-first.h"
    os.link(paths[0], in_root_alias)
    with pytest.raises(ToolchainSupportLockError, match="topology"):
        support_lock._scan_xcode_hardlink_topology(
            support_root=roots[0]._absolute_path,
            app_boundary=app,
        )


def test_xcode_topology_rejects_target_role_root_version_and_policy_near_misses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, root, _paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    wrong_role = create_toolchain_support_locator(
        logical_role="xcode-clang-other",
        path=root,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="hardlink"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=[wrong_role],
        )
    with pytest.raises(ToolchainSupportLockError, match="hardlink"):
        generate_toolchain_support_lock(
            target_triple="x86_64-unknown-linux-gnu",
            manifests=manifests,
            roots=roots,
        )
    with monkeypatch.context() as scoped:
        scoped.setattr(support_lock, "_XCODE_RESOURCE_ROOT", root.parent)
        with pytest.raises(ToolchainSupportLockError, match="hardlink"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )
    wrong_manifest = create_toolchain_support_locator(
        logical_role="xcode-version-other",
        path=manifests[0]._absolute_path,
        kind="file",
    )
    with pytest.raises(ToolchainSupportLockError, match="manifest is missing"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[wrong_manifest],
            roots=roots,
        )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256",
            "0" * 64,
        )
        with pytest.raises(ToolchainSupportLockError, match="manifest differs"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_XCODE_VERSION_MANIFEST_RAW_SHA256",
            "0" * 64,
        )
        with pytest.raises(ToolchainSupportLockError, match="manifest differs"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_XCODE_HARDLINK_POLICY_MERKLE_SHA256",
            "0" * 64,
        )
        with pytest.raises(ToolchainSupportLockError, match="topology"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )


def test_xcode_topology_brackets_tree_capture_and_final_reopens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, _root, paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    original_scan = support_lock._scan_xcode_hardlink_topology
    calls = 0

    def racing_scan(*, support_root: Path, app_boundary: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            paths[-1].chmod(0o700)
        result = original_scan(
            support_root=support_root,
            app_boundary=app_boundary,
        )
        return result

    monkeypatch.setattr(
        support_lock,
        "_scan_xcode_hardlink_topology",
        racing_scan,
    )
    with pytest.raises(ToolchainSupportLockError, match="changed across"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )
    assert calls == 2


def test_xcode_topology_uses_two_independent_consumed_plans_and_reopens_all(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, _root, _paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    real_from_topology = support_lock._AllowedHardlinkPlan.from_topology.__func__
    plans: list[object] = []

    def tracked_plan(cls: type[object], topology: object):
        plan = real_from_topology(cls, topology)
        plans.append(plan)
        return plan

    monkeypatch.setattr(
        support_lock._AllowedHardlinkPlan,
        "from_topology",
        classmethod(tracked_plan),
    )
    real_reopen = support_lock._open_xcode_topology_regular
    reopened: list[tuple[Path, str]] = []

    def tracked_reopen(
        *, boundary: Path, relative_path: str, expected: object
    ) -> None:
        reopened.append((boundary, relative_path))
        real_reopen(
            boundary=boundary,
            relative_path=relative_path,
            expected=expected,
        )

    monkeypatch.setattr(
        support_lock,
        "_open_xcode_topology_regular",
        tracked_reopen,
    )
    generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    assert len(plans) == 2
    assert plans[0] is not plans[1]
    assert all(not plan.entries for plan in plans)
    assert len(reopened) == 7


def test_xcode_topology_rejects_plan_leftover_final_reopen_race_and_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, app, root, paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    real_from_topology = support_lock._AllowedHardlinkPlan.from_topology.__func__

    def plan_with_leftover(cls: type[object], topology: object):
        plan = real_from_topology(cls, topology)
        plan.entries["ghost/member"] = topology.groups[0].stamp
        return plan

    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock._AllowedHardlinkPlan,
            "from_topology",
            classmethod(plan_with_leftover),
        )
        with pytest.raises(ToolchainSupportLockError, match="not fully consumed"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )
    real_reopen = support_lock._open_xcode_topology_regular
    reopened = False

    def racing_reopen(
        *, boundary: Path, relative_path: str, expected: object
    ) -> None:
        nonlocal reopened
        if not reopened:
            reopened = True
            paths[-1].chmod(0o700)
        real_reopen(
            boundary=boundary,
            relative_path=relative_path,
            expected=expected,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(
            support_lock,
            "_open_xcode_topology_regular",
            racing_reopen,
        )
        with pytest.raises(ToolchainSupportLockError, match="final stamp"):
            generate_toolchain_support_lock(
                target_triple="aarch64-apple-darwin",
                manifests=manifests,
                roots=roots,
            )
    paths[-1].chmod(0o644)
    with monkeypatch.context() as scoped:
        scoped.setattr(support_lock, "_XCODE_HARDLINK_SUPPORT_MAX_ENTRIES", 1)
        with pytest.raises(ToolchainSupportLockError, match="entry bound"):
            support_lock._scan_xcode_hardlink_topology(
                support_root=root,
                app_boundary=app,
            )


def test_xcode_topology_revalidates_version_manifest_after_tree_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests, roots, _app, _root, _paths = _xcode_topology_inputs(
        tmp_path,
        monkeypatch,
    )
    original_reopen = support_lock._reopen_xcode_hardlink_topology

    def mutate_manifest(*args: object, **kwargs: object) -> None:
        original_reopen(*args, **kwargs)
        manifests[0]._absolute_path.write_bytes(b"changed version manifest\n")

    monkeypatch.setattr(
        support_lock,
        "_reopen_xcode_hardlink_topology",
        mutate_manifest,
    )
    with pytest.raises(ToolchainSupportLockError, match="version manifest changed"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=manifests,
            roots=roots,
        )


def test_xcode_single_link_variant_needs_no_hardlink_disposition(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"xcode=single-link\n")
    root = tmp_path / "clang-resource"
    include = root / "include"
    include.mkdir(parents=True)
    (include / "__clang_cuda_builtin_vars.h").write_bytes(b"single link")
    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=[
            create_toolchain_support_locator(
                logical_role="xcode-manifest", path=manifest, kind="file"
            )
        ],
        roots=[
            create_toolchain_support_locator(
                logical_role="xcode-clang-resource", path=root, kind="tree"
            )
        ],
    )

    assert lock.roots[0].hardlink_disposition_count == 0
    assert lock.roots[0].hardlink_dispositions == ()


def test_manifest_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"manifest")
    symlink = tmp_path / "manifest-link"
    symlink.symlink_to(manifest.name)
    with pytest.raises(ToolchainSupportLockError):
        capture_toolchain_support_file(
            create_toolchain_support_locator(
                logical_role="manifest", path=symlink, kind="file"
            )
        )

    symlink.unlink()
    try:
        os.link(manifest, tmp_path / "manifest-hardlink")
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    with pytest.raises(ToolchainSupportLockError, match="single-link"):
        capture_toolchain_support_file(
            create_toolchain_support_locator(
                logical_role="manifest",
                path=tmp_path / "manifest-hardlink",
                kind="file",
            )
        )


def test_tree_rejects_member_byte_count_and_depth_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    byte_root = tmp_path / "byte-root"
    byte_root.mkdir()
    (byte_root / "large").write_bytes(b"ab")
    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_FILE_BYTES", 1)
    with pytest.raises(ToolchainSupportLockError, match="byte bound"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="byte-root", path=byte_root, kind="tree"
            )
        )

    monkeypatch.setattr(
        support_lock,
        "MAX_TOOLCHAIN_SUPPORT_FILE_BYTES",
        512 * 1024 * 1024,
    )
    count_root = tmp_path / "count-root"
    count_root.mkdir()
    (count_root / "one").write_bytes(b"1")
    (count_root / "two").write_bytes(b"2")
    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_DIRECTORY_ENTRIES", 1)
    with pytest.raises(ToolchainSupportLockError, match="directory entry count"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="directory-count-root", path=count_root, kind="tree"
            )
        )

    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_DIRECTORY_ENTRIES", 65_536)
    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS", 1)
    with pytest.raises(ToolchainSupportLockError, match="member count"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="count-root", path=count_root, kind="tree"
            )
        )

    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS", 65_536)
    deep_root = tmp_path / "deep-root"
    deep_root.mkdir()
    (deep_root / "nested").mkdir()
    (deep_root / "nested" / "member").write_bytes(b"member")
    monkeypatch.setattr(support_lock, "MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH", 1)
    with pytest.raises(ToolchainSupportLockError, match="depth"):
        capture_toolchain_support_tree(
            create_toolchain_support_locator(
                logical_role="deep-root", path=deep_root, kind="tree"
            )
        )


def test_role_aliases_and_locator_kinds_fail_closed(tmp_path: Path) -> None:
    manifest, root, manifest_locator, _root_locator = _inputs(tmp_path)
    alias_locator = create_toolchain_support_locator(
        logical_role="PYTHON-ABI-CONFIG".lower(),
        path=manifest,
        kind="file",
    )
    other_root_locator = create_toolchain_support_locator(
        logical_role="python-abi-config",
        path=root,
        kind="tree",
    )
    with pytest.raises(ToolchainSupportLockError, match="role alias"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[manifest_locator],
            roots=[other_root_locator],
        )
    with pytest.raises(ToolchainSupportLockError, match="file locator"):
        generate_toolchain_support_lock(
            target_triple="aarch64-apple-darwin",
            manifests=[
                create_toolchain_support_locator(
                    logical_role="wrong-kind", path=root, kind="tree"
                )
            ],
            roots=[
                create_toolchain_support_locator(
                    logical_role="root", path=root, kind="tree"
                )
            ],
        )
    assert alias_locator.logical_role == "python-abi-config"
