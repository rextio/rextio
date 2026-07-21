from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pickle
import ctypes
from dataclasses import fields, replace
import sys
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

    assert TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION == 4
    assert TOOLCHAIN_SUPPORT_LOCK_DOMAIN.endswith("support-lock.v4")
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


def test_v4_tree_disposition_schema_rejects_v3_missing_extra_and_stale_fields(
    tmp_path: Path,
) -> None:
    lock, _manifest_locator, _root_locator = _lock(tmp_path)

    v3 = lock.to_dict()
    v3["schema_version"] = 3
    v3["domain"] = "rextio.full-c6-toolchain-support-lock.v3"
    v3_bytes = _canonical(v3)
    with pytest.raises(ToolchainSupportLockError, match="identity"):
        parse_toolchain_support_lock(
            v3_bytes,
            expected_raw_sha256=hashlib.sha256(v3_bytes).hexdigest(),
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


def test_exact_xcode_hardlink_disposition_binds_aliases_and_complete_stamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "Xcode.app"
    toolchain = (
        app
        / "Contents"
        / "Developer"
        / "Toolchains"
        / "XcodeDefault.xctoolchain"
    )
    root = toolchain / "usr" / "lib" / "clang" / "21"
    include = root / "include"
    include.mkdir(parents=True)
    original = include / "__clang_cuda_builtin_vars.h"
    original.write_bytes(b"fixed xcode hardlink disposition")
    aliases = app / "Aliases"
    aliases.mkdir(parents=True)
    alias_one = aliases / "alias-one"
    alias_two = aliases / "alias-two"
    try:
        os.link(original, alias_one)
        os.link(original, alias_two)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    app_relative_paths = tuple(
        item.relative_to(app).as_posix()
        for item in (original, alias_one, alias_two)
    )
    policy_digests = dict(
        zip(
            sorted(app_relative_paths),
            support_lock._XCODE_HARDLINK_ALIAS_PATH_SHA256S,
            strict=True,
        )
    )
    real_path_digest = support_lock._xcode_hardlink_alias_path_sha256

    def synthetic_path_digest(relative_path: str) -> str:
        return policy_digests.get(relative_path, real_path_digest(relative_path))

    def synthetic_context(
        *, root_path: Path, relative_path: str
    ) -> tuple[Path, PurePosixPath] | None:
        if (
            root_path == root
            and relative_path == support_lock._XCODE_HARDLINK_RELATIVE_PATH
        ):
            return app, PurePosixPath(*original.relative_to(app).parts)
        return None

    monkeypatch.setattr(
        support_lock,
        "_xcode_hardlink_alias_path_sha256",
        synthetic_path_digest,
    )
    monkeypatch.setattr(
        support_lock,
        "_xcode_hardlink_scan_context",
        synthetic_context,
    )
    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"xcode=fixture\n")
    manifests = [
        create_toolchain_support_locator(
            logical_role="xcode-manifest", path=manifest, kind="file"
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="xcode-clang-resource", path=root, kind="tree"
        )
    ]
    observed = support_lock._stamp(original.stat())
    expected_stamp_sha256 = support_lock._xcode_hardlink_full_stamp_sha256(
        observed
    )

    lock = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    receipt = lock.roots[0]
    assert receipt.member_count == 2
    assert receipt.file_count == 1
    assert receipt.directory_count == 1
    assert receipt.total_bytes == len(original.read_bytes())
    assert receipt.hardlink_disposition_count == 1
    hardlink = receipt.hardlink_dispositions[0]
    assert hardlink.relative_path == "include/__clang_cuda_builtin_vars.h"
    assert hardlink.link_count == hardlink.alias_count == 3
    assert (
        hardlink.alias_path_sha256s
        == support_lock._XCODE_HARDLINK_ALIAS_PATH_SHA256S
    )
    assert hardlink.full_stamp_sha256 == expected_stamp_sha256
    assert len(hardlink.alias_parent_chain_merkle_sha256) == 64
    assert str(app).encode() not in lock.canonical_bytes
    assert alias_one.name.encode() not in lock.canonical_bytes
    assert alias_two.name.encode() not in lock.canonical_bytes
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
        hardlink_document = document["roots"][0]["hardlink_dispositions"][0]
        if mutation == "missing":
            del hardlink_document["full_stamp_sha256"]
        elif mutation == "extra":
            hardlink_document["absolute_alias_path"] = str(alias_one)
        else:
            hardlink_document["alias_parent_chain_merkle_sha256"] = "0" * 64
        encoded = _canonical(document)
        with pytest.raises(ToolchainSupportLockError):
            parse_toolchain_support_lock(
                encoded,
                expected_raw_sha256=hashlib.sha256(encoded).hexdigest(),
            )

    aliases.chmod(0o700)
    with pytest.raises(ToolchainSupportLockError, match="differ"):
        verify_toolchain_support_lock(
            parsed,
            manifests=manifests,
            roots=roots,
        )

    for stamp_field in fields(observed):
        value = getattr(observed, stamp_field.name)
        changed_value = 1 if value is None else value + 1
        changed = replace(observed, **{stamp_field.name: changed_value})
        assert (
            support_lock._xcode_hardlink_full_stamp_sha256(changed)
            != expected_stamp_sha256
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
