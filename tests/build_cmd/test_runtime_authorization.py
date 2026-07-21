from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import sys
from typing import Any, cast

import pytest

from rextio.build import runtime_authorization as runtime_authorization_module
from rextio.artifacts.evidence import (
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    NativeRuntimeTransitiveClosureEdge,
    NativeRuntimeTransitiveClosureInventory,
    NativeRuntimeTransitiveClosureNode,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE
from rextio.build.runtime_authorization import (
    REASON_AUTHORIZED,
    REASON_IMPORTED_SYMBOL,
    REASON_LOAD_CONSTRUCT,
    REASON_LOAD_SET,
    REASON_OUT_OF_SCOPE,
    REASON_PLATFORM_BASE,
    REASON_PROBE_FAILED,
    REASON_STATIC_INVALID,
    RUNTIME_AUTHORIZED,
    RUNTIME_DENIED,
    RUNTIME_OUT_OF_SCOPE,
    RUNTIME_VERIFICATION_INJECTED_TEST_ONLY,
    RuntimeAuthorizationError,
    RuntimeImageSnapshot,
    RuntimeLoadedImage,
    RuntimeLoadCommandInspection,
    _capture_native_runtime_snapshot,
    authorize_native_runtime,
    authorize_native_runtime_for_testing,
    capture_runtime_image_snapshot,
    capture_runtime_loaded_image,
    verify_native_runtime_authorization,
)
from rextio.build.runtime_closure import NativeRuntimeTransitiveClosureObservation
from rextio.build.runtime_resolution import (
    NativeRuntimePathResolutionObservation,
    _read_candidate_secure,
)


@dataclass(frozen=True)
class _RuntimeCase:
    target_triple: str
    root: Path
    extension: Path
    runtime_inventory: NativeRuntimeInventory
    path_resolution: NativeRuntimePathResolutionObservation
    transitive_closure: NativeRuntimeTransitiveClosureObservation
    platform_base: RuntimeImageSnapshot
    declared_system_images: tuple[RuntimeLoadedImage, ...]
    after: RuntimeImageSnapshot


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _case(
    tmp_path: Path,
    *,
    target_triple: str = "aarch64-apple-darwin",
    packaged_dependency: bool = False,
) -> _RuntimeCase:
    is_macho = target_triple == "aarch64-apple-darwin"
    format_name = "mach-o" if is_macho else "elf"
    architecture = "aarch64" if is_macho else "x86_64"
    inspector = "otool" if is_macho else "readelf"
    system_name = "libSystem.B.dylib" if is_macho else "libc.so.6"
    extension_name = "_native_ext.so"

    root = tmp_path / "root"
    extension = root / "pkg" / extension_name
    extension.parent.mkdir(parents=True)
    extension.write_bytes(b"exact-extension-bytes")
    member = f"pkg/{extension_name}"
    subject_sha256 = _sha(extension)
    subject_size = extension.stat().st_size

    if packaged_dependency:
        dependency_name = "libthird.dylib" if is_macho else "libthird.so"
        dependency = NativeRuntimeDependency(
            name=dependency_name,
            origin="wheel-candidate",
        )
        packaged_path = extension.parent / dependency_name
        packaged_path.write_bytes(b"third-party-runtime")
        packaged_member = f"pkg/{dependency_name}"
        record = NativeRuntimePathResolutionRecord(
            dependency_bom_ref=dependency.bom_ref(),
            dependency_name=dependency_name,
            dependency_origin="wheel-candidate",
            resolution="wheel-member",
            mechanism="macho-loader-path" if is_macho else "elf-origin-rpath",
            wheel_member=packaged_member,
            sha256=_sha(packaged_path),
            size=packaged_path.stat().st_size,
        )
    else:
        dependency_name = system_name
        dependency = NativeRuntimeDependency(name=dependency_name, origin="system")
        packaged_path = None
        packaged_member = None
        record = NativeRuntimePathResolutionRecord(
            dependency_bom_ref=dependency.bom_ref(),
            dependency_name=dependency_name,
            dependency_origin="system",
            resolution="system-logical",
            mechanism="macho-system" if is_macho else "elf-system-name",
        )

    runtime_inventory = NativeRuntimeInventory(
        format=format_name,
        architecture=architecture,
        inspector=inspector,
        subject_basename=extension_name,
        subject_sha256=subject_sha256,
        subject_size=subject_size,
        wheel_member=member,
        wheel_member_sha256=subject_sha256,
        wheel_member_size=subject_size,
        dependencies=(dependency,),
    )
    path_inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=member,
        subject_sha256=subject_sha256,
        records=(record,),
    )
    root_node = NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format=format_name,
        name=extension_name,
        wheel_member=member,
        sha256=subject_sha256,
        size=subject_size,
    )
    if packaged_dependency:
        assert packaged_path is not None and packaged_member is not None
        dependency_node = NativeRuntimeTransitiveClosureNode(
            kind="wheel-member",
            format=format_name,
            name=dependency_name,
            wheel_member=packaged_member,
            sha256=_sha(packaged_path),
            size=packaged_path.stat().st_size,
        )
    else:
        dependency_node = NativeRuntimeTransitiveClosureNode(
            kind="system-logical",
            format=format_name,
            name=dependency_name,
        )
    edge = NativeRuntimeTransitiveClosureEdge(
        source_ref=root_node.node_ref,
        target_ref=dependency_node.node_ref,
        dependency_name=dependency_name,
        mechanism=record.mechanism,
    )
    nodes = tuple(sorted((root_node, dependency_node), key=lambda node: node.node_ref))
    closure_inventory = NativeRuntimeTransitiveClosureInventory(
        format=format_name,
        architecture=architecture,
        subject_wheel_member=member,
        subject_sha256=subject_sha256,
        subject_size=subject_size,
        root_node_ref=root_node.node_ref,
        nodes=nodes,
        edges=(edge,),
    )
    closure_receipts = [
        _read_candidate_secure(root=root, parts=("pkg", extension_name))
    ]
    if packaged_dependency:
        closure_receipts.append(
            _read_candidate_secure(root=root, parts=("pkg", dependency_name))
        )
    transitive_closure = NativeRuntimeTransitiveClosureObservation(
        inventory=closure_inventory,
        receipts=tuple(
            sorted(closure_receipts, key=lambda receipt: receipt.parts)
        ),
    )

    platform_process = tmp_path / "python-runtime"
    platform_process.write_bytes(b"python-runtime")
    base = capture_runtime_image_snapshot((platform_process,))
    extension_image = capture_runtime_loaded_image(extension)
    if packaged_dependency:
        system_images: tuple[RuntimeLoadedImage, ...] = ()
        after = capture_runtime_image_snapshot((platform_process, extension))
    else:
        system_path = tmp_path / system_name
        system_path.write_bytes(b"system-abi-leaf")
        system_images = (capture_runtime_loaded_image(system_path),)
        after = capture_runtime_image_snapshot((platform_process, extension, system_path))
    # C6.8/C6.9 receipts bind every ancestor directory stamp.  Capture them
    # only after the complete fixture (including sibling platform files) exists.
    path_resolution = NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(
            (_read_candidate_secure(root=root, parts=("pkg", dependency_name)),)
            if packaged_dependency
            else ()
        ),
    )
    refreshed_closure_receipts = [
        _read_candidate_secure(root=root, parts=("pkg", extension_name))
    ]
    if packaged_dependency:
        refreshed_closure_receipts.append(
            _read_candidate_secure(root=root, parts=("pkg", dependency_name))
        )
    transitive_closure = NativeRuntimeTransitiveClosureObservation(
        inventory=closure_inventory,
        receipts=tuple(
            sorted(refreshed_closure_receipts, key=lambda receipt: receipt.parts)
        ),
    )
    assert extension_image in after.images
    return _RuntimeCase(
        target_triple=target_triple,
        root=root,
        extension=extension,
        runtime_inventory=runtime_inventory,
        path_resolution=path_resolution,
        transitive_closure=transitive_closure,
        platform_base=base,
        declared_system_images=system_images,
        after=after,
    )


def _authorize(
    case: _RuntimeCase,
    *,
    snapshots: tuple[RuntimeImageSnapshot, ...] | None = None,
    import_action: Any = lambda: None,
    commands: tuple[str, ...] | None = None,
    symbols: tuple[str, ...] = ("PyLong_FromLong",),
    system_platform_images: tuple[str, ...] = (),
    inspected_dependencies: tuple[str, ...] | None = None,
):
    values = iter(snapshots or (case.platform_base, case.after))
    command_tokens = commands or (
        ("LC_LOAD_DYLIB",) if case.target_triple.startswith("aarch64-") else ("NEEDED",)
    )
    load_inspection = RuntimeLoadCommandInspection(
        format=case.runtime_inventory.format,
        dependencies=(
            tuple(
                sorted(
                    dependency.name
                    for dependency in case.runtime_inventory.dependencies
                )
            )
            if inspected_dependencies is None
            else tuple(sorted(set(inspected_dependencies)))
        ),
        commands=tuple(sorted(set(command_tokens))),
    )
    return authorize_native_runtime_for_testing(
        target_triple=case.target_triple,
        expected_python_root=case.root,
        extension_path=case.extension,
        runtime_inventory=case.runtime_inventory,
        path_resolution=case.path_resolution,
        transitive_closure=case.transitive_closure,
        platform_base=case.platform_base,
        declared_system_images=case.declared_system_images,
        import_action=import_action,
        declared_system_platform_images=system_platform_images,
        snapshot_collector=lambda: next(values),
        load_command_inspector=lambda _path, _target: load_inspection,
        symbol_inspector=lambda _path, _target: symbols,
    )


@pytest.mark.parametrize(
    "target_triple",
    ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"],
)
def test_authorizes_exact_root_only_system_runtime(
    tmp_path: Path, target_triple: str
) -> None:
    case = _case(tmp_path, target_triple=target_triple)

    result = _authorize(case)

    assert result.status == RUNTIME_AUTHORIZED
    assert result.reason == REASON_AUTHORIZED
    assert result.authorized is True
    assert result.receipt is not None
    assert result.receipt.target_triple == target_triple
    assert result.receipt.verification_mode == RUNTIME_VERIFICATION_INJECTED_TEST_ONLY
    assert verify_native_runtime_authorization(result.receipt) is False
    assert len(result.receipt.digest) == 64
    assert result.receipt.to_dict()["scope"] == FULL_C6_SCOPE
    assert result.receipt.to_dict()["distribution_authorized"] is False
    assert result.distribution_authorized is False
    assert result.receipt.newly_loaded_images == tuple(
        image for image in case.after.images if image not in case.platform_base.images
    )


def test_unsupported_profile_returns_fixed_result_without_touching_inputs() -> None:
    def fail() -> None:
        raise AssertionError("unsupported target must not invoke callbacks")

    result = authorize_native_runtime(
        target_triple="x86_64-pc-windows-msvc",
        expected_python_root=cast(Any, None),
        extension_path=cast(Any, None),
        runtime_inventory=cast(Any, None),
        path_resolution=cast(Any, None),
        transitive_closure=cast(Any, None),
        platform_base=cast(Any, None),
        declared_system_images=cast(Any, None),
        import_action=fail,
    )

    assert result.status == RUNTIME_OUT_OF_SCOPE
    assert result.reason == REASON_OUT_OF_SCOPE
    assert result.receipt is None


def test_rejects_additional_packaged_runtime_node(tmp_path: Path) -> None:
    case = _case(tmp_path, packaged_dependency=True)

    result = _authorize(case)

    assert result.status == RUNTIME_DENIED
    assert result.reason == REASON_STATIC_INVALID


def test_macos_shared_cache_names_are_bound_separately_from_regular_files(
    tmp_path: Path,
) -> None:
    regular = tmp_path / "python-runtime"
    regular.write_bytes(b"python")
    platform_path = "/usr/lib/libSystem.B.dylib"

    snapshot = _capture_native_runtime_snapshot(
        (regular, platform_path),
        allow_darwin_platform_images=True,
    )

    assert tuple(image.path for image in snapshot.images) == (str(regular),)
    assert snapshot.platform_images == (platform_path,)


def test_authorizes_declared_macos_shared_cache_leaf(tmp_path: Path) -> None:
    case = _case(tmp_path)
    platform_path = "/usr/lib/libSystem.B.dylib"
    extension_image = capture_runtime_loaded_image(case.extension)
    base = RuntimeImageSnapshot(
        images=case.platform_base.images,
        platform_images=(platform_path,),
    )
    after = RuntimeImageSnapshot(
        images=tuple(
            sorted((*base.images, extension_image), key=lambda image: image.path)
        ),
        platform_images=(platform_path,),
    )
    case = replace(
        case,
        platform_base=base,
        declared_system_images=(),
        after=after,
    )

    result = _authorize(case, system_platform_images=(platform_path,))

    assert result.status == RUNTIME_AUTHORIZED
    assert result.receipt is not None
    assert result.receipt.declared_system_platform_images == (platform_path,)
    assert result.receipt.newly_loaded_platform_images == ()


def test_rejects_cross_model_subject_disagreement(tmp_path: Path) -> None:
    case = _case(tmp_path)
    inventory = case.runtime_inventory
    forged = NativeRuntimeInventory(
        format=inventory.format,
        architecture=inventory.architecture,
        inspector=inventory.inspector,
        subject_basename=inventory.subject_basename,
        subject_sha256="a" * 64,
        subject_size=inventory.subject_size,
        wheel_member=inventory.wheel_member,
        wheel_member_sha256="a" * 64,
        wheel_member_size=inventory.wheel_member_size,
        dependencies=inventory.dependencies,
    )
    mutated = replace(case, runtime_inventory=forged)

    result = _authorize(mutated)

    assert result.reason == REASON_STATIC_INVALID


def test_rejects_fresh_direct_dependency_disagreement(tmp_path: Path) -> None:
    case = _case(tmp_path)

    result = _authorize(case, inspected_dependencies=("libUnexpected.dylib",))

    assert result.reason == REASON_LOAD_CONSTRUCT


@pytest.mark.parametrize(
    "commands",
    [
        ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB"),
        ("LC_LOAD_DYLIB", "LC_REEXPORT_DYLIB"),
        ("LC_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB"),
        ("LC_LOAD_DYLIB", "LC_LAZY_LOAD_DYLIB"),
        ("LC_LOAD_DYLIB", "LC_RPATH"),
    ],
)
def test_rejects_macho_alternate_or_search_loader_constructs(
    tmp_path: Path, commands: tuple[str, ...]
) -> None:
    result = _authorize(_case(tmp_path), commands=commands)

    assert result.reason == REASON_LOAD_CONSTRUCT


@pytest.mark.parametrize("tag", ["AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY", "RPATH", "RUNPATH"])
def test_rejects_elf_alternate_or_search_loader_constructs(
    tmp_path: Path, tag: str
) -> None:
    case = _case(tmp_path, target_triple="x86_64-unknown-linux-gnu")

    result = _authorize(case, commands=("NEEDED", tag))

    assert result.reason == REASON_LOAD_CONSTRUCT


@pytest.mark.parametrize(
    "symbol",
    ["_dlopen", "dlmopen@@GLIBC_2.34", "__dlsym", "__libc_dlvsym_private"],
)
def test_rejects_dynamic_loader_symbol_family(tmp_path: Path, symbol: str) -> None:
    result = _authorize(_case(tmp_path), symbols=(symbol,))

    assert result.reason == REASON_IMPORTED_SYMBOL


@pytest.mark.parametrize(
    "symbol",
    [
        "dlsym@GLIBC_2.2.5 (2)",
        "__dlopen@@GLIBC_2.34 (17)",
        "__libc_dlvsym_private@GLIBC_PRIVATE (65535)",
    ],
)
def test_rejects_versioned_dynamic_loader_symbol_with_index(
    tmp_path: Path, symbol: str
) -> None:
    result = _authorize(_case(tmp_path), symbols=(symbol,))

    assert result.reason == REASON_IMPORTED_SYMBOL


def test_elf_import_parser_preserves_symbol_version_and_index() -> None:
    output = """
Symbol table '.dynsym' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND PyLong_FromLong
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT    7 local_definition
"""

    records = runtime_authorization_module._parse_elf_imported_symbols(output)

    assert tuple(record.symbol for record in records) == (
        "PyLong_FromLong",
        "memcpy@GLIBC_2.14",
    )
    assert tuple(record.version_index for record in records) == (None, 2)
    assert tuple(record.canonical_token for record in records) == (
        "PyLong_FromLong",
        "memcpy@GLIBC_2.14 (2)",
    )


@pytest.mark.parametrize(
    "blank_row",
    [
        "1: 0000000000000000 0 NOTYPE LOCAL DEFAULT UND",
        "0: 0000000000000001 0 NOTYPE LOCAL DEFAULT UND",
        "0: 0000000000000000 1 NOTYPE LOCAL DEFAULT UND",
        "0: 0000000000000000 0 FUNC LOCAL DEFAULT UND",
        "0: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND",
        "0: 0000000000000000 0 NOTYPE LOCAL HIDDEN UND",
    ],
)
def test_elf_import_parser_rejects_noncanonical_blank_numbered_rows(
    blank_row: str,
) -> None:
    with pytest.raises(RuntimeAuthorizationError):
        runtime_authorization_module._parse_elf_imported_symbols(blank_row)


def test_linux_symbol_inspection_keeps_gnu_version_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = tmp_path / "native.so"
    extension.write_bytes(b"native")
    output = (
        "  4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND "
        "memcpy@GLIBC_2.14 (2)\n"
    )
    monkeypatch.setattr(
        runtime_authorization_module,
        "_run_inspector",
        lambda command: output
        if command == ("/usr/bin/readelf", "-Ws", str(extension))
        else "",
    )

    assert runtime_authorization_module._inspect_imported_symbols(
        extension, "x86_64-unknown-linux-gnu"
    ) == ("memcpy@GLIBC_2.14 (2)",)


@pytest.mark.parametrize(
    "raw_name",
    [
        "memcpy (2)",
        "memcpy@GLIBC_2.14 (0)",
        "memcpy@GLIBC_2.14 (02)",
        "memcpy@GLIBC_2.14 (65536)",
        "memcpy@GLIBC_2.14 (two)",
        "memcpy@GLIBC_2.14 (2) trailing",
        "memcpy@GLIBC_2.14@OTHER (2)",
    ],
)
def test_elf_import_parser_rejects_noncanonical_version_records(
    raw_name: str,
) -> None:
    output = (
        "  4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND "
        f"{raw_name}\n"
    )

    with pytest.raises(RuntimeAuthorizationError):
        runtime_authorization_module._parse_elf_imported_symbols(output)


def test_rejects_platform_base_mismatch(tmp_path: Path) -> None:
    case = _case(tmp_path)
    empty = RuntimeImageSnapshot(images=())

    result = _authorize(case, snapshots=(empty, case.after))

    assert result.reason == REASON_PLATFORM_BASE


def test_rejects_undeclared_new_regular_image(tmp_path: Path) -> None:
    case = _case(tmp_path)
    reference = case.after.images[0]
    extra = RuntimeLoadedImage(
        path=str(tmp_path / "libextra.dylib"),
        device=reference.device,
        inode=max(image.inode for image in case.after.images) + 10_000,
        sha256="c" * 64,
        size=10,
    )
    after = RuntimeImageSnapshot(
        images=tuple(sorted((*case.after.images, extra), key=lambda image: image.path))
    )

    result = _authorize(case, snapshots=(case.platform_base, after))

    assert result.reason == REASON_LOAD_SET


def test_rejects_probe_exception_without_leaking_it(tmp_path: Path) -> None:
    case = _case(tmp_path)

    def fail_import() -> None:
        raise RuntimeError("private loader failure")

    result = _authorize(case, import_action=fail_import)

    assert result.reason == REASON_PROBE_FAILED
    assert "private" not in str(result.to_dict())


def test_secure_capture_rejects_symlink_and_nonregular_image(tmp_path: Path) -> None:
    target = tmp_path / "target.so"
    target.write_bytes(b"target")
    alias = tmp_path / "alias.so"
    alias.symlink_to(target)

    with pytest.raises(RuntimeAuthorizationError):
        capture_runtime_loaded_image(alias)
    with pytest.raises(RuntimeAuthorizationError):
        capture_runtime_loaded_image(tmp_path)


def test_snapshot_model_rejects_duplicate_inode_aliases(tmp_path: Path) -> None:
    first = tmp_path / "first.so"
    second = tmp_path / "second.so"
    first.write_bytes(b"same-inode")
    identity = capture_runtime_loaded_image(first)
    alias_identity = RuntimeLoadedImage(
        path=str(second),
        device=identity.device,
        inode=identity.inode,
        sha256=identity.sha256,
        size=identity.size,
    )

    with pytest.raises(ValueError, match="inode aliases"):
        RuntimeImageSnapshot(images=tuple(sorted((identity, alias_identity), key=lambda x: x.path)))


def test_result_models_do_not_promote_denial_to_authorization(tmp_path: Path) -> None:
    case = _case(tmp_path)
    result = _authorize(case, symbols=("dlsym",))

    assert result.status == RUNTIME_DENIED
    assert result.receipt is None
    assert result.to_dict()["authorized"] is False


def test_production_entry_point_does_not_accept_injected_inspectors() -> None:
    with pytest.raises(TypeError, match="snapshot_collector"):
        authorize_native_runtime(
            target_triple="x86_64-unknown-linux-gnu",
            expected_python_root=cast(Any, None),
            extension_path=cast(Any, None),
            runtime_inventory=cast(Any, None),
            path_resolution=cast(Any, None),
            transitive_closure=cast(Any, None),
            platform_base=cast(Any, None),
            declared_system_images=cast(Any, None),
            import_action=lambda: None,
            **{"snapshot_collector": lambda: None},
        )


def test_native_entry_point_rejects_loader_affecting_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = (
        "aarch64-apple-darwin"
        if sys.platform == "darwin"
        else "x86_64-unknown-linux-gnu"
    )
    environment_name = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_PRELOAD"
    monkeypatch.setenv(environment_name, "")

    result = authorize_native_runtime(
        target_triple=target,
        expected_python_root=cast(Any, None),
        extension_path=cast(Any, None),
        runtime_inventory=cast(Any, None),
        path_resolution=cast(Any, None),
        transitive_closure=cast(Any, None),
        platform_base=cast(Any, None),
        declared_system_images=cast(Any, None),
        import_action=lambda: None,
    )

    assert result.status == RUNTIME_DENIED
    assert result.reason == REASON_STATIC_INVALID
