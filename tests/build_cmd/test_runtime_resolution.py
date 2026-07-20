"""Focused C6.8 one-hop native path-resolution tests."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from rextio.artifacts.evidence import (
    ArtifactEvidenceError,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    WheelEntryRef,
    hash_regular_file,
)
from rextio.build import runtime_resolution
from rextio.build.runtime_inventory import _PrivateBinarySnapshot


def _entry(path: Path, *, root: Path) -> WheelEntryRef:
    digest, size = hash_regular_file(path)
    return WheelEntryRef(
        name=path.relative_to(root).as_posix(),
        sha256=digest,
        compressed_size=size,
        uncompressed_size=size,
    )


def _layout(
    tmp_path: Path,
    *,
    dependency: NativeRuntimeDependency,
    candidate: str | None,
    format: str,
) -> tuple[Path, str, NativeRuntimeInventory, tuple[WheelEntryRef, ...]]:
    root = tmp_path / "python"
    package = root / "pkg"
    package.mkdir(parents=True)
    suffix = ".dylib" if format == "mach-o" else ".so"
    subject = package / f"_rextio_native{suffix}"
    subject.write_bytes(b"subject")
    entries = [_entry(subject, root=root)]
    if candidate is not None:
        candidate_path = root / candidate
        candidate_path.parent.mkdir(parents=True, exist_ok=True)
        candidate_path.write_bytes(b"candidate")
        entries.append(_entry(candidate_path, root=root))
    subject_entry = entries[0]
    inventory = NativeRuntimeInventory(
        format=format,
        architecture="aarch64" if format == "mach-o" else "x86_64",
        inspector="otool" if format == "mach-o" else "readelf",
        subject_basename=subject.name,
        subject_sha256=subject_entry.sha256,
        subject_size=subject_entry.uncompressed_size,
        wheel_member=subject_entry.name,
        wheel_member_sha256=subject_entry.sha256,
        wheel_member_size=subject_entry.uncompressed_size,
        dependencies=(dependency,),
    )
    return root, subject_entry.name, inventory, tuple(entries)


def _macho_output(*, dependency: str, rpaths: tuple[str, ...] = ()) -> str:
    blocks = [
        "Load command 0\n"
        "          cmd LC_LOAD_DYLIB\n"
        "      cmdsize 56\n"
        f"         name {dependency} (offset 24)\n"
    ]
    for index, rpath in enumerate(rpaths, start=1):
        blocks.append(
            f"Load command {index}\n"
            "          cmd LC_RPATH\n"
            "      cmdsize 40\n"
            f"         path {rpath} (offset 12)\n"
        )
    return "/private/snapshot/_rextio_native.dylib:\n" + "".join(blocks)


@pytest.mark.parametrize(
    ("dependency_path", "candidate", "mechanism"),
    [
        ("@loader_path/libfoo.dylib", "pkg/libfoo.dylib", "macho-loader-path"),
        ("@rpath/libfoo.dylib", "pkg/lib/libfoo.dylib", "macho-rpath"),
    ],
)
def test_macho_loader_and_self_rpath_bind_exact_wheel_member(
    tmp_path: Path,
    dependency_path: str,
    candidate: str,
    mechanism: str,
) -> None:
    dependency = NativeRuntimeDependency(name="libfoo.dylib", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate=candidate,
        format="mach-o",
    )
    rpaths = ("@loader_path/lib",) if dependency_path.startswith("@rpath/") else ()
    plan = runtime_resolution.parse_macho_load_commands(
        _macho_output(dependency=dependency_path, rpaths=rpaths)
    )

    records, receipts = runtime_resolution._resolve_macho_records(
        plan=plan,
        runtime_inventory=inventory,
        root=root,
        subject_member=subject_member,
        wheel_entries=entries,
    )

    assert len(receipts) == 1
    assert records[0].to_dict() == {
        "dependency_bom_ref": dependency.bom_ref(),
        "dependency_name": dependency.name,
        "dependency_origin": "wheel-candidate",
        "resolution": "wheel-member",
        "mechanism": mechanism,
        "wheel_member": candidate,
        "sha256": entries[1].sha256,
        "size": entries[1].uncompressed_size,
    }


@pytest.mark.parametrize(
    "dependency",
    [
        "@loader_path/../libfoo.dylib",
        "@executable_path/libfoo.dylib",
        "/private/libfoo.dylib",
    ],
)
def test_macho_rejects_traversal_executable_and_private_forms(dependency: str) -> None:
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_macho_load_commands(_macho_output(dependency=dependency))


@pytest.mark.parametrize(
    "dependency",
    [
        "/usr/lib/../../tmp/libevil.dylib",
        "/usr/lib//libevil.dylib",
        "/usr/lib/./libevil.dylib",
        "/System/Library/../tmp/libevil.dylib",
    ],
)
def test_macho_rejects_noncanonical_system_dependency_paths(dependency: str) -> None:
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_macho_load_commands(_macho_output(dependency=dependency))


@pytest.mark.parametrize(
    "dependency",
    [
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    ],
)
def test_macho_accepts_canonical_system_dependency_paths(dependency: str) -> None:
    plan = runtime_resolution.parse_macho_load_commands(
        _macho_output(dependency=dependency)
    )

    assert plan.dependencies == (dependency,)


@pytest.mark.parametrize(
    "command",
    ["LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB"],
)
def test_macho_rejects_alternate_dependency_load_commands(command: str) -> None:
    output = (
        "/private/snapshot/native.dylib:\n"
        "Load command 0\n"
        f"          cmd {command}\n"
        "      cmdsize 56\n"
        "         name @loader_path/libfoo.dylib (offset 24)\n"
    )
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_macho_load_commands(output)


def test_macho_rpath_missing_ambiguous_symlink_and_hash_mismatch_fail_closed(
    tmp_path: Path,
) -> None:
    dependency = NativeRuntimeDependency(name="libfoo.dylib", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/a/libfoo.dylib",
        format="mach-o",
    )
    plan = runtime_resolution.parse_macho_load_commands(
        _macho_output(
            dependency="@rpath/libfoo.dylib",
            rpaths=("@loader_path/a", "@loader_path/b"),
        )
    )
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_macho_records(
            plan=replace(plan, run_paths=("@loader_path/missing",)),
            runtime_inventory=inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )

    second = root / "pkg/b/libfoo.dylib"
    second.parent.mkdir(parents=True)
    second.write_bytes(b"candidate-two")
    ambiguous_entries = (*entries, _entry(second, root=root))
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_macho_records(
            plan=plan,
            runtime_inventory=inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=ambiguous_entries,
        )

    first = root / "pkg/a/libfoo.dylib"
    first.unlink()
    first.symlink_to(second)
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_macho_records(
            plan=replace(plan, run_paths=("@loader_path/a",)),
            runtime_inventory=inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )

    first.unlink()
    first.write_bytes(b"mutated")
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_macho_records(
            plan=replace(plan, run_paths=("@loader_path/a",)),
            runtime_inventory=inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )


def test_macho_rpath_existing_unbound_candidate_prevents_later_match(
    tmp_path: Path,
) -> None:
    dependency = NativeRuntimeDependency(name="libfoo.dylib", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/b/libfoo.dylib",
        format="mach-o",
    )
    unbound = root / "pkg/a/libfoo.dylib"
    unbound.parent.mkdir(parents=True)
    unbound.write_bytes(b"installed-but-not-in-wheel-inventory")
    plan = runtime_resolution.parse_macho_load_commands(
        _macho_output(
            dependency="@rpath/libfoo.dylib",
            rpaths=("@loader_path/a", "@loader_path/b"),
        )
    )

    with pytest.raises(ArtifactEvidenceError, match="wheel inventory binding"):
        runtime_resolution._resolve_macho_records(
            plan=plan,
            runtime_inventory=inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )


def _elf_output(*, tag: str = "RUNPATH", path: str = "$ORIGIN/lib") -> str:
    return (
        "Dynamic section at offset 0x1000 contains 3 entries:\n"
        "  Tag        Type                         Name/Value\n"
        " 0x0000000000000001 (NEEDED) Shared library: [libfoo.so]\n"
        f" 0x000000000000001d ({tag}) Library {tag.lower()}: [{path}]\n"
        " 0x0000000000000000 (NULL) 0x0\n"
    )


@pytest.mark.parametrize("tag", ["RUNPATH", "RPATH"])
def test_elf_origin_runpath_and_rpath_bind_exact_wheel_member(
    tmp_path: Path,
    tag: str,
) -> None:
    dependency = NativeRuntimeDependency(name="libfoo.so", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/lib/libfoo.so",
        format="elf",
    )
    plan = runtime_resolution.parse_elf_load_plan(_elf_output(tag=tag))

    records, receipts = runtime_resolution._resolve_elf_records(
        plan=plan,
        runtime_inventory=inventory,
        target_triple="x86_64-unknown-linux-gnu",
        root=root,
        subject_member=subject_member,
        wheel_entries=entries,
    )

    assert plan.path_tag == tag
    assert len(receipts) == 1
    assert records[0].mechanism == "elf-origin-rpath"
    assert records[0].wheel_member == "pkg/lib/libfoo.so"


@pytest.mark.parametrize(
    "path",
    ["/private/lib", "$LIB/lib", "$ORIGIN/../lib", "$ORIGIN::${ORIGIN}/lib"],
)
def test_elf_rejects_absolute_other_variable_escape_and_empty_segments(path: str) -> None:
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_elf_load_plan(_elf_output(path=path))


def test_elf_rejects_conflicting_search_tags_and_alternate_loader_tags() -> None:
    conflict = _elf_output() + (
        " 0x000000000000000f (RPATH) Library rpath: [$ORIGIN/other]\n"
    )
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_elf_load_plan(conflict)
    alternate = _elf_output() + " 0x000000006ffffefc (AUDIT) Audit library: [evil.so]\n"
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution.parse_elf_load_plan(alternate)


def test_elf_missing_symlink_and_hash_mismatch_fail_closed(tmp_path: Path) -> None:
    dependency = NativeRuntimeDependency(name="libfoo.so", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/lib/libfoo.so",
        format="elf",
    )
    plan = runtime_resolution.parse_elf_load_plan(_elf_output())
    candidate = root / "pkg/lib/libfoo.so"
    candidate.unlink()
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_elf_records(
            plan=plan,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )

    target = root / "pkg/target.so"
    target.write_bytes(b"candidate")
    candidate.symlink_to(target)
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_elf_records(
            plan=plan,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )

    candidate.unlink()
    candidate.write_bytes(b"different")
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._resolve_elf_records(
            plan=plan,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            root=root,
            subject_member=subject_member,
            wheel_entries=entries,
        )


def test_elf_current_system_only_dependency_is_a_logical_leaf(tmp_path: Path) -> None:
    dependency = NativeRuntimeDependency(name="libc.so.6", origin="unresolved")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate=None,
        format="elf",
    )
    plan = runtime_resolution.parse_elf_load_plan(
        "Dynamic section at offset 0x1000 contains 2 entries:\n"
        " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
        " 0x0000000000000000 (NULL) 0x0\n"
    )
    records, receipts = runtime_resolution._resolve_elf_records(
        plan=plan,
        runtime_inventory=inventory,
        target_triple="x86_64-unknown-linux-gnu",
        root=root,
        subject_member=subject_member,
        wheel_entries=entries,
    )
    assert receipts == ()
    assert records[0].resolution == "system-logical"
    assert records[0].mechanism == "elf-system-name"


def test_resolution_inventory_rejects_bool_schema_and_duplicate_wheel_binding() -> None:
    dependency_a = NativeRuntimeDependency(name="liba.so", origin="wheel-candidate")
    dependency_b = NativeRuntimeDependency(name="libb.so", origin="wheel-candidate")
    records = tuple(
        NativeRuntimePathResolutionRecord(
            dependency_bom_ref=dependency.bom_ref(),
            dependency_name=dependency.name,
            dependency_origin=dependency.origin,
            resolution="wheel-member",
            mechanism="elf-origin-rpath",
            wheel_member="pkg/libshared.so",
            sha256="a" * 64,
            size=1,
        )
        for dependency in sorted((dependency_a, dependency_b), key=lambda item: item.bom_ref())
    )
    with pytest.raises(ValueError, match="schema"):
        NativeRuntimePathResolutionInventory(
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256="b" * 64,
            records=(),
            schema_version=True,
        )
    with pytest.raises(ValueError, match="wheel bindings"):
        NativeRuntimePathResolutionInventory(
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256="b" * 64,
            records=records,
        )
    for invalid_subject in ("../_rextio_native.so", "pkg/"):
        with pytest.raises(ValueError):
            NativeRuntimePathResolutionInventory(
                subject_wheel_member=invalid_subject,
                subject_sha256="b" * 64,
                records=(),
            )


def test_candidate_receipt_detects_leaf_mutation_and_restore_metadata(tmp_path: Path) -> None:
    root = tmp_path / "python"
    candidate = root / "pkg/lib.so"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"original")
    receipt = runtime_resolution._read_candidate_secure(
        root=root,
        parts=("pkg", "lib.so"),
    )
    record = NativeRuntimePathResolutionInventory(
        subject_wheel_member="pkg/_rextio_native.so",
        subject_sha256="c" * 64,
        records=(),
    )
    observation = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=record,
        receipts=(receipt,),
    )
    candidate.write_bytes(b"mutated")
    candidate.write_bytes(b"original")
    assert not runtime_resolution.verify_native_runtime_path_resolution(
        observation,
        expected_python_root=root,
    )


def test_candidate_receipt_detects_parent_swap_and_restore(tmp_path: Path) -> None:
    root = tmp_path / "python"
    candidate = root / "pkg/lib.so"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"original")
    receipt = runtime_resolution._read_candidate_secure(
        root=root,
        parts=("pkg", "lib.so"),
    )
    observation = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=NativeRuntimePathResolutionInventory(
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256="d" * 64,
            records=(),
        ),
        receipts=(receipt,),
    )
    held = root / "held"
    candidate.parent.rename(held)
    held.rename(root / "pkg")
    assert not runtime_resolution.verify_native_runtime_path_resolution(
        observation,
        expected_python_root=root,
    )


def test_refresh_rebuilds_receipts_after_private_snapshot_lifecycle(
    tmp_path: Path,
) -> None:
    dependency = NativeRuntimeDependency(name="libchild.so", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/libchild.so",
        format="elf",
    )
    child = root / "pkg/libchild.so"
    child_entry = next(entry for entry in entries if entry.name == "pkg/libchild.so")
    path_inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=subject_member,
        subject_sha256=inventory.subject_sha256,
        records=(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=dependency.bom_ref(),
                dependency_name=dependency.name,
                dependency_origin=dependency.origin,
                resolution="wheel-member",
                mechanism="elf-origin-rpath",
                wheel_member=child_entry.name,
                sha256=child_entry.sha256,
                size=child_entry.uncompressed_size,
            ),
        ),
    )
    seed = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(
            runtime_resolution._read_candidate_secure(
                root=root,
                parts=("pkg", "libchild.so"),
            ),
        ),
    )
    before = runtime_resolution.refresh_native_runtime_path_resolution_observation(
        seed,
        expected_python_root=root,
    )
    assert before is not None
    assert runtime_resolution.verify_native_runtime_path_resolution(
        before,
        expected_python_root=root,
    )

    with runtime_resolution._private_binary_snapshot(child, expected_root=root):
        pass

    assert not runtime_resolution.verify_native_runtime_path_resolution(
        before,
        expected_python_root=root,
    )
    refreshed = runtime_resolution.refresh_native_runtime_path_resolution_observation(
        before,
        expected_python_root=root,
    )
    assert refreshed is not None
    assert refreshed.inventory == path_inventory
    assert runtime_resolution.verify_native_runtime_path_resolution(
        refreshed,
        expected_python_root=root,
    )


def test_refresh_requires_prior_coverage_and_rejects_non_root_changes(
    tmp_path: Path,
) -> None:
    dependency = NativeRuntimeDependency(name="libchild.so", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/libchild.so",
        format="elf",
    )
    child_entry = next(entry for entry in entries if entry.name == "pkg/libchild.so")
    path_inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=subject_member,
        subject_sha256=inventory.subject_sha256,
        records=(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=dependency.bom_ref(),
                dependency_name=dependency.name,
                dependency_origin=dependency.origin,
                resolution="wheel-member",
                mechanism="elf-origin-rpath",
                wheel_member=child_entry.name,
                sha256=child_entry.sha256,
                size=child_entry.uncompressed_size,
            ),
        ),
    )
    missing = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(),
    )
    assert (
        runtime_resolution.refresh_native_runtime_path_resolution_observation(
            missing,
            expected_python_root=root,
        )
        is None
    )

    child = root / "pkg/libchild.so"
    receipt = runtime_resolution._read_candidate_secure(
        root=root,
        parts=("pkg", "libchild.so"),
    )
    observed = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(receipt,),
    )
    unrelated = root / "pkg/unrelated.tmp"
    unrelated.write_bytes(b"temporary")
    unrelated.unlink()
    assert (
        runtime_resolution.refresh_native_runtime_path_resolution_observation(
            observed,
            expected_python_root=root,
        )
        is None
    )

    receipt = runtime_resolution._read_candidate_secure(
        root=root,
        parts=("pkg", "libchild.so"),
    )
    observed = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(receipt,),
    )
    original = child.read_bytes()
    child.write_bytes(b"changed")
    child.write_bytes(original)
    assert (
        runtime_resolution.refresh_native_runtime_path_resolution_observation(
            observed,
            expected_python_root=root,
        )
        is None
    )


def test_path_resolution_entrypoints_reject_symlink_generated_root(
    tmp_path: Path,
) -> None:
    dependency = NativeRuntimeDependency(name="libchild.so", origin="wheel-candidate")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate="pkg/libchild.so",
        format="elf",
    )
    path_inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=subject_member,
        subject_sha256=inventory.subject_sha256,
        records=(),
    )
    empty = runtime_resolution.NativeRuntimePathResolutionObservation(
        inventory=path_inventory,
        receipts=(),
    )
    refreshed = runtime_resolution.refresh_native_runtime_path_resolution_observation(
        empty,
        expected_python_root=root,
    )
    assert refreshed is not None and refreshed.receipts == ()

    linked_root = tmp_path / "linked-python"
    linked_root.symlink_to(root, target_is_directory=True)
    assert not runtime_resolution.verify_native_runtime_path_resolution(
        empty,
        expected_python_root=linked_root,
    )
    assert (
        runtime_resolution.refresh_native_runtime_path_resolution_observation(
            empty,
            expected_python_root=linked_root,
        )
        is None
    )
    assert (
        runtime_resolution.collect_native_runtime_path_resolution(
            installed_path=linked_root / subject_member,
            expected_python_root=linked_root,
            wheel_entries=entries,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=1.0,
        )
        is None
    )


def test_collection_rejects_subject_snapshot_digest_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependency = NativeRuntimeDependency(name="libc.so.6", origin="unresolved")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate=None,
        format="elf",
    )
    subject = root / subject_member

    @contextmanager
    def mismatched_snapshot(*_args, **_kwargs):
        yield _PrivateBinarySnapshot(
            path=subject,
            sha256="0" * 64,
            size=inventory.subject_size,
        )

    monkeypatch.setattr(runtime_resolution, "_private_binary_snapshot", mismatched_snapshot)
    with pytest.raises(ArtifactEvidenceError, match="snapshot binding"):
        runtime_resolution._collect_native_runtime_path_resolution(
            installed_path=subject,
            expected_python_root=root,
            wheel_entries=entries,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=1.0,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wheel_member", "other/_rextio_native.so"),
        ("subject_basename", "different.so"),
    ],
)
def test_collection_rejects_low_level_subject_path_identity_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    dependency = NativeRuntimeDependency(name="libc.so.6", origin="unresolved")
    root, subject_member, inventory, entries = _layout(
        tmp_path,
        dependency=dependency,
        candidate=None,
        format="elf",
    )
    object.__setattr__(inventory, field, value)

    with pytest.raises(ArtifactEvidenceError, match="subject path binding"):
        runtime_resolution._collect_native_runtime_path_resolution(
            installed_path=root / subject_member,
            expected_python_root=root,
            wheel_entries=entries,
            runtime_inventory=inventory,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=1.0,
        )


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires O_NOFOLLOW")
def test_candidate_parent_symlink_is_never_followed(tmp_path: Path) -> None:
    root = tmp_path / "python"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lib.so").write_bytes(b"outside")
    root.mkdir()
    (root / "pkg").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ArtifactEvidenceError):
        runtime_resolution._read_candidate_secure(
            root=root,
            parts=("pkg", "lib.so"),
        )
