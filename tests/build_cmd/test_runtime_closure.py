"""Focused C6.9 bounded transitive native-runtime graph tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from rextio.artifacts import evidence as evidence_mod
from rextio.artifacts.evidence import (
    MAX_RUNTIME_CLOSURE_DEPTH,
    ArtifactEvidenceError,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    NativeRuntimeTransitiveClosureEdge,
    NativeRuntimeTransitiveClosureInventory,
    NativeRuntimeTransitiveClosureNode,
    WheelEntryRef,
)
from rextio.build import runtime_closure


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wheel_entry(name: str, data: bytes) -> WheelEntryRef:
    return WheelEntryRef(
        name=name,
        sha256=_digest(data),
        compressed_size=len(data),
        uncompressed_size=len(data),
    )


def _wheel_index(
    entries: tuple[WheelEntryRef, ...],
) -> runtime_closure._WheelEntryIndex:
    return runtime_closure._build_wheel_entry_index(
        entries,
        deadline=runtime_closure.time.monotonic() + 5.0,
    )


def _packaged_node(name: str, data: bytes) -> NativeRuntimeTransitiveClosureNode:
    return NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format="elf",
        name=Path(name).name,
        wheel_member=name,
        sha256=_digest(data),
        size=len(data),
    )


def _graph_fixture(tmp_path: Path):
    root_data = b"root-elf"
    a_data = b"library-a"
    b_data = b"library-b"
    members = {
        "pkg/_rextio_native.so": root_data,
        "pkg/liba.so": a_data,
        "pkg/libb.so": b_data,
    }
    for name, data in members.items():
        path = tmp_path.joinpath(*Path(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    entries = tuple(_wheel_entry(name, data) for name, data in sorted(members.items()))
    dependency = NativeRuntimeDependency(name="liba.so", origin="wheel-candidate")
    inventory = NativeRuntimeInventory(
        format="elf",
        architecture="x86_64",
        inspector="readelf",
        subject_basename="_rextio_native.so",
        subject_sha256=_digest(root_data),
        subject_size=len(root_data),
        wheel_member="pkg/_rextio_native.so",
        wheel_member_sha256=_digest(root_data),
        wheel_member_size=len(root_data),
        dependencies=(dependency,),
    )
    resolution = NativeRuntimePathResolutionInventory(
        subject_wheel_member="pkg/_rextio_native.so",
        subject_sha256=_digest(root_data),
        records=(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=dependency.bom_ref(),
                dependency_name="liba.so",
                dependency_origin="wheel-candidate",
                resolution="wheel-member",
                mechanism="elf-origin-rpath",
                wheel_member="pkg/liba.so",
                sha256=_digest(a_data),
                size=len(a_data),
            ),
        ),
    )
    return members, entries, inventory, resolution


def _cycle_inspector(members: dict[str, bytes]):
    a = _packaged_node("pkg/liba.so", members["pkg/liba.so"])
    b = _packaged_node("pkg/libb.so", members["pkg/libb.so"])
    system = NativeRuntimeTransitiveClosureNode(
        kind="system-logical",
        format="elf",
        name="libc.so.6",
    )

    def inspect(*, node: NativeRuntimeTransitiveClosureNode, **_kwargs):
        if node.wheel_member == "pkg/liba.so":
            return ((b, "libb.so", "elf-origin-rpath"),)
        if node.wheel_member == "pkg/libb.so":
            # Preserve the cycle as an edge; liba is not inspected twice.
            return (
                (a, "liba.so", "elf-origin-rpath"),
                (system, "libc.so.6", "elf-system-name"),
            )
        raise AssertionError(f"unexpected node: {node.wheel_member}")

    return inspect


def test_collects_deterministic_cycle_safe_graph_and_verifies_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    members, entries, inventory, resolution = _graph_fixture(tmp_path)
    monkeypatch.setattr(
        runtime_closure,
        "_inspect_packaged_node",
        _cycle_inspector(members),
    )

    first = runtime_closure._collect_native_runtime_transitive_closure(
        installed_path=tmp_path / "pkg" / "_rextio_native.so",
        expected_python_root=tmp_path,
        wheel_entries=entries,
        runtime_inventory=inventory,
        path_resolution=resolution,
        target_triple="x86_64-unknown-linux-gnu",
        timeout=5.0,
    )
    second = runtime_closure._collect_native_runtime_transitive_closure(
        installed_path=tmp_path / "pkg" / "_rextio_native.so",
        expected_python_root=tmp_path,
        wheel_entries=tuple(reversed(entries)),
        runtime_inventory=inventory,
        path_resolution=resolution,
        target_triple="x86_64-unknown-linux-gnu",
        timeout=5.0,
    )

    assert first.inventory.to_dict() == second.inventory.to_dict()
    report = first.inventory.to_dict()
    assert report["node_count"] == 4
    assert report["edge_count"] == 4
    assert report["max_depth_observed"] == 3
    assert report["transitive_closure_complete"] is False
    assert report["actual_loader_selection"] is False
    assert len(first.receipts) == 3
    assert runtime_closure.verify_native_runtime_transitive_closure(
        first,
        expected_python_root=tmp_path,
    )

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(tmp_path, target_is_directory=True)
    assert not runtime_closure.verify_native_runtime_transitive_closure(
        first,
        expected_python_root=linked_root,
    )
    assert (
        runtime_closure.collect_native_runtime_transitive_closure(
            installed_path=linked_root / "pkg" / "_rextio_native.so",
            expected_python_root=linked_root,
            wheel_entries=entries,
            runtime_inventory=inventory,
            path_resolution=resolution,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=5.0,
        )
        is None
    )

    (tmp_path / "pkg" / "libb.so").write_bytes(b"tampered!")
    assert not runtime_closure.verify_native_runtime_transitive_closure(
        first,
        expected_python_root=tmp_path,
    )


def test_public_collector_omits_only_c69_on_malformed_recursive_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _members, entries, inventory, resolution = _graph_fixture(tmp_path)

    def malformed(**_kwargs):
        raise ArtifactEvidenceError(
            "malformed inspector output",
            reason="native-runtime-inventory-malformed",
        )

    monkeypatch.setattr(runtime_closure, "_inspect_packaged_node", malformed)
    assert (
        runtime_closure.collect_native_runtime_transitive_closure(
            installed_path=tmp_path / "pkg" / "_rextio_native.so",
            expected_python_root=tmp_path,
            wheel_entries=entries,
            runtime_inventory=inventory,
            path_resolution=resolution,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=5.0,
        )
        is None
    )


def test_candidate_resolution_rejects_multiple_paths_missing_and_case_aliases(
    tmp_path: Path,
) -> None:
    data = b"candidate"
    path = tmp_path / "pkg" / "libx.so"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    entry = _wheel_entry("pkg/libx.so", data)
    budget = runtime_closure._TraversalBudget()

    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._resolve_exact_candidate(
            candidate_parts=(("pkg", "libx.so"), ("other", "libx.so")),
            format="elf",
            root=tmp_path,
            wheel_index=_wheel_index((entry,)),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=budget,
        )
    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._resolve_exact_candidate(
            candidate_parts=(("pkg", "missing.so"),),
            format="elf",
            root=tmp_path,
            wheel_index=_wheel_index((_wheel_entry("pkg/missing.so", data),)),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )
    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._resolve_exact_candidate(
            candidate_parts=(("pkg", "libx.so"),),
            format="elf",
            root=tmp_path,
            wheel_index=_wheel_index(
                (entry, _wheel_entry("pkg/LIBX.so", data))
            ),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


def test_linux_system_soname_shadowing_is_fail_closed(tmp_path: Path) -> None:
    data = b"shadow"
    path = tmp_path / "pkg" / "libc.so.6"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    plan = runtime_closure.ElfLoadPlan(
        dependencies=("libc.so.6",),
        path_tag="RUNPATH",
        search_paths=((),),
    )
    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._resolve_elf_node_edges(
            plan=plan,
            source_member="pkg/liba.so",
            target_triple="x86_64-unknown-linux-gnu",
            root=tmp_path,
            wheel_index=_wheel_index((_wheel_entry("pkg/libc.so.6", data),)),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


def test_linux_system_soname_dangling_symlink_shadow_is_fail_closed(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "pkg" / "libc.so.6"
    shadow.parent.mkdir(parents=True)
    shadow.symlink_to("missing-libc.so.6")
    plan = runtime_closure.ElfLoadPlan(
        dependencies=("libc.so.6",),
        path_tag="RUNPATH",
        search_paths=((),),
    )

    with pytest.raises(ArtifactEvidenceError, match="shadowed"):
        runtime_closure._resolve_elf_node_edges(
            plan=plan,
            source_member="pkg/liba.so",
            target_triple="x86_64-unknown-linux-gnu",
            root=tmp_path,
            wheel_index=_wheel_index(()),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


def test_recursive_macho_system_path_is_revalidated_after_parser_boundary(
    tmp_path: Path,
) -> None:
    plan = runtime_closure.MachoLoadPlan(
        dependencies=("/usr/lib/../../tmp/libevil.dylib",),
        run_paths=(),
    )

    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._resolve_macho_node_edges(
            plan=plan,
            source_member="pkg/liba.dylib",
            root=tmp_path,
            wheel_index=_wheel_index(()),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


@pytest.mark.parametrize(
    ("observed_architecture", "macho_filetype"),
    (
        ("aarch64", runtime_closure._MH_DYLIB),
        ("x86_64", 0),
    ),
)
def test_recursive_macho_node_requires_expected_architecture_and_dylib_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed_architecture: str,
    macho_filetype: int,
) -> None:
    data = b"packaged-macho"
    member = "pkg/libchild.dylib"
    path = tmp_path.joinpath(*Path(member).parts)
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    node = NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format="mach-o",
        name="libchild.dylib",
        wheel_member=member,
        sha256=_digest(data),
        size=len(data),
    )
    monkeypatch.setattr(
        runtime_closure,
        "_inspect_binary_header",
        lambda *_args, **_kwargs: SimpleNamespace(
            format="mach-o",
            architecture=observed_architecture,
            macho_filetype=macho_filetype,
        ),
    )
    monkeypatch.setattr(
        runtime_closure,
        "_run_resolution_inspector",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid recursive node must fail before inspector execution"
        ),
    )

    with pytest.raises(ArtifactEvidenceError, match="format is inconsistent"):
        runtime_closure._inspect_packaged_node(
            node=node,
            target_triple="x86_64-apple-darwin",
            expected_architecture="x86_64",
            root=tmp_path,
            wheel_index=_wheel_index((_wheel_entry(member, data),)),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


@pytest.mark.parametrize(
    "unexpected_row",
    (
        " this row is not part of readelf's closed grammar\n",
        " 0x0000000000000001 (NEEDED) Shared library: libbad.so\n",
    ),
)
def test_recursive_elf_inspection_requires_strict_complete_dynamic_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unexpected_row: str,
) -> None:
    data = b"packaged-elf"
    member = "pkg/libchild.so"
    path = tmp_path.joinpath(*Path(member).parts)
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    node = _packaged_node(member, data)
    output = (
        "Dynamic section at offset 0x1000 contains 2 entries:\n"
        "  Tag        Type                         Name/Value\n"
        " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
        " 0x0000000000000000 (NULL) 0x0\n"
        + unexpected_row
    )
    # The path-only parser historically ignored these rows. Recursive C6.9
    # must additionally apply C6.4's closed readelf grammar.
    assert runtime_closure.parse_elf_load_plan(output).dependencies == ("libc.so.6",)
    monkeypatch.setattr(
        runtime_closure,
        "_inspect_binary_header",
        lambda *_args, **_kwargs: SimpleNamespace(
            format="elf",
            architecture="x86_64",
            macho_filetype=None,
        ),
    )
    monkeypatch.setattr(
        runtime_closure,
        "_run_resolution_inspector",
        lambda *_args, **_kwargs: output,
    )

    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._inspect_packaged_node(
            node=node,
            target_triple="x86_64-unknown-linux-gnu",
            expected_architecture="x86_64",
            root=tmp_path,
            wheel_index=_wheel_index((_wheel_entry(member, data),)),
            deadline=runtime_closure.time.monotonic() + 5.0,
            budget=runtime_closure._TraversalBudget(),
        )


def test_budget_objects_reject_candidate_inspector_and_output_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime_closure,
        "MAX_RUNTIME_CLOSURE_CANDIDATES_PER_DEPENDENCY",
        1,
    )
    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._TraversalBudget().charge_candidates(2)

    monkeypatch.setattr(runtime_closure, "MAX_RUNTIME_CLOSURE_CANDIDATE_ATTEMPTS", 1)
    budget = runtime_closure._TraversalBudget()
    budget.charge_candidates(1)
    with pytest.raises(ArtifactEvidenceError):
        budget.charge_candidates(1)

    monkeypatch.setattr(runtime_closure, "MAX_RUNTIME_CLOSURE_INSPECTOR_INVOCATIONS", 1)
    budget = runtime_closure._TraversalBudget()
    budget.start_inspector()
    with pytest.raises(ArtifactEvidenceError):
        budget.start_inspector()

    monkeypatch.setattr(runtime_closure, "MAX_RUNTIME_CLOSURE_INSPECTOR_OUTPUT_BYTES", 1)
    with pytest.raises(ArtifactEvidenceError):
        runtime_closure._TraversalBudget().charge_inspector_output("xx")


def test_large_wheel_index_is_case_aware_and_charged_to_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = tuple(
        _wheel_entry(f"pkg/lib{index}.so", str(index).encode())
        for index in range(512)
    )
    index = _wheel_index(entries)
    assert len(index.exact_members) == 512
    assert len(index.casefold_members) == 512
    assert "lib511.so" in index.casefold_basenames

    aliased = _wheel_index(
        (
            _wheel_entry("pkg/libx.so", b"lower"),
            _wheel_entry("pkg/LIBX.so", b"upper"),
        )
    )
    with pytest.raises(ArtifactEvidenceError, match="case-ambiguous"):
        runtime_closure._exact_wheel_entry(
            member="pkg/libx.so",
            wheel_index=aliased,
        )

    normalization_aliased = _wheel_index(
        (
            _wheel_entry("pkg/caf\N{LATIN SMALL LETTER E WITH ACUTE}/libx.so", b"nfc"),
            _wheel_entry("pkg/cafe\N{COMBINING ACUTE ACCENT}/libx.so", b"nfd"),
        )
    )
    with pytest.raises(ArtifactEvidenceError, match="case-ambiguous"):
        runtime_closure._exact_wheel_entry(
            member="pkg/caf\N{LATIN SMALL LETTER E WITH ACUTE}/libx.so",
            wheel_index=normalization_aliased,
        )

    calls = 0

    def bounded_clock() -> float:
        nonlocal calls
        calls += 1
        return 0.0 if calls < 64 else 2.0

    monkeypatch.setattr(runtime_closure.time, "monotonic", bounded_clock)
    with pytest.raises(ArtifactEvidenceError, match="deadline"):
        runtime_closure._build_wheel_entry_index(entries, deadline=1.0)
    assert calls == 64


def test_graph_models_reject_node_edge_depth_and_serialized_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _packaged_node("pkg/_rextio_native.so", b"root")
    system_nodes = tuple(
        NativeRuntimeTransitiveClosureNode(
            kind="system-logical",
            format="elf",
            name=f"lib{index}.so",
        )
        for index in range(2)
    )
    nodes = tuple(sorted((root, *system_nodes), key=lambda node: node.node_ref))
    edges = tuple(
        sorted(
            (
                NativeRuntimeTransitiveClosureEdge(
                    source_ref=root.node_ref,
                    target_ref=node.node_ref,
                    dependency_name=node.name,
                    mechanism="elf-system-name",
                )
                for node in system_nodes
            ),
            key=lambda edge: edge.canonical_key,
        )
    )
    monkeypatch.setattr(evidence_mod, "MAX_RUNTIME_CLOSURE_NODES", 2)
    with pytest.raises(ValueError, match="node count"):
        NativeRuntimeTransitiveClosureInventory(
            format="elf",
            architecture="x86_64",
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256=_digest(b"root"),
            subject_size=4,
            root_node_ref=root.node_ref,
            nodes=nodes,
            edges=edges,
        )
    monkeypatch.setattr(evidence_mod, "MAX_RUNTIME_CLOSURE_NODES", 128)
    monkeypatch.setattr(evidence_mod, "MAX_RUNTIME_CLOSURE_EDGES", 1)
    with pytest.raises(ValueError, match="edge count"):
        NativeRuntimeTransitiveClosureInventory(
            format="elf",
            architecture="x86_64",
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256=_digest(b"root"),
            subject_size=4,
            root_node_ref=root.node_ref,
            nodes=nodes,
            edges=edges,
        )

    chain = [root]
    chain_edges: list[NativeRuntimeTransitiveClosureEdge] = []
    for index in range(MAX_RUNTIME_CLOSURE_DEPTH + 1):
        node = _packaged_node(f"pkg/lib{index}.so", str(index).encode())
        chain_edges.append(
            NativeRuntimeTransitiveClosureEdge(
                source_ref=chain[-1].node_ref,
                target_ref=node.node_ref,
                dependency_name=node.name,
                mechanism="elf-origin-rpath",
            )
        )
        chain.append(node)
    monkeypatch.setattr(evidence_mod, "MAX_RUNTIME_CLOSURE_EDGES", 512)
    with pytest.raises(ValueError, match="depth"):
        NativeRuntimeTransitiveClosureInventory(
            format="elf",
            architecture="x86_64",
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256=_digest(b"root"),
            subject_size=4,
            root_node_ref=root.node_ref,
            nodes=tuple(sorted(chain, key=lambda node: node.node_ref)),
            edges=tuple(sorted(chain_edges, key=lambda edge: edge.canonical_key)),
        )

    monkeypatch.setattr(evidence_mod, "MAX_RUNTIME_CLOSURE_INVENTORY_CHARS", 1)
    with pytest.raises(ValueError, match="inventory exceeds"):
        NativeRuntimeTransitiveClosureInventory(
            format="elf",
            architecture="x86_64",
            subject_wheel_member="pkg/_rextio_native.so",
            subject_sha256=_digest(b"root"),
            subject_size=4,
            root_node_ref=root.node_ref,
            nodes=(root,),
            edges=(),
        )


def test_collector_enforces_one_total_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _members, entries, inventory, resolution = _graph_fixture(tmp_path)
    ticks = iter((0.0, 6.0))
    monkeypatch.setattr(runtime_closure.time, "monotonic", lambda: next(ticks))
    with pytest.raises(ArtifactEvidenceError, match="deadline"):
        runtime_closure._collect_native_runtime_transitive_closure(
            installed_path=tmp_path / "pkg" / "_rextio_native.so",
            expected_python_root=tmp_path,
            wheel_entries=entries,
            runtime_inventory=inventory,
            path_resolution=resolution,
            target_triple="x86_64-unknown-linux-gnu",
            timeout=5.0,
        )
