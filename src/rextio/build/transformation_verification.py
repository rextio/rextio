"""Bounded C6.10 replay verification for one narrow PyO3 source closure.

The first slice is intentionally smaller than C6.6's descriptive inventory:
all source modules must be project-owned, every accepted function must be a
plugin-free module-level direct-native function, and the full accepted set is
reanalyzed, relowered, and regenerated. Any unsupported or inconsistent state
returns ``None`` without perturbing the ordinary build path.
"""

from __future__ import annotations

import ast
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.evidence import (
    MAX_EVIDENCE_FILE_BYTES,
    MAX_SOURCE_TRANSFORMATIONS,
    EvidenceFileRef,
    SourceTransformationInventory,
    SourceTransformationRecord,
    SourceTransformationVerification,
    canonical_json_bytes,
    sha256_hex,
    validate_logical_reference,
)
from rextio.artifacts.models import ArtifactKind
from rextio.codegen.rust.generator import generate_rust_module
from rextio.ir.lowering import lower_project
from rextio.partition.build_plan import BuildPlan
from rextio.source.models import SourceModule, SourceOrigin

if TYPE_CHECKING:
    from rextio.build.supply_chain import EvidenceInputSnapshot

_GENERATOR_BACKEND = "rextio-core-rust-pyo3-v1"
_FunctionIdentity = tuple[str, str, Path, int, int, int, int, str]


@dataclass(frozen=True, slots=True)
class _FilesystemStamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int
    links: int


@dataclass(frozen=True, slots=True)
class _FileReceipt:
    data: bytes
    file_stamp: _FilesystemStamp
    directory_stamps: tuple[_FilesystemStamp, ...]

    @property
    def sha256(self) -> str:
        return sha256_hex(self.data)

    @property
    def size(self) -> int:
        return len(self.data)


def collect_scoped_source_transformation_verification(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
    transformation_inventory: SourceTransformationInventory,
    embedding_enabled: bool,
) -> SourceTransformationVerification | None:
    """Replay one complete plugin-free project-native PyO3 closure, or ``None``."""
    try:
        return _collect_scoped_source_transformation_verification(
            project_root=project_root,
            plan=plan,
            input_snapshot=input_snapshot,
            transformation_inventory=transformation_inventory,
            embedding_enabled=embedding_enabled,
        )
    except Exception:
        return None


def _collect_scoped_source_transformation_verification(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
    transformation_inventory: SourceTransformationInventory,
    embedding_enabled: bool,
) -> SourceTransformationVerification:
    from rextio.build.supply_chain import EvidenceInputSnapshot as SnapshotModel

    if type(plan) is not BuildPlan:
        raise TypeError("source transformation verification plan is invalid")
    if type(input_snapshot) is not SnapshotModel:
        raise TypeError("source transformation verification snapshot is invalid")
    if type(transformation_inventory) is not SourceTransformationInventory:
        raise TypeError("source transformation verification inventory is invalid")
    if type(embedding_enabled) is not bool or embedding_enabled:
        raise ValueError("source transformation verification embedding is out of scope")
    if input_snapshot.unavailable_reason is not None:
        raise ValueError("source transformation verification snapshot is unavailable")

    root = _validated_project_root(project_root)
    analysis_root = Path(os.path.abspath(plan.analysis.project_root))
    if analysis_root != root:
        raise ValueError("source transformation verification project root disagrees")
    _require_pyo3_profile(plan)

    accepted = _accepted_function_map(plan.analysis)
    native_accepted = _accepted_function_map_from_tuple(plan.native.accepted_functions)
    if not accepted or accepted != native_accepted:
        raise ValueError("source transformation verification accepted closure disagrees")
    if (
        plan.native.embedded_functions
        or plan.native.accepted_top_levels
        or plan.analysis.accepted_native_top_levels
        or plan.analysis.embedding_candidates
    ):
        raise ValueError("source transformation verification plan is outside function scope")

    records = _inventory_record_map(transformation_inventory)
    if set(records) != set(accepted):
        raise ValueError("source transformation verification inventory coverage is incomplete")

    graph = plan.host_source_plan.graph
    if graph is None or not plan.host_source_plan.available:
        raise ValueError("source transformation verification source graph is unavailable")
    modules = _project_module_map(graph.modules)
    source_inputs = _project_input_map(input_snapshot.project_inputs)
    if set(source_inputs) != {module.path for module in modules.values()}:
        raise ValueError("source transformation verification source snapshot coverage differs")

    generated_rust = _generated_rust_ref(input_snapshot, transformation_inventory)
    initial_sources = {
        logical_path: _read_contained_file(root=root, logical_path=logical_path)
        for logical_path in sorted(source_inputs)
    }
    for logical_path, receipt in initial_sources.items():
        expected = source_inputs[logical_path]
        module = next(item for item in modules.values() if item.path == logical_path)
        if (
            receipt.sha256 != expected.sha256
            or receipt.size != expected.size
            or receipt.sha256 != module.sha256
        ):
            raise ValueError("source transformation verification source receipt differs")
    initial_generated = _read_contained_file(
        root=root,
        logical_path=generated_rust.logical_path,
    )
    if (
        initial_generated.sha256 != generated_rust.sha256
        or initial_generated.size != generated_rust.size
    ):
        raise ValueError("source transformation verification generated receipt differs")

    _verify_rederived_ast_records(
        root=root,
        modules=modules,
        accepted=accepted,
        records=records,
        source_receipts=initial_sources,
    )

    replay_analysis = analyze_project(
        root,
        boundary_warnings=True,
        native_marker="auto",
        target_language="rust",
        native_top_level=False,
        active_plugins=(),
        embedding_enabled=False,
        delegate_fallback=False,
        plugin_registry=None,
        plugin_config=None,
    )
    replay_accepted = _accepted_function_map(replay_analysis)
    if replay_accepted != accepted:
        raise ValueError("source transformation verification replay closure differs")
    module_ir = lower_project(
        replay_analysis,
        include_embedding=False,
        plugin_types=None,
    )
    ir_qualnames = tuple(function.qualname for function in module_ir.functions)
    if ir_qualnames != tuple(sorted(accepted)):
        raise ValueError("source transformation verification lowered closure differs")
    if any(
        function.native_runtime_semantics
        or function.embedded
        or function.has_boundary_calls
        or function.plugin_lowered
        for function in module_ir.functions
    ):
        raise ValueError("source transformation verification lowered flags are out of scope")
    regenerated = generate_rust_module(
        module_ir,
        boundary_call_return_types={},
        plugin_providers={},
        plugin_types_by_key={},
    ).encode("utf-8")
    if regenerated != initial_generated.data:
        raise ValueError("source transformation verification regenerated Rust differs")

    final_sources = {
        logical_path: _read_contained_file(root=root, logical_path=logical_path)
        for logical_path in sorted(source_inputs)
    }
    final_generated = _read_contained_file(
        root=root,
        logical_path=generated_rust.logical_path,
    )
    if final_sources != initial_sources or final_generated != initial_generated:
        raise ValueError("source transformation verification inputs changed during replay")

    inventory_digest = sha256_hex(canonical_json_bytes(transformation_inventory.to_dict()))
    canonical_source_inputs = tuple(
        source_inputs[path] for path in sorted(source_inputs)
    )
    source_input_set_digest = sha256_hex(
        canonical_json_bytes([item.to_dict() for item in canonical_source_inputs])
    )
    module_ir_digest = sha256_hex(canonical_json_bytes(module_ir.to_dict()))
    regenerated_digest = sha256_hex(regenerated)
    return SourceTransformationVerification(
        source_transformation_inventory_sha256=inventory_digest,
        source_input_set_sha256=source_input_set_digest,
        module_ir_sha256=module_ir_digest,
        function_qualnames=tuple(sorted(accepted)),
        source_inputs=canonical_source_inputs,
        generated_rust=generated_rust,
        regenerated_rust_sha256=regenerated_digest,
        regenerated_rust_size=len(regenerated),
        generator_backend=_GENERATOR_BACKEND,
    )


def _require_pyo3_profile(plan: BuildPlan) -> None:
    if plan.fallback.backend != "cpython" or len(plan.artifact_profiles) != 1:
        raise ValueError("source transformation verification profile is out of scope")
    profile = plan.artifact_profiles[0]
    if (
        profile.kind is not ArtifactKind.HOST_EXTENSION
        or profile.packaging_backend != "wheel"
        or profile.python_fallback_backend != "cpython"
    ):
        raise ValueError("source transformation verification requires a CPython wheel")


def _accepted_function_map(analysis: ProjectAnalysis) -> dict[str, _FunctionIdentity]:
    if type(analysis) is not ProjectAnalysis:
        raise TypeError("source transformation verification analysis is invalid")
    return _accepted_function_map_from_tuple(tuple(analysis.accepted_native_functions))


def _accepted_function_map_from_tuple(
    functions: tuple[FunctionAnalysis, ...],
) -> dict[str, _FunctionIdentity]:
    if not functions or len(functions) > MAX_SOURCE_TRANSFORMATIONS:
        raise ValueError("source transformation verification function count is out of scope")
    result: dict[str, _FunctionIdentity] = {}
    for function in functions:
        if type(function) is not FunctionAnalysis or not _function_is_in_scope(function):
            raise ValueError("source transformation verification function is out of scope")
        if function.qualname in result:
            raise ValueError("source transformation verification function is duplicated")
        source_range = function.source_range
        if source_range is None or not function.source_ast_fingerprint:
            raise ValueError("source transformation verification function identity is missing")
        result[function.qualname] = (
            function.module_name,
            function.name,
            Path(os.path.abspath(function.file_path)),
            source_range.start.line,
            source_range.start.column,
            source_range.end.line,
            source_range.end.column,
            function.source_ast_fingerprint,
        )
    if tuple(result) != tuple(sorted(result)):
        raise ValueError("source transformation verification functions are noncanonical")
    return result


def _function_is_in_scope(function: FunctionAnalysis) -> bool:
    return (
        function.accepted is True
        and function.is_native_candidate is True
        and function.route == "native-direct"
        and function.native_target_language == "rust"
        and function.native_runtime_semantics is False
        and function.external_accelerator is None
        and function.is_embedding_candidate is False
        and not function.plugin_claims
        and not function.plugin_type_keys
        and not function.boundary_call_targets
        and not function.delegated_call_targets
        and function.qualname == f"{function.module_name}.{function.name}"
    )


def _inventory_record_map(
    inventory: SourceTransformationInventory,
) -> dict[str, SourceTransformationRecord]:
    if not inventory.records or len(inventory.records) > MAX_SOURCE_TRANSFORMATIONS:
        raise ValueError("source transformation verification inventory is empty")
    records: dict[str, SourceTransformationRecord] = {}
    for record in inventory.records:
        if type(record) is not SourceTransformationRecord or record.plugin_ids:
            raise ValueError("source transformation verification record is out of scope")
        if record.generator_backend != _GENERATOR_BACKEND:
            raise ValueError("source transformation verification backend differs")
        if record.function_qualname in records:
            raise ValueError("source transformation verification record is duplicated")
        records[record.function_qualname] = record
    return records


def _project_module_map(modules: tuple[SourceModule, ...]) -> dict[str, SourceModule]:
    if not modules:
        raise ValueError("source transformation verification source graph is empty")
    result: dict[str, SourceModule] = {}
    paths: set[str] = set()
    for module in modules:
        if type(module) is not SourceModule or module.source_origin is not SourceOrigin.PROJECT:
            raise ValueError("source transformation verification requires project modules")
        if module.module_name in result or module.path in paths:
            raise ValueError("source transformation verification source graph is ambiguous")
        result[module.module_name] = module
        paths.add(module.path)
    return result


def _project_input_map(inputs: tuple[EvidenceFileRef, ...]) -> dict[str, EvidenceFileRef]:
    result: dict[str, EvidenceFileRef] = {}
    for item in inputs:
        if type(item) is not EvidenceFileRef or item.role != "project-python-source":
            raise ValueError("source transformation verification project input is invalid")
        if item.logical_path in result:
            raise ValueError("source transformation verification project input is duplicated")
        result[item.logical_path] = item
    return result


def _generated_rust_ref(
    snapshot: EvidenceInputSnapshot,
    inventory: SourceTransformationInventory,
) -> EvidenceFileRef:
    generated = tuple(
        item
        for item in snapshot.generated_rust
        if item.role == "generated-rust-input"
        and PurePosixPath(item.logical_path).parts[-2:] == ("src", "lib.rs")
    )
    if len(generated) != 1:
        raise ValueError("source transformation verification Rust input is ambiguous")
    expected = generated[0]
    if any(record.generated_rust != expected for record in inventory.records):
        raise ValueError("source transformation verification Rust record binding differs")
    return expected


def _verify_rederived_ast_records(
    *,
    root: Path,
    modules: dict[str, SourceModule],
    accepted: dict[str, _FunctionIdentity],
    records: dict[str, SourceTransformationRecord],
    source_receipts: dict[str, _FileReceipt],
) -> None:
    nodes: dict[str, tuple[ast.FunctionDef, SourceModule]] = {}
    for module_name, module in modules.items():
        receipt = source_receipts[module.path]
        source = receipt.data.decode("utf-8")
        tree = ast.parse(source, filename=module.path)
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            qualname = f"{module_name}.{node.name}"
            if qualname in nodes:
                raise ValueError("source transformation verification AST is ambiguous")
            nodes[qualname] = (node, module)
    for qualname, binding in accepted.items():
        node_and_module = nodes.get(qualname)
        record = records[qualname]
        if node_and_module is None:
            raise ValueError("source transformation verification AST function is missing")
        node, module = node_and_module
        if node.end_lineno is None or node.end_col_offset is None:
            raise ValueError("source transformation verification AST range is unavailable")
        expected_range = (
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        )
        record_range = (
            record.source_range.start_line,
            record.source_range.start_column,
            record.source_range.end_line,
            record.source_range.end_column,
        )
        semantic = sha256_hex(executable_ast_fingerprint(node).encode("utf-8"))
        if (
            binding[0] != module.module_name
            or binding[1] != node.name
            or binding[2] != root / module.path
            or tuple(binding[3:7]) != expected_range
            or binding[7] != executable_ast_fingerprint(node)
            or record.source_path != module.path
            or record.source_sha256 != source_receipts[module.path].sha256
            or record.function_module != module.module_name
            or record_range != expected_range
            or record.semantic_ast_sha256 != semantic
        ):
            raise ValueError("source transformation verification AST identity differs")


def _validated_project_root(project_root: Path) -> Path:
    lexical = Path(os.path.abspath(project_root))
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current = current / part
        linked = current.lstat()
        if stat.S_ISLNK(linked.st_mode):
            raise ValueError("source transformation verification root contains symlink")
    linked_root = lexical.lstat()
    if not stat.S_ISDIR(linked_root.st_mode) or lexical.resolve(strict=True) != lexical:
        raise ValueError("source transformation verification root is noncanonical")
    return lexical


def _stamp(value: os.stat_result) -> _FilesystemStamp:
    return _FilesystemStamp(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        ctime_ns=value.st_ctime_ns,
        mtime_ns=value.st_mtime_ns,
        mode=value.st_mode,
        links=value.st_nlink,
    )


def _read_contained_file(*, root: Path, logical_path: str) -> _FileReceipt:
    validate_logical_reference(logical_path)
    parts = PurePosixPath(logical_path).parts
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or not parts:
        raise OSError("secure source transformation traversal is unavailable")
    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    directory_handles: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    file_fd = -1
    try:
        root_fd = os.open(str(root), directory_flags)
        root_stamp = _stamp(os.fstat(root_fd))
        linked_root = _stamp(os.lstat(root))
        if root_stamp != linked_root or not stat.S_ISDIR(root_stamp.mode):
            raise OSError("source transformation root identity changed")
        directory_handles.append((root_fd, None, None, root_stamp))
        current_fd = root_fd
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            held = _stamp(os.fstat(next_fd))
            linked = _stamp(os.stat(part, dir_fd=current_fd, follow_symlinks=False))
            if held != linked or not stat.S_ISDIR(held.mode):
                os.close(next_fd)
                raise OSError("source transformation directory identity changed")
            directory_handles.append((next_fd, current_fd, part, held))
            current_fd = next_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=current_fd)
        file_stamp = _stamp(os.fstat(file_fd))
        linked_file = _stamp(
            os.stat(parts[-1], dir_fd=current_fd, follow_symlinks=False)
        )
        if (
            file_stamp != linked_file
            or not stat.S_ISREG(file_stamp.mode)
            or file_stamp.links != 1
            or file_stamp.size < 0
            or file_stamp.size > MAX_EVIDENCE_FILE_BYTES
        ):
            raise OSError("source transformation file identity is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_EVIDENCE_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_EVIDENCE_FILE_BYTES or len(data) != file_stamp.size:
            raise OSError("source transformation file size changed")
        if _stamp(os.fstat(file_fd)) != file_stamp:
            raise OSError("source transformation file changed during read")
        for handle, parent_fd, name, expected in directory_handles:
            if _stamp(os.fstat(handle)) != expected:
                raise OSError("source transformation directory changed during read")
            if parent_fd is None or name is None:
                linked = _stamp(os.lstat(root))
            else:
                linked = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
            if linked != expected:
                raise OSError("source transformation directory link changed")
        return _FileReceipt(
            data=data,
            file_stamp=file_stamp,
            directory_stamps=tuple(item[3] for item in directory_handles),
        )
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for handle, _parent_fd, _name, _expected in reversed(directory_handles):
            try:
                os.close(handle)
            except OSError:
                pass


__all__ = ["collect_scoped_source_transformation_verification"]
