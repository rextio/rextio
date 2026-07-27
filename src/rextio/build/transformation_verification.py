"""Bounded replay verification for one narrow PyO3 source closure.

This slice is intentionally smaller than the descriptive source inventory:
all source modules must be project-owned, every accepted function must be a
plugin-free module-level direct-native function, and the full accepted set is
reanalyzed, relowered, and regenerated. Any unsupported or inconsistent state
returns ``None`` without perturbing the ordinary build path.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, SupportsIndex

from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.evidence import (
    MAX_EVIDENCE_FILE_BYTES,
    MAX_INPUT_FILES,
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
from rextio.build.artifact_layout import ArtifactLayout
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.codegen.rust.cargo import render_cargo_toml
from rextio.codegen.rust.generator import generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.fallback.module_copy import (
    fallback_module_path,
    generated_module_path,
    native_top_level_fallback_module_path,
    render_native_top_level_fallback_module,
)
from rextio.ir.lowering import lower_project
from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
from rextio.source.models import SourceModule, SourceOrigin
from rextio.source.external_linkage import ExternalNativeRegistry, ExternalRuntimeGuard

if TYPE_CHECKING:
    from rextio.build.full_c6_host_inputs import FullC6AnalysisScope
    from rextio.build.supply_chain import EvidenceInputSnapshot

_GENERATOR_BACKEND = "rextio-core-rust-pyo3-v1"
_REPLAY_AUTHORITY_DOMAIN = "rextio.source-transformation-replay-authority.v1"
_REPLAY_AUTHORITY_KEY = secrets.token_bytes(32)
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


@dataclass(frozen=True, slots=True)
class _ReplayResult:
    verification: SourceTransformationVerification
    generated_python: tuple[EvidenceFileRef, ...]
    generated_cargo_toml: EvidenceFileRef


class SourceTransformationReplayAuthority:
    """Process-local proof that the exact transformation replay completed."""

    __slots__ = (
        "verification",
        "generated_python",
        "generated_cargo_toml",
        "generated_python_tree_sha256",
        "_authority_seal",
        "_frozen",
    )

    verification: SourceTransformationVerification
    generated_python: tuple[EvidenceFileRef, ...]
    generated_cargo_toml: EvidenceFileRef
    generated_python_tree_sha256: str
    _authority_seal: bytes
    _frozen: bool

    def __init__(
        self,
        *,
        verification: SourceTransformationVerification,
        generated_python: tuple[EvidenceFileRef, ...],
        generated_cargo_toml: EvidenceFileRef,
        _authority_seal: bytes | None = None,
    ) -> None:
        if type(_authority_seal) is not bytes:
            raise TypeError("source transformation replay authority requires its collector")
        if type(verification) is not SourceTransformationVerification:
            raise TypeError("source transformation replay verification is invalid")
        _validate_generated_python_refs(generated_python)
        _validate_generated_cargo_ref(generated_cargo_toml)
        tree_sha256 = _generated_python_tree_digest(generated_python)
        object.__setattr__(self, "verification", verification)
        object.__setattr__(self, "generated_python", generated_python)
        object.__setattr__(self, "generated_cargo_toml", generated_cargo_toml)
        object.__setattr__(self, "generated_python_tree_sha256", tree_sha256)
        object.__setattr__(self, "_authority_seal", _authority_seal)
        object.__setattr__(self, "_frozen", True)
        if not hmac.compare_digest(_authority_seal, _replay_authority_seal(self._payload())):
            raise ValueError("source transformation replay authority seal is stale")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("source transformation replay authority is immutable")

    def __copy__(self) -> object:
        raise TypeError("source transformation replay authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("source transformation replay authority cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("source transformation replay authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("source transformation replay authority cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("source transformation replay authority cannot be serialized")

    def __repr__(self) -> str:
        return (
            "SourceTransformationReplayAuthority("
            f"digest={self.digest!r}, exact_outputs=<sealed>)"
        )

    @property
    def digest(self) -> str:
        """Return the path-bounded semantic identity protected by the seal."""
        return sha256_hex(canonical_json_bytes(self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "domain": _REPLAY_AUTHORITY_DOMAIN,
            "verification": self.verification.to_dict(),
            "generated_python": [item.to_dict() for item in self.generated_python],
            "generated_python_tree_sha256": self.generated_python_tree_sha256,
            "generated_cargo_toml": self.generated_cargo_toml.to_dict(),
        }


def validate_source_transformation_replay_authority(
    value: SourceTransformationReplayAuthority,
) -> SourceTransformationReplayAuthority:
    """Require an unmodified authority minted by this process's real collector."""
    if type(value) is not SourceTransformationReplayAuthority:
        raise TypeError("source transformation replay authority is missing")
    _validate_generated_python_refs(value.generated_python)
    _validate_generated_cargo_ref(value.generated_cargo_toml)
    if (
        value.generated_python_tree_sha256
        != _generated_python_tree_digest(value.generated_python)
        or not hmac.compare_digest(
            value._authority_seal,
            _replay_authority_seal(value._payload()),
        )
    ):
        raise ValueError("source transformation replay authority is stale")
    return value


def collect_scoped_source_transformation_verification(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
    transformation_inventory: SourceTransformationInventory,
    embedding_enabled: bool,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    external_native_registry: ExternalNativeRegistry | None = None,
    external_runtime_guard: ExternalRuntimeGuard | None = None,
    full_c6_analysis_scope: FullC6AnalysisScope | None = None,
    full_c6_config: RextioConfig | None = None,
) -> SourceTransformationVerification | None:
    """Replay one complete plugin-free project-native PyO3 closure, or ``None``."""
    try:
        return _collect_scoped_source_transformation_replay(
            project_root=project_root,
            plan=plan,
            input_snapshot=input_snapshot,
            transformation_inventory=transformation_inventory,
            embedding_enabled=embedding_enabled,
            boundary_fallback_threshold=boundary_fallback_threshold,
            external_native_registry=external_native_registry,
            external_runtime_guard=external_runtime_guard,
            full_c6_analysis_scope=full_c6_analysis_scope,
            full_c6_config=full_c6_config,
        ).verification
    except Exception:
        return None


def collect_scoped_source_transformation_replay_authority(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
    transformation_inventory: SourceTransformationInventory,
    embedding_enabled: bool,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    external_native_registry: ExternalNativeRegistry | None = None,
    external_runtime_guard: ExternalRuntimeGuard | None = None,
    full_c6_analysis_scope: FullC6AnalysisScope | None = None,
    full_c6_config: RextioConfig | None = None,
) -> SourceTransformationReplayAuthority | None:
    """Replay exact transformation outputs and mint local authority, or ``None``."""
    try:
        result = _collect_scoped_source_transformation_replay(
            project_root=project_root,
            plan=plan,
            input_snapshot=input_snapshot,
            transformation_inventory=transformation_inventory,
            embedding_enabled=embedding_enabled,
            boundary_fallback_threshold=boundary_fallback_threshold,
            external_native_registry=external_native_registry,
            external_runtime_guard=external_runtime_guard,
            full_c6_analysis_scope=full_c6_analysis_scope,
            full_c6_config=full_c6_config,
        )
        payload = _replay_authority_payload(
            verification=result.verification,
            generated_python=result.generated_python,
            generated_cargo_toml=result.generated_cargo_toml,
        )
        return SourceTransformationReplayAuthority(
            verification=result.verification,
            generated_python=result.generated_python,
            generated_cargo_toml=result.generated_cargo_toml,
            _authority_seal=_replay_authority_seal(payload),
        )
    except Exception:
        return None


def _collect_scoped_source_transformation_replay(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
    transformation_inventory: SourceTransformationInventory,
    embedding_enabled: bool,
    boundary_fallback_threshold: int,
    external_native_registry: ExternalNativeRegistry | None,
    external_runtime_guard: ExternalRuntimeGuard | None,
    full_c6_analysis_scope: FullC6AnalysisScope | None,
    full_c6_config: RextioConfig | None,
) -> _ReplayResult:
    from rextio.build.supply_chain import EvidenceInputSnapshot as SnapshotModel

    if type(plan) is not BuildPlan:
        raise TypeError("source transformation verification plan is invalid")
    if type(input_snapshot) is not SnapshotModel:
        raise TypeError("source transformation verification snapshot is invalid")
    if type(transformation_inventory) is not SourceTransformationInventory:
        raise TypeError("source transformation verification inventory is invalid")
    if type(embedding_enabled) is not bool or embedding_enabled:
        raise ValueError("source transformation verification embedding is out of scope")
    if type(boundary_fallback_threshold) is not int or boundary_fallback_threshold < 0:
        raise ValueError("source transformation verification fallback threshold is invalid")
    if (external_native_registry is None) != (external_runtime_guard is None):
        raise ValueError("source transformation verification external context is incomplete")
    if external_native_registry is not None and (
        type(external_native_registry) is not ExternalNativeRegistry
        or type(external_runtime_guard) is not ExternalRuntimeGuard
    ):
        raise TypeError("source transformation verification external context is invalid")
    if input_snapshot.unavailable_reason is not None:
        raise ValueError("source transformation verification snapshot is unavailable")

    root = _validated_project_root(project_root)
    analysis_root = Path(os.path.abspath(plan.analysis.project_root))
    if analysis_root != root:
        raise ValueError("source transformation verification project root disagrees")
    replay_config = _require_replay_analysis_scope(
        root=root,
        plan=plan,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=full_c6_config,
    )
    if replay_config is not None and (
        replay_config.build.fallback_threshold != boundary_fallback_threshold
        or replay_config.embedding.enabled is not embedding_enabled
    ):
        raise ValueError("source transformation verification config disagrees")
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
    generated_python = _generated_python_refs(input_snapshot)
    generated_cargo_toml = _generated_cargo_ref(input_snapshot)
    initial_python_paths = _walk_generated_python_paths(root)
    if initial_python_paths != tuple(item.logical_path for item in generated_python):
        raise ValueError("source transformation verification Python tree differs")
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
    initial_python = {
        item.logical_path: _read_contained_file(root=root, logical_path=item.logical_path)
        for item in generated_python
    }
    for item in generated_python:
        receipt = initial_python[item.logical_path]
        if receipt.sha256 != item.sha256 or receipt.size != item.size:
            raise ValueError("source transformation verification Python receipt differs")
    initial_cargo = _read_contained_file(
        root=root,
        logical_path=generated_cargo_toml.logical_path,
    )
    if (
        initial_cargo.sha256 != generated_cargo_toml.sha256
        or initial_cargo.size != generated_cargo_toml.size
    ):
        raise ValueError("source transformation verification Cargo receipt differs")

    _verify_rederived_ast_records(
        root=root,
        modules=modules,
        accepted=accepted,
        records=records,
        source_receipts=initial_sources,
    )

    _revalidate_replay_analysis_scope(
        root=root,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=replay_config,
    )
    replay_analysis = analyze_project(
        root,
        boundary_warnings=(
            True if replay_config is None else replay_config.policy.boundary_warnings
        ),
        native_marker=(
            "auto" if replay_config is None else replay_config.policy.native_marker
        ),
        target_language="rust",
        native_top_level=(
            False if replay_config is None else replay_config.policy.native_top_level
        ),
        imports_config=None if replay_config is None else replay_config.imports,
        active_plugins=(),
        embedding_enabled=False,
        delegate_fallback=False,
        plugin_registry=None,
        plugin_config=replay_config,
        external_native_registry=external_native_registry,
        full_c6_analysis_scope=full_c6_analysis_scope,
    )
    _revalidate_replay_analysis_scope(
        root=root,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=replay_config,
    )
    original_stub_inputs = plan.analysis._stub_inputs
    if original_stub_inputs is not None:
        if replay_analysis._stub_inputs != original_stub_inputs:
            raise ValueError("source transformation verification replay stub inputs differ")
        replay_analysis._stub_inputs = original_stub_inputs
    replay_accepted = _accepted_function_map(replay_analysis)
    if replay_accepted != accepted:
        raise ValueError("source transformation verification replay closure differs")
    module_ir = lower_project(
        replay_analysis,
        include_embedding=False,
        plugin_types=None,
        external_native_registry=external_native_registry,
    )
    ir_qualnames = tuple(function.qualname for function in module_ir.functions)
    external_qualnames = (
        tuple(function.qualname for function in external_native_registry.private_functions)
        if external_native_registry is not None
        else ()
    )
    expected_ir_qualnames = (*accepted, *external_qualnames)
    if (
        len(set(expected_ir_qualnames)) != len(expected_ir_qualnames)
        or len(ir_qualnames) != len(expected_ir_qualnames)
        or set(ir_qualnames) != set(expected_ir_qualnames)
    ):
        raise ValueError("source transformation verification lowered closure differs")
    if any(
        function.native_runtime_semantics
        or function.embedded
        or function.has_boundary_calls
        or function.plugin_lowered
        for function in module_ir.functions
        if function.qualname in accepted
    ):
        raise ValueError("source transformation verification lowered flags are out of scope")
    regenerated = generate_rust_module(
        module_ir,
        boundary_call_return_types={},
        plugin_providers={},
        plugin_types_by_key={},
        external_runtime_guard=external_runtime_guard,
    ).encode("utf-8")
    if regenerated != initial_generated.data:
        raise ValueError("source transformation verification regenerated Rust differs")
    replay_plan = create_build_plan(
        replay_analysis,
        "cpython",
        artifact_profiles=plan.artifact_profiles,
    )
    regenerated_python = _regenerate_python_tree(
        root=root,
        plan=replay_plan,
        boundary_fallback_threshold=boundary_fallback_threshold,
    )
    if tuple(regenerated_python) != tuple(item.logical_path for item in generated_python):
        raise ValueError("source transformation verification regenerated Python tree differs")
    if any(
        regenerated_python[path] != initial_python[path].data
        for path in regenerated_python
    ):
        raise ValueError("source transformation verification regenerated Python differs")
    regenerated_cargo = render_cargo_toml(extra_dependencies=()).encode("utf-8")
    if regenerated_cargo != initial_cargo.data:
        raise ValueError("source transformation verification regenerated Cargo.toml differs")

    final_sources = {
        logical_path: _read_contained_file(root=root, logical_path=logical_path)
        for logical_path in sorted(source_inputs)
    }
    final_generated = _read_contained_file(
        root=root,
        logical_path=generated_rust.logical_path,
    )
    final_python_paths = _walk_generated_python_paths(root)
    final_python = {
        item.logical_path: _read_contained_file(root=root, logical_path=item.logical_path)
        for item in generated_python
    }
    final_cargo = _read_contained_file(
        root=root,
        logical_path=generated_cargo_toml.logical_path,
    )
    if (
        final_sources != initial_sources
        or final_generated != initial_generated
        or final_python_paths != initial_python_paths
        or final_python != initial_python
        or final_cargo != initial_cargo
    ):
        raise ValueError("source transformation verification inputs changed during replay")
    _revalidate_replay_analysis_scope(
        root=root,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=replay_config,
    )

    inventory_digest = sha256_hex(canonical_json_bytes(transformation_inventory.to_dict()))
    canonical_source_inputs = tuple(
        source_inputs[path] for path in sorted(source_inputs)
    )
    source_input_set_digest = sha256_hex(
        canonical_json_bytes([item.to_dict() for item in canonical_source_inputs])
    )
    module_ir_digest = sha256_hex(canonical_json_bytes(module_ir.to_dict()))
    regenerated_digest = sha256_hex(regenerated)
    return _ReplayResult(
        verification=SourceTransformationVerification(
            source_transformation_inventory_sha256=inventory_digest,
            source_input_set_sha256=source_input_set_digest,
            module_ir_sha256=module_ir_digest,
            function_qualnames=tuple(sorted(accepted)),
            source_inputs=canonical_source_inputs,
            generated_rust=generated_rust,
            regenerated_rust_sha256=regenerated_digest,
            regenerated_rust_size=len(regenerated),
            generator_backend=_GENERATOR_BACKEND,
        ),
        generated_python=generated_python,
        generated_cargo_toml=generated_cargo_toml,
    )


def _require_replay_analysis_scope(
    *,
    root: Path,
    plan: BuildPlan,
    full_c6_analysis_scope: FullC6AnalysisScope | None,
    full_c6_config: RextioConfig | None,
) -> RextioConfig | None:
    """Bind strict replay to the analysis namespace that produced its plan."""
    plan_scope = plan.analysis._full_c6_analysis_scope
    if full_c6_analysis_scope is None or full_c6_config is None:
        if (
            full_c6_analysis_scope is not None
            or full_c6_config is not None
            or plan_scope is not None
        ):
            raise ValueError("source transformation verification strict scope is incomplete")
        return None
    if type(full_c6_config) is not RextioConfig:
        raise TypeError("source transformation verification strict config is invalid")
    if plan_scope is not full_c6_analysis_scope:
        raise ValueError("source transformation verification strict scope disagrees")
    _revalidate_replay_analysis_scope(
        root=root,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=full_c6_config,
    )
    return full_c6_config


def _revalidate_replay_analysis_scope(
    *,
    root: Path,
    full_c6_analysis_scope: FullC6AnalysisScope | None,
    full_c6_config: RextioConfig | None,
) -> None:
    if full_c6_analysis_scope is None:
        if full_c6_config is not None:
            raise ValueError("source transformation verification strict scope is incomplete")
        return
    if type(full_c6_config) is not RextioConfig:
        raise TypeError("source transformation verification strict config is invalid")
    from rextio.build.full_c6_host_inputs import require_full_c6_analysis_scope

    require_full_c6_analysis_scope(
        full_c6_analysis_scope,
        project_root=root,
        config=full_c6_config,
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


def _generated_python_refs(
    snapshot: EvidenceInputSnapshot,
) -> tuple[EvidenceFileRef, ...]:
    generated = tuple(snapshot.generated_python)
    _validate_generated_python_refs(generated)
    return generated


def _validate_generated_python_refs(
    generated: tuple[EvidenceFileRef, ...],
) -> None:
    if type(generated) is not tuple or not generated or len(generated) > MAX_INPUT_FILES:
        raise ValueError("source transformation verification Python inputs are invalid")
    if any(
        type(item) is not EvidenceFileRef
        or item.role != "generated-python-input"
        or PurePosixPath(item.logical_path).suffix != ".py"
        for item in generated
    ):
        raise ValueError("source transformation verification Python input is invalid")
    paths = tuple(item.logical_path for item in generated)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ValueError("source transformation verification Python inputs are noncanonical")


def _generated_cargo_ref(snapshot: EvidenceInputSnapshot) -> EvidenceFileRef:
    generated = tuple(
        item
        for item in snapshot.generated_rust
        if PurePosixPath(item.logical_path).parts[-2:] == ("rust", "Cargo.toml")
    )
    if len(generated) != 1:
        raise ValueError("source transformation verification Cargo.toml is ambiguous")
    _validate_generated_cargo_ref(generated[0])
    return generated[0]


def _validate_generated_cargo_ref(value: EvidenceFileRef) -> None:
    if (
        type(value) is not EvidenceFileRef
        or value.role != "generated-rust-input"
        or PurePosixPath(value.logical_path).parts[-2:] != ("rust", "Cargo.toml")
    ):
        raise ValueError("source transformation verification Cargo.toml is invalid")


def _generated_python_tree_digest(generated: tuple[EvidenceFileRef, ...]) -> str:
    return sha256_hex(canonical_json_bytes([item.to_dict() for item in generated]))


def _replay_authority_payload(
    *,
    verification: SourceTransformationVerification,
    generated_python: tuple[EvidenceFileRef, ...],
    generated_cargo_toml: EvidenceFileRef,
) -> dict[str, object]:
    return {
        "domain": _REPLAY_AUTHORITY_DOMAIN,
        "verification": verification.to_dict(),
        "generated_python": [item.to_dict() for item in generated_python],
        "generated_python_tree_sha256": _generated_python_tree_digest(generated_python),
        "generated_cargo_toml": generated_cargo_toml.to_dict(),
    }


def _replay_authority_seal(payload: object) -> bytes:
    return hmac.new(
        _REPLAY_AUTHORITY_KEY,
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).digest()


def _regenerate_python_tree(
    *,
    root: Path,
    plan: BuildPlan,
    boundary_fallback_threshold: int,
) -> dict[str, bytes]:
    """Render the generated Python tree without consulting generated bytes."""
    sentinel = Path("/__rextio_replayed_python__")
    relative_files: dict[str, bytes] = {}
    for module_plan in plan.fallback.modules:
        module = module_plan.module
        source = Path(module.file_path).read_bytes()
        if not module_plan.needs_wrapper:
            path = generated_module_path(sentinel, module)
            relative_files[path.relative_to(sentinel).as_posix()] = source
            continue
        fallback_path = fallback_module_path(sentinel, module)
        relative_files[fallback_path.relative_to(sentinel).as_posix()] = source
        if module_plan.accepted_native_top_level is not None:
            top_level_path = native_top_level_fallback_module_path(sentinel, module)
            relative_files[top_level_path.relative_to(sentinel).as_posix()] = (
                render_native_top_level_fallback_module(module).encode("utf-8")
            )
        wrapper_path = generated_module_path(sentinel, module)
        relative_files[wrapper_path.relative_to(sentinel).as_posix()] = render_wrapper_module(
            module,
            boundary_fallback_threshold,
        ).encode("utf-8")

    # Match orchestrator._write_runtime_support exactly: its runtime copy
    # replaces any project-generated subtree at rextio/runtime.
    for relative_key in tuple(relative_files):
        if relative_key == "rextio/runtime" or relative_key.startswith(
            "rextio/runtime/"
        ):
            del relative_files[relative_key]
    package_root = Path(__file__).resolve().parents[1]
    relative_files["rextio/__init__.py"] = (package_root / "__init__.py").read_bytes()
    relative_files["rextio/__about__.py"] = (package_root / "__about__.py").read_bytes()
    runtime_root = package_root / "runtime"
    for path in sorted(runtime_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(runtime_root).as_posix()
        relative_files[f"rextio/runtime/{relative}"] = path.read_bytes()

    prefix = ArtifactLayout(root).python_dir.relative_to(root).as_posix()
    return {
        PurePosixPath(prefix, relative).as_posix(): data
        for relative, data in sorted(relative_files.items())
    }


def _walk_generated_python_paths(root: Path) -> tuple[str, ...]:
    """List the exact current generated ``.py`` tree without following links."""
    python_root = ArtifactLayout(root).python_dir
    linked_root = python_root.lstat()
    if not stat.S_ISDIR(linked_root.st_mode) or python_root.is_symlink():
        raise OSError("source transformation generated Python root is unsafe")
    stack = [python_root]
    found: list[str] = []
    visited_directories = 0
    while stack:
        directory = stack.pop()
        visited_directories += 1
        if visited_directories > MAX_INPUT_FILES:
            raise OSError("source transformation generated Python tree is too large")
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            linked = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(linked.st_mode):
                raise OSError("source transformation generated Python tree contains a symlink")
            path = Path(entry.path)
            if stat.S_ISDIR(linked.st_mode):
                stack.append(path)
            elif stat.S_ISREG(linked.st_mode):
                if path.suffix != ".py":
                    raise OSError(
                        "source transformation generated Python tree contains "
                        "a non-Python file"
                    )
                found.append(path.relative_to(root).as_posix())
                if len(found) > MAX_INPUT_FILES:
                    raise OSError("source transformation generated Python tree is too large")
            else:
                raise OSError("source transformation generated Python tree is unsafe")
    return tuple(sorted(found))


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


__all__ = [
    "SourceTransformationReplayAuthority",
    "collect_scoped_source_transformation_replay_authority",
    "collect_scoped_source_transformation_verification",
    "validate_source_transformation_replay_authority",
]
