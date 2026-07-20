"""C6.2/C6.4/C6.6-C6.8 evidence emission for host-extension+cpython wheels.

In-scope builds always emit an ``artifact_evidence`` record with status
``preview-ready`` or ``unavailable`` (authority ``evidence-only``). Evidence
unavailability never changes ordinary build success and never prevents
``build.json`` from being written. Out-of-scope builds omit the field.

C6.4 adds a sanitized direct native runtime linkage inventory (macOS Mach-O via
``/usr/bin/otool -L``; Linux ELF via ``/usr/bin/readelf -W -d``) bound to the
installed extension and matching wheel member. Failures still map to
``unavailable`` and never break ordinary best-effort builds.

C6.6 adds a bounded, observation-only source-transformation inventory. If it
cannot be collected or would exceed the provenance sidecar ceiling, only that
inventory is omitted; the existing evidence and required-gate outcomes remain
unchanged.

C6.7 adds an exact observation-only inventory of Cargo metadata license
strings. C6.8 adds exact one-hop static packaged path observations for direct
native dependencies. It is the newest sidecar payload and is therefore omitted
first when the closed provenance ceiling would otherwise be exceeded.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from rextio.artifacts.evidence import (
    DEFAULT_LIMITATIONS,
    MAX_INPUT_FILES,
    MAX_SIDECAR_BYTES,
    REASON_CARGO_LOCK_MISSING,
    REASON_EVIDENCE_INTERNAL,
    REASON_INPUT_COUNT_EXCEEDED,
    REASON_NATIVE_NOT_BUILT,
    REASON_RUNTIME_BINARY_MISMATCH,
    REASON_RUNTIME_BINARY_MISSING,
    REASON_SNAPSHOT_MISSING,
    REASON_SOURCE_SNAPSHOT_MISMATCH,
    REASON_SOURCE_UNREADABLE,
    REASON_WHEEL_MUTATED,
    ArtifactEvidence,
    ArtifactEvidenceError,
    EvidenceFileRef,
    SidecarArtifact,
    SidecarWriteTransaction,
    _FileReceipt,
    build_cyclonedx_document,
    build_intoto_provenance_document,
    hash_regular_file,
    load_wheel_snapshot,
    pretty_json_bytes,
    project_relative_logical_path,
    sha256_hex,
)
from rextio.artifacts.models import ArtifactKind, ArtifactProfile
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.cargo_builder import NativeBuildResult
from rextio.build.cargo_inventory import resolve_cargo_inventory
from rextio.build.license_inventory import collect_component_license_inventory
from rextio.build.runtime_inventory import (
    inspect_native_runtime_inventory,
    resolve_installed_native_binary,
)
from rextio.build.runtime_resolution import (
    collect_native_runtime_path_resolution,
    verify_native_runtime_path_resolution,
)
from rextio.build.transformation_inventory import (
    collect_source_transformation_inventory,
)
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS
from rextio.build.wheel_builder import WheelBuildResult
from rextio.config.schema import ToolchainConfig
from rextio.partition.build_plan import BuildPlan
from rextio.source.models import SourceOrigin


@dataclass(frozen=True)
class EvidenceInputSnapshot:
    """Coherent pre-build input hashes for later evidence binding."""

    project_inputs: tuple[EvidenceFileRef, ...]
    generated_python: tuple[EvidenceFileRef, ...]
    generated_rust: tuple[EvidenceFileRef, ...]
    cargo_lock: EvidenceFileRef | None = None
    unavailable_reason: str | None = None

    @property
    def all_inputs(self) -> tuple[EvidenceFileRef, ...]:
        """Return every captured input in deterministic order."""
        items = list(self.project_inputs) + list(self.generated_python) + list(
            self.generated_rust
        )
        if self.cargo_lock is not None:
            items.append(self.cargo_lock)
        return tuple(sorted(items, key=lambda item: (item.role, item.logical_path, item.sha256)))


def capture_project_source_snapshot(
    *,
    project_root: Path,
    plan: BuildPlan,
) -> EvidenceInputSnapshot:
    """Hash every project SourceModule and compare to analyzed sha256.

    Any unreadable file, invalid logical path, or digest mismatch yields an
    unavailable snapshot. Silent skip is not permitted. Never raises into the
    ordinary build path.
    """
    try:
        graph = plan.host_source_plan.graph
        if graph is None:
            return EvidenceInputSnapshot(
                project_inputs=(),
                generated_python=(),
                generated_rust=(),
                unavailable_reason=REASON_SOURCE_UNREADABLE,
            )
        refs: list[EvidenceFileRef] = []
        for module in graph.modules:
            if module.source_origin is not SourceOrigin.PROJECT:
                continue
            absolute = project_root / module.path
            try:
                digest, size = hash_regular_file(absolute)
                ref = EvidenceFileRef(
                    logical_path=module.path,
                    sha256=digest,
                    size=size,
                    role="project-python-source",
                )
            except ArtifactEvidenceError as error:
                return EvidenceInputSnapshot(
                    project_inputs=(),
                    generated_python=(),
                    generated_rust=(),
                    unavailable_reason=error.reason or REASON_SOURCE_UNREADABLE,
                )
            except (ValueError, OSError, TypeError):
                return EvidenceInputSnapshot(
                    project_inputs=(),
                    generated_python=(),
                    generated_rust=(),
                    unavailable_reason=REASON_SOURCE_UNREADABLE,
                )
            if digest != module.sha256:
                return EvidenceInputSnapshot(
                    project_inputs=(),
                    generated_python=(),
                    generated_rust=(),
                    unavailable_reason=REASON_SOURCE_SNAPSHOT_MISMATCH,
                )
            refs.append(ref)
            if len(refs) > MAX_INPUT_FILES:
                return EvidenceInputSnapshot(
                    project_inputs=(),
                    generated_python=(),
                    generated_rust=(),
                    unavailable_reason=REASON_INPUT_COUNT_EXCEEDED,
                )
        return EvidenceInputSnapshot(
            project_inputs=tuple(sorted(refs, key=lambda item: item.logical_path)),
            generated_python=(),
            generated_rust=(),
        )
    except Exception:
        return EvidenceInputSnapshot(
            project_inputs=(),
            generated_python=(),
            generated_rust=(),
            unavailable_reason=REASON_EVIDENCE_INTERNAL,
        )


def _bounded_py_walk(
    root: Path, *, max_files: int, max_depth: int = 32
) -> list[Path] | str:
    """Bounded iterative directory walk for generated Python inputs.

    Returns a list of regular ``.py`` files or a fixed reason string on failure.
    Never uses eager unbounded ``rglob``. Every directory's entry count is
    bounded before sorting so a hostile tree cannot force an unbounded sort.
    """
    if max_files <= 0:
        return REASON_INPUT_COUNT_EXCEEDED
    results: list[Path] = []
    # (directory, depth)
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen_dirs = 0
    max_dirs = max_files * 4
    # Cap per-directory children before sorting (dirs + non-py files count too).
    max_children_per_dir = max(max_files * 4, 64)
    while stack:
        current, depth = stack.pop()
        seen_dirs += 1
        if seen_dirs > max_dirs:
            return REASON_INPUT_COUNT_EXCEEDED
        if depth > max_depth:
            return REASON_SOURCE_UNREADABLE
        try:
            if current.is_symlink():
                return REASON_SOURCE_UNREADABLE
            # Bound the entry list before sorting so sort work is O(bound).
            children_raw: list[Path] = []
            for child in current.iterdir():
                children_raw.append(child)
                if len(children_raw) > max_children_per_dir:
                    return REASON_INPUT_COUNT_EXCEEDED
            children = sorted(children_raw, key=lambda item: item.name)
        except OSError:
            return REASON_SOURCE_UNREADABLE
        for child in children:
            try:
                if child.is_symlink():
                    return REASON_SOURCE_UNREADABLE
                if child.is_dir():
                    stack.append((child, depth + 1))
                    continue
                if not child.is_file() or child.suffix != ".py":
                    continue
            except OSError:
                return REASON_SOURCE_UNREADABLE
            results.append(child)
            if len(results) > max_files:
                return REASON_INPUT_COUNT_EXCEEDED
    return results


def capture_generated_python_inputs(
    snapshot: EvidenceInputSnapshot,
    *,
    project_root: Path,
    layout: ArtifactLayout,
) -> EvidenceInputSnapshot:
    """Hash generated Python sources after generation, before native compile."""
    if snapshot.unavailable_reason is not None:
        return snapshot
    try:
        python_dir = layout.python_dir
        if not python_dir.is_dir() or python_dir.is_symlink():
            return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
        remaining = MAX_INPUT_FILES - len(snapshot.project_inputs)
        walked = _bounded_py_walk(python_dir, max_files=max(remaining, 0))
        if isinstance(walked, str):
            return replace(snapshot, unavailable_reason=walked)
        refs: list[EvidenceFileRef] = []
        for path in walked:
            try:
                logical = project_relative_logical_path(project_root, path)
                digest, size = hash_regular_file(path)
                refs.append(
                    EvidenceFileRef(
                        logical_path=logical,
                        sha256=digest,
                        size=size,
                        role="generated-python-input",
                    )
                )
            except ArtifactEvidenceError as error:
                return replace(
                    snapshot, unavailable_reason=error.reason or REASON_SOURCE_UNREADABLE
                )
            except (ValueError, OSError, TypeError):
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
            total = len(snapshot.project_inputs) + len(refs)
            if total > MAX_INPUT_FILES:
                return replace(snapshot, unavailable_reason=REASON_INPUT_COUNT_EXCEEDED)
        return replace(
            snapshot,
            generated_python=tuple(sorted(refs, key=lambda item: item.logical_path)),
        )
    except Exception:
        return replace(snapshot, unavailable_reason=REASON_EVIDENCE_INTERNAL)


def capture_generated_rust_inputs(
    snapshot: EvidenceInputSnapshot,
    *,
    project_root: Path,
    layout: ArtifactLayout,
) -> EvidenceInputSnapshot:
    """Hash generated Rust inputs after write, before cargo compilation.

    Always requires ``Cargo.toml`` and ``src/lib.rs``. Includes
    ``.cargo/config.toml`` and maturin ``pyproject.toml`` when present.
    """
    if snapshot.unavailable_reason is not None:
        return snapshot
    try:
        required = (
            layout.rust_dir / "Cargo.toml",
            layout.rust_dir / "src" / "lib.rs",
        )
        optional = (
            layout.rust_dir / ".cargo" / "config.toml",
            layout.rust_dir / "pyproject.toml",
        )
        refs: list[EvidenceFileRef] = []
        for path in required:
            if path.is_symlink():
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
            if not path.is_file():
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
            try:
                logical = project_relative_logical_path(project_root, path)
                digest, size = hash_regular_file(path)
                refs.append(
                    EvidenceFileRef(
                        logical_path=logical,
                        sha256=digest,
                        size=size,
                        role="generated-rust-input",
                    )
                )
            except ArtifactEvidenceError as error:
                return replace(
                    snapshot, unavailable_reason=error.reason or REASON_SOURCE_UNREADABLE
                )
            except (ValueError, OSError, TypeError):
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
        for path in optional:
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file():
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
            try:
                logical = project_relative_logical_path(project_root, path)
                digest, size = hash_regular_file(path)
                refs.append(
                    EvidenceFileRef(
                        logical_path=logical,
                        sha256=digest,
                        size=size,
                        role="generated-rust-input",
                    )
                )
            except ArtifactEvidenceError as error:
                return replace(
                    snapshot, unavailable_reason=error.reason or REASON_SOURCE_UNREADABLE
                )
            except (ValueError, OSError, TypeError):
                return replace(snapshot, unavailable_reason=REASON_SOURCE_UNREADABLE)
            total = (
                len(snapshot.project_inputs)
                + len(snapshot.generated_python)
                + len(refs)
            )
            if total > MAX_INPUT_FILES:
                return replace(snapshot, unavailable_reason=REASON_INPUT_COUNT_EXCEEDED)
        total = (
            len(snapshot.project_inputs)
            + len(snapshot.generated_python)
            + len(refs)
        )
        if total > MAX_INPUT_FILES:
            return replace(snapshot, unavailable_reason=REASON_INPUT_COUNT_EXCEEDED)
        return replace(
            snapshot,
            generated_rust=tuple(sorted(refs, key=lambda item: item.logical_path)),
        )
    except Exception:
        return replace(snapshot, unavailable_reason=REASON_EVIDENCE_INTERNAL)


def capture_cargo_lock_input(
    snapshot: EvidenceInputSnapshot,
    *,
    project_root: Path,
    layout: ArtifactLayout,
) -> EvidenceInputSnapshot:
    """Hash Cargo.lock after a successful native build (locked resolve product)."""
    if snapshot.unavailable_reason is not None:
        return snapshot
    try:
        path = layout.rust_dir / "Cargo.lock"
        if path.is_symlink() or not path.is_file():
            return replace(snapshot, unavailable_reason=REASON_CARGO_LOCK_MISSING)
        try:
            logical = project_relative_logical_path(project_root, path)
            digest, size = hash_regular_file(path)
            lock_ref = EvidenceFileRef(
                logical_path=logical,
                sha256=digest,
                size=size,
                role="generated-cargo-lock",
            )
        except ArtifactEvidenceError as error:
            return replace(
                snapshot, unavailable_reason=error.reason or REASON_CARGO_LOCK_MISSING
            )
        except (ValueError, OSError, TypeError):
            return replace(snapshot, unavailable_reason=REASON_CARGO_LOCK_MISSING)
        total = (
            len(snapshot.project_inputs)
            + len(snapshot.generated_python)
            + len(snapshot.generated_rust)
            + 1
        )
        if total > MAX_INPUT_FILES:
            return replace(snapshot, unavailable_reason=REASON_INPUT_COUNT_EXCEEDED)
        return replace(snapshot, cargo_lock=lock_ref)
    except Exception:
        return replace(snapshot, unavailable_reason=REASON_EVIDENCE_INTERNAL)


def verify_input_snapshot(
    snapshot: EvidenceInputSnapshot,
    *,
    project_root: Path,
) -> str | None:
    """Re-hash every snapshot path; return a fixed reason on mismatch."""
    if snapshot.unavailable_reason is not None:
        return snapshot.unavailable_reason
    try:
        for item in snapshot.all_inputs:
            absolute = project_root / item.logical_path
            try:
                digest, size = hash_regular_file(absolute)
            except ArtifactEvidenceError as error:
                return error.reason or REASON_SOURCE_UNREADABLE
            except (ValueError, OSError, TypeError):
                return REASON_SOURCE_UNREADABLE
            if digest != item.sha256 or size != item.size:
                return REASON_SOURCE_SNAPSHOT_MISMATCH
        return None
    except Exception:
        return REASON_EVIDENCE_INTERNAL


def emit_host_extension_wheel_evidence(
    *,
    project_root: Path,
    layout: ArtifactLayout,
    plan: BuildPlan,
    wheel_build: WheelBuildResult,
    native_build: NativeBuildResult,
    input_snapshot: EvidenceInputSnapshot | None,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
    output_claim: Callable[
        [tuple[tuple[Path, _FileReceipt], ...]], None
    ]
    | None = None,
) -> ArtifactEvidence | None:
    """Emit C6.2/C6.4 evidence or return None when the build is out of scope.

    In-scope host-extension+cpython wheels always return an
    :class:`ArtifactEvidence` with ``preview-ready`` or ``unavailable``.
    Failures are converted to unavailable records; they never raise into the
    ordinary build success path.
    """
    profile = _in_scope_host_extension_profile(plan.artifact_profiles)
    if profile is None:
        return None
    if wheel_build.status != "built" or not wheel_build.path:
        return None

    target_triple = profile.target_triple
    if native_build.status != "built":
        return ArtifactEvidence.unavailable(
            reason=REASON_NATIVE_NOT_BUILT, target_triple=target_triple
        )
    if input_snapshot is None:
        return ArtifactEvidence.unavailable(
            reason=REASON_SNAPSHOT_MISSING, target_triple=target_triple
        )

    wheel_path = Path(wheel_build.path)
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")
    try:
        return _emit_preview_ready(
            project_root=project_root,
            layout=layout,
            plan=plan,
            profile=profile,
            wheel_path=wheel_path,
            sbom_path=sbom_path,
            provenance_path=provenance_path,
            input_snapshot=input_snapshot,
            native_build=native_build,
            timeout=timeout,
            toolchain=toolchain,
            output_claim=output_claim,
        )
    except ArtifactEvidenceError as error:
        return ArtifactEvidence.unavailable(
            reason=error.reason or REASON_EVIDENCE_INTERNAL,
            target_triple=target_triple,
        )
    except Exception:
        return ArtifactEvidence.unavailable(
            reason=REASON_EVIDENCE_INTERNAL, target_triple=target_triple
        )


def _emit_preview_ready(
    *,
    project_root: Path,
    layout: ArtifactLayout,
    plan: BuildPlan,
    profile: ArtifactProfile,
    wheel_path: Path,
    sbom_path: Path,
    provenance_path: Path,
    input_snapshot: EvidenceInputSnapshot,
    native_build: NativeBuildResult,
    timeout: float,
    toolchain: ToolchainConfig | None,
    output_claim: Callable[
        [tuple[tuple[Path, _FileReceipt], ...]], None
    ]
    | None,
) -> ArtifactEvidence:
    """Build preview-ready evidence with post-cargo/runtime and pre-return checks.

    Sidecars are written only under a contained non-symlink dist parent. On any
    late failure, only sidecars created by this emission are cleaned up.
    Concurrent mutation of captured inputs or the wheel yields
    :data:`REASON_SOURCE_SNAPSHOT_MISMATCH` / :data:`REASON_WHEEL_MUTATED`
    (unavailable) rather than a race-free guarantee.
    """
    dist_parent = wheel_path.parent

    mismatch = verify_input_snapshot(input_snapshot, project_root=project_root)
    if mismatch is not None:
        raise ArtifactEvidenceError("input snapshot verification failed", reason=mismatch)

    # One immutable wheel byte snapshot for both subject SHA-256 and ZIP inventory.
    subject, wheel_entries = load_wheel_snapshot(wheel_path, project_root=project_root)
    inventory = resolve_cargo_inventory(
        layout.rust_dir,
        target_triple=profile.target_triple,
        timeout=timeout,
        toolchain=toolchain,
    )

    # Re-verify all captured inputs after cargo metadata (tooling can mutate).
    mismatch = verify_input_snapshot(input_snapshot, project_root=project_root)
    if mismatch is not None:
        raise ArtifactEvidenceError(
            "input snapshot verification failed after cargo metadata", reason=mismatch
        )

    installed = resolve_installed_native_binary(
        installed_path=native_build.installed_path,
        expected_python_root=layout.python_dir,
    )
    if installed is None:
        raise ArtifactEvidenceError(
            "installed native extension binary is missing",
            reason=REASON_RUNTIME_BINARY_MISSING,
        )

    runtime_inventory = inspect_native_runtime_inventory(
        installed_path=installed,
        expected_python_root=layout.python_dir,
        wheel_entries=wheel_entries,
        target_triple=profile.target_triple,
        timeout=timeout,
    )
    runtime_resolution_observation = collect_native_runtime_path_resolution(
        installed_path=installed,
        expected_python_root=layout.python_dir,
        wheel_entries=wheel_entries,
        runtime_inventory=runtime_inventory,
        target_triple=profile.target_triple,
        timeout=timeout,
    )
    runtime_path_resolution = (
        runtime_resolution_observation.inventory
        if runtime_resolution_observation is not None
        else None
    )

    # Re-verify inputs and re-hash the wheel after native inspection.
    mismatch = verify_input_snapshot(input_snapshot, project_root=project_root)
    if mismatch is not None:
        raise ArtifactEvidenceError(
            "input snapshot verification failed after runtime inspection",
            reason=mismatch,
        )
    try:
        wheel_digest_after, wheel_size_after = hash_regular_file(wheel_path)
    except ArtifactEvidenceError as error:
        raise ArtifactEvidenceError(
            "wheel could not be re-read after runtime inspection",
            reason=REASON_WHEEL_MUTATED,
        ) from error
    except OSError as exc:
        raise ArtifactEvidenceError(
            "wheel could not be re-read after runtime inspection",
            reason=REASON_WHEEL_MUTATED,
        ) from exc
    if wheel_digest_after != subject.sha256 or wheel_size_after != subject.size:
        raise ArtifactEvidenceError(
            "wheel bytes changed during runtime inspection",
            reason=REASON_WHEEL_MUTATED,
        )

    inputs = input_snapshot.all_inputs
    # C6.6 is an observation layered on top of the already captured inputs.
    # Unsupported/malformed plan bindings yield None without changing evidence
    # publication or the independent required-evidence gate outcome.
    transformation_inventory = collect_source_transformation_inventory(
        project_root=project_root,
        plan=plan,
        input_snapshot=input_snapshot,
    )
    component_license_inventory = collect_component_license_inventory(
        inventory.packages
    )

    sbom_document = build_cyclonedx_document(
        subject=subject,
        inputs=inputs,
        wheel_entries=wheel_entries,
        cargo_packages=inventory.packages,
        cargo_dependencies=inventory.dependencies,
        target_triple=profile.target_triple,
        native_runtime_inventory=runtime_inventory,
    )
    sbom_bytes = pretty_json_bytes(sbom_document)
    sbom_digest = sha256_hex(sbom_bytes)
    sbom_size = len(sbom_bytes)
    sbom_logical = project_relative_logical_path(project_root, sbom_path)
    sbom_ref = EvidenceFileRef(
        logical_path=sbom_logical,
        sha256=sbom_digest,
        size=sbom_size,
        role="cyclonedx-sbom",
    )

    provenance_document = build_intoto_provenance_document(
        subject=subject,
        sbom=sbom_ref,
        inputs=inputs,
        cargo_packages=inventory.packages,
        target_triple=profile.target_triple,
        native_runtime_inventory=runtime_inventory,
        native_runtime_path_resolution=runtime_path_resolution,
        source_transformation_inventory=transformation_inventory,
        component_license_inventory=component_license_inventory,
    )
    provenance_bytes = pretty_json_bytes(provenance_document)
    if runtime_path_resolution is not None and len(provenance_bytes) > MAX_SIDECAR_BYTES:
        # C6.8 is the newest additive observation and therefore the first
        # deterministic omission at the closed provenance sidecar ceiling.
        runtime_path_resolution = None
        runtime_resolution_observation = None
        provenance_document = build_intoto_provenance_document(
            subject=subject,
            sbom=sbom_ref,
            inputs=inputs,
            cargo_packages=inventory.packages,
            target_triple=profile.target_triple,
            native_runtime_inventory=runtime_inventory,
            native_runtime_path_resolution=None,
            source_transformation_inventory=transformation_inventory,
            component_license_inventory=component_license_inventory,
        )
        provenance_bytes = pretty_json_bytes(provenance_document)
    if (
        component_license_inventory is not None
        and len(provenance_bytes) > MAX_SIDECAR_BYTES
    ):
        # After the newer C6.8 payload has been omitted, omit C6.7 next. This
        # preserves C6.6 and every earlier evidence/gate result whenever only
        # the license observation caused the remaining ceiling crossing.
        component_license_inventory = None
        provenance_document = build_intoto_provenance_document(
            subject=subject,
            sbom=sbom_ref,
            inputs=inputs,
            cargo_packages=inventory.packages,
            target_triple=profile.target_triple,
            native_runtime_inventory=runtime_inventory,
            native_runtime_path_resolution=None,
            source_transformation_inventory=transformation_inventory,
            component_license_inventory=None,
        )
        provenance_bytes = pretty_json_bytes(provenance_document)
    if (
        transformation_inventory is not None
        and len(provenance_bytes) > MAX_SIDECAR_BYTES
    ):
        # C6.6 is additive observation metadata, not part of the independent
        # C6.2/C6.3 evidence success contract. If it alone pushes provenance
        # beyond the closed sidecar ceiling, deterministically omit only that
        # inventory and rebuild. A baseline oversize retains the existing
        # evidence-unavailable behavior through SidecarArtifact validation.
        transformation_inventory = None
        provenance_document = build_intoto_provenance_document(
            subject=subject,
            sbom=sbom_ref,
            inputs=inputs,
            cargo_packages=inventory.packages,
            target_triple=profile.target_triple,
            native_runtime_inventory=runtime_inventory,
            native_runtime_path_resolution=None,
            source_transformation_inventory=None,
            component_license_inventory=None,
        )
        provenance_bytes = pretty_json_bytes(provenance_document)
    provenance_digest = sha256_hex(provenance_bytes)
    provenance_size = len(provenance_bytes)
    provenance_logical = project_relative_logical_path(project_root, provenance_path)

    # Final re-verify before preview-ready return: inputs + wheel digest/size only.
    mismatch = verify_input_snapshot(input_snapshot, project_root=project_root)
    if mismatch is not None:
        raise ArtifactEvidenceError(
            "input snapshot verification failed before evidence return", reason=mismatch
        )
    try:
        # Reread for digest/size confirmation only (no second ZIP inventory).
        # Use the global bound so growth beyond the captured size still reads
        # and fails the equality check below as wheel-bytes-mutated.
        wheel_digest, wheel_size = hash_regular_file(wheel_path)
    except ArtifactEvidenceError as error:
        raise ArtifactEvidenceError(
            "wheel could not be re-read for confirmation",
            reason=REASON_WHEEL_MUTATED,
        ) from error
    except OSError as exc:
        raise ArtifactEvidenceError(
            "wheel could not be re-read for confirmation",
            reason=REASON_WHEEL_MUTATED,
        ) from exc
    if wheel_digest != subject.sha256 or wheel_size != subject.size:
        raise ArtifactEvidenceError(
            "wheel bytes changed after the evidence snapshot",
            reason=REASON_WHEEL_MUTATED,
        )
    try:
        native_digest, native_size = hash_regular_file(installed)
    except (ArtifactEvidenceError, OSError) as exc:
        raise ArtifactEvidenceError(
            "native extension could not be re-read before evidence return",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        ) from exc
    if (
        native_digest != runtime_inventory.subject_sha256
        or native_size != runtime_inventory.subject_size
    ):
        raise ArtifactEvidenceError(
            "native extension changed during sidecar generation",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )

    if runtime_resolution_observation is not None and not (
        verify_native_runtime_path_resolution(
            runtime_resolution_observation,
            expected_python_root=layout.python_dir,
        )
    ):
        # A packaged candidate changed or its pinned path identity no longer
        # matches. C6.8 remains optional: omit only its observation and rebuild
        # deterministic provenance without changing earlier evidence/gates.
        runtime_path_resolution = None
        runtime_resolution_observation = None
        provenance_document = build_intoto_provenance_document(
            subject=subject,
            sbom=sbom_ref,
            inputs=inputs,
            cargo_packages=inventory.packages,
            target_triple=profile.target_triple,
            native_runtime_inventory=runtime_inventory,
            native_runtime_path_resolution=None,
            source_transformation_inventory=transformation_inventory,
            component_license_inventory=component_license_inventory,
        )
        provenance_bytes = pretty_json_bytes(provenance_document)
        provenance_digest = sha256_hex(provenance_bytes)
        provenance_size = len(provenance_bytes)

    evidence = ArtifactEvidence(
        kind="host-extension-wheel",
        status="preview-ready",
        target_triple=profile.target_triple,
        subject=subject,
        sbom=SidecarArtifact(
            format="CycloneDX",
            logical_path=sbom_logical,
            sha256=sbom_digest,
            size=sbom_size,
            extra={
                "spec_version": "1.6",
                "aggregate": "incomplete",
                "signed": False,
            },
        ),
        provenance=SidecarArtifact(
            format="in-toto-Statement",
            logical_path=provenance_logical,
            sha256=provenance_digest,
            size=provenance_size,
            extra={
                "predicate_type": "https://slsa.dev/provenance/v1",
                "statement_type": "https://in-toto.io/Statement/v1",
                "signed": False,
            },
        ),
        inputs=inputs,
        wheel_entries=wheel_entries,
        cargo_packages=inventory.packages,
        cargo_dependencies=inventory.dependencies,
        native_runtime_inventory=runtime_inventory,
        native_runtime_path_resolution=runtime_path_resolution,
        source_transformation_inventory=transformation_inventory,
        component_license_inventory=component_license_inventory,
        limitations=DEFAULT_LIMITATIONS,
    )

    # Publication is the final fallible phase. The transaction stages both
    # sidecars under one pinned parent, preserves exact prior entries, and
    # removes/restores only inode/dev identities owned by this emission.
    transaction = SidecarWriteTransaction.prepare(
        (sbom_path, provenance_path),
        project_root=project_root,
        expected_parent=dist_parent,
    )
    try:
        transaction.write(sbom_path, sbom_bytes)
        transaction.write(provenance_path, provenance_bytes)
        transaction.commit(output_claim)
    except BaseException:
        try:
            transaction.rollback()
        except Exception:
            # Best-effort evidence must never turn a successful ordinary build
            # into an exception merely because defensive cleanup also failed.
            pass
        raise
    return evidence


def _in_scope_host_extension_profile(
    profiles: tuple[ArtifactProfile, ...],
) -> ArtifactProfile | None:
    """Return the in-scope host-extension+cpython profile, if any.

    Explicitly excludes Nuitka fallback host-extension profiles and every
    non-host-extension artifact kind.
    """
    for profile in profiles:
        if profile.kind is not ArtifactKind.HOST_EXTENSION:
            continue
        if profile.python_fallback_backend != "cpython":
            # nuitka (and any other backend) is out of scope for C6.2.
            continue
        return profile
    return None


def is_in_scope_host_extension_cpython(plan: BuildPlan) -> bool:
    """Return whether the build plan requests in-scope C6.2 evidence."""
    return _in_scope_host_extension_profile(plan.artifact_profiles) is not None


# Backward-compatible alias used by older call sites/tests.
def maybe_emit_host_extension_wheel_evidence(
    *,
    project_root: Path,
    layout: ArtifactLayout,
    plan: BuildPlan,
    wheel_build: WheelBuildResult,
    native_build: NativeBuildResult,
    input_snapshot: EvidenceInputSnapshot | None = None,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
    output_claim: Callable[
        [tuple[tuple[Path, _FileReceipt], ...]], None
    ]
    | None = None,
) -> ArtifactEvidence | None:
    """Compatibility wrapper around :func:`emit_host_extension_wheel_evidence`."""
    return emit_host_extension_wheel_evidence(
        project_root=project_root,
        layout=layout,
        plan=plan,
        wheel_build=wheel_build,
        native_build=native_build,
        input_snapshot=input_snapshot,
        timeout=timeout,
        toolchain=toolchain,
        output_claim=output_claim,
    )


__all__ = [
    "EvidenceInputSnapshot",
    "capture_cargo_lock_input",
    "capture_generated_python_inputs",
    "capture_generated_rust_inputs",
    "capture_project_source_snapshot",
    "emit_host_extension_wheel_evidence",
    "is_in_scope_host_extension_cpython",
    "maybe_emit_host_extension_wheel_evidence",
    "verify_input_snapshot",
]
