"""Bounded transitive native-runtime graph observations for C6.9.

The graph starts from C6.8's exact direct path-resolution inventory. Only
packaged wheel members reached by those static Mach-O/ELF semantics are opened,
copied to immutable private snapshots, and recursively inspected. System
dependencies are logical terminal leaves. This module never consults loader
environment variables, caches, ``ldd``, ``dlopen``, or actual loader choices,
and it never claims that the resulting bounded graph is a complete closure.
"""

from __future__ import annotations

import heapq
import stat
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from rextio.artifacts.evidence import (
    MAX_RUNTIME_CLOSURE_CANDIDATE_ATTEMPTS,
    MAX_RUNTIME_CLOSURE_CANDIDATES_PER_DEPENDENCY,
    MAX_RUNTIME_CLOSURE_DEPTH,
    MAX_RUNTIME_CLOSURE_EDGES,
    MAX_RUNTIME_CLOSURE_INSPECTOR_INVOCATIONS,
    MAX_RUNTIME_CLOSURE_INSPECTOR_OUTPUT_BYTES,
    MAX_RUNTIME_CLOSURE_NODES,
    REASON_RUNTIME_MALFORMED,
    REASON_RUNTIME_UNSAFE_PATH,
    ArtifactEvidenceError,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimeTransitiveClosureEdge,
    NativeRuntimeTransitiveClosureInventory,
    NativeRuntimeTransitiveClosureNode,
    WheelEntryRef,
)
from rextio.build.runtime_inventory import (
    _allowed_elf_dependencies,
    _clamp_inspector_timeout,
    _inspect_binary_header,
    _MH_DYLIB,
    _private_binary_snapshot,
    parse_readelf_d_output,
    resolve_installed_native_binary,
)
from rextio.build.runtime_resolution import (
    ElfLoadPlan,
    MachoLoadPlan,
    _CandidateReceipt,
    _loader_path_suffix,
    _member_parent,
    _read_candidate_secure,
    _relative_parts,
    _run_resolution_inspector,
    _validate_macho_system_dependency_path,
    _validated_lexical_root,
    parse_elf_load_plan,
    parse_macho_load_commands,
)
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class NativeRuntimeTransitiveClosureObservation:
    """Serialized C6.9 inventory plus private path-identity receipts."""

    inventory: NativeRuntimeTransitiveClosureInventory
    receipts: tuple[_CandidateReceipt, ...]


@dataclass(frozen=True, slots=True)
class _WheelEntryIndex:
    """One bounded exact/case-folded wheel lookup built per C6.9 attempt."""

    exact_members: dict[str, tuple[WheelEntryRef, ...]]
    casefold_members: dict[str, tuple[WheelEntryRef, ...]]
    casefold_basenames: frozenset[str]


@dataclass(slots=True)
class _TraversalBudget:
    """Mutable counters whose maxima are serialized by the inventory model."""

    inspector_invocations: int = 0
    inspector_output_bytes: int = 0
    candidate_attempts: int = 0

    def start_inspector(self) -> None:
        self.inspector_invocations += 1
        if self.inspector_invocations > MAX_RUNTIME_CLOSURE_INSPECTOR_INVOCATIONS:
            raise ArtifactEvidenceError(
                "native runtime closure inspector invocation bound exceeded",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )

    def charge_inspector_output(self, output: str) -> None:
        self.inspector_output_bytes += len(output.encode("utf-8"))
        if self.inspector_output_bytes > MAX_RUNTIME_CLOSURE_INSPECTOR_OUTPUT_BYTES:
            raise ArtifactEvidenceError(
                "native runtime closure inspector output bound exceeded",
                reason=REASON_RUNTIME_MALFORMED,
            )

    def charge_candidates(self, count: int) -> None:
        if count > MAX_RUNTIME_CLOSURE_CANDIDATES_PER_DEPENDENCY:
            raise ArtifactEvidenceError(
                "native runtime closure per-dependency candidate bound exceeded",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        self.candidate_attempts += count
        if self.candidate_attempts > MAX_RUNTIME_CLOSURE_CANDIDATE_ATTEMPTS:
            raise ArtifactEvidenceError(
                "native runtime closure candidate-attempt bound exceeded",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )


def _filesystem_alias_key(value: str) -> str:
    """Approximate case-insensitive, normalization-insensitive path aliases."""
    return unicodedata.normalize("NFD", value).casefold()


def _require_before_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ArtifactEvidenceError(
            "native runtime closure total inspection deadline exceeded",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _build_wheel_entry_index(
    wheel_entries: tuple[WheelEntryRef, ...],
    *,
    deadline: float,
) -> _WheelEntryIndex:
    """Build all wheel lookup forms once while charging the total deadline."""
    exact: dict[str, list[WheelEntryRef]] = {}
    casefolded: dict[str, list[WheelEntryRef]] = {}
    basenames: set[str] = set()
    for entry in wheel_entries:
        _require_before_deadline(deadline)
        if type(entry) is not WheelEntryRef:
            raise TypeError("native runtime closure wheel entry model is invalid")
        exact.setdefault(entry.name, []).append(entry)
        casefolded.setdefault(_filesystem_alias_key(entry.name), []).append(entry)
        basenames.add(_filesystem_alias_key(PurePosixPath(entry.name).name))
    _require_before_deadline(deadline)
    def entry_sort_key(item: WheelEntryRef) -> tuple[str, str, int, int]:
        return (
            item.name,
            item.sha256,
            item.compressed_size,
            item.uncompressed_size,
        )

    return _WheelEntryIndex(
        exact_members={
            name: tuple(sorted(entries, key=entry_sort_key))
            for name, entries in exact.items()
        },
        casefold_members={
            name: tuple(sorted(entries, key=entry_sort_key))
            for name, entries in casefolded.items()
        },
        casefold_basenames=frozenset(basenames),
    )


def collect_native_runtime_transitive_closure(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionInventory | None,
    target_triple: str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> NativeRuntimeTransitiveClosureObservation | None:
    """Return optional C6.9 evidence, omitting it on every unsafe gap."""
    try:
        if path_resolution is None:
            return None
        return _collect_native_runtime_transitive_closure(
            installed_path=installed_path,
            expected_python_root=expected_python_root,
            wheel_entries=wheel_entries,
            runtime_inventory=runtime_inventory,
            path_resolution=path_resolution,
            target_triple=target_triple,
            timeout=timeout,
        )
    except Exception:
        # C6.9 is additive preview metadata. Never perturb C6.2-C6.8 or the
        # ordinary build when its stricter recursive observation is unavailable.
        return None


def _collect_native_runtime_transitive_closure(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionInventory,
    target_triple: str,
    timeout: float,
) -> NativeRuntimeTransitiveClosureObservation:
    """Collect one deterministic graph or raise a fixed, non-serialized error."""
    if type(runtime_inventory) is not NativeRuntimeInventory:
        raise TypeError("native runtime inventory model is invalid")
    if type(path_resolution) is not NativeRuntimePathResolutionInventory:
        raise TypeError("native runtime path-resolution model is invalid")
    if (
        path_resolution.subject_wheel_member != runtime_inventory.wheel_member
        or path_resolution.subject_sha256 != runtime_inventory.subject_sha256
    ):
        raise ArtifactEvidenceError(
            "native runtime closure root observations disagree",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    total_timeout = _clamp_inspector_timeout(timeout)
    deadline = time.monotonic() + total_timeout
    root = _validated_lexical_root(expected_python_root)
    _require_before_deadline(deadline)
    reported = None if installed_path is None else str(installed_path)
    binary = resolve_installed_native_binary(
        installed_path=reported,
        expected_python_root=root,
    )
    if binary is None:
        raise ArtifactEvidenceError(
            "native runtime closure subject is unavailable",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    subject_member = binary.relative_to(root).as_posix()
    if subject_member != runtime_inventory.wheel_member:
        raise ArtifactEvidenceError(
            "native runtime closure subject path is inconsistent",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    wheel_index = _build_wheel_entry_index(wheel_entries, deadline=deadline)

    root_node = _exact_packaged_node(
        member=subject_member,
        expected_sha256=runtime_inventory.subject_sha256,
        expected_size=runtime_inventory.subject_size,
        format=runtime_inventory.format,
        root=root,
        wheel_index=wheel_index,
        deadline=deadline,
    )
    nodes: dict[str, NativeRuntimeTransitiveClosureNode] = {
        root_node.node_ref: root_node
    }
    wheel_members: dict[str, str] = {subject_member: root_node.node_ref}
    edges: list[NativeRuntimeTransitiveClosureEdge] = []
    depths: dict[str, int] = {root_node.node_ref: 0}
    pending: list[tuple[int, str, str]] = []
    inspected = {root_node.node_ref}  # C6.8 already inspected and bound the root.

    for record in path_resolution.records:
        _require_before_deadline(deadline)
        if record.resolution == "wheel-member":
            if (
                record.wheel_member is None
                or record.sha256 is None
                or record.size is None
            ):
                raise TypeError("native runtime direct wheel record is incomplete")
            target = _exact_packaged_node(
                member=record.wheel_member,
                expected_sha256=record.sha256,
                expected_size=record.size,
                format=runtime_inventory.format,
                root=root,
                wheel_index=wheel_index,
                deadline=deadline,
            )
        else:
            if (
                runtime_inventory.format == "elf"
                and _filesystem_alias_key(record.dependency_name)
                in wheel_index.casefold_basenames
            ):
                # C6.8 intentionally does not serialize the root's ORIGIN
                # paths. A same-basename packaged member could shadow this
                # allowlisted SONAME, so C6.9 cannot safely seed a system leaf.
                raise ArtifactEvidenceError(
                    "native runtime closure root system SONAME may be shadowed",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            target = NativeRuntimeTransitiveClosureNode(
                kind="system-logical",
                format=runtime_inventory.format,
                name=record.dependency_name,
            )
        _add_node(nodes, wheel_members, target)
        edge = NativeRuntimeTransitiveClosureEdge(
            source_ref=root_node.node_ref,
            target_ref=target.node_ref,
            dependency_name=record.dependency_name,
            mechanism=record.mechanism,
        )
        _add_edge(edges, edge)
        depths.setdefault(target.node_ref, 1)
        if target.kind == "wheel-member" and target.node_ref not in inspected:
            if target.wheel_member is None:  # closed model/type guard
                raise TypeError("native runtime packaged node member is missing")
            heapq.heappush(pending, (1, target.wheel_member, target.node_ref))
        _require_before_deadline(deadline)

    budget = _TraversalBudget()
    while pending:
        if time.monotonic() >= deadline:
            raise ArtifactEvidenceError(
                "native runtime closure total inspection deadline exceeded",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        depth, member, node_ref = heapq.heappop(pending)
        if node_ref in inspected:
            continue
        if depth != depths[node_ref]:
            continue
        node = nodes[node_ref]
        if node.kind != "wheel-member" or node.wheel_member != member:
            raise TypeError("native runtime closure work item is invalid")
        child_edges = _inspect_packaged_node(
            node=node,
            target_triple=target_triple,
            expected_architecture=runtime_inventory.architecture,
            root=root,
            wheel_index=wheel_index,
            deadline=deadline,
            budget=budget,
        )
        inspected.add(node_ref)
        for target, dependency_name, mechanism in child_edges:
            _require_before_deadline(deadline)
            _add_node(nodes, wheel_members, target)
            edge = NativeRuntimeTransitiveClosureEdge(
                source_ref=node_ref,
                target_ref=target.node_ref,
                dependency_name=dependency_name,
                mechanism=mechanism,
            )
            _add_edge(edges, edge)
            candidate_depth = depth + 1
            prior_depth = depths.get(target.node_ref)
            if prior_depth is None:
                if candidate_depth > MAX_RUNTIME_CLOSURE_DEPTH:
                    raise ArtifactEvidenceError(
                        "native runtime closure traversal depth exceeded",
                        reason=REASON_RUNTIME_UNSAFE_PATH,
                    )
                depths[target.node_ref] = candidate_depth
                if target.kind == "wheel-member":
                    if target.wheel_member is None:  # closed model/type guard
                        raise TypeError("native runtime packaged node member is missing")
                    heapq.heappush(
                        pending,
                        (candidate_depth, target.wheel_member, target.node_ref),
                    )
            elif candidate_depth < prior_depth:
                depths[target.node_ref] = candidate_depth
                if target.kind == "wheel-member" and target.node_ref not in inspected:
                    if target.wheel_member is None:  # closed model/type guard
                        raise TypeError("native runtime packaged node member is missing")
                    heapq.heappush(
                        pending,
                        (candidate_depth, target.wheel_member, target.node_ref),
                    )
            _require_before_deadline(deadline)

    _require_before_deadline(deadline)
    inventory = NativeRuntimeTransitiveClosureInventory(
        format=runtime_inventory.format,
        architecture=runtime_inventory.architecture,
        subject_wheel_member=subject_member,
        subject_sha256=runtime_inventory.subject_sha256,
        subject_size=runtime_inventory.subject_size,
        root_node_ref=root_node.node_ref,
        nodes=tuple(sorted(nodes.values(), key=lambda item: item.node_ref)),
        edges=tuple(sorted(edges, key=lambda item: item.canonical_key)),
    )
    _require_before_deadline(deadline)

    # Snapshot directories mutate the generated root's directory stamp. Capture
    # final receipts only after every private snapshot has been removed.
    receipts_list: list[_CandidateReceipt] = []
    for node in sorted(
        (item for item in inventory.nodes if item.kind == "wheel-member"),
        key=lambda item: item.wheel_member or "",
    ):
        _require_before_deadline(deadline)
        receipts_list.append(
            _read_and_validate_node_receipt(
                node=node,
                root=root,
                wheel_index=wheel_index,
                deadline=deadline,
            )
        )
        _require_before_deadline(deadline)
    receipts = tuple(receipts_list)
    inode_identities = tuple(
        (receipt.file_stamp.device, receipt.file_stamp.inode) for receipt in receipts
    )
    if len(inode_identities) != len(set(inode_identities)):
        raise ArtifactEvidenceError(
            "native runtime closure wheel members alias one filesystem inode",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    _require_before_deadline(deadline)
    return NativeRuntimeTransitiveClosureObservation(
        inventory=inventory,
        receipts=receipts,
    )


def verify_native_runtime_transitive_closure(
    observation: NativeRuntimeTransitiveClosureObservation,
    *,
    expected_python_root: Path,
) -> bool:
    """Reopen all packaged nodes and require their final exact receipts."""
    try:
        if type(observation) is not NativeRuntimeTransitiveClosureObservation:
            return False
        root = _validated_lexical_root(expected_python_root)
        expected_parts = tuple(
            PurePosixPath(node.wheel_member).parts
            for node in observation.inventory.nodes
            if node.kind == "wheel-member" and node.wheel_member is not None
        )
        receipt_parts = tuple(receipt.parts for receipt in observation.receipts)
        if tuple(sorted(expected_parts)) != tuple(sorted(receipt_parts)):
            return False
        for receipt in observation.receipts:
            current = _read_candidate_secure(root=root, parts=receipt.parts)
            if (
                current.directory_stamps != receipt.directory_stamps
                or current.file_stamp != receipt.file_stamp
                or current.sha256 != receipt.sha256
                or current.size != receipt.size
            ):
                return False
        return True
    except Exception:
        return False


def _inspect_packaged_node(
    *,
    node: NativeRuntimeTransitiveClosureNode,
    target_triple: str,
    expected_architecture: str,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
    budget: _TraversalBudget,
) -> tuple[tuple[NativeRuntimeTransitiveClosureNode, str, str], ...]:
    """Inspect one immutable packaged node and resolve each static dependency."""
    if node.wheel_member is None or node.sha256 is None or node.size is None:
        raise TypeError("native runtime packaged node lacks exact identity")
    path = root.joinpath(*PurePosixPath(node.wheel_member).parts)
    plan: MachoLoadPlan | ElfLoadPlan
    with _private_binary_snapshot(path, expected_root=root) as snapshot:
        if snapshot.sha256 != node.sha256 or snapshot.size != node.size:
            raise ArtifactEvidenceError(
                "native runtime closure snapshot bytes are inconsistent",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        header = _inspect_binary_header(snapshot.path, target_triple=target_triple)
        if (
            header.format != node.format
            or header.architecture != expected_architecture
            or (node.format == "mach-o" and header.macho_filetype != _MH_DYLIB)
        ):
            raise ArtifactEvidenceError(
                "native runtime closure node format is inconsistent",
                reason=REASON_RUNTIME_MALFORMED,
            )
        if node.format == "mach-o":
            budget.start_inspector()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactEvidenceError(
                    "native runtime closure total inspection deadline exceeded",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            output = _run_resolution_inspector(
                ["/usr/bin/otool", "-l", str(snapshot.path)],
                cwd=snapshot.path.parent,
                timeout=remaining,
            )
            budget.charge_inspector_output(output)
            plan = parse_macho_load_commands(output)
        else:
            budget.start_inspector()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactEvidenceError(
                    "native runtime closure total inspection deadline exceeded",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            output = _run_resolution_inspector(
                ["/usr/bin/readelf", "-W", "-d", str(snapshot.path)],
                cwd=snapshot.path.parent,
                timeout=remaining,
            )
            budget.charge_inspector_output(output)
            strict_linkage = parse_readelf_d_output(
                output,
                target_triple=target_triple,
            )
            plan = parse_elf_load_plan(output)
            if tuple(
                dependency.name for dependency in strict_linkage.dependencies
            ) != plan.dependencies:
                raise ArtifactEvidenceError(
                    "native runtime closure ELF parsers disagree",
                    reason=REASON_RUNTIME_MALFORMED,
                )
    if isinstance(plan, MachoLoadPlan):
        return _resolve_macho_node_edges(
            plan=plan,
            source_member=node.wheel_member,
            root=root,
            wheel_index=wheel_index,
            deadline=deadline,
            budget=budget,
        )
    return _resolve_elf_node_edges(
        plan=plan,
        source_member=node.wheel_member,
        target_triple=target_triple,
        root=root,
        wheel_index=wheel_index,
        deadline=deadline,
        budget=budget,
    )


def _resolve_macho_node_edges(
    *,
    plan: MachoLoadPlan,
    source_member: str,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
    budget: _TraversalBudget,
) -> tuple[tuple[NativeRuntimeTransitiveClosureNode, str, str], ...]:
    names = tuple(PurePosixPath(raw).name for raw in plan.dependencies)
    if len(names) != len(set(names)):
        raise ArtifactEvidenceError(
            "native runtime closure Mach-O dependencies are ambiguous",
            reason=REASON_RUNTIME_MALFORMED,
        )
    resolved: list[tuple[NativeRuntimeTransitiveClosureNode, str, str]] = []
    for raw in sorted(plan.dependencies, key=lambda value: (PurePosixPath(value).name, value)):
        _require_before_deadline(deadline)
        name = PurePosixPath(raw).name
        if raw.startswith(("/usr/lib/", "/System/Library/")):
            _validate_macho_system_dependency_path(raw)
            resolved.append(
                (
                    NativeRuntimeTransitiveClosureNode(
                        kind="system-logical",
                        format="mach-o",
                        name=name,
                    ),
                    name,
                    "macho-system",
                )
            )
            _require_before_deadline(deadline)
            continue
        candidates: tuple[tuple[str, ...], ...]
        if raw.startswith("@loader_path/"):
            candidates = (
                _member_parent(source_member)
                + _relative_parts(raw.removeprefix("@loader_path/")),
            )
            mechanism = "macho-loader-path"
        elif raw.startswith("@rpath/"):
            suffix = _relative_parts(raw.removeprefix("@rpath/"))
            candidates = tuple(
                _member_parent(source_member)
                + _loader_path_suffix(run_path)
                + suffix
                for run_path in plan.run_paths
            )
            mechanism = "macho-rpath"
        else:  # parser already rejects every other form
            raise ArtifactEvidenceError(
                "native runtime closure Mach-O dependency form is unsupported",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        target = _resolve_exact_candidate(
            candidate_parts=candidates,
            format="mach-o",
            root=root,
            wheel_index=wheel_index,
            deadline=deadline,
            budget=budget,
        )
        resolved.append((target, name, mechanism))
        _require_before_deadline(deadline)
    _require_before_deadline(deadline)
    return tuple(resolved)


def _resolve_elf_node_edges(
    *,
    plan: ElfLoadPlan,
    source_member: str,
    target_triple: str,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
    budget: _TraversalBudget,
) -> tuple[tuple[NativeRuntimeTransitiveClosureNode, str, str], ...]:
    if len(plan.dependencies) != len(set(plan.dependencies)):
        raise ArtifactEvidenceError(
            "native runtime closure ELF dependencies are ambiguous",
            reason=REASON_RUNTIME_MALFORMED,
        )
    system_names = _allowed_elf_dependencies(target_triple)
    resolved: list[tuple[NativeRuntimeTransitiveClosureNode, str, str]] = []
    for name in sorted(plan.dependencies):
        _require_before_deadline(deadline)
        if name in system_names:
            # An allowlisted SONAME remains only a logical system leaf. If an
            # ORIGIN path also contains that name, static selection is shadowed
            # and C6.9 conservatively becomes unavailable.
            shadow_candidates = tuple(
                _member_parent(source_member) + search_path + (name,)
                for search_path in plan.search_paths
            )
            budget.charge_candidates(len(tuple(sorted(set(shadow_candidates)))))
            for parts in sorted(set(shadow_candidates)):
                _require_before_deadline(deadline)
                member = PurePosixPath(*parts).as_posix()
                try:
                    root.joinpath(*parts).lstat()
                except FileNotFoundError:
                    shadow_exists = False
                except OSError as exc:
                    raise ArtifactEvidenceError(
                        "native runtime closure system SONAME shadow is unreadable",
                        reason=REASON_RUNTIME_UNSAFE_PATH,
                    ) from exc
                else:
                    shadow_exists = True
                if shadow_exists or (
                    _filesystem_alias_key(member) in wheel_index.casefold_members
                ):
                    raise ArtifactEvidenceError(
                        "native runtime closure system SONAME is shadowed",
                        reason=REASON_RUNTIME_UNSAFE_PATH,
                    )
                _require_before_deadline(deadline)
            resolved.append(
                (
                    NativeRuntimeTransitiveClosureNode(
                        kind="system-logical",
                        format="elf",
                        name=name,
                    ),
                    name,
                    "elf-system-name",
                )
            )
            _require_before_deadline(deadline)
            continue
        candidates = tuple(
            _member_parent(source_member) + search_path + (name,)
            for search_path in plan.search_paths
        )
        target = _resolve_exact_candidate(
            candidate_parts=candidates,
            format="elf",
            root=root,
            wheel_index=wheel_index,
            deadline=deadline,
            budget=budget,
        )
        resolved.append((target, name, "elf-origin-rpath"))
        _require_before_deadline(deadline)
    _require_before_deadline(deadline)
    return tuple(resolved)


def _resolve_exact_candidate(
    *,
    candidate_parts: tuple[tuple[str, ...], ...],
    format: str,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
    budget: _TraversalBudget,
) -> NativeRuntimeTransitiveClosureNode:
    _require_before_deadline(deadline)
    unique_candidates = tuple(sorted(set(candidate_parts)))
    budget.charge_candidates(len(unique_candidates))
    # C6.9 does not claim actual loader ordering. Multiple static search paths
    # would require securely proving every absence and selection precedence, so
    # this bounded preview accepts exactly one canonical candidate path.
    if len(unique_candidates) != 1:
        raise ArtifactEvidenceError(
            "native runtime closure candidate path is absent or ambiguous",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    matches: list[NativeRuntimeTransitiveClosureNode] = []
    for parts in unique_candidates:
        _require_before_deadline(deadline)
        member = PurePosixPath(*parts).as_posix()
        path = root.joinpath(*parts)
        try:
            path.lstat()
        except FileNotFoundError:
            if _filesystem_alias_key(member) in wheel_index.casefold_members:
                raise ArtifactEvidenceError(
                    "native runtime closure candidate is absent from generated output",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            _require_before_deadline(deadline)
            continue
        _require_before_deadline(deadline)
        receipt = _read_candidate_secure(root=root, parts=parts)
        _require_before_deadline(deadline)
        _require_unaliased_receipt(path=path, receipt=receipt)
        entry = _exact_wheel_entry(member=member, wheel_index=wheel_index)
        if entry.sha256 != receipt.sha256 or entry.uncompressed_size != receipt.size:
            raise ArtifactEvidenceError(
                "native runtime closure candidate bytes disagree with the wheel",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        matches.append(
            NativeRuntimeTransitiveClosureNode(
                kind="wheel-member",
                format=format,
                name=PurePosixPath(member).name,
                wheel_member=member,
                sha256=receipt.sha256,
                size=receipt.size,
            )
        )
        _require_before_deadline(deadline)
    if len(matches) != 1:
        raise ArtifactEvidenceError(
            "native runtime closure candidate is missing or ambiguous",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    _require_before_deadline(deadline)
    return matches[0]


def _exact_packaged_node(
    *,
    member: str,
    expected_sha256: str,
    expected_size: int,
    format: str,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
) -> NativeRuntimeTransitiveClosureNode:
    _require_before_deadline(deadline)
    parts = PurePosixPath(member).parts
    receipt = _read_candidate_secure(root=root, parts=parts)
    _require_before_deadline(deadline)
    _require_unaliased_receipt(path=root.joinpath(*parts), receipt=receipt)
    entry = _exact_wheel_entry(member=member, wheel_index=wheel_index)
    if (
        entry.sha256 != expected_sha256
        or entry.uncompressed_size != expected_size
        or receipt.sha256 != expected_sha256
        or receipt.size != expected_size
    ):
        raise ArtifactEvidenceError(
            "native runtime closure packaged node binding is invalid",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    _require_before_deadline(deadline)
    return NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format=format,
        name=PurePosixPath(member).name,
        wheel_member=member,
        sha256=expected_sha256,
        size=expected_size,
    )


def _read_and_validate_node_receipt(
    *,
    node: NativeRuntimeTransitiveClosureNode,
    root: Path,
    wheel_index: _WheelEntryIndex,
    deadline: float,
) -> _CandidateReceipt:
    if node.wheel_member is None or node.sha256 is None or node.size is None:
        raise TypeError("native runtime packaged node lacks exact identity")
    _require_before_deadline(deadline)
    receipt = _read_candidate_secure(
        root=root,
        parts=PurePosixPath(node.wheel_member).parts,
    )
    _require_before_deadline(deadline)
    _require_unaliased_receipt(
        path=root.joinpath(*PurePosixPath(node.wheel_member).parts),
        receipt=receipt,
    )
    entry = _exact_wheel_entry(member=node.wheel_member, wheel_index=wheel_index)
    if (
        entry.sha256 != node.sha256
        or entry.uncompressed_size != node.size
        or receipt.sha256 != node.sha256
        or receipt.size != node.size
    ):
        raise ArtifactEvidenceError(
            "native runtime closure final node receipt is inconsistent",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    _require_before_deadline(deadline)
    return receipt


def _exact_wheel_entry(
    *, member: str, wheel_index: _WheelEntryIndex
) -> WheelEntryRef:
    """Require one byte-exact, case-unambiguous canonical wheel member."""
    exact = wheel_index.exact_members.get(member, ())
    aliases = wheel_index.casefold_members.get(_filesystem_alias_key(member), ())
    if len(exact) != 1 or len(aliases) != 1:
        raise ArtifactEvidenceError(
            "native runtime closure wheel member is missing or case-ambiguous",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return exact[0]


def _require_unaliased_receipt(*, path: Path, receipt: _CandidateReceipt) -> None:
    """Reject symlink/hardlink aliases and bind lstat to the opened receipt."""
    try:
        linked = path.lstat()
    except OSError as exc:
        raise ArtifactEvidenceError(
            "native runtime closure member path changed",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        ) from exc
    stamp = receipt.file_stamp
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_nlink != 1
        or linked.st_dev != stamp.device
        or linked.st_ino != stamp.inode
        or linked.st_size != stamp.size
        or linked.st_ctime_ns != stamp.ctime_ns
        or linked.st_mtime_ns != stamp.mtime_ns
        or linked.st_mode != stamp.mode
    ):
        raise ArtifactEvidenceError(
            "native runtime closure member has an unsafe filesystem alias",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _add_node(
    nodes: dict[str, NativeRuntimeTransitiveClosureNode],
    wheel_members: dict[str, str],
    node: NativeRuntimeTransitiveClosureNode,
) -> None:
    existing = nodes.get(node.node_ref)
    if existing is not None and existing != node:
        raise ArtifactEvidenceError(
            "native runtime closure node identity collided",
            reason=REASON_RUNTIME_MALFORMED,
        )
    if node.kind == "wheel-member":
        if node.wheel_member is None:
            raise TypeError("native runtime packaged node member is missing")
        prior_ref = wheel_members.get(node.wheel_member)
        if prior_ref is not None and prior_ref != node.node_ref:
            raise ArtifactEvidenceError(
                "native runtime closure wheel member identity is ambiguous",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        wheel_members[node.wheel_member] = node.node_ref
    nodes[node.node_ref] = node
    if len(nodes) > MAX_RUNTIME_CLOSURE_NODES:
        raise ArtifactEvidenceError(
            "native runtime closure node bound exceeded",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _add_edge(
    edges: list[NativeRuntimeTransitiveClosureEdge],
    edge: NativeRuntimeTransitiveClosureEdge,
) -> None:
    dependency_key = (edge.source_ref, edge.dependency_name)
    if any(
        (existing.source_ref, existing.dependency_name) == dependency_key
        for existing in edges
    ):
        raise ArtifactEvidenceError(
            "native runtime closure dependency edge is ambiguous",
            reason=REASON_RUNTIME_MALFORMED,
        )
    edges.append(edge)
    if len(edges) > MAX_RUNTIME_CLOSURE_EDGES:
        raise ArtifactEvidenceError(
            "native runtime closure edge bound exceeded",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


__all__ = [
    "NativeRuntimeTransitiveClosureObservation",
    "collect_native_runtime_transitive_closure",
    "verify_native_runtime_transitive_closure",
]
