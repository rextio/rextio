"""Bounded reachable Cargo resolve inventory for C6.2 artifact evidence.

Uses sanitized ``cargo metadata --locked --offline --filter-platform`` with a
hard streaming output cap. Only the resolve graph reachable from
``resolve.root`` is admitted. The generated root is the only allowed
source-less/path package; other path packages and all git packages are
rejected. Registry packages require matching ``Cargo.lock`` checksums.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from rextio.artifacts.evidence import (
    MAX_CARGO_EDGES,
    MAX_CARGO_METADATA_BYTES,
    MAX_CARGO_PACKAGES,
    MAX_EVIDENCE_STRING_CHARS,
    REASON_CARGO_GRAPH_INVALID,
    REASON_CARGO_LOCK_MISSING,
    REASON_CARGO_METADATA_FAILED,
    REASON_CARGO_OUTPUT_EXCEEDED,
    ArtifactEvidenceError,
    CargoDepEdge,
    CargoPackageRef,
    canonicalize_registry_source,
    read_regular_file_bytes,
)
from rextio.build.subprocess_utils import (
    DEFAULT_BUILD_TIMEOUT_SECONDS,
    OUTPUT_OVERFLOW_EXIT_CODE,
    run_build_tool,
)
from rextio.build.toolchain import cargo_environment, resolve_tool, rust_pin_error
from rextio.config.schema import ToolchainConfig

_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_TARGET_TRIPLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class CargoInventory:
    """Sanitized reachable host-extension Cargo dependency inventory."""

    target_triple: str
    root_package: str
    packages: tuple[CargoPackageRef, ...]
    dependencies: tuple[CargoDepEdge, ...]
    lockfile_present: bool

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "target_triple": self.target_triple,
            "root_package": self.root_package,
            "lockfile_present": self.lockfile_present,
            "packages": [package.to_dict() for package in self.packages],
            "dependencies": [edge.to_dict() for edge in self.dependencies],
        }


def resolve_cargo_inventory(
    rust_dir: Path,
    *,
    target_triple: str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> CargoInventory:
    """Resolve the reachable sanitized Cargo package inventory for the crate."""
    if not _TARGET_TRIPLE_RE.fullmatch(target_triple.strip()):
        raise ArtifactEvidenceError(
            "artifact target triple is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    target_triple = target_triple.strip()

    cargo_toml = rust_dir / "Cargo.toml"
    cargo_lock = rust_dir / "Cargo.lock"
    if not cargo_toml.is_file() or cargo_toml.is_symlink():
        raise ArtifactEvidenceError(
            "generated Cargo.toml is missing", reason=REASON_CARGO_LOCK_MISSING
        )
    if not cargo_lock.is_file() or cargo_lock.is_symlink():
        raise ArtifactEvidenceError(
            "generated Cargo.lock is missing", reason=REASON_CARGO_LOCK_MISSING
        )

    lock_checksums = _load_lock_checksums(cargo_lock)
    root_crate_name = _read_package_name(cargo_toml)

    toolchain = toolchain or ToolchainConfig()
    cargo, resolve_error = resolve_tool("cargo", toolchain.cargo)
    if cargo is None:
        raise ArtifactEvidenceError(
            f"cargo was not found for artifact evidence ({resolve_error or 'missing'})",
            reason=REASON_CARGO_METADATA_FAILED,
        )
    env = cargo_environment(toolchain)
    pin_error = rust_pin_error(toolchain, "cargo", env)
    if pin_error is not None:
        raise ArtifactEvidenceError(
            "cargo toolchain pin is invalid for artifact evidence",
            reason=REASON_CARGO_METADATA_FAILED,
        )

    # Never serialize the cargo path; it is process-local only.
    command = [
        cargo,
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--offline",
        "--filter-platform",
        target_triple,
        "--manifest-path",
        str(cargo_toml),
    ]
    completed = run_build_tool(
        command,
        cwd=rust_dir,
        timeout=timeout,
        env=env,
        max_output_bytes=MAX_CARGO_METADATA_BYTES,
    )
    if completed.returncode == OUTPUT_OVERFLOW_EXIT_CODE:
        raise ArtifactEvidenceError(
            "cargo metadata output exceeded the allowed bound",
            reason=REASON_CARGO_OUTPUT_EXCEEDED,
        )
    if completed.returncode != 0:
        raise ArtifactEvidenceError(
            "cargo metadata failed for artifact evidence",
            reason=REASON_CARGO_METADATA_FAILED,
        )

    stdout = completed.stdout or ""
    try:
        payload = json.loads(stdout, parse_constant=_reject_json_constant)
    except (TypeError, ValueError) as exc:
        raise ArtifactEvidenceError(
            "cargo metadata output is not valid JSON",
            reason=REASON_CARGO_METADATA_FAILED,
        ) from exc
    if not isinstance(payload, dict):
        raise ArtifactEvidenceError(
            "cargo metadata root must be an object",
            reason=REASON_CARGO_METADATA_FAILED,
        )

    return _inventory_from_metadata(
        payload,
        lock_checksums=lock_checksums,
        target_triple=target_triple,
        expected_root_name=root_crate_name,
    )


def _inventory_from_metadata(
    payload: dict[str, object],
    *,
    lock_checksums: dict[tuple[str, str, str | None], str],
    target_triple: str,
    expected_root_name: str,
) -> CargoInventory:
    raw_packages = payload.get("packages")
    resolve = payload.get("resolve")
    if not isinstance(raw_packages, list):
        raise ArtifactEvidenceError(
            "cargo metadata packages are missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    if not isinstance(resolve, dict):
        raise ArtifactEvidenceError(
            "cargo metadata resolve graph is missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    root_id = resolve.get("root")
    nodes = resolve.get("nodes")
    if (
        not isinstance(root_id, str)
        or not root_id
        or len(root_id) > MAX_EVIDENCE_STRING_CHARS
    ):
        raise ArtifactEvidenceError(
            "cargo resolve root is missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    if not isinstance(nodes, list):
        raise ArtifactEvidenceError(
            "cargo resolve nodes are missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    if len(raw_packages) > MAX_CARGO_PACKAGES or len(nodes) > MAX_CARGO_PACKAGES:
        raise ArtifactEvidenceError(
            "cargo package count exceeds the bound", reason=REASON_CARGO_GRAPH_INVALID
        )

    packages_by_id: dict[str, dict[str, object]] = {}
    for raw in raw_packages:
        if not isinstance(raw, dict):
            raise ArtifactEvidenceError(
                "cargo metadata package entry is invalid",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        package_id = raw.get("id")
        if not isinstance(package_id, str) or not package_id:
            raise ArtifactEvidenceError(
                "cargo package id is missing", reason=REASON_CARGO_GRAPH_INVALID
            )
        if len(package_id) > MAX_EVIDENCE_STRING_CHARS:
            raise ArtifactEvidenceError(
                "cargo package id is too long", reason=REASON_CARGO_GRAPH_INVALID
            )
        if package_id in packages_by_id:
            raise ArtifactEvidenceError(
                "cargo metadata package id is duplicated",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        packages_by_id[package_id] = raw

    node_by_id: dict[str, dict[str, object]] = {}
    for raw_node in nodes:
        if not isinstance(raw_node, dict):
            raise ArtifactEvidenceError(
                "cargo resolve node is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        node_id = raw_node.get("id")
        if (
            not isinstance(node_id, str)
            or not node_id
            or len(node_id) > MAX_EVIDENCE_STRING_CHARS
        ):
            raise ArtifactEvidenceError(
                "cargo resolve node id is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        if node_id in node_by_id:
            raise ArtifactEvidenceError(
                "cargo resolve node id is duplicated",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        node_by_id[node_id] = raw_node

    # Parse and normalize every adjacency list exactly once. The aggregate raw
    # reference count is bounded before BFS so repeated short dependency IDs
    # cannot inflate the queue or defer rejection until edge construction.
    adjacency: dict[str, tuple[str, ...]] = {}
    raw_dependency_references = 0
    for node_id, node in node_by_id.items():
        raw_deps = node.get("dependencies")
        if raw_deps is None:
            raw_deps = node.get("deps")
        if raw_deps is None:
            dependency_items: list[object] = []
        elif isinstance(raw_deps, list):
            dependency_items = raw_deps
        else:
            raise ArtifactEvidenceError(
                "cargo resolve dependencies are invalid",
                reason=REASON_CARGO_GRAPH_INVALID,
            )

        raw_dependency_references += len(dependency_items)
        if raw_dependency_references > MAX_CARGO_EDGES:
            raise ArtifactEvidenceError(
                "cargo dependency reference count exceeds the bound",
                reason=REASON_CARGO_GRAPH_INVALID,
            )

        normalized: list[str] = []
        normalized_seen: set[str] = set()
        for item in dependency_items:
            if isinstance(item, str):
                dep_id = item
            elif isinstance(item, dict) and isinstance(item.get("pkg"), str):
                dep_id = item["pkg"]
            else:
                raise ArtifactEvidenceError(
                    "cargo resolve dependency entry is invalid",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )
            if not dep_id or len(dep_id) > MAX_EVIDENCE_STRING_CHARS:
                raise ArtifactEvidenceError(
                    "cargo resolve dependency id is invalid",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )
            if dep_id not in normalized_seen:
                normalized_seen.add(dep_id)
                normalized.append(dep_id)
        adjacency[node_id] = tuple(normalized)

    if root_id not in packages_by_id or root_id not in node_by_id:
        raise ArtifactEvidenceError(
            "cargo resolve root is not present in packages/nodes",
            reason=REASON_CARGO_GRAPH_INVALID,
        )

    # BFS over the reachable resolve graph only.
    reachable: list[str] = []
    seen: set[str] = set()
    queued: set[str] = {root_id}
    queue: deque[str] = deque([root_id])
    while queue:
        current = queue.popleft()
        queued.discard(current)
        if current in seen:
            continue
        seen.add(current)
        reachable.append(current)
        if len(reachable) > MAX_CARGO_PACKAGES:
            raise ArtifactEvidenceError(
                "reachable cargo package count exceeds the bound",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        for dep_id in adjacency[current]:
            if dep_id not in packages_by_id or dep_id not in node_by_id:
                raise ArtifactEvidenceError(
                    "cargo resolve dependency is missing from packages/nodes",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )
            if dep_id not in seen and dep_id not in queued:
                queue.append(dep_id)
                queued.add(dep_id)

    packages: list[CargoPackageRef] = []
    package_by_resolve_id: dict[str, CargoPackageRef] = {}
    seen_bom_refs: set[str] = set()
    for package_id in reachable:
        raw = packages_by_id[package_id]
        package = _sanitize_reachable_package(
            raw,
            package_id=package_id,
            is_root=(package_id == root_id),
            expected_root_name=expected_root_name,
            lock_checksums=lock_checksums,
            features=_node_features(node_by_id[package_id]),
        )
        bom_ref = package.bom_ref()
        if bom_ref in seen_bom_refs:
            raise ArtifactEvidenceError(
                "cargo package bom-ref is duplicated after normalization",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        seen_bom_refs.add(bom_ref)
        packages.append(package)
        package_by_resolve_id[package_id] = package

    edges: list[CargoDepEdge] = []
    for package_id in reachable:
        dependent_ref = package_by_resolve_id[package_id].bom_ref()
        for dep_id in adjacency[package_id]:
            if dep_id not in package_by_resolve_id:
                raise ArtifactEvidenceError(
                    "cargo resolve edge escapes the reachable set",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )
            dependency_ref = package_by_resolve_id[dep_id].bom_ref()
            if dependent_ref == dependency_ref:
                raise ArtifactEvidenceError(
                    "cargo resolve graph contains a self dependency",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )
            edges.append(
                CargoDepEdge(
                    dependent_ref=dependent_ref,
                    dependency_ref=dependency_ref,
                )
            )
            if len(edges) > MAX_CARGO_EDGES:
                raise ArtifactEvidenceError(
                    "cargo dependency edge count exceeds the bound",
                    reason=REASON_CARGO_GRAPH_INVALID,
                )

    packages.sort(
        key=lambda item: (
            item.name,
            item.version,
            item.kind,
            item.source_fingerprint() or "",
            item.checksum or "",
            item.bom_ref(),
        )
    )
    edges.sort(key=lambda item: (item.dependent_ref, item.dependency_ref))
    # Deduplicate edges while preserving order.
    unique_edges: list[CargoDepEdge] = []
    seen_edges: set[tuple[str, str]] = set()
    for edge in edges:
        key = (edge.dependent_ref, edge.dependency_ref)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique_edges.append(edge)

    root_package = package_by_resolve_id[root_id].name
    return CargoInventory(
        target_triple=target_triple,
        root_package=root_package,
        packages=tuple(packages),
        dependencies=tuple(unique_edges),
        lockfile_present=True,
    )


def _node_features(node: dict[str, object]) -> tuple[str, ...]:
    features = node.get("features")
    if features is None:
        return ()
    if not isinstance(features, list):
        raise ArtifactEvidenceError(
            "cargo resolve features are invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    if len(features) > 128:
        raise ArtifactEvidenceError(
            "cargo feature count exceeds the bound", reason=REASON_CARGO_GRAPH_INVALID
        )
    result: list[str] = []
    for feature in features:
        if not isinstance(feature, str) or not feature or len(feature) > 128:
            raise ArtifactEvidenceError(
                "cargo feature name is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        if any(ord(ch) < 32 for ch in feature):
            raise ArtifactEvidenceError(
                "cargo feature name is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        result.append(feature)
    return tuple(sorted(set(result)))


def _sanitize_reachable_package(
    raw: dict[str, object],
    *,
    package_id: str,
    is_root: bool,
    expected_root_name: str,
    lock_checksums: dict[tuple[str, str, str | None], str],
    features: tuple[str, ...],
) -> CargoPackageRef:
    name = raw.get("name")
    version = raw.get("version")
    source = raw.get("source")
    license_value = raw.get("license")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ArtifactEvidenceError(
            "cargo package identity is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    if not _PACKAGE_NAME_RE.fullmatch(name) or not _PACKAGE_VERSION_RE.fullmatch(version):
        raise ArtifactEvidenceError(
            "cargo package identity is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )

    license_text: str | None = None
    if license_value is not None:
        if not isinstance(license_value, str):
            raise ArtifactEvidenceError(
                "cargo package license is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        if len(license_value) > MAX_EVIDENCE_STRING_CHARS:
            raise ArtifactEvidenceError(
                "cargo package license is too long", reason=REASON_CARGO_GRAPH_INVALID
            )
        # Use stripping only to detect missing/blank metadata. Preserve every
        # nonblank string verbatim, including leading/trailing whitespace.
        # C6.7 performs no SPDX parsing or normalization.
        if not license_value.strip():
            license_text = None
        elif any(ord(character) < 32 for character in license_value):
            raise ArtifactEvidenceError(
                "cargo package license is invalid", reason=REASON_CARGO_GRAPH_INVALID
            )
        else:
            license_text = license_value

    if source is None:
        if not is_root:
            raise ArtifactEvidenceError(
                "only the generated root package may be path/source-less",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        if name != expected_root_name:
            raise ArtifactEvidenceError(
                "cargo resolve root package name mismatch",
                reason=REASON_CARGO_GRAPH_INVALID,
            )
        return CargoPackageRef(
            name=name,
            version=version,
            source=None,
            checksum=None,
            kind="path-root",
            features=features,
            license=license_text,
            package_id="path-root",
        )

    if not isinstance(source, str):
        raise ArtifactEvidenceError(
            "cargo package source is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    if source.startswith("git+") or "git+" in source:
        raise ArtifactEvidenceError(
            "git cargo packages are not admitted in this evidence slice",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    if source.startswith("path+") or source.startswith("file:") or source.startswith("/"):
        raise ArtifactEvidenceError(
            "non-root path cargo packages are not admitted",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    if not source.startswith("registry+"):
        raise ArtifactEvidenceError(
            "unsupported cargo package source kind",
            reason=REASON_CARGO_GRAPH_INVALID,
        )

    canonical_source = canonicalize_registry_source(source)
    # Exact match only: name + version + canonical registry source. No
    # cross-registry fallback that could bind the wrong checksum.
    checksum = lock_checksums.get((name, version, canonical_source))
    if checksum is None or not _HEX_SHA256.fullmatch(checksum):
        raise ArtifactEvidenceError(
            f"Cargo.lock checksum missing for registry package {name}@{version}",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    return CargoPackageRef(
        name=name,
        version=version,
        source=canonical_source,
        checksum=checksum,
        kind="registry",
        features=features,
        license=license_text,
        package_id="registry",
    )


def _load_lock_checksums(cargo_lock: Path) -> dict[tuple[str, str, str | None], str]:
    """Parse registry checksums from Cargo.lock without absolute paths."""
    raw = read_regular_file_bytes(cargo_lock, max_bytes=MAX_CARGO_METADATA_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactEvidenceError(
            "Cargo.lock is not valid UTF-8", reason=REASON_CARGO_LOCK_MISSING
        ) from exc
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ArtifactEvidenceError(
            "Cargo.lock is not valid TOML", reason=REASON_CARGO_LOCK_MISSING
        ) from exc

    packages = document.get("package", [])
    if not isinstance(packages, list):
        raise ArtifactEvidenceError(
            "Cargo.lock package table is invalid", reason=REASON_CARGO_LOCK_MISSING
        )
    if len(packages) > MAX_CARGO_PACKAGES:
        raise ArtifactEvidenceError(
            "Cargo.lock package count exceeds the bound",
            reason=REASON_CARGO_LOCK_MISSING,
        )

    checksums: dict[tuple[str, str, str | None], str] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            raise ArtifactEvidenceError(
                "Cargo.lock package entry is invalid", reason=REASON_CARGO_LOCK_MISSING
            )
        name = entry.get("name")
        version = entry.get("version")
        source = entry.get("source")
        checksum = entry.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ArtifactEvidenceError(
                "Cargo.lock package identity is invalid",
                reason=REASON_CARGO_LOCK_MISSING,
            )
        if not _PACKAGE_NAME_RE.fullmatch(name) or not _PACKAGE_VERSION_RE.fullmatch(version):
            raise ArtifactEvidenceError(
                "Cargo.lock package identity is invalid",
                reason=REASON_CARGO_LOCK_MISSING,
            )
        source_value: str | None
        if source is None:
            source_value = None
        elif isinstance(source, str) and 0 < len(source) <= MAX_EVIDENCE_STRING_CHARS:
            if source.startswith("registry+"):
                # Canonicalize so credential-bearing forms never persist.
                source_value = canonicalize_registry_source(source)
            elif source.startswith("git+"):
                # Git packages are rejected at admission time; skip storing.
                continue
            else:
                # Non-registry sources are not used for checksum binding here.
                source_value = None
        else:
            raise ArtifactEvidenceError(
                "Cargo.lock package source is invalid",
                reason=REASON_CARGO_LOCK_MISSING,
            )
        if checksum is None:
            continue
        if not isinstance(checksum, str) or not _HEX_SHA256.fullmatch(checksum):
            raise ArtifactEvidenceError(
                "Cargo.lock package checksum is invalid",
                reason=REASON_CARGO_LOCK_MISSING,
            )
        key = (name, version, source_value)
        if key in checksums:
            raise ArtifactEvidenceError(
                "Cargo.lock package checksum key is duplicated",
                reason=REASON_CARGO_LOCK_MISSING,
            )
        checksums[key] = checksum
    return checksums


def _read_package_name(cargo_toml: Path) -> str:
    raw = read_regular_file_bytes(cargo_toml, max_bytes=MAX_CARGO_METADATA_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactEvidenceError(
            "Cargo.toml is not valid UTF-8", reason=REASON_CARGO_GRAPH_INVALID
        ) from exc
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ArtifactEvidenceError(
            "Cargo.toml is not valid TOML", reason=REASON_CARGO_GRAPH_INVALID
        ) from exc
    package = document.get("package")
    if not isinstance(package, dict):
        raise ArtifactEvidenceError(
            "Cargo.toml package table is missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    name = package.get("name")
    if not isinstance(name, str) or not _PACKAGE_NAME_RE.fullmatch(name):
        raise ArtifactEvidenceError(
            "Cargo.toml package name is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    return name


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


__all__ = [
    "CargoInventory",
    "resolve_cargo_inventory",
]
