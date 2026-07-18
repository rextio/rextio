"""Train C5 external pure-Python source inventory preview.

This module is intentionally non-executing: it reads installed distribution
metadata and source bytes, but never imports the selected package.  The result
is planning evidence only.  C6 must authorize any build or redistribution.
"""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import importlib.metadata as metadata
import io
import re
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

from rextio.artifacts import ArtifactProvenance
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.source.models import SourceModule, SourceOrigin

if TYPE_CHECKING:
    from rextio.analyzer.models import ProjectAnalysis


EXTERNAL_SOURCE_LICENSE_WARNING = (
    "External package source-native work can create redistribution and derivative-work "
    "obligations. Review the exact package license with particular care for GNU/copyleft "
    "terms before enabling any future build; Rextio's inventory is not legal advice."
)


@dataclass(frozen=True)
class ExternalSourcePlan:
    """One exact installed-distribution source preview, never build authority."""

    package: str
    distribution: str
    requested_version: str
    installed_version: str | None
    max_depth: int
    status: str
    license: str | None = None
    modules: tuple[SourceModule, ...] = ()
    candidate_functions: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def build_blocked(self) -> bool:
        """C5 never grants build or redistribution authority."""
        return True

    @property
    def license_warning(self) -> str:
        """Return the mandatory non-legal-advice warning for this preview."""
        return EXTERNAL_SOURCE_LICENSE_WARNING

    def to_dict(self) -> dict[str, object]:
        """Return deterministic tooling-contract 2.5 preview evidence."""
        return {
            "status": self.status,
            "execution_authority": "preview-only",
            "distributable": False,
            "c6_gate": "required",
            "package": self.package,
            "distribution": self.distribution,
            "requested_version": self.requested_version,
            "installed_version": self.installed_version,
            "max_depth": self.max_depth,
            "license_observed": self.license,
            "modules": [module.to_dict() for module in self.modules],
            "candidate_functions": list(self.candidate_functions),
            "reason": self.reason,
            "license_warning": self.license_warning,
        }


@dataclass(frozen=True)
class _RecordEntry:
    relative: PurePosixPath
    sha256: str | None
    size: int | None


@dataclass(frozen=True)
class _VerifiedDistributionMetadata:
    name: str
    version: str
    license: str | None


class ExternalSourceBuildBlockedError(RuntimeError):
    """A C5 preview attempted to cross the unimplemented C6 build gate."""

    def __init__(self, plan: ExternalSourcePlan) -> None:
        self.plan = plan
        super().__init__(
            "RXT060 External source build blocked: Train C5 grants preview-only "
            f"authority for {plan.distribution}=={plan.requested_version}. "
            "A verified C6 SourceLock, license decision, SBOM, and provenance "
            "attestation are required before build or redistribution."
        )


def resolve_external_source_plan(
    config: ImportsConfig,
    analysis: ProjectAnalysis,
    *,
    distribution_getter: Callable[[str], metadata.Distribution] | None = None,
) -> ExternalSourcePlan | None:
    """Resolve the one used, fully pinned C5 declaration without importing it."""
    declarations = [
        (package, policy)
        for package, policy in sorted(config.packages.items())
        if _is_source_preview_declaration(policy) and _package_is_used(package, analysis)
    ]
    if not declarations:
        return None
    if len(declarations) != 1:
        # The config loader prevents this; retain a defensive programmatic gate.
        package, policy = declarations[0]
        return _unavailable(package, policy, "multiple source-native declarations are active")

    package, policy = declarations[0]
    assert policy.distribution is not None and policy.version is not None
    if not _valid_preview_identity(package, policy.distribution, policy.version):
        return _unavailable(
            package,
            policy,
            "source-native preview identity fields are not safe exact names",
        )
    if _package_uses_plugin(package, analysis):
        return _unavailable(
            package,
            policy,
            "source-native preview conflicts with an active plugin route",
        )
    getter = distribution_getter or metadata.distribution
    try:
        distribution = getter(policy.distribution)
    except metadata.PackageNotFoundError:
        return _unavailable(package, policy, "the exact distribution is not installed")
    except Exception:  # metadata providers are third-party inputs; never leak paths
        return _unavailable(package, policy, "distribution metadata could not be read")

    try:
        base_raw, base, inventory, wheel_text, verified_metadata = (
            _verified_distribution_inventory(
                distribution,
                expected_name=policy.distribution,
            )
        )
    except ValueError as exc:
        return _unavailable(
            package,
            policy,
            str(exc),
        )
    except Exception:
        return _unavailable(
            package,
            policy,
            "distribution inventory could not be verified",
        )
    installed_version = verified_metadata.version
    if _canonical_name(verified_metadata.name) != _canonical_name(
        policy.distribution
    ):
        return _unavailable(
            package,
            policy,
            "installed distribution name does not match the exact configured distribution",
            installed_version=installed_version,
        )
    if installed_version != policy.version:
        return _unavailable(
            package,
            policy,
            "installed distribution version does not match the exact configured version",
            installed_version=installed_version,
        )
    if not _is_pure_universal_wheel(wheel_text):
        return _unavailable(
            package,
            policy,
            "distribution is not recorded as a py3-none-any pure-Python wheel",
            installed_version=installed_version,
        )
    license_text = verified_metadata.license
    try:
        modules, functions = _read_modules(
            distribution,
            package,
            policy,
            base_raw=base_raw,
            base=base,
            inventory=inventory,
            license_text=license_text,
        )
    except ValueError as exc:
        return _unavailable(
            package,
            policy,
            str(exc),
            installed_version=installed_version,
            license_text=license_text,
        )
    except Exception:
        return _unavailable(
            package,
            policy,
            "distribution source inventory could not be read",
            installed_version=installed_version,
            license_text=license_text,
        )
    if not modules:
        return _unavailable(
            package,
            policy,
            "no contained depth-1 Python source modules were found",
            installed_version=installed_version,
            license_text=license_text,
        )
    if not functions:
        return _unavailable(
            package,
            policy,
            "no top-level fully annotated scalar function candidates were found",
            installed_version=installed_version,
            license_text=license_text,
        )
    return ExternalSourcePlan(
        package=package,
        distribution=policy.distribution,
        requested_version=policy.version,
        installed_version=installed_version,
        max_depth=policy.max_depth,
        status="preview-ready",
        license=license_text,
        modules=modules,
        candidate_functions=functions,
    )


def _is_source_preview_declaration(policy: ImportPackagePolicy) -> bool:
    return (
        policy.policy == "try-native"
        and policy.max_depth == 1
        and policy.distribution is not None
        and policy.version is not None
    )


def _valid_preview_identity(package: str, distribution: str, version: str) -> bool:
    return bool(
        re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
            package,
        )
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
            distribution,
        )
        and re.fullmatch(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*", version)
    )


def _package_is_used(package: str, analysis: ProjectAnalysis) -> bool:
    return any(
        decision.origin in {"external", "external-plugin"}
        and (decision.package == package or decision.target == package)
        for module in analysis.modules
        for decision in module.import_policies
    )


def _package_uses_plugin(package: str, analysis: ProjectAnalysis) -> bool:
    return any(
        decision.origin == "external-plugin"
        and (decision.package == package or decision.target == package)
        for module in analysis.modules
        for decision in module.import_policies
    )


def _is_pure_universal_wheel(wheel: str) -> bool:
    try:
        message = BytesParser(policy=compat32).parsebytes(wheel.encode("utf-8"))
    except Exception:
        return False
    if message.defects or message.is_multipart():
        return False
    payload = message.get_payload()
    if not isinstance(payload, str) or payload.strip():
        return False
    wheel_versions = _header_values(message, "Wheel-Version")
    roots = tuple(value.lower() for value in _header_values(message, "Root-Is-Purelib"))
    tags = tuple(value.lower() for value in _header_values(message, "Tag"))
    return wheel_versions == ("1.0",) and roots == ("true",) and tags == ("py3-none-any",)


def _record_path(raw: str) -> PurePosixPath:
    raw = raw.replace("\\", "/")
    posix = PurePosixPath(raw)
    windows = PureWindowsPath(raw)
    if (
        not raw
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or ".." in posix.parts
        or ".." in windows.parts
    ):
        raise ValueError("distribution RECORD contains an unsafe path")
    return posix


def _one_metadata_entry(
    inventory: tuple[_RecordEntry, ...],
    dist_info_root: PurePosixPath,
    name: str,
) -> _RecordEntry:
    matches = tuple(
        entry
        for entry in inventory
        if entry.relative == dist_info_root / name
    )
    if len(matches) != 1:
        raise ValueError(f"distribution RECORD must contain exactly one {name} entry")
    return matches[0]


def _recorded_bytes(
    distribution: metadata.Distribution,
    base_raw: Path,
    base: Path,
    entry: _RecordEntry,
    *,
    label: str,
    verify_hash: bool = True,
) -> bytes:
    try:
        located_path = Path(str(distribution.locate_file(entry.relative.as_posix())))
    except Exception as exc:
        raise ValueError(f"distribution {label} path could not be located") from exc
    raw_path = base_raw.joinpath(*entry.relative.parts)
    if located_path.absolute() != raw_path.absolute():
        raise ValueError(f"distribution {label} path does not match its RECORD entry")
    try:
        resolved = raw_path.resolve()
    except Exception as exc:
        raise ValueError(f"distribution {label} path could not be resolved") from exc
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"distribution {label} escapes its installed root") from exc
    current = base_raw
    try:
        for part in entry.relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"distribution {label} is a symlink or non-regular file")
    except OSError as exc:
        raise ValueError(f"distribution {label} path could not be inspected") from exc
    if raw_path.is_symlink() or not resolved.is_file():
        raise ValueError(f"distribution {label} is a symlink or non-regular file")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise ValueError(f"distribution {label} could not be read") from exc
    if not verify_hash:
        return data

    if entry.sha256 is None:
        raise ValueError(f"distribution RECORD has no SHA-256 for {label}")
    actual_hash = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    if actual_hash.rstrip("=") != entry.sha256.rstrip("="):
        raise ValueError(f"distribution RECORD SHA-256 drift detected for {label}")
    if entry.size is None or entry.size != len(data):
        raise ValueError(f"distribution RECORD size drift detected for {label}")
    return data


def _verified_distribution_inventory(
    distribution: metadata.Distribution,
    *,
    expected_name: str,
) -> tuple[
    Path,
    Path,
    tuple[_RecordEntry, ...],
    str,
    _VerifiedDistributionMetadata,
]:
    """Validate contained RECORD metadata without importing distribution code."""
    try:
        record_text = distribution.read_text("RECORD")
        metadata_text = distribution.read_text("METADATA")
        wheel_api_text = distribution.read_text("WHEEL")
    except Exception as exc:
        raise ValueError("distribution metadata snapshots could not be read") from exc
    if record_text is None:
        raise ValueError("distribution has no RECORD source inventory")
    if metadata_text is None or wheel_api_text is None:
        raise ValueError("distribution has incomplete dist-info metadata")
    preliminary_metadata = _parse_distribution_metadata(metadata_text.encode("utf-8"))
    if _canonical_name(preliminary_metadata.name) != _canonical_name(expected_name):
        raise ValueError(
            "installed distribution name does not match the exact configured distribution"
        )
    dist_info_root = _dist_info_root(
        preliminary_metadata.name,
        preliminary_metadata.version,
    )
    inventory: list[_RecordEntry] = []
    seen: set[PurePosixPath] = set()
    try:
        rows = csv.reader(io.StringIO(record_text))
        for row in rows:
            if len(row) != 3:
                raise ValueError("distribution RECORD contains a malformed row")
            relative = _record_path(row[0])
            if relative in seen:
                raise ValueError("distribution RECORD contains a duplicate path")
            seen.add(relative)
            hash_field = row[1]
            if hash_field:
                algorithm, separator, digest = hash_field.partition("=")
                if separator != "=" or algorithm.lower() != "sha256" or not digest:
                    raise ValueError("distribution RECORD contains a non-SHA-256 hash")
                sha256 = digest
            else:
                sha256 = None
            if row[2]:
                if not row[2].isdigit():
                    raise ValueError("distribution RECORD contains an invalid size")
                size = int(row[2])
            else:
                size = None
            inventory.append(_RecordEntry(relative=relative, sha256=sha256, size=size))
    except csv.Error as exc:
        raise ValueError("distribution RECORD could not be parsed") from exc
    if not inventory:
        raise ValueError("distribution RECORD source inventory is empty")
    inventory_tuple = tuple(inventory)
    for entry in inventory_tuple:
        dist_info_parts = tuple(
            (index, part)
            for index, part in enumerate(entry.relative.parts)
            if part.endswith(".dist-info")
        )
        if dist_info_parts and dist_info_parts != ((0, dist_info_root.name),):
            raise ValueError("distribution RECORD contains a foreign dist-info root")
    record_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "RECORD")
    metadata_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "METADATA")
    wheel_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "WHEEL")

    try:
        base_raw = Path(str(distribution.locate_file(""))).absolute()
        base = base_raw.resolve()
    except Exception as exc:
        raise ValueError("distribution installed root could not be resolved") from exc
    if not base.is_dir():
        raise ValueError("distribution installed root is not a directory")
    record_bytes = _recorded_bytes(
        distribution,
        base_raw,
        base,
        record_entry,
        label="RECORD",
        verify_hash=False,
    )
    metadata_bytes = _recorded_bytes(
        distribution,
        base_raw,
        base,
        metadata_entry,
        label="METADATA",
    )
    wheel_bytes = _recorded_bytes(distribution, base_raw, base, wheel_entry, label="WHEEL")
    try:
        record_snapshot = record_bytes.decode("utf-8")
        metadata_snapshot = metadata_bytes.decode("utf-8")
        wheel_text = wheel_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("distribution dist-info metadata is not UTF-8") from exc
    if _normalize_newlines(record_snapshot) != _normalize_newlines(record_text):
        raise ValueError("distribution RECORD snapshot does not match its dist-info provider")
    if _normalize_newlines(metadata_snapshot) != _normalize_newlines(metadata_text):
        raise ValueError("distribution METADATA snapshot does not match its dist-info provider")
    if _normalize_newlines(wheel_text) != _normalize_newlines(wheel_api_text):
        raise ValueError("distribution WHEEL snapshot does not match its dist-info provider")
    verified_metadata = _parse_distribution_metadata(metadata_bytes)
    if verified_metadata != preliminary_metadata:
        raise ValueError("distribution METADATA changed during inventory")
    return base_raw, base, inventory_tuple, wheel_text, verified_metadata


def _read_modules(
    distribution: metadata.Distribution,
    package: str,
    policy: ImportPackagePolicy,
    *,
    base_raw: Path,
    base: Path,
    inventory: tuple[_RecordEntry, ...],
    license_text: str | None,
) -> tuple[tuple[SourceModule, ...], tuple[str, ...]]:
    assert policy.distribution is not None and policy.version is not None
    package_path = PurePosixPath(*package.split("."))
    modules: list[SourceModule] = []
    functions: list[str] = []
    for entry in sorted(inventory, key=lambda item: str(item.relative)):
        relative = entry.relative
        if relative.suffix != ".py":
            continue
        try:
            under_package = relative.relative_to(package_path)
        except ValueError:
            continue
        # depth 1: package __init__.py and direct package modules only.
        if len(under_package.parts) != 1:
            continue
        data = _recorded_bytes(distribution, base_raw, base, entry, label="source")
        try:
            source_text = data.decode("utf-8")
            tree = ast.parse(source_text, filename=relative.as_posix())
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise ValueError("distribution source is not parseable UTF-8 Python") from exc
        if any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree)):
            raise ValueError("depth-1 preview source contains an unresolved import")
        module_name = (
            package
            if under_package.name == "__init__.py"
            else f"{package}.{under_package.stem}"
        )
        reference = (
            f"distributions/{_canonical_name(policy.distribution)}/{relative.as_posix()}"
        )
        modules.append(
            SourceModule(
                module_name=module_name,
                path=reference,
                is_package_init=under_package.name == "__init__.py",
                source_origin=SourceOrigin.DISTRIBUTION,
                sha256=hashlib.sha256(data).hexdigest(),
                dependency_depth=1,
                distribution=policy.distribution,
                version=policy.version,
                license=license_text,
                provenance=ArtifactProvenance(source_references=(reference,)),
            )
        )
        functions.extend(f"{module_name}.{name}" for name in _typed_scalar_functions(tree))
    return tuple(sorted(modules, key=lambda item: item.module_name)), tuple(sorted(functions))


def _typed_scalar_functions(tree: ast.Module) -> tuple[str, ...]:
    scalar_names = {"bool", "float", "int", "str"}
    names: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.decorator_list or node.returns is None:
            continue
        if node.args.vararg is not None or node.args.kwarg is not None:
            continue
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        annotations = [argument.annotation for argument in arguments]
        annotations.append(node.returns)
        if all(isinstance(item, ast.Name) and item.id in scalar_names for item in annotations):
            names.append(node.name)
    return tuple(sorted(names))


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _dist_info_root(name: str, version: str) -> PurePosixPath:
    normalized_name = re.sub(r"[-_.]+", "_", name).lower()
    # Wheel escaping preserves the PEP 440 local-version '+' separator. Runs
    # of hyphens are escaped because '-' separates wheel/dist-info fields.
    normalized_version = re.sub(r"-+", "_", version).lower()
    return PurePosixPath(f"{normalized_name}-{normalized_version}.dist-info")


def _header_values(message: Message, key: str) -> tuple[str, ...]:
    raw_values = message.get_all(key, [])
    values: list[str] = []
    for value in raw_values:
        if not isinstance(value, str):
            return ()
        values.append(value.strip())
    return tuple(values)


def _parse_distribution_metadata(data: bytes) -> _VerifiedDistributionMetadata:
    try:
        message = BytesParser(policy=compat32).parsebytes(data)
    except Exception as exc:
        raise ValueError("distribution METADATA could not be parsed") from exc
    if message.defects or message.is_multipart():
        raise ValueError("distribution METADATA has malformed RFC822 structure")
    metadata_versions = _header_values(message, "Metadata-Version")
    names = _header_values(message, "Name")
    versions = _header_values(message, "Version")
    if len(metadata_versions) != 1 or re.fullmatch(r"[1-9][0-9]*\.[0-9]+", metadata_versions[0]) is None:
        raise ValueError("distribution METADATA must contain one Metadata-Version")
    if len(names) != 1:
        raise ValueError("distribution METADATA must contain one Name")
    if len(versions) != 1:
        raise ValueError("distribution METADATA must contain one Version")
    name = names[0]
    version = versions[0]
    if not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
        name,
    ):
        raise ValueError("distribution METADATA has an invalid Name")
    if not re.fullmatch(
        r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*",
        version,
    ):
        raise ValueError("distribution METADATA has an invalid Version")
    license_expressions = _header_values(message, "License-Expression")
    legacy_licenses = _header_values(message, "License")
    if len(license_expressions) > 1 or len(legacy_licenses) > 1:
        raise ValueError("distribution METADATA contains duplicate license headers")
    raw_license = (
        license_expressions[0]
        if license_expressions
        else legacy_licenses[0]
        if legacy_licenses
        else None
    )
    license_text = _sanitize_license(raw_license)
    return _VerifiedDistributionMetadata(
        name=name,
        version=version,
        license=license_text,
    )


def _sanitize_license(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 256:
        return None
    if re.fullmatch(r"[A-Za-z0-9 .,+()_:-]+", normalized) is None:
        return None
    return normalized


def _unavailable(
    package: str,
    policy: ImportPackagePolicy,
    reason: str,
    *,
    installed_version: str | None = None,
    license_text: str | None = None,
) -> ExternalSourcePlan:
    assert policy.distribution is not None and policy.version is not None
    return ExternalSourcePlan(
        package=package,
        distribution=policy.distribution,
        requested_version=policy.version,
        installed_version=installed_version,
        max_depth=policy.max_depth,
        status="unavailable",
        license=license_text,
        reason=reason,
    )
