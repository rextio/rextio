"""Bounded, fail-closed two-build reproducibility verification for Full C6.

The verifier deliberately does not launch a build or claim that the supplied
callback is hermetic.  It proves only that one callback invocation in each of
two caller-provided, empty, disjoint real directories produced byte-identical
unsigned wheels and semantically identical bounded JSON evidence.  The result
is an immutable, non-authorizing foundation receipt.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from rextio.build.input_closure import (
    BuildInputIdentityError,
    ExactFileIdentity,
    capture_exact_file_bytes,
    verify_exact_file,
)


REPRODUCIBILITY_DOMAIN = "rextio.two-build-reproducibility.v1"
REPRODUCIBILITY_SCOPE = (
    "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
)
MAX_REPRODUCIBILITY_JSON_BYTES = 8 * 1024 * 1024
MAX_REPRODUCIBILITY_JSON_DEPTH = 64
MAX_REPRODUCIBILITY_JSON_NODES = 100_000
_SHA256_LENGTH = 64


class ReproducibilityError(RuntimeError):
    """A two-build reproducibility claim could not be established safely."""


@dataclass(frozen=True, slots=True)
class ReproducibilityBuildOutputs:
    """The three exact outputs returned by one isolated build callback."""

    unsigned_wheel: Path
    sbom_json: Path
    provenance_input_json: Path

    def __post_init__(self) -> None:
        for field_name in ("unsigned_wheel", "sbom_json", "provenance_input_json"):
            value = getattr(self, field_name)
            if not isinstance(value, (str, os.PathLike)):
                raise TypeError("reproducibility output path has an invalid type")
            object.__setattr__(self, field_name, Path(value))


@dataclass(frozen=True, slots=True)
class ReproducibilityBuildReceipt:
    """Path-free identities captured from exactly one build root."""

    ordinal: int
    unsigned_wheel: ExactFileIdentity
    sbom_json: ExactFileIdentity
    provenance_input_json: ExactFileIdentity
    sbom_canonical_sha256: str
    provenance_input_canonical_sha256: str

    def __post_init__(self) -> None:
        if self.ordinal not in (1, 2):
            raise ValueError("reproducibility build ordinal is invalid")
        for value, role in (
            (self.unsigned_wheel, "unsigned-wheel"),
            (self.sbom_json, "sbom-json"),
            (self.provenance_input_json, "provenance-input-json"),
        ):
            if type(value) is not ExactFileIdentity or value.role != role:
                raise TypeError("reproducibility output identity is invalid")
        for digest in (
            self.sbom_canonical_sha256,
            self.provenance_input_canonical_sha256,
        ):
            if type(digest) is not str or len(digest) != _SHA256_LENGTH:
                raise ValueError("reproducibility canonical JSON digest is invalid")
            try:
                bytes.fromhex(digest)
            except ValueError as exc:
                raise ValueError("reproducibility canonical JSON digest is invalid") from exc

    def to_dict(self) -> dict[str, object]:
        """Return the path-free identity for this build."""
        return {
            "ordinal": self.ordinal,
            "unsigned_wheel": self.unsigned_wheel.to_dict(),
            "sbom_json": self.sbom_json.to_dict(),
            "provenance_input_json": self.provenance_input_json.to_dict(),
            "sbom_canonical_sha256": self.sbom_canonical_sha256,
            "provenance_input_canonical_sha256": self.provenance_input_canonical_sha256,
        }


@dataclass(frozen=True, slots=True)
class ReproducibilityReceipt:
    """Canonical proof that exactly two bounded build results matched."""

    builds: tuple[ReproducibilityBuildReceipt, ReproducibilityBuildReceipt]
    domain: str = REPRODUCIBILITY_DOMAIN
    scope: str = REPRODUCIBILITY_SCOPE
    reproducible: bool = True
    complete_for_scope: bool = True
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        builds = tuple(self.builds)
        if len(builds) != 2 or tuple(item.ordinal for item in builds) != (1, 2):
            raise ValueError("reproducibility receipt must represent exactly two ordered builds")
        if not all(type(item) is ReproducibilityBuildReceipt for item in builds):
            raise TypeError("reproducibility build receipt has an invalid type")
        if self.domain != REPRODUCIBILITY_DOMAIN or self.scope != REPRODUCIBILITY_SCOPE:
            raise ValueError("reproducibility receipt domain or scope is invalid")
        if self.reproducible is not True or self.complete_for_scope is not True:
            raise ValueError("reproducibility receipt must be complete and reproducible")
        if self.authorizes_distribution is not False:
            raise ValueError("reproducibility evidence cannot authorize distribution")
        _require_matching_receipts(builds[0], builds[1])
        object.__setattr__(self, "builds", builds)

    @property
    def wheel_sha256(self) -> str:
        """Return the exact unsigned-wheel digest shared by both builds."""
        return self.builds[0].unsigned_wheel.sha256

    @property
    def sbom_canonical_sha256(self) -> str:
        """Return the canonical SBOM JSON digest shared by both builds."""
        return self.builds[0].sbom_canonical_sha256

    @property
    def provenance_input_canonical_sha256(self) -> str:
        """Return the canonical provenance-input digest shared by both builds."""
        return self.builds[0].provenance_input_canonical_sha256

    @property
    def digest(self) -> str:
        """Return the semantic digest of the non-authorizing receipt."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "scope": self.scope,
            "reproducible": True,
            "complete_for_scope": True,
            "authorizes_distribution": False,
            "builds": [item.to_dict() for item in self.builds],
            "wheel_sha256": self.wheel_sha256,
            "sbom_canonical_sha256": self.sbom_canonical_sha256,
            "provenance_input_canonical_sha256": (self.provenance_input_canonical_sha256),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical receipt plus its semantic digest."""
        return {**self._payload(), "digest": self.digest}


BuildCallback: TypeAlias = Callable[[Path], ReproducibilityBuildOutputs]


@dataclass(frozen=True, slots=True)
class _CapturedBuild:
    paths: ReproducibilityBuildOutputs
    receipt: ReproducibilityBuildReceipt
    wheel_bytes: bytes
    sbom_canonical_bytes: bytes
    provenance_canonical_bytes: bytes
    inode_keys: frozenset[tuple[int, int]]


def verify_two_build_reproducibility(
    first_root: Path | str,
    second_root: Path | str,
    *,
    build: BuildCallback,
) -> ReproducibilityReceipt:
    """Invoke ``build`` once in each empty root and compare exact results.

    Isolation of processes, networks, clocks, and environment variables is a
    caller responsibility.  This function verifies the filesystem boundary,
    captures each output through a no-follow descriptor, compares the results,
    and revalidates every captured file before returning.
    """
    if not callable(build):
        raise ReproducibilityError("reproducibility build callback is not callable")
    roots = (_validate_root(first_root), _validate_root(second_root))
    if roots[0][0] == roots[1][0]:
        raise ReproducibilityError("reproducibility roots must be distinct")
    if roots[0][0] in roots[1][0].parents or roots[1][0] in roots[0][0].parents:
        raise ReproducibilityError("reproducibility roots must not be nested")
    for root, _root_stat in roots:
        _require_empty_root(root)

    captured: list[_CapturedBuild] = []
    for ordinal, (root, original_stat) in enumerate(roots, start=1):
        try:
            raw_outputs = build(root)
        except ReproducibilityError:
            raise
        except Exception as exc:
            raise ReproducibilityError("reproducibility build callback failed") from exc
        if type(raw_outputs) is not ReproducibilityBuildOutputs:
            raise ReproducibilityError("reproducibility build callback returned invalid outputs")
        _verify_root_unchanged(root, original_stat)
        captured.append(_capture_build(root, raw_outputs, ordinal=ordinal))

    if captured[0].inode_keys.intersection(captured[1].inode_keys):
        raise ReproducibilityError("reproducibility builds contain shared hardlinked outputs")

    for item in captured:
        _reverify_build(item)
    if not hmac.compare_digest(captured[0].wheel_bytes, captured[1].wheel_bytes):
        raise ReproducibilityError("unsigned wheel bytes are not reproducible")
    if not hmac.compare_digest(
        captured[0].sbom_canonical_bytes,
        captured[1].sbom_canonical_bytes,
    ):
        raise ReproducibilityError("canonical SBOM JSON is not reproducible")
    if not hmac.compare_digest(
        captured[0].provenance_canonical_bytes,
        captured[1].provenance_canonical_bytes,
    ):
        raise ReproducibilityError("canonical provenance-input JSON is not reproducible")

    try:
        return ReproducibilityReceipt(builds=(captured[0].receipt, captured[1].receipt))
    except (TypeError, ValueError) as exc:
        raise ReproducibilityError(str(exc)) from exc


def _validate_root(value: Path | str) -> tuple[Path, os.stat_result]:
    candidate = Path(value)
    try:
        _reject_symlink_components(candidate)
        root_stat = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise ReproducibilityError("reproducibility root is missing") from exc
    except OSError as exc:
        raise ReproducibilityError("reproducibility root could not be inspected") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise ReproducibilityError("reproducibility root must not be a symlink")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ReproducibilityError("reproducibility root must be a directory")
    try:
        resolved = candidate.resolve(strict=True)
    except ReproducibilityError:
        raise
    except OSError as exc:
        raise ReproducibilityError("reproducibility root could not be inspected") from exc
    return resolved, root_stat


def _require_empty_root(root: Path) -> None:
    try:
        if next(root.iterdir(), None) is not None:
            raise ReproducibilityError("reproducibility root must be empty before the build")
    except ReproducibilityError:
        raise
    except OSError as exc:
        raise ReproducibilityError("reproducibility root could not be inspected") from exc


def _verify_root_unchanged(root: Path, expected: os.stat_result) -> None:
    try:
        _reject_symlink_components(root)
        observed = os.lstat(root)
    except OSError as exc:
        raise ReproducibilityError("reproducibility root changed during the build") from exc
    if not stat.S_ISDIR(observed.st_mode) or (observed.st_dev, observed.st_ino) != (
        expected.st_dev,
        expected.st_ino,
    ):
        raise ReproducibilityError("reproducibility root changed during the build")


def _capture_build(
    root: Path,
    outputs: ReproducibilityBuildOutputs,
    *,
    ordinal: int,
) -> _CapturedBuild:
    output_paths = (
        outputs.unsigned_wheel,
        outputs.sbom_json,
        outputs.provenance_input_json,
    )
    normalized: list[Path] = []
    inode_keys: set[tuple[int, int]] = set()
    for path in output_paths:
        normalized_path, inode_key = _validate_output_path(root, path)
        normalized.append(normalized_path)
        inode_keys.add(inode_key)
    if len(set(normalized)) != 3 or len(inode_keys) != 3:
        raise ReproducibilityError("reproducibility build contains duplicate output paths")
    normalized_outputs = ReproducibilityBuildOutputs(*normalized)

    try:
        wheel_identity, wheel_bytes = capture_exact_file_bytes(
            normalized_outputs.unsigned_wheel,
            logical_name=f"build-{ordinal}/unsigned-wheel.whl",
            role="unsigned-wheel",
        )
        sbom_identity, sbom_bytes = capture_exact_file_bytes(
            normalized_outputs.sbom_json,
            logical_name=f"build-{ordinal}/sbom.json",
            role="sbom-json",
            max_bytes=MAX_REPRODUCIBILITY_JSON_BYTES,
        )
        provenance_identity, provenance_bytes = capture_exact_file_bytes(
            normalized_outputs.provenance_input_json,
            logical_name=f"build-{ordinal}/provenance-input.json",
            role="provenance-input-json",
            max_bytes=MAX_REPRODUCIBILITY_JSON_BYTES,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise ReproducibilityError("reproducibility output could not be captured safely") from exc

    sbom_canonical = _parse_canonical_json(sbom_bytes, label="SBOM")
    provenance_canonical = _parse_canonical_json(provenance_bytes, label="provenance input")
    receipt = ReproducibilityBuildReceipt(
        ordinal=ordinal,
        unsigned_wheel=wheel_identity,
        sbom_json=sbom_identity,
        provenance_input_json=provenance_identity,
        sbom_canonical_sha256=hashlib.sha256(sbom_canonical).hexdigest(),
        provenance_input_canonical_sha256=hashlib.sha256(provenance_canonical).hexdigest(),
    )
    return _CapturedBuild(
        paths=normalized_outputs,
        receipt=receipt,
        wheel_bytes=wheel_bytes,
        sbom_canonical_bytes=sbom_canonical,
        provenance_canonical_bytes=provenance_canonical,
        inode_keys=frozenset(inode_keys),
    )


def _validate_output_path(root: Path, value: Path) -> tuple[Path, tuple[int, int]]:
    candidate = Path(value)
    try:
        _reject_symlink_components(candidate)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        observed = os.lstat(candidate)
    except ValueError as exc:
        raise ReproducibilityError("reproducibility output must not escape its build root") from exc
    except FileNotFoundError as exc:
        raise ReproducibilityError("reproducibility output is missing") from exc
    except OSError as exc:
        raise ReproducibilityError("reproducibility output could not be inspected") from exc
    if stat.S_ISLNK(observed.st_mode):
        raise ReproducibilityError("reproducibility output must not be a symlink")
    if not stat.S_ISREG(observed.st_mode):
        raise ReproducibilityError("reproducibility output must be a regular file")
    return resolved, (observed.st_dev, observed.st_ino)


def _reject_symlink_components(value: Path) -> None:
    absolute = value.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            observed = os.lstat(component)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(observed.st_mode):
            raise ReproducibilityError("reproducibility path contains a symlink component")


def _reverify_build(captured: _CapturedBuild) -> None:
    try:
        verify_exact_file(captured.paths.unsigned_wheel, captured.receipt.unsigned_wheel)
        verify_exact_file(
            captured.paths.sbom_json,
            captured.receipt.sbom_json,
            max_bytes=MAX_REPRODUCIBILITY_JSON_BYTES,
        )
        verify_exact_file(
            captured.paths.provenance_input_json,
            captured.receipt.provenance_input_json,
            max_bytes=MAX_REPRODUCIBILITY_JSON_BYTES,
        )
    except BuildInputIdentityError as exc:
        raise ReproducibilityError("reproducibility output changed after capture") from exc


def _parse_canonical_json(data: bytes, *, label: str) -> bytes:
    if len(data) > MAX_REPRODUCIBILITY_JSON_BYTES:
        raise ReproducibilityError(f"{label} JSON exceeds the byte bound")

    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReproducibilityError(f"{label} JSON contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ReproducibilityError(f"{label} JSON contains a non-finite number")

    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except ReproducibilityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ReproducibilityError(f"{label} JSON is invalid") from exc
    _validate_json_tree(document, label=label)
    try:
        return _canonical_json(document)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReproducibilityError(f"{label} JSON cannot be canonicalized") from exc


def _validate_json_tree(document: object, *, label: str) -> None:
    stack: list[tuple[object, int]] = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > MAX_REPRODUCIBILITY_JSON_DEPTH:
            raise ReproducibilityError(f"{label} JSON exceeds the nesting depth bound")
        if nodes > MAX_REPRODUCIBILITY_JSON_NODES:
            raise ReproducibilityError(f"{label} JSON exceeds the node-count bound")
        if isinstance(value, dict):
            if not all(type(key) is str for key in value):
                raise ReproducibilityError(f"{label} JSON object key is invalid")
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is float:
            if not math.isfinite(value):
                raise ReproducibilityError(f"{label} JSON contains a non-finite number")
        elif value is not None and type(value) not in (str, int, bool):
            raise ReproducibilityError(f"{label} JSON contains an unsupported value")


def _require_matching_receipts(
    first: ReproducibilityBuildReceipt,
    second: ReproducibilityBuildReceipt,
) -> None:
    if not hmac.compare_digest(first.unsigned_wheel.sha256, second.unsigned_wheel.sha256):
        raise ValueError("reproducibility wheel digests do not match")
    if first.unsigned_wheel.size != second.unsigned_wheel.size:
        raise ValueError("reproducibility wheel sizes do not match")
    if not hmac.compare_digest(first.sbom_canonical_sha256, second.sbom_canonical_sha256):
        raise ValueError("reproducibility SBOM digests do not match")
    if not hmac.compare_digest(
        first.provenance_input_canonical_sha256,
        second.provenance_input_canonical_sha256,
    ):
        raise ValueError("reproducibility provenance-input digests do not match")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "MAX_REPRODUCIBILITY_JSON_BYTES",
    "REPRODUCIBILITY_DOMAIN",
    "REPRODUCIBILITY_SCOPE",
    "ReproducibilityBuildOutputs",
    "ReproducibilityBuildReceipt",
    "ReproducibilityError",
    "ReproducibilityReceipt",
    "verify_two_build_reproducibility",
]
