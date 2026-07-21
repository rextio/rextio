"""Non-authorizing owner-policy bootstrap for the bounded Full C6 profile.

The strict policy parser accepts only a complete, owner-authored manifest.  It
must not be weakened merely to discover what the owner still has to complete.
This module therefore writes a separate, digest-only completion request from
actual observations.  The request contains no source bytes, host paths,
private transaction authority, signature, or distribution authority.

The bootstrap file is deliberately create-if-absent.  An exact existing file
is an idempotent reuse; every alias, link, permission mismatch, changed byte,
or observed race fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Literal
import unicodedata

from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    canonical_json_bytes,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    MAX_FULL_C6_POLICY_ROWS,
    MAX_FULL_C6_POLICY_TRANSFORMATIONS,
)
from rextio.config.schema import RextioConfig


FULL_C6_POLICY_BOOTSTRAP_FILENAME = "rextio.full-c6-policy.bootstrap.json"
FULL_C6_POLICY_BOOTSTRAP_KIND = "full-c6-owner-policy-completion-request"
FULL_C6_POLICY_BOOTSTRAP_DOMAIN = "rextio.full-c6-owner-policy-bootstrap.v1"
FULL_C6_POLICY_BOOTSTRAP_SCHEMA_VERSION = 1

_FULL_C6_DISTRIBUTION_POLICY = "full-c6-required"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_MAX_BOOTSTRAP_BYTES = 256 * 1024
_MAX_STATE_DIRECTORY_ENTRIES = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_TRIPLES = frozenset(
    {
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-gnu",
    }
)
_INPUT_DIGEST_FIELDS = (
    "analysis_ir_transaction_sha256",
    "artifact_coverage_inventory_sha256",
    "artifact_authority_partition_sha256",
    "build_input_closure_sha256",
    "cargo_workspace_sha256",
    "combined_authority_partition_sha256",
    "external_authority_partition_sha256",
    "license_materials_transaction_sha256",
    "source_lock_verification_sha256",
)

FullC6PolicyLifecycleStatus = Literal[
    "disabled",
    "bootstrap-required",
    "signing-required",
    "publication-required",
]


class FullC6PolicyBootstrapError(RuntimeError):
    """The policy bootstrap lifecycle or filesystem transaction failed closed."""


@dataclass(frozen=True, slots=True)
class FullC6PolicyLifecycle:
    """Configuration state before the signed Full C6 pipeline runs.

    ``publication-required`` means that a detached-signature *path* is
    configured.  It is not a published state and grants no authority.  Only
    the later hard gate plus atomic publication receipt may report
    ``published``.
    """

    status: FullC6PolicyLifecycleStatus
    bootstrap_allowed: bool
    owner_policy_pinned: bool
    signing_request_allowed: bool
    publication_attempt_allowed: bool
    published: bool = False

    def __post_init__(self) -> None:
        expected = {
            "disabled": (False, False, False, False),
            "bootstrap-required": (True, False, False, False),
            "signing-required": (False, True, True, False),
            "publication-required": (False, True, True, True),
        }
        if self.status not in expected or (
            self.bootstrap_allowed,
            self.owner_policy_pinned,
            self.signing_request_allowed,
            self.publication_attempt_allowed,
        ) != expected[self.status]:
            raise FullC6PolicyBootstrapError("Full C6 policy lifecycle is inconsistent")
        if self.published is not False:
            raise FullC6PolicyBootstrapError(
                "configuration cannot claim a published Full C6 artifact"
            )


def resolve_full_c6_policy_lifecycle(config: RextioConfig) -> FullC6PolicyLifecycle:
    """Resolve bootstrap, signing, and publication prerequisites from config.

    The resolver intentionally performs no filesystem inference.  In
    particular, a configured final-signature path is only a prerequisite for a
    later verified publication attempt; it cannot mint a ``published`` state.
    """
    if type(config) is not RextioConfig:
        raise FullC6PolicyBootstrapError("Full C6 policy lifecycle requires typed config")
    build = config.build
    if build.artifact_distribution_policy != _FULL_C6_DISTRIBUTION_POLICY:
        return FullC6PolicyLifecycle(
            status="disabled",
            bootstrap_allowed=False,
            owner_policy_pinned=False,
            signing_request_allowed=False,
            publication_attempt_allowed=False,
        )
    manifest = build.artifact_policy_manifest
    manifest_sha256 = build.artifact_policy_manifest_sha256
    final_signature = build.artifact_final_signature
    if type(manifest) is not str or not manifest:
        raise FullC6PolicyBootstrapError(
            "full-c6-required lifecycle lacks an owner policy manifest path"
        )
    if manifest_sha256 is None:
        if final_signature is not None:
            raise FullC6PolicyBootstrapError(
                "policy bootstrap cannot consume a final signature"
            )
        return FullC6PolicyLifecycle(
            status="bootstrap-required",
            bootstrap_allowed=True,
            owner_policy_pinned=False,
            signing_request_allowed=False,
            publication_attempt_allowed=False,
        )
    _require_sha256(manifest_sha256, "owner policy manifest")
    if final_signature is None:
        return FullC6PolicyLifecycle(
            status="signing-required",
            bootstrap_allowed=False,
            owner_policy_pinned=True,
            signing_request_allowed=True,
            publication_attempt_allowed=False,
        )
    if type(final_signature) is not str or not final_signature:
        raise FullC6PolicyBootstrapError("Full C6 final signature path is invalid")
    return FullC6PolicyLifecycle(
        status="publication-required",
        bootstrap_allowed=False,
        owner_policy_pinned=True,
        signing_request_allowed=True,
        publication_attempt_allowed=True,
    )


@dataclass(frozen=True, slots=True)
class FullC6PolicyBootstrapInputs:
    """Path-free scalar projection supplied by the future production collector."""

    analysis_ir_transaction_sha256: str
    artifact_coverage_inventory_sha256: str
    artifact_authority_partition_sha256: str
    build_input_closure_sha256: str
    cargo_workspace_sha256: str
    combined_authority_partition_sha256: str
    external_authority_partition_sha256: str
    license_materials_transaction_sha256: str
    source_lock_verification_sha256: str
    artifact_class_observed_counts: tuple[int, ...]
    external_class_observed_counts: tuple[int, ...]
    artifact_observed_component_count: int
    external_observed_component_count: int
    required_transformation_count: int
    target_triple: str
    build_profile: str = "release"

    def __post_init__(self) -> None:
        for name in _INPUT_DIGEST_FIELDS:
            _require_sha256(getattr(self, name), name)
        counts = (
            self.artifact_observed_component_count,
            self.external_observed_component_count,
            self.required_transformation_count,
        )
        if any(type(value) is not int for value in counts):
            raise FullC6PolicyBootstrapError("Full C6 policy completion counts are invalid")
        row_count = (
            self.artifact_observed_component_count
            + self.external_observed_component_count
        )
        if (
            self.artifact_observed_component_count < 0
            or self.external_observed_component_count < 0
            or not 1 <= row_count <= MAX_FULL_C6_POLICY_ROWS
            or not 1
            <= self.required_transformation_count
            <= MAX_FULL_C6_POLICY_TRANSFORMATIONS
        ):
            raise FullC6PolicyBootstrapError(
                "Full C6 policy completion counts are outside the bounded profile"
            )
        class_counts = (
            (
                self.artifact_class_observed_counts,
                ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
                self.artifact_observed_component_count,
            ),
            (
                self.external_class_observed_counts,
                FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
                self.external_observed_component_count,
            ),
        )
        for observed_counts, class_ids, expected_total in class_counts:
            if (
                type(observed_counts) is not tuple
                or len(observed_counts) != len(class_ids)
                or any(
                    type(value) is not int
                    or value < 0
                    or value > MAX_FULL_C6_POLICY_ROWS
                    for value in observed_counts
                )
                or sum(observed_counts) != expected_total
            ):
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy class coverage counts are not exact"
                )
        if self.target_triple not in _TARGET_TRIPLES:
            raise FullC6PolicyBootstrapError("Full C6 policy bootstrap target is unsupported")
        if self.build_profile != "release":
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap requires the release build profile"
            )

    @property
    def required_policy_row_count(self) -> int:
        """Return the exact C6.14-plus-C5.2 policy row count."""
        return (
            self.artifact_observed_component_count
            + self.external_observed_component_count
        )

    def input_aggregates(self) -> dict[str, str]:
        """Return the exact ordered-by-canonical-JSON digest-only input set."""
        return {name: getattr(self, name) for name in _INPUT_DIGEST_FIELDS}


@dataclass(frozen=True, slots=True)
class FullC6PolicyBootstrapRequest:
    """Canonical, non-authorizing owner-completion request."""

    inputs: FullC6PolicyBootstrapInputs
    trusted_owner_public_key_sha256: str

    def __post_init__(self) -> None:
        if type(self.inputs) is not FullC6PolicyBootstrapInputs:
            raise FullC6PolicyBootstrapError("Full C6 policy bootstrap inputs are invalid")
        _require_sha256(
            self.trusted_owner_public_key_sha256,
            "trusted owner public key",
        )
        if len(self.to_bytes()) > _MAX_BOOTSTRAP_BYTES:
            raise FullC6PolicyBootstrapError("Full C6 policy bootstrap request is too large")

    def _payload(self) -> dict[str, object]:
        inputs = self.inputs
        input_aggregates = inputs.input_aggregates()
        return {
            "authority": "non-authorizing-observation",
            "completion_requirements": {
                "artifact_coverage": {
                    "classes": [
                        {"class_id": class_id, "observed_count": observed_count}
                        for class_id, observed_count in zip(
                            ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
                            inputs.artifact_class_observed_counts,
                            strict=True,
                        )
                    ],
                    "class_count": len(ARTIFACT_POLICY_COVERAGE_CLASS_IDS),
                    "observed_component_count": (
                        inputs.artifact_observed_component_count
                    ),
                    "exact_coverage_required": True,
                },
                "external_authority": {
                    "classes": [
                        {"class_id": class_id, "observed_count": observed_count}
                        for class_id, observed_count in zip(
                            FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
                            inputs.external_class_observed_counts,
                            strict=True,
                        )
                    ],
                    "class_count": len(FULL_C6_EXTERNAL_POLICY_CLASS_IDS),
                    "observed_component_count": (
                        inputs.external_observed_component_count
                    ),
                    "exact_coverage_required": True,
                },
                "policy_rows": {
                    "required_count": inputs.required_policy_row_count,
                    "exact_authority_partition_required": True,
                    "closed_license_disposition_required": True,
                    "closed_transformation_disposition_required": True,
                },
                "transformations": {
                    "required_count": inputs.required_transformation_count,
                    "exact_source_output_coverage_required": True,
                    "analysis_and_lowered_ir_bindings_required": True,
                },
                "owner_declaration_required": True,
                "complete_for_scope_required": True,
            },
            "distribution_authorized": False,
            "domain": FULL_C6_POLICY_BOOTSTRAP_DOMAIN,
            "input_aggregate_set_sha256": _digest(
                {
                    "domain": "rextio.full-c6-policy-bootstrap-input-set.v1",
                    "input_aggregates": input_aggregates,
                }
            ),
            "input_aggregates": input_aggregates,
            "kind": FULL_C6_POLICY_BOOTSTRAP_KIND,
            "owner_completion_required": True,
            "schema_version": FULL_C6_POLICY_BOOTSTRAP_SCHEMA_VERSION,
            "target": {
                "build_profile": inputs.build_profile,
                "target_triple": inputs.target_triple,
            },
            "trusted_owner_public_key_sha256": (
                self.trusted_owner_public_key_sha256
            ),
        }

    @property
    def request_sha256(self) -> str:
        """Return the semantic digest of the completion request payload."""
        return _digest(self._payload())

    def to_dict(self) -> dict[str, object]:
        """Return a path-free digest-only request document."""
        return {**self._payload(), "request_sha256": self.request_sha256}

    def to_bytes(self) -> bytes:
        """Return the sole canonical on-disk encoding."""
        try:
            return canonical_json_bytes(self.to_dict())
        except (TypeError, ValueError, RecursionError) as exc:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap request cannot be serialized"
            ) from exc


def create_configured_full_c6_policy_bootstrap_request(
    *,
    config: RextioConfig,
    inputs: FullC6PolicyBootstrapInputs,
) -> FullC6PolicyBootstrapRequest:
    """Create the request only for the strict path-without-digest lifecycle."""
    lifecycle = resolve_full_c6_policy_lifecycle(config)
    if lifecycle.status != "bootstrap-required" or not lifecycle.bootstrap_allowed:
        raise FullC6PolicyBootstrapError(
            "Full C6 owner policy bootstrap is not required by configuration"
        )
    trusted_key_sha256 = config.build.artifact_trusted_public_key_sha256
    if type(trusted_key_sha256) is not str:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap lacks a trusted public-key digest"
        )
    return FullC6PolicyBootstrapRequest(
        inputs=inputs,
        trusted_owner_public_key_sha256=trusted_key_sha256,
    )


@dataclass(frozen=True, slots=True)
class FullC6PolicyBootstrapMaterialization:
    """Path-free result of one secure create-or-exact-reuse transaction."""

    filename: str
    request_sha256: str
    size: int
    created: bool
    status: str = "bootstrap-required"
    distribution_authorized: bool = False

    def __post_init__(self) -> None:
        if (
            self.filename != FULL_C6_POLICY_BOOTSTRAP_FILENAME
            or not _is_sha256(self.request_sha256)
            or type(self.size) is not int
            or not 0 < self.size <= _MAX_BOOTSTRAP_BYTES
            or type(self.created) is not bool
            or self.status != "bootstrap-required"
            or self.distribution_authorized is not False
        ):
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap materialization is invalid"
            )

    def to_dict(self) -> dict[str, object]:
        """Return a non-authorizing result without a machine-local path."""
        return {
            "created": self.created,
            "distribution_authorized": False,
            "filename": self.filename,
            "request_sha256": self.request_sha256,
            "size": self.size,
            "status": self.status,
        }


def materialize_full_c6_policy_bootstrap_request(
    *,
    state_directory: Path | str,
    request: FullC6PolicyBootstrapRequest,
) -> FullC6PolicyBootstrapMaterialization:
    """Create the canonical private bootstrap file or reuse exact safe bytes."""
    if type(request) is not FullC6PolicyBootstrapRequest:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap requires a typed request"
        )
    payload = request.to_bytes()
    if not payload or len(payload) > _MAX_BOOTSTRAP_BYTES:
        raise FullC6PolicyBootstrapError("Full C6 policy bootstrap bytes are invalid")
    state_path: Path | str = state_directory
    root_fd = _open_private_state_directory(state_path)
    root_identity = _directory_identity(os.fstat(root_fd))
    created = False
    try:
        _require_no_bootstrap_filename_aliases(root_fd)
        nofollow = _require_nofollow()
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow
        )
        try:
            descriptor = os.open(
                FULL_C6_POLICY_BOOTSTRAP_FILENAME,
                flags,
                _FILE_MODE,
                dir_fd=root_fd,
            )
        except FileExistsError:
            existing, _stamp = _read_private_file(root_fd)
            if not hmac.compare_digest(existing, payload):
                raise FullC6PolicyBootstrapError(
                    "existing Full C6 policy bootstrap bytes differ"
                ) from None
        except OSError as exc:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap file cannot be created"
            ) from exc
        else:
            created = True
            try:
                os.fchmod(descriptor, _FILE_MODE)
                _write_all(descriptor, payload)
                os.fsync(descriptor)
                written = os.fstat(descriptor)
                _require_private_file_stat(written, expected_size=len(payload))
                linked = os.stat(
                    FULL_C6_POLICY_BOOTSTRAP_FILENAME,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                if _stat_identity(written) != _stat_identity(linked):
                    raise FullC6PolicyBootstrapError(
                        "Full C6 policy bootstrap file changed while writing"
                    )
            except Exception as exc:
                _unlink_created_file(root_fd, descriptor)
                if isinstance(exc, FullC6PolicyBootstrapError):
                    raise
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap file changed while writing"
                ) from exc
            finally:
                os.close(descriptor)
            observed, stamp = _read_private_file(root_fd)
            if not hmac.compare_digest(observed, payload) or (
                _stat_identity(stamp) != _stat_identity(written)
            ):
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap final bytes changed"
                )
            try:
                os.fsync(root_fd)
            except OSError as exc:
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap state synchronization failed"
                ) from exc
        _require_no_bootstrap_filename_aliases(root_fd)
        _verify_private_state_directory(state_path, root_identity)
    finally:
        os.close(root_fd)
    return FullC6PolicyBootstrapMaterialization(
        filename=FULL_C6_POLICY_BOOTSTRAP_FILENAME,
        request_sha256=request.request_sha256,
        size=len(payload),
        created=created,
    )


def materialize_configured_full_c6_policy_bootstrap(
    *,
    state_directory: Path | str,
    config: RextioConfig,
    inputs: FullC6PolicyBootstrapInputs,
) -> FullC6PolicyBootstrapMaterialization:
    """Create and materialize one configured bootstrap transaction."""
    request = create_configured_full_c6_policy_bootstrap_request(
        config=config,
        inputs=inputs,
    )
    return materialize_full_c6_policy_bootstrap_request(
        state_directory=state_directory,
        request=request,
    )


def _open_private_state_directory(path: Path | str) -> int:
    parts = _validated_absolute_state_path(path)
    nofollow = _require_nofollow()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | nofollow
    )
    try:
        descriptor = os.open("/", flags)
    except OSError as exc:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap filesystem root cannot be opened"
        ) from exc
    try:
        for component in parts:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap state path must be a symlink-free "
                    "directory walk"
                ) from exc
            try:
                opened = os.fstat(child)
                linked = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _directory_identity(opened) != _directory_identity(linked)
                ):
                    raise FullC6PolicyBootstrapError(
                        "Full C6 policy bootstrap state path changed during its "
                        "symlink-free directory walk"
                    )
            except Exception as exc:
                os.close(child)
                if isinstance(exc, FullC6PolicyBootstrapError):
                    raise
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap state path changed during its "
                    "symlink-free directory walk"
                ) from exc
            os.close(descriptor)
            descriptor = child
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != _DIRECTORY_MODE
            or observed.st_uid != os.getuid()
        ):
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap state directory must be owner-owned mode 0700"
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _verify_private_state_directory(
    path: Path | str,
    expected_identity: tuple[int, int, int, int],
) -> None:
    descriptor = _open_private_state_directory(path)
    try:
        if _directory_identity(os.fstat(descriptor)) != expected_identity:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap state directory changed during materialization"
            )
    finally:
        os.close(descriptor)


def _validated_absolute_state_path(path: Path | str) -> tuple[str, ...]:
    if isinstance(path, Path):
        value = str(path)
    elif type(path) is str:
        value = path
    else:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state path must be a string or Path"
        )
    if (
        not value.startswith("/")
        or value.startswith("//")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
    ):
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state path must be absolute and lexically canonical"
        )
    if unicodedata.normalize("NFC", value) != value:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state path must be NFC-normalized"
        )
    parts = tuple(value.split("/")[1:])
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state path must be absolute and lexically canonical"
        )
    return parts


def _require_no_bootstrap_filename_aliases(root_fd: int) -> None:
    try:
        names = os.listdir(root_fd)
    except OSError as exc:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state directory inventory failed"
        ) from exc
    if len(names) > _MAX_STATE_DIRECTORY_ENTRIES:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap state directory inventory exceeds the bound"
        )
    canonical_alias = unicodedata.normalize(
        "NFC", FULL_C6_POLICY_BOOTSTRAP_FILENAME
    ).casefold()
    for name in names:
        try:
            alias = unicodedata.normalize("NFC", name).casefold()
        except (TypeError, ValueError, UnicodeError) as exc:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap state directory contains an invalid name"
            ) from exc
        if alias == canonical_alias and name != FULL_C6_POLICY_BOOTSTRAP_FILENAME:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap canonical filename has a casefold/NFC alias"
            )


def _read_private_file(root_fd: int) -> tuple[bytes, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | _require_nofollow()
    )
    try:
        descriptor = os.open(
            FULL_C6_POLICY_BOOTSTRAP_FILENAME,
            flags,
            dir_fd=root_fd,
        )
    except OSError as exc:
        raise FullC6PolicyBootstrapError(
            "existing Full C6 policy bootstrap file is unsafe"
        ) from exc
    try:
        before = os.fstat(descriptor)
        _require_private_file_stat(before)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise FullC6PolicyBootstrapError(
                    "Full C6 policy bootstrap file was truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap file grew while reading"
            )
        after = os.fstat(descriptor)
        linked = os.stat(
            FULL_C6_POLICY_BOOTSTRAP_FILENAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(linked)
        ):
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap file changed while reading"
            )
        return b"".join(chunks), after
    except OSError as exc:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap file cannot be read"
        ) from exc
    finally:
        os.close(descriptor)


def _require_private_file_stat(
    observed: os.stat_result,
    *,
    expected_size: int | None = None,
) -> None:
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != _FILE_MODE
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or not 0 < observed.st_size <= _MAX_BOOTSTRAP_BYTES
        or (expected_size is not None and observed.st_size != expected_size)
    ):
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap must be an owner-owned mode 0600 single-link file"
        )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as exc:
            raise FullC6PolicyBootstrapError(
                "Full C6 policy bootstrap write failed"
            ) from exc
        if written <= 0:
            raise FullC6PolicyBootstrapError("Full C6 policy bootstrap write stalled")
        offset += written


def _unlink_created_file(root_fd: int, descriptor: int) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(
            FULL_C6_POLICY_BOOTSTRAP_FILENAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if _stat_identity(opened) == _stat_identity(linked):
            os.unlink(FULL_C6_POLICY_BOOTSTRAP_FILENAME, dir_fd=root_fd)
    except OSError:
        pass


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_nlink,
        value.st_size,
        value.st_ctime_ns,
        value.st_mtime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
    )


def _require_nofollow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if type(value) is not int or value == 0:
        raise FullC6PolicyBootstrapError(
            "Full C6 policy bootstrap requires O_NOFOLLOW support"
        )
    return value


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise FullC6PolicyBootstrapError(f"{label} must be a lowercase SHA-256 digest")
    assert isinstance(value, str)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "FULL_C6_POLICY_BOOTSTRAP_DOMAIN",
    "FULL_C6_POLICY_BOOTSTRAP_FILENAME",
    "FULL_C6_POLICY_BOOTSTRAP_KIND",
    "FULL_C6_POLICY_BOOTSTRAP_SCHEMA_VERSION",
    "FullC6PolicyBootstrapError",
    "FullC6PolicyBootstrapInputs",
    "FullC6PolicyBootstrapMaterialization",
    "FullC6PolicyBootstrapRequest",
    "FullC6PolicyLifecycle",
    "FullC6PolicyLifecycleStatus",
    "create_configured_full_c6_policy_bootstrap_request",
    "materialize_configured_full_c6_policy_bootstrap",
    "materialize_full_c6_policy_bootstrap_request",
    "resolve_full_c6_policy_lifecycle",
]
