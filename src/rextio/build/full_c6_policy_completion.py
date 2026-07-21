"""Strict offline owner completion for a Full C6 technical bootstrap."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePath
import re
import stat
from typing import Literal
import unicodedata

from rextio.artifacts.evidence import canonical_json_bytes
from rextio.build.full_c6_policy import (
    FULL_C6_LICENSE_DETECTOR_RECEIPT_KIND,
    MAX_FULL_C6_LICENSE_FILES_PER_ROW,
    MAX_FULL_C6_POLICY_ROWS,
    MAX_FULL_C6_POLICY_SERIALIZED_BYTES,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_policy_bootstrap import (
    FullC6PolicyBootstrapRequest,
    parse_full_c6_policy_bootstrap_request,
)
from rextio.build.full_c6_policy_manifest import (
    full_c6_policy_manifest_bytes,
    parse_full_c6_owner_declaration_document,
)
from rextio.build.full_c6_policy_template import (
    MAX_FULL_C6_POLICY_TEMPLATE_BYTES,
    FullC6ExternalLicenseObservation,
    FullC6InternalLicenseObservation,
    FullC6TechnicalPolicyRow,
)
from rextio.build.owner_policy_lock import read_strict_owner_policy_lock


FULL_C6_POLICY_COMPLETION_KIND = "full-c6-owner-policy-completion"
FULL_C6_POLICY_COMPLETION_DOMAIN = "rextio.full-c6-owner-policy-completion.v1"
FULL_C6_POLICY_COMPLETION_SCHEMA_VERSION = 1
FULL_C6_TRANSFORMATION_ACCEPTANCE = "accept-exact-observed-transformation-set"
MAX_FULL_C6_POLICY_COMPLETION_BYTES = MAX_FULL_C6_POLICY_SERIALIZED_BYTES
_MAX_FINALIZE_INPUT_BYTES = MAX_FULL_C6_POLICY_TEMPLATE_BYTES + 256 * 1024
_MAX_JSON_DEPTH = 40
_FILE_MODE = 0o600
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FullC6PolicyCompletionError(ValueError):
    """Owner completion or its filesystem transaction failed closed."""


@dataclass(frozen=True, slots=True)
class FullC6OwnerLicenseDecision:
    """One explicit owner allow decision and exact supporting observation."""

    authority_identity: str
    declared_spdx: str
    detected_spdx: str
    source_detector_receipt_sha256: str
    detector_payload_sha256: str
    license_files: tuple[FullC6PolicyFileIdentity, ...]
    evidence_origin: Literal[
        "owner-project-observation",
        "production-external-observation",
    ]
    decision: str = "allow"

    def __post_init__(self) -> None:
        if type(self.authority_identity) is not str or not self.authority_identity:
            raise FullC6PolicyCompletionError("Full C6 license authority identity is missing")
        if self.decision != "allow":
            raise FullC6PolicyCompletionError("Full C6 license decision must be explicit allow")
        if self.evidence_origin not in {
            "owner-project-observation",
            "production-external-observation",
        }:
            raise FullC6PolicyCompletionError("Full C6 license evidence origin is invalid")
        if (
            type(self.declared_spdx) is not str
            or not self.declared_spdx
            or type(self.detected_spdx) is not str
            or not self.detected_spdx
        ):
            raise FullC6PolicyCompletionError("Full C6 license SPDX values are missing")
        if not _is_sha256(self.source_detector_receipt_sha256):
            raise FullC6PolicyCompletionError("Full C6 source detector receipt is invalid")
        if (
            type(self.license_files) is not tuple
            or not self.license_files
            or len(self.license_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW
            or any(type(item) is not FullC6PolicyFileIdentity for item in self.license_files)
        ):
            raise FullC6PolicyCompletionError("Full C6 license files are invalid")
        expected = full_c6_license_detector_payload_digest(
            self.detected_spdx,
            self.license_files,
            source_detector_receipt_sha256=self.source_detector_receipt_sha256,
        )
        if self.detector_payload_sha256 != expected:
            raise FullC6PolicyCompletionError("Full C6 license detector payload is stale")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical explicit per-row owner decision."""
        return {
            "authority_identity": self.authority_identity,
            "decision": "allow",
            "declared_spdx": self.declared_spdx,
            "detected_spdx": self.detected_spdx,
            "source_detector_receipt_sha256": self.source_detector_receipt_sha256,
            "detector_payload_sha256": self.detector_payload_sha256,
            "license_files": [item.to_dict() for item in self.license_files],
            "evidence_origin": self.evidence_origin,
            "legal_advice_inferred": False,
        }


@dataclass(frozen=True, slots=True)
class FullC6OwnerPolicyCompletion:
    """Canonical owner-authored decisions pinned to one exact bootstrap."""

    bootstrap_request_sha256: str
    transformation_set_sha256: str
    owner_declaration: FullC6OwnerDeclaration
    license_decisions: tuple[FullC6OwnerLicenseDecision, ...]
    transformation_decision: str = FULL_C6_TRANSFORMATION_ACCEPTANCE

    def __post_init__(self) -> None:
        if not _is_sha256(self.bootstrap_request_sha256) or not _is_sha256(
            self.transformation_set_sha256
        ):
            raise FullC6PolicyCompletionError("Full C6 completion pin is invalid")
        if type(self.owner_declaration) is not FullC6OwnerDeclaration:
            raise FullC6PolicyCompletionError("Full C6 owner declaration is invalid")
        if self.transformation_decision != FULL_C6_TRANSFORMATION_ACCEPTANCE:
            raise FullC6PolicyCompletionError(
                "Full C6 transformation set was not explicitly accepted"
            )
        if (
            type(self.license_decisions) is not tuple
            or not self.license_decisions
            or len(self.license_decisions) > MAX_FULL_C6_POLICY_ROWS
            or any(
                type(item) is not FullC6OwnerLicenseDecision
                for item in self.license_decisions
            )
        ):
            raise FullC6PolicyCompletionError("Full C6 license decisions are invalid")
        identities = tuple(item.authority_identity for item in self.license_decisions)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise FullC6PolicyCompletionError(
                "Full C6 license decisions are noncanonical or duplicated"
            )
        if len(self.to_bytes()) > MAX_FULL_C6_POLICY_COMPLETION_BYTES:
            raise FullC6PolicyCompletionError("Full C6 completion exceeds byte bound")

    def _payload(self) -> dict[str, object]:
        return {
            "kind": FULL_C6_POLICY_COMPLETION_KIND,
            "schema_version": FULL_C6_POLICY_COMPLETION_SCHEMA_VERSION,
            "domain": FULL_C6_POLICY_COMPLETION_DOMAIN,
            "bootstrap_request_sha256": self.bootstrap_request_sha256,
            "transformation_acceptance": {
                "decision": FULL_C6_TRANSFORMATION_ACCEPTANCE,
                "transformation_set_sha256": self.transformation_set_sha256,
            },
            "owner_declaration": self.owner_declaration.to_dict(),
            "license_decisions": [item.to_dict() for item in self.license_decisions],
            "private_key_present": False,
            "signature_present": False,
            "legal_advice_inferred": False,
            "distribution_authorized": False,
        }

    @property
    def completion_sha256(self) -> str:
        """Return the semantic identity of the explicit owner completion."""
        return _digest(self._payload())

    def to_dict(self) -> dict[str, object]:
        """Return the strict non-authorizing completion document."""
        return {**self._payload(), "completion_sha256": self.completion_sha256}

    def to_bytes(self) -> bytes:
        """Return canonical bounded completion JSON."""
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class FullC6PolicyFinalizeResult:
    """Path-free result of an offline canonical manifest finalization."""

    bootstrap_request_sha256: str
    completion_sha256: str
    manifest_sha256: str
    size: int
    created: bool

    def to_dict(self) -> dict[str, object]:
        """Return the non-authorizing offline finalization receipt."""
        return {
            "status": "full-c6-policy-finalized",
            "bootstrap_request_sha256": self.bootstrap_request_sha256,
            "completion_sha256": self.completion_sha256,
            "manifest_sha256": self.manifest_sha256,
            "size": self.size,
            "created": self.created,
            "signed": False,
            "distribution_authorized": False,
        }


def parse_full_c6_owner_policy_completion(value: bytes) -> FullC6OwnerPolicyCompletion:
    """Parse exact canonical owner-completion bytes with no defaults."""
    document = _strict_json_bytes(value, max_bytes=MAX_FULL_C6_POLICY_COMPLETION_BYTES)
    if canonical_json_bytes(document) != value:
        raise FullC6PolicyCompletionError("Full C6 completion JSON is not canonical")
    data = _exact_dict(document, _COMPLETION_FIELDS, "completion")
    if (
        data["kind"] != FULL_C6_POLICY_COMPLETION_KIND
        or type(data["schema_version"]) is not int
        or data["schema_version"] != FULL_C6_POLICY_COMPLETION_SCHEMA_VERSION
        or data["domain"] != FULL_C6_POLICY_COMPLETION_DOMAIN
        or data["private_key_present"] is not False
        or data["signature_present"] is not False
        or data["legal_advice_inferred"] is not False
        or data["distribution_authorized"] is not False
    ):
        raise FullC6PolicyCompletionError("Full C6 completion claims invalid authority")
    acceptance = _exact_dict(
        data["transformation_acceptance"],
        {"decision", "transformation_set_sha256"},
        "transformation acceptance",
    )
    decisions = _exact_list(data["license_decisions"], "license decisions")
    try:
        completion = FullC6OwnerPolicyCompletion(
            bootstrap_request_sha256=_sha256(
                data["bootstrap_request_sha256"], "bootstrap request"
            ),
            transformation_set_sha256=_sha256(
                acceptance["transformation_set_sha256"], "transformation set"
            ),
            transformation_decision=_string(
                acceptance["decision"], "transformation decision"
            ),
            owner_declaration=parse_full_c6_owner_declaration_document(
                data["owner_declaration"]
            ),
            license_decisions=tuple(_parse_license_decision(item) for item in decisions),
        )
    except FullC6PolicyCompletionError:
        raise
    except (TypeError, ValueError) as exc:
        raise FullC6PolicyCompletionError("Full C6 completion values are invalid") from exc
    if (
        data["completion_sha256"] != completion.completion_sha256
        or completion.to_bytes() != value
    ):
        raise FullC6PolicyCompletionError("Full C6 completion is stale or noncanonical")
    return completion


def finalize_full_c6_policy_manifest(
    *,
    bootstrap: FullC6PolicyBootstrapRequest,
    completion: FullC6OwnerPolicyCompletion,
) -> bytes:
    """Create canonical final manifest bytes from exact technical facts and decisions."""
    if type(bootstrap) is not FullC6PolicyBootstrapRequest or type(
        completion
    ) is not FullC6OwnerPolicyCompletion:
        raise FullC6PolicyCompletionError("Full C6 finalization requires typed inputs")
    template = bootstrap.technical_template
    if not hmac.compare_digest(
        completion.bootstrap_request_sha256,
        bootstrap.request_sha256,
    ):
        raise FullC6PolicyCompletionError("Full C6 completion targets another bootstrap")
    if not hmac.compare_digest(
        completion.transformation_set_sha256,
        template.transformation_set_sha256,
    ):
        raise FullC6PolicyCompletionError("Full C6 completion accepts another transformation set")
    owner = completion.owner_declaration
    if owner.owner_identity != template.observed_owner_identity:
        raise FullC6PolicyCompletionError("Full C6 owner identity differs from SourceLock")
    if not hmac.compare_digest(
        owner.trusted_public_key_sha256,
        bootstrap.trusted_owner_public_key_sha256,
    ):
        raise FullC6PolicyCompletionError("Full C6 owner key differs from the bootstrap pin")
    applicable = tuple(
        row
        for row in template.rows
        if row.required_license_disposition == "owner-approved-allow"
    )
    decisions = {item.authority_identity: item for item in completion.license_decisions}
    if set(decisions) != {item.authority_identity for item in applicable}:
        raise FullC6PolicyCompletionError(
            "Full C6 completion does not decide every license-applicable row exactly once"
        )
    rows = tuple(
        _completed_row(
            row,
            decision=decisions.get(row.authority_identity),
            bootstrap=bootstrap,
        )
        for row in template.rows
    )
    receipt = FullC6PolicyReceipt(
        rows=rows,
        transformations=template.transformations,
        owner_declaration=owner,
        artifact_coverage=template.artifact_coverage,
        external_authority=template.external_authority,
        bootstrap_request_sha256=bootstrap.request_sha256,
    )
    return full_c6_policy_manifest_bytes(receipt)


def finalize_full_c6_policy_files(
    *,
    bootstrap_path: Path,
    completion_path: Path,
    output_path: Path,
) -> FullC6PolicyFinalizeResult:
    """Read strict inputs and atomically create or exactly reuse one final manifest."""
    bootstrap_bytes = _read_strict_path(bootstrap_path, _MAX_FINALIZE_INPUT_BYTES)
    bootstrap = parse_full_c6_policy_bootstrap_request(bootstrap_bytes)
    completion_bytes = _read_strict_path(
        completion_path,
        MAX_FULL_C6_POLICY_COMPLETION_BYTES,
    )
    completion = parse_full_c6_owner_policy_completion(completion_bytes)
    manifest = finalize_full_c6_policy_manifest(
        bootstrap=bootstrap,
        completion=completion,
    )
    created = _atomic_create_or_exact_reuse(output_path, manifest)
    return FullC6PolicyFinalizeResult(
        bootstrap_request_sha256=bootstrap.request_sha256,
        completion_sha256=completion.completion_sha256,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        size=len(manifest),
        created=created,
    )


def _completed_row(
    row: FullC6TechnicalPolicyRow,
    *,
    decision: FullC6OwnerLicenseDecision | None,
    bootstrap: FullC6PolicyBootstrapRequest,
) -> FullC6PolicyInputRow:
    evidence = None
    if row.required_license_disposition == "owner-approved-allow":
        if decision is None or decision.evidence_origin != row.license_evidence_origin:
            raise FullC6PolicyCompletionError("Full C6 row lacks its explicit license decision")
        observation: (
            FullC6ExternalLicenseObservation | FullC6InternalLicenseObservation
        )
        if decision.evidence_origin == "production-external-observation":
            observation = bootstrap.technical_template.external_license_observation
            mismatch = "independent wheel observation"
        else:
            matches = tuple(
                item
                for item in bootstrap.technical_template.internal_license_observations
                if item.observation_sha256 == row.license_observation_sha256
            )
            if len(matches) != 1:
                raise FullC6PolicyCompletionError(
                    "Full C6 row lacks exact internal license materials"
                )
            observation = matches[0]
            mismatch = "production license-material observation"
        if (
            decision.declared_spdx != observation.declared_spdx
            or decision.detected_spdx != observation.detected_spdx
            or decision.source_detector_receipt_sha256
            != observation.source_detector_receipt_sha256
            or decision.detector_payload_sha256 != observation.detector_payload_sha256
            or decision.license_files != observation.license_files
        ):
            raise FullC6PolicyCompletionError(
                f"Full C6 decision differs from {mismatch}"
            )
        evidence = FullC6LicenseEvidence(
            declared_spdx=decision.declared_spdx,
            detected_spdx=decision.detected_spdx,
            subject_authority_identity=row.authority_identity,
            subject_identity_sha256=row.canonical_identity_sha256,
            authority_partition_sha256=(
                bootstrap.technical_template.authority_partition_sha256
            ),
            source_detector_receipt_sha256=(
                decision.source_detector_receipt_sha256
            ),
            detector_payload_sha256=decision.detector_payload_sha256,
            license_files=decision.license_files,
            detector_receipt_kind=FULL_C6_LICENSE_DETECTOR_RECEIPT_KIND,
        )
    elif decision is not None:
        raise FullC6PolicyCompletionError("Full C6 non-applicable row has a license decision")
    return FullC6PolicyInputRow(
        class_id=row.class_id,
        canonical_identity=row.canonical_identity,
        authority_identity=row.authority_identity,
        identity_mode=row.identity_mode,
        sha256=row.sha256,
        size=row.size,
        license_disposition=row.required_license_disposition,
        transformation_disposition=row.transformation_disposition,
        license_evidence=evidence,
    )


def _parse_license_decision(value: object) -> FullC6OwnerLicenseDecision:
    data = _exact_dict(value, _LICENSE_DECISION_FIELDS, "license decision")
    if data["legal_advice_inferred"] is not False:
        raise FullC6PolicyCompletionError("Full C6 completion cannot infer legal advice")
    files = _exact_list(data["license_files"], "license files")
    return FullC6OwnerLicenseDecision(
        authority_identity=_string(data["authority_identity"], "authority identity"),
        decision=_string(data["decision"], "license decision"),
        declared_spdx=_string(data["declared_spdx"], "declared SPDX"),
        detected_spdx=_string(data["detected_spdx"], "detected SPDX"),
        source_detector_receipt_sha256=_sha256(
            data["source_detector_receipt_sha256"], "source detector receipt"
        ),
        detector_payload_sha256=_sha256(
            data["detector_payload_sha256"], "detector payload"
        ),
        license_files=tuple(_parse_policy_file(item) for item in files),
        evidence_origin=_string(data["evidence_origin"], "evidence origin"),  # type: ignore[arg-type]
    )


def _parse_policy_file(value: object) -> FullC6PolicyFileIdentity:
    data = _exact_dict(
        value,
        {"logical_path", "sha256", "size", "role"},
        "license file",
    )
    return FullC6PolicyFileIdentity(
        logical_path=_string(data["logical_path"], "license path"),
        sha256=_sha256(data["sha256"], "license file"),
        size=_integer(data["size"], "license size"),
        role=_string(data["role"], "license role"),
    )


def _read_strict_path(path: Path, max_bytes: int) -> bytes:
    if not _is_absolute_lexical_path(path):
        raise FullC6PolicyCompletionError("Full C6 policy path must be absolute")
    try:
        locked = read_strict_owner_policy_lock(
            project_root=path.parent,
            filename=path.name,
            max_bytes=max_bytes,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise FullC6PolicyCompletionError("Full C6 policy input file is unsafe") from exc
    return locked.data


def _atomic_create_or_exact_reuse(path: Path, payload: bytes) -> bool:
    if (
        not _is_absolute_lexical_path(path)
        or PurePath(path.name).name != path.name
        or not payload
    ):
        raise FullC6PolicyCompletionError("Full C6 policy output path is invalid")
    try:
        parent_fd = _open_absolute_directory(path.parent)
    except FullC6PolicyCompletionError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise FullC6PolicyCompletionError(
            "Full C6 policy output transaction failed"
        ) from exc
    temporary = f".{path.name}.rextio-{os.getpid()}-{hashlib.sha256(payload).hexdigest()[:16]}.tmp"
    descriptor = -1
    created_temp = False
    try:
        try:
            existing = read_strict_owner_policy_lock(
                project_root=path.parent,
                filename=path.name,
                max_bytes=MAX_FULL_C6_POLICY_SERIALIZED_BYTES + 64 * 1024,
            )
        except (OSError, ValueError):
            existing = None
        if existing is not None:
            if not hmac.compare_digest(existing.data, payload):
                raise FullC6PolicyCompletionError(
                    "existing Full C6 policy output bytes differ"
                )
            return False
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | _require_nofollow()
        )
        descriptor = os.open(temporary, flags, _FILE_MODE, dir_fd=parent_fd)
        created_temp = True
        os.fchmod(descriptor, _FILE_MODE)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != len(payload):
            raise FullC6PolicyCompletionError("Full C6 policy temporary output is unsafe")
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = read_strict_owner_policy_lock(
                project_root=path.parent,
                filename=path.name,
                max_bytes=MAX_FULL_C6_POLICY_SERIALIZED_BYTES + 64 * 1024,
            )
            if not hmac.compare_digest(existing.data, payload):
                raise FullC6PolicyCompletionError(
                    "concurrent Full C6 policy output bytes differ"
                ) from None
            return False
        os.unlink(temporary, dir_fd=parent_fd)
        created_temp = False
        os.fsync(parent_fd)
        final = read_strict_owner_policy_lock(
            project_root=path.parent,
            filename=path.name,
            max_bytes=MAX_FULL_C6_POLICY_SERIALIZED_BYTES + 64 * 1024,
        )
        if not hmac.compare_digest(final.data, payload):
            raise FullC6PolicyCompletionError("Full C6 policy final bytes changed")
        return True
    except FullC6PolicyCompletionError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise FullC6PolicyCompletionError("Full C6 policy output transaction failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created_temp:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def _is_absolute_lexical_path(path: object) -> bool:
    if not isinstance(path, Path):
        return False
    text = str(path)
    return (
        path.is_absolute()
        and unicodedata.normalize("NFC", text) == text
        and ".." not in path.parts
        and path == Path(os.path.abspath(path))
    )


def _open_absolute_directory(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = (
        os.O_RDONLY
        | _require_nofollow()
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            if part in {"", ".", ".."} or "/" in part or "\\" in part:
                raise FullC6PolicyCompletionError("Full C6 policy output path is unsafe")
            child = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            linked = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_dev != linked.st_dev
                or opened.st_ino != linked.st_ino
            ):
                os.close(child)
                raise FullC6PolicyCompletionError("Full C6 policy output path changed")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise FullC6PolicyCompletionError("Full C6 policy output write stalled")
        offset += written


def _require_nofollow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if type(value) is not int or value == 0:
        raise FullC6PolicyCompletionError("Full C6 policy finalization requires O_NOFOLLOW")
    return value


def _strict_json_bytes(value: bytes, *, max_bytes: int) -> dict[str, object]:
    if type(value) is not bytes or not value or len(value) > max_bytes:
        raise FullC6PolicyCompletionError("Full C6 completion bytes are invalid")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise FullC6PolicyCompletionError("Full C6 completion has duplicate keys")
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise FullC6PolicyCompletionError("Full C6 completion has non-finite JSON")

    try:
        document = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except FullC6PolicyCompletionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FullC6PolicyCompletionError("Full C6 completion JSON is invalid") from exc
    if type(document) is not dict:
        raise FullC6PolicyCompletionError("Full C6 completion root must be an object")
    _assert_depth(document, depth=0)
    return document


def _assert_depth(value: object, *, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise FullC6PolicyCompletionError("Full C6 completion nesting is too deep")
    if type(value) is dict:
        for child in value.values():
            _assert_depth(child, depth=depth + 1)
    elif type(value) is list:
        for child in value:
            _assert_depth(child, depth=depth + 1)


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise FullC6PolicyCompletionError(f"Full C6 {label} schema is invalid")
    return value


def _exact_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise FullC6PolicyCompletionError(f"Full C6 {label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if type(value) is not str:
        raise FullC6PolicyCompletionError(f"Full C6 {label} must be a string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise FullC6PolicyCompletionError(f"Full C6 {label} must be an integer")
    return value


def _sha256(value: object, label: str) -> str:
    result = _string(value, label)
    if not _is_sha256(result):
        raise FullC6PolicyCompletionError(f"Full C6 {label} must be SHA-256")
    return result


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


_LICENSE_DECISION_FIELDS = {
    "authority_identity",
    "decision",
    "declared_spdx",
    "detected_spdx",
    "source_detector_receipt_sha256",
    "detector_payload_sha256",
    "license_files",
    "evidence_origin",
    "legal_advice_inferred",
}
_COMPLETION_FIELDS = {
    "kind",
    "schema_version",
    "domain",
    "bootstrap_request_sha256",
    "transformation_acceptance",
    "owner_declaration",
    "license_decisions",
    "private_key_present",
    "signature_present",
    "legal_advice_inferred",
    "distribution_authorized",
    "completion_sha256",
}

__all__ = [
    "FULL_C6_POLICY_COMPLETION_DOMAIN",
    "FULL_C6_POLICY_COMPLETION_KIND",
    "FULL_C6_POLICY_COMPLETION_SCHEMA_VERSION",
    "FULL_C6_TRANSFORMATION_ACCEPTANCE",
    "FullC6OwnerLicenseDecision",
    "FullC6OwnerPolicyCompletion",
    "FullC6PolicyCompletionError",
    "FullC6PolicyFinalizeResult",
    "finalize_full_c6_policy_files",
    "finalize_full_c6_policy_manifest",
    "parse_full_c6_owner_policy_completion",
]
