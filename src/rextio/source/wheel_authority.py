"""Exact, non-executing source-wheel authority for the bounded C5.2 slice.

The verifier reads one explicitly configured wheel through a pinned descriptor,
parses only the resulting immutable bytes, and never extracts or imports it.
Successful output is analysis input authority only; it is neither build nor
distribution authorization.
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import hmac
import io
import os
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

from rextio.source.external import (
    MAX_AUTHORITY_PATH_LEN,
    MAX_FILE_BYTES,
    MAX_RECORD_ENTRIES,
    MAX_SOURCE_MODULES,
    AuthorityFile,
    ExternalSourcePlan,
    _canonical_name,
    _dist_info_root,
    _parse_distribution_metadata,
)
from rextio.source.external_analysis import ExternalSourceSnapshot
from rextio.source.models import SourceModule, SourceOrigin


SOURCE_WHEEL_AUTHORITY_DOMAIN = "rextio.external-source-wheel-authority.v1"
SOURCE_WHEEL_LICENSE_DETECTION_DOMAIN = "rextio.source-wheel-license-detection.v1"
SOURCE_WHEEL_LICENSE_DETECTION_KIND = "bounded-license-text-detection"
SOURCE_WHEEL_LICENSE_DETECTOR = "rextio-mit-license-text"
SOURCE_WHEEL_LICENSE_DETECTOR_VERSION = "1"
_MIT_LICENSE_TITLES = ("MIT License",)
_MIT_COPYRIGHT = re.compile(
    r"Copyright(?: \(c\)| ©)? [0-9]{4}(?:-[0-9]{4})? "
    r"[A-Za-z0-9][A-Za-z0-9 .,_+@()&'/-]{0,200}"
)
_MIT_LICENSE_CANONICAL_BODY = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""
_MIT_LICENSE_RULESET = (
    f"titles={','.join(_MIT_LICENSE_TITLES)}\n"
    f"copyright_regex={_MIT_COPYRIGHT.pattern}\n"
    "copyright_lines=1..4\n"
    f"body={_MIT_LICENSE_CANONICAL_BODY}"
)
SOURCE_WHEEL_LICENSE_DETECTOR_RULESET_SHA256 = hashlib.sha256(
    b"rextio.source-wheel-license-detection.ruleset.v1\0MIT\0one-file\0"
    + _MIT_LICENSE_RULESET.encode("utf-8")
).hexdigest()
MAX_SOURCE_WHEEL_BYTES = 128 * 1024 * 1024
MAX_SOURCE_WHEEL_ENTRIES = MAX_RECORD_ENTRIES
MAX_SOURCE_WHEEL_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_SOURCE_WHEEL_COMPRESSION_RATIO = 200
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIST_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_]*$")
_VERSION_FILENAME = re.compile(r"^[A-Za-z0-9]+(?:[._+][A-Za-z0-9]+)*$")


class SourceWheelAuthorityError(ValueError):
    """Stable fail-closed source-wheel rejection."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class SourceWheelArchiveIdentity:
    """Sanitized exact identity of the configured wheel archive."""

    filename: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if (
            type(self.filename) is not str
            or not self.filename.isascii()
            or not self.filename
            or len(self.filename) > MAX_AUTHORITY_PATH_LEN
            or unicodedata.normalize("NFC", self.filename) != self.filename
            or PurePosixPath(self.filename).name != self.filename
            or PureWindowsPath(self.filename).name != self.filename
            or any(ord(character) < 32 or ord(character) == 127 for character in self.filename)
            or not self.filename.endswith(".whl")
        ):
            raise ValueError("source wheel filename is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("source wheel SHA-256 is invalid")
        if type(self.size) is not int or not 0 < self.size <= MAX_SOURCE_WHEEL_BYTES:
            raise ValueError("source wheel size is outside the bound")

    def to_dict(self) -> dict[str, object]:
        """Return the sanitized archive identity."""
        return {"filename": self.filename, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class SourceWheelEntryIdentity:
    """One immutable regular wheel member identity."""

    path: str
    sha256: str
    size: int
    compressed_size: int
    crc32: str
    unix_mode: int

    def __post_init__(self) -> None:
        _validate_member_name(self.path)
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("source wheel entry SHA-256 is invalid")
        if type(self.size) is not int or not 0 <= self.size <= MAX_FILE_BYTES:
            raise ValueError("source wheel entry size is outside the bound")
        if type(self.compressed_size) is not int or self.compressed_size < 0:
            raise ValueError("source wheel compressed size is invalid")
        if not re.fullmatch(r"[0-9a-f]{8}", self.crc32):
            raise ValueError("source wheel entry CRC32 is invalid")
        if type(self.unix_mode) is not int or stat.S_IFMT(self.unix_mode) != stat.S_IFREG:
            raise ValueError("source wheel entry is not a regular file")

    def to_dict(self) -> dict[str, object]:
        """Return the exact member identity without its bytes."""
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "crc32": self.crc32,
            "unix_mode": self.unix_mode,
        }


@dataclass(frozen=True, slots=True)
class SourceWheelLicensePayloadIdentity:
    """Exact license payload identity consumed by the bounded detector."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        _validate_member_name(self.path)
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("source wheel license payload SHA-256 is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or not 0 <= self.size <= MAX_FILE_BYTES
        ):
            raise ValueError("source wheel license payload size is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the path-free-host exact payload identity."""
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class SourceWheelLicenseDetectionReceipt:
    """Independent, byte-derived, non-authorizing bounded detector result."""

    status: str
    detected_spdx: str | None
    license_payloads: tuple[SourceWheelLicensePayloadIdentity, ...]
    domain: str = SOURCE_WHEEL_LICENSE_DETECTION_DOMAIN
    kind: str = SOURCE_WHEEL_LICENSE_DETECTION_KIND
    detector: str = SOURCE_WHEEL_LICENSE_DETECTOR
    detector_version: str = SOURCE_WHEEL_LICENSE_DETECTOR_VERSION
    detector_ruleset_sha256: str = SOURCE_WHEEL_LICENSE_DETECTOR_RULESET_SHA256
    complete_for_scope: bool = True
    authorizes_build: bool = False
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if (
            self.domain != SOURCE_WHEEL_LICENSE_DETECTION_DOMAIN
            or self.kind != SOURCE_WHEEL_LICENSE_DETECTION_KIND
            or self.detector != SOURCE_WHEEL_LICENSE_DETECTOR
            or self.detector_version != SOURCE_WHEEL_LICENSE_DETECTOR_VERSION
            or self.detector_ruleset_sha256 != SOURCE_WHEEL_LICENSE_DETECTOR_RULESET_SHA256
        ):
            raise ValueError("source wheel license detector identity is invalid")
        if self.status not in {"detected", "unsupported"}:
            raise ValueError("source wheel license detector status is invalid")
        if (self.status, self.detected_spdx) not in {
            ("detected", "MIT"),
            ("unsupported", None),
        }:
            raise ValueError("source wheel license detector result is invalid")
        if type(self.license_payloads) is not tuple or not self.license_payloads:
            raise TypeError("source wheel license detector payloads are invalid")
        if any(
            type(item) is not SourceWheelLicensePayloadIdentity
            for item in self.license_payloads
        ):
            raise TypeError("source wheel license detector payload identity is invalid")
        canonical = tuple(sorted(self.license_payloads, key=lambda item: item.path.casefold()))
        if self.license_payloads != canonical or len(
            {item.path.casefold() for item in self.license_payloads}
        ) != len(self.license_payloads):
            raise ValueError("source wheel license detector payloads are noncanonical")
        if (
            self.complete_for_scope is not True
            or self.authorizes_build
            or self.authorizes_distribution
        ):
            raise ValueError("source wheel license detector authority posture is invalid")

    @property
    def semantic_sha256(self) -> str:
        """Return the exact detector identity, result, and input digest."""
        return hashlib.sha256(_canonical_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the canonical independent detector receipt."""
        return {
            "domain": SOURCE_WHEEL_LICENSE_DETECTION_DOMAIN,
            "kind": SOURCE_WHEEL_LICENSE_DETECTION_KIND,
            "detector": SOURCE_WHEEL_LICENSE_DETECTOR,
            "detector_version": SOURCE_WHEEL_LICENSE_DETECTOR_VERSION,
            "detector_ruleset_sha256": SOURCE_WHEEL_LICENSE_DETECTOR_RULESET_SHA256,
            "status": self.status,
            "detected_spdx": self.detected_spdx,
            "license_payloads": [item.to_dict() for item in self.license_payloads],
            "complete_for_scope": True,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


def detect_source_wheel_license_payloads(
    paths: tuple[str, ...],
    payloads: tuple[bytes, ...],
) -> SourceWheelLicenseDetectionReceipt:
    """Run the bounded detector using only exact license-file payload bytes."""
    if (
        type(paths) is not tuple
        or type(payloads) is not tuple
        or not paths
        or len(paths) != len(payloads)
        or paths != tuple(sorted(paths))
        or len({path.casefold() for path in paths}) != len(paths)
        or any(type(path) is not str for path in paths)
        or any(type(payload) is not bytes for payload in payloads)
    ):
        raise SourceWheelAuthorityError("license-detector-input-invalid")
    identities: list[SourceWheelLicensePayloadIdentity] = []
    for path, payload in zip(paths, payloads, strict=True):
        try:
            identity = SourceWheelLicensePayloadIdentity(
                path=path,
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            )
        except ValueError as exc:
            raise SourceWheelAuthorityError("license-detector-input-invalid") from exc
        identities.append(identity)
    detected = len(payloads) == 1 and _is_bounded_mit_license(payloads[0])
    return SourceWheelLicenseDetectionReceipt(
        status="detected" if detected else "unsupported",
        detected_spdx="MIT" if detected else None,
        license_payloads=tuple(identities),
    )


def verify_source_wheel_license_detection(
    receipt: SourceWheelLicenseDetectionReceipt,
    paths: tuple[str, ...],
    payloads: tuple[bytes, ...],
) -> bool:
    """Re-run the byte-only detector and compare the complete exact receipt."""
    if type(receipt) is not SourceWheelLicenseDetectionReceipt:
        return False
    try:
        rebuilt = detect_source_wheel_license_payloads(paths, payloads)
    except (SourceWheelAuthorityError, TypeError, ValueError):
        return False
    return hmac.compare_digest(receipt.semantic_sha256, rebuilt.semantic_sha256)


def _is_bounded_mit_license(payload: bytes) -> bool:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "\x00" in text:
        return False
    normalized = unicodedata.normalize(
        "NFC",
        text.replace("\r\n", "\n").replace("\r", "\n"),
    )
    lines = [line.rstrip(" \t") for line in normalized.rstrip("\n").split("\n")]
    if len(lines) < 5 or lines[0] not in _MIT_LICENSE_TITLES or lines[1] != "":
        return False
    separator = next(
        (index for index in range(2, min(len(lines), 7)) if lines[index] == ""),
        None,
    )
    if separator is None or not 3 <= separator <= 6:
        return False
    copyright_lines = lines[2:separator]
    if not all(_MIT_COPYRIGHT.fullmatch(line) for line in copyright_lines):
        return False
    body = "\n".join(lines[separator + 1 :])
    return hmac.compare_digest(body, _MIT_LICENSE_CANONICAL_BODY)


@dataclass(frozen=True, slots=True)
class VerifiedSourceWheel:
    """Exact wheel authority plus immutable depth-1 analysis snapshots."""

    package: str
    distribution: str
    version: str
    license_observed: str
    archive: SourceWheelArchiveIdentity
    entries: tuple[SourceWheelEntryIdentity, ...]
    source_entry_paths: tuple[str, ...]
    metadata_entry_paths: tuple[str, ...]
    license_entry_paths: tuple[str, ...]
    snapshots: tuple[ExternalSourceSnapshot, ...] = field(repr=False)
    license_payloads: tuple[bytes, ...] = field(repr=False)
    license_detection: SourceWheelLicenseDetectionReceipt
    domain: str = SOURCE_WHEEL_AUTHORITY_DOMAIN
    authority: str = "analysis-input-only"
    authorizes_build: bool = False
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if self.domain != SOURCE_WHEEL_AUTHORITY_DOMAIN:
            raise ValueError("source wheel authority domain is invalid")
        if self.authority != "analysis-input-only":
            raise ValueError("source wheel authority class is invalid")
        if self.authorizes_build or self.authorizes_distribution:
            raise ValueError("source wheel authority cannot authorize an artifact")
        if type(self.archive) is not SourceWheelArchiveIdentity:
            raise TypeError("source wheel archive identity is invalid")
        if not self.entries or tuple(item.path for item in self.entries) != tuple(
            sorted(item.path for item in self.entries)
        ):
            raise ValueError("source wheel entries are not canonical")
        if len({item.path for item in self.entries}) != len(self.entries):
            raise ValueError("source wheel entries are duplicated")
        if not self.snapshots or tuple(item.module.module_name for item in self.snapshots) != tuple(
            sorted(item.module.module_name for item in self.snapshots)
        ):
            raise ValueError("source wheel snapshots are not canonical")
        for collection in (
            self.source_entry_paths,
            self.metadata_entry_paths,
            self.license_entry_paths,
        ):
            if collection != tuple(sorted(collection)) or len(collection) != len(set(collection)):
                raise ValueError("source wheel selected entry paths are not canonical")
        if (
            type(self.license_payloads) is not tuple
            or len(self.license_payloads) != len(self.license_entry_paths)
            or any(type(payload) is not bytes for payload in self.license_payloads)
        ):
            raise ValueError("source wheel license payload snapshot is invalid")
        entry_by_path = {item.path: item for item in self.entries}
        for path, payload in zip(
            self.license_entry_paths,
            self.license_payloads,
            strict=True,
        ):
            entry = entry_by_path.get(path)
            if (
                entry is None
                or entry.size != len(payload)
                or entry.sha256 != hashlib.sha256(payload).hexdigest()
            ):
                raise ValueError("source wheel license payload identity is stale")
        if not verify_source_wheel_license_detection(
            self.license_detection,
            self.license_entry_paths,
            self.license_payloads,
        ):
            raise ValueError("source wheel license detector receipt is stale")

    @property
    def semantic_sha256(self) -> str:
        """Return the canonical semantic digest of this authority."""
        return hashlib.sha256(_canonical_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return deterministic authority material without source bytes."""
        return {
            "domain": SOURCE_WHEEL_AUTHORITY_DOMAIN,
            "authority": "analysis-input-only",
            "package": self.package,
            "distribution": self.distribution,
            "version": self.version,
            "license_observed": self.license_observed,
            "archive": self.archive.to_dict(),
            "entries": [item.to_dict() for item in self.entries],
            "source_entry_paths": list(self.source_entry_paths),
            "metadata_entry_paths": list(self.metadata_entry_paths),
            "license_entry_paths": list(self.license_entry_paths),
            "license_detection": self.license_detection.to_dict(),
            "snapshots": [item.to_dict() for item in self.snapshots],
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


def verify_source_wheel(
    wheel_path: str | Path,
    *,
    expected_sha256: str,
    plan: ExternalSourcePlan,
) -> VerifiedSourceWheel:
    """Verify one exact pure wheel and bind it strictly to a C5.1 plan.

    A normal wheel installer rewrites the installed ``RECORD`` to add its own
    provenance rows.  The plan therefore binds that installed ``RECORD`` while
    this authority independently binds the archive ``RECORD``.  Every shared
    source, METADATA, WHEEL, and license-file identity must still match exactly.
    """
    if type(plan) is not ExternalSourcePlan:
        raise SourceWheelAuthorityError("plan-invalid")
    if type(expected_sha256) is not str or _SHA256.fullmatch(expected_sha256) is None:
        raise SourceWheelAuthorityError("expected-archive-sha256-invalid")
    if (
        plan.status != "preview-ready"
        or plan.max_depth != 1
        or plan.installed_version != plan.requested_version
        or not plan.license
        or not plan.source_files
        or not plan.metadata_files
        or not any(item.role == "license-file" for item in plan.metadata_files)
    ):
        raise SourceWheelAuthorityError("plan-out-of-scope")
    license_observed = plan.license
    if license_observed is None:  # narrowed by the closed scope above
        raise SourceWheelAuthorityError("plan-out-of-scope")
    path = Path(wheel_path)
    try:
        archive_bytes = _read_pinned_regular(path, MAX_SOURCE_WHEEL_BYTES)
    except SourceWheelAuthorityError:
        raise
    except Exception as exc:
        raise SourceWheelAuthorityError("archive-read-failed") from exc
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    if archive_sha256 != expected_sha256:
        raise SourceWheelAuthorityError("archive-sha256-mismatch")
    try:
        return _verify_source_wheel_bytes(
            archive_bytes,
            filename=path.name,
            archive_sha256=archive_sha256,
            plan=plan,
            license_observed=license_observed,
        )
    except SourceWheelAuthorityError:
        raise
    except Exception as exc:
        raise SourceWheelAuthorityError("archive-invalid") from exc


def _verify_source_wheel_bytes(
    archive_bytes: bytes,
    *,
    filename: str,
    archive_sha256: str,
    plan: ExternalSourcePlan,
    license_observed: str,
) -> VerifiedSourceWheel:
    dist_info = _validate_wheel_filename(filename, plan)
    raw_entries: dict[str, bytes] = {}
    identities: list[SourceWheelEntryIdentity] = []
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_SOURCE_WHEEL_ENTRIES:
                raise SourceWheelAuthorityError("archive-entry-count-out-of-bounds")
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise SourceWheelAuthorityError("archive-duplicate-entry")
            aliases: set[str] = set()
            total = 0
            for info in infos:
                _validate_member_name(info.filename)
                alias = unicodedata.normalize("NFC", info.filename).casefold()
                if alias in aliases:
                    raise SourceWheelAuthorityError("archive-entry-alias")
                aliases.add(alias)
                if info.flag_bits & 0x1:
                    raise SourceWheelAuthorityError("archive-encrypted-entry")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise SourceWheelAuthorityError("archive-compression-unsupported")
                mode = info.external_attr >> 16
                if info.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG:
                    raise SourceWheelAuthorityError("archive-entry-not-regular")
                if info.file_size > MAX_FILE_BYTES:
                    raise SourceWheelAuthorityError("archive-entry-size-out-of-bounds")
                if info.file_size and (
                    info.compress_size == 0
                    or info.file_size > info.compress_size * MAX_SOURCE_WHEEL_COMPRESSION_RATIO
                ):
                    raise SourceWheelAuthorityError("archive-compression-ratio-out-of-bounds")
                total += info.file_size
                if total > MAX_SOURCE_WHEEL_TOTAL_UNCOMPRESSED_BYTES:
                    raise SourceWheelAuthorityError("archive-total-size-out-of-bounds")
                try:
                    data = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    raise SourceWheelAuthorityError("archive-entry-read-failed") from exc
                if len(data) != info.file_size:
                    raise SourceWheelAuthorityError("archive-entry-size-mismatch")
                raw_entries[info.filename] = data
                identities.append(
                    SourceWheelEntryIdentity(
                        path=info.filename,
                        sha256=hashlib.sha256(data).hexdigest(),
                        size=len(data),
                        compressed_size=info.compress_size,
                        crc32=f"{info.CRC:08x}",
                        unix_mode=mode,
                    )
                )
    except SourceWheelAuthorityError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise SourceWheelAuthorityError("archive-zip-invalid") from exc

    metadata_name = f"{dist_info}/METADATA"
    wheel_name = f"{dist_info}/WHEEL"
    record_name = f"{dist_info}/RECORD"
    if any(name not in raw_entries for name in (metadata_name, wheel_name, record_name)):
        raise SourceWheelAuthorityError("archive-required-metadata-missing")
    archive_records = tuple(name for name in raw_entries if name == record_name)
    if len(archive_records) != 1:
        raise SourceWheelAuthorityError("archive-record-set-invalid")
    _validate_foreign_dist_info(tuple(raw_entries), dist_info)
    metadata = _parse_distribution_metadata(raw_entries[metadata_name])
    if (
        _canonical_name(metadata.name) != _canonical_name(plan.distribution)
        or metadata.version != plan.requested_version
        or metadata.license != license_observed
        or _dist_info_root(metadata.name, metadata.version).as_posix() != dist_info
    ):
        raise SourceWheelAuthorityError("archive-metadata-identity-mismatch")
    if not metadata.license_files:
        raise SourceWheelAuthorityError("archive-license-entry-missing")
    _validate_wheel_metadata(raw_entries[wheel_name])
    _validate_record(raw_entries[record_name], raw_entries, record_name)

    authority_prefix = f"distributions/{_canonical_name(plan.distribution)}/"
    package_path = PurePosixPath(*plan.package.split("."))
    source_names = tuple(
        sorted(name for name in raw_entries if _is_depth_one_python_member(name, package_path))
    )
    if not source_names or len(source_names) > MAX_SOURCE_MODULES:
        raise SourceWheelAuthorityError("archive-source-set-out-of-bounds")
    license_names = tuple(sorted(f"{dist_info}/licenses/{name}" for name in metadata.license_files))
    if any(name not in raw_entries for name in license_names):
        raise SourceWheelAuthorityError("archive-license-entry-missing")
    metadata_names = tuple(sorted((record_name, metadata_name, wheel_name, *license_names)))

    source_authority = tuple(
        sorted(
            (
                AuthorityFile(
                    path=authority_prefix + name,
                    sha256=hashlib.sha256(raw_entries[name]).hexdigest(),
                    size=len(raw_entries[name]),
                    role="source-module",
                    module_name=_module_name(plan.package, name, package_path),
                )
                for name in source_names
            ),
            key=lambda item: item.path,
        )
    )
    metadata_authority = tuple(
        sorted(
            (
                AuthorityFile(
                    path=authority_prefix + name,
                    sha256=hashlib.sha256(raw_entries[name]).hexdigest(),
                    size=len(raw_entries[name]),
                    role=(
                        "record"
                        if name == record_name
                        else "metadata"
                        if name == metadata_name
                        else "wheel"
                        if name == wheel_name
                        else "license-file"
                    ),
                )
                for name in metadata_names
            ),
            key=lambda item: item.path,
        )
    )
    installed_record_path = authority_prefix + record_name
    if type(plan.metadata_files) is not tuple or any(
        type(item) is not AuthorityFile for item in plan.metadata_files
    ):
        raise SourceWheelAuthorityError("installed-record-plan-invalid")
    installed_records = tuple(
        item for item in plan.metadata_files if item.role == "record"
    )
    installed_record = installed_records[0] if len(installed_records) == 1 else None
    if (
        installed_record is None
        or type(installed_record.path) is not str
        or installed_record.path != installed_record_path
        or type(installed_record.sha256) is not str
        or _SHA256.fullmatch(installed_record.sha256) is None
        or type(installed_record.size) is not int
        or not 0 <= installed_record.size <= MAX_FILE_BYTES
        or installed_record.role != "record"
        or installed_record.module_name is not None
    ):
        raise SourceWheelAuthorityError("installed-record-plan-invalid")
    archive_records_authority = tuple(
        item for item in metadata_authority if item.role == "record"
    )
    if (
        len(archive_records_authority) != 1
        or archive_records_authority[0].path != installed_record_path
    ):
        raise SourceWheelAuthorityError("archive-record-set-invalid")
    if source_authority != tuple(sorted(plan.source_files, key=lambda item: item.path)):
        raise SourceWheelAuthorityError("archive-source-set-plan-mismatch")
    archive_shared_metadata = tuple(
        item for item in metadata_authority if item.role != "record"
    )
    installed_shared_metadata = tuple(
        sorted(
            (item for item in plan.metadata_files if item.role != "record"),
            key=lambda item: item.path,
        )
    )
    if archive_shared_metadata != installed_shared_metadata:
        raise SourceWheelAuthorityError("archive-metadata-set-plan-mismatch")

    modules = {module.module_name: module for module in plan.modules}
    if len(modules) != len(plan.modules) or set(modules) != {
        item.module_name for item in source_authority
    }:
        raise SourceWheelAuthorityError("archive-module-set-plan-mismatch")
    snapshots: list[ExternalSourceSnapshot] = []
    for item, name in zip(source_authority, source_names, strict=True):
        if item.module_name is None:
            raise SourceWheelAuthorityError("archive-module-identity-missing")
        module = modules[item.module_name]
        if (
            type(module) is not SourceModule
            or module.path != item.path
            or module.sha256 != item.sha256
            or module.source_origin is not SourceOrigin.DISTRIBUTION
            or module.dependency_depth != 1
            or module.distribution != plan.distribution
            or module.version != plan.requested_version
            or module.license != license_observed
        ):
            raise SourceWheelAuthorityError("archive-module-plan-mismatch")
        snapshots.append(ExternalSourceSnapshot(module=module, source_bytes=raw_entries[name]))

    license_payloads = tuple(raw_entries[name] for name in license_names)
    return VerifiedSourceWheel(
        package=plan.package,
        distribution=plan.distribution,
        version=plan.requested_version,
        license_observed=license_observed,
        archive=SourceWheelArchiveIdentity(filename, archive_sha256, len(archive_bytes)),
        entries=tuple(sorted(identities, key=lambda item: item.path)),
        source_entry_paths=source_names,
        metadata_entry_paths=metadata_names,
        license_entry_paths=license_names,
        snapshots=tuple(sorted(snapshots, key=lambda item: item.module.module_name)),
        license_payloads=license_payloads,
        license_detection=detect_source_wheel_license_payloads(license_names, license_payloads),
    )


def _read_pinned_regular(path: Path, limit: int) -> bytes:
    if path.name != str(path.name) or not path.name.endswith(".whl"):
        raise SourceWheelAuthorityError("archive-path-invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise SourceWheelAuthorityError("archive-no-follow-unavailable")
    try:
        linked = path.lstat()
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise SourceWheelAuthorityError("archive-not-regular")
        fd = os.open(path, flags | nofollow)
    except SourceWheelAuthorityError:
        raise
    except OSError as exc:
        raise SourceWheelAuthorityError("archive-open-failed") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_size <= 0
            or before.st_size > limit
        ):
            raise SourceWheelAuthorityError("archive-identity-invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise SourceWheelAuthorityError("archive-size-out-of-bounds")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            any(getattr(before, item) != getattr(after, item) for item in fields)
            or total != before.st_size
        ):
            raise SourceWheelAuthorityError("archive-changed-during-read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _validate_member_name(name: str) -> None:
    if (
        type(name) is not str
        or not name
        or len(name) > MAX_AUTHORITY_PATH_LEN
        or name != unicodedata.normalize("NFC", name)
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or name.endswith("/")
    ):
        raise SourceWheelAuthorityError("archive-entry-name-unsafe")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or "//" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or posix.as_posix() != name
    ):
        raise SourceWheelAuthorityError("archive-entry-name-unsafe")


def _validate_wheel_filename(filename: str, plan: ExternalSourcePlan) -> str:
    if not filename.endswith(".whl"):
        raise SourceWheelAuthorityError("archive-filename-invalid")
    fields = filename[:-4].split("-")
    if len(fields) != 5 or fields[2:] != ["py3", "none", "any"]:
        raise SourceWheelAuthorityError("archive-not-pure-py3-none-any")
    distribution, version = fields[:2]
    expected_distribution = re.sub(r"[-_.]+", "_", plan.distribution).lower()
    expected_version = re.sub(r"-+", "_", plan.requested_version).lower()
    if (
        _DIST_FILENAME.fullmatch(distribution) is None
        or _VERSION_FILENAME.fullmatch(version) is None
        or distribution != expected_distribution
        or version != expected_version
    ):
        raise SourceWheelAuthorityError("archive-filename-identity-mismatch")
    return _dist_info_root(plan.distribution, plan.requested_version).as_posix()


def _validate_wheel_metadata(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceWheelAuthorityError("archive-wheel-metadata-invalid") from exc
    values: dict[str, list[str]] = {}
    for raw in text.splitlines():
        if not raw:
            continue
        key, separator, value = raw.partition(":")
        if separator != ":":
            raise SourceWheelAuthorityError("archive-wheel-metadata-invalid")
        values.setdefault(key.strip().casefold(), []).append(value.strip())
    if (
        values.get("wheel-version") != ["1.0"]
        or [value.casefold() for value in values.get("root-is-purelib", [])] != ["true"]
        or values.get("tag") != ["py3-none-any"]
    ):
        raise SourceWheelAuthorityError("archive-not-pure-py3-none-any")


def _validate_record(data: bytes, entries: dict[str, bytes], record_name: str) -> None:
    try:
        text = data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise SourceWheelAuthorityError("archive-record-invalid") from exc
    if len(rows) != len(entries) or len(rows) > MAX_RECORD_ENTRIES:
        raise SourceWheelAuthorityError("archive-record-coverage-mismatch")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise SourceWheelAuthorityError("archive-record-invalid")
        name, encoded_hash, encoded_size = row
        _validate_member_name(name)
        if name in seen or name not in entries:
            raise SourceWheelAuthorityError("archive-record-coverage-mismatch")
        seen.add(name)
        payload = entries[name]
        if name == record_name:
            if encoded_hash or encoded_size:
                raise SourceWheelAuthorityError("archive-record-self-entry-invalid")
            continue
        algorithm, separator, digest_text = encoded_hash.partition("=")
        if separator != "=" or algorithm != "sha256" or not digest_text:
            raise SourceWheelAuthorityError("archive-record-hash-invalid")
        try:
            padded = digest_text + "=" * (-len(digest_text) % 4)
            digest = base64.urlsafe_b64decode(padded.encode("ascii"))
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise SourceWheelAuthorityError("archive-record-hash-invalid") from exc
        canonical = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        if len(digest) != 32 or canonical != digest_text:
            raise SourceWheelAuthorityError("archive-record-hash-invalid")
        if digest != hashlib.sha256(payload).digest():
            raise SourceWheelAuthorityError("archive-record-hash-mismatch")
        if not encoded_size.isdigit() or int(encoded_size) != len(payload):
            raise SourceWheelAuthorityError("archive-record-size-mismatch")
    if seen != set(entries):
        raise SourceWheelAuthorityError("archive-record-coverage-mismatch")


def _validate_foreign_dist_info(names: tuple[str, ...], expected: str) -> None:
    expected_alias = unicodedata.normalize("NFC", expected).casefold()
    for name in names:
        for part in PurePosixPath(name).parts:
            alias = unicodedata.normalize("NFC", part).casefold()
            if alias.endswith(".dist-info") and (alias != expected_alias or part != expected):
                raise SourceWheelAuthorityError("archive-foreign-dist-info")


def _is_depth_one_python_member(name: str, package_path: PurePosixPath) -> bool:
    relative = PurePosixPath(name)
    if relative.suffix != ".py":
        return False
    try:
        child = relative.relative_to(package_path)
    except ValueError:
        return False
    return len(child.parts) == 1


def _module_name(package: str, name: str, package_path: PurePosixPath) -> str:
    child = PurePosixPath(name).relative_to(package_path)
    return package if child.name == "__init__.py" else f"{package}.{child.stem}"


def _canonical_bytes(value: object) -> bytes:
    import json

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


__all__ = [
    "SOURCE_WHEEL_AUTHORITY_DOMAIN",
    "SOURCE_WHEEL_LICENSE_DETECTION_DOMAIN",
    "SOURCE_WHEEL_LICENSE_DETECTION_KIND",
    "SOURCE_WHEEL_LICENSE_DETECTOR",
    "SOURCE_WHEEL_LICENSE_DETECTOR_RULESET_SHA256",
    "SOURCE_WHEEL_LICENSE_DETECTOR_VERSION",
    "SourceWheelArchiveIdentity",
    "SourceWheelAuthorityError",
    "SourceWheelEntryIdentity",
    "SourceWheelLicenseDetectionReceipt",
    "SourceWheelLicensePayloadIdentity",
    "VerifiedSourceWheel",
    "detect_source_wheel_license_payloads",
    "verify_source_wheel_license_detection",
    "verify_source_wheel",
]
