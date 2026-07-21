"""Typed PEP 639 material for the bounded Full C6 output-wheel profile."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
import re
import unicodedata

from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)


MAX_OUTPUT_WHEEL_LICENSE_FILES = 64
MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_PATH_CHARS = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseFile:
    """One exact license payload and its PEP 639 relative path."""

    path: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _is_canonical_license_path(self.path):
            raise ValueError("output wheel license-file path is invalid")
        if (
            type(self.data) is not bytes
            or not self.data
            or len(self.data) > MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
        ):
            raise ValueError("output wheel license-file payload is invalid")


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseContract:
    """Exact PEP 639 expression and license bytes for one generated wheel."""

    expression: str
    files: tuple[OutputWheelLicenseFile, ...]

    def __post_init__(self) -> None:
        try:
            expression = canonicalize_full_c6_spdx_expression(self.expression)
        except FullC6PolicyError as error:
            raise ValueError(str(error)) from error
        if expression != self.expression:
            raise ValueError("output wheel license expression is noncanonical")
        if (
            type(self.files) is not tuple
            or not self.files
            or len(self.files) > MAX_OUTPUT_WHEEL_LICENSE_FILES
            or any(type(item) is not OutputWheelLicenseFile for item in self.files)
            or self.files != tuple(sorted(self.files, key=lambda item: item.path))
        ):
            raise ValueError("output wheel license-file set is invalid")
        paths = tuple(item.path for item in self.files)
        aliases = tuple(_alias(path) for path in paths)
        if len(paths) != len(set(paths)) or len(aliases) != len(set(aliases)):
            raise ValueError("output wheel license-file set contains aliases")
        if sum(len(item.data) for item in self.files) > MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES:
            raise ValueError("output wheel license-file set is outside the byte bound")

    @property
    def paths(self) -> tuple[str, ...]:
        """Return the canonical ordered ``License-File`` values."""
        return tuple(item.path for item in self.files)


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseMemberIdentity:
    """One exact license member rederived from the completed output wheel."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not _is_canonical_member_path(self.path):
            raise ValueError("output wheel license member path is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("output wheel license member digest is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or self.size <= 0
            or self.size > MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
        ):
            raise ValueError("output wheel license member size is invalid")


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseVerification:
    """Exact PEP 639 identities rederived from one completed wheel."""

    expression: str
    metadata_member: str
    metadata_sha256: str
    license_members: tuple[OutputWheelLicenseMemberIdentity, ...]
    record_member: str
    wheel_sha256: str

    def __post_init__(self) -> None:
        try:
            expression = canonicalize_full_c6_spdx_expression(self.expression)
        except FullC6PolicyError as error:
            raise ValueError(str(error)) from error
        if (
            expression != self.expression
            or not _is_canonical_member_path(self.metadata_member)
            or not self.metadata_member.endswith(".dist-info/METADATA")
            or not _is_canonical_member_path(self.record_member)
            or not self.record_member.endswith(".dist-info/RECORD")
            or type(self.metadata_sha256) is not str
            or _SHA256.fullmatch(self.metadata_sha256) is None
            or type(self.wheel_sha256) is not str
            or _SHA256.fullmatch(self.wheel_sha256) is None
            or type(self.license_members) is not tuple
            or not self.license_members
            or len(self.license_members) > MAX_OUTPUT_WHEEL_LICENSE_FILES
            or any(
                type(item) is not OutputWheelLicenseMemberIdentity
                for item in self.license_members
            )
        ):
            raise ValueError("output wheel license verification is invalid")
        metadata_root = self.metadata_member.rsplit("/", 1)[0]
        member_paths = tuple(item.path for item in self.license_members)
        aliases = tuple(_alias(path) for path in member_paths)
        if (
            self.license_members
            != tuple(sorted(self.license_members, key=lambda item: item.path))
            or len(member_paths) != len(set(member_paths))
            or len(aliases) != len(set(aliases))
            or sum(item.size for item in self.license_members)
            > MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES
            or any(
                not path.startswith(f"{metadata_root}/licenses/")
                for path in member_paths
            )
            or self.record_member.rsplit("/", 1)[0] != metadata_root
        ):
            raise ValueError("output wheel license verification is invalid")


def rebuild_output_wheel_license_contract(
    value: OutputWheelLicenseContract,
) -> OutputWheelLicenseContract:
    """Rebuild an exact typed contract without trusting subclassed containers."""
    if type(value) is not OutputWheelLicenseContract:
        raise TypeError("output wheel license contract has an invalid type")
    try:
        if type(value.files) is not tuple:
            raise TypeError("output wheel license-file set has an invalid type")
        files = tuple(
            OutputWheelLicenseFile(path=item.path, data=item.data)
            for item in value.files
            if type(item) is OutputWheelLicenseFile
        )
        if len(files) != len(value.files):
            raise TypeError("output wheel license-file has an invalid type")
        return OutputWheelLicenseContract(
            expression=value.expression,
            files=files,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("output wheel license contract is invalid") from error


def _alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _is_canonical_license_path(value: object) -> bool:
    return _is_canonical_member_path(value)


def _is_canonical_member_path(value: object) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_OUTPUT_WHEEL_LICENSE_PATH_CHARS
        or value != unicodedata.normalize("NFC", value)
        or value.endswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return not (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or posix.as_posix() != value
    )


__all__ = [
    "MAX_OUTPUT_WHEEL_LICENSE_FILES",
    "MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES",
    "MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES",
    "OutputWheelLicenseContract",
    "OutputWheelLicenseFile",
    "OutputWheelLicenseMemberIdentity",
    "OutputWheelLicenseVerification",
    "rebuild_output_wheel_license_contract",
]
