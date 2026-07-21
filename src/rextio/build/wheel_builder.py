"""Building a wheel from the generated Python package."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import stat
import sys
import sysconfig
import unicodedata
import zipfile
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath, PureWindowsPath


class WheelContractError(ValueError):
    """A strict external-source output wheel contract was not satisfied."""


@dataclass(frozen=True, slots=True)
class ExternalWheelMemberIdentity:
    """Exact source-wheel member excluded from the generated artifact."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not _is_safe_member_path(self.path):
            raise ValueError("external wheel member path is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("external wheel member digest is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or self.size < 0
            or self.size > _MAX_STRICT_ENTRY_BYTES
        ):
            raise ValueError("external wheel member size is invalid")


@dataclass(frozen=True, slots=True)
class ExternalWheelContract:
    """Exact dependency and source-exclusion contract for one C5.2 wheel."""

    package: str
    distribution: str
    version: str
    source_members: tuple[str, ...]
    external_members: tuple[ExternalWheelMemberIdentity, ...]

    def __post_init__(self) -> None:
        package_parts = self.package.split(".")
        members = tuple(self.source_members)
        external_members = tuple(self.external_members)
        package_root = "/".join(package_parts)
        if (
            not package_parts
            or any(not part.isascii() or not part.isidentifier() for part in package_parts)
            or _DIST_REQUIREMENT.fullmatch(self.distribution) is None
            or _VERSION_REQUIREMENT.fullmatch(self.version) is None
            or not members
            or members != tuple(sorted(members))
            or len(set(members)) != len(members)
            or not external_members
            or not all(
                type(item) is ExternalWheelMemberIdentity for item in external_members
            )
            or external_members
            != tuple(sorted(external_members, key=lambda item: item.path))
            or len({item.path for item in external_members}) != len(external_members)
        ):
            raise ValueError("external wheel contract identity is invalid")
        aliases: set[str] = set()
        for member in members:
            path = PurePosixPath(member)
            alias = unicodedata.normalize("NFC", member).casefold()
            if (
                not member.endswith(".py")
                or path.is_absolute()
                or path.as_posix() != member
                or any(part in {"", ".", ".."} for part in path.parts)
                or not (member == f"{package_root}.py" or member.startswith(f"{package_root}/"))
                or alias in aliases
            ):
                raise ValueError("external wheel source member is invalid")
            aliases.add(alias)
        external_paths = {item.path for item in external_members}
        if not set(members).issubset(external_paths):
            raise ValueError("external wheel inventory omits a source member")
        dist_info = tuple(
            item.path
            for item in external_members
            if ".dist-info/" in item.path
        )
        if not all(
            any(path.endswith(suffix) for path in dist_info)
            for suffix in ("/METADATA", "/WHEEL", "/RECORD")
        ) or not any(".dist-info/licenses/" in path for path in dist_info):
            raise ValueError("external wheel metadata inventory is incomplete")
        external_aliases = tuple(
            unicodedata.normalize("NFC", item.path).casefold()
            for item in external_members
        )
        if len(external_aliases) != len(set(external_aliases)):
            raise ValueError("external wheel inventory contains aliased members")

    @property
    def requirement(self) -> str:
        """Return the sole exact dependency spelling accepted in METADATA."""
        return f"{self.distribution}=={self.version}"

    @property
    def external_member_paths(self) -> tuple[str, ...]:
        """Return the complete canonical source-wheel member inventory."""
        return tuple(item.path for item in self.external_members)


@dataclass(frozen=True, slots=True)
class ExternalWheelVerification:
    """Successful final output-wheel verification result."""

    requirement: str
    metadata_member: str
    record_member: str
    wheel_sha256: str


_DIST_REQUIREMENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION_REQUIREMENT = re.compile(r"^[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_STRICT_WHEEL_BYTES = 512_000_000
_MAX_STRICT_WHEEL_ENTRIES = 4096
_MAX_STRICT_ENTRY_BYTES = 256_000_000
_MAX_STRICT_TOTAL_BYTES = 1_000_000_000
_MAX_STRICT_COMPRESSION_RATIO = 200
_MAX_STRICT_MEMBER_NAME = 512


@dataclass(frozen=True, slots=True)
class _PinnedStagingFile:
    relative: str
    data: bytes


@dataclass(frozen=True)
class WheelBuildResult:
    """The outcome of building a wheel."""

    status: str
    path: str | None
    message: str

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        return {
            "status": self.status,
            "path": self.path,
            "message": self.message,
        }


def skipped_wheel(message: str) -> WheelBuildResult:
    """Return a result marking the wheel build as skipped."""
    return WheelBuildResult(status="skipped", path=None, message=message)


def build_artifact_wheel(
    project_root: Path,
    python_dir: Path,
    dist_dir: Path,
    *,
    external_contract: ExternalWheelContract | None = None,
) -> WheelBuildResult:
    """Build a wheel from the generated Python package and return the result."""
    if not python_dir.exists():
        return WheelBuildResult(
            status="failed",
            path=None,
            message="RXT060 Wheel build failed because the Python build artifact was missing.",
        )
    if external_contract is not None:
        if type(external_contract) is not ExternalWheelContract:
            raise WheelContractError("external wheel contract has an invalid type")
    staging_files = _collect_staging_files(python_dir)
    if external_contract is not None:
        _require_external_source_absent(staging_files, external_contract)

    wheel_path = artifact_wheel_path(
        project_root,
        python_dir,
        dist_dir,
        staging_files=staging_files,
    )
    name = _normalize_distribution_name(project_root.name or "rextio_hybrid_artifact")
    version = "0.1.0"
    wheel_tag = _wheel_tag(python_dir, staging_files=staging_files)
    root_is_purelib = (
        "false" if _has_native_extension(staging_files=staging_files) else "true"
    )
    dist_info = f"{name}-{version}.dist-info"
    dist_dir.mkdir(parents=True, exist_ok=True)
    if wheel_path.exists():
        wheel_path.unlink()

    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        staging_names = frozenset(item.relative for item in staging_files)
        for item in staging_files:
            if _shadowed_by_compiled_sibling(item.relative, staging_names):
                # A Nuitka-compiled extension of the same module sits next to
                # this source file; the import system prefers the extension, so
                # the .py would be dead weight that also exposes the source.
                # (Modules kept plain for external accelerators have no
                # compiled sibling and ship their .py as before.)
                continue
            relative = item.relative
            data = item.data
            _write_bytes(archive, relative, data)
            records.append((relative, _hash_record(data), len(data)))

        metadata_entries = {
            f"{dist_info}/METADATA": (
                "Metadata-Version: 2.1\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "Summary: Rextio generated hybrid artifact.\n"
                + (
                    f"Requires-Dist: {external_contract.requirement}\n"
                    if external_contract is not None
                    else ""
                )
            ).encode("utf-8"),
            f"{dist_info}/WHEEL": (
                "Wheel-Version: 1.0\n"
                "Generator: rextio\n"
                f"Root-Is-Purelib: {root_is_purelib}\n"
                f"Tag: {wheel_tag}\n"
            ).encode("utf-8"),
        }
        for relative, data in metadata_entries.items():
            _write_bytes(archive, relative, data)
            records.append((relative, _hash_record(data), len(data)))

        record_path = f"{dist_info}/RECORD"
        record_lines = [f"{relative},{digest},{size}" for relative, digest, size in records]
        record_lines.append(f"{record_path},,")
        _write_bytes(archive, record_path, ("\n".join(record_lines) + "\n").encode("utf-8"))

    if external_contract is not None:
        try:
            verify_external_wheel_contract(wheel_path, external_contract)
        except WheelContractError:
            wheel_path.unlink(missing_ok=True)
            raise
    return WheelBuildResult(
        status="built",
        path=str(wheel_path),
        message="Generated hybrid artifact wheel.",
    )


def verify_external_wheel_contract(
    wheel_path: Path,
    contract: ExternalWheelContract,
) -> ExternalWheelVerification:
    """Reopen the final wheel and verify exact pin, exclusion, and RECORD."""
    if type(contract) is not ExternalWheelContract:
        raise WheelContractError("external wheel contract has an invalid type")
    path = Path(wheel_path)
    try:
        wheel_bytes, pinned_identity = _read_pinned_wheel(path)
        with zipfile.ZipFile(io.BytesIO(wheel_bytes), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _MAX_STRICT_WHEEL_ENTRIES:
                raise WheelContractError("output wheel entry count is outside the bound")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise WheelContractError("output wheel contains duplicate members")
            aliases: set[str] = set()
            total = 0
            payloads: dict[str, bytes] = {}
            for info in infos:
                _validate_strict_wheel_member(info)
                alias = unicodedata.normalize("NFC", info.filename).casefold()
                if alias in aliases:
                    raise WheelContractError("output wheel contains aliased members")
                aliases.add(alias)
                total += info.file_size
                if total > _MAX_STRICT_TOTAL_BYTES:
                    raise WheelContractError("output wheel expanded size is outside the bound")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise WheelContractError("output wheel member size is inconsistent")
                payloads[info.filename] = data
    except WheelContractError:
        raise
    except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        raise WheelContractError("output wheel could not be verified") from error

    metadata = tuple(name for name in names if name.endswith(".dist-info/METADATA"))
    records = tuple(name for name in names if name.endswith(".dist-info/RECORD"))
    if len(metadata) != 1 or len(records) != 1:
        raise WheelContractError("output wheel metadata coverage is invalid")
    metadata_root = metadata[0].rsplit("/", 1)[0]
    if records[0].rsplit("/", 1)[0] != metadata_root:
        raise WheelContractError("output wheel dist-info identity is inconsistent")
    wheel_metadata = f"{metadata_root}/WHEEL"
    dist_info_roots = {name.split("/", 1)[0] for name in names if ".dist-info/" in name}
    if (
        wheel_metadata not in payloads
        or dist_info_roots != {metadata_root}
        or not path.name.endswith(".whl")
        or path.name[:-4].rsplit("-", 3)[0] != metadata_root.removesuffix(".dist-info")
    ):
        raise WheelContractError("output wheel dist-info identity is inconsistent")
    try:
        payloads[metadata[0]].decode("utf-8")
        metadata_message = BytesParser(policy=email_policy.default).parsebytes(
            payloads[metadata[0]]
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise WheelContractError("output wheel METADATA is not UTF-8") from error
    if metadata_message.defects:
        raise WheelContractError("output wheel METADATA is malformed")
    requirements = list(metadata_message.get_all("Requires-Dist", []))
    if requirements != [contract.requirement]:
        raise WheelContractError("output wheel Requires-Dist is not the exact pin")

    forbidden_aliases = {
        unicodedata.normalize("NFC", member).casefold()
        for member in contract.external_member_paths
    }
    package_root = "/".join(contract.package.split(".")).casefold()
    for name in names:
        alias = unicodedata.normalize("NFC", name).casefold()
        if alias in forbidden_aliases or (
            alias == package_root
            or alias.startswith(f"{package_root}/")
            or alias.startswith(f"{package_root}.")
        ):
            raise WheelContractError("output wheel contains external package material")
    _verify_record(payloads, records[0])
    _require_pinned_wheel_unchanged(path, pinned_identity)
    return ExternalWheelVerification(
        requirement=contract.requirement,
        metadata_member=metadata[0],
        record_member=records[0],
        wheel_sha256=hashlib.sha256(wheel_bytes).hexdigest(),
    )


def _require_external_source_absent(
    staging_files: tuple[_PinnedStagingFile, ...],
    contract: ExternalWheelContract,
) -> None:
    package_root = "/".join(contract.package.split(".")).casefold()
    forbidden = {
        unicodedata.normalize("NFC", member).casefold()
        for member in contract.external_member_paths
    }
    for item in staging_files:
        alias = unicodedata.normalize("NFC", item.relative).casefold()
        if alias in forbidden or (
            alias == package_root
            or alias.startswith(f"{package_root}/")
            or alias.startswith(f"{package_root}.")
        ):
            raise WheelContractError("staging tree contains external package material")


def _collect_staging_files(python_dir: Path) -> tuple[_PinnedStagingFile, ...]:
    """Collect one exact bounded tree through no-follow directory descriptors."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise WheelContractError("staging no-follow traversal is unavailable")
    root = Path(os.path.abspath(python_dir))
    flags = os.O_RDONLY | nofollow | directory_flag | getattr(os, "O_CLOEXEC", 0)
    try:
        linked = root.lstat()
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISDIR(linked.st_mode):
            raise WheelContractError("staging root is not a regular directory")
        root_fd = os.open(root, flags)
    except WheelContractError:
        raise
    except OSError as exc:
        raise WheelContractError("staging root cannot be opened safely") from exc
    try:
        opened = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise WheelContractError("staging root identity changed")
        files: list[_PinnedStagingFile] = []
        aliases: set[str] = set()
        total = [0]
        _walk_staging_directory(
            root_fd,
            (),
            files=files,
            aliases=aliases,
            total=total,
            directory_flags=flags,
        )
        final_root = os.fstat(root_fd)
        if _directory_identity(opened) != _directory_identity(final_root):
            raise WheelContractError("staging root changed during collection")
        return tuple(sorted(files, key=lambda item: item.relative))
    finally:
        os.close(root_fd)


def _walk_staging_directory(
    directory_fd: int,
    parent_parts: tuple[str, ...],
    *,
    files: list[_PinnedStagingFile],
    aliases: set[str],
    total: list[int],
    directory_flags: int,
) -> None:
    try:
        entries = sorted(os.scandir(directory_fd), key=lambda item: item.name)
    except OSError as exc:
        raise WheelContractError("staging directory cannot be enumerated") from exc
    for entry in entries:
        name = entry.name
        if not _is_safe_staging_component(name):
            raise WheelContractError("staging tree contains an unsafe name")
        parts = (*parent_parts, name)
        relative = PurePosixPath(*parts).as_posix()
        alias = unicodedata.normalize("NFC", relative).casefold()
        if alias in aliases:
            raise WheelContractError("staging tree contains aliased paths")
        aliases.add(alias)
        try:
            linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise WheelContractError("staging entry cannot be inspected") from exc
        if stat.S_ISLNK(linked.st_mode):
            raise WheelContractError("staging tree contains a symlink")
        if stat.S_ISDIR(linked.st_mode):
            try:
                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise WheelContractError("staging directory cannot be opened safely") from exc
            try:
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
                ):
                    raise WheelContractError("staging directory identity changed")
                _walk_staging_directory(
                    child_fd,
                    parts,
                    files=files,
                    aliases=aliases,
                    total=total,
                    directory_flags=directory_flags,
                )
                after = os.fstat(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    _directory_identity(opened) != _directory_identity(after)
                    or _directory_identity(after) != _directory_identity(current)
                ):
                    raise WheelContractError("staging directory changed during collection")
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
            raise WheelContractError("staging entry is not an unaliased regular file")
        data = _read_staging_file(directory_fd, name, linked)
        total[0] += len(data)
        if total[0] > _MAX_STRICT_TOTAL_BYTES:
            raise WheelContractError("staging tree size is outside the bound")
        files.append(_PinnedStagingFile(relative=relative, data=data))
        if len(files) > _MAX_STRICT_WHEEL_ENTRIES:
            raise WheelContractError("staging entry count is outside the bound")


def _read_staging_file(
    directory_fd: int,
    name: str,
    linked: os.stat_result,
) -> bytes:
    if linked.st_size < 0 or linked.st_size > _MAX_STRICT_ENTRY_BYTES:
        raise WheelContractError("staging file size is outside the bound")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise WheelContractError("staging file cannot be opened safely") from exc
    try:
        before = os.fstat(fd)
        identity = _staging_file_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_size != linked.st_size
        ):
            raise WheelContractError("staging file identity changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = _MAX_STRICT_ENTRY_BYTES + 1 - total
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_STRICT_ENTRY_BYTES:
                raise WheelContractError("staging file size is outside the bound")
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            identity != _staging_file_identity(after)
            or identity != _staging_file_identity(current)
            or total != before.st_size
        ):
            raise WheelContractError("staging file changed during collection")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _staging_file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _is_safe_staging_component(value: str) -> bool:
    return bool(
        value
        and value not in {".", ".."}
        and len(value) <= _MAX_STRICT_MEMBER_NAME
        and value == unicodedata.normalize("NFC", value)
        and "/" not in value
        and "\\" not in value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _read_pinned_wheel(path: Path) -> tuple[bytes, tuple[int, ...]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise WheelContractError("output wheel no-follow open is unavailable")
    try:
        linked = path.lstat()
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise WheelContractError("output wheel is not a regular file")
        fd = os.open(path, flags | nofollow)
    except WheelContractError:
        raise
    except OSError as error:
        raise WheelContractError("output wheel could not be opened safely") from error
    try:
        before = os.fstat(fd)
        identity = _stat_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_size <= 0
            or before.st_size > _MAX_STRICT_WHEEL_BYTES
        ):
            raise WheelContractError("output wheel identity is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = _MAX_STRICT_WHEEL_BYTES + 1 - total
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_STRICT_WHEEL_BYTES:
                raise WheelContractError("output wheel size is outside the bound")
        after = os.fstat(fd)
        if identity != _stat_identity(after) or total != before.st_size:
            raise WheelContractError("output wheel changed during verification")
        return b"".join(chunks), identity
    finally:
        os.close(fd)


def _require_pinned_wheel_unchanged(path: Path, identity: tuple[int, ...]) -> None:
    try:
        current = path.lstat()
    except OSError as error:
        raise WheelContractError("output wheel changed during verification") from error
    if stat.S_ISLNK(current.st_mode) or _stat_identity(current) != identity:
        raise WheelContractError("output wheel changed during verification")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_strict_wheel_member(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if (
        type(name) is not str
        or not name
        or len(name) > _MAX_STRICT_MEMBER_NAME
        or name != unicodedata.normalize("NFC", name)
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or name.endswith("/")
    ):
        raise WheelContractError("output wheel member name is unsafe")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or "//" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or posix.as_posix() != name
    ):
        raise WheelContractError("output wheel member name is unsafe")
    if info.flag_bits & 0x1:
        raise WheelContractError("output wheel contains an encrypted member")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise WheelContractError("output wheel compression is unsupported")
    if info.file_size < 0 or info.file_size > _MAX_STRICT_ENTRY_BYTES:
        raise WheelContractError("output wheel member size is outside the bound")
    if info.compress_size < 0 or (
        info.file_size
        and (
            info.compress_size == 0
            or info.file_size > info.compress_size * _MAX_STRICT_COMPRESSION_RATIO
        )
    ):
        raise WheelContractError("output wheel compression ratio is outside the bound")
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if file_type not in {0, stat.S_IFREG}:
        raise WheelContractError("output wheel member is not a regular file")


def _is_safe_member_path(name: str) -> bool:
    if (
        type(name) is not str
        or not name
        or len(name) > _MAX_STRICT_MEMBER_NAME
        or name != unicodedata.normalize("NFC", name)
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or name.endswith("/")
    ):
        return False
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    return not (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or "//" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or posix.as_posix() != name
    )


def _verify_record(payloads: dict[str, bytes], record_name: str) -> None:
    try:
        rows = list(csv.reader(io.StringIO(payloads[record_name].decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as error:
        raise WheelContractError("output wheel RECORD is invalid") from error
    if len(rows) != len(payloads):
        raise WheelContractError("output wheel RECORD coverage is incomplete")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise WheelContractError("output wheel RECORD row is invalid")
        name, digest, size = row
        if name in seen or name not in payloads:
            raise WheelContractError("output wheel RECORD identity is invalid")
        seen.add(name)
        if name == record_name:
            if digest or size:
                raise WheelContractError("output wheel RECORD self row is invalid")
            continue
        data = payloads[name]
        if digest != _hash_record(data) or size != str(len(data)):
            raise WheelContractError("output wheel RECORD digest is invalid")
    if seen != set(payloads):
        raise WheelContractError("output wheel RECORD coverage is incomplete")


def artifact_wheel_path(
    project_root: Path,
    python_dir: Path,
    dist_dir: Path,
    *,
    staging_files: tuple[_PinnedStagingFile, ...] | None = None,
) -> Path:
    """Return the exact deterministic wheel output path without touching disk."""
    name = _normalize_distribution_name(project_root.name or "rextio_hybrid_artifact")
    return dist_dir / (
        f"{name}-0.1.0-{_wheel_tag(python_dir, staging_files=staging_files)}.whl"
    )


def _normalize_distribution_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.]+", "_", value).strip("._")
    if not normalized:
        return "rextio_hybrid_artifact"
    return normalized.lower()


def _wheel_tag(
    python_dir: Path,
    *,
    staging_files: tuple[_PinnedStagingFile, ...] | None = None,
) -> str:
    if not _has_native_extension(python_dir, staging_files=staging_files):
        return "py3-none-any"
    python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    abi_tag = python_tag
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return f"{python_tag}-{abi_tag}-{platform_tag}"


def _has_native_extension(
    python_dir: Path | None = None,
    *,
    staging_files: tuple[_PinnedStagingFile, ...] | None = None,
) -> bool:
    """Whether the tree carries ANY platform-specific extension module.

    Both the PyO3 extension (`_rextio_native*`) and Nuitka-compiled fallback
    modules count: a wheel containing either must carry a platform tag, not
    `py3-none-any` (pip would otherwise install it on platforms where the
    binaries cannot load).
    """
    if staging_files is None:
        if python_dir is None:
            raise TypeError("native-extension detection requires a staging tree")
        staging_files = _collect_staging_files(python_dir)
    return any(
        _is_native_extension(PurePosixPath(item.relative).name)
        for item in staging_files
    )


# Platform-specific binary content: any of these in the tree means the wheel
# must carry a platform tag instead of py3-none-any.
_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
# Suffixes Python's import system actually loads as extension MODULES
# (importlib EXTENSION_SUFFIXES end in .so on POSIX and .pyd on Windows). A
# .dylib/.dll next to a .py is a ctypes-style payload, NOT a module shadow -
# dropping the .py for those would break the installed package.
_EXTENSION_MODULE_SUFFIXES = (".so", ".pyd")


def _is_native_extension(filename: str) -> bool:
    return filename.endswith(_NATIVE_SUFFIXES)


def _shadowed_by_compiled_sibling(
    relative: str,
    staging_names: frozenset[str],
) -> bool:
    """Whether a compiled extension MODULE for the same module sits next to a .py.

    A valid extension filename for module `stem` is `stem.so`-style or
    `stem.<tag>.so`-style (dot right after the stem), so `plain2.so` does not
    shadow `plain.py`; only import-loadable suffixes count (see
    `_EXTENSION_MODULE_SUFFIXES`).
    """
    path = PurePosixPath(relative)
    if path.suffix != ".py":
        return False
    stem = path.stem
    for sibling_relative in staging_names:
        sibling = PurePosixPath(sibling_relative)
        if sibling.parent != path.parent or not sibling.name.endswith(
            _EXTENSION_MODULE_SUFFIXES
        ):
            continue
        if sibling.name.startswith(f"{stem}."):
            return True
    return False


def _write_bytes(archive: zipfile.ZipFile, relative: str, data: bytes) -> None:
    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def _hash_record(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"
