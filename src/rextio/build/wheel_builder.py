"""Building a wheel from the generated Python package."""

from __future__ import annotations

import base64
import hashlib
import re
import sys
import sysconfig
import zipfile
from dataclasses import dataclass
from pathlib import Path


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
) -> WheelBuildResult:
    """Build a wheel from the generated Python package and return the result."""
    if not python_dir.exists():
        return WheelBuildResult(
            status="failed",
            path=None,
            message="RXT060 Wheel build failed because the Python build artifact was missing.",
        )

    name = _normalize_distribution_name(project_root.name or "rextio_hybrid_artifact")
    version = "0.1.0"
    wheel_tag = _wheel_tag(python_dir)
    root_is_purelib = "false" if _has_native_extension(python_dir) else "true"
    dist_info = f"{name}-{version}.dist-info"
    dist_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = dist_dir / f"{name}-{version}-{wheel_tag}.whl"
    if wheel_path.exists():
        wheel_path.unlink()

    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in python_dir.rglob("*") if item.is_file()):
            if _shadowed_by_compiled_sibling(path):
                # A Nuitka-compiled extension of the same module sits next to
                # this source file; the import system prefers the extension, so
                # the .py would be dead weight that also exposes the source.
                # (Modules kept plain for external accelerators have no
                # compiled sibling and ship their .py as before.)
                continue
            relative = path.relative_to(python_dir).as_posix()
            data = path.read_bytes()
            _write_bytes(archive, relative, data)
            records.append((relative, _hash_record(data), len(data)))

        metadata_entries = {
            f"{dist_info}/METADATA": (
                "Metadata-Version: 2.1\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "Summary: Rextio generated hybrid artifact.\n"
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

    return WheelBuildResult(
        status="built",
        path=str(wheel_path),
        message="Generated hybrid artifact wheel.",
    )


def _normalize_distribution_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.]+", "_", value).strip("._")
    if not normalized:
        return "rextio_hybrid_artifact"
    return normalized.lower()


def _wheel_tag(python_dir: Path) -> str:
    if not _has_native_extension(python_dir):
        return "py3-none-any"
    python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    abi_tag = python_tag
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return f"{python_tag}-{abi_tag}-{platform_tag}"


def _has_native_extension(python_dir: Path) -> bool:
    """Whether the tree carries ANY platform-specific extension module.

    Both the PyO3 extension (`_rextio_native*`) and Nuitka-compiled fallback
    modules count: a wheel containing either must carry a platform tag, not
    `py3-none-any` (pip would otherwise install it on platforms where the
    binaries cannot load).
    """
    return any(_is_native_extension(path.name) for path in python_dir.rglob("*") if path.is_file())


_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")


def _is_native_extension(filename: str) -> bool:
    return filename.endswith(_NATIVE_SUFFIXES)


def _shadowed_by_compiled_sibling(path: Path) -> bool:
    """Whether a compiled extension for the same module sits next to a .py file.

    A valid extension filename for module `stem` is `stem.so`-style or
    `stem.<tag>.so`-style (dot right after the stem), so `plain2.so` does not
    shadow `plain.py`.
    """
    if path.suffix != ".py":
        return False
    stem = path.stem
    for sibling in path.parent.iterdir():
        if not sibling.is_file() or not _is_native_extension(sibling.name):
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
