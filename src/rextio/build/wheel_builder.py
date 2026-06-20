from __future__ import annotations

import base64
import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WheelBuildResult:
    status: str
    path: str | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "path": self.path,
            "message": self.message,
        }


def skipped_wheel(message: str) -> WheelBuildResult:
    return WheelBuildResult(status="skipped", path=None, message=message)


def build_artifact_wheel(
    project_root: Path,
    python_dir: Path,
    dist_dir: Path,
) -> WheelBuildResult:
    if not python_dir.exists():
        return WheelBuildResult(
            status="failed",
            path=None,
            message="RXT060 Wheel build failed because the Python build artifact was missing.",
        )

    name = _normalize_distribution_name(project_root.name or "rextio_hybrid_artifact")
    version = "0.1.0"
    dist_info = f"{name}-{version}.dist-info"
    dist_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = dist_dir / f"{name}-{version}-py3-none-any.whl"
    if wheel_path.exists():
        wheel_path.unlink()

    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in python_dir.rglob("*") if item.is_file()):
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
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
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


def _write_bytes(archive: zipfile.ZipFile, relative: str, data: bytes) -> None:
    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def _hash_record(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"
