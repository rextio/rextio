from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArtifactLayout:
    root: Path

    @property
    def rextio_dir(self) -> Path:
        return self.root / ".rextio"

    @property
    def generated_dir(self) -> Path:
        return self.rextio_dir / "generated"

    @property
    def build_dir(self) -> Path:
        return self.rextio_dir / "build"

    @property
    def build_python_dir(self) -> Path:
        return self.build_dir / "python"

    @property
    def dist_dir(self) -> Path:
        return self.root / "dist"

    @property
    def rust_dir(self) -> Path:
        return self.generated_dir / "rust"

    @property
    def rust_src_dir(self) -> Path:
        return self.rust_dir / "src"

    @property
    def python_dir(self) -> Path:
        return self.generated_dir / "python"

    @property
    def reports_dir(self) -> Path:
        return self.rextio_dir / "reports"
