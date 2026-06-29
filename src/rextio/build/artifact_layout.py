"""The on-disk layout of generated and built artifacts under ``.rextio``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArtifactLayout:
    """Resolves the on-disk paths for a project's generated and built artifacts."""

    root: Path

    @property
    def rextio_dir(self) -> Path:
        """The project's ``.rextio`` working directory."""
        return self.root / ".rextio"

    @property
    def generated_dir(self) -> Path:
        """The directory holding generated source artifacts."""
        return self.rextio_dir / "generated"

    @property
    def build_dir(self) -> Path:
        """The directory holding compiled build artifacts."""
        return self.rextio_dir / "build"

    @property
    def build_python_dir(self) -> Path:
        """The built, importable Python package directory."""
        return self.build_dir / "python"

    @property
    def dist_dir(self) -> Path:
        """The distribution output directory."""
        return self.root / "dist"

    @property
    def rust_dir(self) -> Path:
        """The generated Rust project directory."""
        return self.target_dir("rust")

    @property
    def rust_src_dir(self) -> Path:
        """The generated Rust ``src`` directory."""
        return self.rust_dir / "src"

    @property
    def rust_crate_dir(self) -> Path:
        """The Rust-importable crate directory."""
        return self.generated_dir / "rust_crate"

    @property
    def rust_crate_src_dir(self) -> Path:
        """The Rust-importable crate ``src`` directory."""
        return self.rust_crate_dir / "src"

    def target_dir(self, language: str) -> Path:
        """Return the generated project directory for a given target language."""
        return self.generated_dir / language

    @property
    def python_dir(self) -> Path:
        """The generated Python package directory."""
        return self.generated_dir / "python"

    @property
    def reports_dir(self) -> Path:
        """The directory holding rextio JSON reports."""
        return self.rextio_dir / "reports"
