"""Build-time toolchain preflight checks.

`rextio build` shells out to external toolchains (Cargo/rustc, maturin, Nuitka)
that are intentionally *not* declared as hard Python dependencies. This module
checks that the tools required for the selected backends are present and returns
clear, actionable messages so a missing tool is reported up front instead of as
an opaque mid-build failure.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class MissingTool:
    name: str
    reason: str
    install: str

    def message(self) -> str:
        return f"{self.name} was not found ({self.reason}). Install it with: {self.install}"


def missing_build_tools(
    *,
    native_backend: str = "rust",
    build_tool: str = "cargo",
    nuitka: bool = False,
) -> list[MissingTool]:
    """Return the tools required by the requested backends that are missing."""
    missing: list[MissingTool] = []

    if native_backend == "rust":
        # cargo is the ultimate driver: when `build_tool = "maturin"` is selected
        # but maturin is absent, the build falls back to cargo, so only the
        # presence of the selected tool *or* cargo is required.
        if shutil.which(build_tool) is None and shutil.which("cargo") is None:
            missing.append(
                MissingTool(
                    name="Rust toolchain",
                    reason="cargo is required to compile generated native code",
                    install="https://rustup.rs (or your platform package manager)",
                )
            )

    if nuitka and shutil.which("nuitka") is None:
        missing.append(
            MissingTool(
                name="Nuitka",
                reason="selected for fallback/executable packaging",
                install='pip install "rextio[nuitka]"  # or: pip install nuitka',
            )
        )

    return missing


def format_missing_tools(missing: list[MissingTool]) -> str:
    lines = ["RXT060 Build prerequisites are missing:"]
    lines.extend(f"  - {tool.message()}" for tool in missing)
    return "\n".join(lines)
