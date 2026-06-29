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
    """A required external build tool that was not found, with install guidance."""

    name: str
    reason: str
    install: str

    def message(self) -> str:
        """Return a human-readable message describing the missing tool and how to install it."""
        return f"{self.name} was not found ({self.reason}). Install it with: {self.install}"


def missing_build_tools(*, native_backend: str = "rust") -> list[MissingTool]:
    """Return the tools required to compile a native artifact that are missing.

    Only called when a native artifact is actually needed (see build_cmd). cargo is
    always required for the rust backend: maturin wraps cargo/rustc, and a missing
    maturin falls back to cargo in the orchestrator — so cargo is the single real
    requirement. Other backends (mojo/julia) are not implemented yet and gate
    nothing here.
    """
    missing: list[MissingTool] = []

    if native_backend == "rust" and shutil.which("cargo") is None:
        missing.append(
            MissingTool(
                name="Rust toolchain",
                reason="cargo is required to compile generated native code",
                install="https://rustup.rs (or your platform package manager)",
            )
        )

    return missing


def format_missing_tools(missing: list[MissingTool]) -> str:
    """Format a list of missing tools into a user-facing diagnostic string."""
    lines = ["RXT060 Build prerequisites are missing:"]
    lines.extend(f"  - {tool.message()}" for tool in missing)
    return "\n".join(lines)
