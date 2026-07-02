"""Build-time toolchain preflight checks.

`rextio build` shells out to external toolchains (Cargo/rustc, maturin, Nuitka)
that are intentionally *not* declared as hard Python dependencies. This module
checks that the tools required for the selected backends are present and returns
clear, actionable messages so a missing tool is reported up front instead of as
an opaque mid-build failure.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

# Any 2.x release is accepted; every 1.x release is rejected.
MINIMUM_NUITKA_MAJOR = 2


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


def nuitka_version_error(nuitka: str) -> str | None:
    """Return an actionable error when the installed Nuitka predates 2.0.

    Rextio's Nuitka integration is validated against the 2.x CLI (module,
    standalone, and onefile modes). The probe is best-effort: if the version
    cannot be determined, the build proceeds and the real invocation surfaces
    any incompatibility.
    """
    try:
        completed = subprocess.run(
            [nuitka, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        # A broken install may still print something version-shaped;
        # treat it as undetermined rather than trusting the output.
        return None
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    first_line = output.splitlines()[0].strip() if output else ""
    # search, not match: tolerate a "Nuitka 1.9.7"-style prefix on the line.
    match = re.search(r"(\d+)\.(\d+)", first_line)
    if match is None:
        return None
    if int(match.group(1)) < MINIMUM_NUITKA_MAJOR:
        return (
            f"Nuitka {first_line} is too old: Rextio requires Nuitka >= "
            f"{MINIMUM_NUITKA_MAJOR}.0. Upgrade with: pip install -U nuitka"
        )
    return None
