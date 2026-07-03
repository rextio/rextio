"""Build-time toolchain preflight checks.

`rextio build` shells out to external toolchains (Cargo/rustc, maturin, Nuitka)
that are intentionally *not* declared as hard Python dependencies. This module
checks that the tools required for the selected backends are present and returns
clear, actionable messages so a missing tool is reported up front instead of as
an opaque mid-build failure.
"""

from __future__ import annotations

from dataclasses import dataclass

from pathlib import Path

from rextio.build.toolchain import check_version_pin, probe_version, resolve_tool
from rextio.config.schema import ToolchainConfig

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


def missing_build_tools(
    *, native_backend: str = "rust", toolchain: ToolchainConfig | None = None
) -> list[MissingTool]:
    """Return the tools required to compile a native artifact that are missing.

    Only called when a native artifact is actually needed (see build_cmd). cargo is
    always required for the rust backend: maturin wraps cargo/rustc, and a missing
    maturin falls back to cargo in the orchestrator — so cargo is the single real
    requirement. Other backends (mojo/julia) are not implemented yet and gate
    nothing here.
    """
    missing: list[MissingTool] = []

    if native_backend == "rust":
        cargo, resolve_error = resolve_tool("cargo", (toolchain or ToolchainConfig()).cargo)
        if cargo is None:
            missing.append(
                MissingTool(
                    name="Rust toolchain",
                    reason=resolve_error or "cargo is required to compile generated native code",
                    install="https://rustup.rs (or your platform package manager)",
                )
            )

    return missing


def format_missing_tools(missing: list[MissingTool]) -> str:
    """Format a list of missing tools into a user-facing diagnostic string."""
    lines = ["RXT060 Build prerequisites are missing:"]
    lines.extend(f"  - {tool.message()}" for tool in missing)
    return "\n".join(lines)


def nuitka_toolchain_error(command: list[str], toolchain: ToolchainConfig | None) -> str | None:
    """Run every Nuitka toolchain check that applies at a point of use.

    The >= 2.0 floor is best-effort; an explicit [toolchain] nuitka_version
    pin is strict. One `--version` probe feeds both checks. Shared by the
    CLI gate and all three Nuitka invocation sites (fallback builder,
    executable builder, hybrid dispatcher) so no path can drift out of the
    contract.
    """
    command = [str(part) for part in command]
    reported = probe_version(command)
    floor_error = _nuitka_floor_error(reported)
    if floor_error is not None:
        return floor_error
    return check_version_pin(
        "Nuitka",
        command,
        (toolchain or ToolchainConfig()).nuitka_version,
        reported=reported,
    )


def nuitka_version_error(command: list[str]) -> str | None:
    """Return an actionable error when the installed Nuitka predates 2.0.

    ``command`` is the invocation prefix from ``resolve_nuitka_command``
    (e.g. ``[path]`` or ``[python, "-m", "nuitka"]``). Rextio's Nuitka
    integration is validated against the 2.x CLI (module, standalone, and
    onefile modes). The probe is best-effort: if the version cannot be
    determined, the build proceeds and the real invocation surfaces any
    incompatibility.
    """
    if isinstance(command, (str, Path)):  # a bare path is ONE argument, not chars
        command = [str(command)]
    return _nuitka_floor_error(probe_version([str(part) for part in command]))


def _nuitka_floor_error(reported: str | None) -> str | None:
    if reported is None:
        return None
    if int(reported.split(".", 1)[0]) < MINIMUM_NUITKA_MAJOR:
        return (
            f"Nuitka {reported} is too old: Rextio requires Nuitka >= "
            f"{MINIMUM_NUITKA_MAJOR}.0. Upgrade with: pip install -U nuitka"
        )
    return None
