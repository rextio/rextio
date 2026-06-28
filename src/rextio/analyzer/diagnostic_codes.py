"""Central registry of Rextio diagnostic codes (RXT…).

Diagnostic codes are part of Rextio's public surface: users read and filter them
in `rextio check`/`rextio build` output. Keeping every code documented in one
place prevents drift between the code that emits a diagnostic, the user docs, and
the tests. The companion test `tests/analyzer/test_diagnostic_codes.py` asserts
that every `RXT…` code emitted in the source is registered here.

`stability` is "stable" for codes whose identity we intend to keep, and
"experimental" for codes tied to experimental features (e.g. the runtime shim)
that may change before the first non-alpha release.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticCode:
    code: str
    title: str
    stability: str = "stable"


_CODES: tuple[DiagnosticCode, ...] = (
    DiagnosticCode("RXT000", "Python parse error in a candidate module"),
    DiagnosticCode("RXT001", "Missing type annotation for a function argument"),
    DiagnosticCode("RXT002", "Unsupported argument type for native lowering"),
    DiagnosticCode("RXT003", "Unsupported or missing return type annotation"),
    DiagnosticCode("RXT010", "Unsupported syntax or invalid @rextio.native marker"),
    DiagnosticCode("RXT020", "Unsupported dynamic Python feature"),
    DiagnosticCode("RXT030", "Unsupported external/boundary call"),
    DiagnosticCode("RXT050", "Native code generation failure"),
    DiagnosticCode("RXT060", "Build failure (configuration, prerequisites, or compile)"),
    DiagnosticCode("RXT070", "Native function calls a fallback-only function"),
    DiagnosticCode("RXT071", "Possible excessive Python/Rust boundary crossing"),
    DiagnosticCode("RXT072", "Native dependency rejected, so the caller must fall back"),
    DiagnosticCode("RXT073", "Native function call inside a Python loop may erase the speedup"),
    DiagnosticCode("RXT074", "Auto-discovered function depends on a runtime-shim native"),
    DiagnosticCode("RXT080", "Function uses the Python runtime-semantics shim", "experimental"),
)

DIAGNOSTIC_CODES: dict[str, DiagnosticCode] = {entry.code: entry for entry in _CODES}


def is_registered(code: str) -> bool:
    return code in DIAGNOSTIC_CODES
