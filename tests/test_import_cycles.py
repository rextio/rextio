"""Import-cycle regression guard for the decomposed modules (mod-proposal P0-5).

The generator and analyzer were split into smaller modules with care to avoid
import cycles (e.g. `RustCodegenError` lives in `errors` so codegen submodules can
raise it without importing `generator`; `type_predicates` depends only on
`native_marker`/`capabilities`). A future deeper split could silently reintroduce
a cycle that only fails at runtime depending on import order.

Each module is imported *first* in a fresh interpreter (a subprocess), which is
exactly the condition under which a circular import fails — and keeps the check
isolated from the rest of the test session's module state.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

_MODULES = [
    "rextio.codegen.rust.errors",
    "rextio.codegen.rust.rust_format",
    "rextio.codegen.rust.checked_arith",
    "rextio.codegen.rust.generator",
    "rextio.analyzer.type_predicates",
    "rextio.analyzer.native_marker",
    "rextio.analyzer.unsupported_patterns",
]


@pytest.mark.parametrize("module_name", _MODULES)
def test_module_imports_first_without_cycle(module_name: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", f"import {module_name}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_rust_codegen_error_is_reexported_from_generator() -> None:
    # The split moved RustCodegenError into `errors`; `generator` must still
    # expose the same class object for existing importers.
    from rextio.codegen.rust import errors, generator

    assert generator.RustCodegenError is errors.RustCodegenError
