"""IR -> backend contract tests (mod-proposal P1-7).

The product invariant is "analysis accepts => code generation succeeds": any
function the analyzer admits into the native subset must flow all the way through
``lower_project`` and the Rust backends without raising. These tests pin that
contract over a corpus spanning the supported subset, so a future analyzer change
that accepts a construct the backend can't emit fails here instead of at a user's
``cargo build``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_crate_module, generate_rust_module
from rextio.ir.lowering import lower_project

# Each entry is a self-contained module whose decorated functions exercise a
# slice of the supported subset. `direct_rust` is False when the module relies on
# the runtime-semantics shim (RXT080), which is not emitted to the importable
# crate, so the crate backend is only asserted for direct-Rust modules.
_CORPUS: dict[str, str] = {
    "scalar_arithmetic": """
import rextio

@rextio.native
def mix(a: int, b: int) -> int:
    return a + b - a * b % (b + 1) + -a

@rextio.native
def floaty(a: float, b: float) -> float:
    return a / b + a % b + abs(a)
""",
    "control_flow": """
import rextio

@rextio.native
def classify(n: int) -> str:
    if n > 0:
        return "pos"
    if n < 0:
        return "neg"
    return "zero"

@rextio.native
def countdown(n: int) -> int:
    total = 0
    while n > 0:
        total += n
        n -= 1
    return total
""",
    "collections_and_comprehensions": """
import rextio

@rextio.native
def doubled(xs: list[int]) -> list[int]:
    return [x * 2 for x in xs if x > 0]

@rextio.native
def lookup(scores: dict[str, int], key: str) -> int:
    return scores[key]

@rextio.native
def uniq(xs: list[int]) -> set[int]:
    return {x for x in xs}

@rextio.native
def index_sum(xs: list[int]) -> int:
    return len(xs) + xs[0] + xs[-1]
""",
    "reductions_and_builtins": """
import rextio

@rextio.native
def stats(xs: list[int]) -> int:
    return sum(xs) + min(xs[0], xs[1]) + max(xs[0], xs[1])
""",
    "math_subset": """
import math
import rextio

@rextio.native
def geo(x: float, y: float) -> float:
    return math.sqrt(x * x + y * y)

@rextio.native
def floored(x: float) -> int:
    return math.floor(x)
""",
    "native_to_native": """
import rextio

@rextio.native
def square(x: int) -> int:
    return x * x

@rextio.native
def sum_of_squares(x: int) -> int:
    return square(x) + square(x + 1)
""",
}


def _accepted(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    analysis = analyze_project(tmp_path)
    # The corpus must actually be accepted, otherwise the contract is vacuous.
    assert not analysis.has_error_diagnostics, [
        d.to_dict() for d in analysis.error_diagnostics
    ]
    accepted = [function.qualname for function in analysis.accepted_native_functions]
    assert accepted, "corpus module produced no accepted native functions"
    return accepted


@pytest.mark.parametrize("name", sorted(_CORPUS))
def test_accepted_functions_lower_and_emit_pyo3(name: str, tmp_path: Path) -> None:
    _accepted(tmp_path, _CORPUS[name])
    source = generate_rust_module(lower_project(analyze_project(tmp_path)))
    assert source.strip()
    assert "fn _rextio_native" in source


@pytest.mark.parametrize("name", sorted(_CORPUS))
def test_accepted_functions_emit_importable_crate(name: str, tmp_path: Path) -> None:
    _accepted(tmp_path, _CORPUS[name])
    # Every corpus module is direct-Rust (no runtime-semantics shim), so the
    # importable crate backend must also succeed.
    source = generate_rust_crate_module(lower_project(analyze_project(tmp_path)))
    assert source.strip()
    assert "pub fn " in source
