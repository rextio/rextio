"""IR -> backend contract tests (mod-proposal P1-7).

The product invariant is "analysis accepts => code generation succeeds": any
function the analyzer admits into the native subset must flow all the way through
``lower_project`` and the Rust backends without raising. These tests pin that
contract over a corpus spanning the supported subset, so a future analyzer change
that accepts a construct the backend can't emit fails here instead of at a user's
``cargo build``.

Scope: this is a code-generation contract — the generated Rust is *inspected*
(it is produced without raising and contains the expected markers) but it is not
compiled by Cargo here. Real compilation is covered by the ``needs_cargo`` e2e
suite; keeping that out of this fast unit-level test is deliberate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import (
    RustCodegenError,
    generate_rust_crate_module,
    generate_rust_module,
)
from rextio.ir.lowering import lower_project

# Direct-Rust corpus: each module's accepted functions lower straight to Rust, so
# both the pyo3 module and the importable crate must succeed.
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
    "tuples_and_optional": """
import rextio

@rextio.native
def pair(a: int, b: int) -> tuple[int, int]:
    return (a, b)

@rextio.native
def maybe(a: int, flag: bool) -> int | None:
    if flag:
        return a
    return None
""",
    "str_and_bytes_methods": """
import rextio

@rextio.native
def shout(s: str) -> str:
    return s.upper()

@rextio.native
def head(b: bytes) -> int:
    return len(b)
""",
    "stdlib_lowering": """
import base64
import hashlib
import json
import rextio

@rextio.native
def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

@rextio.native
def encode(b: bytes) -> bytes:
    return base64.b64encode(b)

@rextio.native
def dump(xs: list[int]) -> str:
    return json.dumps(xs)
""",
}

# Runtime-semantics (RXT080) corpus: functions that preserve Python object
# semantics through a PyO3 shim rather than direct-Rust lowering. They must still
# emit a pyo3 module, but they are *not* part of the importable crate, so crate
# generation must reject them rather than silently dropping or miscompiling them.
_SHIM_CORPUS: dict[str, str] = {
    "exception_handling": """
import rextio

@rextio.native
def safe_inc(a: int) -> int:
    try:
        return a + 1
    except Exception:
        return 0
""",
    "generator": """
import rextio

@rextio.native
def counts(n: int):
    for i in range(n):
        yield i
""",
}


def _analyze(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    analysis = analyze_project(tmp_path)
    # The corpus must actually be accepted, otherwise the contract is vacuous.
    assert not analysis.has_error_diagnostics, [
        d.to_dict() for d in analysis.error_diagnostics
    ]
    assert analysis.accepted_native_functions, "module produced no accepted native functions"
    return analysis


@pytest.mark.parametrize("name", sorted({**_CORPUS, **_SHIM_CORPUS}))
def test_accepted_functions_lower_and_emit_pyo3(name: str, tmp_path: Path) -> None:
    source_text = {**_CORPUS, **_SHIM_CORPUS}[name]
    _analyze(tmp_path, source_text)
    source = generate_rust_module(lower_project(analyze_project(tmp_path)))
    assert source.strip()
    assert "fn _rextio_native" in source


@pytest.mark.parametrize("name", sorted(_CORPUS))
def test_direct_rust_functions_emit_importable_crate(name: str, tmp_path: Path) -> None:
    analysis = _analyze(tmp_path, _CORPUS[name])
    # Sanity-check the corpus curation: these modules must be direct-Rust.
    assert all(
        not function.native_runtime_semantics
        for function in analysis.accepted_native_functions
    ), "direct corpus module unexpectedly routed to the runtime-semantics shim"
    source = generate_rust_crate_module(lower_project(analyze_project(tmp_path)))
    assert source.strip()
    assert "pub fn " in source


@pytest.mark.parametrize("name", sorted(_SHIM_CORPUS))
def test_runtime_shim_modules_are_excluded_from_importable_crate(
    name: str, tmp_path: Path
) -> None:
    analysis = _analyze(tmp_path, _SHIM_CORPUS[name])
    # Confirm these really are runtime-shim functions (RXT080), not direct-Rust.
    for function in analysis.accepted_native_functions:
        assert function.native_runtime_semantics, "shim corpus module lowered to direct Rust"
        assert function.has_diagnostic("RXT080"), "shim function is missing the RXT080 diagnostic"
    # The importable crate is Rust-only and cannot host the shim, so generation
    # must reject it explicitly (with the specific "no direct Rust" error) rather
    # than emit nothing or miscompile.
    with pytest.raises(RustCodegenError, match="no direct Rust"):
        generate_rust_crate_module(lower_project(analyze_project(tmp_path)))
