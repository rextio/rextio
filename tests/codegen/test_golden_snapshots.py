"""Golden snapshot tests for the deterministic Rust/PyO3 code generator.

The generator claims deterministic output; these tests pin the generated Rust for
representative inputs against committed golden files so any unintended change to
codegen is caught in review. Regenerate with ``REXTIO_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import os
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_crate_module, generate_rust_module
from rextio.ir.lowering import lower_project

_GOLDEN_DIR = Path(__file__).parent / "golden"

# A single module exercising arithmetic, control flow, list/dict/set, indexing,
# comprehensions, native-to-native calls, and string handling.
_SOURCE = """
import rextio

@rextio.native
def total(xs: list[int]) -> int:
    acc = 0
    for x in xs:
        acc += x
    return acc

@rextio.native
def at(xs: list[int], i: int) -> int:
    return xs[i]

@rextio.native
def doubled(xs: list[int]) -> list[int]:
    return [x * 2 for x in xs]

@rextio.native
def lookup(scores: dict[str, int], key: str) -> int:
    return scores[key]

@rextio.native
def classify(n: int) -> str:
    if n > 0:
        return "positive"
    if n < 0:
        return "negative"
    return "zero"

@rextio.native
def sum_total(xs: list[int]) -> int:
    return total(xs) + 1

"""

# Native try/except is pyo3-backend-only, so the exception-dispatch snapshot
# (Python::attach guard) rides a pyo3-specific source variant.
_SOURCE_PYO3_ONLY = _SOURCE + """
@rextio.native
def safe_mod(a: int, b: int) -> int:
    out = 0
    try:
        out = a % b
    except ZeroDivisionError:
        out = -1
    return out
"""


def _write_project(tmp_path: Path, source: str = _SOURCE) -> Path:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return tmp_path


def _normalize_newlines(text: str) -> str:
    # The generator always emits LF; normalize the on-disk golden in case a
    # Windows / `core.autocrlf` checkout rewrote it to CRLF, so the comparison
    # tests determinism of content rather than line endings. `.gitattributes`
    # pins these files to LF as the primary guard; this is belt-and-suspenders.
    return text.replace("\r\n", "\n")


def _assert_golden(name: str, generated: str) -> None:
    golden_path = _GOLDEN_DIR / name
    if os.environ.get("REXTIO_UPDATE_GOLDEN") == "1":
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(generated, encoding="utf-8", newline="\n")
        return
    assert golden_path.exists(), (
        f"missing golden file {golden_path}; run REXTIO_UPDATE_GOLDEN=1 pytest to create it"
    )
    expected = golden_path.read_text(encoding="utf-8")
    assert _normalize_newlines(generated) == _normalize_newlines(expected), (
        f"generated Rust diverged from {name}; if intended, regenerate with "
        "REXTIO_UPDATE_GOLDEN=1 pytest"
    )


def test_pyo3_module_matches_golden(tmp_path: Path) -> None:
    source = generate_rust_module(
        lower_project(analyze_project(_write_project(tmp_path, _SOURCE_PYO3_ONLY)))
    )
    _assert_golden("representative_pyo3.rs", source)


def test_crate_module_matches_golden(tmp_path: Path) -> None:
    source = generate_rust_crate_module(lower_project(analyze_project(_write_project(tmp_path))))
    _assert_golden("representative_crate.rs", source)


def test_generation_is_deterministic(tmp_path: Path) -> None:
    # Same input, generated twice, must be byte-identical.
    project = _write_project(tmp_path)
    first = generate_rust_module(lower_project(analyze_project(project)))
    second = generate_rust_module(lower_project(analyze_project(project)))
    assert first == second
