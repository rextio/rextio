"""WP-4 follow-up 4, section 1: fixed-binding stability across every binder.

A native local/parameter lowers to one Rust binding of a fixed type; a later
binding (plain ``Assign``, ``AnnAssign``, or walrus/``NamedExpr`` — inside a
comprehension too) that changes that type must fail during analysis rather than
generate uncompilable Rust. Scalar ``int``↔``float`` changes are the plugin-free
controls here; resident/plugin controls live in the resident-chain e2e.
"""

from __future__ import annotations

import ast

import pytest

from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.unsupported_patterns import validate_native_function


def _accepts(src: str) -> bool:
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    analysis = FunctionAnalysis(
        name=fn.name,
        qualname=f"m.{fn.name}",
        module_name="m",
        file_path="m.py",
        line=1,
        column=0,
        is_native_candidate=True,
    )
    validate_native_function(fn, analysis)
    return analysis.accepted


_INCOMPATIBLE = [
    # plain Assign: scalar int -> float
    "def f() -> float:\n    x = 1\n    x = 1.0\n    return x",
    # AnnAssign re-annotates an existing int binding as float
    "def f() -> float:\n    x = 1\n    x: float = 1.0\n    return x",
    # a scalar parameter reassigned to a different scalar type
    "def f(x: int) -> float:\n    x = 1.0\n    return x",
    # walrus inside a comprehension changing an existing binding's type
    "def f() -> int:\n    x = 1\n    ys = [(x := 1.0) for _n in range(3)]\n    return len(ys)",
]


@pytest.mark.parametrize("src", _INCOMPATIBLE)
def test_type_changing_rebinding_falls_back(src: str) -> None:
    assert _accepts(src) is False


_COMPATIBLE = [
    # same-type rebinding is fine (the let-mut binding keeps its type)
    "def f() -> int:\n    x = 1\n    x = 2\n    return x",
    "def f() -> float:\n    x = 1.0\n    x = 2.0\n    return x",
    # a fresh walrus target is not a rebinding
    "def f() -> int:\n    ys = [(y := n) for n in range(3)]\n    return len(ys)",
]


@pytest.mark.parametrize("src", _COMPATIBLE)
def test_same_type_rebinding_stays_native(src: str) -> None:
    assert _accepts(src) is True
