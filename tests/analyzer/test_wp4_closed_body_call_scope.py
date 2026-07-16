"""WP-4 follow-up 4, section 6: closed-body call targets respect scope.

A call inside a closed callable body is a pure builtin/math call only when its
head is NOT shadowed by a UDF parameter/local or a module-level binding. A
shadowed head resolves to a different target than Python calls, so the body must
be unavailable (and never ``accepts_native``); an unshadowed builtin / ``from``
import / module import stays supported.
"""

from __future__ import annotations

import ast

import pytest

from rextio.analyzer.callable_metadata import (
    IndexedSymbol,
    collect_module_final_bindings,
    extract_callable_meta,
)
from rextio.analyzer.final_bindings import build_module_bindings
from rextio.analyzer.type_collector import annotation_name, is_supported_type


def _resolve_type(annotation: ast.expr, _imports: dict[str, str]) -> str | None:
    return annotation_name(annotation) if is_supported_type(annotation) else None


def _meta_for(module_src: str, fn_name: str, imports: dict[str, str]):
    tree = ast.parse(module_src)
    fb = collect_module_final_bindings(tree)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn_name)
    indexed = IndexedSymbol(
        qualname=f"m.{fn_name}",
        name=fn_name,
        node=fn,
        module_name="m",
        imports=imports,
        final_bindings=fb,
        module_bindings=build_module_bindings(tree, "m"),
    )
    return extract_callable_meta(0, indexed, _resolve_type, receiver_schema=None)


@pytest.mark.parametrize("name", ["abs", "min", "max"])
def test_wildcard_import_shadow_makes_builtin_body_unavailable(name: str) -> None:
    # A `from x import *` may have introduced this bare builtin spelling, so the
    # closed body must fail closed even though nothing explicitly rebinds it.
    call = f"{name}(x, 1)" if name in {"min", "max"} else f"{name}(x)"
    meta = _meta_for(f"from pkg import *\ndef udf(x: int) -> int:\n    return {call}", "udf", {})
    assert meta.body.available is False
    assert meta.accepts_native is False


# (module source, fn name, imports, expect body available)
_SHADOWED = [
    ("def udf(x: int, abs: int) -> int:\n    return abs(x)", "udf", {}),
    ("from math import sin\ndef udf(x: float, sin: float) -> float:\n    return sin(x)", "udf", {}),
    (
        "import math\ndef udf(x: float, math: float) -> float:\n    return math.sin(x)",
        "udf",
        {"math": "math"},
    ),
    # a module-level project def/assignment/del that shadows the spelling
    ("def abs(x): return x\ndef udf(x: int) -> int:\n    return abs(x)", "udf", {}),
    ("sin = 5\ndef udf(x: float) -> float:\n    return sin(x)", "udf", {}),
]


@pytest.mark.parametrize("src, fn, imports", _SHADOWED)
def test_shadowed_call_head_makes_body_unavailable(src: str, fn: str, imports: dict) -> None:
    meta = _meta_for(src, fn, imports)
    assert meta.body.available is False
    assert meta.accepts_native is False


_UNSHADOWED = [
    ("def udf(x: int) -> int:\n    return abs(x)", "udf", {}),
    (
        "from math import sin\ndef udf(x: float) -> float:\n    return sin(x)",
        "udf",
        {"sin": "math.sin"},
    ),
    ("import math\ndef udf(x: float) -> float:\n    return math.sin(x)", "udf", {"math": "math"}),
]


@pytest.mark.parametrize("src, fn, imports", _UNSHADOWED)
def test_unshadowed_pure_calls_stay_supported(src: str, fn: str, imports: dict) -> None:
    meta = _meta_for(src, fn, imports)
    assert meta.body.available is True
    assert meta.accepts_native is True
