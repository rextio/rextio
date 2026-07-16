"""WP-4 follow-up 4, section 2: callable metadata must match real core.

Every callable-body ``accepts_native`` (and, for identity/chained comparisons,
``body.available``) verdict is checked against a real
:func:`~rextio.analyzer.unsupported_patterns.validate_native_function` run on the
same function, so the static metadata never promises a native contract core
itself would fall back on.
"""

from __future__ import annotations

import ast

import pytest

from rextio.analyzer.callable_metadata import IndexedSymbol, extract_callable_meta
from rextio.analyzer.final_bindings import build_module_bindings
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.analyzer.unsupported_patterns import validate_native_function


def _resolve_type(annotation: ast.expr, _imports: dict[str, str]) -> str | None:
    return annotation_name(annotation) if is_supported_type(annotation) else None


def _meta(module_src: str):
    tree = ast.parse(module_src)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    indexed = IndexedSymbol(
        qualname=f"m.{fn.name}",
        name=fn.name,
        node=fn,
        module_name="m",
        imports={"math": "math"},
        module_bindings=build_module_bindings(tree, "m"),
    )
    return extract_callable_meta(0, indexed, _resolve_type, receiver_schema=None)


def _core_accepts(module_src: str) -> bool:
    tree = ast.parse(module_src)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    analysis = FunctionAnalysis(
        name=fn.name,
        qualname=f"m.{fn.name}",
        module_name="m",
        file_path="m.py",
        line=1,
        column=0,
        is_native_candidate=True,
        # Faithful to the real pipeline: a module-qualified stdlib call (`math.sin`)
        # is native only when the receiver is a proven final import, so the hand-
        # built analysis must carry the same import map / final-binding authority
        # the module parser attaches (plugin API 1.3, WP-4).
        imports={"math": "math"},
        module_bindings=build_module_bindings(tree, "m"),
    )
    validate_native_function(fn, analysis)
    return analysis.accepted


# (source, expect_accepts_native). accepts_native must be True exactly when real
# core accepts the function as a scalar native helper.
_ACCEPTS_MATRIX = [
    ("def udf(x: int) -> bool:\n    return x == 1", True),
    ("def udf(x: int, y: int) -> bool:\n    return x != y", True),
    ("def udf(x: int) -> bool:\n    return 0 < x < 10", True),
    ("def udf(x: float, y: float) -> bool:\n    return x <= y", True),
    ("def udf(x: int, y: int) -> int:\n    return x + y", True),
    ("def udf(x: int) -> int:\n    return abs(x)", True),
    ("def udf(a: bool, b: bool) -> bool:\n    return a and b", True),
    ("import math\ndef udf(x: float) -> float:\n    return math.sin(x)", True),
    # identity comparisons: core falls back on every form
    ("def udf(x: bool) -> bool:\n    return None is None", False),
    ("def udf(x: bool) -> bool:\n    return None is not None", False),
    ("def udf(x: bool) -> bool:\n    return x is None", False),
    ("def udf(x: bool) -> bool:\n    return None is x", False),
    # chained comparison with a call-valued middle operand
    ("import math\ndef udf(x: float) -> bool:\n    return x < math.sin(x) < 1.0", False),
    ("def udf(x: int) -> bool:\n    return x < abs(x) < 10", False),
    # conditional expression: core rejects a native IfExp helper
    ("def udf(x: int, y: int, flag: bool) -> int:\n    return x if flag else y", False),
    ("def udf(x: float, y: float, flag: bool) -> float:\n    return x if flag else y", False),
]


@pytest.mark.parametrize("source, expected", _ACCEPTS_MATRIX)
def test_accepts_native_matches_real_core(source: str, expected: bool) -> None:
    meta = _meta(source)
    assert meta.accepts_native is expected, source
    # accepts_native never disagrees with what real core would accept.
    assert meta.accepts_native == _core_accepts(source), source


@pytest.mark.parametrize(
    "source",
    [
        "def udf(x: bool) -> bool:\n    return None is None",
        "def udf(x: bool) -> bool:\n    return None is not None",
        "def udf(x: bool) -> bool:\n    return x is None",
        "def udf(x: bool) -> bool:\n    return None is x",
        "import math\ndef udf(x: float) -> bool:\n    return x < math.sin(x) < 1.0",
        "def udf(x: int) -> bool:\n    return x < abs(x) < 10",
    ],
)
def test_identity_and_call_chained_bodies_are_unavailable(source: str) -> None:
    # These forms are not modeled by the closed scalar grammar and core falls
    # back, so the body is unavailable (fail closed), not merely non-native.
    assert _meta(source).body.available is False


@pytest.mark.parametrize(
    "source",
    [
        "def udf(x: int, y: int, flag: bool) -> int:\n    return x if flag else y",
        "def udf(x: float, y: float, flag: bool) -> float:\n    return x if flag else y",
    ],
)
def test_conditional_body_available_but_not_native(source: str) -> None:
    # A conditional stays representable for a plugin to lower, but is not
    # accepts_native because core rejects a native IfExp helper.
    meta = _meta(source)
    assert meta.body.available is True
    assert meta.accepts_native is False
