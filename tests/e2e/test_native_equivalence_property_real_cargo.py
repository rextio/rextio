"""Property-based native<->Python equivalence for integer arithmetic.

mod-proposal P0-3 asked for "Python<->native execution equivalence" tests over a
representative input space. The generated native arithmetic has a precise
contract: i64 ``+``/``-``/``*``/unary-``-`` raise ``OverflowError`` when the
mathematically-correct result leaves the i64 range, ``%`` is floored and raises
``ZeroDivisionError`` on a zero divisor. These tests build the native module once
with a real cargo toolchain and use Hypothesis to assert, over many random i64
inputs, that each native function either returns the same value as a
Python reference implementing that contract, or raises the same exception type.
"""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable, Iterator

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from rextio.cli.main import main

_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_i64 = st.integers(min_value=_I64_MIN, max_value=_I64_MAX)

_APP_SOURCE = """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

@rextio.native
def sub(a: int, b: int) -> int:
    return a - b

@rextio.native
def mul(a: int, b: int) -> int:
    return a * b

@rextio.native
def negate(a: int) -> int:
    return -a

@rextio.native
def modulo(a: int, b: int) -> int:
    return a % b
"""


def _checked(value: int) -> int:
    if not (_I64_MIN <= value <= _I64_MAX):
        raise OverflowError
    return value


def _ref_modulo(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    return a % b  # Python `%` is floored; the native helper matches it.


@pytest.fixture(scope="module")
def native_ops(tmp_path_factory: pytest.TempPathFactory) -> Iterator[object]:
    tmp = tmp_path_factory.mktemp("equiv")
    (tmp / "rextio.toml").write_text(
        '[rust]\nbuild_tool = "cargo"\n', encoding="utf-8"
    )
    source = tmp / "src" / "equiv_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(_APP_SOURCE, encoding="utf-8")

    assert main(["build", str(tmp), "--fallback=cpython"]) == 0

    build_python = tmp / ".rextio" / "build" / "python"
    previous_mode = os.environ.get("REXTIO_NATIVE_MODE")

    def _drop_built_modules() -> None:
        # Remove every module this build introduced — the native extension and
        # any equiv_app submodule — so no stale entry can leak into another test.
        for name in list(sys.modules):
            if name == "_rextio_native" or name.startswith(("_rextio_native.", "equiv_app")):
                del sys.modules[name]
        importlib.invalidate_caches()

    os.environ["REXTIO_NATIVE_MODE"] = "native"
    sys.path.insert(0, str(build_python))
    _drop_built_modules()
    try:
        yield importlib.import_module("equiv_app.math_ops")
    finally:
        if str(build_python) in sys.path:
            sys.path.remove(str(build_python))
        if previous_mode is None:
            os.environ.pop("REXTIO_NATIVE_MODE", None)
        else:
            os.environ["REXTIO_NATIVE_MODE"] = previous_mode
        _drop_built_modules()


def _assert_equivalent(native_call: Callable[[], int], reference: Callable[[], int]) -> None:
    try:
        expected = reference()
    except Exception as exc:  # noqa: BLE001 - we compare the raised type below
        with pytest.raises(type(exc)) as exc_info:
            native_call()
        # Exact type match: the native op must raise the *same* exception class as
        # CPython, not merely a subclass (e.g. a generic ArithmeticError).
        assert exc_info.type is type(exc)
        return
    assert native_call() == expected


@settings(deadline=None, max_examples=75)
@example(a=_I64_MAX, b=1)  # overflow at the upper edge
@example(a=_I64_MIN, b=-1)  # overflow at the lower edge
@example(a=0, b=0)  # in-range
@given(a=_i64, b=_i64)
def test_add_matches_reference(native_ops: object, a: int, b: int) -> None:
    _assert_equivalent(lambda: native_ops.add(a, b), lambda: _checked(a + b))


@settings(deadline=None, max_examples=75)
@example(a=_I64_MIN, b=1)  # overflow
@example(a=_I64_MAX, b=_I64_MIN)  # overflow
@example(a=5, b=3)  # in-range
@given(a=_i64, b=_i64)
def test_sub_matches_reference(native_ops: object, a: int, b: int) -> None:
    _assert_equivalent(lambda: native_ops.sub(a, b), lambda: _checked(a - b))


@settings(deadline=None, max_examples=75)
@example(a=_I64_MIN, b=-1)  # overflow (|MIN| > MAX)
@example(a=_I64_MAX, b=2)  # overflow
@example(a=6, b=7)  # in-range
@given(a=_i64, b=_i64)
def test_mul_matches_reference(native_ops: object, a: int, b: int) -> None:
    _assert_equivalent(lambda: native_ops.mul(a, b), lambda: _checked(a * b))


@settings(deadline=None, max_examples=75)
@example(a=_I64_MIN)  # -MIN overflows i64
@example(a=_I64_MAX)  # in-range
@example(a=0)
@given(a=_i64)
def test_negate_matches_reference(native_ops: object, a: int) -> None:
    _assert_equivalent(lambda: native_ops.negate(a), lambda: _checked(-a))


@settings(deadline=None, max_examples=100)
@example(a=_I64_MIN, b=-1)  # the i64 rem overflow edge; Python result is 0
@example(a=-7, b=3)  # floored: 2
@example(a=7, b=-3)  # floored: -2
@example(a=1, b=0)  # ZeroDivisionError
@given(a=_i64, b=_i64)
def test_modulo_matches_reference(native_ops: object, a: int, b: int) -> None:
    _assert_equivalent(lambda: native_ops.modulo(a, b), lambda: _ref_modulo(a, b))
