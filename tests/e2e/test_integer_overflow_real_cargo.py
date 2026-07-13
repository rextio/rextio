from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


def test_real_cargo_integer_overflow_raises_instead_of_wrapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "overflow_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        """
import rextio

@rextio.native
def square(a: int) -> int:
    return a * a

@rextio.native
def accumulate(xs: list[int]) -> int:
    acc = 0
    for x in xs:
        acc += x
    return acc

@rextio.native
def modulo(a: int, b: int) -> int:
    return a % b

@rextio.native
def negate(a: int) -> int:
    return -a

@rextio.native
def min_literal() -> int:
    return -9223372036854775808

@rextio.native
def magnitude(a: int) -> int:
    return abs(a)

@rextio.native
def total(xs: list[int]) -> int:
    return sum(xs)

@rextio.native
def scaled_total(xs: list[int]) -> int:
    return sum([x * x for x in xs])
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0
    assert report["native_build"]["status"] == "built"

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    for module_name in (
        "_rextio_native",
        "overflow_app.math_ops",
        "overflow_app._fallback_math_ops",
    ):
        sys.modules.pop(module_name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("overflow_app.math_ops")

    # In-range arithmetic is unchanged.
    assert module.square(3) == 9
    assert module.accumulate([1, 2, 3]) == 6
    assert module.modulo(7, 3) == 1
    assert module.negate(5) == -5
    assert module.min_literal() == -(2**63)
    assert module.magnitude(-5) == 5
    assert module.total([1, 2, 3]) == 6
    assert module.scaled_total([1, 2, 3]) == 14

    # `%` follows Python's floored semantics (the result takes the divisor's
    # sign), not Rust's truncated remainder.
    assert module.modulo(-7, 3) == 2
    assert module.modulo(7, -3) == -2

    # An i64 overflow is a real error (Python ints are arbitrary precision). The
    # generated code uses checked arithmetic and raises `OverflowError` — a normal
    # `Exception` subclass that `except Exception:` can catch — instead of either
    # silently wrapping or raising an uncatchable PyO3 `PanicException`
    # (`BaseException`). Pin the concrete type so a regression to either failure
    # mode is caught.
    with pytest.raises(OverflowError):
        module.square(2**40)

    # The same guarantee holds for accumulation across a loop, not just a single
    # multiply.
    with pytest.raises(OverflowError):
        module.accumulate([2**62, 2**62, 2**62])

    # `OverflowError` is catchable as a plain `Exception` (the property the old
    # PanicException approach failed to provide).
    try:
        module.square(2**40)
    except Exception:
        caught = True
    else:  # pragma: no cover - the call above always raises
        caught = False
    assert caught

    # Modulo by zero is a catchable `ZeroDivisionError` (Python semantics), not a
    # Rust divide-by-zero panic; `i64::MIN % -1` is 0, not a panic.
    with pytest.raises(ZeroDivisionError):
        module.modulo(5, 0)
    assert module.modulo(-(2**63), -1) == 0

    # Negating i64::MIN overflows i64 but is representable in Python, so it is a
    # catchable `OverflowError` rather than an uncatchable panic.
    with pytest.raises(OverflowError):
        module.negate(-(2**63))

    # `abs(i64::MIN)` and an overflowing `sum` are also catchable OverflowErrors,
    # not panics — including a `sum` over an overflowing comprehension, which pins
    # that `?` propagates out of the comprehension's `push` lowering.
    with pytest.raises(OverflowError):
        module.magnitude(-(2**63))
    with pytest.raises(OverflowError):
        module.total([2**62, 2**62, 2**62])
    with pytest.raises(OverflowError):
        module.scaled_total([2**32, 2**32])
