from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_keeps_uncompilable_shapes_off_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Each of these shapes would emit Rust that fails ``cargo build`` (or silently
    # diverge) if accepted natively: E0308 for a scalar call-argument type mismatch
    # (literal float->int, a known float local, and a nested float-returning call ->
    # int), E0061 for an arity mismatch (omitted default, an extra argument, and a
    # zero-parameter callee called with an argument), a keyword-only parameter
    # supplied positionally (which would silently diverge from CPython's TypeError),
    # and E0282 for a bare-None local and a None tuple item. The analyzer must keep
    # their callers/owners on the Python fallback so the native module still builds,
    # while type-matching callers (including a matching nested call), an exact-arity
    # call, and an all-scalar tuple stay native with CPython-equivalent results.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "guard_app"
    package.mkdir(parents=True)
    (package / "ops.py").write_text(
        """
from typing import Optional


def callee(x: int) -> int:
    return x + 1


def with_default(x: int = 1) -> int:
    return x


def bad_literal_arg() -> int:
    return callee(1.2)


def bad_local_arg() -> int:
    y = 1.2
    return callee(y)


def bad_too_few() -> int:
    return with_default()


def bad_too_many() -> int:
    return callee(1, 2)


def good_caller() -> int:
    return callee(1)


def no_params() -> int:
    return 7


def bad_zero_param_arg() -> int:
    return no_params(1)


def kwonly(*, x: int) -> int:
    return x


def bad_kwonly_positional() -> int:
    return kwonly(1)


def make_float() -> float:
    return 1.5


def bad_nested_arg() -> int:
    return callee(make_float())


def bare_local() -> Optional[int]:
    x = None
    return x


def tuple_none() -> Optional[int]:
    pair = (None,)
    return pair[0]


def scalar_tuple() -> tuple[int, float]:
    return (1, 2.0)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    # The native module must still compile even though every uncompilable shape is
    # present in the source; they are routed to the Python fallback, not built.
    assert report["native_build"]["status"] == "built"

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    ops = importlib.import_module("guard_app.ops")

    # The functions that stay native (or whose fallback does not depend on a native
    # callee's argument enforcement) run with CPython-equivalent semantics.
    assert ops.callee(4) == 5
    assert ops.good_caller() == 2
    assert ops.bare_local() is None
    assert ops.tuple_none() is None
    assert ops.scalar_tuple() == (1, 2.0)
    # The mismatched/over-arity callers were kept off native so the module compiled;
    # their runtime behavior (raising at the native callee boundary, or a genuine
    # CPython arity TypeError) is orthogonal to the build-break this guards against.
    with pytest.raises(TypeError):
        ops.bad_too_many()
