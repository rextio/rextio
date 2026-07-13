from __future__ import annotations

import importlib
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_native_print_of_bool_and_float_matches_cpython(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    # print of bool/float is lowered to CPython-exact text (True/False and
    # __rextio_repr_float's shortest correctly-rounded repr - never Rust's
    # true/false or NaN spellings). Rust's println! writes to the OS-level
    # stdout, so capture with capfd, not capsys.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "printfmt_app" / "render.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def render(flag: bool, x: float) -> None:
    print(flag, x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("printfmt_app.render")

    battery = [
        1.0,
        -1.5,
        0.1,
        1e15,
        1e16,
        0.0001,
        0.00001,
        1.5e-5,
        5e-324,
        1e308,
        -0.0,
        2.7907518603480913e14,  # Ryu/Gay shortest-repr tie-break case
        math.nan,
        math.inf,
        -math.inf,
    ]
    capfd.readouterr()
    for flag in (True, False):
        for value in battery:
            module.render(flag, value)
            captured = capfd.readouterr()
            assert captured.out == f"{flag} {value!r}\n", (flag, value)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_native_list_index_failure_message_matches_cpython(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CPython's message interpolates the needle repr: "5 is not in list",
    # "'x' is not in list". The native message must match, including the
    # exception type (ValueError).
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "indexmsg_app" / "finder.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def find_int(xs: list[int], needle: int) -> int:
    return xs.index(needle)

@rextio.native
def find_str(xs: list[str], needle: str) -> int:
    return xs.index(needle)

@rextio.native
def find_nested(xs: list[list[int]], needle: list[int]) -> int:
    return xs.index(needle)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("indexmsg_app.finder")

    with pytest.raises(ValueError) as int_error:
        module.find_int([1, 2], 5)
    with pytest.raises(ValueError) as str_error:
        module.find_str(["a"], "it's")
    with pytest.raises(ValueError) as ctrl_error:
        module.find_str(["a"], "ctl\x01\x1b")

    with pytest.raises(ValueError) as nested_error:
        module.find_nested([[1, 2]], [3])

    assert str(int_error.value) == str(_cpython_index_error([1, 2], 5))
    assert str(str_error.value) == str(_cpython_index_error(["a"], "it's"))
    assert str(ctrl_error.value) == str(_cpython_index_error(["a"], "ctl\x01\x1b"))
    assert str(nested_error.value) == str(_cpython_index_error([[1, 2]], [3]))


def _cpython_index_error(xs: list, needle: object) -> ValueError:
    try:
        xs.index(needle)
    except ValueError as exc:
        return exc
    raise AssertionError("needle unexpectedly present")


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_native_print_of_containers_matches_cpython(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Containers compose CPython repr recursively (quoted strings, True/False,
    # float repr, nested lists, tuples, Optional None).
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "containerfmt_app" / "render.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def show(words: list[str], flags: list[bool], values: list[float], nested: list[list[int]], pair: tuple[int, str], opt: int | None) -> None:
    print(words, flags, values, nested, pair, opt)

@rextio.native
def show_opt_str(x: str | None) -> None:
    print(x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("containerfmt_app.render")

    cases = [
        (
            ["a", "it's", 'say "hi"', ""],
            [True, False],
            [1.0, 1e16, -0.0],
            [[1, 2], []],
            (7, "x"),
            None,
        ),
        ([], [], [], [], (0, ""), 5),
    ]
    capfd.readouterr()
    for words, flags, values, nested, pair, opt in cases:
        module.show(words, flags, values, nested, pair, opt)
        captured = capfd.readouterr()
        expected = f"{words} {flags} {values} {nested} {pair} {opt}\n"
        assert captured.out == expected, (words, flags, values, nested, pair, opt)

    # print of a top-level Optional[str] uses str() semantics: bare payload,
    # not the repr-quoted form (an Optional IS its payload at runtime).
    for value in ("hi", "it's", None, ""):
        module.show_opt_str(value)
        captured = capfd.readouterr()
        assert captured.out == f"{value}\n", value
