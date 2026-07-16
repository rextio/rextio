"""WP-4 follow-up 6 real-Cargo regressions: final binding is authoritative.

Each case reproduces a confirmed silent miscompile end-to-end — build a real
crate with cargo, import the generated hybrid module, and assert the native leg
now produces the SAME value as CPython (because the stale target fails closed to
the Python fallback) rather than the old wrong native result. The Python and
native sentinel values are deliberately non-equal for the *stale* target, so a
regression that re-lowered the stale target would fail the equality assertion.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main

_TOML = """
[rust]
build_tool = "cargo"
"""


def _write(tmp_path: Path, files: dict[str, str]) -> None:
    (tmp_path / "rextio.toml").write_text(_TOML, encoding="utf-8")
    for rel, contents in files.items():
        path = tmp_path / "src" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


def _build(tmp_path: Path) -> dict:
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"
    return report


def _statuses(tmp_path: Path) -> dict[str, str]:
    main(["check", str(tmp_path)])
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    return {
        function["qualname"]: function["native_status"]
        for module in report["modules"]
        for function in module["functions"]
    }


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_same_module_stale_project_function_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `def good` (x + 100) then `class good` (x + 200): CPython resolves the class,
    # so udf(1) == good(1) == 201. Before the fix, native lowered the stale
    # function and the wrapper installed it (both 101). Now both fail closed.
    _write(
        tmp_path,
        {
            "wp4f1/ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "class good:\n    def __new__(cls, x: int) -> int:\n        return x + 200\n\n"
                "@rextio.native\ndef udf(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    # Both the overwritten native definition and the stale call fail closed.
    assert statuses["wp4f1.ops.good"] == "rejected"
    assert statuses["wp4f1.ops.udf"] == "rejected"
    # A native build still happens for other functions in a real project, but here
    # neither is native, so there is no native artifact to build.
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4f1.ops")
    # The wrapper did NOT install the overwritten native function: the class wins.
    assert module.good(1) == 201
    assert module.udf(1) == 201


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_wildcard_import_builtin_shadow_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `from .helper import *` shadows builtin abs with helper.abs (x + 100), so
    # CPython udf(-5) == abs(-5) == 95. Before the fix native emitted the builtin
    # abs and returned 5. The helper's own abs (its module-final def) stays native.
    _write(
        tmp_path,
        {
            "wp4f3/__init__.py": "",
            "wp4f3/helper.py": "def abs(x: int) -> int:\n    return x + 100\n",
            "wp4f3/app.py": (
                "import rextio\nfrom .helper import *\n\n"
                "import rextio\n\n"
                "@rextio.native\ndef udf(x: int) -> int:\n    return abs(x)\n"
            ),
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp4f3.app.udf"] == "rejected"
    assert statuses["wp4f3.helper.abs"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    app = fresh_import("wp4f3.app")
    # helper.abs (x + 100), NOT builtin abs (which would give 5).
    assert app.udf(-5) == 95


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_class_math_head_shadow_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `import math` then `class math` with a custom sin returning 100.5: CPython
    # udf(1.0) == 100.5. Before the fix native lowered stdlib sin ≈ 0.8415.
    _write(
        tmp_path,
        {
            "wp4f4/ops.py": (
                "import rextio\nimport math\n\n"
                "class math:\n    @staticmethod\n"
                "    def sin(x: float) -> float:\n        return 100.5\n\n"
                "@rextio.native\ndef udf(x: float) -> float:\n    return math.sin(x)\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp4f4.ops.udf"] == "rejected"
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4f4.ops")
    assert module.udf(1.0) == 100.5


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_shadowed_math_constant_does_not_lower_stdlib_pi(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `import math` then `class math` with `pi = 100.5`: CPython reads the class
    # attr (100.5). Before the fix native lowered `std::f64::consts::PI`
    # (3.14159...). The receiver-ignored constant read now fails the direct-native
    # path, so the value is preserved (via the Python-runtime-semantics shim).
    _write(
        tmp_path,
        {
            "wp4f6/ops.py": (
                "import rextio\nimport math\n\n"
                "class math:\n    pi = 100.5\n\n"
                "@rextio.native\ndef udf() -> float:\n    return math.pi\n"
            )
        },
    )
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4f6.ops")
    assert module.udf() == 100.5


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_valid_sibling_and_builtins_still_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # A control: with no final shadow, an ordinary builtin and a valid sibling
    # shadow both stay native and compute correctly (no over-rejection).
    _write(
        tmp_path,
        {
            "wp4f5/ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef abs(x: int) -> int:\n    return x + 100\n\n"
                "@rextio.native\ndef via_sibling(x: int) -> int:\n    return abs(x)\n\n"
                "@rextio.native\ndef via_builtin(a: int, b: int) -> int:\n    return min(a, b)\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp4f5.ops.abs"] == "accepted"
    assert statuses["wp4f5.ops.via_sibling"] == "accepted"
    assert statuses["wp4f5.ops.via_builtin"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4f5.ops")
    assert module.via_sibling(-5) == 95  # sibling abs (x + 100), not builtin
    assert module.via_builtin(3, 7) == 3
