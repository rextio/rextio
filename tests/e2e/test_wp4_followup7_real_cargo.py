"""WP-4 follow-up 7 real-Cargo regressions: residual final-binding/runtime holes.

Each case reproduces a confirmed silent miscompile end-to-end — build a real
crate with cargo, import the generated hybrid module, and assert the native leg
now matches CPython (because the stale/never-imported target fails closed to the
Python fallback) rather than the old wrong native result. Python and native
sentinel values are deliberately non-equal for the stale target, so a regression
that re-lowered it would fail the assertion.
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


requires_cargo = pytest.mark.skipif(
    shutil.which("cargo") is None, reason="cargo is required for native e2e"
)


@requires_cargo
def test_p0_1_stdlib_call_without_import_raises_nameerror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `math.sin(x)` with no `import math`: CPython raises NameError. Before the fix
    # native lowered stdlib sin (~0.8415). Now `f` fails closed and, running the
    # Python fallback, raises NameError — the same as CPython. `keep` is a valid
    # native sibling so the crate still builds.
    _write(
        tmp_path,
        {
            "wp7a/ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef f(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp7a.ops.f"] == "rejected"
    assert statuses["wp7a.ops.keep"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp7a.ops")
    with pytest.raises(NameError):
        module.f(1.0)
    assert module.keep(1) == 2


@requires_cargo
def test_p0_1_stdlib_constant_without_import_raises_nameerror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `math.pi` with no `import math`: CPython raises NameError. Before the fix
    # native lowered `std::f64::consts::PI`. Now `p` rides the Python-runtime shim
    # and raises NameError.
    _write(
        tmp_path,
        {
            "wp7b/ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef p() -> float:\n    return math.pi\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp7b.ops")
    with pytest.raises(NameError):
        module.p()
    assert module.keep(1) == 2


@requires_cargo
def test_p0_1_stdlib_with_proven_import_is_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # Control: `import math` (and an alias) proves the receiver, so the calls stay
    # native and compute correctly.
    import math

    _write(
        tmp_path,
        {
            "wp7c/ops.py": (
                "import rextio\nimport math\nimport math as m\n\n"
                "@rextio.native\ndef s(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef t(x: float) -> float:\n    return m.sin(x)\n\n"
                "@rextio.native\ndef pi() -> float:\n    return math.pi\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp7c.ops.s"] == "accepted"
    assert statuses["wp7c.ops.t"] == "accepted"
    assert statuses["wp7c.ops.pi"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp7c.ops")
    assert module.s(1.0) == pytest.approx(math.sin(1.0))
    assert module.t(1.0) == pytest.approx(math.sin(1.0))
    assert module.pi() == pytest.approx(math.pi)


@requires_cargo
def test_p0_2_overwritten_class_method_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `class A` with a native method `m`, then a second `class A: pass`. CPython's
    # final `A` has no `m`. Before the fix the wrapper installed `A.m` (or crashed
    # on import reading the missing attribute). Now the method is rejected: the
    # wrapper imports cleanly and the final `A` has no `m`, exactly like CPython.
    _write(
        tmp_path,
        {
            "wp7d/ops.py": (
                "import rextio\n\n"
                "class A:\n    @rextio.native\n"
                "    def m(self, x: int) -> int:\n        return x + 100\n\n"
                "class A:\n    pass\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp7d.ops.A.m"] == "rejected"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp7d.ops")
    assert not hasattr(module.A, "m")
    assert module.keep(1) == 2


@requires_cargo
def test_p0_2_valid_final_method_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # Control: a valid final class + method installs and runs.
    _write(
        tmp_path,
        {
            "wp7e/ops.py": (
                "import rextio\n\nclass A:\n    @rextio.native\n"
                "    def m(self, x: int) -> int:\n        return x + 100\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp7e.ops.A.m"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp7e.ops")
    assert module.A().m(1) == 101


@requires_cargo
@pytest.mark.parametrize(
    "slug, effect",
    [
        ("wp7f1", '_result = exec("good = lambda x: x + 200")'),
        ("wp7f2", "@decorator_that_rebinds_good\ndef trigger(): ..."),
        ("wp7f3", 'def trigger(_=globals().__setitem__("good", lambda x: x + 200)): ...'),
    ],
)
def test_p0_3_module_execution_effect_uses_rebound_good(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    slug: str,
    effect: str,
) -> None:
    # Each effect rebinds `good` at module load, so CPython's `caller(1)` uses the
    # rebound lambda (201). Before the fix native lowered the stale `good` (101).
    # Now both `good` and `caller` fail closed and run the rebound Python object.
    decorator = (
        "def decorator_that_rebinds_good(fn):\n"
        "    globals()['good'] = lambda x: x + 200\n    return fn\n\n"
        if "decorator_that_rebinds_good" in effect
        else ""
    )
    _write(
        tmp_path,
        {
            f"{slug}/ops.py": (
                "import rextio\n\n"
                f"{decorator}"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                f"{effect}\n\n"
                "import rextio\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import(f"{slug}.ops")
    assert module.caller(1) == 201


@requires_cargo
def test_p0_4_module_attribute_mutation_uses_rebound_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # `pkg.app` mutates `pkg.helper.good` at import. CPython's `caller(1)` uses the
    # rebound lambda (201). Before the fix native called the stale compiled target
    # (101). Now `good` is not installed and `caller` runs the rebound attribute.
    _write(
        tmp_path,
        {
            "wp7g/__init__.py": "",
            "wp7g/helper.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"
            ),
            "wp7g/app.py": (
                "import rextio\nimport wp7g.helper as h\n\nh.good = lambda x: x + 200\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp7g.helper.good"] == "rejected"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    app = fresh_import("wp7g.app")
    assert app.caller(1) == 201
