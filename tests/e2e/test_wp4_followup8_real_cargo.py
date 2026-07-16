"""WP-4 follow-up 8 real-Cargo executable-binding identity regressions.

The stale bodies use distinct sentinel results (101 native vs 201 rebound
Python) so every assertion proves that source-visible execution/mutation won
and was not silently replaced by a stale Rust target.
"""

from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import pytest
import rextio

from rextio.cli.main import main

_TOML = """
[rust]
build_tool = "cargo"
"""


def _write(tmp_path: Path, files: dict[str, str]) -> None:
    (tmp_path / "rextio.toml").write_text(_TOML, encoding="utf-8")
    for relative, source in files.items():
        path = tmp_path / "src" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def _build(tmp_path: Path) -> dict[str, object]:
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"
    return report


def _statuses(tmp_path: Path) -> dict[str, str]:
    assert main(["check", str(tmp_path)]) == 0
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    return {
        function["qualname"]: (
            "shim"
            if function["native_status"] == "accepted" and function["native_runtime_semantics"]
            else function["native_status"]
        )
        for module in report["modules"]
        for function in module["functions"]
    }


requires_cargo = pytest.mark.skipif(
    shutil.which("cargo") is None, reason="cargo is required for native e2e"
)


@pytest.fixture(autouse=True)
def _restore_process_global_mutations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep deliberate source-level stdlib/Rextio mutation local to each repro."""
    # Register the clean current values with monkeypatch.  Test modules imported
    # later may assign these attributes directly; monkeypatch's teardown still
    # restores the snapshots and prevents order-dependent fallback identities.
    monkeypatch.setattr(rextio, "native", rextio.native)
    monkeypatch.setattr(math, "sin", math.sin)
    monkeypatch.setattr(math, "pi", math.pi)


@requires_cargo
@pytest.mark.parametrize(
    "slug,effect",
    [
        ("wp8localcall", "_result = mutate()"),
        ("wp8default", "def trigger(_=mutate()):\n    pass"),
    ],
)
def test_local_mutator_execution_uses_rebound_function(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    slug: str,
    effect: str,
) -> None:
    _write(
        tmp_path,
        {
            f"{slug}/ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def mutate():\n    globals()['good'] = lambda x: x + 200\n\n"
                f"{effect}\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses[f"{slug}.ops.good"] == "rejected"
    assert statuses[f"{slug}.ops.caller"] != "accepted"
    assert statuses[f"{slug}.ops.keep"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import(f"{slug}.ops")
    assert module.caller(1) == 201
    assert module.keep(1) == 2


@requires_cargo
def test_class_body_import_alias_mutation_uses_rebound_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    _write(
        tmp_path,
        {
            "wp8class/__init__.py": "",
            "wp8class/helper.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"
            ),
            "wp8class/mutator.py": (
                "import wp8class.helper as h\n\nclass Trigger:\n    h.good = lambda x: x + 200\n"
            ),
            "wp8class/app.py": (
                "import rextio\nimport wp8class.mutator\nimport wp8class.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            ),
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp8class.helper.good"] == "rejected"
    assert statuses["wp8class.app.caller"] != "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    app = fresh_import("wp8class.app")
    assert app.caller(1) == 201
    assert app.keep(1) == 2


@requires_cargo
@pytest.mark.parametrize(
    "slug,mutation,caller",
    [
        (
            "wp8alias",
            "import wp8alias.helper as h\na = h\na.good = lambda x: x + 200",
            "h.good(x)",
        ),
        (
            "wp8overwrite",
            "import wp8overwrite.helper as h\nh.good = lambda x: x + 200\nh = None",
            "h.good(x)",
        ),
        (
            "wp8prefix",
            (
                "import wp8prefix as pkg\n"
                "class Fake:\n    good = staticmethod(lambda x: x + 200)\n"
                "pkg.helper = Fake"
            ),
            "wp8prefix.helper.good(x)",
        ),
    ],
)
def test_alias_copy_before_overwrite_and_parent_prefix_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    slug: str,
    mutation: str,
    caller: str,
) -> None:
    helper_import = (
        f"import {slug}.helper as h\n" if caller.startswith("h.") else f"import {slug}\n"
    )
    _write(
        tmp_path,
        {
            f"{slug}/__init__.py": "from . import helper\n",
            f"{slug}/helper.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"
            ),
            f"{slug}/mutator.py": f"{mutation}\n",
            f"{slug}/app.py": (
                f"import rextio\nimport {slug}.mutator\n{helper_import}\n"
                f"@rextio.native\ndef caller(x: int) -> int:\n    return {caller}\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            ),
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses[f"{slug}.helper.good"] == "rejected"
    assert statuses[f"{slug}.app.caller"] != "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    app = fresh_import(f"{slug}.app")
    assert app.caller(1) == 201
    assert app.keep(1) == 2


_CLASS_CASES = [
    (
        "decorator",
        (
            "def replace(cls):\n"
            "    class B:\n        pass\n"
            "    return B\n\n"
            "@replace\nclass A:\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 100\n"
        ),
        "missing",
    ),
    (
        "base",
        (
            "class Base:\n"
            "    def __init_subclass__(cls):\n        del cls.m\n\n"
            "class A(Base):\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 100\n"
        ),
        "missing",
    ),
    (
        "metaclass",
        (
            "class Meta(type):\n"
            "    def __new__(meta, name, bases, namespace):\n"
            "        namespace.pop('m', None)\n"
            "        return super().__new__(meta, name, bases, namespace)\n\n"
            "import rextio\n\n"
            "class A(metaclass=Meta):\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 100\n"
        ),
        "missing",
    ),
    (
        "assign",
        (
            "class A:\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 100\n\n"
            "A.m = lambda self, x: x + 200\n"
        ),
        "replaced",
    ),
    (
        "delete",
        (
            "class A:\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 100\n\n"
            "del A.m\n"
        ),
        "missing",
    ),
]


@requires_cargo
@pytest.mark.parametrize("slug_suffix,class_source,outcome", _CLASS_CASES)
def test_unstable_class_construction_and_post_class_mutation_do_not_install_method(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    slug_suffix: str,
    class_source: str,
    outcome: str,
) -> None:
    slug = f"wp8method_{slug_suffix}"
    _write(
        tmp_path,
        {
            f"{slug}/ops.py": f"import rextio\n\n{class_source}\n",
            f"{slug}/clean.py": (
                "import rextio\n\n@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            ),
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses.get(f"{slug}.ops.A.m") != "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import(f"{slug}.ops")
    clean = fresh_import(f"{slug}.clean")
    if outcome == "replaced":
        assert module.A().m(1) == 201
    else:
        assert not hasattr(module.A, "m")
    assert clean.keep(1) == 2


@requires_cargo
@pytest.mark.parametrize(
    "slug,marker_source",
    [
        (
            "wp8fake",
            (
                "def native(fn):\n    return lambda x: x + 200\n\n"
                "@native\ndef f(x: int) -> int:\n    return x + 100\n"
            ),
        ),
        (
            "wp8mutmarker",
            (
                "import rextio\n"
                "rextio.native = lambda fn: (lambda x: x + 200)\n\n"
                "@rextio.native\ndef f(x: int) -> int:\n    return x + 100\n"
            ),
        ),
    ],
)
def test_fake_or_mutated_native_marker_never_lowers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    slug: str,
    marker_source: str,
) -> None:
    _write(
        tmp_path,
        {f"{slug}/ops.py": (f"{marker_source}\n\ndef keep(x: int) -> int:\n    return x + 1\n")},
    )
    statuses = _statuses(tmp_path)
    assert statuses[f"{slug}.ops.f"] != "accepted"
    assert statuses[f"{slug}.ops.keep"] == "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import(f"{slug}.ops")
    assert module.f(1) == 201
    assert module.keep(1) == 2


@requires_cargo
def test_mutated_math_call_and_constant_are_not_statically_lowered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    _write(
        tmp_path,
        {
            "wp8math/ops.py": (
                "import rextio\nimport math\n\n"
                "math.sin = lambda x: 201.0\nmath.pi = 9.0\n\n"
                "@rextio.native\ndef f(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef p() -> float:\n    return math.pi\n\n"
                "@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp8math.ops.f"] != "accepted"
    assert statuses["wp8math.ops.p"] != "accepted"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp8math.ops")
    assert module.f(1.0) == 201.0
    assert module.p() == 9.0
    assert module.keep(1) == 2


@requires_cargo
def test_clean_math_sibling_and_stable_method_remain_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    _write(
        tmp_path,
        {
            "wp8clean/ops.py": (
                "import rextio\nimport math\nimport math as m\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n\n"
                "@rextio.native\ndef sine(x: float) -> float:\n    return m.sin(x)\n\n"
                "@rextio.native\ndef pi() -> float:\n    return math.pi\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def method(self, x: int) -> int:\n        return x + 100\n"
            )
        },
    )
    statuses = _statuses(tmp_path)
    for qualname in (
        "wp8clean.ops.good",
        "wp8clean.ops.caller",
        "wp8clean.ops.sine",
        "wp8clean.ops.pi",
    ):
        assert statuses[qualname] == "accepted"
    assert statuses["wp8clean.ops.A.method"] == "shim"
    _build(tmp_path)
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp8clean.ops")
    assert module.caller(1) == 101
    assert module.sine(1.0) == pytest.approx(math.sin(1.0))
    assert module.pi() == pytest.approx(math.pi)
    assert module.A().method(1) == 101


@requires_cargo
@pytest.mark.parametrize(
    "replacement,error",
    [
        ("class A:\n    pass\n", "fallback method is missing"),
        (
            "class A:\n    m = lambda self, x: x + 200\n",
            "fallback method identity mismatch",
        ),
    ],
)
def test_wrapper_runtime_guard_rejects_missing_or_replaced_method(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
    replacement: str,
    error: str,
) -> None:
    _write(
        tmp_path,
        {
            "wp8guard/ops.py": (
                "import rextio\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n        return x + 100\n"
            )
        },
    )
    _build(tmp_path)
    fallback = tmp_path / ".rextio" / "build" / "python" / "wp8guard" / "_fallback_ops.py"
    fallback.write_text(replacement, encoding="utf-8")
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    with pytest.raises(RuntimeError, match=error):
        fresh_import("wp8guard.ops")
