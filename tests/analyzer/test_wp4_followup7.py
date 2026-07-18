"""WP-4 follow-up 7: residual final-binding and runtime-target holes.

Analyzer-level regressions for the four confirmed P0 divergences and the P1
authority-contract positives. Each case runs the real ``analyze_project``
pipeline (so the import map, the shared final-binding authority, and the
project-wide mutation authority are all populated exactly as in production) and
asserts the native status of the affected functions.

* P0-1 — a dotted stdlib receiver (``math.sin``/``math.pi``) is native only with a
  proven final import; a never-imported spelling fails closed (CPython
  ``NameError``).
* P0-2 — a native method belongs to the module's exact final class and the class
  body's exact final method binding; duplicates/overwrites fail closed.
* P0-3 — an unproven module-execution effect (``exec``/``globals`` mutation, an
  unproven decorator/default) invalidates earlier stale bindings.
* P0-4 — a project module attribute mutated at module load blocks every
  direct-native call/import that reaches the stale target.
* P1 — ``import pkg.sub`` binds ``pkg``; re-export chains resolve with cycle
  detection; ``from __future__ import annotations`` binds nothing; positives are
  preserved.
"""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project


def _statuses(root: Path, files: dict[str, str]) -> dict[str, str]:
    for rel, contents in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    analysis = analyze_project(root)
    statuses: dict[str, str] = {}
    for module in analysis.modules:
        for function in module.functions:
            if function.accepted and function.native_runtime_semantics:
                statuses[function.qualname] = "shim"
            elif function.accepted:
                statuses[function.qualname] = "native"
            elif function.is_native_candidate:
                statuses[function.qualname] = "rejected"
            else:
                statuses[function.qualname] = "not-candidate"
    return statuses


# --------------------------------------------------------------------------- P0-1


def test_p0_1_stdlib_receiver_without_import_fails_closed(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef f(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef p() -> float:\n    return math.pi\n"
            )
        },
    )
    # No `import math`: CPython raises NameError. The call fails closed (fallback)
    # and the constant read rides the Python-runtime shim — both run real Python.
    assert statuses["ops.f"] == "rejected"
    assert statuses["ops.p"] == "shim"


def test_p0_1_stdlib_receiver_with_proven_imports_stays_native(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\nimport math\nimport math as m\nfrom math import sin\n"
                "from math import sin as abs\n\n"
                "@rextio.native\ndef a(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef c() -> float:\n    return math.pi\n\n"
                "@rextio.native\ndef d(x: float) -> float:\n    return m.sin(x)\n\n"
                "@rextio.native\ndef e(x: float) -> float:\n    return sin(x)\n\n"
                "@rextio.native\ndef g(x: float) -> float:\n    return abs(x)\n"
            )
        },
    )
    for name in ("a", "c", "d", "e", "g"):
        assert statuses[f"ops.{name}"] == "native", name


# --------------------------------------------------------------------------- P0-2


def test_p0_2_method_on_non_final_class_or_method_fails_closed(tmp_path: Path) -> None:
    method = "    @rextio.native\n    def m(self, x: int) -> int:\n        return x + 100\n"
    cases = {
        "dup_class": f"import rextio\n\nclass A:\n{method}\nclass A:\n    pass\n",
        "class_value": f"import rextio\n\nclass A:\n{method}\nA = 3\n",
        "dup_method": (
            f"import rextio\n\nclass A:\n{method}"
            "    def m(self, x: int) -> int:\n        return x + 200\n"
        ),
        "method_value": f"import rextio\n\nclass A:\n{method}    m = 5\n",
    }
    for name, source in cases.items():
        root = tmp_path / name
        path = root / "app.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        analysis = analyze_project(root)
        statuses = [
            function.native_status
            for module in analysis.modules
            for function in module.functions
            if function.qualname == "app.A.m"
        ]
        # Contract 2.2 can additionally report the later unmarked duplicate,
        # but the legacy explicit-native rejection record must remain present.
        assert "rejected" in statuses, name


def test_p0_2_valid_final_method_stays_native_shim(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "app.py": (
                "import rextio\n\nclass A:\n    @rextio.native\n"
                "    def m(self, x: int) -> int:\n        return x + 100\n"
            )
        },
    )
    assert statuses["app.A.m"] == "shim"


# --------------------------------------------------------------------------- P0-3


def _good_caller(effect: str) -> str:
    return (
        "import rextio\n\n"
        "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
        f"{effect}\n"
        "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
    )


def test_p0_3_module_execution_effects_invalidate_stale_bindings(tmp_path: Path) -> None:
    effects = {
        "exec_rhs": '_result = exec("good = lambda x: x + 200")',
        "decorator": "@decorator_that_rebinds_good\ndef trigger(): ...",
        "default": 'def trigger(_=globals().__setitem__("good", lambda x: x + 200)): ...',
    }
    for name, effect in effects.items():
        statuses = _statuses(tmp_path / name, {"ops.py": _good_caller(effect)})
        # `good` (defined before the effect) is poisoned and not installed; the
        # caller's call to it fails closed. CPython uses the rebound lambda (201).
        assert statuses["ops.good"] == "rejected", name
        assert statuses["ops.caller"] in {"rejected", "shim", "not-candidate"}, name


def test_p0_3_later_definition_restores_and_function_body_is_not_an_effect(
    tmp_path: Path,
) -> None:
    # A later explicit `def good` after the exec effect restores the exact name.
    restore = _statuses(
        tmp_path / "restore",
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                '_r = exec("z = 1")\n\n'
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert restore["ops.good"] == "native"
    assert restore["ops.caller"] == "native"

    # `exec`/`globals` inside a FUNCTION body run later, not at module load, so they
    # are not a module-execution effect.
    body_only = _statuses(
        tmp_path / "body",
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def other(s: str):\n    exec(s)\n    globals()['z'] = 1\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert body_only["ops.good"] == "native"
    assert body_only["ops.caller"] == "native"


# --------------------------------------------------------------------------- P0-4

_HELPER = "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"


def test_p0_4_module_attribute_mutation_blocks_direct_native_targets(tmp_path: Path) -> None:
    assign = _statuses(
        tmp_path / "assign",
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HELPER,
            "pkg/app.py": (
                "import rextio\nimport pkg.helper as h\n\nh.good = lambda x: x + 200\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert assign["pkg.helper.good"] == "rejected"
    assert assign["pkg.app.caller"] in {"rejected", "shim"}

    setattr_case = _statuses(
        tmp_path / "setattr",
        {
            "pk2/__init__.py": "",
            "pk2/helper.py": _HELPER,
            "pk2/app.py": (
                "import rextio\nimport pk2.helper as h\n\nsetattr(h, 'good', lambda x: x + 200)\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert setattr_case["pk2.helper.good"] == "rejected"
    assert setattr_case["pk2.app.caller"] in {"rejected", "shim"}

    # The mutation and the consumer live in a THIRD module: still blocked.
    third = _statuses(
        tmp_path / "third",
        {
            "pk3/__init__.py": "",
            "pk3/helper.py": _HELPER,
            "pk3/mut.py": "import pk3.helper as h\nh.good = lambda x: x + 200\n",
            "pk3/consumer.py": (
                "import rextio\nimport pk3.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert third["pk3.helper.good"] == "rejected"
    assert third["pk3.consumer.caller"] in {"rejected", "shim"}


def test_p0_4_clean_control_stays_native(tmp_path: Path) -> None:
    control = _statuses(
        tmp_path,
        {
            "pk4/__init__.py": "",
            "pk4/helper.py": _HELPER,
            "pk4/app.py": (
                "import rextio\nimport pk4.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert control["pk4.helper.good"] == "native"
    assert control["pk4.app.caller"] == "native"


# ----------------------------------------------------------------------------- P1


def test_p1_1_import_pkg_sub_resolves_valid_call(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg2/__init__.py": "",
            "pkg2/sub.py": _HELPER,
            "pkg2/app.py": (
                "import rextio\nimport pkg2.sub\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return pkg2.sub.good(x)\n"
            ),
        },
    )
    # `import pkg2.sub` binds `pkg2`; the call resolves to the real sibling, not a
    # bogus `pkg2.sub.sub.good`.
    assert statuses["pkg2.app.caller"] == "native"
    assert statuses["pkg2.sub.good"] == "native"


def test_p1_2_reexport_chain_resolves_and_fails_closed_on_mutation(tmp_path: Path) -> None:
    chain = _statuses(
        tmp_path / "chain",
        {
            "pk/__init__.py": "",
            "pk/c.py": _HELPER,
            "pk/b.py": "from pk.c import good\n",
            "pk/a.py": (
                "import rextio\nfrom pk.b import good\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            ),
        },
    )
    # A valid A -> B -> C re-export chain resolves to the defining function.
    assert chain["pk.a.caller"] == "native"

    mutated = _statuses(
        tmp_path / "mutated",
        {
            "pm/__init__.py": "",
            "pm/c.py": _HELPER,
            "pm/b.py": "from pm.c import good\n",
            "pm/mut.py": "import pm.c as c\nc.good = lambda x: x + 200\n",
            "pm/a.py": (
                "import rextio\nfrom pm.b import good\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            ),
        },
    )
    # A mutated hop anywhere in the chain fails closed.
    assert mutated["pm.c.good"] == "rejected"
    assert mutated["pm.a.caller"] in {"rejected", "shim"}


def test_p1_2_cyclic_reexport_fails_closed(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "cy/__init__.py": "",
            "cy/b.py": "from cy.a import good\n",
            "cy/a.py": (
                "import rextio\nfrom cy.b import good\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            ),
        },
    )
    # `a` re-exports from `b`, `b` re-exports from `a`: no defining function; the
    # cycle is detected and the caller fails closed rather than looping.
    assert statuses["cy.a.caller"] in {"rejected", "shim", "not-candidate"}
