"""WP-4 follow-up 8: executable binding identity must fail closed.

These regressions exercise the shared source-order binding/effect/mutation
authority through the real project analyzer.  Each negative is source-visible
Python behavior that must never be replaced by a stale Rust target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _statuses(root: Path, files: dict[str, str]) -> dict[str, str]:
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    analysis = analyze_project(root, native_marker="decorator")
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


def _good_caller(effect: str) -> str:
    return (
        "import rextio\n\n"
        "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
        f"{effect}\n\n"
        "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
    )


@pytest.mark.parametrize(
    "effect",
    [
        "_result = mutate()",
        "def trigger(_=mutate()):\n    pass",
        "if mutate():\n    pass",
        "for _item in (mutate(),):\n    pass",
        "with mutate():\n    pass",
        "@mutate()\ndef trigger():\n    pass",
        "def trigger(value: mutate()):\n    pass",
        "class Trigger(mutate()):\n    pass",
        "class Trigger:\n    value = mutate()",
    ],
)
def test_local_module_load_mutator_call_invalidates_prior_binding(
    tmp_path: Path, effect: str
) -> None:
    source = (
        "import rextio\n\n"
        "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
        "def mutate():\n    globals()['good'] = lambda x: x + 200\n\n"
        f"{effect}\n\n"
        "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
    )
    statuses = _statuses(tmp_path, {"ops.py": source})
    assert statuses["ops.good"] == "rejected"
    # A dynamic class base additionally makes class-construction hooks unproven;
    # in that variant the later marker identity may conservatively be unavailable.
    assert statuses["ops.caller"] in {"not-candidate", "rejected", "shim"}


def test_future_annotations_do_not_execute_mutator_annotation(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "from __future__ import annotations\nimport rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def mutate():\n    globals()['good'] = lambda x: x + 200\n\n"
                "def trigger(value: mutate()):\n    pass\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "native"
    assert statuses["ops.caller"] == "native"


def test_uncalled_mutator_body_and_later_exact_definition_remain_positive(tmp_path: Path) -> None:
    uncalled = _statuses(
        tmp_path / "uncalled",
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def mutate():\n    globals()['good'] = lambda x: x + 200\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert uncalled["ops.good"] == "native"
    assert uncalled["ops.caller"] == "native"

    restored = _statuses(
        tmp_path / "restored",
        {
            "ops.py": (
                "import rextio\n\n"
                "def mutate():\n    globals()['good'] = lambda x: x + 200\n\n"
                "_result = mutate()\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert restored["ops.good"] == "native"
    assert restored["ops.caller"] == "native"


_HELPER = "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"


@pytest.mark.parametrize(
    "mutation",
    [
        "class Trigger:\n    h.good = lambda x: x + 200",
        "a = h\na.good = lambda x: x + 200",
        "h.good = lambda x: x + 200\nh = None\nimport pkg.helper as h2",
        "match 1:\n    case 1:\n        h.good = lambda x: x + 200",
        "def trigger(_=setattr(h, 'good', lambda x: x + 200)):\n    pass",
        "h.good: object = lambda x: x + 200",
        "del h.good",
        "setattr(h, 'good', lambda x: x + 200)",
        "delattr(h, 'good')",
        "name = 'good'\nsetattr(h, name, lambda x: x + 200)",
        "vars(h)['good'] = lambda x: x + 200",
        "h.__dict__['good'] = lambda x: x + 200",
    ],
)
def test_source_order_alias_and_executed_scope_mutations_are_project_wide(
    tmp_path: Path, mutation: str
) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HELPER,
            "pkg/mutator.py": f"import pkg.helper as h\n\n{mutation}\n",
            "pkg/consumer.py": (
                "import rextio\nimport pkg.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_instance_attribute_write_is_not_a_project_module_mutation(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HELPER,
            "pkg/mutator.py": (
                "class Box:\n    pass\n\nbox = Box()\nbox.good = lambda x: x + 200\n"
            ),
            "pkg/consumer.py": (
                "import rextio\nimport pkg.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert statuses["pkg.helper.good"] == "native"
    assert statuses["pkg.consumer.caller"] == "native"


def test_parent_prefix_mutation_invalidates_compiled_descendants(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "from pkg import helper\n",
            "pkg/helper.py": _HELPER,
            "pkg/mutator.py": (
                "import pkg\n\n"
                "class Fake:\n"
                "    good = staticmethod(lambda x: x + 200)\n\n"
                "pkg.helper = Fake\n"
            ),
            "pkg/consumer.py": (
                "import rextio\nimport pkg.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_qualified_mutation_uses_segment_prefixes_not_substrings(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HELPER,
            "pkg/help.py": "value = 1\n",
            "pkg/mutator.py": "import pkg.help as short\nshort.value = 2\n",
            "pkg/consumer.py": (
                "import rextio\nimport pkg.helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert statuses["pkg.helper.good"] == "native"
    assert statuses["pkg.consumer.caller"] == "native"


@pytest.mark.parametrize(
    "tail",
    [
        "A.m = lambda self, x: x + 200",
        "del A.m",
        "setattr(A, 'm', lambda self, x: x + 200)",
        "delattr(A, 'm')",
    ],
)
def test_post_class_member_mutation_rejects_native_method(tmp_path: Path, tail: str) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 100\n\n"
                f"{tail}\n"
            )
        },
    )
    assert statuses["ops.A.m"] == "rejected"


@pytest.mark.parametrize(
    "prefix",
    [
        ("def replace(cls):\n    class B:\n        pass\n    return B\n\n@replace\n"),
        ("class Base:\n    def __init_subclass__(cls):\n        del cls.m\n\nclass A(Base):\n"),
        (
            "class Meta(type):\n"
            "    def __new__(meta, name, bases, namespace):\n"
            "        namespace.pop('m', None)\n"
            "        return super().__new__(meta, name, bases, namespace)\n\n"
            "import rextio\n\n"
            "class A(metaclass=Meta):\n"
        ),
    ],
)
def test_unproven_class_construction_rejects_native_method(tmp_path: Path, prefix: str) -> None:
    if prefix.endswith("@replace\n"):
        source = (
            "import rextio\n\n"
            f"{prefix}class A:\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n"
            "        return x + 100\n"
        )
    else:
        source = (
            "import rextio\n\n"
            f"{prefix}"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n"
            "        return x + 100\n"
        )
    statuses = _statuses(tmp_path, {"ops.py": source})
    assert statuses["ops.A.m"] == "rejected"


def test_simple_stable_native_method_remains_a_shim(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 100\n"
            )
        },
    )
    assert statuses["ops.A.m"] == "shim"


def test_class_body_descriptor_call_rejects_method_identity(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "def descriptor(fn):\n    return property(fn)\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 100\n"
                "    m = descriptor(m)\n"
            )
        },
    )
    assert statuses["ops.A.m"] == "rejected"


@pytest.mark.parametrize(
    "source, qualname",
    [
        (
            "def native(fn):\n    return lambda x: x + 200\n\n"
            "@native\ndef f(x: int) -> int:\n    return x + 100\n",
            "ops.f",
        ),
        (
            "import rextio\n"
            "rextio.native = lambda fn: (lambda x: x + 200)\n\n"
            "@rextio.native\ndef f(x: int) -> int:\n    return x + 100\n",
            "ops.f",
        ),
        (
            "import fake as rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 100\n",
            "ops.f",
        ),
    ],
)
def test_unproven_native_marker_spelling_never_creates_candidate(
    tmp_path: Path, source: str, qualname: str
) -> None:
    statuses = _statuses(tmp_path, {"ops.py": source})
    assert statuses[qualname] == "not-candidate"


def test_exact_rextio_marker_imports_remain_candidates(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\nimport rextio as rx\nfrom rextio import native as n\n\n"
                "@rextio.native\ndef a(x: int) -> int:\n    return x + 1\n\n"
                "@n\ndef b(x: int) -> int:\n    return x + 2\n\n"
                "@rx.native\ndef c(x: int) -> int:\n    return x + 3\n"
            )
        },
    )
    assert statuses["ops.a"] == "native"
    assert statuses["ops.b"] == "native"
    assert statuses["ops.c"] == "native"


@pytest.mark.parametrize(
    "prefix",
    [
        "if flag:\n    import rextio\n",
        "import rextio\nfrom shadow import *\n",
        "import fake as rextio\n",
    ],
)
def test_conditional_wildcard_and_fake_marker_bindings_fail_closed(
    tmp_path: Path, prefix: str
) -> None:
    statuses = _statuses(
        tmp_path,
        {"ops.py": (f"{prefix}\n@rextio.native\ndef f(x: int) -> int:\n    return x + 1\n")},
    )
    assert statuses["ops.f"] == "not-candidate"


def test_mutated_stdlib_targets_do_not_lower_statically(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\nimport math\nimport math as m\n\n"
                "math.sin = lambda x: 201.0\n"
                "math.pi = 9.0\n\n"
                "@rextio.native\ndef f(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef p() -> float:\n    return math.pi\n\n"
                "@rextio.native\ndef g(x: float) -> float:\n    return m.sin(x)\n"
            )
        },
    )
    assert statuses["ops.f"] in {"rejected", "shim"}
    assert statuses["ops.p"] in {"rejected", "shim"}
    assert statuses["ops.g"] in {"rejected", "shim"}


def test_clean_math_import_alias_and_constant_remain_native(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\nimport math\nimport math as m\n\n"
                "@rextio.native\ndef f(x: float) -> float:\n    return math.sin(x)\n\n"
                "@rextio.native\ndef p() -> float:\n    return math.pi\n\n"
                "@rextio.native\ndef g(x: float) -> float:\n    return m.sin(x)\n"
            )
        },
    )
    assert statuses["ops.f"] == "native"
    assert statuses["ops.p"] == "native"
    assert statuses["ops.g"] == "native"
