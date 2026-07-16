"""Adjacent executable-effect and qualified-mutation regressions for WP-4."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.callable_metadata import (
    FINAL_BINDING_FUNCTION,
    IndexedSymbol,
    resolve_symbol_qualname,
)
from rextio.analyzer.final_bindings import (
    BindingKind,
    ProjectBindings,
    definition_is_final,
    head_binding_blocks,
)
from rextio.analyzer.module_parser import parse_module
from rextio.analyzer.project_scanner import analyze_project


_HELPER = "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"


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


def _project_with_mutator(tmp_path: Path, mutation: str) -> dict[str, str]:
    return _statuses(
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


@pytest.mark.parametrize(
    "mutation",
    [
        ("flag = False\nif flag:\n    h = None\nelse:\n    h.good = lambda x: x + 200"),
        ("flag = True\nif flag:\n    a = h\n    a.good = lambda x: x + 200"),
        ("flag = True\nif flag:\n    a = h\nelse:\n    a = h\na.good = lambda x: x + 200"),
    ],
)
def test_branch_local_aliases_retain_path_authority(tmp_path: Path, mutation: str) -> None:
    statuses = _project_with_mutator(tmp_path, mutation)
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


@pytest.mark.parametrize(
    "mutation",
    [
        ("def mutate():\n    h.good = lambda x: x + 200\n\nmutate()"),
        ("def mutate(module):\n    setattr(module, 'good', lambda x: x + 200)\n\nmutate(h)"),
        ("def mutate(h):\n    setattr(h, 'good', lambda x: x + 200)\n\nmutate(h)"),
        "(lambda module: setattr(module, 'good', lambda x: x + 200))(h)",
    ],
)
def test_executed_local_callable_tracks_qualified_mutations_and_arguments(
    tmp_path: Path, mutation: str
) -> None:
    statuses = _project_with_mutator(tmp_path, mutation)
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_relative_import_alias_mutation_is_project_wide(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HELPER,
            "pkg/mutator.py": ("from . import helper as h\nh.good = lambda x: x + 200\n"),
            "pkg/consumer.py": (
                "import rextio\nfrom . import helper as h\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return h.good(x)\n"
            ),
        },
    )
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_chained_alias_assignment_preserves_module_root(tmp_path: Path) -> None:
    statuses = _project_with_mutator(
        tmp_path,
        "a = b = h\na.good = lambda x: x + 200",
    )
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_class_body_global_assignment_invalidates_module_binding(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "class Trigger:\n"
                "    global good\n"
                "    good = lambda x: x + 200\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "rejected"
    assert statuses["ops.caller"] in {"rejected", "shim"}


def test_all_effects_in_one_expression_are_scanned(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "class Fake:\n"
                "    native = staticmethod(lambda fn: (lambda x: x + 200))\n\n"
                "_result = (\n"
                "    globals().__setitem__('unrelated', 1),\n"
                "    globals().__setitem__('rextio', Fake),\n"
                ")\n\n"
                "@rextio.native\ndef f(x: int) -> int:\n    return x + 100\n"
            )
        },
    )
    assert statuses["ops.f"] == "not-candidate"


def test_mutated_logging_get_logger_is_not_a_purity_exemption(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\nimport logging\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "logging.getLogger = lambda: globals().__setitem__(\n"
                "    'good', lambda x: x + 200\n"
                ")\n"
                "logger = logging.getLogger()\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "rejected"
    assert statuses["ops.caller"] in {"not-candidate", "rejected", "shim"}


@pytest.mark.parametrize(
    "body",
    [
        ("class Box:\n    pass\nfor h in [Box()]:\n    h.good = lambda x: x + 200"),
        (
            "class Ctx:\n"
            "    def __enter__(self):\n        return self\n"
            "    def __exit__(self, *args):\n        return False\n"
            "with Ctx() as h:\n"
            "    h.good = lambda x: x + 200"
        ),
        ("try:\n    raise ValueError()\nexcept ValueError as h:\n    h.good = lambda x: x + 200"),
        ("class Box:\n    pass\nmatch Box():\n    case h:\n        h.good = lambda x: x + 200"),
    ],
)
def test_control_flow_targets_shadow_module_alias_before_body(tmp_path: Path, body: str) -> None:
    statuses = _project_with_mutator(tmp_path, body)
    assert statuses["pkg.helper.good"] == "native"
    assert statuses["pkg.consumer.caller"] == "native"


@pytest.mark.parametrize(
    "body",
    [
        "g = (setattr(h, 'good', lambda x: x + 200) for _ in ())",
        "h.good: object",
    ],
)
def test_deferred_generator_and_annotation_only_target_do_not_mutate(
    tmp_path: Path, body: str
) -> None:
    statuses = _project_with_mutator(tmp_path, body)
    assert statuses["pkg.helper.good"] == "native"
    assert statuses["pkg.consumer.caller"] == "native"


def test_called_function_returning_uniterated_generator_has_no_effect(
    tmp_path: Path,
) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def make_generator():\n"
                "    return (\n"
                "        globals().__setitem__('good', lambda x: x + 200)\n"
                "        for _ in ()\n"
                "    )\n\n"
                "unused = make_generator()\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "native"
    assert statuses["ops.caller"] == "native"


def test_generator_consumed_at_module_load_tracks_qualified_mutation(
    tmp_path: Path,
) -> None:
    statuses = _project_with_mutator(
        tmp_path,
        "list(setattr(h, 'good', lambda x: x + 200) for _ in [0])",
    )
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


@pytest.mark.parametrize(
    "mutation",
    [
        (
            "def make():\n"
            "    return (setattr(h, 'good', lambda x: x + 200) for _ in [0])\n\n"
            "g = make()\n"
            "list(g)"
        ),
        "list(setattr(a, 'good', lambda x: x + 200) for a in [h])",
        "for a in [h]:\n    a.good = lambda x: x + 200",
        "match h:\n    case a:\n        a.good = lambda x: x + 200",
        ("[(a := h, setattr(a, 'good', lambda x: x + 200)) for _ in [0]]"),
    ],
)
def test_consumed_iterables_preserve_project_aliases(
    tmp_path: Path,
    mutation: str,
) -> None:
    statuses = _project_with_mutator(tmp_path, mutation)
    assert statuses["pkg.helper.good"] == "rejected"
    assert statuses["pkg.consumer.caller"] in {"rejected", "shim"}


def test_calling_decorator_replaced_local_callable_is_an_unknown_effect(
    tmp_path: Path,
) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "def replace(fn):\n"
                "    return lambda: globals().__setitem__(\n"
                "        'good', lambda x: x + 200\n"
                "    )\n\n"
                "@replace\n"
                "def mutate():\n"
                "    pass\n\n"
                "mutate()\n"
                "import rextio\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "rejected"
    assert statuses["ops.caller"] in {"not-candidate", "rejected", "shim"}


def test_module_iteration_protocol_hook_is_an_unknown_effect(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "class Items:\n"
                "    def __iter__(self):\n"
                "        globals()['good'] = lambda x: x + 200\n"
                "        return iter(())\n\n"
                "items = Items()\n"
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                "for _ in items:\n"
                "    pass\n"
                "import rextio\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "rejected"
    assert statuses["ops.caller"] in {"not-candidate", "rejected", "shim"}


@pytest.mark.parametrize(
    "setup,trigger",
    [
        (
            "class Trigger:\n"
            "    def __bool__(self):\n"
            "        globals()['good'] = lambda x: x + 200\n"
            "        return False\n\n"
            "trigger = Trigger()\n",
            "if trigger:\n    pass",
        ),
        (
            "class Trigger:\n"
            "    def __enter__(self):\n"
            "        globals()['good'] = lambda x: x + 200\n"
            "        return self\n"
            "    def __exit__(self, *args):\n"
            "        return False\n\n"
            "trigger = Trigger()\n",
            "with trigger:\n    pass",
        ),
        (
            "class Trigger:\n"
            "    @property\n"
            "    def value(self):\n"
            "        globals()['good'] = lambda x: x + 200\n"
            "        return 1\n\n"
            "trigger = Trigger()\n",
            "_value = trigger.value",
        ),
    ],
)
def test_implicit_module_protocol_hooks_are_unknown_effects(
    tmp_path: Path,
    setup: str,
    trigger: str,
) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                f"{setup}"
                "import rextio\n\n"
                "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                f"{trigger}\n"
                "import rextio\n\n"
                "@rextio.native\ndef caller(x: int) -> int:\n    return good(x)\n"
            )
        },
    )
    assert statuses["ops.good"] == "rejected"
    assert statuses["ops.caller"] in {"not-candidate", "rejected", "shim"}


def test_imported_builtins_mutation_blocks_bare_builtin_lowering(tmp_path: Path) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import builtins\n"
                "builtins.len = lambda value: 201\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def f(values: list[int]) -> int:\n"
                "    return len(values)\n"
            )
        },
    )
    assert statuses["ops.f"] != "native"


def test_descendant_marker_state_mutation_invalidates_marker_identity(
    tmp_path: Path,
) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "def fake(fn):\n"
                "    return lambda x: x + 200\n\n"
                "rextio.native.__code__ = fake.__code__\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    return x + 100\n"
            )
        },
    )
    assert statuses["ops.f"] == "not-candidate"


def test_standalone_parse_module_builds_local_mutation_authority(tmp_path: Path) -> None:
    path = tmp_path / "ops.py"
    path.write_text(
        "import rextio\n"
        "rextio.native = lambda fn: (lambda x: x + 200)\n\n"
        "@rextio.native\n"
        "def f(x: int) -> int:\n"
        "    return x + 100\n",
        encoding="utf-8",
    )

    module = parse_module(path, tmp_path, native_marker="decorator")
    function = next(function for function in module.functions if function.qualname == "ops.f")

    assert function.is_native_candidate is False
    assert module.project_mutations.target_is_mutated("rextio.native")


@pytest.mark.parametrize(
    "mutation",
    [
        "A.m = lambda self, x: x + 200",
        "name = 'm'\nsetattr(A, name, lambda self, x: x + 200)",
    ],
)
def test_later_exact_class_restores_member_identity(tmp_path: Path, mutation: str) -> None:
    statuses = _statuses(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 100\n\n"
                f"{mutation}\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 300\n"
            )
        },
    )
    assert statuses["ops.A.m"] == "shim"


def test_missing_binding_authority_fails_closed() -> None:
    assert not definition_is_final(None, "f", BindingKind.FUNCTION, 1, 0)
    assert head_binding_blocks(None, "f")
    missing = ProjectBindings({}).for_module("missing")
    assert missing.lookup("f").kind is BindingKind.UNKNOWN_STAR

    function = ast.parse("def f():\n    pass\n").body[0]
    known = {
        "m.f": IndexedSymbol(
            qualname="m.f",
            name="f",
            node=function,
            module_name="m",
            imports={},
        )
    }
    assert (
        resolve_symbol_qualname(
            "f",
            {},
            "m",
            known,
            kind=FINAL_BINDING_FUNCTION,
            final_bindings={"m": {"f": FINAL_BINDING_FUNCTION}},
            project_mutations=None,
        )
        is None
    )
