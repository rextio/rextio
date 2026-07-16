"""Soundness regressions for WP-4 follow-up 13."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _analyze(root: Path, files: dict[str, str]):
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return analyze_project(root, native_marker="decorator")


def _helper_project() -> dict[str, str]:
    return {
        "pkg/__init__.py": "",
        "pkg/helper.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
        ),
    }


def _helper_is_direct(analysis) -> bool:
    return (
        next(
            function.route
            for module in analysis.modules
            for function in module.functions
            if function.qualname == "pkg.helper.good"
        )
        == "native-direct"
    )


@pytest.mark.parametrize("builtin", ["id", "len", "range"])
def test_project_wide_builtin_mutation_revokes_purity(tmp_path: Path, builtin: str) -> None:
    files = _helper_project()
    argument = {"id": "helper", "len": "(1, 2)", "range": "3"}[builtin]
    files["pkg/a_call.py"] = (
        f"from . import helper\ndef run():\n    return {builtin}({argument})\nrun()\n"
    )
    # Lexically later on purpose: the mutation authority must converge across
    # modules rather than depend on filesystem scan order.
    files["pkg/z_mutate.py"] = f"__builtins__[{builtin!r}] = lambda *args: 0\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated(f"builtins.{builtin}")
    assert not _helper_is_direct(analysis)


@pytest.mark.parametrize(
    "call",
    ["id(helper)", "len((1, 2))", "tuple(range(3))"],
)
def test_untouched_builtin_controls_remain_clean(tmp_path: Path, call: str) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = f"from . import helper\ndef run():\n    return {call}\nrun()\n"
    assert _helper_is_direct(_analyze(tmp_path, files))


@pytest.mark.parametrize("hook", ["__new__", "__init__"])
def test_post_definition_constructor_hook_mutation_fails_closed(tmp_path: Path, hook: str) -> None:
    files = _helper_project()
    replacement = (
        "staticmethod(lambda cls: object.__new__(cls))"
        if hook == "__new__"
        else "lambda self: None"
    )
    files["pkg/boot.py"] = (
        "class Clean:\n    pass\n"
        "def build():\n    return Clean()\n"
        f"Clean.{hook} = {replacement}\n"
        "build()\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_source_class_protocol_hook_use_fails_closed(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "class Hooked:\n"
        "    def __setattr__(self, name, value):\n"
        "        helper.good = lambda x: x + 10\n"
        "def run():\n"
        "    value = Hooked()\n"
        "    value.item = 1\n"
        "run()\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_source_class_method_call_is_not_assumed_pure(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "class Worker:\n"
        "    def touch(self):\n"
        "        helper.good = lambda x: x + 10\n"
        "def run():\n"
        "    worker = Worker()\n"
        "    worker.touch()\n"
        "run()\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_clean_plain_source_class_construction_remains_clean(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = "class Plain:\n    pass\ndef run():\n    return Plain()\nrun()\n"
    assert _helper_is_direct(_analyze(tmp_path, files))


@pytest.mark.parametrize(
    "mutation",
    [
        "choose()['slot'].good = lambda x: x + 10",
        "selected = choose()\nselected['slot'].good = lambda x: x + 10",
    ],
)
def test_container_return_shape_never_manufactures_subscript_path(
    tmp_path: Path, mutation: str
) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def choose():\n"
        "    return {'slot': {'nested': helper}} if FLAG else {'slot': helper}\n"
        f"{mutation}\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper")
    assert not _helper_is_direct(analysis)


def test_mutated_logging_factory_is_not_proven(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/a_consumer.py"] = "import logging\nlogger = logging.getLogger('clean')\n"
    files["pkg/z_mutate.py"] = "import logging\nlogging.getLogger = lambda name: object()\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("logging.getLogger")
    assert not _helper_is_direct(analysis)


def test_untouched_logging_factory_control_remains_clean(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = "import logging\nlogger = logging.getLogger('clean')\n"
    assert _helper_is_direct(_analyze(tmp_path, files))


@pytest.mark.parametrize(
    "argument",
    [
        "helper",
        "{'value': [helper]}",
        "{'value': [(helper for _ in (0,))]}",
        "deferred",
    ],
)
def test_module_scope_opaque_exposure_recurses_into_containers_and_generators(
    tmp_path: Path, argument: str
) -> None:
    files = _helper_project()
    deferred = "deferred = (helper for _ in (0,))\n" if argument == "deferred" else ""
    files["pkg/boot.py"] = (
        f"from . import helper\nfrom external_package import touch\n{deferred}touch({argument})\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_unknown_alias_exposure_fails_closed(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from external_package import make, touch\nvalue = make()\ntouch(value)\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_nested_deferred_generator_effect_is_replayed_on_opaque_exposure(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\nfrom external_package import touch\n"
        "def mutate(value):\n"
        "    value.good = lambda x: x + 10\n"
        "deferred = (0 for _ in (0,) if mutate(helper))\n"
        "touch({'nested': [deferred]})\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_executed_nonlocal_callable_fails_closed(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def outer():\n"
        "    target = helper\n"
        "    def mutate():\n"
        "        nonlocal target\n"
        "        target.good = lambda x: x + 10\n"
        "    mutate()\n"
        "outer()\n"
    )
    assert not _helper_is_direct(_analyze(tmp_path, files))


def test_unexecuted_nonlocal_closure_control_remains_clean(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def outer():\n"
        "    target = helper\n"
        "    def mutate():\n"
        "        nonlocal target\n"
        "        target = helper\n"
        "    return 1\n"
        "outer()\n"
    )
    assert _helper_is_direct(_analyze(tmp_path, files))
