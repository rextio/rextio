"""Runtime wrapper collision regressions for WP-4 follow-up 12."""

from __future__ import annotations

import importlib
import inspect
import sys
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.module_copy import render_native_top_level_fallback_module
from rextio.runtime.original_registry import resolve_runtime_original


def _import_rendered_wrapper(
    tmp_path: Path,
    source_text: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    native_top_level: bool = False,
    native_loader=None,
):
    source = tmp_path / "source" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(source_text, encoding="utf-8")
    analysis = analyze_project(source.parent, native_top_level=native_top_level)
    wrapper = render_wrapper_module(analysis.modules[0])
    build = tmp_path / "build"
    build.mkdir()
    (build / "app.py").write_text(wrapper, encoding="utf-8")
    (build / "_fallback_app.py").write_text(source_text, encoding="utf-8")
    native_fallback = (
        render_native_top_level_fallback_module(analysis.modules[0])
        if native_top_level
        else source_text
    )
    (build / "_native_top_level_fallback_app.py").write_text(native_fallback, encoding="utf-8")
    if native_loader is not None:
        monkeypatch.setattr("rextio.runtime.native_loader.load_native_function", native_loader)
    monkeypatch.syspath_prepend(str(build))
    for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
        sys.modules.pop(name, None)
    module = importlib.import_module("app")
    return module, wrapper


def test_user_native_names_cannot_collide_with_internal_wrapper_factories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = """
import rextio

__all__ = [
    "foo", "_rextio_make_foo", "_rextio_wrapper_C_m",
    "_rextio_initialize_dispatch", "C",
]

@rextio.native
def foo(_rextio_dispatch_capture_0: int) -> int:
    return _rextio_dispatch_capture_0 + 1

@rextio.native
def _rextio_make_foo(value: int) -> int:
    return value + 2

@rextio.native
def _rextio_wrapper_C_m(value: int) -> int:
    return value + 3

@rextio.native
def _rextio_initialize_dispatch(value: int) -> int:
    return value + 5

class C:
    @rextio.native
    def m(self, value: int) -> int:
        return value + 4
"""
    module, wrapper = _import_rendered_wrapper(tmp_path, source, monkeypatch)
    try:
        assert module.foo(10) == 11
        assert module._rextio_make_foo(10) == 12
        assert module._rextio_wrapper_C_m(10) == 13
        assert module._rextio_initialize_dispatch(10) == 15
        assert module.C().m(10) == 14
        assert callable(module._rextio_make_foo)
        assert callable(module._rextio_wrapper_C_m)
        assert callable(module._rextio_initialize_dispatch)
        assert "_rextio_make__rextio_make_foo" not in module.__dict__
        assert "def _rextio_initialize_dispatch(" in wrapper
    finally:
        for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
            sys.modules.pop(name, None)


def test_native_top_level_updates_publish_after_internal_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = """
import rextio

__all__ = ["value", "_rextio_builtin_hasattr", "add"]
value: list[str] = ["fallback"]
_rextio_builtin_hasattr: list[str] = ["helper"]

@rextio.native
def add(value: int) -> int:
    return value + 1
"""

    def native_loader(*, module_name: str, function_name: str):
        del module_name
        if function_name == "app____rextio_top_level":
            return lambda: {
                "value": ["native"],
                "_rextio_builtin_hasattr": ["native-helper"],
                "__all__": ["value", "_rextio_builtin_hasattr", "add"],
            }
        return None

    module, wrapper = _import_rendered_wrapper(
        tmp_path,
        source,
        monkeypatch,
        native_top_level=True,
        native_loader=native_loader,
    )
    try:
        assert module.value == ["native"]
        assert module._rextio_builtin_hasattr == ["native-helper"]
        assert module.add(4) == 5
        assert "_rextio_builtin_globals().update(updates)" not in wrapper
    finally:
        for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
            sys.modules.pop(name, None)


def test_runtime_originals_use_isolated_ordinal_registry_not_fallback_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = """
import rextio

__all__ = ["C", "_rextio_original_app__C__m"]
_rextio_original_app__C__m = "user-value"

class C:
    @rextio.native
    def m(self, value: int) -> int:
        return self.offset + value
"""
    module, wrapper = _import_rendered_wrapper(tmp_path, source, monkeypatch)
    try:
        instance = module.C()
        instance.offset = 4
        assert instance.m(3) == 7
        assert module._rextio_original_app__C__m == "user-value"
        fallback = sys.modules["_fallback_app"]
        assert fallback._rextio_original_app__C__m == "user-value"
        original = resolve_runtime_original("app", 0)
        fallback_instance = fallback.C()
        fallback_instance.offset = 5
        assert original(fallback_instance, 2) == 7
        assert "_rextio_builtin_setattr(_rextio_fallback_module" not in wrapper
        assert "_rextio_register_runtime_originals" in wrapper
    finally:
        for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
            sys.modules.pop(name, None)


@pytest.mark.parametrize("kind", ["class", "function"])
@pytest.mark.parametrize("assignment_first", [True, False])
@pytest.mark.parametrize("native_enabled", [True, False])
def test_native_top_level_name_collisions_follow_exact_final_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    assignment_first: bool,
    native_enabled: bool,
) -> None:
    assignment = "C: int = 7" if kind == "class" else "foo: int = 7"
    definition = (
        "class C:\n"
        "    @rextio.native\n"
        "    def m(self, value: int) -> int:\n"
        "        return value + 1"
        if kind == "class"
        else "@rextio.native\ndef foo(value: int) -> int:\n    return value + 1"
    )
    body = f"{assignment}\n\n{definition}" if assignment_first else f"{definition}\n\n{assignment}"
    source = f"import rextio\n\n{body}\n"

    def native_loader(*, module_name: str, function_name: str):
        del module_name
        if function_name == "app____rextio_top_level":
            return lambda: {"C" if kind == "class" else "foo": 7}
        return None

    if not native_enabled:
        monkeypatch.setenv("REXTIO_DISABLE_NATIVE", "1")
    module, wrapper = _import_rendered_wrapper(
        tmp_path,
        source,
        monkeypatch,
        native_top_level=True,
        native_loader=native_loader,
    )
    try:
        name = "C" if kind == "class" else "foo"
        value = getattr(module, name)
        if assignment_first:
            assert callable(value) if kind == "function" else isinstance(value, type)
            assert value(3) == 4 if kind == "function" else value().m(3) == 4
        else:
            assert value == 7
        assert "module.__dict__.update(updates)" not in wrapper
    finally:
        for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
            sys.modules.pop(name, None)


@pytest.mark.parametrize(
    "function_name, parameter_name",
    [
        ("foo", "_rextio_native_slot_0"),
        ("_rextio_native_disabled", "value"),
        ("_rextio_dispatch_capture_0", "value"),
    ],
)
def test_internal_capture_spellings_preserve_user_names_and_signatures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
    parameter_name: str,
) -> None:
    source = (
        "import rextio\n\n"
        "@rextio.native\n"
        f"def {function_name}({parameter_name}: int) -> int:\n"
        f"    return {parameter_name} + 1\n"
    )
    module, _wrapper = _import_rendered_wrapper(tmp_path, source, monkeypatch)
    try:
        function = getattr(module, function_name)
        assert function(**{parameter_name: 2}) == 3
        assert list(inspect.signature(function).parameters) == [parameter_name]
        assert function.__name__ == function_name
    finally:
        for name in ("app", "_fallback_app", "_native_top_level_fallback_app"):
            sys.modules.pop(name, None)
