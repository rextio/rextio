from __future__ import annotations

import importlib.machinery
import warnings

import pytest

import rextio.runtime.native_loader as native_loader


def _spec() -> importlib.machinery.ModuleSpec:
    return importlib.machinery.ModuleSpec("_rextio_native", loader=None)


def test_absent_native_module_returns_none_silently(monkeypatch: pytest.MonkeyPatch) -> None:
    # find_spec returns None -> the module was never built -> silent fallback.
    monkeypatch.setattr(native_loader.importlib.util, "find_spec", lambda name: None)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert native_loader.load_native_module("_rextio_native") is None
    assert caught == []


def test_broken_native_module_warns_instead_of_silently_swallowing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_loader.importlib.util, "find_spec", lambda name: _spec())
    monkeypatch.setattr(
        native_loader, "import_module", lambda name: (_ for _ in ()).throw(ImportError("bad abi"))
    )
    monkeypatch.delenv("REXTIO_DEBUG_NATIVE", raising=False)
    with pytest.warns(RuntimeWarning, match="failed to load"):
        assert native_loader.load_native_module("_rextio_native") is None


def test_missing_native_dependency_is_not_mistaken_for_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The native module exists (spec found) but one of ITS imports is missing:
    # broken, not absent, so it must warn rather than fall back silently.
    monkeypatch.setattr(native_loader.importlib.util, "find_spec", lambda name: _spec())

    def _missing_dependency(name: str) -> object:
        raise ModuleNotFoundError("No module named 'some_dep'", name="some_dep")

    monkeypatch.setattr(native_loader, "import_module", _missing_dependency)
    monkeypatch.delenv("REXTIO_DEBUG_NATIVE", raising=False)
    with pytest.warns(RuntimeWarning, match="failed to load"):
        assert native_loader.load_native_module("_rextio_native") is None


def test_debug_native_re_raises_the_underlying_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_loader.importlib.util, "find_spec", lambda name: _spec())
    monkeypatch.setattr(
        native_loader,
        "import_module",
        lambda name: (_ for _ in ()).throw(ImportError("ABI mismatch")),
    )
    monkeypatch.setenv("REXTIO_DEBUG_NATIVE", "1")
    with pytest.raises(ImportError, match="ABI mismatch"):
        native_loader.load_native_module("_rextio_native")
