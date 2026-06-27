from __future__ import annotations

import warnings

import pytest

import rextio.runtime.native_loader as native_loader


def test_missing_native_module_returns_none_silently(monkeypatch: pytest.MonkeyPatch) -> None:
    def _missing(name: str) -> object:
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(native_loader, "import_module", _missing)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert native_loader.load_native_module("_rextio_native") is None
    assert caught == []


def test_broken_native_module_warns_instead_of_silently_swallowing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken(name: str) -> object:
        raise ImportError("invalid mach-o / ABI mismatch")

    monkeypatch.setattr(native_loader, "import_module", _broken)
    monkeypatch.delenv("REXTIO_DEBUG_NATIVE", raising=False)
    with pytest.warns(RuntimeWarning, match="failed to load"):
        assert native_loader.load_native_module("_rextio_native") is None


def test_debug_native_re_raises_the_underlying_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _broken(name: str) -> object:
        raise ImportError("invalid mach-o / ABI mismatch")

    monkeypatch.setattr(native_loader, "import_module", _broken)
    monkeypatch.setenv("REXTIO_DEBUG_NATIVE", "1")
    with pytest.raises(ImportError, match="ABI mismatch"):
        native_loader.load_native_module("_rextio_native")
