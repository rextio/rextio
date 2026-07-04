from __future__ import annotations

import pytest

from rextio.runtime.flags import native_disabled, native_mode, native_required


def test_native_mode_defaults_to_auto(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_NATIVE_MODE", raising=False)

    assert native_mode() == "auto"
    assert not native_disabled()
    assert not native_required()


def test_invalid_native_mode_falls_back_to_auto(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "invalid")

    with pytest.warns(RuntimeWarning, match="not one of auto/native/fallback"):
        assert native_mode() == "auto"


def test_fallback_mode_disables_native(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")

    assert native_disabled()
    assert not native_required()


def test_native_mode_requires_native(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")

    assert native_required()


def test_native_mode_values_are_case_insensitive(monkeypatch) -> None:
    for value in ("fallback", "FALLBACK", " Fallback "):
        monkeypatch.setenv("REXTIO_NATIVE_MODE", value)
        assert native_disabled(), value
    for value in ("native", "NATIVE"):
        monkeypatch.setenv("REXTIO_NATIVE_MODE", value)
        assert native_required(), value


def test_invalid_native_mode_warns(monkeypatch) -> None:
    import warnings

    from rextio.runtime import flags

    flags._warned_modes.clear()
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "nativ")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert native_mode() == "auto"
    assert any(issubclass(w.category, RuntimeWarning) for w in caught)


def test_boundary_disable_accepts_truthy_strings(monkeypatch) -> None:
    from rextio.runtime.boundary_fallback import boundary_fallback_disabled

    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "1000")
    for value in ("1", "true", "YES", "on"):
        monkeypatch.setenv("REXTIO_DISABLE_BOUNDARY_FALLBACK", value)
        assert boundary_fallback_disabled(), value
