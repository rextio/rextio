from __future__ import annotations

from rextio.runtime.dispatcher import dispatch
from rextio.runtime.flags import native_disabled, native_mode, native_required


def test_native_mode_defaults_to_auto(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_DISABLE_NATIVE", raising=False)
    monkeypatch.delenv("REXTIO_NATIVE_MODE", raising=False)

    assert native_mode() == "auto"
    assert not native_disabled()
    assert not native_required()


def test_invalid_native_mode_falls_back_to_auto(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "invalid")

    assert native_mode() == "auto"
    assert dispatch(None, lambda value: value + 1, 1) == 2


def test_dispatch_respects_fallback_mode(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")

    assert native_disabled()
    assert dispatch(lambda value: value + 100, lambda value: value + 1, 1) == 2


def test_dispatch_native_mode_requires_native_function(monkeypatch) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")

    try:
        dispatch(None, lambda value: value + 1, 1)
    except RuntimeError as exc:
        assert "native mode requires generated native function" in str(exc)
    else:
        raise AssertionError("native mode should fail when native function is unavailable")


def test_disable_native_accepts_truthy_strings(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_NATIVE_MODE", raising=False)
    for value in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("REXTIO_DISABLE_NATIVE", value)
        assert native_disabled(), value


def test_invalid_native_mode_warns(monkeypatch) -> None:
    import warnings

    from rextio.runtime import flags

    flags._warned_modes.clear()
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "nativ")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert native_mode() == "auto"
    assert any(issubclass(w.category, RuntimeWarning) for w in caught)
