from __future__ import annotations

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


def test_fallback_mode_disables_native(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_DISABLE_NATIVE", raising=False)
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")

    assert native_disabled()
    assert not native_required()


def test_native_mode_requires_native(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_DISABLE_NATIVE", raising=False)
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")

    assert native_required()


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


def test_boundary_disable_accepts_truthy_strings(monkeypatch) -> None:
    from rextio.runtime.boundary_fallback import boundary_fallback_disabled

    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "1000")
    for value in ("1", "true", "YES", "on"):
        monkeypatch.setenv("REXTIO_DISABLE_BOUNDARY_FALLBACK", value)
        assert boundary_fallback_disabled(), value
