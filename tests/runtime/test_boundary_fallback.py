from __future__ import annotations

from rextio.runtime.boundary_fallback import (
    DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    boundary_fallback_count,
    boundary_fallback_disabled,
    boundary_fallback_required,
    boundary_fallback_threshold,
    reset_boundary_fallback_state,
)


def test_boundary_fallback_threshold_defaults_for_missing_or_invalid_values(monkeypatch) -> None:
    monkeypatch.delenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", raising=False)
    assert boundary_fallback_threshold() == DEFAULT_BOUNDARY_FALLBACK_THRESHOLD

    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "not-an-int")
    assert boundary_fallback_threshold() == DEFAULT_BOUNDARY_FALLBACK_THRESHOLD

    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "-1")
    assert boundary_fallback_threshold() == DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


def test_boundary_fallback_required_after_threshold(monkeypatch) -> None:
    reset_boundary_fallback_state()
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "2")

    assert not boundary_fallback_required("demo.score_one")
    assert not boundary_fallback_required("demo.score_one")
    assert boundary_fallback_required("demo.score_one")
    assert boundary_fallback_required("demo.score_one")
    assert boundary_fallback_count("demo.score_one") == 3


def test_boundary_fallback_uses_provided_default_threshold(monkeypatch) -> None:
    reset_boundary_fallback_state()
    monkeypatch.delenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", raising=False)

    assert not boundary_fallback_required("demo.score_one", 2)
    assert not boundary_fallback_required("demo.score_one", 2)
    assert boundary_fallback_required("demo.score_one", 2)


def test_boundary_fallback_env_overrides_provided_default_threshold(monkeypatch) -> None:
    reset_boundary_fallback_state()
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "3")

    assert not boundary_fallback_required("demo.score_one", 1)
    assert not boundary_fallback_required("demo.score_one", 1)
    assert not boundary_fallback_required("demo.score_one", 1)
    assert boundary_fallback_required("demo.score_one", 1)


def test_boundary_fallback_tracks_functions_independently(monkeypatch) -> None:
    reset_boundary_fallback_state()
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "2")

    assert not boundary_fallback_required("demo.first")
    assert not boundary_fallback_required("demo.second")
    assert not boundary_fallback_required("demo.second")
    assert not boundary_fallback_required("demo.first")
    assert boundary_fallback_required("demo.first")
    assert boundary_fallback_required("demo.second")


def test_boundary_fallback_can_be_disabled(monkeypatch) -> None:
    reset_boundary_fallback_state()
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "1")
    monkeypatch.setenv("REXTIO_DISABLE_BOUNDARY_FALLBACK", "1")

    assert boundary_fallback_disabled()
    assert not boundary_fallback_required("demo.score_one")
    assert not boundary_fallback_required("demo.score_one")
    assert boundary_fallback_count("demo.score_one") == 0

    monkeypatch.delenv("REXTIO_DISABLE_BOUNDARY_FALLBACK")
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "0")

    assert boundary_fallback_disabled()
    assert not boundary_fallback_required("demo.score_one")
    assert boundary_fallback_count("demo.score_one") == 0
