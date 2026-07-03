"""Tests for the native scalar boundary-call runtime hook."""

from __future__ import annotations

import sys
import types

from rextio.runtime.boundary_call import boundary_call
from rextio.runtime.boundary_fallback import (
    boundary_fallback_count,
    reset_boundary_fallback_state,
)


def _install_module(monkeypatch, name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def test_boundary_call_dispatches_and_counts(monkeypatch):
    reset_boundary_fallback_state()
    _install_module(monkeypatch, "bc_demo", bump=lambda x: x + 1)

    assert boundary_call("app.compute", "bc_demo.bump", (41,)) == 42
    assert boundary_fallback_count("app.compute") == 1
    boundary_call("app.compute", "bc_demo.bump", (1,))
    assert boundary_fallback_count("app.compute") == 2
    reset_boundary_fallback_state()


def test_boundary_call_resolves_the_target_at_call_time(monkeypatch):
    # Monkeypatching the fallback module attribute is honored by the native
    # path exactly like a Python caller: resolution happens per call.
    reset_boundary_fallback_state()
    module = _install_module(monkeypatch, "bc_patch", bump=lambda x: x + 1)

    assert boundary_call("app.compute", "bc_patch.bump", (1,)) == 2
    module.bump = lambda x: x + 100
    assert boundary_call("app.compute", "bc_patch.bump", (1,)) == 101
    reset_boundary_fallback_state()


def test_boundary_call_propagates_exceptions(monkeypatch):
    reset_boundary_fallback_state()

    def boom(x):
        raise ValueError(f"bad value: {x}")

    _install_module(monkeypatch, "bc_err", boom=boom)

    import pytest

    with pytest.raises(ValueError, match="bad value: 7"):
        boundary_call("app.compute", "bc_err.boom", (7,))
    reset_boundary_fallback_state()
