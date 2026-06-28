"""Toolchain-aware markers for the real-toolchain e2e suite.

Each e2e module that drives a real external toolchain is auto-tagged so it can be
selected/deselected with ``-m`` (e.g. ``pytest -m needs_cargo``) and is skipped
centrally when the toolchain is unavailable — instead of repeating a
``@pytest.mark.skipif`` on every test:

  * files named ``*_real_cargo*`` / ``*_real_toolchain*`` need cargo,
  * files named ``*nuitka*`` need nuitka.
"""

from __future__ import annotations

import shutil

import pytest

_NEEDS_CARGO = pytest.mark.needs_cargo
_NEEDS_NUITKA = pytest.mark.needs_nuitka


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    cargo = shutil.which("cargo")
    nuitka = shutil.which("nuitka")
    skip_cargo = pytest.mark.skip(reason="cargo is required for this real-toolchain e2e")
    skip_nuitka = pytest.mark.skip(reason="nuitka is required for this real-toolchain e2e")

    for item in items:
        name = item.fspath.basename if item.fspath else ""
        if "nuitka" in name:
            item.add_marker(_NEEDS_NUITKA)
            if nuitka is None:
                item.add_marker(skip_nuitka)
        elif "real_cargo" in name or "real_toolchain" in name:
            item.add_marker(_NEEDS_CARGO)
            if cargo is None:
                item.add_marker(skip_cargo)
