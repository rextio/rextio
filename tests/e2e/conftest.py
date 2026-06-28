"""Toolchain-aware markers for the real-toolchain e2e suite.

Each e2e module that drives a real external toolchain is auto-tagged so it can be
selected/deselected with ``-m`` (e.g. ``pytest -m needs_cargo``) and is skipped
centrally when the toolchain is unavailable — instead of repeating a
``@pytest.mark.skipif`` on every test:

  * files whose stem ends with ``_real_cargo`` / ``_real_toolchain`` need cargo,
  * files with a ``nuitka`` name segment need nuitka.

The CI ``e2e`` job runs the whole directory (``pytest tests/e2e``) rather than
``-m needs_cargo`` so that toolchain-free e2e tests (e.g. the CLI smoke and zipapp
tests, which use the ``fake_cargo`` shim) are not silently deselected and run
*nowhere*. To keep that guarantee, collection fails if a ``tests/e2e`` test is
neither toolchain-tagged nor toolchain-free: such a test would otherwise drop out
of every CI lane the moment it is misnamed (mod-proposal P1-10 / council B2).
"""

from __future__ import annotations

import shutil

import pytest

_NEEDS_CARGO = pytest.mark.needs_cargo
_NEEDS_NUITKA = pytest.mark.needs_nuitka


def _classify(stem: str) -> str | None:
    """Return the required toolchain for a test file stem, or ``None``.

    Matching is segment-based (``_``-delimited) so a name like
    ``test_no_nuitka_workaround`` is not mistaken for a real-toolchain test by a
    loose substring match.
    """
    segments = stem.split("_")
    if "nuitka" in segments:
        return "nuitka"
    adjacent = set(zip(segments, segments[1:]))
    if ("real", "cargo") in adjacent or ("real", "toolchain") in adjacent:
        return "cargo"
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    cargo = shutil.which("cargo")
    nuitka = shutil.which("nuitka")
    skip_cargo = pytest.mark.skip(reason="cargo is required for this real-toolchain e2e")
    skip_nuitka = pytest.mark.skip(reason="nuitka is required for this real-toolchain e2e")

    unclassified: list[str] = []
    for item in items:
        path = item.fspath
        if path is None or path.purebasename == "conftest":
            continue
        stem = path.purebasename
        toolchain = _classify(stem)
        if toolchain == "nuitka":
            item.add_marker(_NEEDS_NUITKA)
            if nuitka is None:
                item.add_marker(skip_nuitka)
        elif toolchain == "cargo":
            item.add_marker(_NEEDS_CARGO)
            if cargo is None:
                item.add_marker(skip_cargo)
        else:
            # Not toolchain-tagged by filename. It must be a toolchain-free e2e
            # (the CLI smoke / zipapp tests stub the build with the `fake_cargo`
            # fixture). Anything else is a real-toolchain test that would silently
            # run nowhere once `-m needs_cargo` is applied, so fail loudly.
            if "fake_cargo" not in getattr(item, "fixturenames", ()):
                unclassified.append(item.nodeid)

    if unclassified:
        listing = "\n  ".join(sorted(unclassified))
        raise pytest.UsageError(
            "e2e tests must declare their toolchain so CI cannot silently drop "
            "them. Name a real-cargo test `*_real_cargo` / `*_real_toolchain`, a "
            "Nuitka test with a `nuitka` segment, or use the `fake_cargo` fixture "
            f"for a toolchain-free test. Unclassified:\n  {listing}"
        )
