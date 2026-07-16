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
*nowhere* (mod-proposal P1-10 / council B2).

As a backstop, any ``tests/e2e`` test that is neither toolchain-tagged nor
recognized as toolchain-free emits a (non-fatal) warning so a misnamed
real-toolchain test is surfaced rather than silently dropped. A genuinely
toolchain-free test that does not use the ``fake_cargo`` shim can opt out of the
warning with ``@pytest.mark.no_toolchain`` (council M4: the previous hard
collection error was too aggressive for legitimate pure-Python e2e tests).

Locally this is a warning; in CI (where ``REXTIO_E2E_STRICT=1`` is set) it is
escalated to a hard collection error so a misnamed test cannot slip through a
green pipeline.
"""

from __future__ import annotations

import os
import shutil
import warnings
from pathlib import Path

import pytest

_E2E_DIR = Path(__file__).resolve().parent

_NEEDS_CARGO = pytest.mark.needs_cargo
_NEEDS_NUITKA = pytest.mark.needs_nuitka
_NEEDS_MATURIN = pytest.mark.needs_maturin


def pytest_addoption(parser: pytest.Parser) -> None:
    # Local ergonomics for the CI escalation: `pytest --e2e-strict` reproduces the
    # `REXTIO_E2E_STRICT=1` behavior without exporting an env var.
    parser.addoption(
        "--e2e-strict",
        action="store_true",
        default=False,
        help="Fail collection if a tests/e2e test is not toolchain-classified.",
    )


def _strict_mode(config: pytest.Config) -> bool:
    return bool(os.environ.get("REXTIO_E2E_STRICT")) or config.getoption("--e2e-strict")


def _classify(stem: str) -> str | None:
    """Return the required toolchain for a test file stem, or ``None``.

    Matching is segment-based (``_``-delimited) so a name like
    ``test_no_nuitka_workaround`` is not mistaken for a real-toolchain test by a
    loose substring match.
    """
    segments = stem.split("_")
    if "nuitka" in segments:
        return "nuitka"
    if "maturin" in segments:
        return "maturin"
    adjacent = set(zip(segments, segments[1:]))
    if ("real", "cargo") in adjacent or ("real", "toolchain") in adjacent:
        return "cargo"
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    cargo = shutil.which("cargo")
    nuitka = shutil.which("nuitka")
    maturin = shutil.which("maturin")
    skip_cargo = pytest.mark.skip(reason="cargo is required for this real-toolchain e2e")
    skip_nuitka = pytest.mark.skip(reason="nuitka is required for this real-toolchain e2e")
    skip_maturin = pytest.mark.skip(
        reason="maturin and cargo are required for this real-toolchain e2e"
    )

    unclassified: list[str] = []
    for item in items:
        path = item.fspath
        if path is None or path.purebasename == "conftest":
            continue
        # pytest_collection_modifyitems is a session-scoped hook: when the run
        # root is wider than tests/e2e (e.g. a full `pytest` from the repo
        # root), this conftest still receives EVERY collected item. The
        # toolchain classification only applies to this directory's tests -
        # without this scope check the guard flagged the whole unit suite as
        # "unclassified" in combined runs.
        if not Path(str(path)).resolve().is_relative_to(_E2E_DIR):
            continue
        stem = path.purebasename
        toolchain = _classify(stem)
        if toolchain == "nuitka":
            item.add_marker(_NEEDS_NUITKA)
            if nuitka is None:
                item.add_marker(skip_nuitka)
        elif toolchain == "maturin":
            item.add_marker(_NEEDS_MATURIN)
            if maturin is None or cargo is None:
                item.add_marker(skip_maturin)
        elif toolchain == "cargo":
            item.add_marker(_NEEDS_CARGO)
            if cargo is None:
                item.add_marker(skip_cargo)
        else:
            # Not toolchain-tagged by filename. Toolchain-free tests (the CLI
            # smoke / zipapp tests stub the build with the `fake_cargo` fixture)
            # are fine; an explicit `no_toolchain` marker also opts out. Anything
            # else might be a misnamed real-toolchain test, so surface it.
            fixtures = getattr(item, "fixturenames", ())
            has_optout = item.get_closest_marker("no_toolchain") is not None
            if "fake_cargo" not in fixtures and not has_optout:
                unclassified.append(item.nodeid)

    if unclassified:
        listing = "\n  ".join(sorted(unclassified))
        message = (
            "e2e tests should declare their toolchain so CI cannot silently drop "
            "them. Name a real-cargo test `*_real_cargo` / `*_real_toolchain`, a "
            "Nuitka test with a `nuitka` segment, use the `fake_cargo` fixture, or "
            f"mark a pure-Python test `@pytest.mark.no_toolchain`. Unclassified:\n  {listing}"
        )
        if _strict_mode(config):
            # `UsageError` is pytest's idiomatic "abort collection with a message"
            # signal; prefix it so CI logs read as a deliberate strict-check
            # failure rather than a generic pytest misuse.
            raise pytest.UsageError(f"strict e2e toolchain check failed: {message}")
        warnings.warn(message, stacklevel=2)


@pytest.fixture
def fresh_import():
    """Import a freshly-built module, evicting any cached `_rextio_native`.

    Each real-cargo e2e builds its own `_rextio_native` extension; without
    eviction a later test would reuse an earlier test's module (and miss its own
    functions). Returns a callable: ``fresh_import("pkg.mod")``.
    """
    import importlib
    import sys

    def _import(name: str) -> object:
        root = name.split(".", 1)[0]
        # A wrapper imports package-local support modules such as
        # ``pkg._fallback_ops``.  Evict the entire package subtree, not only the
        # requested module/root, so a parametrized rebuild cannot reuse the prior
        # case's fallback class or function identities.
        for cached in tuple(sys.modules):
            if cached == "_rextio_native" or cached == root or cached.startswith(f"{root}."):
                sys.modules.pop(cached, None)
        importlib.invalidate_caches()
        return importlib.import_module(name)

    return _import
