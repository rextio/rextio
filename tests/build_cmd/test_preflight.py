from __future__ import annotations

import pytest

from rextio.build import preflight


def test_no_missing_tools_when_cargo_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert preflight.missing_build_tools(native_backend="rust", build_tool="cargo") == []


def test_reports_missing_rust_toolchain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    missing = preflight.missing_build_tools(native_backend="rust", build_tool="cargo")
    assert [tool.name for tool in missing] == ["Rust toolchain"]
    assert "rustup.rs" in preflight.format_missing_tools(missing)


def test_missing_maturin_is_ok_when_cargo_present(monkeypatch: pytest.MonkeyPatch) -> None:
    # maturin builds fall back to cargo, so a missing maturin is not fatal.
    monkeypatch.setattr(
        preflight.shutil, "which", lambda name: "/usr/bin/cargo" if name == "cargo" else None
    )
    assert preflight.missing_build_tools(native_backend="rust", build_tool="maturin") == []


def test_missing_both_maturin_and_cargo_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    missing = preflight.missing_build_tools(native_backend="rust", build_tool="maturin")
    assert [tool.name for tool in missing] == ["Rust toolchain"]


def test_reports_missing_nuitka_when_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight.shutil, "which", lambda name: "/usr/bin/cargo" if name == "cargo" else None
    )
    missing = preflight.missing_build_tools(native_backend="rust", build_tool="cargo", nuitka=True)
    assert "Nuitka" in {tool.name for tool in missing}


def test_non_rust_backend_does_not_require_cargo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    assert preflight.missing_build_tools(native_backend="mojo", build_tool="cargo") == []
