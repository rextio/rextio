from __future__ import annotations

import pytest

from rextio.build import preflight


def test_no_missing_tools_when_cargo_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert preflight.missing_build_tools(native_backend="rust") == []


def test_reports_missing_rust_toolchain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    missing = preflight.missing_build_tools(native_backend="rust")
    assert [tool.name for tool in missing] == ["Rust toolchain"]
    assert "rustup.rs" in preflight.format_missing_tools(missing)


def test_cargo_required_even_when_only_maturin_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # maturin wraps cargo/rustc, so cargo is still required.
    monkeypatch.setattr(
        preflight.shutil, "which", lambda name: "/usr/bin/maturin" if name == "maturin" else None
    )
    missing = preflight.missing_build_tools(native_backend="rust")
    assert [tool.name for tool in missing] == ["Rust toolchain"]


def test_non_rust_backend_does_not_require_cargo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    assert preflight.missing_build_tools(native_backend="mojo") == []
