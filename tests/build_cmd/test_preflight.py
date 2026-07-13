from __future__ import annotations

import pytest

from rextio.build import preflight
from rextio.build import toolchain as toolchain_mod


def test_no_missing_tools_when_cargo_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(toolchain_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert preflight.missing_build_tools(native_backend="rust") == []


def test_reports_missing_rust_toolchain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(toolchain_mod.shutil, "which", lambda name: None)
    missing = preflight.missing_build_tools(native_backend="rust")
    assert [tool.name for tool in missing] == ["Rust toolchain"]
    assert "rustup.rs" in preflight.format_missing_tools(missing)


def test_cargo_required_even_when_only_maturin_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # maturin wraps cargo/rustc, so cargo is still required.
    monkeypatch.setattr(
        toolchain_mod.shutil,
        "which",
        lambda name: "/usr/bin/maturin" if name == "maturin" else None,
    )
    missing = preflight.missing_build_tools(native_backend="rust")
    assert [tool.name for tool in missing] == ["Rust toolchain"]


def test_non_rust_backend_does_not_require_cargo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(toolchain_mod.shutil, "which", lambda name: None)
    assert preflight.missing_build_tools(native_backend="zig") == []


def _fake_nuitka_printing(
    tmp_path, version_line: str, *, exit_code: int = 0, to_stderr: bool = False
) -> str:
    import stat

    fake = tmp_path / "nuitka"
    redirect = " >&2" if to_stderr else ""
    fake.write_text(
        f"#!/bin/sh\necho '{version_line}'{redirect}\nexit {exit_code}\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    return str(fake)


def test_nuitka_version_error_rejects_pre_2(tmp_path) -> None:
    from rextio.build.preflight import nuitka_version_error

    error = nuitka_version_error([_fake_nuitka_printing(tmp_path, "1.9.7")])
    assert error is not None
    assert "Nuitka 1.9.7 is too old" in error
    assert ">= 2.0" in error


def test_nuitka_version_error_accepts_2_and_unparseable(tmp_path) -> None:
    # 2.x passes; an unparseable version is best-effort (the real invocation
    # surfaces any incompatibility), so the probe does not block the build.
    from rextio.build.preflight import nuitka_version_error

    assert nuitka_version_error([_fake_nuitka_printing(tmp_path, "2.4.8")]) is None
    assert nuitka_version_error([_fake_nuitka_printing(tmp_path, "Nuitka something")]) is None


def test_nuitka_version_error_ignores_output_on_nonzero_exit(tmp_path) -> None:
    # A broken install may still print something version-shaped; the probe
    # treats a non-zero exit as undetermined and passes through.
    from rextio.build.preflight import nuitka_version_error

    assert nuitka_version_error([_fake_nuitka_printing(tmp_path, "1.9.7", exit_code=1)]) is None


def test_nuitka_version_error_reads_stderr_and_prefixed_lines(tmp_path) -> None:
    # The version may arrive on stderr or behind a "Nuitka ..." prefix; both
    # still enforce the floor.
    from rextio.build.preflight import nuitka_version_error

    stderr_error = nuitka_version_error([_fake_nuitka_printing(tmp_path, "1.9.7", to_stderr=True)])
    assert stderr_error is not None and "too old" in stderr_error
    prefixed_error = nuitka_version_error([_fake_nuitka_printing(tmp_path, "Nuitka 1.9.7")])
    assert prefixed_error is not None and "too old" in prefixed_error
    assert (
        nuitka_version_error([_fake_nuitka_printing(tmp_path, "Nuitka 2.4.8", to_stderr=True)])
        is None
    )
