from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path
from typing import Any, cast

import pytest

from rextio.cli.main import (
    _REXTIO_DEPRECATION_MODULE,
    _install_deprecation_filter,
    _positive_number,
    _rextio_deprecation_filter_present,
    main,
)
from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS, MAX_BUILD_TIMEOUT_SECONDS


def _installed_rextio_filters() -> list[tuple]:
    # Read each filter's module element defensively (it may be a compiled pattern, a
    # plain string, or None) — mirrors `_rextio_deprecation_filter_present` in the source.
    return [
        f
        for f in warnings.filters
        if f[2] is DeprecationWarning and getattr(f[3], "pattern", f[3]) == _REXTIO_DEPRECATION_MODULE
    ]


def test_main_surfaces_plugin_rules_deprecation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # End-to-end: a `rextio check` run that discovers a plugin declaring a legacy
    # `rules` field must SURFACE the DeprecationWarning — i.e. the CLI's filter
    # actually unhides it (overrides Python's default-ignore), not merely installs a
    # filter object. We start from an "ignore" baseline and capture which warnings the
    # filter machinery decides to *show* via a recording showwarning hook (this is what
    # writing to stderr means, without fighting pytest's own warning capture).
    from rextio.plugins import loader as plugin_loader

    class _FakeEntryPoint:
        name = "legacy-plugin"

        def load(self) -> dict[str, object]:
            return {"target_language": "rust", "packages": ["x"], "rules": ["y"]}

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))
    # The "default" action dedups per location via the loader module's
    # __warningregistry__; clear it so the deprecation re-surfaces regardless of prior
    # emissions (the filter mutations below already bump the version, but this is explicit).
    if hasattr(plugin_loader, "__warningregistry__"):
        plugin_loader.__warningregistry__.clear()
    (tmp_path / "app.py").write_text("def f(x: int) -> int:\n    return x\n", encoding="utf-8")

    shown: list[str] = []
    with warnings.catch_warnings():
        # Reset to a clean baseline (don't depend on whatever filters leak in), then make
        # Python's default-ignore the fallback. main()'s presence-based install prepends
        # the rextio "default" filter, which must win over this ignore for rextio modules.
        warnings.resetwarnings()
        warnings.simplefilter("ignore", DeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", lambda message, *a, **k: shown.append(str(message)))
        exit_code = main(["check", str(tmp_path), "--no-report"])

    assert exit_code == 0
    assert shown, "no DeprecationWarning was shown — the CLI filter failed to unhide it"
    # The plugin `rules` deprecation was shown despite the ignore baseline.
    assert any("is ignored" in message and "legacy-plugin" in message for message in shown)


def test_deprecation_filter_is_idempotent_and_scoped() -> None:
    with warnings.catch_warnings():
        warnings.resetwarnings()
        baseline = len(warnings.filters)
        _install_deprecation_filter()
        _install_deprecation_filter()  # second call must not add a duplicate (presence-based)
        added = _installed_rextio_filters()
        assert len(warnings.filters) == baseline + 1
        assert len(added) == 1
        pattern = added[0][3]
        # Matches the package and its submodules, not lookalikes.
        assert pattern.match("rextio")
        assert pattern.match("rextio.plugins.loader")
        assert not pattern.match("rextio_extra")
        assert not pattern.match("rextiofoo")


def test_deprecation_filter_self_heals_after_teardown() -> None:
    # The presence-based install re-registers the filter if it was torn down (e.g. by a
    # surrounding catch_warnings), where the old flag-based guard would have stayed set.
    with warnings.catch_warnings():
        warnings.resetwarnings()
        _install_deprecation_filter()
        warnings.resetwarnings()  # simulate the filter being removed
        _install_deprecation_filter()
        assert len(_installed_rextio_filters()) == 1


def test_deprecation_filter_presence_handles_str_and_none_module_elements() -> None:
    # A filter's module element can be a compiled pattern, a plain string, or None.
    # The presence check must read it defensively (no AttributeError) and not false-match.
    with warnings.catch_warnings():
        warnings.resetwarnings()
        # warnings.filters is typed as an immutable Sequence but is a mutable list at
        # runtime; we craft synthetic entries (str / None module elements) it can't model.
        # Use action="default" so each entry passes the presence check's action gate and
        # actually reaches the defensive `getattr(module, ...)` read (an "ignore" action
        # would short-circuit before it, leaving the str/None branches unexercised).
        filters = cast("list[Any]", warnings.filters)
        filters[:] = [
            ("default", None, DeprecationWarning, None, 0),  # module is None
            ("default", None, DeprecationWarning, "rextio_extra", 0),  # module is a non-matching str
        ]
        assert _rextio_deprecation_filter_present() is False
        filters.insert(0, ("default", None, DeprecationWarning, _REXTIO_DEPRECATION_MODULE, 0))
        assert _rextio_deprecation_filter_present() is True


@pytest.mark.parametrize("bad", ["inf", "nan", "0", "-1", "abc", str(MAX_BUILD_TIMEOUT_SECONDS + 1)])
def test_build_timeout_cli_validator_rejects(bad: str) -> None:
    # The --build-timeout argparse type must reject inf/nan/non-positive/over-cap.
    with pytest.raises(argparse.ArgumentTypeError):
        _positive_number(bad)


def test_build_timeout_cli_validator_accepts_valid_value() -> None:
    assert _positive_number(str(DEFAULT_BUILD_TIMEOUT_SECONDS)) == float(DEFAULT_BUILD_TIMEOUT_SECONDS)
    assert _positive_number(str(MAX_BUILD_TIMEOUT_SECONDS)) == float(MAX_BUILD_TIMEOUT_SECONDS)


def test_init_creates_default_project_files(tmp_path: Path, capsys) -> None:
    exit_code = main(["init", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Rextio init" in captured.out
    assert (tmp_path / "rextio.toml").exists()
    assert (tmp_path / "REXTIO.md").exists()
    assert (tmp_path / ".rextioignore").exists()
    config_text = (tmp_path / "rextio.toml").read_text(encoding="utf-8")
    assert 'native_marker = "auto"' in config_text
    assert 'default_external_policy = "fallback"' in config_text
    assert "[jit]" in config_text
    assert "enabled = false" in config_text


def test_check_json_outputs_structured_analysis(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    report = json.loads((tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert data["accepted_native"] == ["app.add"]
    assert data["diagnostics"] == []
    assert report["accepted_native"] == ["app.add"]


def test_check_no_report_skips_report_file(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json", "--no-report"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert exit_code == 0
    assert data["accepted_native"] == ["app.add"]
    # The command stays side-effect-free: no report file is written.
    assert not (tmp_path / ".rextio" / "reports" / "check.json").exists()


def test_check_json_respects_native_marker_target_language(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native(target="mojo")
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            str(tmp_path),
            "--json",
            "--native-marker=decorator",
            "--target-language=rust",
        ]
    )

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == []


def test_check_json_auto_discovers_unmarked_typed_functions(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == ["app.add"]


def test_check_json_reports_native_top_level_when_enabled(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
total: int = 41
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json", "--native-top-level"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native_top_levels"] == ["app.__rextio_top_level__"]


def test_check_json_respects_decorator_only_native_discovery(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == []


def test_check_respects_boundary_warnings_policy(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
boundary_warnings = false
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def score_one(x: float) -> float:
    return x * 2.0

def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(score_one(x))
    return out
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == ["app.score_one"]
    assert data["diagnostics"] == []


def test_check_environment_overrides_policy_config(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MARKER", "auto")
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == ["app.add"]


def test_check_cli_overrides_environment_policy(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REXTIO_NATIVE_MARKER", "auto")
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--json", "--native-marker=decorator"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["accepted_native"] == []


def test_check_rejects_unsupported_cli_policy_override(tmp_path: Path, capsys) -> None:
    exit_code = main(["check", str(tmp_path), "--allow-dynamic-features"])

    captured = capsys.readouterr()

    assert exit_code == 1
    # Configuration errors are routed to stderr so stdout stays a clean result stream.
    assert "RXT060 Configuration error" in captured.err
    assert "allow_dynamic_features" in captured.err


def test_check_reports_plugin_configuration_error(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "check",
            str(tmp_path),
            "--enable-plugin=numpy-rust",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Configuration error" in captured.err
    assert "enabled plugin was not discovered: numpy-rust" in captured.err


def test_check_applies_package_import_policy_override(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
import safe_pkg

def compute(x: float) -> float:
    return safe_pkg.normalize(x)
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "check",
            str(tmp_path),
            "--package-import-policy=safe_pkg=try-native",
        ]
    )

    captured = capsys.readouterr()

    # A dependency rejection keeps the function on the Python fallback (an
    # expected, advisory outcome), so `check` reports it but exits 0; only a
    # genuine parse failure makes `check` non-zero.
    assert exit_code == 0
    assert "experimental dependency lowering" in captured.out
    assert "Import policies:" in captured.out
    assert "[try-native] safe_pkg (external)" in captured.out


def test_check_reports_config_error(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
allow_dynamic_features = true
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Configuration error" in captured.err
    assert "allow_dynamic_features" in captured.err


def test_clean_removes_generated_artifacts(tmp_path: Path, capsys) -> None:
    for name in ("build", "generated", "reports"):
        path = tmp_path / ".rextio" / name
        path.mkdir(parents=True)
        (path / "artifact.txt").write_text("generated", encoding="utf-8")

    exit_code = main(["clean", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Rextio clean" in captured.out
    assert not (tmp_path / ".rextio" / "build").exists()
    assert not (tmp_path / ".rextio" / "generated").exists()
    assert not (tmp_path / ".rextio" / "reports").exists()


def test_version_flag_reports_version(capsys: "pytest.CaptureFixture[str]") -> None:
    import pytest

    from rextio.__about__ import __version__

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"rextio {__version__}"


def test_check_exits_zero_on_pure_rejection(tmp_path: Path, capsys) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        """
import rextio

@rextio.native
def loop_else(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total = total + x
    else:
        total = total + 1
    return total
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--no-report"])

    # The function is rejected (RXT010) and stays on the Python fallback — an
    # advisory outcome, not a failure.
    assert exit_code == 0


def test_check_exits_nonzero_on_parse_error(tmp_path: Path, capsys) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        """
import rextio

@rextio.native
def broken(x: int) ->
""",
        encoding="utf-8",
    )

    exit_code = main(["check", str(tmp_path), "--no-report"])

    assert exit_code == 1
