from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path

import pytest

import rextio.cli.main as cli_main
from rextio.cli.main import _install_deprecation_filter, _positive_number, main
from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS, MAX_BUILD_TIMEOUT_SECONDS


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
    # Reset the install guard so main() registers the filter inside our scope.
    monkeypatch.setattr(cli_main, "_REXTIO_WARNING_FILTER_INSTALLED", False)
    (tmp_path / "app.py").write_text("def f(x: int) -> int:\n    return x\n", encoding="utf-8")

    shown: list[str] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # Python's default baseline
        monkeypatch.setattr(warnings, "showwarning", lambda message, *a, **k: shown.append(str(message)))
        exit_code = main(["check", str(tmp_path), "--no-report"])

    assert exit_code == 0
    # The plugin `rules` deprecation was shown despite the ignore baseline.
    assert any("no longer used" in message and "legacy-plugin" in message for message in shown)


def test_deprecation_filter_is_idempotent_and_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_REXTIO_WARNING_FILTER_INSTALLED", False)
    with warnings.catch_warnings():
        warnings.resetwarnings()
        baseline = len(warnings.filters)
        _install_deprecation_filter()
        _install_deprecation_filter()  # second call must not add a duplicate
        added = [
            f
            for f in warnings.filters
            if f[2] is DeprecationWarning and f[3] is not None and f[3].pattern == r"rextio($|\.)"
        ]
        assert len(warnings.filters) == baseline + 1
        assert len(added) == 1
        pattern = added[0][3]
        # Matches the package and its submodules, not lookalikes.
        assert pattern.match("rextio")
        assert pattern.match("rextio.plugins.loader")
        assert not pattern.match("rextio_extra")
        assert not pattern.match("rextiofoo")


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
    assert 'backend = "cranelift"' in config_text


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

    assert exit_code == 1
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
