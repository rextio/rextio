from __future__ import annotations

import json
from pathlib import Path

from rextio.cli.main import main


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
    assert "RXT060 Configuration error" in captured.out
    assert "allow_dynamic_features" in captured.out


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
    assert "RXT060 Configuration error" in captured.out
    assert "enabled plugin was not discovered: numpy-rust" in captured.out


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
    assert "RXT060 Configuration error" in captured.out
    assert "allow_dynamic_features" in captured.out


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
