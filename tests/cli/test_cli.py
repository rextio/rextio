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
    assert 'native_marker = "auto"' in (tmp_path / "rextio.toml").read_text(
        encoding="utf-8"
    )


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
