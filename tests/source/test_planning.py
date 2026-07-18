from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.source import planning
from rextio.source.planning import (
    build_host_source_plan,
    ensure_host_source_plan,
    select_executable_module_initializers,
)


def test_host_source_plan_is_coherent_deterministic_and_cached(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("seed = 1\n", encoding="utf-8")
    analysis = analyze_project(tmp_path)

    first = build_host_source_plan(analysis)
    second = build_host_source_plan(analysis)

    assert first == second
    assert first.available
    assert first.graph is not None
    assert first.graph.modules[0].path == "app.py"
    assert first.module_initializers[0].path == "app.py"
    assert first.graph.modules[0].sha256 == first.module_initializers[0].source_sha256

    cached = ensure_host_source_plan(analysis)
    source.write_text("seed = 2\n", encoding="utf-8")
    assert ensure_host_source_plan(analysis) is cached


def test_host_source_plan_fails_closed_on_snapshot_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("seed = 1\n", encoding="utf-8")
    analysis = analyze_project(tmp_path)
    original = planning.build_project_module_init_irs(analysis)
    mismatched = replace(original[0], source_sha256="0" * 64)
    monkeypatch.setattr(planning, "build_project_module_init_irs", lambda _analysis: (mismatched,))

    plan = build_host_source_plan(analysis)

    assert not plan.available
    assert plan.unavailable_reason == "source-snapshot-mismatch:app"


def test_host_source_plan_serializes_parse_failure_without_absolute_source_paths(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    analysis = analyze_project(tmp_path)

    data = build_host_source_plan(analysis).to_dict()

    assert data["availability"] == "unavailable"
    assert str(tmp_path) not in repr(data)
    assert "broken.py" in repr(data)


def test_host_source_plan_fails_closed_for_symlink_outside_project_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("seed = 1\n", encoding="utf-8")
    (project / "app.py").symlink_to(outside)
    analysis = analyze_project(project)

    data = build_host_source_plan(analysis).to_dict()

    assert data["availability"] == "unavailable"
    assert data["unavailable_reason"] == "module-init-plan-unavailable"
    assert data["graph"] is None
    assert data["module_initializers"] == []
    assert str(outside) not in repr(data)


def test_selects_only_scalar_literal_initializer_in_entry_module(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    selection = select_executable_module_initializers(analysis, "app.main")

    assert selection.blockers == ()
    assert [item.qualname for item in selection.initializers] == ["app.__rextio_top_level__"]


def test_initializer_name_may_be_shadowed_by_an_entrypoint_local(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n"
        "    seed = len(argv)\n    return seed\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    selection = select_executable_module_initializers(analysis, "app.main")

    assert selection.blockers == ()
    assert len(selection.initializers) == 1


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (
            "seed: int = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
            "plain scalar-literal assignments",
        ),
        (
            "seed = 1 + 2\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
            "plain scalar-literal assignments",
        ),
        (
            "import math\nseed = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
            "imports are outside",
        ),
    ],
)
def test_executable_initializer_slice_fails_closed(
    tmp_path: Path,
    source: str,
    reason: str,
) -> None:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    selection = select_executable_module_initializers(analysis, "app.main")

    assert selection.initializers == ()
    assert selection.blockers
    assert reason in selection.blockers[0].reason


def test_executable_initializer_initial_slice_rejects_multiple_modules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text(
        "def helper(value: int) -> int:\n    return value + 1\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    selection = select_executable_module_initializers(analysis, "app.main")

    assert selection.initializers == ()
    assert "exactly one source module" in selection.blockers[0].reason
