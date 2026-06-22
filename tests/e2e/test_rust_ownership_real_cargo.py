from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_owned_values_reused_after_container_literals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "ownership_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
def alias_read(xs: list[int]) -> int:
    ys = xs
    return ys[0] + xs[0]

def group_lengths(xs: list[int], ys: list[int]) -> int:
    groups: list[list[int]] = [xs, ys]
    return len(groups[0]) + xs[0] + ys[0]

def label_lengths(label: str) -> int:
    labels: dict[str, str] = {"primary": label}
    return len(labels["primary"]) + len(label)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert report["native_build"]["status"] == "built"
    assert report["accepted_native_count"] == 3

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("ownership_app.ops")

    assert module.alias_read([4]) == 8
    assert module.group_lengths([4, 5], [7]) == 13
    assert module.label_lengths("abc") == 6
