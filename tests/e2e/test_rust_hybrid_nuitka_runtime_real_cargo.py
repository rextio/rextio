from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required to build the binary")
def test_hybrid_runtime_nuitka(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text('[rust]\nbuild_tool = "cargo"\n', encoding="utf-8")
    source = tmp_path / "src" / "hb" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.exempt
def slugify(text: str) -> str:
    return text.lower()

@rextio.native
def main(argv: list[str]) -> int:
    return len(slugify(argv[1]))
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--executable-backend=rust",
            "--entrypoint=hb.app:main",
            "--hybrid-runtime=nuitka",
        ]
    )
    report = json.loads((tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8"))
    executable = report["executable_build"]

    if shutil.which("nuitka") is None:
        # The binary compiles, but packaging the dispatcher fails with a clear message.
        assert exit_code != 0
        assert executable["status"] == "failed"
        assert "Nuitka is not installed" in executable["message"]
    else:
        # With Nuitka available, a self-contained dispatcher executable is produced.
        assert exit_code == 0
        assert executable["status"] == "built"
        binary = Path(executable["path"])
        assert (binary.parent / f"{binary.name}.runtime" / "dispatcher").exists()
