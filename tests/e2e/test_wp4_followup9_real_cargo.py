"""WP-4 follow-up 9 executable-authority real-Cargo regression."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


requires_cargo = pytest.mark.skipif(
    shutil.which("cargo") is None, reason="cargo is required for native e2e"
)


@requires_cargo
def test_mutated_logger_receiver_stays_on_python_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        '[rust]\nbuild_tool = "cargo"\n',
        encoding="utf-8",
    )
    source = tmp_path / "src" / "wp9logger" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "import logging\n"
        "import rextio\n\n"
        "logger = logging.getLogger(__name__)\n"
        "@rextio.native\n"
        "def affected(x: int) -> int:\n"
        "    logger.info('x=%s', x)\n"
        "    return x + 100\n\n"
        "alias = logger\n"
        "alias.info = lambda *args: (_ for _ in ()).throw(\n"
        "    RuntimeError('mutated logger receiver')\n"
        ")\n",
        encoding="utf-8",
    )
    (source.parent / "clean.py").write_text(
        "import rextio\n\n@rextio.native\ndef keep(x: int) -> int:\n    return x + 1\n",
        encoding="utf-8",
    )

    assert main(["check", str(tmp_path)]) == 0
    check = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    statuses = {
        function["qualname"]: function["native_status"]
        for module in check["modules"]
        for function in module["functions"]
    }
    assert statuses["wp9logger.ops.affected"] == "rejected"
    assert statuses["wp9logger.clean.keep"] == "accepted"

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    build = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert build["native_build"]["status"] == "built"
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp9logger.ops")
    clean = fresh_import("wp9logger.clean")

    with pytest.raises(RuntimeError, match="mutated logger receiver"):
        module.affected(1)
    assert clean.keep(1) == 2
