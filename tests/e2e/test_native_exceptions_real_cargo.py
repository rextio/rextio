from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_native_try_except_finally(
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
    source = tmp_path / "src" / "exc_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def safe_mod(a: int, b: int) -> int:
    result = 0
    try:
        result = a % b
    except ZeroDivisionError:
        result = -1
    finally:
        result = result + 100
    return result

@rextio.native
def guarded_index(xs: list[int], i: int) -> int:
    value = 0
    try:
        value = xs[i]
    except IndexError:
        value = -1
    return value

@rextio.native
def reraises(a: int, b: int) -> int:
    out = 0
    try:
        out = a % b
    except IndexError:
        out = -1
    finally:
        out = out + 1
    return out
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
    assert report["rejected_native_count"] == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("exc_app.ops")

    # No exception: try body runs, then finally.
    assert module.safe_mod(10, 3) == 10 % 3 + 100
    # Caught exception: handler runs, then finally.
    assert module.safe_mod(10, 0) == -1 + 100
    # IndexError caught natively.
    assert module.guarded_index([1, 2, 3], 1) == 2
    assert module.guarded_index([1, 2, 3], 9) == -1
    # Unmatched handler: finally still runs, then the original error propagates.
    assert module.reraises(5, 2) == 5 % 2 + 1
    with pytest.raises(ZeroDivisionError):
        module.reraises(5, 0)
