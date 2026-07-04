from __future__ import annotations

import hashlib
import json
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
# The fixture calls datetime.utcnow() ON PURPOSE - it pins Rextio's
# utcnow().timestamp() lowering - and CPython 3.12+ deprecation-warns about
# the fixture's own fallback execution. Scoped here so the run summary stays
# empty without hiding utcnow deprecations anywhere else.
@pytest.mark.filterwarnings("ignore:datetime.datetime.utcnow:DeprecationWarning")
def test_real_cargo_build_handles_expanded_stdlib_lowering(
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
    source = tmp_path / "src" / "stdlib_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import base64
import hashlib
import json
import math
import statistics
import time
from datetime import datetime

def mathy(xs: list[float]) -> float:
    return (
        math.tan(xs[0])
        + math.asin(xs[1])
        + math.acos(xs[2])
        + math.atan(xs[3])
        + math.atan2(xs[0], xs[1])
        + math.exp(xs[0])
        + math.log(xs[1])
        + math.log(xs[1], math.e)
        + math.log2(xs[1])
        + math.log10(xs[1])
        + math.pi
        + statistics.mean(xs)
        + statistics.fmean(xs)
    )

def roundy(x: float) -> int:
    return math.ceil(x) + math.trunc(x) + math.floor(x)

def predicates(x: float, flags: list[bool]) -> bool:
    return math.isfinite(x) and not math.isnan(x) and not math.isinf(x) and any(flags) and all(flags)

def text(value: str) -> str:
    return value.strip().lower().replace("a", "b").upper()

def prefix_suffix(value: str) -> bool:
    return value.startswith("a") or value.endswith("z")

def list_ops(xs: list[int]) -> int:
    copied = xs.copy()
    sorted_values = sorted(copied)
    total = sorted_values.count(2) + sorted_values.index(2)
    for value in reversed(sorted_values):
        total += value
    return total

def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def b64_roundtrip(value: str) -> str:
    encoded = base64.b64encode(value.encode())
    return base64.b64decode(encoded).decode()

def json_roundtrip(value: str) -> dict[str, int]:
    parsed: dict[str, int] = json.loads(value)
    return parsed

def json_dump(value: dict[str, int]) -> str:
    return json.dumps(value)

def clocks() -> float:
    return time.time() + datetime.utcnow().timestamp()
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    assert exit_code == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = __import__("stdlib_app.ops", fromlist=["ops"])

    xs = [0.25, 0.5, 0.75, 1.0]
    assert module.mathy(xs) == pytest.approx(
        math.tan(xs[0])
        + math.asin(xs[1])
        + math.acos(xs[2])
        + math.atan(xs[3])
        + math.atan2(xs[0], xs[1])
        + math.exp(xs[0])
        + math.log(xs[1])
        + math.log(xs[1], math.e)
        + math.log2(xs[1])
        + math.log10(xs[1])
        + math.pi
        + sum(xs) / len(xs)
        + sum(xs) / len(xs)
    )
    assert module.roundy(3.8) == math.ceil(3.8) + math.trunc(3.8) + math.floor(3.8)
    assert module.predicates(1.0, [True, True])
    assert module.text("  Alpha  ") == "BLPHB"
    assert module.prefix_suffix("abc")
    assert module.list_ops([3, 2, 1, 2]) == 11
    assert module.digest("hello") == hashlib.sha256("hello".encode()).hexdigest()
    assert module.b64_roundtrip("hello") == "hello"
    assert module.json_roundtrip('{"a": 1, "b": 2}') == {"a": 1, "b": 2}
    assert json.loads(module.json_dump({"a": 1, "b": 2})) == {"a": 1, "b": 2}
    assert module.clocks() > 0.0
