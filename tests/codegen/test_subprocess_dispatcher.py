from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from rextio.codegen.subprocess_dispatcher import PROTOCOL_VERSION, render_dispatcher_script


def _run_dispatcher(tmp_path: Path, allowed: list[str], requests: list[dict]) -> list[dict]:
    (tmp_path / "fb.py").write_text(
        """
def add(a, b):
    return a + b

def greet(name):
    return "hi " + name

def boom(x):
    raise ValueError("kaboom: " + str(x))

def total(xs):
    return sum(xs)
""",
        encoding="utf-8",
    )
    dispatcher = tmp_path / "dispatcher.py"
    dispatcher.write_text(render_dispatcher_script(allowed), encoding="utf-8")

    stdin = "".join(json.dumps(request) + "\n" for request in requests)
    completed = subprocess.run(
        [sys.executable, str(dispatcher)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=tmp_path,  # put the fallback module on sys.path
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def test_dispatcher_serves_calls_errors_and_denies_unlisted(tmp_path: Path) -> None:
    responses = _run_dispatcher(
        tmp_path,
        allowed=["fb.add", "fb.greet", "fb.boom", "fb.total"],
        requests=[
            {"call": "fb.add", "args": [2, 3]},
            {"call": "fb.greet", "args": ["ada"]},
            {"call": "fb.total", "args": [[1, 2, 3, 4]]},
            {"call": "fb.boom", "args": [7]},
            {"call": "fb.not_listed", "args": []},
        ],
    )

    assert responses[0] == {"ok": 5}
    assert responses[1] == {"ok": "hi ada"}
    assert responses[2] == {"ok": 10}
    # A Python exception is forwarded with its type name and message.
    assert responses[3] == {"error": {"type": "ValueError", "message": "kaboom: 7"}}
    # A call outside the allow-list is refused without importing/executing it.
    assert responses[4]["error"]["type"] == "LookupError"
    assert "not permitted" in responses[4]["error"]["message"]


def test_dispatcher_reports_invalid_json_request(tmp_path: Path) -> None:
    (tmp_path / "fb.py").write_text("def noop():\n    return None\n", encoding="utf-8")
    dispatcher = tmp_path / "dispatcher.py"
    dispatcher.write_text(render_dispatcher_script(["fb.noop"]), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(dispatcher)],
        input="{not json}\n",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout.splitlines()[0])
    assert response["error"]["type"] == "ValueError"


def test_render_is_deterministic_and_embeds_sorted_allowlist() -> None:
    first = render_dispatcher_script(["b.y", "a.x"])
    second = render_dispatcher_script(["a.x", "b.y"])
    assert first == second
    assert '["a.x", "b.y"]' in first
    assert f"PROTOCOL_VERSION = {PROTOCOL_VERSION}" in first
