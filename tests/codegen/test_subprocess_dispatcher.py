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


def test_dispatcher_survives_poison_calls_and_isolates_output(tmp_path: Path) -> None:
    # A delegated function that prints, raises SystemExit, or returns a
    # non-serializable value must not corrupt the wire or kill the long-lived
    # dispatcher: its output goes to stderr and every later call is still answered.
    (tmp_path / "fb.py").write_text(
        """
def ok(a, b):
    return a + b

def talk(a):
    print("delegated stdout")
    import sys
    sys.stderr.write("delegated stderr\\n")
    return a * 2

def bail():
    raise SystemExit(3)

def nonserial():
    return object()

def recurse():
    return recurse()  # RecursionError raised inside the delegated call

def circular():
    a = []
    a.append(a)
    return a  # json.dumps raises on the circular reference
""",
        encoding="utf-8",
    )
    dispatcher = tmp_path / "dispatcher.py"
    dispatcher.write_text(
        render_dispatcher_script(
            ["fb.ok", "fb.talk", "fb.bail", "fb.nonserial", "fb.recurse", "fb.circular"]
        ),
        encoding="utf-8",
    )
    requests = [
        {"call": "fb.talk", "args": [5]},
        {"call": "fb.bail", "args": []},
        {"call": "fb.nonserial", "args": []},
        {"call": "fb.recurse", "args": []},  # RecursionError from the call
        {"call": "fb.circular", "args": []},  # serialization failure in json.dumps
        {"call": "fb.ok", "args": [10, 20]},
    ]
    completed = subprocess.run(
        [sys.executable, str(dispatcher)],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert responses[0] == {"ok": 10}
    assert responses[1] == {"error": {"type": "SystemExit", "message": "3"}}
    assert responses[2]["error"]["type"] == "TypeError"
    assert responses[3]["error"]["type"] == "RecursionError"  # call recursion -> error frame
    assert responses[4]["error"]["type"] == "ValueError"  # json.dumps circular ref -> error frame
    # The dispatcher survived every poison call and still answers the last request.
    assert responses[5] == {"ok": 30}
    # Delegated stdout never reaches the protocol stream; it is on stderr.
    assert "delegated stdout" not in completed.stdout
    assert "delegated stdout" in completed.stderr


def test_dispatcher_survives_str_raising_exception_and_bad_request(tmp_path: Path) -> None:
    # An exception whose __str__ itself raises, and a non-dict request, must each
    # yield an error frame rather than killing the long-lived dispatcher.
    (tmp_path / "fb.py").write_text(
        """
def ok(a, b):
    return a + b

class Bad(Exception):
    def __str__(self):
        raise RuntimeError("boom in __str__")

def raise_bad():
    raise Bad()
""",
        encoding="utf-8",
    )
    dispatcher = tmp_path / "dispatcher.py"
    dispatcher.write_text(render_dispatcher_script(["fb.ok", "fb.raise_bad"]), encoding="utf-8")
    stdin = (
        json.dumps({"call": "fb.raise_bad", "args": []}) + "\n"
        + json.dumps([1, 2, 3]) + "\n"  # a valid-JSON but non-dict request
        + json.dumps({"call": "fb.ok", "args": [40, 2]}) + "\n"
    )
    completed = subprocess.run(
        [sys.executable, str(dispatcher)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert responses[0]["error"]["type"] == "Bad"  # __str__ raising did not crash the dispatcher
    assert responses[1]["error"]["type"] == "AttributeError"  # non-dict request handled
    assert responses[2] == {"ok": 42}  # dispatcher still alive after both poison inputs


def test_dispatcher_stubs_rextio_when_unavailable(tmp_path: Path) -> None:
    # The reconstructed project source imports rextio for its decorators; the
    # dispatcher must run even under a stripped interpreter with no rextio.
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.exempt
def slug(text):
    return text.lower().replace(" ", "-")
""",
        encoding="utf-8",
    )
    dispatcher = tmp_path / "dispatcher.py"
    dispatcher.write_text(render_dispatcher_script(["app.slug"]), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-S", "-E", str(dispatcher)],  # no site-packages, no env -> no rextio
        input=json.dumps({"call": "app.slug", "args": ["Hello World"]}) + "\n",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout.splitlines()[0]) == {"ok": "hello-world"}


def test_render_is_deterministic_and_embeds_sorted_allowlist() -> None:
    first = render_dispatcher_script(["b.y", "a.x"])
    second = render_dispatcher_script(["a.x", "b.y"])
    assert first == second
    assert '["a.x", "b.y"]' in first
    assert f"PROTOCOL_VERSION = {PROTOCOL_VERSION}" in first
