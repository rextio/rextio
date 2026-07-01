from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for the hybrid executable e2e")
def test_rust_hybrid_executable_delegates_fallback_to_cpython(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "hb" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.exempt
def slugify(text: str) -> str:
    import re
    # Not in the native Rust subset -> left as Python, run via the dispatcher.
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

@rextio.native
def main(argv: list[str]) -> int:
    s = slugify(argv[1])
    print(s)
    return len(s)
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
        ]
    )
    assert exit_code == 0
    capsys.readouterr()

    report = json.loads((tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8"))
    executable = report["executable_build"]
    assert executable["status"] == "built", executable
    binary = Path(executable["path"])
    assert binary.exists()

    # The runtime directory (dispatcher + project source) is shipped next to the binary.
    runtime = binary.parent / f"{binary.name}.runtime"
    assert (runtime / "_rextio_dispatcher.py").exists()
    assert (runtime / "hb" / "app.py").exists()

    # Running it delegates slugify() to CPython and returns the slug's length.
    completed = subprocess.run(
        [str(binary), "Hello, Rextio World!"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.stdout.strip() == "hello-rextio-world"
    assert completed.returncode == len("hello-rextio-world")

    # A native error (out-of-range index) prints CPython-style to stderr.
    missing_arg = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    assert missing_arg.returncode == 1
    assert "IndexError" in missing_arg.stderr

    # A bad interpreter surfaces a clean RextioError (exit 1) instead of a Rust
    # panic (exit 101): the dispatcher launch failure is fallible, not `.expect()`.
    bad_python = subprocess.run(
        [str(binary), "Hello, Rextio World!"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**__import__("os").environ, "REXTIO_PYTHON": "/nonexistent/rextio-python"},
    )
    assert bad_python.returncode == 1, bad_python.stderr
    assert "dispatcher" in bad_python.stderr
