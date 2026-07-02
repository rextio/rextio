from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.codegen.rust.cargo import render_binary_cargo_toml
from rextio.codegen.rust.subprocess_client import render_subprocess_client


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required to compile the IPC client")
def test_subprocess_client_compiles(tmp_path: Path) -> None:
    # The IPC client is non-trivial Rust (disjoint field borrows through a
    # MutexGuard, OnceLock, serde_json); compile it against a minimal RextioError
    # to catch borrow/type errors without needing a full generated project.
    (tmp_path / "Cargo.toml").write_text(
        render_binary_cargo_toml("rextio_client_probe", "rextio_client_probe", hybrid=True),
        encoding="utf-8",
    )
    src = tmp_path / "src"
    src.mkdir()
    main_rs = "\n".join(
        [
            "pub struct RextioError { kind: String, message: String }",
            "impl RextioError {",
            "    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {",
            "        Self { kind: kind.into(), message: message.into() }",
            "    }",
            "}",
            render_subprocess_client(),
            "fn main() {",
            "    // Reference the client so it is type-checked; do not launch Python here.",
            "    let _ = __rextio_call_python as fn(&str, Vec<serde_json::Value>) "
            "-> Result<serde_json::Value, RextioError>;",
            "}",
        ]
    )
    (src / "main.rs").write_text(main_rs, encoding="utf-8")
    cargo = shutil.which("cargo")
    assert cargo is not None

    completed = subprocess.run(
        [cargo, "build", "--release", "--manifest-path", str(tmp_path / "Cargo.toml")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert completed.returncode == 0, completed.stderr
