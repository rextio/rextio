from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for Rust crate e2e")
def test_real_cargo_builds_rust_importable_crate_and_consumer_imports_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
importable = true
crate_name = "demo_rust_lib"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "demo_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
def square(x: int) -> int:
    return x * x

def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += square(x)
    return total
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    crate_path = tmp_path / "dist" / "demo_rust_lib-rust-crate"

    assert exit_code == 0
    assert report["rust_crate_build"]["status"] == "built"
    assert report["rust_crate_build"]["crate_path"] == str(crate_path)
    assert crate_path.exists()

    consumer = tmp_path / "consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "Cargo.toml").write_text(
        f"""
[package]
name = "demo-rust-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
demo_rust_lib = {{ path = {json.dumps(str(crate_path))} }}
""",
        encoding="utf-8",
    )
    (consumer / "src" / "main.rs").write_text(
        """
fn main() {
    let square = demo_rust_lib::demo_app__ops__square(4).unwrap();
    let total = demo_rust_lib::demo_app__ops__sum_squares(vec![1, 2, 3]).unwrap();
    assert_eq!(square, 16);
    assert_eq!(total, 14);
}
""",
        encoding="utf-8",
    )

    cargo = shutil.which("cargo") or "cargo"
    completed = subprocess.run(
        [cargo, "run", "--quiet"],
        cwd=consumer,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
