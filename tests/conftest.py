from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def fake_cargo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(
        """#!/usr/bin/env python3
import sys
import tomllib
from pathlib import Path

release = Path.cwd() / "target" / "release"
release.mkdir(parents=True, exist_ok=True)
for name in (
    "lib_rextio_native.dylib",
    "lib_rextio_native.so",
    "_rextio_native.dll",
    "_rextio_native.pyd",
):
    (release / name).write_bytes(b"fake native library")
if "--manifest-path" in sys.argv:
    manifest = Path(sys.argv[sys.argv.index("--manifest-path") + 1])
    if manifest.exists():
        package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
        crate_name = str(package.get("name", "rextio_generated_rust")).replace("-", "_")
        (release / f"lib{crate_name}.rlib").write_bytes(b"fake rust library")
""",
        encoding="utf-8",
    )
    cargo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return cargo


@pytest.fixture
def fake_maturin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "fake-maturin-bin"
    bin_dir.mkdir()
    maturin = bin_dir / "maturin"
    maturin.write_text(
        """#!/usr/bin/env python3
import sys
import zipfile
from pathlib import Path

out = Path(sys.argv[sys.argv.index("--out") + 1])
out.mkdir(parents=True, exist_ok=True)
wheel = out / "rextio_generated_native-0.1.0-py3-none-any.whl"
with zipfile.ZipFile(wheel, "w") as archive:
    archive.writestr("_rextio_native.cpython-311-darwin.so", b"fake native library")
""",
        encoding="utf-8",
    )
    maturin.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return maturin


@pytest.fixture
def fake_nuitka(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "fake-nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        """#!/usr/bin/env python3
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("2.4.8")
    sys.exit(0)
source = Path(args[args.index("--module") + 1])
output_arg = next(arg for arg in args if arg == "--output-dir" or arg.startswith("--output-dir="))
if output_arg == "--output-dir":
    out = Path(args[args.index("--output-dir") + 1])
else:
    out = Path(output_arg.split("=", 1)[1])
out.mkdir(parents=True, exist_ok=True)
(out / f"{source.stem}.cpython-311-darwin.so").write_bytes(b"fake nuitka module")
log = Path(__file__).with_name("nuitka.log")
with log.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(args) + "\\n")
""",
        encoding="utf-8",
    )
    nuitka.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return nuitka
