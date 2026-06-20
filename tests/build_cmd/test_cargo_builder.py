from __future__ import annotations

import os
import sys
from pathlib import Path

from rextio.build.cargo_builder import build_native_extension_with_cargo


def test_cargo_builder_retries_offline_after_registry_network_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.txt"
    cargo = bin_dir / "cargo"
    cargo.write_text(
        f"""#!{sys.executable}
import sys
from pathlib import Path

calls = Path({str(calls)!r})
count = int(calls.read_text(encoding="utf-8")) if calls.exists() else 0
calls.write_text(str(count + 1), encoding="utf-8")

if "--offline" not in sys.argv:
    print("download of config.json failed", file=sys.stderr)
    sys.exit(1)

release = Path.cwd() / "target" / "release"
release.mkdir(parents=True, exist_ok=True)
(release / "lib_rextio_native.dylib").write_bytes(b"native")
""",
        encoding="utf-8",
    )
    cargo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    rust_dir = tmp_path / "rust"
    python_dir = tmp_path / "python"
    rust_dir.mkdir()
    cargo_toml = '[package]\nname = "demo"\nversion = "0.1.0"\n'
    (rust_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")

    result = build_native_extension_with_cargo(rust_dir, python_dir)

    assert result.status == "built"
    assert result.command[:3] == [str(cargo), "build", "--release"]
    assert "--offline" in result.command
    assert calls.read_text(encoding="utf-8") == "2"
    assert Path(result.installed_path or "").exists()
