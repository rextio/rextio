from __future__ import annotations

from argparse import Namespace
from pathlib import Path

DEFAULT_CONFIG = """[build]
native_backend = "rust"
fallback_backend = "cpython"
fallback_threshold = 1000

[rust]
binding = "pyo3"
build_tool = "maturin"
importable = false
crate_name = "rextio_generated_rust"

[fallback]
nuitka = "experimental"

[target]
# version = "stable"

[target.build_options]
# profile = "release"

[plugins]
enabled = []

[imports]
default_external_policy = "fallback"

[imports.packages]
# "some_pkg" = { policy = "try-native", max_depth = 1 }
# "known_pkg" = { policy = "plugin", plugin = "known-rust" }

[executable]
# entrypoint = "myapp.cli:main"
# name = "myapp"
backend = "zipapp"
nuitka_mode = "standalone"

[policy]
native_marker = "auto"
require_type_hints = true
allow_dynamic_features = false
boundary_warnings = true
native_top_level = false
"""

DEFAULT_REXTIO_MD = """# Rextio Project

This project is configured for the Rextio 0.1.0 alpha-stage workflow.

Rextio discovers eligible typed Python functions automatically. To require
explicit markers, set `[policy] native_marker = "decorator"` and mark functions
with `@rextio.native`.

Then run:

```text
rextio check
rextio build --fallback=cpython
```
"""

DEFAULT_IGNORE = """.rextio/
dist/
build/
__pycache__/
*.pyc
"""


def _write_file(path: Path, contents: str, force: bool) -> str:
    if path.exists() and not force:
        return f"skipped {path.name} (already exists)"
    path.write_text(contents, encoding="utf-8")
    return f"created {path.name}"


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    project_root.mkdir(parents=True, exist_ok=True)
    messages = [
        _write_file(project_root / "rextio.toml", DEFAULT_CONFIG, args.force),
        _write_file(project_root / "REXTIO.md", DEFAULT_REXTIO_MD, args.force),
        _write_file(project_root / ".rextioignore", DEFAULT_IGNORE, args.force),
    ]
    print("Rextio init")
    for message in messages:
        print(f"  {message}")
    return 0
