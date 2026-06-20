from __future__ import annotations

import shutil
from argparse import Namespace
from pathlib import Path


GENERATED_PATHS = ("build", "generated", "reports")


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    rextio_dir = project_root / ".rextio"
    print("Rextio clean")
    for name in GENERATED_PATHS:
        path = rextio_dir / name
        if path.exists():
            shutil.rmtree(path)
            print(f"  removed {path}")
        else:
            print(f"  skipped {path} (not found)")
    return 0
