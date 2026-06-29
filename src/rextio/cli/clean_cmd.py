"""The ``rextio clean`` command."""

from __future__ import annotations

import shutil
from argparse import Namespace
from pathlib import Path

from rextio.cli.reporter import Reporter


GENERATED_PATHS = ("build", "generated", "reports")


def run(args: Namespace) -> int:
    """Run the clean command; return the process exit code."""
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    rextio_dir = project_root / ".rextio"
    lines = ["Rextio clean"]
    removed: list[str] = []
    skipped: list[str] = []
    for name in GENERATED_PATHS:
        path = rextio_dir / name
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
            lines.append(f"  removed {path}")
        else:
            skipped.append(str(path))
            lines.append(f"  skipped {path} (not found)")
    reporter.print_result(
        text="\n".join(lines),
        data={"status": "cleaned", "removed": removed, "skipped": skipped},
    )
    return 0
