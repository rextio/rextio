from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_module_init_imports_in_a_clean_interpreter() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", "import rextio.analyzer.module_init"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_module_init_tests_collect_in_isolation() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "tests/analyzer/test_module_init_segments.py",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
