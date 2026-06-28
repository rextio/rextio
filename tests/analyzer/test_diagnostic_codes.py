from __future__ import annotations

import ast
import re
from pathlib import Path

from rextio.analyzer.diagnostic_codes import DIAGNOSTIC_CODES

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "rextio"
_CODE_PATTERN = re.compile(r"RXT\d{3}")


def _emitted_codes() -> set[str]:
    # Collect codes from string *literals* only (via AST), so codes mentioned in
    # comments don't count as real emissions and produce false positives.
    codes: set[str] = set()
    for path in _SRC_ROOT.rglob("*.py"):
        if path.name == "diagnostic_codes.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                codes.update(_CODE_PATTERN.findall(node.value))
    return codes


def test_every_emitted_code_is_registered() -> None:
    emitted = _emitted_codes()
    unregistered = sorted(code for code in emitted if code not in DIAGNOSTIC_CODES)
    assert unregistered == [], f"diagnostic codes missing from the registry: {unregistered}"


def test_registry_has_no_stale_codes() -> None:
    # Every registered code should still be emitted somewhere; otherwise the
    # registry has drifted from the implementation.
    emitted = _emitted_codes()
    stale = sorted(code for code in DIAGNOSTIC_CODES if code not in emitted)
    assert stale == [], f"registered codes no longer emitted anywhere: {stale}"
