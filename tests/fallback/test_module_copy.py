from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis
from rextio.fallback.module_copy import (
    copy_module_to_fallback,
    fallback_module_name,
    fallback_module_path,
    generated_module_path,
)


def _module(file_path: Path, module_name: str) -> ModuleAnalysis:
    return ModuleAnalysis(module_name=module_name, file_path=str(file_path))


def test_fallback_module_name_prefixes_the_stem(tmp_path: Path) -> None:
    source = tmp_path / "scoring.py"
    source.write_text("x = 1\n", encoding="utf-8")

    assert fallback_module_name(_module(source, "pkg.scoring")) == "_fallback_scoring"


def test_generated_and_fallback_paths_follow_the_package_layout(tmp_path: Path) -> None:
    source = tmp_path / "scoring.py"
    source.write_text("x = 1\n", encoding="utf-8")
    module = _module(source, "pkg.sub.scoring")
    root = tmp_path / "generated"

    generated = generated_module_path(root, module)
    fallback = fallback_module_path(root, module)

    assert generated == root / "pkg" / "sub" / "scoring.py"
    assert fallback == root / "pkg" / "sub" / "_fallback_scoring.py"


def test_copy_module_to_fallback_copies_source(tmp_path: Path) -> None:
    source = tmp_path / "scoring.py"
    source.write_text("VALUE = 42\n", encoding="utf-8")
    module = _module(source, "scoring")
    fallback = fallback_module_path(tmp_path / "generated", module)

    copy_module_to_fallback(module, fallback)

    assert fallback.exists()
    assert fallback.read_text(encoding="utf-8") == "VALUE = 42\n"
