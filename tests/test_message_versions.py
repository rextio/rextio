"""Regression tests: user-visible release-version references are single-sourced.

Every runtime diagnostic, suggestion, CLI help string, config error, target
warning, and init-generated template that names the Rextio release must display
the package version exported by ``rextio.__about__`` rather than a hard-coded
literal. Expectations here derive from ``__version__`` so a release bump keeps
these tests green without edits; the assertions that the stale ``0.1.0`` literal
is absent guard against a message drifting back to a hard-coded version.

Generated artifact/package metadata (Cargo.toml / wheel versions) is a separate
contract and is intentionally not covered here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from rextio.__about__ import __version__
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.init_cmd import DEFAULT_REXTIO_MD
from rextio.cli.main import build_parser
from rextio.config.loader import ConfigError, load_config
from rextio.targets.plan import create_target_spec

# The stale literal these messages used to hard-code. It must never appear in a
# user-visible release-version reference again.
_STALE = "0.1.0"


def _write(root: Path, name: str, contents: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _diagnostic_texts(root: Path) -> list[str]:
    analysis = analyze_project(root)
    texts: list[str] = []
    for diagnostic in analysis.diagnostics:
        texts.append(diagnostic.message)
        if diagnostic.suggestion:
            texts.append(diagnostic.suggestion)
    return texts


def test_analyzer_diagnostics_and_suggestions_use_shared_version(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        """
import rextio

@extra_decorator
@rextio.native
def bad_decorator(x: int) -> int:
    return x

@rextio.native
def bad_arg(x: complex) -> int:
    return 1

@rextio.native
def missing_arg_annotation(x) -> int:
    return 1

@rextio.native
def missing_return_annotation(x: int):
    return mystery(x)

@rextio.native
def uses_genexp(xs: list[int]) -> int:
    return sum(x for x in xs)

@rextio.native
def int_division(a: int, b: int) -> int:
    return a / b

@rextio.native
def boolean_operands(a: int, b: int) -> bool:
    return a and b

@rextio.native
def not_operand(x: int) -> bool:
    return not x
""",
    )

    texts = _diagnostic_texts(tmp_path)
    v = __version__

    expected = {
        f"Use only @rextio.native on {v} native candidates.",
        f"Use a supported {v} scalar or collection type.",
        f"Add a supported {v} type annotation.",
        f"Add a supported {v} return type annotation.",
        f"comprehensions are not supported in {v} native functions",
        f"Keep native candidates inside the supported {v} subset.",
        f"int division is not supported in {v} native functions",
        f"not operator requires bool in {v} native functions, got int",
    }
    missing = sorted(phrase for phrase in expected if phrase not in texts)
    assert missing == [], f"expected version-sourced diagnostic text not emitted: {missing}"

    # A representative message that interpolates the version mid-string.
    assert any(
        text == f"boolean operations require bool operands in {v}, got int" for text in texts
    )

    # No diagnostic text may carry the stale hard-coded release literal.
    stale = sorted({text for text in texts if _STALE in text})
    assert stale == [], f"diagnostic text still hard-codes {_STALE!r}: {stale}"


def test_config_errors_use_shared_version(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "rextio.toml",
        """
[policy]
require_type_hints = false
""",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path)
    assert str(excinfo.value) == f"{__version__} requires [policy] require_type_hints = true"
    assert _STALE not in str(excinfo.value)


def test_config_dynamic_feature_error_uses_shared_version(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "rextio.toml",
        """
[policy]
allow_dynamic_features = true
""",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path)
    assert (
        str(excinfo.value)
        == f"{__version__} does not support [policy] allow_dynamic_features = true"
    )
    assert _STALE not in str(excinfo.value)


def test_target_reserved_option_warning_uses_shared_version(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "rextio.toml",
        """
[target]
version = "stable"
""",
    )
    config = load_config(tmp_path)
    with pytest.warns(RuntimeWarning, match=f"no effect in {re.escape(__version__)}"):
        create_target_spec(config)


def test_cli_help_uses_shared_version(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["check", "--help"])
    check_help = capsys.readouterr().out
    assert f"{__version__} implements rust" in check_help
    assert f"{_STALE} implements rust" not in check_help

    with pytest.raises(SystemExit):
        parser.parse_args(["build", "--help"])
    build_help = capsys.readouterr().out
    assert f"{__version__} supports pyo3 only" in build_help
    assert f"{_STALE} supports pyo3 only" not in build_help


def test_init_template_uses_shared_version() -> None:
    assert f"Rextio {__version__} alpha-stage workflow." in DEFAULT_REXTIO_MD
    assert _STALE not in DEFAULT_REXTIO_MD
