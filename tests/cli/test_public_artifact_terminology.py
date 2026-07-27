"""Guard user-visible artifact-contract terminology against internal code names."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Callable, Iterator
import inspect
import re
import textwrap

from rextio.analyzer import project_scanner
from rextio.build import full_c6_input_identity
from rextio.build.orchestrator import build_hybrid_artifact
from rextio.cli import build_cmd, policy_cmd
from rextio.cli.main import build_parser
from rextio.config import loader as config_loader
from rextio.source.external import (
    ExternalSourceBuildBlockedError,
    ExternalSourceC5NotImplementedError,
    ExternalSourcePlan,
)
from rextio.source import source_lock_v2


_INTERNAL_MILESTONE = re.compile(
    r"full[-_ ]?c6|(?<![A-Za-z0-9_])c[56](?:\.[0-9]+)?(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def _string_literals(owner: Callable[..., object]) -> Iterator[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(owner)))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def _parser_help(parser: argparse.ArgumentParser) -> Iterator[str]:
    yield parser.format_help()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            for child in choices.values():
                if isinstance(child, argparse.ArgumentParser):
                    yield from _parser_help(child)


def _raised_literal_fragments(module: object) -> Iterator[str]:
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
            continue
        for argument in node.exc.args:
            for child in ast.walk(argument):
                if isinstance(child, ast.Constant) and isinstance(
                    child.value,
                    str,
                ):
                    yield child.value


def test_public_cli_help_and_output_literals_hide_internal_milestones() -> None:
    public_owners: tuple[Callable[..., object], ...] = (
        build_parser,
        build_cmd._report_external_source_build_blocked,
        build_cmd._report_full_c6_pipeline_failure,
        build_cmd._report_full_c6_preanalysis_failure,
        build_cmd._report_full_c6_projection_failure,
        build_cmd._report_full_c6_pipeline_success,
        build_cmd._run_full_c6_cli_lifecycle,
        policy_cmd.run_finalize,
        policy_cmd.run_bootstrap_support_lock,
        build_hybrid_artifact,
        ExternalSourcePlan.to_dict,
        ExternalSourceBuildBlockedError.__init__,
        ExternalSourceC5NotImplementedError.__init__,
    )
    current_output = "\n".join(
        [
            *_parser_help(build_parser()),
            *(
                literal
                for owner in public_owners
                for literal in _string_literals(owner)
            ),
        ]
    )

    assert _INTERNAL_MILESTONE.search(current_output) is None
    assert "artifact-candidate" in current_output
    assert "artifact_contract" in current_output
    assert "artifact-policy-bootstrap-required" in current_output
    assert "artifact-signing-required" in current_output
    assert "artifact-published" in current_output


def test_current_public_exception_and_reason_literals_hide_internal_milestones() -> None:
    public_error_modules = (
        config_loader,
        project_scanner,
        full_c6_input_identity,
        source_lock_v2,
    )
    current_errors = "\n".join(
        [
            *(
                fragment
                for module in public_error_modules
                for fragment in _raised_literal_fragments(module)
            ),
            *(
                message
                for _error_type, message in build_cmd._FULL_C6_FAILURE_REASON_CODES
            ),
        ]
    )

    assert _INTERNAL_MILESTONE.search(current_errors) is None
    assert "artifact build" in current_errors
    assert "external-source plan" in current_errors
