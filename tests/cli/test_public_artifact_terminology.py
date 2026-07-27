"""Guard user-visible artifact-contract terminology against internal code names."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Callable, Iterator
import inspect
import re
import textwrap

from rextio.build.orchestrator import build_hybrid_artifact
from rextio.cli import build_cmd, policy_cmd
from rextio.cli.main import build_parser
from rextio.source.external import (
    ExternalSourceBuildBlockedError,
    ExternalSourceC5NotImplementedError,
    ExternalSourcePlan,
)


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
