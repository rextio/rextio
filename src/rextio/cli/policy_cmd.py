"""Offline commands for the strict Full C6 owner-policy handoff."""

from __future__ import annotations

from argparse import Namespace
import os
from pathlib import Path

from rextio.build.full_c6_policy_completion import (
    FullC6PolicyCompletionError,
    finalize_full_c6_policy_files,
)
from rextio.build.full_c6_toolchain_support import (
    FullC6ToolchainSupportError,
    bootstrap_full_c6_toolchain_support_lock,
)
from rextio.cli.reporter import Reporter


def run_finalize(args: Namespace) -> int:
    """Finalize one exact bootstrap/completion pair without signing it."""
    reporter = Reporter.from_args(args)
    try:
        bootstrap = _absolute_path(args.bootstrap)
        completion = _absolute_path(args.completion)
        output = _absolute_path(args.output)
        result = finalize_full_c6_policy_files(
            bootstrap_path=bootstrap,
            completion_path=completion,
            output_path=output,
        )
    except FullC6PolicyCompletionError as exc:
        reporter.error("RXT060 Full C6 owner-policy finalization failed.")
        reporter.error(f"Cause: {exc}")
        reporter.error(
            "Suggestion: use the exact canonical bootstrap and completion files, "
            "then choose a new output path or reuse identical output bytes."
        )
        return 1

    data = {**result.to_dict(), "output": str(output)}
    action = "created" if result.created else "reused exact existing bytes"
    reporter.print_result(
        text="\n".join(
            [
                "Rextio policy finalize",
                f"status: {data['status']}",
                f"output: {output}",
                f"result: {action}",
                f"manifest SHA-256: {result.manifest_sha256}",
                "signed: false",
                "distribution authorized: false",
            ]
        ),
        data=data,
    )
    return 0


def run_bootstrap_support_lock(args: Namespace) -> int:
    """Bootstrap one strict host support lock."""
    reporter = Reporter.from_args(args)
    try:
        project_root = _absolute_path(args.project_root)
        output = args.output
        if type(output) is not str:
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output path is invalid"
            )
        result = bootstrap_full_c6_toolchain_support_lock(
            project_root=project_root,
            output=output,
            inherited_environment=dict(os.environ),
        )
    except (FullC6PolicyCompletionError, FullC6ToolchainSupportError) as exc:
        reporter.error("RXT060 Full C6 support-lock bootstrap failed.")
        reporter.error(f"Cause: {exc}")
        reporter.error(
            "Suggestion: use a supported CPython 3.11 host, the exact configured "
            "Python/Cargo toolchain, and a new project-relative output below an "
            "owner-private mode-0700 directory."
        )
        return 1

    data = result.to_dict()
    config = result.config
    reporter.print_result(
        text="\n".join(
            [
                "Rextio policy bootstrap-support-lock",
                f"status: {data['status']}",
                f"result: {result.result}",
                f"target: {result.target}",
                f"manifest roles: {', '.join(result.manifest_roles)}",
                f"root roles: {', '.join(result.root_roles)}",
                f"raw SHA-256: {result.raw_sha256}",
                f"Merkle SHA-256: {result.merkle_sha256}",
                (
                    "config artifact_toolchain_support_lock: "
                    f"{config['artifact_toolchain_support_lock']}"
                ),
                (
                    "config artifact_toolchain_support_lock_sha256: "
                    f"{config['artifact_toolchain_support_lock_sha256']}"
                ),
                "build authorized: false",
                "distribution authorized: false",
            ]
        ),
        data=data,
    )
    return 0


def _absolute_path(value: object) -> Path:
    if type(value) is not str or not value or "\0" in value:
        raise FullC6PolicyCompletionError("Full C6 policy CLI path is invalid")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(candidate))


__all__ = ["run_bootstrap_support_lock", "run_finalize"]
