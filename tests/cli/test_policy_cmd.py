"""CLI tests for strict offline Full C6 owner-policy finalization."""

from __future__ import annotations

import json
from pathlib import Path
import runpy

import pytest

from rextio.build.full_c6_toolchain_support import (
    FullC6ToolchainSupportBootstrapResult,
    FullC6ToolchainSupportError,
)
from rextio.cli import policy_cmd
from rextio.cli.main import build_parser, main


_BUILD_TESTS = Path(__file__).parents[1] / "build_cmd"
_BOOTSTRAP = runpy.run_path(
    str(_BUILD_TESTS / "test_full_c6_policy_bootstrap.py")
)
_COMPLETION = runpy.run_path(
    str(_BUILD_TESTS / "test_full_c6_policy_completion.py")
)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    bootstrap = _BOOTSTRAP["_request"](tmp_path)
    completion = _COMPLETION["_completion"](bootstrap)
    input_dir = tmp_path / "inputs"
    output_dir = tmp_path / "output"
    input_dir.mkdir(mode=0o700)
    output_dir.mkdir(mode=0o700)
    bootstrap_path = input_dir / "bootstrap.json"
    completion_path = input_dir / "completion.json"
    output_path = output_dir / "manifest.json"
    bootstrap_path.write_bytes(bootstrap.to_bytes())
    completion_path.write_bytes(completion.to_bytes())
    bootstrap_path.chmod(0o600)
    completion_path.chmod(0o600)
    return bootstrap_path, completion_path, output_path


def test_policy_finalize_parser_contract() -> None:
    args = build_parser().parse_args(
        [
            "policy",
            "finalize",
            "--bootstrap",
            "bootstrap.json",
            "--completion",
            "completion.json",
            "--output",
            "manifest.json",
            "--format",
            "json",
        ]
    )

    assert args.policy_command == "finalize"
    assert args.bootstrap == "bootstrap.json"
    assert args.completion == "completion.json"
    assert args.output == "manifest.json"
    assert args.format == "json"


def test_policy_bootstrap_support_lock_parser_contract() -> None:
    args = build_parser().parse_args(
        [
            "policy",
            "bootstrap-support-lock",
            "--project-root",
            "project",
            "--output",
            "authority/rextio.toolchain-support.lock.json",
            "--format",
            "json",
        ]
    )

    assert args.policy_command == "bootstrap-support-lock"
    assert args.project_root == "project"
    assert args.output == "authority/rextio.toolchain-support.lock.json"
    assert args.format == "json"


def test_policy_finalize_json_creates_and_exactly_reuses(
    tmp_path: Path,
    capsys,
) -> None:
    bootstrap, completion, output = _inputs(tmp_path)
    argv = [
        "policy",
        "finalize",
        "--bootstrap",
        str(bootstrap),
        "--completion",
        str(completion),
        "--output",
        str(output),
        "--format",
        "json",
    ]

    assert main(argv) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "full-c6-policy-finalized"
    assert created["created"] is True
    assert created["output"] == str(output)
    assert created["signed"] is False
    assert created["distribution_authorized"] is False
    assert output.is_file()

    assert main(argv) == 0
    reused = json.loads(capsys.readouterr().out)
    assert reused["created"] is False
    assert reused["manifest_sha256"] == created["manifest_sha256"]


def test_policy_finalize_text_is_explicitly_non_authorizing(
    tmp_path: Path,
    capsys,
) -> None:
    bootstrap, completion, output = _inputs(tmp_path)

    assert main(
        [
            "policy",
            "finalize",
            "--bootstrap",
            str(bootstrap),
            "--completion",
            str(completion),
            "--output",
            str(output),
        ]
    ) == 0
    captured = capsys.readouterr()
    assert "Rextio policy finalize" in captured.out
    assert "signed: false" in captured.out
    assert "distribution authorized: false" in captured.out
    assert captured.err == ""


def test_policy_finalize_failure_uses_stderr_and_no_result_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    bootstrap, completion, output = _inputs(tmp_path)
    completion.write_bytes(b"{}")

    assert main(
        [
            "policy",
            "finalize",
            "--bootstrap",
            str(bootstrap),
            "--completion",
            str(completion),
            "--output",
            str(output),
            "--format",
            "json",
        ]
    ) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "RXT060 Full C6 owner-policy finalization failed" in captured.err
    assert not output.exists()


def test_policy_bootstrap_support_lock_json_is_path_private_and_non_authorizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    result = FullC6ToolchainSupportBootstrapResult(
        result="created",
        target="x86_64-unknown-linux-gnu",
        manifest_roles=(
            "landlock-launcher",
            "linux-ar",
            "linux-binutils-ld",
            "linux-bwrap",
            "linux-dynamic-loader",
            "linux-ranlib",
            "python-runtime-library",
            "rustup-components",
        ),
        root_roles=(
            "linux-gcc-support",
            "linux-python-library-support",
            "linux-runtime-support",
            "python-runtime",
            "rust-sysroot",
        ),
        raw_sha256="a" * 64,
        merkle_sha256="b" * 64,
        output="authority/support.json",
    )
    observed: dict[str, object] = {}

    def bootstrap(**kwargs: object) -> FullC6ToolchainSupportBootstrapResult:
        observed.update(kwargs)
        return result

    monkeypatch.setattr(
        policy_cmd,
        "bootstrap_full_c6_toolchain_support_lock",
        bootstrap,
        raising=False,
    )

    assert main(
        [
            "policy",
            "bootstrap-support-lock",
            "--project-root",
            str(tmp_path),
            "--output",
            "authority/support.json",
            "--format",
            "json",
        ]
    ) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data == result.to_dict()
    assert captured.err == ""
    assert observed["project_root"] == tmp_path
    assert observed["output"] == "authority/support.json"
    assert isinstance(observed["inherited_environment"], dict)
    assert str(tmp_path) not in captured.out


def test_policy_bootstrap_support_lock_text_is_explicitly_non_authorizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    result = FullC6ToolchainSupportBootstrapResult(
        result="reused",
        target="aarch64-apple-darwin",
        manifest_roles=(
            "macos-sandbox-dyld-profile",
            "macos-sandbox-system-profile",
            "python-runtime-library",
            "rustup-components",
            "xcode-ar",
            "xcode-clang",
            "xcode-ld",
            "xcode-ranlib",
            "xcode-sdk-settings",
            "xcode-version-plist",
        ),
        root_roles=(
            "python-runtime",
            "rust-sysroot",
            "xcode-clang-resource",
            "xcode-sdk",
        ),
        raw_sha256="c" * 64,
        merkle_sha256="d" * 64,
        output="authority/support.json",
    )
    monkeypatch.setattr(
        policy_cmd,
        "bootstrap_full_c6_toolchain_support_lock",
        lambda **_kwargs: result,
    )

    assert main(
        [
            "policy",
            "bootstrap-support-lock",
            "--project-root",
            str(tmp_path),
            "--output",
            "authority/support.json",
        ]
    ) == 0
    captured = capsys.readouterr()
    assert "result: reused" in captured.out
    assert "build authorized: false" in captured.out
    assert "distribution authorized: false" in captured.out
    assert str(tmp_path) not in captured.out
    assert captured.err == ""


def test_policy_bootstrap_support_lock_failure_is_stderr_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    def reject(**_kwargs: object) -> object:
        raise FullC6ToolchainSupportError("unsupported Full C6 host")

    monkeypatch.setattr(
        policy_cmd,
        "bootstrap_full_c6_toolchain_support_lock",
        reject,
    )

    assert main(
        [
            "policy",
            "bootstrap-support-lock",
            "--project-root",
            str(tmp_path),
            "--output",
            "authority/support.json",
            "--format",
            "json",
        ]
    ) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "RXT060 Full C6 support-lock bootstrap failed" in captured.err
    assert "unsupported Full C6 host" in captured.err
