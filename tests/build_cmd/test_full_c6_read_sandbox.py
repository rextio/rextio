from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from rextio.build.full_c6_read_sandbox import (
    FullC6ReadSandboxError,
    MacOSPlatformAnchor,
    SandboxPathRule,
    UnavailableMacOSPlatformAnchorProvider,
    build_full_c6_sandbox_plan,
    capture_active_macos_platform_anchor,
    prepare_full_c6_sandbox_launch,
)
from rextio.build import full_c6_read_sandbox as sandbox_module


_SHA = "a" * 64


def _rules(tmp_path: Path) -> tuple[SandboxPathRule, ...]:
    inputs = tmp_path / "inputs"
    outputs = tmp_path / "outputs"
    tool = tmp_path / "tool"
    inputs.mkdir()
    outputs.mkdir()
    tool.write_bytes(b"tool")
    tool.chmod(0o755)
    return (
        SandboxPathRule(inputs, "read", "bound-input"),
        SandboxPathRule(outputs, "read-write", "private-output"),
        SandboxPathRule(tool, "read-execute", "bound-tool"),
    )


def test_plan_is_canonical_and_path_private(tmp_path: Path) -> None:
    rules = _rules(tmp_path)
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=reversed(rules),
        platform_anchor_sha256=_SHA,
    )

    assert plan.engine == "landlock-v3"
    assert tuple(rule.path for rule in plan.rules) == tuple(
        sorted((rule.path for rule in rules), key=os.fsencode)
    )
    assert str(tmp_path) not in plan.digest


def test_plan_rejects_duplicate_or_wrong_engine(tmp_path: Path) -> None:
    rule = _rules(tmp_path)[0]
    with pytest.raises(FullC6ReadSandboxError, match="canonical and unique"):
        build_full_c6_sandbox_plan(
            target_triple="x86_64-unknown-linux-gnu",
            rules=(rule, rule),
            platform_anchor_sha256=_SHA,
        )


def test_plan_rejects_unknown_target(tmp_path: Path) -> None:
    with pytest.raises(FullC6ReadSandboxError, match="unsupported"):
        build_full_c6_sandbox_plan(
            target_triple="aarch64-unknown-linux-gnu",
            rules=_rules(tmp_path),
            platform_anchor_sha256=_SHA,
        )


def test_landlock_missing_or_old_abi_fails_closed(tmp_path: Path) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )

    with pytest.raises(FullC6ReadSandboxError, match="ABI 3"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("cargo", "build"),
            landlock_syscall=lambda *_args: 2,
            landlock_prctl=lambda *_args: 0,
            require_single_thread=False,
        )


def test_landlock_launch_enforces_rules_before_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    calls: list[tuple[object, ...]] = []
    next_fd = 70

    def syscall(*args: object) -> int:
        nonlocal next_fd
        calls.append(args)
        number = args[0]
        if number == 444 and len(args) == 4 and getattr(args[2], "value", None) == 0:
            return 3
        if number == 444:
            return 60
        return 0

    opened: list[str] = []
    closed: list[int] = []

    def fake_open(path: str, flags: int) -> int:
        nonlocal next_fd
        del flags
        opened.append(path)
        next_fd += 1
        return next_fd

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "close", closed.append)
    prctl_calls: list[tuple[object, ...]] = []

    def prctl(*args: object) -> int:
        prctl_calls.append(args)
        return 0

    launch = prepare_full_c6_sandbox_launch(
        plan,
        ("cargo", "build"),
        landlock_syscall=syscall,
        landlock_prctl=prctl,
        require_single_thread=False,
    )
    assert launch.command == ("cargo", "build")
    assert launch.preexec_fn is not None
    launch.preexec_fn()

    assert opened == [str(rule.path) for rule in plan.rules]
    assert prctl_calls[0] == (38, 1, 0, 0, 0)
    assert prctl_calls[1][0:2] == (22, 2)
    assert 60 in closed
    assert sum(call[0] == 445 for call in calls) == len(plan.rules)
    assert calls[-1][:2] == (446, 60)


def test_landlock_required_device_never_receives_truncate() -> None:
    read_write = sandbox_module._landlock_access(
        "read-write", directory=False, character_device=True
    )
    regular_write = sandbox_module._landlock_access(
        "read-write", directory=False, character_device=False
    )

    assert read_write == (1 << 1) | (1 << 2)
    assert not read_write & (1 << 14)
    assert regular_write & (1 << 14)


def test_rule_root_symlink_and_unexpected_device_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=(SandboxPathRule(linked, "read", "bound-input"),),
        platform_anchor_sha256=_SHA,
    )
    with pytest.raises(FullC6ReadSandboxError, match="type is unsafe"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("cargo", "build"),
            landlock_syscall=lambda *_args: 3,
            landlock_prctl=lambda *_args: 0,
            require_single_thread=False,
        )


class _AnchorProvider:
    def __init__(self) -> None:
        self.seen: MacOSPlatformAnchor | None = None

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        self.seen = expected


def test_macos_requires_verified_anchor_and_emits_deterministic_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _rules(tmp_path)
    anchor = MacOSPlatformAnchor(
        authenticated_snapshot_id="b" * 64,
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=rules,
        platform_anchor_sha256=anchor.digest,
    )
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    monkeypatch.setattr(Path, "is_absolute", lambda self: True)
    monkeypatch.setattr(
        os,
        "lstat",
        lambda path: os.stat_result((stat.S_IFREG | 0o755,) + (0,) * 9),
    )
    monkeypatch.setattr(os, "access", lambda path, mode: True)
    provider = _AnchorProvider()
    compiled: list[tuple[Path, str]] = []

    launch = prepare_full_c6_sandbox_launch(
        plan,
        ("cargo", "build"),
        macos_anchor=anchor,
        macos_anchor_provider=provider,
        sandbox_exec=sandbox_exec,
        macos_profile_compiler=lambda path, profile: compiled.append((path, profile)),
    )

    assert provider.seen == anchor
    assert compiled == [(sandbox_exec, launch.command[2])]
    assert launch.command[:3] == ("/usr/bin/sandbox-exec", "-p", launch.command[2])
    assert launch.command[-3:] == ("--", "cargo", "build")
    assert hashlib.sha256(launch.command[2].encode()).hexdigest() == launch.profile_sha256
    assert "(deny default)" in launch.command[2]
    assert "(deny network*)" in launch.command[2]
    assert '(import "system.sb")' in launch.command[2]
    assert "(deny mach-lookup)" in launch.command[2]
    assert '(subpath "/private/var")' in launch.command[2]
    assert str(tmp_path / "inputs") in launch.command[2]


def test_macos_default_anchor_provider_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = MacOSPlatformAnchor(
        authenticated_snapshot_id="b" * 64,
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=_rules(tmp_path),
        platform_anchor_sha256=anchor.digest,
    )
    monkeypatch.setattr(Path, "is_absolute", lambda self: True)
    with pytest.raises(FullC6ReadSandboxError, match="APFS/SSV"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("cargo", "build"),
            macos_anchor=anchor,
            macos_anchor_provider=UnavailableMacOSPlatformAnchorProvider(),
        )


def test_macos_anchor_change_is_rejected_before_launch(tmp_path: Path) -> None:
    anchor = MacOSPlatformAnchor(
        authenticated_snapshot_id="b" * 64,
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    changed = MacOSPlatformAnchor(
        authenticated_snapshot_id="c" * 64,
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=_rules(tmp_path),
        platform_anchor_sha256=anchor.digest,
    )
    with pytest.raises(FullC6ReadSandboxError, match="differs"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("cargo", "build"),
            macos_anchor=changed,
            macos_anchor_provider=_AnchorProvider(),
        )


@pytest.mark.skipif(
    sys.platform != "darwin" or os.uname().machine.lower() not in {"arm64", "aarch64"},
    reason="real sandbox-exec/SSV gate is macOS arm64 only",
)
def test_real_macos_anchor_and_sandbox_exec_enforce_profile() -> None:
    anchor = capture_active_macos_platform_anchor()
    rule = SandboxPathRule(Path("/usr/bin/true"), "read-execute", "bound-tool")
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=(rule,),
        platform_anchor_sha256=anchor.digest,
    )

    launch = prepare_full_c6_sandbox_launch(
        plan,
        ("/usr/bin/true",),
        macos_anchor=anchor,
    )
    completed = subprocess.run(
        launch.command,
        check=False,
        capture_output=True,
        text=True,
        timeout=10.0,
        env={},
    )

    assert completed.returncode == 0, completed.stderr
