from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from collections.abc import Iterator

import pytest

from rextio.build.full_c6_read_sandbox import (
    FullC6ReadSandboxError,
    FullC6ReadSandboxPlan,
    FullC6SandboxLaunch,
    MacOSPlatformAnchor,
    SandboxPathRule,
    UnavailableMacOSPlatformAnchorProvider,
    build_full_c6_sandbox_plan,
    capture_active_macos_platform_anchor,
    linux_full_c6_seccomp_program,
    prepare_full_c6_sandbox_launch,
)
from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_LAUNCHER,
    FULL_C6_LINUX_PYTHON,
    expected_linux_pyo3_environment_signature,
)
from rextio.build import full_c6_read_sandbox as sandbox_module


_SHA = "a" * 64


def _rules(tmp_path: Path) -> tuple[SandboxPathRule, ...]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = tmp_path / "project"
    build = tmp_path / "build"
    cargo = tmp_path / "cargo"
    python = tmp_path / "python3.11"
    stdlib = tmp_path / "python-stdlib"
    launcher = tmp_path / "full_c6_linux_launcher.py"
    runtime = tmp_path / "runtime-libs"
    loader = tmp_path / "ld-linux-x86-64.so.2"
    project.mkdir()
    build.mkdir()
    (stdlib / "lib-dynload").mkdir(parents=True)
    runtime.mkdir()
    cargo.write_bytes(b"cargo")
    cargo.chmod(0o755)
    python.write_bytes(b"python")
    python.chmod(0o755)
    launcher.write_bytes(b"launcher")
    loader.write_bytes(b"loader")
    loader.chmod(0o755)
    return (
        SandboxPathRule(project, "read", "project-root"),
        SandboxPathRule(build, "read-write", "build-root"),
        SandboxPathRule(cargo, "read-execute", "toolchain-cargo"),
        SandboxPathRule(python, "read-execute", "toolchain-python311"),
        SandboxPathRule(stdlib, "read", "toolchain-python311-stdlib"),
        SandboxPathRule(launcher, "read", "support-landlock-launcher"),
        SandboxPathRule(runtime, "read", "support-runtime-libs"),
        SandboxPathRule(loader, "read-execute", "runtime-loader-mirror"),
    )


def _macos_rules(tmp_path: Path) -> tuple[SandboxPathRule, ...]:
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


def _environment() -> dict[str, str]:
    return {
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": "/rextio/build/target",
        "HOME": "/rextio/build/home",
        "LANG": "C",
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": "/rextio/support/runtime-libs",
        "PATH": "/rextio/toolchain/bin:/rextio/toolchain",
        "PYO3_CONFIG_FILE": "/rextio/build/rextio.pyo3-config.txt",
        "PYO3_ENVIRONMENT_SIGNATURE": expected_linux_pyo3_environment_signature(),
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }


@pytest.fixture
def seccomp_fd(tmp_path: Path) -> Iterator[int]:
    path = tmp_path / "seccomp.bpf"
    path.write_bytes(linux_full_c6_seccomp_program())
    descriptor = os.open(path, os.O_RDONLY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _bwrap(tmp_path: Path) -> Path:
    path = tmp_path / "bwrap"
    path.write_bytes(b"fixture-bwrap")
    path.chmod(0o755)
    return path


def test_plan_is_canonical_and_path_private(tmp_path: Path) -> None:
    rules = _rules(tmp_path)
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=tuple(reversed(rules)),
        platform_anchor_sha256=_SHA,
    )

    assert plan.engine == "linux-bwrap-landlock-v1"
    assert tuple(rule.path for rule in plan.rules) == tuple(
        rule.path
        for rule in sorted(
            rules,
            key=lambda item: (
                item.logical_role,
                item.access,
                os.fsencode(item.path),
            ),
        )
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


def _prepare_linux(
    plan: FullC6ReadSandboxPlan,
    *,
    bwrap: Path,
    seccomp_fd: int,
    environment: dict[str, str] | None = None,
    bwrap_digest: str = "b" * 64,
) -> FullC6SandboxLaunch:
    return prepare_full_c6_sandbox_launch(
        plan,
        ("/rextio/toolchain/cargo", "build"),
        bubblewrap=bwrap,
        bubblewrap_verifier=lambda _path: bwrap_digest,
        linux_seccomp_fd=seccomp_fd,
        linux_payload_environment=(
            _environment() if environment is None else environment
        ),
    )


def test_linux_launch_uses_bwrap_then_isolated_post_namespace_launcher(
    tmp_path: Path, seccomp_fd: int
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    launch = _prepare_linux(
        plan,
        bwrap=bwrap,
        seccomp_fd=seccomp_fd,
    )
    assert launch.command[0] == str(bwrap)
    assert launch.command[1:9] == (
        "--unshare-all",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--new-session",
        "--die-with-parent",
        "--clearenv",
    )
    assert launch.command[-10:] == (
        FULL_C6_LINUX_PYTHON,
        "-I",
        "-B",
        "-S",
        FULL_C6_LINUX_LAUNCHER,
        "--environment-sha256",
        launch.command[-4],
        "--",
        "/rextio/toolchain/cargo",
        "build",
    )
    assert launch.command[-13:-11] == ("--seccomp", str(seccomp_fd))
    assert launch.command[-11] == "--"
    assert launch.pass_fds == (seccomp_fd,)
    assert launch.preexec_fn is None


def test_linux_command_has_exact_mapping_order_and_launcher_support_is_hidden(
    tmp_path: Path, seccomp_fd: int
) -> None:
    rules = (*_rules(tmp_path),)
    launcher = tmp_path / "launcher-libs"
    launcher.mkdir()
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=(
            *rules,
            SandboxPathRule(
                launcher, "read-execute", "launcher-support-bwrap-libs"
            ),
        ),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    launch = prepare_full_c6_sandbox_launch(
        plan,
        ("/rextio/toolchain/cargo", "build"),
        bubblewrap=bwrap,
        bubblewrap_verifier=lambda _path: "b" * 64,
        linux_seccomp_fd=seccomp_fd,
        linux_payload_environment=_environment(),
    )

    command = launch.command
    setenv_rows = [
        (command[index + 1], command[index + 2])
        for index, value in enumerate(command)
        if value == "--setenv"
    ]
    assert setenv_rows == sorted(_environment().items())
    proc_index = command.index("--proc")
    assert command[proc_index : proc_index + 6] == (
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    )
    dir_index = proc_index + 6
    assert command[dir_index : dir_index + 14] == (
        "--dir",
        "/rextio",
        "--dir",
        "/rextio/toolchain",
        "--dir",
        "/rextio/toolchain/bin",
        "--dir",
        "/rextio/toolchain/lib",
        "--dir",
        "/rextio/support",
        "--dir",
        "/rextio/support/rextio",
        "--dir",
        "/lib64",
    )
    expected_mappings = (
        "--ro-bind",
        str(tmp_path / "project"),
        "/rextio/project",
        "--bind",
        str(tmp_path / "build"),
        "/rextio/build",
        "--ro-bind",
        str(tmp_path / "python3.11"),
        "/rextio/toolchain/bin/python3.11",
        "--ro-bind",
        str(tmp_path / "cargo"),
        "/rextio/toolchain/cargo",
        "--ro-bind",
        str(tmp_path / "python-stdlib"),
        "/rextio/toolchain/lib/python3.11",
        "--ro-bind",
        str(tmp_path / "full_c6_linux_launcher.py"),
        "/rextio/support/rextio/full_c6_linux_launcher.py",
        "--ro-bind",
        str(tmp_path / "runtime-libs"),
        "/rextio/support/runtime-libs",
        "--ro-bind",
        str(tmp_path / "ld-linux-x86-64.so.2"),
        "/lib64/ld-linux-x86-64.so.2",
    )
    mappings_index = dir_index + 14
    assert command[mappings_index : mappings_index + len(expected_mappings)] == expected_mappings
    tail_index = mappings_index + len(expected_mappings)
    assert command[tail_index : tail_index + 10] == (
        "--dir",
        "/rextio/build/home",
        "--dir",
        "/rextio/build/target",
        "--chdir",
        "/rextio/project",
        "--seccomp",
        str(seccomp_fd),
        "--",
        FULL_C6_LINUX_PYTHON,
    )
    assert str(launcher) not in command


def test_linux_requires_exact_caller_owned_seccomp_filter(
    tmp_path: Path,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    with pytest.raises(FullC6ReadSandboxError, match="caller-owned"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("/rextio/toolchain/cargo",),
            bubblewrap=bwrap,
            bubblewrap_verifier=lambda _path: "b" * 64,
            linux_payload_environment=_environment(),
        )

    wrong = tmp_path / "wrong.bpf"
    wrong.write_bytes(linux_full_c6_seccomp_program() + b"x")
    descriptor = os.open(wrong, os.O_RDONLY)
    try:
        with pytest.raises(FullC6ReadSandboxError, match="exact filter"):
            prepare_full_c6_sandbox_launch(
                plan,
                ("/rextio/toolchain/cargo",),
                bubblewrap=bwrap,
                bubblewrap_verifier=lambda _path: "b" * 64,
                linux_seccomp_fd=descriptor,
                linux_payload_environment=_environment(),
            )
    finally:
        os.close(descriptor)


def test_linux_seccomp_filter_rejects_x32_network_and_ipc_syscalls() -> None:
    rows = tuple(
        struct.iter_unpack("=HBBI", linux_full_c6_seccomp_program())
    )

    assert (0x35, 0, 1, 0x40000000) in rows
    assert (0x15, 0, 1, 41) in rows  # socket
    assert (0x15, 0, 1, 29) in rows  # shmget
    assert (0x15, 0, 1, 240) in rows  # mq_open
    assert (0x15, 0, 1, 425) in rows  # io_uring_setup


def test_linux_rejects_nonzero_seccomp_offset(
    tmp_path: Path,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    path = tmp_path / "seccomp.bpf"
    path.write_bytes(linux_full_c6_seccomp_program())
    descriptor = os.open(path, os.O_RDONLY)
    os.lseek(descriptor, 8, os.SEEK_SET)
    try:
        with pytest.raises(FullC6ReadSandboxError, match="exact filter"):
            prepare_full_c6_sandbox_launch(
                plan,
                ("/rextio/toolchain/cargo",),
                bubblewrap=_bwrap(tmp_path),
                bubblewrap_verifier=lambda _path: "b" * 64,
                linux_seccomp_fd=descriptor,
                linux_payload_environment=_environment(),
            )
    finally:
        os.close(descriptor)


def test_linux_profile_binds_bwrap_and_virtual_semantics_not_host_paths(
    tmp_path: Path, seccomp_fd: int
) -> None:
    first = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path / "one"),
        platform_anchor_sha256=_SHA,
    )
    second = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path / "two"),
        platform_anchor_sha256=_SHA,
    )

    def launch(
        plan: FullC6ReadSandboxPlan, root: Path, digest: str
    ) -> FullC6SandboxLaunch:
        return _prepare_linux(
            plan,
            bwrap=_bwrap(root),
            seccomp_fd=seccomp_fd,
            bwrap_digest=digest,
        )

    first_launch = launch(first, tmp_path / "one", "b" * 64)
    relocated_launch = launch(second, tmp_path / "two", "b" * 64)
    changed_bwrap = launch(first, tmp_path / "one", "c" * 64)

    assert first.digest == second.digest
    assert first_launch.profile_sha256 == relocated_launch.profile_sha256
    assert first_launch.profile_sha256 != changed_bwrap.profile_sha256


def test_bubblewrap_path_missing_alias_or_untrusted_file_fails_closed(
    tmp_path: Path,
) -> None:
    with pytest.raises(FullC6ReadSandboxError, match="canonical"):
        sandbox_module._verify_bubblewrap(Path("bwrap"))
    with pytest.raises(FullC6ReadSandboxError, match="unavailable"):
        sandbox_module._verify_bubblewrap(tmp_path / "missing" / "bwrap")

    target = tmp_path / "target"
    target.write_bytes(b"fixture")
    target.chmod(0o755)
    alias = tmp_path / "bwrap"
    alias.symlink_to(target)
    with pytest.raises(FullC6ReadSandboxError, match="unsafe"):
        sandbox_module._verify_bubblewrap(alias)
    alias.unlink()
    alias.write_bytes(b"fixture")
    alias.chmod(0o755)
    with pytest.raises(FullC6ReadSandboxError, match="unsafe"):
        sandbox_module._verify_bubblewrap(alias)


def test_linux_rejects_unknown_roles_and_unmapped_payload(tmp_path: Path) -> None:
    rules = list(_rules(tmp_path))
    rules[-1] = SandboxPathRule(
        rules[-1].path, "read-execute", "unknown-loader"
    )
    with pytest.raises(FullC6ReadSandboxError, match="unknown semantic role"):
        build_full_c6_sandbox_plan(
            target_triple="x86_64-unknown-linux-gnu",
            rules=rules,
            platform_anchor_sha256=_SHA,
        )


def test_rule_root_symlink_and_unexpected_device_fail_closed(tmp_path: Path) -> None:
    rules = list(_rules(tmp_path))
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    project_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.logical_role == "project-root"
    )
    rules[project_index] = SandboxPathRule(linked, "read", "project-root")
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=rules,
        platform_anchor_sha256=_SHA,
    )
    with pytest.raises(FullC6ReadSandboxError, match="type is unsafe"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("cargo", "build"),
        )


class _AnchorProvider:
    def __init__(self) -> None:
        self.seen: MacOSPlatformAnchor | None = None

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        self.seen = expected


def test_macos_requires_verified_anchor_and_emits_deterministic_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _macos_rules(tmp_path)
    anchor = MacOSPlatformAnchor(
        authenticated_snapshot_id="b" * 64,
        snapshot_uuid="12345678-1234-1234-1234-123456789abc",
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
    assert '(subpath "/Library")' in launch.command[2]
    assert '(subpath "/dev")' in launch.command[2]
    assert '(subpath "/System/Volumes/Preboot")' in launch.command[2]
    assert "(deny sysctl-write)" in launch.command[2]
    assert str(tmp_path / "inputs") in launch.command[2]


def test_macos_default_anchor_provider_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor = MacOSPlatformAnchor(
        authenticated_snapshot_id="b" * 64,
        snapshot_uuid="12345678-1234-1234-1234-123456789abc",
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=_macos_rules(tmp_path),
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
        snapshot_uuid="12345678-1234-1234-1234-123456789abc",
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    changed = MacOSPlatformAnchor(
        authenticated_snapshot_id="c" * 64,
        snapshot_uuid="12345678-1234-1234-1234-123456789abc",
        os_build="25A123",
        provider="fixture-provider-v1",
    )
    plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=_macos_rules(tmp_path),
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
