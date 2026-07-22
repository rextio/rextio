from __future__ import annotations

import errno
import hashlib
import mmap
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import struct
import subprocess
import sys
from collections.abc import Iterator
from typing import cast

import pytest

from rextio.build.full_c6_read_sandbox import (
    FullC6ReadSandboxError,
    FullC6ReadSandboxPlan,
    FullC6SandboxLaunch,
    LinuxSeccompLease,
    MacOSPlatformAnchor,
    SandboxPathRule,
    UnavailableMacOSPlatformAnchorProvider,
    build_full_c6_sandbox_plan,
    capture_active_macos_platform_anchor,
    create_linux_full_c6_seccomp_lease,
    linux_full_c6_seccomp_program,
    prepare_full_c6_sandbox_launch,
)
from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_CARGO,
    FULL_C6_LINUX_LAUNCHER,
    FULL_C6_LINUX_PYTHON,
    FULL_C6_LINUX_PYTHON_RUNTIME_LIBRARY,
    FULL_C6_LINUX_PYO3_CONFIG,
    expected_linux_pyo3_environment_signature,
)
from rextio.build import full_c6_read_sandbox as sandbox_module


_SHA = "a" * 64
_LINUX_UNMAPPED_RAW_TARGETS = {
    "libLLVM-18.so": "libLLVM.so.18.1",
    "libLLVM.so.18.1": "../llvm-18/lib/libLLVM.so.1",
    "libclang-cpp.so.16": "../llvm-16/lib/libclang-cpp.so.16",
    "libclang-cpp.so.17": "../llvm-17/lib/libclang-cpp.so.17",
    "libclang-cpp.so.18": "../llvm-18/lib/libclang-cpp.so.18.1",
    "libclang-cpp.so.18.1": "../llvm-18/lib/libclang-cpp.so.18.1",
    "libpython3.12.a": (
        "../python3.12/config-3.12-x86_64-linux-gnu/libpython3.12.a"
    ),
}
_LINUX_UNMAPPED_FINAL_VIRTUAL_TARGETS = frozenset(
    {
        "/llvm-16/lib/libclang-cpp.so.16",
        "/llvm-17/lib/libclang-cpp.so.17",
        "/llvm-18/lib/libLLVM.so.1",
        "/llvm-18/lib/libclang-cpp.so.18.1",
        "/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so",
        "/python3.12/config-3.12-x86_64-linux-gnu/libpython3.12.a",
    }
)
_SECCOMP_ALLOW = 0x7FFF0000
_SECCOMP_KILL_PROCESS = 0x80000000
_SECCOMP_EPERM = 0x00050001
_AUDIT_ARCH_X86_64 = 0xC000003E


def _evaluate_seccomp(
    program: bytes,
    *,
    syscall: int,
    args: tuple[int, ...] = (),
    arch: int = _AUDIT_ARCH_X86_64,
) -> int:
    """Evaluate the small classic-BPF subset emitted by the Full C6 filter."""
    if len(args) > 6:
        raise ValueError("seccomp_data only contains six syscall arguments")
    padded_args = (*args, *((0,) * (6 - len(args))))
    seccomp_data = struct.pack("=iI7Q", syscall, arch, 0, *padded_args)
    rows = tuple(struct.iter_unpack("=HBBI", program))
    accumulator = 0
    program_counter = 0
    for _step in range(len(rows) + 1):
        code, jump_true, jump_false, value = rows[program_counter]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            accumulator = struct.unpack_from("=I", seccomp_data, value)[0]
            program_counter += 1
            continue
        if code == 0x15:  # BPF_JMP | BPF_JEQ | BPF_K
            jump = jump_true if accumulator == value else jump_false
            program_counter += jump + 1
            continue
        if code == 0x35:  # BPF_JMP | BPF_JGE | BPF_K
            jump = jump_true if accumulator >= value else jump_false
            program_counter += jump + 1
            continue
        if code == 0x06:  # BPF_RET | BPF_K
            return value
        raise AssertionError(f"unsupported BPF opcode: {code:#x}")
    raise AssertionError("seccomp program did not return")


def _rules(tmp_path: Path) -> tuple[SandboxPathRule, ...]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    project = tmp_path / "project"
    build = tmp_path / "build"
    ar = tmp_path / "ar"
    ld = tmp_path / "ld"
    linker = tmp_path / "linker"
    python = tmp_path / "python3.11"
    python_library_root = tmp_path / "python-library-root"
    python_runtime_library = python_library_root / "libpython3.11.so.1.0"
    ranlib = tmp_path / "ranlib"
    rust_sysroot = tmp_path / "rust-sysroot"
    cargo = rust_sysroot / "bin" / "cargo"
    rustc = rust_sysroot / "bin" / "rustc"
    stdlib = python_library_root / "python3.11"
    launcher = tmp_path / "full_c6_linux_launcher.py"
    gcc_support = tmp_path / "gcc-toolchain"
    runtime = tmp_path / "runtime-libs"
    pyo3_config = tmp_path / "pyo3-config"
    loader = tmp_path / "ld-linux-x86-64.so.2"
    project.mkdir()
    build.mkdir()
    (rust_sysroot / "bin").mkdir(parents=True)
    (rust_sysroot / "lib").mkdir()
    (stdlib / "lib-dynload").mkdir(parents=True)
    gcc_support.mkdir()
    runtime.mkdir()
    ar.write_bytes(b"ar")
    ar.chmod(0o755)
    cargo.write_bytes(b"cargo")
    cargo.chmod(0o755)
    ld.write_bytes(b"ld")
    ld.chmod(0o755)
    linker.write_bytes(b"linker")
    linker.chmod(0o755)
    python.write_bytes(b"python")
    python.chmod(0o755)
    python_runtime_library.write_bytes(b"libpython")
    ranlib.write_bytes(b"ranlib")
    ranlib.chmod(0o755)
    rustc.write_bytes(b"rustc")
    rustc.chmod(0o755)
    pyo3_config.write_bytes(b"pyo3-config")
    launcher.write_bytes(b"launcher")
    loader.write_bytes(b"loader")
    loader.chmod(0o755)
    return (
        SandboxPathRule(project, "read", "project-root"),
        SandboxPathRule(build, "read-write", "build-root"),
        SandboxPathRule(ar, "read-execute", "toolchain-ar"),
        SandboxPathRule(cargo, "read-execute", "toolchain-cargo"),
        SandboxPathRule(ld, "read-execute", "toolchain-ld"),
        SandboxPathRule(linker, "read-execute", "toolchain-linker"),
        SandboxPathRule(python, "read-execute", "toolchain-python311"),
        SandboxPathRule(
            python_runtime_library,
            "read",
            "toolchain-python311-runtime-library",
        ),
        SandboxPathRule(ranlib, "read-execute", "toolchain-ranlib"),
        SandboxPathRule(rustc, "read-execute", "toolchain-rustc"),
        SandboxPathRule(
            rust_sysroot / "lib",
            "read-execute",
            "toolchain-rust-sysroot",
        ),
        SandboxPathRule(stdlib, "read", "toolchain-python311-stdlib"),
        SandboxPathRule(launcher, "read", "support-landlock-launcher"),
        SandboxPathRule(
            gcc_support,
            "read-execute",
            "support-gcc-toolchain",
        ),
        SandboxPathRule(pyo3_config, "read", "support-pyo3-config"),
        SandboxPathRule(
            python_library_root,
            "read",
            "support-python-library-root",
        ),
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
        "AR": "/rextio/toolchain/bin/ar",
        "CC": "/rextio/toolchain/bin/linker",
        "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(
            (
                "--remap-path-prefix=/rextio/project=/rextio/project",
                "--remap-path-prefix=/rextio/build=/rextio/build",
                "-C",
                "linker=/rextio/toolchain/bin/linker",
            )
        ),
        "CARGO_HOME": "/rextio/build/cargo-home",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": "/rextio/build/target",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": (
            "/rextio/toolchain/bin/linker"
        ),
        "COMPILER_PATH": (
            "/rextio/toolchain/bin:/rextio/support/gcc-toolchain"
        ),
        "HOME": "/rextio/build/home",
        "LANG": "C",
        "LC_ALL": "C",
        "LD": "/rextio/toolchain/bin/ld",
        "LD_LIBRARY_PATH": (
            "/rextio/toolchain/lib:/rextio/python/lib:"
            "/rextio/support/python-library-root:"
            "/x86_64-linux-gnu"
        ),
        "LIBRARY_PATH": (
            "/rextio/support/gcc-toolchain:/x86_64-linux-gnu"
        ),
        "PATH": "/rextio/toolchain/bin:/rextio/python/bin",
        "PYO3_CONFIG_FILE": FULL_C6_LINUX_PYO3_CONFIG,
        "PYO3_ENVIRONMENT_SIGNATURE": expected_linux_pyo3_environment_signature(),
        "PWD": "/rextio/project",
        "PYTHONHASHSEED": "0",
        "RANLIB": "/rextio/toolchain/bin/ranlib",
        "RUSTC": "/rextio/toolchain/bin/rustc",
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }


class _MockSealedMemfdKernel:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.seals: dict[int, int] = {}
        self.create_calls: list[tuple[str, int]] = []

    def memfd_create(self, name: str, flags: int) -> int:
        self.create_calls.append((name, flags))
        descriptor = os.open(
            self.path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
        self.seals[descriptor] = 0
        return descriptor

    def fcntl(self, descriptor: int, command: int, argument: int = 0) -> int:
        if command == sandbox_module._F_ADD_SEALS:
            if self.seals[descriptor] & sandbox_module._F_SEAL_SEAL:
                raise OSError(errno.EPERM, "memfd seals are immutable")
            self.seals[descriptor] |= argument
            return 0
        if command == sandbox_module._F_GET_SEALS:
            return self.seals[descriptor]
        raise OSError(errno.EINVAL, "unexpected fcntl command")

    def write(self, descriptor: int, payload: bytes) -> int:
        if self.seals[descriptor] & sandbox_module._F_SEAL_WRITE:
            raise OSError(errno.EPERM, "sealed memfd is immutable")
        return os.write(descriptor, payload)


@pytest.fixture
def seccomp_kernel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _MockSealedMemfdKernel:
    kernel = _MockSealedMemfdKernel(tmp_path / "seccomp.memfd")
    monkeypatch.setattr(sandbox_module, "_is_linux_platform", lambda: True)
    monkeypatch.setattr(sandbox_module, "_memfd_create", kernel.memfd_create)
    monkeypatch.setattr(sandbox_module, "_fcntl_descriptor", kernel.fcntl)
    monkeypatch.setattr(sandbox_module, "_write_descriptor", kernel.write)
    return kernel


@pytest.fixture
def seccomp_lease(
    seccomp_kernel: _MockSealedMemfdKernel,
) -> Iterator[LinuxSeccompLease]:
    lease = create_linux_full_c6_seccomp_lease()
    assert seccomp_kernel.create_calls == [("rextio-full-c6-seccomp", 0x0003)]
    try:
        yield lease
    finally:
        lease.close()


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


def test_linux_unmapped_runtime_symlink_targets_remain_outside_all_mappings(
    tmp_path: Path,
) -> None:
    rules = _rules(tmp_path)
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=rules,
        platform_anchor_sha256=_SHA,
    )
    source_prefix = "/x86_64-linux-gnu"
    fixed_sources = {
        posixpath.join(source_prefix, relative_path): raw_target
        for relative_path, raw_target in _LINUX_UNMAPPED_RAW_TARGETS.items()
    }
    gcc_source_prefix = "/rextio/support/gcc-toolchain"
    fixed_sources[posixpath.join(gcc_source_prefix, "liblto_plugin.so")] = (
        "../../../../libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so"
    )
    final_targets: set[str] = set()
    for source in fixed_sources:
        current = source
        visited: set[str] = set()
        while current in fixed_sources:
            assert current not in visited
            visited.add(current)
            current = posixpath.normpath(
                posixpath.join(
                    posixpath.dirname(current),
                    fixed_sources[current],
                )
            )
        final_targets.add(current)
    assert frozenset(final_targets) == _LINUX_UNMAPPED_FINAL_VIRTUAL_TARGETS
    assert (
        sandbox_module._LINUX_DENIED_UNMAPPED_VIRTUAL_TARGETS
        == _LINUX_UNMAPPED_FINAL_VIRTUAL_TARGETS
    )
    assert all(
        not target.startswith(f"{source_prefix}/")
        for target in final_targets
    )
    assert all(
        not target.startswith(f"{gcc_source_prefix}/")
        for target in final_targets
    )
    destinations = tuple(
        destination
        for rule in plan.rules
        if (destination := sandbox_module._linux_rule_destination(rule))
        is not None
    )
    assert all(
        not (
            target == destination
            or target.startswith(destination.rstrip("/") + "/")
        )
        for target in final_targets
        for destination in destinations
    )


@pytest.mark.parametrize(
    "forbidden_destination",
    (
        "/llvm-16",
        "/llvm-17",
        "/llvm-18",
        "/libexec",
        "/python3.12",
        "/",
    ),
)
def test_linux_plan_rejects_mapping_an_unmapped_virtual_target_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forbidden_destination: str,
) -> None:
    original = sandbox_module._linux_rule_destination

    def forged_destination(rule: SandboxPathRule) -> str | None:
        if rule.logical_role == "support-runtime-libs":
            return forbidden_destination
        return original(rule)

    monkeypatch.setattr(
        sandbox_module,
        "_linux_rule_destination",
        forged_destination,
    )
    with pytest.raises(FullC6ReadSandboxError, match="unmapped virtual target"):
        build_full_c6_sandbox_plan(
            target_triple="x86_64-unknown-linux-gnu",
            rules=_rules(tmp_path),
            platform_anchor_sha256=_SHA,
        )


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
    seccomp_lease: LinuxSeccompLease,
    environment: dict[str, str] | None = None,
    bwrap_digest: str = "b" * 64,
) -> FullC6SandboxLaunch:
    return prepare_full_c6_sandbox_launch(
        plan,
        (FULL_C6_LINUX_CARGO, "build"),
        bubblewrap=bwrap,
        bubblewrap_verifier=lambda _path: bwrap_digest,
        linux_seccomp_lease=seccomp_lease,
        linux_payload_environment=(
            _environment() if environment is None else environment
        ),
    )


def test_linux_launch_uses_bwrap_then_isolated_post_namespace_launcher(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
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
        seccomp_lease=seccomp_lease,
    )
    seccomp_fd = seccomp_lease.fileno()
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
        FULL_C6_LINUX_CARGO,
        "build",
    )
    assert launch.command[-13:-11] == ("--seccomp", str(seccomp_fd))
    assert launch.command[-11] == "--"
    assert launch.pass_fds == (seccomp_fd,)
    assert launch.seccomp_sha256 == hashlib.sha256(
        linux_full_c6_seccomp_program()
    ).hexdigest()
    assert launch.seccomp_lease is seccomp_lease
    assert launch.preexec_fn is None


def test_linux_command_has_exact_mapping_order_and_launcher_support_is_hidden(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
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
        (FULL_C6_LINUX_CARGO, "build"),
        bubblewrap=bwrap,
        bubblewrap_verifier=lambda _path: "b" * 64,
        linux_seccomp_lease=seccomp_lease,
        linux_payload_environment=_environment(),
    )
    seccomp_fd = seccomp_lease.fileno()

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
    assert command[dir_index : dir_index + 22] == (
        "--dir",
        "/rextio",
        "--dir",
        "/rextio/toolchain",
        "--dir",
        "/rextio/toolchain/bin",
        "--dir",
        "/rextio/toolchain/lib",
        "--dir",
        "/rextio/python",
        "--dir",
        "/rextio/python/bin",
        "--dir",
        "/rextio/python/lib",
        "--dir",
        "/rextio/support",
        "--dir",
        "/rextio/support/rextio",
        "--dir",
        "/x86_64-linux-gnu",
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
        "/rextio/python/bin/python3.11",
        "--ro-bind",
        str(tmp_path / "python-library-root" / "libpython3.11.so.1.0"),
        FULL_C6_LINUX_PYTHON_RUNTIME_LIBRARY,
        "--ro-bind",
        str(tmp_path / "python-library-root" / "python3.11"),
        "/rextio/python/lib/python3.11",
        "--ro-bind",
        str(tmp_path / "ar"),
        "/rextio/toolchain/bin/ar",
        "--ro-bind",
        str(tmp_path / "rust-sysroot" / "bin" / "cargo"),
        FULL_C6_LINUX_CARGO,
        "--ro-bind",
        str(tmp_path / "ld"),
        "/rextio/toolchain/bin/ld",
        "--ro-bind",
        str(tmp_path / "linker"),
        "/rextio/toolchain/bin/linker",
        "--ro-bind",
        str(tmp_path / "ranlib"),
        "/rextio/toolchain/bin/ranlib",
        "--ro-bind",
        str(tmp_path / "rust-sysroot" / "bin" / "rustc"),
        "/rextio/toolchain/bin/rustc",
        "--ro-bind",
        str(tmp_path / "rust-sysroot" / "lib"),
        "/rextio/toolchain/lib",
        "--ro-bind",
        str(tmp_path / "gcc-toolchain"),
        "/rextio/support/gcc-toolchain",
        "--ro-bind",
        str(tmp_path / "pyo3-config"),
        FULL_C6_LINUX_PYO3_CONFIG,
        "--ro-bind",
        str(tmp_path / "python-library-root"),
        "/rextio/support/python-library-root",
        "--ro-bind",
        str(tmp_path / "full_c6_linux_launcher.py"),
        "/rextio/support/rextio/full_c6_linux_launcher.py",
        "--ro-bind",
        str(tmp_path / "runtime-libs"),
        "/x86_64-linux-gnu",
        "--ro-bind",
        str(tmp_path / "ld-linux-x86-64.so.2"),
        "/lib64/ld-linux-x86-64.so.2",
    )
    mappings_index = dir_index + 22
    assert command[mappings_index : mappings_index + len(expected_mappings)] == expected_mappings
    tail_index = mappings_index + len(expected_mappings)
    assert command[tail_index : tail_index + 12] == (
        "--dir",
        "/rextio/build/home",
        "--dir",
        "/rextio/build/cargo-home",
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


def test_linux_namespace_preserves_ubuntu_gcc_runtime_symlink_topology(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    launch = _prepare_linux(
        plan,
        bwrap=_bwrap(tmp_path),
        seccomp_lease=seccomp_lease,
    )

    command = launch.command
    bind_destinations = [
        command[index + 2]
        for index, value in enumerate(command)
        if value in {"--bind", "--ro-bind"}
    ]
    gcc_root = "/rextio/support/gcc-toolchain"
    runtime_root = "/x86_64-linux-gnu"
    raw_target = "../../../x86_64-linux-gnu/libstdc++.so.6"
    resolved_target = posixpath.normpath(posixpath.join(gcc_root, raw_target))

    assert resolved_target == f"{runtime_root}/libstdc++.so.6"
    assert bind_destinations.count(runtime_root) == 1
    assert "/rextio/support/runtime-libs" not in command


def test_linux_namespace_has_no_mount_below_read_only_directory(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    launch = _prepare_linux(
        plan,
        bwrap=_bwrap(tmp_path),
        seccomp_lease=seccomp_lease,
    )

    mappings = tuple(
        (
            index,
            value,
            Path(launch.command[index + 1]),
            PurePosixPath(launch.command[index + 2]),
        )
        for index, value in enumerate(launch.command)
        if value in {"--bind", "--ro-bind"}
    )
    read_only_directories = tuple(
        (index, destination)
        for index, operation, source, destination in mappings
        if operation == "--ro-bind" and source.is_dir()
    )

    assert not tuple(
        (ancestor, destination)
        for ancestor_index, ancestor in read_only_directories
        for mapping_index, _operation, _source, destination in mappings
        if mapping_index > ancestor_index and ancestor in destination.parents
    )


def test_linux_namespace_rejects_aliased_rust_sysroot_lib(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
) -> None:
    rules = _rules(tmp_path)
    rust_lib = tmp_path / "rust-sysroot" / "lib"
    rust_lib.rmdir()
    aliased_lib = tmp_path / "aliased-rust-lib"
    aliased_lib.mkdir()
    rust_lib.symlink_to(aliased_lib, target_is_directory=True)
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=rules,
        platform_anchor_sha256=_SHA,
    )

    with pytest.raises(FullC6ReadSandboxError, match="unsafe"):
        _prepare_linux(
            plan,
            bwrap=_bwrap(tmp_path),
            seccomp_lease=seccomp_lease,
        )


def test_linux_payload_is_exactly_fixed_cargo_not_another_mapped_tool(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )

    with pytest.raises(FullC6ReadSandboxError, match="fixed Cargo"):
        prepare_full_c6_sandbox_launch(
            plan,
            ("/rextio/toolchain/bin/rustc", "--version"),
            bubblewrap=_bwrap(tmp_path),
            bubblewrap_verifier=lambda _path: "b" * 64,
            linux_seccomp_lease=seccomp_lease,
            linux_payload_environment=_environment(),
        )


@pytest.mark.parametrize(
    "name",
    (
        "AR",
        "CC",
        "CARGO_BUILD_TARGET",
        "CARGO_HOME",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        "COMPILER_PATH",
        "LD",
        "LD_LIBRARY_PATH",
        "LIBRARY_PATH",
        "PYO3_CONFIG_FILE",
        "PWD",
        "RANLIB",
        "RUSTC",
        "PYTHONHASHSEED",
    ),
)
def test_linux_production_environment_field_is_required_and_exact_before_launch(
    name: str, tmp_path: Path, seccomp_lease: LinuxSeccompLease
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    missing = _environment()
    missing.pop(name)
    with pytest.raises(FullC6ReadSandboxError):
        _prepare_linux(
            plan,
            bwrap=bwrap,
            seccomp_lease=seccomp_lease,
            environment=missing,
        )

    changed = _environment()
    changed[name] += "-changed"
    with pytest.raises(FullC6ReadSandboxError):
        _prepare_linux(
            plan,
            bwrap=bwrap,
            seccomp_lease=seccomp_lease,
            environment=changed,
        )


def test_linux_rejects_missing_or_caller_owned_seccomp_descriptor(
    tmp_path: Path,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    with pytest.raises(FullC6ReadSandboxError, match="typed sealed"):
        prepare_full_c6_sandbox_launch(
            plan,
            (FULL_C6_LINUX_CARGO,),
            bubblewrap=bwrap,
            bubblewrap_verifier=lambda _path: "b" * 64,
            linux_payload_environment=_environment(),
        )

    mutable = tmp_path / "mutable.bpf"
    mutable.write_bytes(linux_full_c6_seccomp_program())
    descriptor = os.open(mutable, os.O_RDWR)
    try:
        with pytest.raises(FullC6ReadSandboxError, match="typed sealed"):
            prepare_full_c6_sandbox_launch(
                plan,
                (FULL_C6_LINUX_CARGO,),
                bubblewrap=bwrap,
                bubblewrap_verifier=lambda _path: "b" * 64,
                linux_seccomp_lease=cast(LinuxSeccompLease, descriptor),
                linux_payload_environment=_environment(),
            )
    finally:
        os.close(descriptor)


def test_mock_linux_factory_seals_exact_filter_and_rejects_mutation(
    seccomp_lease: LinuxSeccompLease,
    seccomp_kernel: _MockSealedMemfdKernel,
) -> None:
    descriptor = seccomp_lease.fileno()

    assert seccomp_lease.closed is False
    assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
    assert os.pread(
        descriptor,
        len(linux_full_c6_seccomp_program()) + 1,
        0,
    ) == linux_full_c6_seccomp_program()
    assert seccomp_kernel.seals[descriptor] == 0x000F
    with pytest.raises(OSError) as raised:
        sandbox_module._write_descriptor(descriptor, b"mutation")
    assert raised.value.errno == errno.EPERM


@pytest.mark.skipif(sys.platform == "linux", reason="non-Linux platform gate")
def test_linux_seccomp_factory_is_unavailable_off_linux() -> None:
    with pytest.raises(FullC6ReadSandboxError, match="unavailable on this host"):
        create_linux_full_c6_seccomp_lease()


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux memfd seals")
def test_real_linux_seccomp_memfd_is_exact_and_immutable() -> None:
    with create_linux_full_c6_seccomp_lease() as lease:
        descriptor = lease.fileno()
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
        assert os.pread(
            descriptor,
            len(linux_full_c6_seccomp_program()) + 1,
            0,
        ) == linux_full_c6_seccomp_program()
        with pytest.raises(OSError) as raised:
            os.write(descriptor, b"mutation")
        assert raised.value.errno == errno.EPERM


def test_linux_seccomp_factory_failure_closes_created_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[int] = []

    def create_memfd(_name: str, _flags: int) -> int:
        descriptor = os.open(
            tmp_path / "failed.memfd",
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
        created.append(descriptor)
        return descriptor

    monkeypatch.setattr(sandbox_module, "_is_linux_platform", lambda: True)
    monkeypatch.setattr(sandbox_module, "_memfd_create", create_memfd)
    monkeypatch.setattr(
        sandbox_module,
        "_fcntl_descriptor",
        lambda _fd, _command, _argument=0: (_ for _ in ()).throw(
            OSError(errno.EINVAL, "sealing unavailable")
        ),
    )

    with pytest.raises(FullC6ReadSandboxError, match="cannot be created and sealed"):
        create_linux_full_c6_seccomp_lease()
    assert len(created) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(created[0])
    assert raised.value.errno == errno.EBADF


def test_linux_seccomp_lease_rejects_forged_closed_and_wrong_owner(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    bwrap = _bwrap(tmp_path)
    forged = object.__new__(LinuxSeccompLease)
    with pytest.raises(FullC6ReadSandboxError, match="forged or incomplete"):
        _prepare_linux(plan, bwrap=bwrap, seccomp_lease=forged)

    owner_pid = os.getpid()
    monkeypatch.setattr(sandbox_module, "_process_id", lambda: owner_pid + 1)
    with pytest.raises(FullC6ReadSandboxError, match="forged, stale, or closed"):
        _prepare_linux(plan, bwrap=bwrap, seccomp_lease=seccomp_lease)
    monkeypatch.setattr(sandbox_module, "_process_id", lambda: owner_pid)

    seccomp_lease.close()
    with pytest.raises(FullC6ReadSandboxError, match="forged, stale, or closed"):
        _prepare_linux(plan, bwrap=bwrap, seccomp_lease=seccomp_lease)


@pytest.mark.parametrize("observed_seals", (0x000E, 0x001F))
def test_linux_seccomp_lease_rejects_missing_or_extra_seals(
    observed_seals: int,
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
    seccomp_kernel: _MockSealedMemfdKernel,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    seccomp_kernel.seals[seccomp_lease.fileno()] = observed_seals

    with pytest.raises(FullC6ReadSandboxError, match="exact required seals"):
        _prepare_linux(
            plan,
            bwrap=_bwrap(tmp_path),
            seccomp_lease=seccomp_lease,
        )


def test_linux_seccomp_lease_rejects_unavailable_seal_query(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
    seccomp_kernel: _MockSealedMemfdKernel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )

    def unavailable_seals(
        descriptor: int,
        command: int,
        argument: int = 0,
    ) -> int:
        if command == sandbox_module._F_GET_SEALS:
            raise OSError(errno.EINVAL, "seal query unavailable")
        return seccomp_kernel.fcntl(descriptor, command, argument)

    monkeypatch.setattr(sandbox_module, "_fcntl_descriptor", unavailable_seals)
    with pytest.raises(FullC6ReadSandboxError, match="seals are unavailable"):
        _prepare_linux(
            plan,
            bwrap=_bwrap(tmp_path),
            seccomp_lease=seccomp_lease,
        )


def test_linux_seccomp_lease_rejects_reused_descriptor_identity(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    descriptor = seccomp_lease.fileno()
    replacement_path = tmp_path / "replacement"
    replacement_path.write_bytes(linux_full_c6_seccomp_program())
    replacement = os.open(replacement_path, os.O_RDONLY)
    try:
        os.dup2(replacement, descriptor)
    finally:
        os.close(replacement)
    try:
        with pytest.raises(FullC6ReadSandboxError, match="identity changed"):
            _prepare_linux(
                plan,
                bwrap=_bwrap(tmp_path),
                seccomp_lease=seccomp_lease,
            )
    finally:
        os.close(descriptor)
        seccomp_lease.close()


def test_linux_launch_cleanup_closes_the_exact_lease_descriptor(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    launch = _prepare_linux(
        plan,
        bwrap=_bwrap(tmp_path),
        seccomp_lease=seccomp_lease,
    )
    descriptor = seccomp_lease.fileno()

    assert launch.pass_fds == (descriptor,)
    assert launch.seccomp_lease is seccomp_lease
    launch.close()
    launch.close()

    assert seccomp_lease.closed is True
    with pytest.raises(OSError) as raised:
        os.fstat(descriptor)
    assert raised.value.errno == errno.EBADF


def test_launch_dataclass_rejects_mismatched_seccomp_receipt_or_descriptor(
    seccomp_lease: LinuxSeccompLease,
) -> None:
    descriptor = seccomp_lease.fileno()
    digest = hashlib.sha256(linux_full_c6_seccomp_program()).hexdigest()

    with pytest.raises(ValueError, match="receipt or descriptor"):
        FullC6SandboxLaunch(
            command=("bwrap",),
            preexec_fn=None,
            profile_sha256="a" * 64,
            pass_fds=(descriptor,),
            seccomp_sha256="b" * 64,
            seccomp_lease=seccomp_lease,
        )
    with pytest.raises(ValueError, match="receipt or descriptor"):
        FullC6SandboxLaunch(
            command=("bwrap",),
            preexec_fn=None,
            profile_sha256="a" * 64,
            pass_fds=(descriptor + 1,),
            seccomp_sha256=digest,
            seccomp_lease=seccomp_lease,
        )
    with pytest.raises(ValueError, match="capability contract"):
        FullC6SandboxLaunch(
            command=("sandbox-exec",),
            preexec_fn=None,
            profile_sha256="a" * 64,
            pass_fds=(),
            seccomp_sha256=digest,
            seccomp_lease=None,
        )


def test_linux_seccomp_filter_rejects_x32_network_and_ipc_syscalls() -> None:
    rows = tuple(
        struct.iter_unpack("=HBBI", linux_full_c6_seccomp_program())
    )

    assert (0x35, 0, 1, 0x40000000) in rows
    assert (0x15, 0, 1, 41) in rows  # socket
    assert (0x15, 0, 1, 29) in rows  # shmget
    assert (0x15, 0, 1, 240) in rows  # mq_open
    assert (0x15, 0, 1, 425) in rows  # io_uring_setup


def test_linux_seccomp_allows_only_rust_process_socketpair_shape() -> None:
    program = linux_full_c6_seccomp_program()
    rust_process_socketpair = (1, 5 | 0x00080000, 0)

    assert (
        _evaluate_seccomp(program, syscall=53, args=rust_process_socketpair)
        == _SECCOMP_ALLOW
    )
    denied_socketpairs = (
        (2, rust_process_socketpair[1], 0),  # AF_INET
        (10, rust_process_socketpair[1], 0),  # AF_INET6
        (1, 1 | 0x00080000, 0),  # SOCK_STREAM | SOCK_CLOEXEC
        (1, 5, 0),  # missing SOCK_CLOEXEC
        (1, rust_process_socketpair[1] | 0x00000800, 0),
        (1, rust_process_socketpair[1], 1),
        (1 | (1 << 32), rust_process_socketpair[1], 0),
        (1, rust_process_socketpair[1] | (1 << 32), 0),
        (1, rust_process_socketpair[1], 1 << 32),
    )
    assert all(
        _evaluate_seccomp(program, syscall=53, args=args) == _SECCOMP_EPERM
        for args in denied_socketpairs
    )
    assert _evaluate_seccomp(program, syscall=41, args=(1, 5, 0)) == _SECCOMP_EPERM
    assert _evaluate_seccomp(program, syscall=42, args=(0, 0, 0)) == _SECCOMP_EPERM
    assert _evaluate_seccomp(program, syscall=0) == _SECCOMP_ALLOW
    assert (
        _evaluate_seccomp(program, syscall=0, arch=0xC00000B7)
        == _SECCOMP_KILL_PROCESS
    )


def test_linux_rejects_nonzero_seccomp_offset(
    tmp_path: Path,
    seccomp_lease: LinuxSeccompLease,
) -> None:
    plan = build_full_c6_sandbox_plan(
        target_triple="x86_64-unknown-linux-gnu",
        rules=_rules(tmp_path),
        platform_anchor_sha256=_SHA,
    )
    descriptor = seccomp_lease.fileno()
    os.lseek(descriptor, 8, os.SEEK_SET)
    try:
        with pytest.raises(FullC6ReadSandboxError, match="exact filter"):
            prepare_full_c6_sandbox_launch(
                plan,
                (FULL_C6_LINUX_CARGO,),
                bubblewrap=_bwrap(tmp_path),
                bubblewrap_verifier=lambda _path: "b" * 64,
                linux_seccomp_lease=seccomp_lease,
                linux_payload_environment=_environment(),
            )
    finally:
        os.lseek(descriptor, 0, os.SEEK_SET)


def test_linux_profile_binds_bwrap_and_virtual_semantics_not_host_paths(
    tmp_path: Path, seccomp_lease: LinuxSeccompLease
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
            seccomp_lease=seccomp_lease,
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


def test_linux_rejects_rust_and_python_leaves_outside_fixed_parent_roots(
    tmp_path: Path,
) -> None:
    rules = list(_rules(tmp_path))
    cargo_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.logical_role == "toolchain-cargo"
    )
    outside_cargo = tmp_path / "outside-cargo"
    outside_cargo.write_bytes(b"cargo")
    outside_cargo.chmod(0o755)
    changed = list(rules)
    changed[cargo_index] = SandboxPathRule(
        outside_cargo,
        "read-execute",
        "toolchain-cargo",
    )
    with pytest.raises(FullC6ReadSandboxError, match="exact Rust sysroot leaf"):
        build_full_c6_sandbox_plan(
            target_triple="x86_64-unknown-linux-gnu",
            rules=changed,
            platform_anchor_sha256=_SHA,
        )

    python_index = next(
        index
        for index, rule in enumerate(rules)
        if rule.logical_role == "toolchain-python311-runtime-library"
    )
    outside_python = tmp_path / "outside-libpython3.11.so.1.0"
    outside_python.write_bytes(b"libpython")
    changed = list(rules)
    changed[python_index] = SandboxPathRule(
        outside_python,
        "read",
        "toolchain-python311-runtime-library",
    )
    with pytest.raises(FullC6ReadSandboxError, match="exact library root leaves"):
        build_full_c6_sandbox_plan(
            target_triple="x86_64-unknown-linux-gnu",
            rules=changed,
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


def test_macos_profile_rule_lines_separate_executable_mapping_by_access() -> None:
    path = '"/__rextio_test__/capability"'

    assert sandbox_module._macos_profile_rule_lines(
        access="read",
        selector="literal",
        path=path,
    ) == (
        f"(allow file-read* (literal {path}))",
    )
    assert sandbox_module._macos_profile_rule_lines(
        access="read-execute",
        selector="literal",
        path=path,
    ) == (
        f"(allow file-read* (literal {path}))",
        f"(allow file-map-executable (literal {path}))",
        f"(allow process-exec (literal {path}))",
    )
    assert sandbox_module._macos_profile_rule_lines(
        access="read-write",
        selector="literal",
        path=path,
    ) == (
        f"(allow file-read* file-write* (literal {path}))",
    )
    assert sandbox_module._macos_profile_rule_lines(
        access="read-write",
        selector="subpath",
        path=path,
    ) == (
        f"(allow file-read* file-write* (subpath {path}))",
        f"(allow file-map-executable (subpath {path}))",
        f"(allow process-exec (subpath {path}))",
    )


def test_macos_requires_verified_anchor_and_emits_deterministic_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _macos_rules(tmp_path)
    fresh_root = tmp_path / "fresh-lifecycle"
    fresh_root.mkdir()
    fresh_rules = _macos_rules(fresh_root)
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
    fresh_plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=fresh_rules,
        platform_anchor_sha256=anchor.digest,
    )
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    real_lstat = os.lstat

    def fake_lstat(path: os.PathLike[str] | str) -> os.stat_result:
        if Path(path) == sandbox_exec:
            return os.stat_result((stat.S_IFREG | 0o755,) + (0,) * 9)
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", fake_lstat)
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
    fresh_launch = prepare_full_c6_sandbox_launch(
        fresh_plan,
        ("cargo", "build"),
        macos_anchor=anchor,
        macos_anchor_provider=provider,
        sandbox_exec=sandbox_exec,
        macos_profile_compiler=lambda path, profile: compiled.append((path, profile)),
    )

    assert provider.seen == anchor
    assert compiled == [
        (sandbox_exec, launch.command[2]),
        (sandbox_exec, fresh_launch.command[2]),
    ]
    assert plan.digest == fresh_plan.digest
    assert launch.pass_fds == ()
    assert launch.seccomp_sha256 is None
    assert launch.seccomp_lease is None
    assert launch.command[:3] == ("/usr/bin/sandbox-exec", "-p", launch.command[2])
    assert launch.command[-3:] == ("--", "cargo", "build")
    rendered_sha256 = hashlib.sha256(launch.command[2].encode()).hexdigest()
    fresh_rendered_sha256 = hashlib.sha256(
        fresh_launch.command[2].encode()
    ).hexdigest()
    assert rendered_sha256 != fresh_rendered_sha256
    assert launch.profile_sha256 == fresh_launch.profile_sha256
    assert launch.profile_sha256 not in {rendered_sha256, fresh_rendered_sha256}
    assert "(deny default)" in launch.command[2]
    assert "(deny network*)" in launch.command[2]
    assert '(import "system.sb")' in launch.command[2]
    assert "(deny mach-lookup)" in launch.command[2]
    assert (
        '(deny file-read* file-test-existence file-map-executable '
        '(subpath "/private/var")'
    ) in launch.command[2]
    assert (
        '(deny file-read* file-write* file-test-existence file-map-executable '
        '(subpath "/Library")'
    ) in launch.command[2]
    assert '(subpath "/private/var")' in launch.command[2]
    assert '(subpath "/Library")' in launch.command[2]
    assert '(subpath "/dev")' in launch.command[2]
    assert '(subpath "/System/Volumes/Preboot")' in launch.command[2]
    profile_lines = launch.command[2].splitlines()
    sysctl_read_index = profile_lines.index("(deny sysctl-read)")
    assert profile_lines[sysctl_read_index : sysctl_read_index + 3] == [
        "(deny sysctl-read)",
        '(allow sysctl-read (sysctl-name "hw.ncpu"))',
        "(deny sysctl-write)",
    ]
    assert sandbox_module._MACOS_PROFILE_CONTRACT_DOMAIN == (
        "rextio.full-c6-macos-sandbox-profile.v2"
    )
    assert str(tmp_path / "inputs") in launch.command[2]
    assert str(fresh_root / "inputs") in fresh_launch.command[2]


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


def _nearest_xcode_developer_root(executable: Path) -> Path | None:
    """Return the nearest resolved ``Contents/Developer`` ancestor."""
    return next(
        (
            parent
            for parent in executable.parents
            if parent.parts[-2:] == ("Contents", "Developer")
        ),
        None,
    )


def test_nearest_xcode_developer_root_uses_versioned_resolved_bundle() -> None:
    executable = Path(
        "/Applications/Xcode_26.5.app/Contents/Developer/Library/Frameworks/"
        "Python3.framework/Versions/3.9/bin/python3.9"
    )

    assert _nearest_xcode_developer_root(executable) == Path(
        "/Applications/Xcode_26.5.app/Contents/Developer"
    )
    assert (
        _nearest_xcode_developer_root(Path("/opt/homebrew/bin/python3")) is None
    )


@pytest.mark.skipif(
    sys.platform != "darwin" or os.uname().machine.lower() not in {"arm64", "aarch64"},
    reason="real sandbox-exec executable-map gate is macOS arm64 only",
)
def test_real_macos_profile_denies_inherited_mutable_executable_mapping() -> None:
    # libRosettaAot.dylib rejects executable mmap even without sandbox-exec on
    # current macOS. Select only an Apple-owned mutable-volume image that first
    # proves it is executable-mappable in this process; absence is an honest
    # host-capability skip (Rosetta is optional).
    mapped_library: Path | None = None
    for candidate in (
        Path("/Library/Apple/usr/libexec/oah/libRosettaRuntime"),
    ):
        try:
            observed = os.lstat(candidate)
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
                continue
            descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                region = mmap.mmap(
                    descriptor,
                    1,
                    flags=mmap.MAP_PRIVATE,
                    prot=mmap.PROT_READ | mmap.PROT_EXEC,
                )
                region.close()
            finally:
                os.close(descriptor)
        except OSError:
            continue
        mapped_library = candidate
        break
    if mapped_library is None:
        pytest.skip("host has no safe executable-mappable mutable-volume control image")

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
    trusted_rule = SandboxPathRule(
        mapped_library,
        "read-execute",
        "trusted-map-library",
    )
    trusted_plan = build_full_c6_sandbox_plan(
        target_triple="aarch64-apple-darwin",
        rules=(rule, trusted_rule),
        platform_anchor_sha256=anchor.digest,
    )
    trusted_launch = prepare_full_c6_sandbox_launch(
        trusted_plan,
        ("/usr/bin/true",),
        macos_anchor=anchor,
    )

    # Use the sealed-system interpreter, not the pytest interpreter: pyenv or
    # Homebrew Python can have dylib dependencies outside sys.base_prefix that
    # are intentionally absent from this minimal profile.
    python_executable = Path(
        "/Applications/Xcode.app/Contents/Developer/usr/bin/python3"
    )
    if not python_executable.is_file():
        pytest.skip("Xcode's direct Python probe interpreter is unavailable")
    python_executable = python_executable.resolve(strict=True)
    python_root = _nearest_xcode_developer_root(python_executable)
    if python_root is None or not python_root.is_dir():
        pytest.skip(
            "resolved Xcode Python is not below an available Contents/Developer root"
        )
    ancestor_literals = " ".join(
        f"(literal {sandbox_module._sandbox_literal(os.fspath(parent))})"
        for parent in reversed(python_root.parents)
        if parent != Path("/")
    )
    python_allowances = (
        f"(allow file-read* file-test-existence {ancestor_literals})\n"
        f"(allow file-read* file-test-existence file-map-executable "
        f"(subpath {sandbox_module._sandbox_literal(os.fspath(python_root))}))\n"
        f"(allow process-exec "
        f"(subpath {sandbox_module._sandbox_literal(os.fspath(python_root))}))\n"
        '(allow file-read* (literal "/dev/urandom"))\n'
    )
    probe_profile = launch.command[2] + python_allowances
    trusted_profile = trusted_launch.command[2] + python_allowances
    assert '(subpath "/Library") ' in probe_profile
    probe = (
        "import mmap, sys\n"
        "try:\n"
        "    region = mmap.mmap(int(sys.argv[1]), 1, flags=mmap.MAP_PRIVATE, "
        "prot=mmap.PROT_READ | mmap.PROT_EXEC)\n"
        "except PermissionError:\n"
        "    raise SystemExit(23)\n"
        "except OSError as exc:\n"
        "    print(f'{exc.errno}:{exc}', file=sys.stderr)\n"
        "    raise SystemExit(24)\n"
        "else:\n"
        "    region.close()\n"
    )

    def run_profile(profile: str, descriptor: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-p",
                profile,
                "--",
                os.fspath(python_executable),
                "-S",
                "-c",
                probe,
                str(descriptor),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
            env={"PYTHONHASHSEED": "0"},
            cwd="/",
            pass_fds=(descriptor,),
        )

    def run_unsandboxed(descriptor: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                os.fspath(python_executable),
                "-S",
                "-c",
                probe,
                str(descriptor),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
            env={"PYTHONHASHSEED": "0"},
            cwd="/",
            pass_fds=(descriptor,),
        )

    trusted_map_allow = (
        "(allow file-map-executable "
        f"(literal {sandbox_module._sandbox_literal(os.fspath(mapped_library))}))"
    )
    assert trusted_map_allow in trusted_profile
    descriptor = os.open(mapped_library, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        unsandboxed = run_unsandboxed(descriptor)
        if unsandboxed.returncode != 0:
            pytest.skip(
                "host cannot establish the unsandboxed executable-map control: "
                f"exit {unsandboxed.returncode}"
            )
        denied = run_profile(probe_profile, descriptor)
        trusted = run_profile(trusted_profile, descriptor)
    finally:
        os.close(descriptor)

    # The host may report EPERM to the probe or terminate it at the sandbox
    # boundary. The otherwise-identical trusted profile is the positive
    # control, so a non-zero denied result is an actual profile differential.
    assert denied.returncode != 0, denied.stderr
    assert trusted.returncode == 0, trusted.stderr
