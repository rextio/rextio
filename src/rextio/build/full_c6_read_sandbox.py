"""Deny-by-default filesystem-read sandbox primitives for strict Full C6.

The Full C6 build is allowed to claim a complete input closure only when the
kernel prevents Cargo, build scripts, rustc, and the linker from reading an
unbound host file.  This module provides that enforcement boundary for the two
frozen Alpha hosts:

* Linux x86_64 uses Landlock in the child between ``fork`` and ``exec``.
* macOS arm64 uses ``sandbox-exec`` only with a separately verified sealed
  platform-image provider.  Rextio deliberately has no permissive default
  provider: if an APFS/SSV anchor cannot be verified, the production build
  fails closed before launching Cargo.

Receipts and tree collection live in ``toolchain_support_lock``.  The private
paths here are execution capabilities and must never be serialized into a
public signing request.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
from typing import Literal, Protocol


FULL_C6_READ_SANDBOX_DOMAIN = "rextio.full-c6-read-sandbox.v1"
_SUPPORTED_TARGETS = frozenset(
    {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RULES = 256
_MAX_PATH_BYTES = 4096

# Linux x86_64 syscall numbers.  Full C6 does not support another Linux ABI.
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1
_AUDIT_ARCH_X86_64 = 0xC000003E

# x86_64 socket and async-I/O syscall numbers.  Denying socket creation and
# connection plus io_uring (which otherwise bypasses ordinary syscall filters)
# makes the child network boundary independent of Cargo's offline flag.
_NETWORK_SYSCALLS_X86_64 = frozenset(
    {
        41,  # socket
        42,  # connect
        43,  # accept
        44,  # sendto
        45,  # recvfrom
        46,  # sendmsg
        47,  # recvmsg
        49,  # bind
        50,  # listen
        53,  # socketpair
        288,  # accept4
        299,  # recvmmsg
        307,  # sendmmsg
        425,  # io_uring_setup
        426,  # io_uring_enter
        427,  # io_uring_register
    }
)

_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MAKE_CHAR = 1 << 6
_LL_MAKE_DIR = 1 << 7
_LL_MAKE_REG = 1 << 8
_LL_MAKE_SOCK = 1 << 9
_LL_MAKE_FIFO = 1 << 10
_LL_MAKE_BLOCK = 1 << 11
_LL_MAKE_SYM = 1 << 12
_LL_REFER = 1 << 13
_LL_TRUNCATE = 1 << 14
_LANDLOCK_HANDLED_FS_V3 = (1 << 15) - 1
_LANDLOCK_READ = _LL_READ_FILE | _LL_READ_DIR
_LANDLOCK_READ_EXECUTE = _LANDLOCK_READ | _LL_EXECUTE
_LANDLOCK_READ_WRITE = _LANDLOCK_HANDLED_FS_V3

SandboxAccess = Literal["read", "read-execute", "read-write"]
SandboxEngine = Literal["landlock-v3", "macos-sandbox-exec-v1"]


class FullC6ReadSandboxError(RuntimeError):
    """The strict read sandbox is unavailable, malformed, or not enforceable."""


@dataclass(frozen=True, slots=True)
class SandboxPathRule:
    """One private, exact path capability granted to the build process tree."""

    path: Path
    access: SandboxAccess
    logical_role: str

    def __post_init__(self) -> None:
        path = Path(self.path)
        if not path.is_absolute() or len(os.fsencode(path)) > _MAX_PATH_BYTES:
            raise ValueError("Full C6 sandbox path must be a bounded absolute path")
        if self.access not in {"read", "read-execute", "read-write"}:
            raise ValueError("Full C6 sandbox access is invalid")
        if (
            type(self.logical_role) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,127}", self.logical_role) is None
        ):
            raise ValueError("Full C6 sandbox logical role is invalid")
        object.__setattr__(self, "path", path)


@dataclass(frozen=True, slots=True)
class MacOSPlatformAnchor:
    """Digest-only receipt for an externally verified Apple sealed image."""

    seal_sha256: str
    os_build: str
    provider: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.seal_sha256) is None:
            raise ValueError("macOS platform seal SHA-256 is invalid")
        for value, label in ((self.os_build, "OS build"), (self.provider, "provider")):
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(character) < 32 for character in value)
            ):
                raise ValueError(f"macOS platform {label} is invalid")

    @property
    def digest(self) -> str:
        payload = (
            f"rextio.macos-platform-anchor.v1\0{self.provider}\0"
            f"{self.os_build}\0{self.seal_sha256}"
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class MacOSPlatformAnchorProvider(Protocol):
    """Provider that verifies, rather than merely reports, the active SSV seal."""

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        """Raise unless the active Apple platform image equals ``expected``."""


class UnavailableMacOSPlatformAnchorProvider:
    """Fail-closed default until a portable APFS/SSV verifier is installed."""

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        del expected
        raise FullC6ReadSandboxError(
            "Full C6 cannot verify the active macOS APFS/SSV platform seal"
        )


@dataclass(frozen=True, slots=True)
class FullC6ReadSandboxPlan:
    """Validated private launch plan for one exact target and path allowlist."""

    target_triple: str
    engine: SandboxEngine
    rules: tuple[SandboxPathRule, ...]
    platform_anchor_sha256: str

    def __post_init__(self) -> None:
        if self.target_triple not in _SUPPORTED_TARGETS:
            raise ValueError("Full C6 sandbox target is unsupported")
        expected_engine = (
            "macos-sandbox-exec-v1"
            if self.target_triple == "aarch64-apple-darwin"
            else "landlock-v3"
        )
        if self.engine != expected_engine:
            raise ValueError("Full C6 sandbox engine does not match the target")
        rules = tuple(self.rules)
        if not rules or len(rules) > _MAX_RULES:
            raise ValueError("Full C6 sandbox rule count is outside the bound")
        if not all(type(rule) is SandboxPathRule for rule in rules):
            raise TypeError("Full C6 sandbox rule has an invalid type")
        keys = [(os.fsencode(rule.path), rule.access, rule.logical_role) for rule in rules]
        if keys != sorted(keys) or len({item[0] for item in keys}) != len(keys):
            raise ValueError("Full C6 sandbox rules are not canonical and unique")
        if _SHA256_RE.fullmatch(self.platform_anchor_sha256) is None:
            raise ValueError("Full C6 sandbox platform anchor digest is invalid")
        object.__setattr__(self, "rules", rules)

    @property
    def digest(self) -> str:
        """Bind semantic rules without exposing private absolute paths."""
        rows = [
            f"{rule.logical_role}\0{rule.access}" for rule in self.rules
        ]
        payload = (
            "rextio.full-c6-read-sandbox-plan.v1\0"
            + self.target_triple
            + "\0"
            + self.engine
            + "\0"
            + self.platform_anchor_sha256
            + "\0"
            + "\n".join(rows)
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class FullC6SandboxLaunch:
    """Command wrapper or child hook consumed by the subprocess boundary."""

    command: tuple[str, ...]
    preexec_fn: Callable[[], None] | None
    profile_sha256: str


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter)))


def build_full_c6_sandbox_plan(
    *,
    target_triple: str,
    rules: Sequence[SandboxPathRule],
    platform_anchor_sha256: str,
) -> FullC6ReadSandboxPlan:
    """Canonicalize a private rule set for one frozen Alpha target."""
    canonical = tuple(
        sorted(rules, key=lambda item: (os.fsencode(item.path), item.access, item.logical_role))
    )
    engine: SandboxEngine = (
        "macos-sandbox-exec-v1"
        if target_triple == "aarch64-apple-darwin"
        else "landlock-v3"
    )
    try:
        return FullC6ReadSandboxPlan(
            target_triple=target_triple,
            engine=engine,
            rules=canonical,
            platform_anchor_sha256=platform_anchor_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ReadSandboxError(str(exc)) from exc


def prepare_full_c6_sandbox_launch(
    plan: FullC6ReadSandboxPlan,
    command: Sequence[str],
    *,
    macos_anchor: MacOSPlatformAnchor | None = None,
    macos_anchor_provider: MacOSPlatformAnchorProvider | None = None,
    sandbox_exec: Path = Path("/usr/bin/sandbox-exec"),
    landlock_syscall: Callable[..., int] | None = None,
    landlock_prctl: Callable[..., int] | None = None,
    require_single_thread: bool = True,
    macos_profile_compiler: Callable[[Path, str], None] | None = None,
) -> FullC6SandboxLaunch:
    """Return a fail-closed launch boundary for one already-validated plan."""
    if type(plan) is not FullC6ReadSandboxPlan:
        raise FullC6ReadSandboxError("Full C6 sandbox plan has an invalid type")
    values = tuple(command)
    if (
        not values
        or len(values) > 512
        or not all(type(value) is str and value and "\0" not in value for value in values)
    ):
        raise FullC6ReadSandboxError("Full C6 sandbox command is invalid")
    _verify_rule_roots(plan.rules)
    if plan.engine == "landlock-v3":
        if sys.platform != "linux" and landlock_syscall is None:
            raise FullC6ReadSandboxError("Full C6 Landlock is unavailable on this host")
        syscall = landlock_syscall or _libc_syscall()
        prctl = landlock_prctl or _libc_prctl()
        abi = _query_landlock_abi(syscall)
        if abi < 3:
            raise FullC6ReadSandboxError("Full C6 requires Landlock ABI 3 or newer")
        if require_single_thread:
            _require_single_threaded_parent()
        hook = _landlock_preexec(plan.rules, syscall=syscall, prctl=prctl)
        return FullC6SandboxLaunch(
            command=values,
            preexec_fn=hook,
            profile_sha256=hashlib.sha256(
                f"landlock-v3+seccomp-net-v1\0{plan.digest}".encode("utf-8")
            ).hexdigest(),
        )

    if macos_anchor is None or type(macos_anchor) is not MacOSPlatformAnchor:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor is missing")
    if macos_anchor.digest != plan.platform_anchor_sha256:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor differs from the plan")
    provider = macos_anchor_provider or UnavailableMacOSPlatformAnchorProvider()
    provider.verify_active_anchor(macos_anchor)
    _verify_sandbox_exec(sandbox_exec)
    profile = _macos_profile(plan.rules)
    compiler = macos_profile_compiler or _compile_macos_profile
    compiler(sandbox_exec, profile)
    return FullC6SandboxLaunch(
        command=(os.fspath(sandbox_exec), "-p", profile, "--", *values),
        preexec_fn=None,
        profile_sha256=hashlib.sha256(profile.encode("utf-8")).hexdigest(),
    )


def _verify_rule_roots(rules: Sequence[SandboxPathRule]) -> None:
    for rule in rules:
        try:
            observed = os.lstat(rule.path)
        except OSError as exc:
            raise FullC6ReadSandboxError("Full C6 sandbox path is unavailable") from exc
        if stat.S_ISLNK(observed.st_mode) or not (
            stat.S_ISREG(observed.st_mode)
            or stat.S_ISDIR(observed.st_mode)
            or stat.S_ISCHR(observed.st_mode)
        ):
            raise FullC6ReadSandboxError("Full C6 sandbox path type is unsafe")
        if stat.S_ISCHR(observed.st_mode) and rule.logical_role != "required-device":
            raise FullC6ReadSandboxError("Full C6 sandbox device role is invalid")


def _libc_syscall() -> Callable[..., int]:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.syscall
    function.restype = ctypes.c_long
    return function


def _libc_prctl() -> Callable[..., int]:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.prctl
    function.restype = ctypes.c_int
    return function


def _query_landlock_abi(syscall: Callable[..., int]) -> int:
    ctypes.set_errno(0)
    result = syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if type(result) is not int or result < 0:
        raise FullC6ReadSandboxError("Full C6 Landlock ABI query failed")
    return result


def _landlock_preexec(
    rules: Sequence[SandboxPathRule],
    *,
    syscall: Callable[..., int],
    prctl: Callable[..., int],
) -> Callable[[], None]:
    """Create a child-only Landlock hook without importing after ``fork``."""
    frozen: list[tuple[str, int]] = []
    for rule in rules:
        observed = os.lstat(rule.path)
        frozen.append(
            (
                os.fspath(rule.path),
                _landlock_access(rule.access, directory=stat.S_ISDIR(observed.st_mode)),
            )
        )
    fixed = tuple(frozen)

    def apply() -> None:
        ruleset_data = struct.pack("=Q", _LANDLOCK_HANDLED_FS_V3)
        ruleset_buffer = ctypes.create_string_buffer(ruleset_data)
        ruleset_fd = syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.byref(ruleset_buffer),
            ctypes.c_size_t(len(ruleset_data)),
            ctypes.c_uint32(0),
        )
        if type(ruleset_fd) is not int or ruleset_fd < 0:
            raise OSError("Full C6 could not create a Landlock ruleset")
        try:
            for path, allowed in fixed:
                flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                parent_fd = os.open(path, flags)
                try:
                    attribute = struct.pack("=Qi", allowed, parent_fd)
                    buffer = ctypes.create_string_buffer(attribute)
                    result = syscall(
                        _SYS_LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        _LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(buffer),
                        ctypes.c_uint32(0),
                    )
                    if type(result) is not int or result != 0:
                        raise OSError("Full C6 could not add a Landlock path rule")
                finally:
                    os.close(parent_fd)
            if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise OSError("Full C6 could not set no_new_privs")
            if syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
                raise OSError("Full C6 could not enforce the Landlock ruleset")
            _install_network_seccomp(prctl)
        finally:
            os.close(ruleset_fd)

    return apply


def _landlock_access(access: SandboxAccess, *, directory: bool) -> int:
    if not directory:
        if access == "read":
            return _LL_READ_FILE
        if access == "read-execute":
            return _LL_READ_FILE | _LL_EXECUTE
        return _LL_READ_FILE | _LL_WRITE_FILE | _LL_TRUNCATE
    if access == "read":
        return _LANDLOCK_READ
    if access == "read-execute":
        return _LANDLOCK_READ_EXECUTE
    return _LANDLOCK_READ_WRITE


def _install_network_seccomp(prctl: Callable[..., int]) -> None:
    """Deny all socket creation/traffic and io_uring in the Linux child.

    The BPF program is deliberately small and architecture-pinned.  An
    unexpected audit architecture kills the process rather than executing an
    unfiltered syscall-number table.
    """
    # BPF_LD | BPF_W | BPF_ABS: seccomp_data.arch at offset 4.
    rows: list[tuple[int, int, int, int]] = [(0x20, 0, 0, 4)]
    # BPF_JMP | BPF_JEQ | BPF_K: continue on x86_64, otherwise kill.
    rows.append((0x15, 1, 0, _AUDIT_ARCH_X86_64))
    rows.append((0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    # Load seccomp_data.nr at offset 0.
    rows.append((0x20, 0, 0, 0))
    for number in sorted(_NETWORK_SYSCALLS_X86_64):
        rows.append((0x15, 0, 1, number))
        rows.append((0x06, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    rows.append((0x06, 0, 0, _SECCOMP_RET_ALLOW))
    filters = (_SockFilter * len(rows))(*(_SockFilter(*row) for row in rows))
    program = _SockFprog(len=len(rows), filter=filters)
    if prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError("Full C6 could not enforce the no-network seccomp filter")


def _require_single_threaded_parent() -> None:
    """Keep the child hook outside Python's documented threaded hazard."""
    task_root = Path("/proc/self/task")
    try:
        tasks = tuple(task_root.iterdir())
    except OSError as exc:
        raise FullC6ReadSandboxError(
            "Full C6 cannot verify a single-threaded Landlock launcher"
        ) from exc
    if len(tasks) != 1:
        raise FullC6ReadSandboxError(
            "Full C6 Landlock launch requires a single-threaded process"
        )


def _verify_sandbox_exec(path: Path) -> None:
    if path != Path("/usr/bin/sandbox-exec") or not path.is_absolute():
        raise FullC6ReadSandboxError("Full C6 sandbox-exec path is not canonical")
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 sandbox-exec is unavailable") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise FullC6ReadSandboxError("Full C6 sandbox-exec is unsafe")
    if not os.access(path, os.X_OK):
        raise FullC6ReadSandboxError("Full C6 sandbox-exec is not executable")


def _macos_profile(rules: Sequence[SandboxPathRule]) -> str:
    lines = [
        "(version 1)",
        "(deny default)",
        "(deny network*)",
        "(allow process-fork)",
        "(allow signal (target self))",
        "(allow sysctl-read)",
    ]
    for rule in rules:
        path = _sandbox_literal(os.fspath(rule.path))
        if rule.access == "read":
            lines.append(f"(allow file-read* (subpath {path}))")
        elif rule.access == "read-execute":
            lines.append(f"(allow file-read* process-exec (subpath {path}))")
        else:
            lines.append(f"(allow file-read* file-write* (subpath {path}))")
    return "\n".join(lines) + "\n"


def _compile_macos_profile(sandbox_exec: Path, profile: str) -> None:
    """Require sandbox-exec to parse and enforce the exact generated profile."""
    probe = Path("/usr/bin/true")
    try:
        observed = os.lstat(probe)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 sandbox profile probe is unavailable") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise FullC6ReadSandboxError("Full C6 sandbox profile probe is unsafe")
    probe_profile = profile + f"(allow file-read* process-exec (literal {_sandbox_literal(str(probe))}))\n"
    try:
        completed = subprocess.run(
            [os.fspath(sandbox_exec), "-p", probe_profile, "--", os.fspath(probe)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
            env={},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FullC6ReadSandboxError("Full C6 sandbox profile could not be compiled") from exc
    if completed.returncode != 0:
        raise FullC6ReadSandboxError("Full C6 sandbox profile failed its enforcement probe")


def _sandbox_literal(value: str) -> str:
    if "\0" in value or any(ord(character) < 32 for character in value):
        raise FullC6ReadSandboxError("Full C6 sandbox path cannot be encoded safely")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def canonical_platform_context(target_triple: str) -> tuple[str, ...]:
    """Return bounded OS context; context never substitutes for support bytes."""
    if target_triple not in _SUPPORTED_TARGETS:
        raise FullC6ReadSandboxError("Full C6 sandbox target is unsupported")
    values = (
        platform.system(),
        platform.machine(),
        platform.release(),
        platform.version(),
    )
    if any(
        not value
        or len(value) > 1024
        or any(ord(character) < 32 for character in value)
        for value in values
    ):
        raise FullC6ReadSandboxError("Full C6 platform context is invalid")
    return values


__all__ = [
    "FULL_C6_READ_SANDBOX_DOMAIN",
    "FullC6ReadSandboxError",
    "FullC6ReadSandboxPlan",
    "FullC6SandboxLaunch",
    "MacOSPlatformAnchor",
    "MacOSPlatformAnchorProvider",
    "SandboxPathRule",
    "UnavailableMacOSPlatformAnchorProvider",
    "build_full_c6_sandbox_plan",
    "canonical_platform_context",
    "prepare_full_c6_sandbox_launch",
]
