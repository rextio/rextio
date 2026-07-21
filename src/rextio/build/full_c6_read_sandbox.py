"""Deny-by-default filesystem-read sandbox primitives for strict Full C6.

The Full C6 build is allowed to claim a complete input closure only when the
kernel prevents Cargo, build scripts, rustc, and the linker from reading an
unbound host file.  This module provides that enforcement boundary for the two
frozen Alpha hosts:

* Linux x86_64 uses a bubblewrap mount/user/PID/UTS/IPC/network namespace and
  a module-owned sealed seccomp memfd that bubblewrap installs after setup.  A
  support-locked isolated CPython helper then installs Landlock inside that
  completed namespace immediately before replacing itself with Cargo.
* macOS arm64 uses ``sandbox-exec`` only with a separately verified sealed
  platform-image provider.  Rextio deliberately has no permissive default
  provider: if an APFS/SSV anchor cannot be verified, the production build
  fails closed before launching Cargo.

Receipts and tree collection live in ``toolchain_support_lock``.  The private
paths here are execution capabilities and must never be serialized into a
public signing request.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import struct
import subprocess
import sys
from typing import Literal, Protocol

from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_LAUNCHER,
    FULL_C6_LINUX_PYTHON,
    FullC6LinuxLauncherError,
    canonical_linux_payload_environment,
    linux_payload_environment_digest,
)


FULL_C6_READ_SANDBOX_DOMAIN = "rextio.full-c6-read-sandbox.v1"
_SUPPORTED_TARGETS = frozenset(
    {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RULES = 256
_MAX_PATH_BYTES = 4096
_PLATFORM_PROBE_MAX_BYTES = 1024 * 1024
_APPLE_SNAPSHOT_RE = re.compile(r"^com\.apple\.os\.update-([0-9A-F]{64})$")
_APPLE_OS_BUILD_RE = re.compile(r"^[0-9]{2}[A-Z][0-9A-Za-z]{1,31}$")
_APPLE_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_APPLE_SYSTEM_SNAPSHOT_DEVICE_RE = re.compile(r"^disk[0-9]+s[0-9]+s[0-9]+$")

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000
_MFD_CLOEXEC = 0x0001
_MFD_ALLOW_SEALING = 0x0002
_F_ADD_SEALS = 1033
_F_GET_SEALS = 1034
_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_FULL_C6_SECCOMP_REQUIRED_SEALS = (
    _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_SEAL
)
_LINUX_SECCOMP_LEASE_TOKEN = object()

# x86_64 socket, System V/POSIX IPC, and async-I/O syscall numbers.  This
# filter is handed to bubblewrap rather than installed in Python's preexec
# hook: bwrap must be able to create its namespace plumbing before the filter
# becomes active.  The new network and IPC namespaces remain independently
# mandatory defense-in-depth boundaries.
_DENIED_PAYLOAD_SYSCALLS_X86_64 = frozenset(
    {
        29,  # shmget
        30,  # shmat
        31,  # shmctl
        41,  # socket
        42,  # connect
        43,  # accept
        44,  # sendto
        45,  # recvfrom
        46,  # sendmsg
        47,  # recvmsg
        48,  # shutdown
        49,  # bind
        50,  # listen
        51,  # getsockname
        52,  # getpeername
        53,  # socketpair
        54,  # setsockopt
        55,  # getsockopt
        64,  # semget
        65,  # semop
        66,  # semctl
        67,  # shmdt
        68,  # msgget
        69,  # msgsnd
        70,  # msgrcv
        71,  # msgctl
        240,  # mq_open
        241,  # mq_unlink
        242,  # mq_timedsend
        243,  # mq_timedreceive
        244,  # mq_notify
        245,  # mq_getsetattr
        288,  # accept4
        299,  # recvmmsg
        307,  # sendmmsg
        425,  # io_uring_setup
        426,  # io_uring_enter
        427,  # io_uring_register
    }
)

_LINUX_BWRAP_FLAGS = (
    "--unshare-all",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-uts",
    "--new-session",
    "--die-with-parent",
    "--clearenv",
)
_LINUX_PROJECT_DESTINATION = "/rextio/project"
_LINUX_BUILD_DESTINATION = "/rextio/build"
_LINUX_TOOLCHAIN_DESTINATION = "/rextio/toolchain"
_LINUX_SUPPORT_DESTINATION = "/rextio/support"
_LINUX_RUNTIME_LOADER_DESTINATION = "/lib64/ld-linux-x86-64.so.2"
_LINUX_PYTHON_STDLIB_DESTINATION = "/rextio/toolchain/lib/python3.11"
_LINUX_LAUNCHER_DESTINATION = FULL_C6_LINUX_LAUNCHER
_LINUX_ROLE_LEAF_RE = re.compile(r"^[a-z][a-z0-9-]{0,95}$")
_MAX_BUBBLEWRAP_BYTES = 64 * 1024 * 1024

SandboxAccess = Literal["read", "read-execute", "read-write"]
SandboxEngine = Literal[
    "linux-bwrap-landlock-v1", "macos-sandbox-exec-v1"
]


class FullC6ReadSandboxError(RuntimeError):
    """The strict read sandbox is unavailable, malformed, or not enforceable."""


class LinuxSeccompLease:
    """Process-local ownership lease for one exact sealed seccomp memfd.

    Instances can only be initialized by this module's Linux-gated factory.
    The descriptor remains live until the launch boundary closes the lease
    after spawning bubblewrap.  It is never serialized or reconstructed.
    """

    __slots__ = ("_closed", "_fd", "_identity", "_owner_pid", "_token")

    def __init__(
        self,
        token: object,
        /,
        *,
        fd: int,
        owner_pid: int,
        identity: tuple[int, int, int],
    ) -> None:
        if token is not _LINUX_SECCOMP_LEASE_TOKEN:
            raise TypeError(
                "Linux seccomp leases must be created by the Full C6 factory"
            )
        self._token = token
        self._fd = fd
        self._owner_pid = owner_pid
        self._identity = identity
        self._closed = False

    @property
    def closed(self) -> bool:
        """Return whether this process-local descriptor lease was closed."""
        return bool(getattr(self, "_closed", True))

    def fileno(self) -> int:
        """Return the live descriptor or fail closed for an invalid lease."""
        if (
            getattr(self, "_token", None) is not _LINUX_SECCOMP_LEASE_TOKEN
            or self.closed
        ):
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp lease is invalid or closed"
            )
        descriptor = getattr(self, "_fd", -1)
        if type(descriptor) is not int or descriptor < 3:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp lease descriptor is invalid"
            )
        return descriptor

    def close(self) -> None:
        """Close the owned descriptor exactly once without closing a reused FD."""
        token = getattr(self, "_token", None)
        descriptor = getattr(self, "_fd", -1)
        identity = getattr(self, "_identity", None)
        if token is not _LINUX_SECCOMP_LEASE_TOKEN or self.closed:
            return
        self._closed = True
        self._fd = -1
        if (
            type(descriptor) is not int
            or descriptor < 3
            or type(identity) is not tuple
            or len(identity) != 3
        ):
            return
        try:
            observed = _fstat_descriptor(descriptor)
        except OSError:
            return
        observed_identity = (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
        )
        if observed_identity != identity:
            return
        try:
            _close_descriptor(descriptor)
        except OSError:
            return

    def __enter__(self) -> LinuxSeccompLease:
        self.fileno()
        return self

    def __exit__(
        self,
        exc_type: object | None,
        exc_value: object | None,
        traceback: object | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # Interpreter shutdown and deliberately forged test objects may
            # have only a subset of slots.  Destruction remains best effort.
            return


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
    """Digest-only receipt for an externally verified Apple sealed snapshot."""

    authenticated_snapshot_id: str
    snapshot_uuid: str
    os_build: str
    provider: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.authenticated_snapshot_id) is None:
            raise ValueError("macOS authenticated snapshot id is invalid")
        if _APPLE_UUID_RE.fullmatch(self.snapshot_uuid) is None:
            raise ValueError("macOS authenticated snapshot UUID is invalid")
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
        """Return the path-free authenticated snapshot receipt digest."""
        payload = (
            f"rextio.macos-platform-anchor.v1\0{self.provider}\0"
            f"{self.os_build}\0{self.authenticated_snapshot_id}\0{self.snapshot_uuid}"
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class MacOSPlatformAnchorProvider(Protocol):
    """Provider that verifies, rather than merely reports, the active SSV seal."""

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        """Raise unless the active Apple platform image equals ``expected``."""


class UnavailableMacOSPlatformAnchorProvider:
    """Explicit fail-closed provider used by negative tests and policy gates."""

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        """Reject because no authenticated snapshot provider exists."""
        del expected
        raise FullC6ReadSandboxError(
            "Full C6 cannot verify the active macOS APFS/SSV platform seal"
        )


class AppleAPFSPlatformAnchorProvider:
    """Verify the active read-only sealed APFS system snapshot via diskutil."""

    def verify_active_anchor(self, expected: MacOSPlatformAnchor) -> None:
        """Recollect and compare the active authenticated APFS snapshot."""
        if type(expected) is not MacOSPlatformAnchor:
            raise FullC6ReadSandboxError("Full C6 macOS platform anchor is invalid")
        observed = capture_active_macos_platform_anchor()
        if observed != expected:
            raise FullC6ReadSandboxError(
                "Full C6 active macOS APFS/SSV platform seal changed"
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
        expected_engine: SandboxEngine = (
            "macos-sandbox-exec-v1"
            if self.target_triple == "aarch64-apple-darwin"
            else "linux-bwrap-landlock-v1"
        )
        if self.engine != expected_engine:
            raise ValueError("Full C6 sandbox engine does not match the target")
        rules = tuple(self.rules)
        if not rules or len(rules) > _MAX_RULES:
            raise ValueError("Full C6 sandbox rule count is outside the bound")
        if not all(type(rule) is SandboxPathRule for rule in rules):
            raise TypeError("Full C6 sandbox rule has an invalid type")
        keys = [(rule.logical_role, rule.access, os.fsencode(rule.path)) for rule in rules]
        if keys != sorted(keys) or len({item[2] for item in keys}) != len(keys):
            raise ValueError("Full C6 sandbox rules are not canonical and unique")
        if self.target_triple == "x86_64-unknown-linux-gnu":
            _validate_linux_rules(rules)
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
    """Private command boundary consumed by the strict subprocess launcher.

    ``pass_fds`` is an exact ownership contract, not a hint.  The executor
    must pass precisely these descriptors to ``Popen``, keep them open until
    spawn returns, close them afterwards, use ``stdin=DEVNULL`` and ``env={}``
    for bwrap itself, and never serialize ``command`` because it contains
    private host mount sources.  ``--clearenv`` plus closed ``--setenv`` rows
    separately construct the post-namespace helper/Cargo environment.
    Linux holds a module-created, sealed, offset-zero seccomp lease strongly
    until the executor calls :meth:`close` after ``Popen`` returns.
    """

    command: tuple[str, ...]
    preexec_fn: Callable[[], None] | None
    profile_sha256: str
    pass_fds: tuple[int, ...]
    seccomp_sha256: str | None = None
    seccomp_lease: LinuxSeccompLease | None = None

    def __post_init__(self) -> None:
        if self.seccomp_lease is None:
            if self.pass_fds or self.seccomp_sha256 is not None:
                raise ValueError(
                    "Full C6 launch has an invalid seccomp capability contract"
                )
            return
        try:
            descriptor, observed_sha256 = _verify_linux_seccomp_lease(
                self.seccomp_lease
            )
        except FullC6ReadSandboxError as exc:
            raise ValueError("Full C6 launch seccomp lease is invalid") from exc
        if (
            self.pass_fds != (descriptor,)
            or type(self.seccomp_sha256) is not str
            or _SHA256_RE.fullmatch(self.seccomp_sha256) is None
            or self.seccomp_sha256 != observed_sha256
        ):
            raise ValueError(
                "Full C6 launch seccomp receipt or descriptor contract differs"
            )

    def close(self) -> None:
        """Release private launch capabilities after the subprocess spawns."""
        if self.seccomp_lease is not None:
            self.seccomp_lease.close()

    def __enter__(self) -> FullC6SandboxLaunch:
        return self

    def __exit__(
        self,
        exc_type: object | None,
        exc_value: object | None,
        traceback: object | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()


def build_full_c6_sandbox_plan(
    *,
    target_triple: str,
    rules: Sequence[SandboxPathRule],
    platform_anchor_sha256: str,
) -> FullC6ReadSandboxPlan:
    """Canonicalize a private rule set for one frozen Alpha target."""
    canonical = tuple(
        sorted(rules, key=lambda item: (item.logical_role, item.access, os.fsencode(item.path)))
    )
    engine: SandboxEngine = (
        "macos-sandbox-exec-v1"
        if target_triple == "aarch64-apple-darwin"
        else "linux-bwrap-landlock-v1"
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
    bubblewrap: Path = Path("/usr/bin/bwrap"),
    linux_seccomp_lease: LinuxSeccompLease | None = None,
    linux_payload_environment: Mapping[str, str] | None = None,
    bubblewrap_verifier: Callable[[Path], str] | None = None,
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
    if plan.engine == "linux-bwrap-landlock-v1":
        if sys.platform != "linux" and bubblewrap_verifier is None:
            raise FullC6ReadSandboxError(
                "Full C6 Linux namespace sandbox is unavailable on this host"
            )
        _verify_linux_rule_types(plan.rules)
        bwrap_path = Path(bubblewrap)
        verifier = bubblewrap_verifier or _verify_bubblewrap
        bwrap_sha256 = verifier(bwrap_path)
        if _SHA256_RE.fullmatch(bwrap_sha256) is None:
            raise FullC6ReadSandboxError(
                "Full C6 bubblewrap verifier returned an invalid digest"
            )
        seccomp_fd, seccomp_sha256 = _verify_linux_seccomp_lease(
            linux_seccomp_lease
        )
        if linux_payload_environment is None:
            raise FullC6ReadSandboxError(
                "Full C6 Linux payload environment is missing"
            )
        try:
            environment_rows = canonical_linux_payload_environment(
                linux_payload_environment
            )
            environment_sha256 = linux_payload_environment_digest(
                linux_payload_environment
            )
        except FullC6LinuxLauncherError as exc:
            raise FullC6ReadSandboxError(str(exc)) from exc
        command_wrapper, virtual_rows = _linux_bubblewrap_command(
            plan.rules,
            values,
            bubblewrap=bwrap_path,
            seccomp_fd=seccomp_fd,
            environment_rows=environment_rows,
            environment_sha256=environment_sha256,
        )
        profile_payload = (
            "rextio.full-c6-linux-sandbox-profile.v1\0"
            + plan.digest
            + "\0"
            + bwrap_sha256
            + "\0"
            + seccomp_sha256
            + "\0"
            + "\n".join(
                (
                    *_LINUX_BWRAP_FLAGS,
                    "fresh-proc-v1\0/proc",
                    "fresh-dev-v1\0/dev",
                    "fresh-tmpfs-v1\0/tmp",
                    "kernel-rng-getrandom-v1",
                    *(f"environment\0{name}\0{value}" for name, value in environment_rows),
                    *virtual_rows,
                )
            )
        ).encode("utf-8")
        assert linux_seccomp_lease is not None
        return FullC6SandboxLaunch(
            command=command_wrapper,
            preexec_fn=None,
            profile_sha256=hashlib.sha256(profile_payload).hexdigest(),
            pass_fds=(seccomp_fd,),
            seccomp_sha256=seccomp_sha256,
            seccomp_lease=linux_seccomp_lease,
        )

    if linux_seccomp_lease is not None:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease is invalid for the macOS sandbox"
        )
    if macos_anchor is None or type(macos_anchor) is not MacOSPlatformAnchor:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor is missing")
    if macos_anchor.digest != plan.platform_anchor_sha256:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor differs from the plan")
    provider = macos_anchor_provider or AppleAPFSPlatformAnchorProvider()
    provider.verify_active_anchor(macos_anchor)
    _verify_sandbox_exec(sandbox_exec)
    profile = _macos_profile(plan.rules)
    compiler = macos_profile_compiler or _compile_macos_profile
    compiler(sandbox_exec, profile)
    return FullC6SandboxLaunch(
        command=(os.fspath(sandbox_exec), "-p", profile, "--", *values),
        preexec_fn=None,
        profile_sha256=hashlib.sha256(profile.encode("utf-8")).hexdigest(),
        pass_fds=(),
        seccomp_sha256=None,
        seccomp_lease=None,
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
        if stat.S_ISCHR(observed.st_mode) and rule.access == "read-execute":
            raise FullC6ReadSandboxError("Full C6 sandbox device cannot be executable")


def _validate_linux_rules(rules: Sequence[SandboxPathRule]) -> None:
    """Validate the closed Linux namespace vocabulary without reading paths."""
    project = [rule for rule in rules if rule.logical_role == "project-root"]
    build = [rule for rule in rules if rule.logical_role == "build-root"]
    loaders = [
        rule for rule in rules if rule.logical_role == "runtime-loader-mirror"
    ]
    toolchain = [
        rule for rule in rules if rule.logical_role.startswith("toolchain-")
    ]
    support = [
        rule for rule in rules if rule.logical_role.startswith("support-")
    ]
    launcher = [
        rule for rule in rules if rule.logical_role.startswith("launcher-support-")
    ]
    recognized = {
        id(rule)
        for rule in (*project, *build, *loaders, *toolchain, *support, *launcher)
    }
    if len(recognized) != len(rules):
        raise ValueError("Full C6 Linux sandbox contains an unknown semantic role")
    if len(project) != 1 or project[0].access != "read":
        raise ValueError("Full C6 Linux sandbox requires one read-only project-root")
    if len(build) != 1 or build[0].access != "read-write":
        raise ValueError("Full C6 Linux sandbox requires one writable build-root")
    if len(loaders) != 1 or loaders[0].access != "read-execute":
        raise ValueError(
            "Full C6 Linux sandbox requires one executable runtime-loader-mirror"
        )
    if not toolchain or not support:
        raise ValueError(
            "Full C6 Linux sandbox requires toolchain and support leaves"
        )
    required_special = {
        "toolchain-python311": "read-execute",
        "toolchain-python311-stdlib": "read",
        "toolchain-linker": "read-execute",
        "toolchain-rustc": "read-execute",
        "support-landlock-launcher": "read",
        "support-runtime-libs": "read",
    }
    by_role = {rule.logical_role: rule for rule in rules}
    for role, access in required_special.items():
        rule = by_role.get(role)
        if rule is None or rule.access != access:
            raise ValueError(
                "Full C6 Linux sandbox is missing a fixed launcher input"
            )
    for rule, prefix in (
        *((rule, "toolchain-") for rule in toolchain),
        *((rule, "support-") for rule in support),
        *((rule, "launcher-support-") for rule in launcher),
    ):
        leaf = rule.logical_role.removeprefix(prefix)
        if _LINUX_ROLE_LEAF_RE.fullmatch(leaf) is None:
            raise ValueError("Full C6 Linux sandbox leaf role is invalid")
        if rule.access == "read-write":
            raise ValueError(
                "Full C6 Linux toolchain/support inputs must be read-only"
            )
    destinations = tuple(_linux_rule_destination(rule) for rule in rules)
    exposed = tuple(destination for destination in destinations if destination is not None)
    if len(set(exposed)) != len(exposed):
        raise ValueError("Full C6 Linux sandbox virtual destinations collide")


def _verify_linux_rule_types(rules: Sequence[SandboxPathRule]) -> None:
    for rule in rules:
        try:
            observed = os.lstat(rule.path)
        except OSError as exc:
            raise FullC6ReadSandboxError(
                "Full C6 Linux sandbox path is unavailable"
            ) from exc
        if rule.logical_role in {"project-root", "build-root"} and not stat.S_ISDIR(
            observed.st_mode
        ):
            raise FullC6ReadSandboxError(
                "Full C6 Linux project/build mapping must be a directory"
            )
        if rule.logical_role in {
            "toolchain-python311-stdlib",
            "support-runtime-libs",
        } and not stat.S_ISDIR(observed.st_mode):
            raise FullC6ReadSandboxError(
                "Full C6 Linux runtime tree mapping must be a directory"
            )
        if rule.logical_role in {
            "toolchain-python311",
            "toolchain-linker",
            "toolchain-rustc",
            "support-landlock-launcher",
        } and not stat.S_ISREG(observed.st_mode):
            raise FullC6ReadSandboxError(
                "Full C6 Linux launcher mapping must be a regular file"
            )
        if rule.logical_role == "runtime-loader-mirror" and not stat.S_ISREG(
            observed.st_mode
        ):
            raise FullC6ReadSandboxError(
                "Full C6 Linux runtime loader must be a regular file"
            )


def _linux_rule_destination(rule: SandboxPathRule) -> str | None:
    if rule.logical_role == "project-root":
        return _LINUX_PROJECT_DESTINATION
    if rule.logical_role == "build-root":
        return _LINUX_BUILD_DESTINATION
    if rule.logical_role == "runtime-loader-mirror":
        return _LINUX_RUNTIME_LOADER_DESTINATION
    if rule.logical_role == "toolchain-python311":
        return FULL_C6_LINUX_PYTHON
    if rule.logical_role == "toolchain-python311-stdlib":
        return _LINUX_PYTHON_STDLIB_DESTINATION
    if rule.logical_role == "toolchain-linker":
        return "/rextio/toolchain/bin/linker"
    if rule.logical_role == "toolchain-rustc":
        return "/rextio/toolchain/bin/rustc"
    if rule.logical_role == "support-landlock-launcher":
        return _LINUX_LAUNCHER_DESTINATION
    if rule.logical_role == "support-runtime-libs":
        return "/rextio/support/runtime-libs"
    if rule.logical_role.startswith("toolchain-"):
        leaf = rule.logical_role.removeprefix("toolchain-")
        return f"{_LINUX_TOOLCHAIN_DESTINATION}/{leaf}"
    if rule.logical_role.startswith("support-"):
        leaf = rule.logical_role.removeprefix("support-")
        return f"{_LINUX_SUPPORT_DESTINATION}/{leaf}"
    if rule.logical_role.startswith("launcher-support-"):
        return None
    raise FullC6ReadSandboxError(
        "Full C6 Linux sandbox contains an unknown semantic role"
    )


def _linux_bubblewrap_command(
    rules: Sequence[SandboxPathRule],
    payload: tuple[str, ...],
    *,
    bubblewrap: Path,
    seccomp_fd: int | None,
    environment_rows: tuple[tuple[str, str], ...],
    environment_sha256: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if seccomp_fd is None:
        raise FullC6ReadSandboxError("Full C6 Linux seccomp descriptor is missing")
    mappings = sorted(
        (
            (destination, rule)
            for rule in rules
            if (destination := _linux_rule_destination(rule)) is not None
        ),
        key=lambda item: (_linux_mapping_rank(item[1]), item[0]),
    )
    executable = _canonical_linux_payload_executable(payload[0])
    executable_allowed = False
    for destination, rule in mappings:
        if rule.access != "read-execute" or not (
            rule.logical_role.startswith("toolchain-")
            or rule.logical_role.startswith("support-")
        ):
            continue
        if executable == destination or executable.startswith(destination + "/"):
            executable_allowed = True
            break
    if not executable_allowed:
        raise FullC6ReadSandboxError(
            "Full C6 Linux payload executable is not a mapped executable input"
        )

    arguments: list[str] = [os.fspath(bubblewrap), *_LINUX_BWRAP_FLAGS]
    for name, value in environment_rows:
        arguments.extend(("--setenv", name, value))
    arguments.extend(("--proc", "/proc"))
    arguments.extend(("--dev", "/dev"))
    arguments.extend(("--tmpfs", "/tmp"))
    arguments.extend(("--dir", "/rextio"))
    arguments.extend(("--dir", _LINUX_TOOLCHAIN_DESTINATION))
    arguments.extend(("--dir", "/rextio/toolchain/bin"))
    arguments.extend(("--dir", "/rextio/toolchain/lib"))
    arguments.extend(("--dir", _LINUX_SUPPORT_DESTINATION))
    arguments.extend(("--dir", "/rextio/support/rextio"))
    if any(
        destination == _LINUX_RUNTIME_LOADER_DESTINATION
        for destination, _rule in mappings
    ):
        arguments.extend(("--dir", "/lib64"))

    virtual_rows: list[str] = []
    for destination, rule in mappings:
        operation = "--bind" if rule.logical_role == "build-root" else "--ro-bind"
        arguments.extend((operation, os.fspath(rule.path), destination))
        virtual_rows.append(
            f"{rule.logical_role}\0{rule.access}\0{operation}\0{destination}"
        )
    for rule in sorted(
        (item for item in rules if _linux_rule_destination(item) is None),
        key=lambda item: (item.logical_role, item.access),
    ):
        virtual_rows.append(
            f"{rule.logical_role}\0{rule.access}\0pre-namespace-only"
        )
    arguments.extend(("--dir", "/rextio/build/home"))
    arguments.extend(("--dir", "/rextio/build/cargo-home"))
    arguments.extend(("--dir", "/rextio/build/target"))
    arguments.extend(("--chdir", _LINUX_PROJECT_DESTINATION))
    arguments.extend(("--seccomp", str(seccomp_fd)))
    arguments.extend(
        (
            "--",
            FULL_C6_LINUX_PYTHON,
            "-I",
            "-B",
            "-S",
            FULL_C6_LINUX_LAUNCHER,
            "--environment-sha256",
            environment_sha256,
            "--",
            *payload,
        )
    )
    return tuple(arguments), tuple(virtual_rows)


def _linux_mapping_rank(rule: SandboxPathRule) -> int:
    if rule.logical_role == "project-root":
        return 0
    if rule.logical_role == "build-root":
        return 1
    if rule.logical_role.startswith("toolchain-"):
        return 2
    if rule.logical_role.startswith("support-"):
        return 3
    if rule.logical_role == "runtime-loader-mirror":
        return 4
    raise FullC6ReadSandboxError("Full C6 Linux mapping role is invalid")


def _canonical_linux_payload_executable(value: str) -> str:
    if (
        not value.startswith("/")
        or value != os.path.normpath(value)
        or len(os.fsencode(value)) > _MAX_PATH_BYTES
    ):
        raise FullC6ReadSandboxError(
            "Full C6 Linux payload executable must be a canonical absolute path"
        )
    return value


def linux_full_c6_seccomp_program() -> bytes:
    """Return the exact x86_64 BPF rows that bwrap installs post-namespace."""
    # BPF_LD | BPF_W | BPF_ABS: seccomp_data.arch at offset 4.
    rows: list[tuple[int, int, int, int]] = [(0x20, 0, 0, 4)]
    # Continue on x86_64; kill before interpreting another ABI's syscall table.
    rows.append((0x15, 1, 0, _AUDIT_ARCH_X86_64))
    rows.append((0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    # BPF_LD | BPF_W | BPF_ABS: seccomp_data.nr at offset 0.
    rows.append((0x20, 0, 0, 0))
    # Reject the x32 ABI range before matching the ordinary x86_64 table.
    rows.append((0x35, 0, 1, _X32_SYSCALL_BIT))
    rows.append((0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    for number in sorted(_DENIED_PAYLOAD_SYSCALLS_X86_64):
        rows.append((0x15, 0, 1, number))
        rows.append((0x06, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    rows.append((0x06, 0, 0, _SECCOMP_RET_ALLOW))
    return b"".join(struct.pack("=HBBI", *row) for row in rows)


def create_linux_full_c6_seccomp_lease() -> LinuxSeccompLease:
    """Create and seal the exact Linux Full C6 seccomp filter memfd."""
    if not _is_linux_platform():
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp memfd is unavailable on this host"
        )
    descriptor: int | None = None
    try:
        descriptor = _memfd_create(
            "rextio-full-c6-seccomp",
            _MFD_CLOEXEC | _MFD_ALLOW_SEALING,
        )
        if type(descriptor) is not int or descriptor < 3:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp memfd descriptor is invalid"
            )
        _write_exact_descriptor(
            descriptor,
            linux_full_c6_seccomp_program(),
        )
        if _seek_descriptor(descriptor, 0, os.SEEK_SET) != 0:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp memfd offset cannot be reset"
            )
        seal_result = _fcntl_descriptor(
            descriptor,
            _F_ADD_SEALS,
            _FULL_C6_SECCOMP_REQUIRED_SEALS,
        )
        if type(seal_result) is not int or seal_result != 0:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp memfd sealing failed"
            )
        identity, _digest = _inspect_linux_seccomp_descriptor(descriptor)
        owner_pid = _process_id()
        if type(owner_pid) is not int or owner_pid <= 0:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp lease owner is invalid"
            )
        lease = LinuxSeccompLease(
            _LINUX_SECCOMP_LEASE_TOKEN,
            fd=descriptor,
            owner_pid=owner_pid,
            identity=identity,
        )
        descriptor = None
        return lease
    except FullC6ReadSandboxError:
        if descriptor is not None:
            _close_descriptor_quietly(descriptor)
        raise
    except (OSError, ValueError) as exc:
        if descriptor is not None:
            _close_descriptor_quietly(descriptor)
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp memfd cannot be created and sealed"
        ) from exc


def _verify_linux_seccomp_lease(
    lease: LinuxSeccompLease | None,
) -> tuple[int, str]:
    if type(lease) is not LinuxSeccompLease:
        raise FullC6ReadSandboxError(
            "Full C6 Linux requires a typed sealed seccomp lease"
        )
    try:
        token = lease._token
        closed = lease._closed
        descriptor = lease._fd
        owner_pid = lease._owner_pid
        identity = lease._identity
    except AttributeError as exc:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease is forged or incomplete"
        ) from exc
    if (
        token is not _LINUX_SECCOMP_LEASE_TOKEN
        or type(closed) is not bool
        or closed
        or type(descriptor) is not int
        or descriptor < 3
        or type(owner_pid) is not int
        or owner_pid != _process_id()
        or type(identity) is not tuple
        or len(identity) != 3
        or not all(type(value) is int for value in identity)
    ):
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease is forged, stale, or closed"
        )
    _observed_identity, digest = _inspect_linux_seccomp_descriptor(
        descriptor,
        expected_identity=identity,
    )
    return descriptor, digest


def _inspect_linux_seccomp_descriptor(
    descriptor: int,
    *,
    expected_identity: tuple[int, int, int] | None = None,
) -> tuple[tuple[int, int, int], str]:
    expected = linux_full_c6_seccomp_program()
    try:
        observed = _fstat_descriptor(descriptor)
    except OSError as exc:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease descriptor is unavailable"
        ) from exc
    identity = (observed.st_dev, observed.st_ino, observed.st_size)
    if expected_identity is not None and identity != expected_identity:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease descriptor identity changed"
        )
    try:
        seals = _fcntl_descriptor(descriptor, _F_GET_SEALS)
    except OSError as exc:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease seals are unavailable"
        ) from exc
    if type(seals) is not int or seals != _FULL_C6_SECCOMP_REQUIRED_SEALS:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease does not have the exact required seals"
        )
    try:
        offset = _seek_descriptor(descriptor, 0, os.SEEK_CUR)
        payload = _pread_descriptor(descriptor, len(expected) + 1, 0)
    except OSError as exc:
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease cannot be inspected"
        ) from exc
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_size != len(expected)
        or offset != 0
        or payload != expected
    ):
        raise FullC6ReadSandboxError(
            "Full C6 Linux seccomp lease does not contain the exact filter"
        )
    return identity, hashlib.sha256(expected).hexdigest()


def _is_linux_platform() -> bool:
    return sys.platform == "linux"


def _memfd_create(name: str, flags: int) -> int:
    creator = getattr(os, "memfd_create", None)
    if creator is None:
        raise OSError("memfd_create is unavailable")
    descriptor = creator(name, flags)
    if type(descriptor) is not int:
        raise OSError("memfd_create returned an invalid descriptor")
    return descriptor


def _fcntl_descriptor(descriptor: int, command: int, argument: int = 0) -> int:
    import fcntl

    return int(fcntl.fcntl(descriptor, command, argument))


def _write_descriptor(descriptor: int, payload: bytes) -> int:
    return os.write(descriptor, payload)


def _write_exact_descriptor(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = _write_descriptor(descriptor, payload[offset:])
        if type(written) is not int or written <= 0 or written > len(payload) - offset:
            raise FullC6ReadSandboxError(
                "Full C6 Linux seccomp memfd write was incomplete"
            )
        offset += written


def _seek_descriptor(descriptor: int, offset: int, whence: int) -> int:
    return os.lseek(descriptor, offset, whence)


def _pread_descriptor(descriptor: int, size: int, offset: int) -> bytes:
    return os.pread(descriptor, size, offset)


def _fstat_descriptor(descriptor: int) -> os.stat_result:
    return os.fstat(descriptor)


def _close_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _close_descriptor_quietly(descriptor: int) -> None:
    try:
        _close_descriptor(descriptor)
    except OSError:
        return


def _process_id() -> int:
    return os.getpid()


def _verify_bubblewrap(path: Path) -> str:
    """Hash one root-controlled, canonical bwrap executable without aliases."""
    raw_path = os.fspath(path)
    if (
        not path.is_absolute()
        or path.name != "bwrap"
        or raw_path != os.path.normpath(raw_path)
        or len(os.fsencode(path)) > _MAX_PATH_BYTES
    ):
        raise FullC6ReadSandboxError("Full C6 bubblewrap path is not canonical")
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 bubblewrap is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_nlink != 1
        or observed.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
        or not observed.st_mode & 0o111
        or not os.access(path, os.X_OK)
    ):
        raise FullC6ReadSandboxError("Full C6 bubblewrap executable is unsafe")
    parent = path.parent
    while True:
        try:
            parent_observed = os.lstat(parent)
        except OSError as exc:
            raise FullC6ReadSandboxError(
                "Full C6 bubblewrap parent is unavailable"
            ) from exc
        if (
            stat.S_ISLNK(parent_observed.st_mode)
            or not stat.S_ISDIR(parent_observed.st_mode)
            or parent_observed.st_uid != 0
            or parent_observed.st_mode & 0o022
        ):
            raise FullC6ReadSandboxError("Full C6 bubblewrap parent is unsafe")
        if parent.parent == parent:
            break
        parent = parent.parent

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 bubblewrap could not be opened") from exc
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_BUBBLEWRAP_BYTES:
                raise FullC6ReadSandboxError(
                    "Full C6 bubblewrap executable exceeds the byte bound"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 bubblewrap could not be hashed") from exc
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or before.st_ino != observed.st_ino:
        raise FullC6ReadSandboxError("Full C6 bubblewrap changed while hashing")
    return digest.hexdigest()


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
        # system.sb supplies Apple's process/dyld bootstrap baseline.  The
        # support lock binds system.sb and its imports, while the APFS provider
        # binds the read-only authenticated SSV that hosts their system roots.
        '(import "system.sb")',
        "(deny default)",
        "(deny network*)",
        # Remove mutable/data-volume allowances inherited from system.sb.
        '(deny file-read* file-test-existence (subpath "/private/var") '
        '(subpath "/private/etc") (subpath "/Library/Preferences"))',
        '(deny file-read* file-write* file-test-existence (subpath "/Library") '
        '(subpath "/dev") (subpath "/cores") '
        '(subpath "/System/Volumes/Preboot"))',
        "(deny mach-lookup)",
        "(deny ipc-posix-shm-read*)",
        "(deny user-preference-read)",
        "(deny sysctl-read)",
        "(deny sysctl-write)",
        "(allow process-fork)",
        "(allow signal (target self))",
    ]
    for rule in rules:
        path = _sandbox_literal(os.fspath(rule.path))
        try:
            observed = os.lstat(rule.path)
        except OSError as exc:
            raise FullC6ReadSandboxError("Full C6 sandbox path is unavailable") from exc
        selector = "subpath" if stat.S_ISDIR(observed.st_mode) else "literal"
        if rule.access == "read":
            lines.append(f"(allow file-read* ({selector} {path}))")
        elif rule.access == "read-execute":
            lines.append(f"(allow file-read* ({selector} {path}))")
            lines.append(f"(allow process-exec ({selector} {path}))")
        else:
            lines.append(f"(allow file-read* file-write* ({selector} {path}))")
            if stat.S_ISDIR(observed.st_mode):
                lines.append(f"(allow process-exec ({selector} {path}))")
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
    probe_profile = profile + (
        f"(allow file-read* (literal {_sandbox_literal(str(probe))}))\n"
        f"(allow process-exec (literal {_sandbox_literal(str(probe))}))\n"
    )
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
    # Prove that system.sb's mutable data-volume allowances were removed.
    stat_tool = Path("/usr/bin/stat")
    try:
        stat_observed = os.lstat(stat_tool)
    except OSError as exc:
        raise FullC6ReadSandboxError("Full C6 sandbox denial probe is unavailable") from exc
    if stat.S_ISLNK(stat_observed.st_mode) or not stat.S_ISREG(stat_observed.st_mode):
        raise FullC6ReadSandboxError("Full C6 sandbox denial probe is unsafe")
    denial_profile = profile + (
        f"(allow file-read* (literal {_sandbox_literal(str(stat_tool))}))\n"
        f"(allow process-exec (literal {_sandbox_literal(str(stat_tool))}))\n"
    )
    for denied_path in (
        "/private/etc/passwd",
        "/Library/Apple",
        "/System/Volumes/Preboot",
    ):
        try:
            denied = subprocess.run(
                [
                    os.fspath(sandbox_exec),
                    "-p",
                    denial_profile,
                    "--",
                    os.fspath(stat_tool),
                    denied_path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10.0,
                env={},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise FullC6ReadSandboxError("Full C6 sandbox denial probe failed") from exc
        if denied.returncode == 0:
            raise FullC6ReadSandboxError(
                "Full C6 sandbox mutable-host read denial is ineffective"
            )


def capture_active_macos_platform_anchor() -> MacOSPlatformAnchor:
    """Capture the kernel-verified read-only APFS system snapshot seal.

    ``diskutil`` reports both the authenticated ``Sealed`` state and the booted
    update snapshot.  Apple's snapshot name embeds the 256-bit seal identifier;
    the receipt also binds the exact OS build.  The tool executables and SSV
    sandbox profile bytes are separate mandatory support-lock members.
    """
    if sys.platform != "darwin" or platform.machine().lower() not in {"arm64", "aarch64"}:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor host is unsupported")
    diskutil = Path("/usr/sbin/diskutil")
    sw_vers = Path("/usr/bin/sw_vers")
    for tool in (diskutil, sw_vers):
        try:
            observed = os.lstat(tool)
        except OSError as exc:
            raise FullC6ReadSandboxError("Full C6 macOS anchor tool is unavailable") from exc
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
            raise FullC6ReadSandboxError("Full C6 macOS anchor tool is unsafe")
    environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"}
    try:
        disk = subprocess.run(
            [os.fspath(diskutil), "info", "-plist", "/"],
            check=False,
            capture_output=True,
            timeout=30.0,
            env=environment,
        )
        build = subprocess.run(
            [os.fspath(sw_vers), "-buildVersion"],
            check=False,
            capture_output=True,
            timeout=30.0,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor probe failed") from exc
    if (
        disk.returncode != 0
        or build.returncode != 0
        or not disk.stdout
        or len(disk.stdout) > _PLATFORM_PROBE_MAX_BYTES
        or not build.stdout
        or len(build.stdout) > 1024
    ):
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor probe failed")
    try:
        document = plistlib.loads(disk.stdout)
        os_build = build.stdout.decode("ascii").strip()
    except (ValueError, UnicodeDecodeError, plistlib.InvalidFileException) as exc:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor output is malformed") from exc
    if not isinstance(document, dict) or _APPLE_OS_BUILD_RE.fullmatch(os_build) is None:
        raise FullC6ReadSandboxError("Full C6 macOS platform anchor output is malformed")
    snapshot_name = document.get("APFSSnapshotName")
    match = _APPLE_SNAPSHOT_RE.fullmatch(snapshot_name) if type(snapshot_name) is str else None
    snapshot_uuid = document.get("APFSSnapshotUUID")
    volume_uuid = document.get("VolumeUUID")
    device_identifier = document.get("DeviceIdentifier")
    canonical_uuid = snapshot_uuid.lower() if type(snapshot_uuid) is str else ""
    if (
        match is None
        or _APPLE_UUID_RE.fullmatch(canonical_uuid) is None
        or type(volume_uuid) is not str
        or volume_uuid.lower() != canonical_uuid
        or document.get("APFSSnapshot") is not True
        or document.get("Sealed") != "Yes"
        or document.get("Writable") is not False
        or document.get("WritableVolume") is not False
        or document.get("Internal") is not True
        or document.get("MountPoint") != "/"
        or document.get("FilesystemType") != "apfs"
        or document.get("IORegistryEntryName") != snapshot_name
        or type(device_identifier) is not str
        or _APPLE_SYSTEM_SNAPSHOT_DEVICE_RE.fullmatch(device_identifier) is None
    ):
        raise FullC6ReadSandboxError(
            "Full C6 active macOS root is not one internal read-only sealed APFS snapshot"
        )
    return MacOSPlatformAnchor(
        authenticated_snapshot_id=match.group(1).lower(),
        snapshot_uuid=canonical_uuid,
        os_build=os_build,
        provider="apple-apfs-ssv-diskutil-v1",
    )


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
    "AppleAPFSPlatformAnchorProvider",
    "FullC6ReadSandboxError",
    "FullC6ReadSandboxPlan",
    "FullC6SandboxLaunch",
    "LinuxSeccompLease",
    "MacOSPlatformAnchor",
    "MacOSPlatformAnchorProvider",
    "SandboxPathRule",
    "UnavailableMacOSPlatformAnchorProvider",
    "build_full_c6_sandbox_plan",
    "canonical_platform_context",
    "capture_active_macos_platform_anchor",
    "create_linux_full_c6_seccomp_lease",
    "linux_full_c6_seccomp_program",
    "prepare_full_c6_sandbox_launch",
]
