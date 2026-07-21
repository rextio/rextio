"""Post-namespace Landlock launcher for strict Full C6 Linux builds.

This file is executed directly by the support-locked CPython 3.11 mapped at
``/rextio/toolchain/bin/python3.11``.  It intentionally imports only the
standard library, validates the exact isolated interpreter/environment/argv
contract, replaces stdin with EOF-only ``/dev/null``, closes every extra
descriptor, installs Landlock in the already-created bubblewrap namespace,
and replaces itself with Cargo.

It must never run before bubblewrap: a Landlock-restricted thread cannot call
``mount(2)`` or ``pivot_root(2)``, both of which bubblewrap requires.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import ctypes
import hashlib
import os
import re
import stat
import struct
import sys


FULL_C6_LINUX_LAUNCHER_DOMAIN = "rextio.full-c6-linux-launcher.v1"
FULL_C6_LINUX_TOOLCHAIN_ROOT = "/rextio/toolchain"
FULL_C6_LINUX_CARGO = "/rextio/toolchain/bin/cargo"
FULL_C6_LINUX_PYTHON = "/rextio/toolchain/bin/python3.11"
FULL_C6_LINUX_PYTHON_PREFIX = FULL_C6_LINUX_TOOLCHAIN_ROOT
FULL_C6_LINUX_PYTHON_RUNTIME_LIBRARY = (
    "/rextio/toolchain/lib/libpython3.11.so.1.0"
)
FULL_C6_LINUX_PYTHON_STDLIB = "/rextio/toolchain/lib/python3.11"
FULL_C6_LINUX_PYO3_CONFIG = "/rextio/support/pyo3-config"
FULL_C6_LINUX_LAUNCHER = (
    "/rextio/support/rextio/full_c6_linux_launcher.py"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_DATE_EPOCH_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
_MAX_ARGUMENTS = 512
_MAX_ARGUMENT_BYTES = 16 * 1024
_MAX_OPEN_FILES = 1024 * 1024
_PYO3_CONFIG_PATH = FULL_C6_LINUX_PYO3_CONFIG
_PYO3_CONFIG_CONTENT = (
    "implementation=CPython\n"
    "version=3.11\n"
    "shared=true\n"
    "pointer_width=64\n"
    "build_flags=\n"
    "suppress_build_script_link_lines=true\n"
).encode("ascii")

_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

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

_CARGO_ENCODED_RUSTFLAGS = "\x1f".join(
    (
        "--remap-path-prefix=/rextio/project=/rextio/project",
        "--remap-path-prefix=/rextio/build=/rextio/build",
        "-C",
        "linker=/rextio/toolchain/bin/linker",
    )
)


def expected_linux_pyo3_environment_signature() -> str:
    """Return the fixed PyO3 identity digest for Linux x86_64 Full C6."""
    content_sha256 = hashlib.sha256(_PYO3_CONFIG_CONTENT).hexdigest()
    payload = (
        "rextio.full-c6-pyo3-config.v1\0"
        "cpython311-pyo3-host-cdylib-v1\0"
        "x86_64-unknown-linux-gnu\0"
        f"{len(_PYO3_CONFIG_CONTENT)}\0{content_sha256}"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()

_FIXED_ENVIRONMENT = {
    "AR": "/rextio/toolchain/bin/ar",
    "CC": "/rextio/toolchain/bin/linker",
    "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu",
    "CARGO_ENCODED_RUSTFLAGS": _CARGO_ENCODED_RUSTFLAGS,
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
        "/rextio/toolchain/lib:/rextio/support/python-library-root:"
        "/rextio/support/runtime-libs"
    ),
    "LIBRARY_PATH": (
        "/rextio/support/gcc-toolchain:/rextio/support/runtime-libs"
    ),
    "PATH": "/rextio/toolchain/bin:/rextio/toolchain",
    "PYO3_CONFIG_FILE": _PYO3_CONFIG_PATH,
    "PYO3_ENVIRONMENT_SIGNATURE": expected_linux_pyo3_environment_signature(),
    "PYTHONHASHSEED": "0",
    "RANLIB": "/rextio/toolchain/bin/ranlib",
    "RUSTC": "/rextio/toolchain/bin/rustc",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
}
_VARIABLE_ENVIRONMENT = frozenset({"SOURCE_DATE_EPOCH"})

# All paths are canonical namespace paths.  Kernel-backed proc/dev/tmp are
# created fresh by bwrap; no ambient host /proc, /dev, or /tmp is mounted.
_LANDLOCK_RULES = (
    ("/dev", "read"),
    ("/dev/null", "read-write"),
    ("/dev/random", "read"),
    ("/dev/urandom", "read"),
    ("/lib64/ld-linux-x86-64.so.2", "read-execute"),
    ("/proc", "read"),
    ("/rextio/build", "read-write"),
    ("/rextio/project", "read"),
    ("/rextio/support", "read-execute"),
    ("/rextio/toolchain", "read-execute"),
    ("/tmp", "read-write"),
)


class FullC6LinuxLauncherError(RuntimeError):
    """The post-namespace launcher contract is unavailable or inconsistent."""


def canonical_linux_payload_environment(
    environment: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    """Validate and canonicalize the exact Cargo payload environment."""
    if not isinstance(environment, Mapping):
        raise FullC6LinuxLauncherError("Full C6 Linux environment is invalid")
    expected_names = set(_FIXED_ENVIRONMENT).union(_VARIABLE_ENVIRONMENT)
    if set(environment) != expected_names:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux environment does not match the closed contract"
        )
    for name, expected in _FIXED_ENVIRONMENT.items():
        if environment.get(name) != expected:
            raise FullC6LinuxLauncherError(
                "Full C6 Linux fixed environment value differs"
            )
    source_date_epoch = environment.get("SOURCE_DATE_EPOCH")
    if (
        type(source_date_epoch) is not str
        or _SOURCE_DATE_EPOCH_RE.fullmatch(source_date_epoch) is None
    ):
        raise FullC6LinuxLauncherError(
            "Full C6 Linux variable environment value is invalid"
        )
    rows: list[tuple[str, str]] = []
    for name in sorted(expected_names):
        value = environment[name]
        if (
            type(name) is not str
            or type(value) is not str
            or not name
            or not value
            or "\0" in name
            or "\0" in value
            or any(ord(character) < 32 for character in name)
            or any(
                ord(character) < 32
                and not (
                    name == "CARGO_ENCODED_RUSTFLAGS" and character == "\x1f"
                )
                for character in value
            )
        ):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux environment row is malformed"
            )
        rows.append((name, value))
    return tuple(rows)


def linux_payload_environment_digest(environment: Mapping[str, str]) -> str:
    """Return the path-safe digest of one canonical virtual environment."""
    rows = canonical_linux_payload_environment(environment)
    payload = (
        FULL_C6_LINUX_LAUNCHER_DOMAIN
        + "\0environment\0"
        + "\n".join(f"{name}\0{value}" for name, value in rows)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_linux_launcher_argv(
    argv: Sequence[str],
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    """Validate launcher control arguments and return the Cargo argv."""
    values = tuple(argv)
    if (
        len(values) < 5
        or len(values) > _MAX_ARGUMENTS
        or values[0] != FULL_C6_LINUX_LAUNCHER
        or values[1] != "--environment-sha256"
        or _SHA256_RE.fullmatch(values[2]) is None
        or values[3] != "--"
    ):
        raise FullC6LinuxLauncherError("Full C6 Linux launcher argv is invalid")
    if values[2] != linux_payload_environment_digest(environment):
        raise FullC6LinuxLauncherError(
            "Full C6 Linux launcher environment digest differs"
        )
    for value in values:
        if (
            type(value) is not str
            or not value
            or "\0" in value
            or len(value.encode("utf-8")) > _MAX_ARGUMENT_BYTES
            or any(ord(character) < 32 for character in value)
        ):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux launcher argument is malformed"
            )
    payload = values[4:]
    executable = payload[0]
    if executable != FULL_C6_LINUX_CARGO:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux payload executable is not the fixed Cargo binary"
        )
    return payload


def validate_isolated_python_runtime() -> None:
    """Require the exact relocatable CPython 3.11 landmark layout."""
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != (3, 11)
        or sys.executable != FULL_C6_LINUX_PYTHON
        or os.path.abspath(sys.argv[0]) != FULL_C6_LINUX_LAUNCHER
        or sys.prefix != FULL_C6_LINUX_PYTHON_PREFIX
        or sys.exec_prefix != FULL_C6_LINUX_PYTHON_PREFIX
        or sys.base_prefix != FULL_C6_LINUX_PYTHON_PREFIX
        or sys.base_exec_prefix != FULL_C6_LINUX_PYTHON_PREFIX
        or sys.flags.isolated != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.no_user_site != 1
        or sys.flags.no_site != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.safe_path is not True
    ):
        raise FullC6LinuxLauncherError(
            "Full C6 Linux launcher CPython contract differs"
        )
    zip_landmark = "/rextio/toolchain/lib/python311.zip"
    if not sys.path:
        raise FullC6LinuxLauncherError("Full C6 Linux launcher sys.path is empty")
    for entry in sys.path:
        if type(entry) is not str or not entry or entry != os.path.normpath(entry):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux launcher sys.path is malformed"
            )
        if entry != zip_landmark and not (
            entry == FULL_C6_LINUX_PYTHON_STDLIB
            or entry.startswith(FULL_C6_LINUX_PYTHON_STDLIB + "/")
        ):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux launcher sys.path escaped the locked stdlib"
            )


def close_untrusted_file_descriptors() -> None:
    """Replace stdin with EOF-only /dev/null and close every extra FD."""
    for descriptor in (1, 2):
        try:
            observed = os.fstat(descriptor)
        except OSError as exc:
            raise FullC6LinuxLauncherError(
                "Full C6 Linux output descriptor is unavailable"
            ) from exc
        if not (
            stat.S_ISFIFO(observed.st_mode)
            or stat.S_ISREG(observed.st_mode)
            or stat.S_ISCHR(observed.st_mode)
        ):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux output descriptor type is unsafe"
            )
    null_path = "/dev/null"
    try:
        path_observed = os.lstat(null_path)
    except OSError as exc:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux stdin device is unavailable"
        ) from exc
    if stat.S_ISLNK(path_observed.st_mode) or not stat.S_ISCHR(
        path_observed.st_mode
    ):
        raise FullC6LinuxLauncherError(
            "Full C6 Linux stdin device is unsafe"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        null_fd = os.open(null_path, flags)
        try:
            opened = os.fstat(null_fd)
            if (
                not stat.S_ISCHR(opened.st_mode)
                or opened.st_dev != path_observed.st_dev
                or opened.st_ino != path_observed.st_ino
                or opened.st_rdev != path_observed.st_rdev
            ):
                raise FullC6LinuxLauncherError(
                    "Full C6 Linux stdin device changed while opening"
                )
            if null_fd == 0:
                os.set_inheritable(0, True)
            else:
                os.dup2(null_fd, 0, inheritable=True)
            stdin_observed = os.fstat(0)
            if (
                not stat.S_ISCHR(stdin_observed.st_mode)
                or stdin_observed.st_rdev != opened.st_rdev
                or not os.get_inheritable(0)
            ):
                raise FullC6LinuxLauncherError(
                    "Full C6 Linux stdin EOF boundary was not installed"
                )
        finally:
            if null_fd != 0:
                os.close(null_fd)
    except FullC6LinuxLauncherError:
        raise
    except OSError as exc:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux stdin EOF boundary could not be installed"
        ) from exc
    try:
        maximum = os.sysconf("SC_OPEN_MAX")
    except (OSError, ValueError) as exc:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux descriptor bound is unavailable"
        ) from exc
    if type(maximum) is not int or maximum < 3 or maximum > _MAX_OPEN_FILES:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux descriptor bound is unsafe"
        )
    os.closerange(3, maximum)


def verify_full_c6_pyo3_config() -> None:
    """Re-read the exact fixed PyO3 config before Landlock and Cargo."""
    try:
        observed = os.lstat(_PYO3_CONFIG_PATH)
    except OSError as exc:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux PyO3 config is unavailable"
        ) from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise FullC6LinuxLauncherError("Full C6 Linux PyO3 config is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_PYO3_CONFIG_PATH, flags)
        try:
            before = os.fstat(descriptor)
            content = os.read(descriptor, len(_PYO3_CONFIG_CONTENT) + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux PyO3 config could not be read"
        ) from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        content != _PYO3_CONFIG_CONTENT
        or identity_before != identity_after
        or before.st_ino != observed.st_ino
    ):
        raise FullC6LinuxLauncherError("Full C6 Linux PyO3 config differs")


def apply_full_c6_landlock(
    *,
    syscall: Callable[..., int] | None = None,
    prctl: Callable[..., int] | None = None,
) -> None:
    """Apply Landlock ABI >=3 inside the completed bwrap namespace."""
    syscall_fn = syscall or _libc_syscall()
    prctl_fn = prctl or _libc_prctl()
    abi = syscall_fn(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    if type(abi) is not int or abi < 3:
        raise FullC6LinuxLauncherError("Full C6 Linux requires Landlock ABI 3")
    frozen: list[tuple[str, int]] = []
    for path, access in _LANDLOCK_RULES:
        try:
            observed = os.lstat(path)
        except OSError as exc:
            raise FullC6LinuxLauncherError(
                "Full C6 Linux Landlock input is unavailable"
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or not (
            stat.S_ISDIR(observed.st_mode)
            or stat.S_ISREG(observed.st_mode)
            or stat.S_ISCHR(observed.st_mode)
        ):
            raise FullC6LinuxLauncherError(
                "Full C6 Linux Landlock input type is unsafe"
            )
        frozen.append(
            (
                path,
                _landlock_access(
                    access,
                    directory=stat.S_ISDIR(observed.st_mode),
                    character_device=stat.S_ISCHR(observed.st_mode),
                ),
            )
        )
    ruleset_data = struct.pack("=Q", _LANDLOCK_HANDLED_FS_V3)
    ruleset_buffer = ctypes.create_string_buffer(ruleset_data)
    ruleset_fd = syscall_fn(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset_buffer),
        ctypes.c_size_t(len(ruleset_data)),
        ctypes.c_uint32(0),
    )
    if type(ruleset_fd) is not int or ruleset_fd < 0:
        raise FullC6LinuxLauncherError(
            "Full C6 Linux could not create a Landlock ruleset"
        )
    try:
        for path, allowed in frozen:
            flags = getattr(os, "O_PATH", os.O_RDONLY)
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            parent_fd = os.open(path, flags)
            try:
                attribute = struct.pack("=Qi", allowed, parent_fd)
                buffer = ctypes.create_string_buffer(attribute)
                result = syscall_fn(
                    _SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(buffer),
                    ctypes.c_uint32(0),
                )
                if type(result) is not int or result != 0:
                    raise FullC6LinuxLauncherError(
                        "Full C6 Linux could not add a Landlock rule"
                    )
            finally:
                os.close(parent_fd)
        if prctl_fn(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise FullC6LinuxLauncherError(
                "Full C6 Linux could not set no_new_privs"
            )
        if syscall_fn(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise FullC6LinuxLauncherError(
                "Full C6 Linux could not enforce Landlock"
            )
    finally:
        os.close(ruleset_fd)


def run_linux_launcher() -> None:
    """Validate, isolate, Landlock, and replace this process with Cargo."""
    validate_isolated_python_runtime()
    environment = dict(os.environ)
    payload = validate_linux_launcher_argv(sys.argv, environment)
    verify_full_c6_pyo3_config()
    close_untrusted_file_descriptors()
    apply_full_c6_landlock()
    os.execve(payload[0], payload, environment)
    raise FullC6LinuxLauncherError("Full C6 Linux execve returned unexpectedly")


def _landlock_access(
    access: str,
    *,
    directory: bool,
    character_device: bool,
) -> int:
    if character_device:
        if access == "read":
            return _LL_READ_FILE
        if access == "read-write":
            return _LL_READ_FILE | _LL_WRITE_FILE
        raise FullC6LinuxLauncherError(
            "Full C6 Linux device cannot be executable"
        )
    if not directory:
        if access == "read":
            return _LL_READ_FILE
        if access == "read-execute":
            return _LL_READ_FILE | _LL_EXECUTE
        if access == "read-write":
            return _LL_READ_FILE | _LL_WRITE_FILE | _LL_TRUNCATE
    elif access == "read":
        return _LANDLOCK_READ
    elif access == "read-execute":
        return _LANDLOCK_READ_EXECUTE
    elif access == "read-write":
        return _LANDLOCK_READ_WRITE
    raise FullC6LinuxLauncherError("Full C6 Linux Landlock access is invalid")


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


def _main() -> int:
    try:
        run_linux_launcher()
    except BaseException:
        try:
            os.write(2, b"Rextio Full C6 Linux launcher failed closed\n")
        except OSError:
            pass
        return 125
    return 125


if __name__ == "__main__":  # pragma: no cover - exercised by Linux E2E
    raise SystemExit(_main())


__all__ = [
    "FULL_C6_LINUX_CARGO",
    "FULL_C6_LINUX_LAUNCHER",
    "FULL_C6_LINUX_LAUNCHER_DOMAIN",
    "FULL_C6_LINUX_PYTHON",
    "FULL_C6_LINUX_PYTHON_PREFIX",
    "FULL_C6_LINUX_PYTHON_RUNTIME_LIBRARY",
    "FULL_C6_LINUX_PYTHON_STDLIB",
    "FULL_C6_LINUX_PYO3_CONFIG",
    "FULL_C6_LINUX_TOOLCHAIN_ROOT",
    "FullC6LinuxLauncherError",
    "apply_full_c6_landlock",
    "canonical_linux_payload_environment",
    "close_untrusted_file_descriptors",
    "expected_linux_pyo3_environment_signature",
    "linux_payload_environment_digest",
    "run_linux_launcher",
    "validate_isolated_python_runtime",
    "validate_linux_launcher_argv",
    "verify_full_c6_pyo3_config",
]
