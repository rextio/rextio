"""Path-free PyO3 build configuration for the frozen artifact build Alpha.

PyO3 normally probes a Python executable and its ``sysconfig`` installation at
build time.  That makes headers, config modules, framework metadata, and search
paths implicit inputs.  artifact build instead supplies one canonical
``PYO3_CONFIG_FILE`` whose bytes are part of the toolchain support lock.  The
fixed CPython 3.11 host-extension scope does not link libpython, so the file
contains no machine-local executable, library, include, or framework path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
from typing import Mapping

from rextio.artifacts.contract_dialects import CURRENT, PYO3_CONFIG_DOMAIN

FULL_C6_PYO3_CONFIG_DOMAIN = CURRENT.string_value(PYO3_CONFIG_DOMAIN)
FULL_C6_PYO3_CONFIG_SCOPE = "cpython311-pyo3-host-cdylib-v1"
FULL_C6_PYO3_CONFIG_NAME = "rextio.pyo3-config.txt"
_SUPPORTED_TARGETS = frozenset({"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DISCOVERY_ENV = frozenset(
    {
        "CONDA_PREFIX",
        "PYO3_CROSS",
        "PYO3_CROSS_LIB_DIR",
        "PYO3_CROSS_PYTHON_IMPLEMENTATION",
        "PYO3_CROSS_PYTHON_VERSION",
        "PYO3_BUILD_EXTENSION_MODULE",
        "PYO3_CONFIG_FILE",
        "PYO3_ENVIRONMENT_SIGNATURE",
        "PYO3_NO_PYTHON",
        "PYO3_PRINT_CONFIG",
        "PYO3_PYTHON",
        "PYO3_USE_ABI3_FORWARD_COMPATIBILITY",
        "PYO3_USE_STABLE_ABI_FORWARD_COMPATIBILITY",
        "VIRTUAL_ENV",
        "_PYTHON_SYSCONFIGDATA_NAME",
    }
)


class FullC6Pyo3ConfigError(RuntimeError):
    """The fixed PyO3 configuration is unavailable, stale, or unsafe."""


@dataclass(frozen=True, slots=True)
class FullC6Pyo3ConfigIdentity:
    """Canonical, path-free bytes consumed by pyo3-build-config 0.29."""

    target_triple: str
    sha256: str
    size: int
    content: bytes
    domain: str = FULL_C6_PYO3_CONFIG_DOMAIN
    scope: str = FULL_C6_PYO3_CONFIG_SCOPE

    def __post_init__(self) -> None:
        if self.domain != FULL_C6_PYO3_CONFIG_DOMAIN:
            raise ValueError("artifact build PyO3 config domain is invalid")
        if self.scope != FULL_C6_PYO3_CONFIG_SCOPE:
            raise ValueError("artifact build PyO3 config scope is invalid")
        if self.target_triple not in _SUPPORTED_TARGETS:
            raise ValueError("artifact build PyO3 config target is unsupported")
        if type(self.content) is not bytes or self.content != _canonical_content():
            raise ValueError("artifact build PyO3 config bytes are not canonical")
        if type(self.size) is not int or self.size != len(self.content):
            raise ValueError("artifact build PyO3 config size is invalid")
        if _SHA256_RE.fullmatch(self.sha256) is None or not hmac.compare_digest(
            self.sha256, hashlib.sha256(self.content).hexdigest()
        ):
            raise ValueError("artifact build PyO3 config SHA-256 is invalid")

    @property
    def digest(self) -> str:
        """Return the semantic identity of the fixed config and target."""
        payload = (
            f"{self.domain}\0{self.scope}\0{self.target_triple}\0{self.size}\0{self.sha256}"
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return a path-free receipt; raw config bytes stay private."""
        return {
            "domain": self.domain,
            "scope": self.scope,
            "target_triple": self.target_triple,
            "implementation": "CPython",
            "version": "3.11",
            "pointer_width": 64,
            "sha256": self.sha256,
            "size": self.size,
            "digest": self.digest,
        }


def capture_full_c6_pyo3_config(target_triple: str) -> FullC6Pyo3ConfigIdentity:
    """Validate the running ABI and return the one fixed path-free config."""
    if target_triple not in _SUPPORTED_TARGETS:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config target is unsupported")
    host_target = _canonical_host_target()
    if target_triple != host_target:
        raise FullC6Pyo3ConfigError(
            "artifact build PyO3 config target differs from the running host"
        )
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11):
        raise FullC6Pyo3ConfigError("artifact build PyO3 config requires CPython 3.11")
    if struct.calcsize("P") * 8 != 64:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config requires a 64-bit interpreter")
    if getattr(sys, "abiflags", "") not in {"", None} or hasattr(sys, "gettotalrefcount"):
        raise FullC6Pyo3ConfigError("artifact build PyO3 config rejects a non-release CPython ABI")
    data = _canonical_content()
    try:
        return FullC6Pyo3ConfigIdentity(
            target_triple=target_triple,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            content=data,
        )
    except ValueError as exc:  # pragma: no cover - constant invariant
        raise FullC6Pyo3ConfigError(str(exc)) from exc


def materialize_full_c6_pyo3_config(
    directory: Path | str,
    identity: FullC6Pyo3ConfigIdentity,
) -> Path:
    """Create and re-read the exact config inside one private build root."""
    if type(identity) is not FullC6Pyo3ConfigIdentity:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config identity has an invalid type")
    root = Path(directory)
    try:
        observed_root = os.lstat(root)
    except OSError as exc:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config root is unavailable") from exc
    if stat.S_ISLNK(observed_root.st_mode) or not stat.S_ISDIR(observed_root.st_mode):
        raise FullC6Pyo3ConfigError("artifact build PyO3 config root is unsafe")
    path = root / FULL_C6_PYO3_CONFIG_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(identity.content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise FullC6Pyo3ConfigError("artifact build PyO3 config write failed")
                view = view[written:]
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise FullC6Pyo3ConfigError("artifact build PyO3 config output is unsafe")
        finally:
            os.close(descriptor)
        verify_full_c6_pyo3_config(path, identity)
    except FullC6Pyo3ConfigError:
        raise
    except OSError as exc:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config could not be materialized") from exc
    return path


def verify_full_c6_pyo3_config(
    path: Path | str,
    expected: FullC6Pyo3ConfigIdentity,
) -> None:
    """Fail unless a no-follow bounded read still has the canonical bytes."""
    if type(expected) is not FullC6Pyo3ConfigIdentity:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config identity has an invalid type")
    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(candidate, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != expected.size
            ):
                raise FullC6Pyo3ConfigError("artifact build PyO3 config file is unsafe")
            data = os.read(descriptor, expected.size + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except FullC6Pyo3ConfigError:
        raise
    except OSError as exc:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config could not be verified") from exc
    if (
        len(data) != expected.size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected.sha256)
        or data != expected.content
    ):
        raise FullC6Pyo3ConfigError("artifact build PyO3 config changed after capture")


def bind_full_c6_pyo3_environment(
    environment: Mapping[str, str],
    *,
    config_path: Path,
    identity: FullC6Pyo3ConfigIdentity,
) -> dict[str, str]:
    """Replace all PyO3 discovery channels with the exact config file."""
    if type(identity) is not FullC6Pyo3ConfigIdentity:
        raise FullC6Pyo3ConfigError("artifact build PyO3 config identity has an invalid type")
    if not isinstance(environment, Mapping):
        raise FullC6Pyo3ConfigError("artifact build PyO3 environment is invalid")
    result = dict(environment)
    # PyO3 0.29 currently recognizes the explicit names above.  Remove any
    # other ambient PYO3_* channel too: a future additive variable must fail
    # inert instead of silently escaping the frozen config contract.
    for name in tuple(result):
        if name in _DISCOVERY_ENV or name.startswith("PYO3_"):
            result.pop(name, None)
    if not config_path.is_absolute():
        raise FullC6Pyo3ConfigError("PYO3_CONFIG_FILE must be an absolute path")
    verify_full_c6_pyo3_config(config_path, identity)
    result["PYO3_CONFIG_FILE"] = os.fspath(config_path)
    result["PYO3_ENVIRONMENT_SIGNATURE"] = identity.digest
    forbidden_remaining = _DISCOVERY_ENV.difference(
        {"PYO3_CONFIG_FILE", "PYO3_ENVIRONMENT_SIGNATURE"}
    )
    if forbidden_remaining.intersection(result):  # pragma: no cover - defensive
        raise FullC6Pyo3ConfigError("uncontrolled PyO3 discovery environment remains")
    return result


def _canonical_content() -> bytes:
    return (
        "implementation=CPython\n"
        "version=3.11\n"
        "shared=true\n"
        "pointer_width=64\n"
        "build_flags=\n"
        "suppress_build_script_link_lines=true\n"
    ).encode("ascii")


def _canonical_host_target() -> str:
    machine = platform.machine().lower()
    if sys.platform == "darwin" and machine in {"arm64", "aarch64"}:
        return "aarch64-apple-darwin"
    if sys.platform.startswith("linux") and machine in {"x86_64", "amd64"}:
        return "x86_64-unknown-linux-gnu"
    raise FullC6Pyo3ConfigError("artifact build PyO3 config host is unsupported")


__all__ = [
    "FULL_C6_PYO3_CONFIG_DOMAIN",
    "FULL_C6_PYO3_CONFIG_NAME",
    "FULL_C6_PYO3_CONFIG_SCOPE",
    "FullC6Pyo3ConfigError",
    "FullC6Pyo3ConfigIdentity",
    "bind_full_c6_pyo3_environment",
    "capture_full_c6_pyo3_config",
    "materialize_full_c6_pyo3_config",
    "verify_full_c6_pyo3_config",
]
