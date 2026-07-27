"""Standalone harness for the installed-wheel Full C6 real-Cargo E2E.

The test exercises only the public lifecycle: a fresh installed ``rextio``
process emits a non-authorizing bootstrap, test-only owner tooling writes an
explicit completion, the installed policy finalizer creates the manifest, an
external signer signs the later request, and two more fresh ``rextio``
processes complete signing and publication.  No process-local production
authority is inspected or monkeypatched.
"""

from __future__ import annotations

import base64
import csv
from dataclasses import replace
import hashlib
from importlib import invalidate_caches, metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Literal, NamedTuple, cast
from urllib.parse import unquote, urlparse
import venv
import zipfile


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)

_SUPPORT_LOCK_OUTPUT = "authority/rextio.toolchain-support.lock.json"
_FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES = 128 * 1024
_FULL_C6_BUILD_FAILURE_DOMAINS = frozenset(
    {
        "FullC6GateError",
        "FullC6HostInputsError",
        "FullC6PipelineError",
        "FullC6PolicyBootstrapError",
        "FullC6ProductionError",
        "FullC6PublicationError",
    }
)
_FULL_C6_BUILD_FAILURE_STAGES = frozenset(
    {
        "host-prerequisites",
        "production-authority",
        "policy-bootstrap",
        "signing-request",
        "prepublication-cleanup",
        "publication-plan",
        "publication",
        "host-cleanup",
    }
)
_FULL_C6_BUILD_FAILURE_REASON_CODES = frozenset(
    {
        "executor-pyo3-profile",
        "executor-sandbox-execution",
        "executor-sandbox-launch",
        "executor-sandbox-plan",
        "executor-seccomp-setup",
        "executor-toolchain-support",
        "external-reanalysis-mismatch",
        "external-toolchain-support",
        "linux-launcher-cargo-exec",
        "linux-launcher-cpython-runtime",
        "linux-launcher-descriptors",
        "linux-launcher-environment-argv",
        "linux-launcher-environment-argv-argv-shape",
        "linux-launcher-environment-argv-closed-set",
        "linux-launcher-environment-argv-environment-digest",
        "linux-launcher-environment-argv-fixed-value",
        "linux-launcher-environment-argv-malformed-argument",
        "linux-launcher-environment-argv-malformed-row",
        "linux-launcher-environment-argv-payload-executable",
        "linux-launcher-environment-argv-unexpected-lc-ctype",
        "linux-launcher-environment-argv-variable-value",
        "linux-launcher-exit-125",
        "linux-launcher-landlock",
        "linux-launcher-pyo3-config",
        "native-build-exit-1",
        "native-build-exit-101",
        "native-bwrap-bind-path-missing",
        "native-bwrap-exec-failed",
        "native-bwrap-mount-failed",
        "native-bwrap-seccomp-failed",
        "native-bwrap-user-namespace-denied",
        "native-cargo-dependency-config",
        "native-compile",
        "native-linker",
        "native-linux-cargo-cache-lock",
        "native-linux-cargo-parallelism",
        "native-linux-permission-build-root",
        "native-linux-permission-dev-root",
        "native-linux-permission-diagnostic-overflow",
        "native-linux-permission-dynamic-loader",
        "native-linux-permission-gcc-lto-plugin",
        "native-linux-permission-jobserver-creation",
        "native-linux-permission-lib64-root",
        "native-linux-permission-network-connect",
        "native-linux-permission-pipe-creation",
        "native-linux-permission-proc-root",
        "native-linux-permission-process-spawn",
        "native-linux-permission-project-root",
        "native-linux-permission-python-root",
        "native-linux-permission-rextio-root",
        "native-linux-permission-socket-creation",
        "native-linux-permission-support-root",
        "native-linux-permission-tmp-root",
        "native-linux-permission-toolchain-root",
        "native-linux-permission-unclassified-no-known-operation",
        "native-linux-rustc-exec-permission",
        "native-macos-permission-build-root",
        "native-macos-permission-denied-dev",
        "native-macos-permission-denied-library",
        "native-macos-permission-denied-preboot",
        "native-macos-permission-denied-private-var",
        "native-macos-permission-mach-lookup",
        "native-macos-permission-project-root",
        "native-macos-permission-sandbox-apply",
        "native-macos-permission-support",
        "native-macos-permission-sysctl-cpu-count",
        "native-macos-permission-toolchain",
        "native-macos-permission-unmatched",
        "native-missing-path",
        "native-permission",
        "native-pyo3",
        "native-rustc",
        "native-sandbox-bubblewrap",
        "production-authority-unclassified",
        "production-cargo-workspace-mismatch",
        "production-collection-failed",
        "production-config-noncanonical",
        "production-lifecycle-disabled",
        "production-preflight-invalid",
        "production-prerequisites-invalid",
        "production-project-root-mismatch",
        "production-toolchain-support",
        "production-toolchain-support-invalid",
        "production-toolchain-support-replaced",
        "pyo3-cpython-version-mismatch",
        "pyo3-target-mismatch",
        "sandbox-bubblewrap-unavailable",
        "sandbox-bubblewrap-unsafe",
        "sandbox-path-unavailable",
        "sandbox-seccomp-unavailable",
        "toolchain-critical-path-changed",
    }
)
_FULL_C6_BUILD_FAILURE_UNAVAILABLE = (
    '{"event":"full-c6-build-failure-report-unavailable"}'
)
_XCODE_HARDLINK_ROLE = "xcode-clang-resource"
_XCODE_HARDLINK_RELATIVE_PATH = "include/__clang_cuda_builtin_vars.h"
_XCODE_HARDLINK_RELATIVE_PATH_SHA256 = (
    "3bbf5e13c9400baf7c260dc5eb3590ee369377ad1f2ec92edba0d6802fe2160e"
)
_XCODE_HARDLINK_ALIAS_COUNT = 3
_XCODE_HARDLINK_MAX_ENTRIES = 250_000
_XCODE_HARDLINK_APP_MAX_ENTRIES = 1_000_000
_XCODE_HARDLINK_MAX_DEPTH = 64
_XCODE_HARDLINK_MAX_PATH_BYTES = 8_192
_XCODE_HARDLINK_TOPOLOGY_MAX_GROUPS = 1_024
_XCODE_HARDLINK_TOPOLOGY_MAX_MEMBERS = 64
_XCODE_HARDLINK_POLICY_GROUP_COUNT = 121
_XCODE_HARDLINK_POLICY_SUPPORT_MEMBER_COUNT = 121
_XCODE_HARDLINK_POLICY_ALIAS_COUNT = 361
_XCODE_HARDLINK_POLICY_MERKLE = (
    "46dfe178bd85f3df653adbda460c674045acbc370c96e1a756564011e2a01e46"
)
_XCODE_VERSION_PLIST_ROLE = "xcode-version-plist"
_XCODE_VERSION_PLIST = Path("/Applications/Xcode.app/Contents/version.plist")
_XCODE_CLANG_RESOURCE_VERSION_RE = re.compile(
    r"\A[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}\Z"
)
_XCODE_HARDLINK_ERROR_RE = re.compile(
    r"\Atoolchain support xcode hardlink observation "
    rf"\(path={_XCODE_HARDLINK_RELATIVE_PATH_SHA256},"
    r"stamp=(?P<stamp>[0-9a-f]{64}),nlink=3,count=1\)\Z"
)
_XCODE_GENERIC_HARDLINK_ERROR_RE = re.compile(
    r"\Atoolchain support regular tree member is a shared hardlink "
    r"\(logical_role=xcode-clang-resource,"
    r" relative_path_sha256=[0-9a-f]{64},"
    r" st_uid=[0-9]{1,20}, st_gid=[0-9]{1,20},"
    r" st_mode=[0-9]{1,20}, st_nlink=[2-9][0-9]{0,19},"
    r" in_root_inode_observation_count=[1-9][0-9]{0,19}\)\Z"
)


class _XcodeHardlinkTopology(NamedTuple):
    group_count: int
    support_member_count: int
    alias_count: int
    policy_merkle: str
    observation_merkle: str


_PATH_FREE_SUPPORT_LOCK_MESSAGES_WITH_SEMANTIC_SLASH = frozenset(
    {
        "toolchain support directory contains an NFC/casefold alias",
        "toolchain support tree contains an NFC/casefold path alias",
        "toolchain support lock contains an NFC/casefold role alias",
        "toolchain support locators contain an NFC/casefold role alias",
    }
)
_GENERIC_PERMISSION_MODE_CAUSE = "toolchain support permission mode is invalid"
_LINUX_FOLDED_NAME_CAUSE = (
    "toolchain support directory contains an NFC/casefold alias"
)
_LINUX_FOLDED_NAME_ROLE = "linux-runtime-support"
_LINUX_FOLDED_NAME_MAX_ENTRIES = 250_000
_LINUX_FOLDED_NAME_MAX_DEPTH = 64
_LINUX_FOLDED_NAME_MAX_PATH_BYTES = 8_192
_LINUX_FOLDED_NAME_MAX_GROUPS = 16
_LINUX_FOLDED_NAME_MAX_GROUP_MEMBERS = 16
_SUPPORT_LOCK_ROLES = {
    "aarch64-apple-darwin": (
        (
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
        (
            "python-runtime",
            "rust-sysroot",
            "xcode-clang-resource",
            "xcode-sdk",
        ),
    ),
    "x86_64-unknown-linux-gnu": (
        (
            "landlock-launcher",
            "linux-ar",
            "linux-binutils-ld",
            "linux-bwrap",
            "linux-dynamic-loader",
            "linux-ranlib",
            "python-runtime-library",
            "rustup-components",
        ),
        (
            "linux-gcc-support",
            "linux-python-library-support",
            "linux-runtime-support",
            "python-runtime",
            "rust-sysroot",
        ),
    ),
}
_SUPPORT_LOCK_FIXED_ROLES = frozenset(
    role
    for manifest_roles, root_roles in _SUPPORT_LOCK_ROLES.values()
    for role in (*manifest_roles, *root_roles)
)
_SUPPORT_LOCK_VERIFICATION_DIAGNOSTIC_RE = re.compile(
    r"toolchain support verification differs \("
    r"manifests=(?P<manifests>[0-9]{1,2}),"
    r"roots=(?P<roots>[0-9]{1,2}),"
    r"kind=(?P<kind>manifest|root),"
    r"role=(?P<role>[a-z0-9-]{1,128}),"
    r"before=(?P<before>[0-9a-f]{64}),"
    r"after=(?P<after>[0-9a-f]{64}),"
    r"hbefore=(?P<hbefore>none|[0-9a-f]{64}),"
    r"hafter=(?P<hafter>none|[0-9a-f]{64}),"
    r"fields=(?P<fields>[0-9a-f]{4})\)"
)


def _recover_x(y: int) -> int:
    value = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(value, (_Q + 3) // 8, _Q)
    if (x * x - value) % _Q != 0:
        x = x * _I % _Q
    return _Q - x if x & 1 else x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_B = (_recover_x(_BY), _BY)


def _add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = first
    x2, y2 = second
    product = _D * x1 * x2 * y1 * y2 % _Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + product, _Q - 2, _Q) % _Q,
        (y1 * y2 + x1 * x2) * pow(1 - product, _Q - 2, _Q) % _Q,
    )


def _multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Small RFC 8032 signer used only with a fresh per-run seed."""
    if len(seed) != 32:
        raise ValueError("test signing seed must be exactly 32 bytes")
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = _encode(_multiply(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    encoded_r = _encode(_multiply(_B, nonce))
    challenge = (
        int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _L
    )
    signature = encoded_r + ((nonce + challenge * scalar) % _L).to_bytes(32, "little")
    return public_key, signature


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 1_800,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _record(entries: dict[str, bytes], dist_info: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, payload in sorted(entries.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    writer.writerow((f"{dist_info}/RECORD", "", ""))
    return output.getvalue().encode()


def _write_dependency_wheel(path: Path) -> None:
    dist_info = "demo_pkg-1.0.0.dist-info"
    license_bytes = (
        b"MIT License\n\n"
        b"Copyright (c) 2026 Rextio Full C6 E2E\n\n"
        b"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
        b'of this software and associated documentation files (the "Software"), to deal\n'
        b"in the Software without restriction, including without limitation the rights\n"
        b"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
        b"copies of the Software, and to permit persons to whom the Software is\n"
        b"furnished to do so, subject to the following conditions:\n\n"
        b"The above copyright notice and this permission notice shall be included in all\n"
        b"copies or substantial portions of the Software.\n\n"
        b'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
        b"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
        b"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
        b"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
        b"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
        b"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
        b"SOFTWARE.\n"
    )
    entries = {
        "demo_pkg/__init__.py": (
            b"def affine(x: int) -> int:\n"
            b"    return x + 1\n"
        ),
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\nName: demo-pkg\nVersion: 1.0.0\n"
            b"License-Expression: MIT\nLicense-File: LICENSE\n\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: rextio-full-c6-e2e\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/licenses/LICENSE": license_bytes,
    }
    entries[f"{dist_info}/RECORD"] = _record(entries, dist_info)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)


def _assert_record_backed_rextio_install() -> None:
    import rextio

    distribution = metadata.distribution("rextio")
    files = tuple(distribution.files or ())
    record = tuple(item for item in files if item.name == "RECORD" and ".dist-info" in str(item))
    if len(record) != 1:
        raise AssertionError("Full C6 E2E requires one installed-wheel RECORD")
    package_file = Path(rextio.__file__ or "").resolve()
    distribution_root = Path(str(distribution.locate_file(""))).resolve()
    if not package_file.is_relative_to(distribution_root):
        raise AssertionError("Rextio import escaped the installed distribution root")
    if "site-packages" not in package_file.as_posix():
        raise AssertionError(f"Rextio did not import from site-packages: {package_file}")
    direct_url = distribution.read_text("direct_url.json")
    if direct_url is not None:
        document = json.loads(direct_url)
        if document.get("dir_info", {}).get("editable") is True:
            raise AssertionError("Full C6 E2E must not use an editable Rextio install")


def _expected_target() -> str:
    machine = platform.machine().lower()
    if sys.platform == "darwin" and machine in {"arm64", "aarch64"}:
        return "aarch64-apple-darwin"
    if sys.platform.startswith("linux") and machine in {"x86_64", "amd64"}:
        return "x86_64-unknown-linux-gnu"
    raise AssertionError(f"unsupported dedicated Full C6 lane: {sys.platform}/{machine}")


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _analyze(
    project: Path,
    config: Any,
    registry: Any | None = None,
    analysis_scope: Any | None = None,
) -> Any:
    from rextio.analyzer.project_scanner import analyze_project
    from rextio.targets.plan import create_target_plan

    target_plan = create_target_plan(project, config)
    return analyze_project(
        project,
        boundary_warnings=config.policy.boundary_warnings,
        native_marker=config.policy.native_marker,
        target_language=target_plan.spec.language,
        native_top_level=config.policy.native_top_level,
        imports_config=config.imports,
        active_plugins=target_plan.plugins.active,
        plugin_registry=target_plan.plugins,
        plugin_config=config,
        embedding_enabled=config.embedding.enabled,
        external_native_registry=registry,
        full_c6_analysis_scope=analysis_scope,
    )


def _typed_config(
    project: Path,
    *,
    wheel_sha256: str,
    key_sha256: str,
    cargo_lock_sha256: str,
    cargo_vendor_sha256: str,
    support_lock_path: str | None = None,
    support_lock_sha256: str | None = None,
    policy_sha256: str | None = None,
    final_signature: str | None = None,
) -> Any:
    from rextio.config.schema import (
        BuildConfig,
        ImportPackagePolicy,
        ImportsConfig,
        RextioConfig,
        ToolchainConfig,
    )

    cargo = shutil.which("cargo")
    if cargo is None:
        raise AssertionError("cargo is missing from the dedicated Full C6 lane")
    cargo_version_output = _run([cargo, "--version"], cwd=project).stdout.split()
    if len(cargo_version_output) < 2:
        raise AssertionError("cargo --version returned an invalid value")
    if cargo_version_output[1] != "1.93.1":
        raise AssertionError(
            "dedicated Full C6 E2E requires exact Rust/Cargo 1.93.1; "
            f"observed {cargo_version_output[1]}"
        )
    if (support_lock_path is None) != (support_lock_sha256 is None):
        raise AssertionError("Full C6 support-lock path and SHA-256 must be paired")
    return RextioConfig(
        build=BuildConfig(
            artifact_evidence_policy="required",
            artifact_distribution_policy="strict-evidence",
            artifact_source_lock_manifest="authority/rextio.external-source.lock.v2.json",
            artifact_source_lock_signature=(
                "authority/rextio.external-source.lock.v2.sig.json"
            ),
            artifact_policy_manifest="policy/rextio.artifact-policy.json",
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_cargo_vendor="cargo-vendor",
            artifact_cargo_vendor_sha256=cargo_vendor_sha256,
            artifact_cargo_lock="authority/Cargo.lock",
            artifact_cargo_lock_sha256=cargo_lock_sha256,
            artifact_toolchain_support_lock=support_lock_path,
            artifact_toolchain_support_lock_sha256=support_lock_sha256,
            artifact_trusted_public_key="authority/owner.ed25519.pub",
            artifact_trusted_public_key_sha256=key_sha256,
            artifact_final_signature=final_signature,
            artifact_signing_request_output=(
                ".rextio/full-c6-state/rextio.artifact-authorization-request.json"
            ),
            artifact_repeat_builds=2,
            build_timeout_seconds=900,
        ),
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive="authority/demo_pkg-1.0.0-py3-none-any.whl",
                    source_archive_sha256=wheel_sha256,
                )
            }
        ),
        toolchain=ToolchainConfig(
            python=str(Path(sys.executable).resolve()),
            python_version=platform.python_version(),
            # Keep a rustup proxy lexical path intact. Resolving the symlink
            # would execute the rustup binary as though it were Cargo and would
            # also bypass the host collector's explicit proxy verification.
            cargo=str(Path(cargo).absolute()),
            cargo_version=cargo_version_output[1],
        ),
    )


def _write_config(project: Path, config: Any) -> None:
    build = config.build
    package = config.imports.packages["demo_pkg"]
    toolchain = config.toolchain
    rows = [
        "[build]",
        'fallback_backend = "cpython"',
        "build_timeout_seconds = 900",
        'artifact_evidence_policy = "required"',
        'artifact_distribution_policy = "strict-evidence"',
        f'artifact_source_lock_manifest = "{build.artifact_source_lock_manifest}"',
        f'artifact_source_lock_signature = "{build.artifact_source_lock_signature}"',
        f'artifact_policy_manifest = "{build.artifact_policy_manifest}"',
    ]
    if build.artifact_policy_manifest_sha256 is not None:
        rows.append(
            f'artifact_policy_manifest_sha256 = "{build.artifact_policy_manifest_sha256}"'
        )
    support_lock_path = build.artifact_toolchain_support_lock
    support_lock_sha256 = build.artifact_toolchain_support_lock_sha256
    if (support_lock_path is None) != (support_lock_sha256 is None):
        raise AssertionError("Full C6 support-lock path and SHA-256 must be paired")
    rows.extend(
        (
            f'artifact_cargo_vendor = "{build.artifact_cargo_vendor}"',
            f'artifact_cargo_vendor_sha256 = "{build.artifact_cargo_vendor_sha256}"',
            f'artifact_cargo_lock = "{build.artifact_cargo_lock}"',
            f'artifact_cargo_lock_sha256 = "{build.artifact_cargo_lock_sha256}"',
        )
    )
    if support_lock_path is not None and support_lock_sha256 is not None:
        rows.extend(
            (
                f'artifact_toolchain_support_lock = "{support_lock_path}"',
                (
                    "artifact_toolchain_support_lock_sha256 = "
                    f'"{support_lock_sha256}"'
                ),
            )
        )
    rows.extend(
        (
            f'artifact_trusted_public_key = "{build.artifact_trusted_public_key}"',
            (
                "artifact_trusted_public_key_sha256 = "
                f'"{build.artifact_trusted_public_key_sha256}"'
            ),
            f'artifact_signing_request_output = "{build.artifact_signing_request_output}"',
        )
    )
    if build.artifact_final_signature is not None:
        rows.append(f'artifact_final_signature = "{build.artifact_final_signature}"')
    rows.extend(
        (
            "artifact_repeat_builds = 2",
            "",
            "[rust]",
            'binding = "pyo3"',
            'build_tool = "cargo"',
            "importable = false",
            "",
            "[plugins]",
            "enabled = []",
            "",
            "[embedding]",
            "enabled = false",
            "",
            "[policy]",
            "native_top_level = false",
            "",
            "[imports]",
            'default_external_policy = "fallback"',
            "",
            "[imports.packages.demo_pkg]",
            f'policy = "{package.policy}"',
            "max_depth = 1",
            f'distribution = "{package.distribution}"',
            f'version = "{package.version}"',
            f'source_archive = "{package.source_archive}"',
            f'source_archive_sha256 = "{package.source_archive_sha256}"',
            "",
            "[toolchain]",
            f'python = "{toolchain.python}"',
            f'python_version = "{toolchain.python_version}"',
            f'cargo = "{toolchain.cargo}"',
            f'cargo_version = "{toolchain.cargo_version}"',
        )
    )
    (project / "rextio.toml").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _write_source_lock(
    project: Path,
    *,
    seed: bytes,
    public_key: bytes,
    key_sha256: str,
    wheel_sha256: str,
) -> None:
    from rextio.config.schema import ImportPackagePolicy, ImportsConfig, RextioConfig
    from rextio.source.external_analysis import analyze_external_source_snapshot
    from rextio.source.source_lock_v2 import (
        SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX,
        SourceLockV2Signature,
        build_source_lock_v2_manifest,
    )
    from rextio.source.wheel_authority import verify_source_wheel

    preview = RextioConfig(
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive="authority/demo_pkg-1.0.0-py3-none-any.whl",
                    source_archive_sha256=wheel_sha256,
                )
            }
        )
    )
    analysis = _analyze(project, preview)
    plan = analysis.external_source_plan
    if plan is None or plan.status != "preview-ready":
        raise AssertionError("tiny installed dependency did not produce a C5 preview plan")
    wheel_path = project / "authority/demo_pkg-1.0.0-py3-none-any.whl"
    wheel = verify_source_wheel(wheel_path, expected_sha256=wheel_sha256, plan=plan)
    analyses = tuple(analyze_external_source_snapshot(item) for item in wheel.snapshots)
    manifest = build_source_lock_v2_manifest(
        plan=plan,
        wheel=wheel,
        analyses=analyses,
        owner="Rextio Full C6 E2E Owner",
        trusted_public_key_sha256=key_sha256,
    )
    observed_public, signature = _sign(
        seed,
        SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX + manifest.canonical_json_bytes,
    )
    if observed_public != public_key:
        raise AssertionError("ephemeral SourceLock signer changed public keys")
    envelope = SourceLockV2Signature.from_signature(
        public_key_sha256=key_sha256,
        manifest_sha256=manifest.manifest_sha256,
        signature=signature,
    )
    authority = project / "authority"
    (authority / "rextio.external-source.lock.v2.json").write_bytes(
        manifest.canonical_json_bytes
    )
    (authority / "rextio.external-source.lock.v2.sig.json").write_bytes(
        envelope.canonical_json_bytes
    )


def _write_project(project: Path) -> None:
    project.mkdir(mode=0o700)
    (project / "authority").mkdir(mode=0o700)
    (project / "policy").mkdir(mode=0o700)
    (project / "app.py").write_text(
        "import demo_pkg\n\n\n"
        "def local_seed(x: int) -> int:\n"
        "    return x + 1\n\n\n"
        "def calculate(x: int) -> int:\n"
        "    return demo_pkg.affine(x)\n",
        encoding="utf-8",
    )
    (project / "LICENSE").write_text(
        "MIT License\n\nCopyright (c) 2026 Rextio Full C6 E2E\n",
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        "[build-system]\n"
        'requires = ["setuptools>=77"]\n'
        'build-backend = "setuptools.build_meta"\n\n'
        "[project]\n"
        'name = "full-c6-demo"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.11"\n'
        'license = "MIT"\n'
        'license-files = ["LICENSE"]\n\n'
        "[tool.setuptools]\n"
        'py-modules = ["app"]\n',
        encoding="utf-8",
    )


def _prepare_preflight(project: Path, config: Any, analysis_scope: Any) -> Any:
    from rextio.build.full_c6_pipeline import prepare_full_c6_external_build

    initial = _analyze(project, config, analysis_scope=analysis_scope)
    return prepare_full_c6_external_build(
        project_root=project,
        initial_analysis=initial,
        config=config,
        analysis_scope=analysis_scope,
        reanalyze=lambda registry: _analyze(
            project,
            config,
            registry,
            analysis_scope,
        ),
    )


def _generate(project: Path, config: Any, preflight: Any) -> Any:
    from rextio.build.orchestrator import generate_source_artifact
    from rextio.targets.plan import create_target_plan

    target_plan = create_target_plan(project, config)
    return generate_source_artifact(
        project,
        preflight.analysis,
        "cpython",
        boundary_fallback_threshold=config.build.fallback_threshold,
        target_plan=target_plan,
        rust_importable=config.rust.importable,
        rust_crate_name=config.rust.crate_name,
        embedding_enabled=config.embedding.enabled,
        full_c6_external_context=preflight.context,
    )


def _generate_cargo_seed(project: Path, config: Any) -> Any:
    """Generate only the dependency-equivalent crate used to prepare owner Cargo pins."""
    from rextio.build.orchestrator import generate_source_artifact
    from rextio.targets.plan import create_target_plan

    analysis = _analyze(project, config)
    target_plan = create_target_plan(project, config)
    return generate_source_artifact(
        project,
        analysis,
        "cpython",
        boundary_fallback_threshold=config.build.fallback_threshold,
        target_plan=target_plan,
        rust_importable=config.rust.importable,
        rust_crate_name=config.rust.crate_name,
        embedding_enabled=config.embedding.enabled,
    )


def _prepare_cargo_inputs(
    project: Path,
    *,
    config: Any,
) -> tuple[str, str, Any]:
    from rextio.build.full_c6_cargo_workspace import (
        collect_full_c6_cargo_dependency_workspace,
        compute_full_c6_cargo_vendor_tree_sha256,
    )
    from rextio.build.full_c6_host_inputs import FULL_C6_CARGO_ROOT_PACKAGE
    from rextio.build.toolchain_identity import capture_cargo_sources

    # Cargo pins are owner inputs to the sealed analysis scope, so prepare them
    # from a dependency-equivalent ordinary crate before collecting that scope.
    # The strict crate is regenerated and byte-checked in every later lifecycle.
    generated = _generate_cargo_seed(project, config)
    rust_dir = generated.layout.rust_dir
    cargo = str(Path(config.toolchain.cargo).absolute())
    _run([cargo, "generate-lockfile"], cwd=rust_dir, timeout=1_800)
    generated_lock = rust_dir / "Cargo.lock"
    if not generated_lock.is_file():
        raise AssertionError("online fixture preparation did not create Cargo.lock")
    owner_lock = project / "authority" / "Cargo.lock"
    shutil.copyfile(generated_lock, owner_lock)
    owner_lock.chmod(0o600)

    vendor = project / "cargo-vendor"
    _run(
        [cargo, "vendor", "--locked", str(vendor)],
        cwd=rust_dir,
        timeout=1_800,
    )
    if generated_lock.read_bytes() != owner_lock.read_bytes():
        raise AssertionError("cargo vendor changed the externally prepared Cargo.lock")
    cargo_lock_sha256 = _sha256(owner_lock.read_bytes())
    cargo_vendor_sha256 = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    sources = capture_cargo_sources(
        owner_lock,
        root_package=FULL_C6_CARGO_ROOT_PACKAGE,
        logical_name="Cargo.lock",
    )
    workspace = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=owner_lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=cargo_vendor_sha256,
    )
    return cargo_lock_sha256, cargo_vendor_sha256, workspace


def _production_input_snapshot(
    project: Path,
    *,
    generated: Any,
    cargo_workspace: Any,
) -> Any:
    from rextio.artifacts.evidence import EvidenceFileRef
    from rextio.build.supply_chain import (
        capture_generated_python_inputs,
        capture_generated_rust_inputs,
        capture_project_source_snapshot,
    )

    snapshot = capture_project_source_snapshot(
        project_root=project,
        plan=generated.plan,
    )
    snapshot = capture_generated_python_inputs(
        snapshot,
        project_root=project,
        layout=generated.layout,
    )
    snapshot = capture_generated_rust_inputs(
        snapshot,
        project_root=project,
        layout=generated.layout,
    )
    generated_rust = tuple(
        item
        for item in snapshot.generated_rust
        if not item.logical_path.endswith("/.cargo/config.toml")
    )
    lock = cargo_workspace.cargo_sources.lock_file
    snapshot = replace(
        snapshot,
        generated_rust=generated_rust,
        cargo_lock=EvidenceFileRef(
            logical_path=lock.logical_name,
            sha256=lock.sha256,
            size=lock.size,
            role="generated-cargo-lock",
        ),
    )
    if snapshot.unavailable_reason is not None:
        raise AssertionError(
            f"Full C6 fixture input snapshot is unavailable: {snapshot.unavailable_reason}"
        )
    return snapshot


def _write_license_locks(
    project: Path,
    *,
    config: Any,
    preflight: Any,
    cargo_workspace: Any,
) -> None:
    from rextio.artifacts.evidence import (
        CARGO_LICENSE_POLICY,
        CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
        CARGO_LICENSE_POLICY_ACTION_SCOPES,
        CARGO_LICENSE_POLICY_LOCK_FILENAME,
        CARGO_LICENSE_POLICY_LOCK_KIND,
        CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
        PROJECT_SOURCE_LICENSE_POLICY,
        PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
        PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES,
        PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME,
        PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
        PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
        canonical_json_bytes,
    )
    from rextio.build.cargo_license_policy import (
        collect_component_license_policy_verification,
    )
    from rextio.build.full_c6_production import _cargo_package_refs
    from rextio.build.license_inventory import collect_component_license_inventory
    from rextio.build.source_license_policy import (
        collect_project_source_license_policy_verification,
    )
    from rextio.build.transformation_inventory import (
        collect_source_transformation_inventory,
    )
    from rextio.build.transformation_verification import (
        collect_scoped_source_transformation_replay_authority,
    )

    generated = _generate(project, config, preflight)
    snapshot = _production_input_snapshot(
        project,
        generated=generated,
        cargo_workspace=cargo_workspace,
    )
    inventory = collect_source_transformation_inventory(
        project_root=project,
        plan=generated.plan,
        input_snapshot=snapshot,
    )
    if inventory is None:
        raise AssertionError("Full C6 fixture transformation inventory is unavailable")
    replay = collect_scoped_source_transformation_replay_authority(
        project_root=project,
        plan=generated.plan,
        input_snapshot=snapshot,
        transformation_inventory=inventory,
        embedding_enabled=False,
        boundary_fallback_threshold=config.build.fallback_threshold,
        external_native_registry=preflight.context.registry,
        external_runtime_guard=preflight.context.runtime_guard,
        full_c6_analysis_scope=preflight.context.analysis_scope,
        full_c6_config=config,
    )
    if replay is None:
        raise AssertionError("Full C6 fixture source replay is unavailable")
    verification = replay.verification
    verification_sha256 = _sha256(canonical_json_bytes(verification.to_dict()))
    source_document = {
        "schema_version": PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
        "scope": PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": PROJECT_SOURCE_LICENSE_POLICY,
        "source_transformation_verification_sha256": verification_sha256,
        "source_input_set_sha256": verification.source_input_set_sha256,
        "project_sources": [item.to_dict() for item in verification.source_inputs],
        "generated_rust": verification.generated_rust.to_dict(),
        "license_declarations": {
            "project_sources": "MIT",
            "generated_rust": "MIT",
        },
        "attestation": {
            "attestor": "Rextio Full C6 E2E",
            "attestor_kind": "organization",
            "attestor_relationship": "organization-owner",
            "decision": "allow",
            "action_scopes": list(PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }
    source_path = project / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME
    source_path.write_bytes(canonical_json_bytes(source_document))
    source_path.chmod(0o600)
    if (
        collect_project_source_license_policy_verification(
            project_root=project,
            source_transformation_verification=verification,
        )
        is None
    ):
        raise AssertionError("Full C6 project source license lock did not verify")

    packages = _cargo_package_refs(
        cargo_workspace,
        root_name=cargo_workspace.cargo_sources.root_package,
    )
    component_inventory = collect_component_license_inventory(packages)
    if component_inventory is None:
        raise AssertionError("Full C6 fixture Cargo license inventory is unavailable")
    inventory_sha256 = _sha256(canonical_json_bytes(component_inventory.to_dict()))
    registry_records = [
        record.to_dict()
        for record in component_inventory.records
        if record.kind == "registry"
    ]
    if not registry_records:
        raise AssertionError("Full C6 fixture Cargo graph has no registry packages")
    cargo_document = {
        "schema_version": CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": CARGO_LICENSE_POLICY_LOCK_KIND,
        "scope": COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": CARGO_LICENSE_POLICY,
        "component_license_inventory_sha256": inventory_sha256,
        "registry_components": registry_records,
        "attestation": {
            "attestor": "Rextio Full C6 E2E",
            "attestor_kind": "organization",
            "attestor_relationship": "organization-owner",
            "decision": "allow",
            "action_scopes": list(CARGO_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }
    cargo_path = project / CARGO_LICENSE_POLICY_LOCK_FILENAME
    cargo_path.write_bytes(canonical_json_bytes(cargo_document))
    cargo_path.chmod(0o600)
    if (
        collect_component_license_policy_verification(
            project_root=project,
            component_license_inventory=component_inventory,
        )
        is None
    ):
        raise AssertionError("Full C6 Cargo license lock did not verify")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_canonical_document(path: Path) -> tuple[bytes, dict[str, object]]:
    raw = path.read_bytes()
    document = json.loads(raw)
    if type(document) is not dict or _canonical_json_bytes(document) != raw:
        raise AssertionError(f"{path.name} is not canonical JSON")
    return raw, document


def _installed_rextio_entrypoint() -> Path:
    candidate = Path(sys.executable).with_name(
        "rextio.exe" if os.name == "nt" else "rextio"
    )
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise AssertionError("installed-wheel E2E lacks the rextio console entrypoint")
    return candidate


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
    }
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _process_table() -> dict[int, tuple[int, str]]:
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,comm="],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"could not observe Cargo child processes: {completed.stderr}")
    table: dict[int, tuple[int, str]] = {}
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3:
            continue
        try:
            pid, parent = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        table[pid] = (parent, fields[2])
    return table


def _descendant_cargo_pids(root_pid: int) -> set[int]:
    table = _process_table()
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _command) in table.items():
            if parent in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    return {
        pid
        for pid in descendants - {root_pid}
        if Path(table[pid][1]).name == "cargo"
    }


def _active_quarantine_names() -> set[str]:
    root = Path(tempfile.gettempdir()).resolve()
    return {
        item.name
        for item in root.glob("rextio-full-c6-*")
        if item.is_dir()
    }


def _process_group_is_alive(process_group_id: int) -> bool:
    completed = subprocess.run(
        ["ps", "-axo", "pgid=,stat="],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"could not inspect process group {process_group_id}: {completed.stderr}"
        )
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            observed_group = int(fields[0])
        except ValueError:
            continue
        if observed_group == process_group_id and not fields[1].startswith("Z"):
            return True
    return False


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    stage: str,
    grace_seconds: float = 5.0,
) -> None:
    process_group_id = process.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except (PermissionError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass
    if _process_group_is_alive(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{stage} root process did not exit after SIGKILL") from exc
    deadline = time.monotonic() + grace_seconds
    while _process_group_is_alive(process_group_id) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _process_group_is_alive(process_group_id):
        raise AssertionError(f"{stage} left process group {process_group_id} alive")


def _read_bounded_process_log(
    stream: BinaryIO,
    *,
    max_bytes: int = 1_048_576,
) -> str:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    if size <= max_bytes:
        payload = stream.read()
    else:
        side = max_bytes // 2
        prefix = stream.read(side)
        stream.seek(-side, os.SEEK_END)
        suffix = stream.read(side)
        omitted = size - len(prefix) - len(suffix)
        payload = (
            prefix
            + f"\n... {omitted} log bytes omitted ...\n".encode("ascii")
            + suffix
        )
    return payload.decode("utf-8", errors="replace")


def _xcode_hardlink_diagnostic_sha256(
    domain: str,
    payload: dict[str, object],
) -> str:
    canonical = json.dumps(
        {"domain": domain, **payload},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _open_xcode_hardlink_target(
    *,
    boundary: Path,
    target_relative_path: PurePosixPath,
    expected_stamp_sha256: str,
) -> Any:
    from rextio.build import toolchain_support_lock as support_lock

    if (
        not boundary.is_absolute()
        or target_relative_path.is_absolute()
        or not target_relative_path.parts
        or any(part in {"", ".", ".."} for part in target_relative_path.parts)
        or len(target_relative_path.as_posix().encode("utf-8"))
        > _XCODE_HARDLINK_MAX_PATH_BYTES
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode hardlink diagnostic target is invalid"
        )
    target = boundary.joinpath(*target_relative_path.parts)
    chain = support_lock._open_directory_chain(target.parent)
    file_fd = -1
    try:
        parent_fd = chain[-1][0]
        file_fd = os.open(
            target.name,
            os.O_RDONLY
            | support_lock._require_flag("O_NOFOLLOW")
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        opened = support_lock._stamp(os.fstat(file_fd))
        linked = support_lock._stamp(
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        )
        if (
            opened != linked
            or not stat.S_ISREG(opened.mode)
            or opened.links != _XCODE_HARDLINK_ALIAS_COUNT
            or support_lock._xcode_hardlink_full_stamp_sha256(opened)
            != expected_stamp_sha256
        ):
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode hardlink diagnostic target changed"
            )
        support_lock._verify_directory_chain(chain)
        return opened
    except support_lock.ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode hardlink diagnostic target is unavailable"
        ) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        support_lock._close_directory_chain(chain)


def _bounded_xcode_hardlink_alias_message(
    *,
    boundary: Path,
    target_relative_path: PurePosixPath,
    expected_stamp_sha256: str,
    app_boundary: Path | None = None,
    app_target_relative_path: PurePosixPath | None = None,
) -> str:
    from rextio.build import toolchain_support_lock as support_lock

    if re.fullmatch(r"[0-9a-f]{64}", expected_stamp_sha256) is None:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode hardlink diagnostic stamp is invalid"
        )

    def scan_once(
        *,
        scan_boundary: Path,
        scan_target_relative_path: PurePosixPath,
        max_entries: int,
    ) -> tuple[Any, tuple[str, ...]]:
        target_stamp = _open_xcode_hardlink_target(
            boundary=scan_boundary,
            target_relative_path=scan_target_relative_path,
            expected_stamp_sha256=expected_stamp_sha256,
        )
        boundary_chain = support_lock._open_directory_chain(scan_boundary)
        aliases: list[str] = []
        entry_count = 0

        def walk(
            directory_fd: int,
            *,
            relative: PurePosixPath,
        ) -> Any:
            nonlocal entry_count
            directory_before = support_lock._stamp(os.fstat(directory_fd))
            if not stat.S_ISDIR(directory_before.mode):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode hardlink diagnostic directory is invalid"
                )
            names = support_lock._bounded_directory_names(directory_fd)
            ordered = sorted(
                names,
                key=lambda item: (support_lock._alias(item), item),
            )
            for name in ordered:
                entry_count += 1
                if entry_count > max_entries:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode hardlink diagnostic entry bound exceeded"
                    )
                child_relative = relative / name
                logical = child_relative.as_posix()
                if (
                    len(child_relative.parts) > _XCODE_HARDLINK_MAX_DEPTH
                    or len(logical.encode("utf-8"))
                    > _XCODE_HARDLINK_MAX_PATH_BYTES
                ):
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode hardlink diagnostic path bound exceeded"
                    )
                observed = support_lock._stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if stat.S_ISDIR(observed.mode):
                    child_fd = support_lock._open_child_directory(directory_fd, name)
                    try:
                        opened = support_lock._stamp(os.fstat(child_fd))
                        if opened != observed:
                            raise support_lock.ToolchainSupportLockError(
                                "toolchain support xcode hardlink diagnostic directory changed"
                            )
                        child_final = walk(
                            child_fd,
                            relative=child_relative,
                        )
                        linked = support_lock._stamp(
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        )
                        if linked != child_final:
                            raise support_lock.ToolchainSupportLockError(
                                "toolchain support xcode hardlink diagnostic directory changed"
                            )
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(observed.mode) or (
                    observed.device,
                    observed.inode,
                ) != (target_stamp.device, target_stamp.inode):
                    continue
                if len(aliases) >= _XCODE_HARDLINK_ALIAS_COUNT:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode hardlink diagnostic alias bound exceeded"
                    )
                file_fd = -1
                try:
                    file_fd = os.open(
                        name,
                        os.O_RDONLY
                        | support_lock._require_flag("O_NOFOLLOW")
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=directory_fd,
                    )
                    opened = support_lock._stamp(os.fstat(file_fd))
                    linked = support_lock._stamp(
                        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    )
                    if (
                        opened != observed
                        or linked != opened
                        or opened != target_stamp
                    ):
                        raise support_lock.ToolchainSupportLockError(
                            "toolchain support xcode hardlink diagnostic alias changed"
                        )
                except support_lock.ToolchainSupportLockError:
                    raise
                except OSError as exc:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode hardlink diagnostic alias is unavailable"
                    ) from exc
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
                aliases.append(logical)
            after_names = support_lock._bounded_directory_names(directory_fd)
            if sorted(
                after_names,
                key=lambda item: (support_lock._alias(item), item),
            ) != ordered:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode hardlink diagnostic inventory changed"
                )
            directory_after = support_lock._stamp(os.fstat(directory_fd))
            if not support_lock._same_stable_stamp(
                directory_after,
                directory_before,
            ):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode hardlink diagnostic directory changed"
                )
            return directory_after

        try:
            root_fd = boundary_chain[-1][0]
            walk(root_fd, relative=PurePosixPath())
            support_lock._verify_directory_chain(boundary_chain)
        except support_lock.ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode hardlink diagnostic scan failed closed"
            ) from exc
        finally:
            support_lock._close_directory_chain(boundary_chain)
        if (
            not 1 <= len(aliases) <= _XCODE_HARDLINK_ALIAS_COUNT
            or scan_target_relative_path.as_posix() not in aliases
        ):
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode hardlink diagnostic alias count differs"
            )
        digests = tuple(
            sorted(
                _xcode_hardlink_diagnostic_sha256(
                    "rextio.full-c6-xcode-hardlink-path-diagnostic.v1",
                    {"root_relative_path": relative_path},
                )
                for relative_path in aliases
            )
        )
        return target_stamp, digests

    def stable_scan(
        *,
        scan_boundary: Path,
        scan_target_relative_path: PurePosixPath,
        max_entries: int,
    ) -> tuple[Any, tuple[str, ...]]:
        first = scan_once(
            scan_boundary=scan_boundary,
            scan_target_relative_path=scan_target_relative_path,
            max_entries=max_entries,
        )
        second = scan_once(
            scan_boundary=scan_boundary,
            scan_target_relative_path=scan_target_relative_path,
            max_entries=max_entries,
        )
        if first != second:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode hardlink diagnostic changed across scans"
            )
        final_target_stamp = _open_xcode_hardlink_target(
            boundary=scan_boundary,
            target_relative_path=scan_target_relative_path,
            expected_stamp_sha256=expected_stamp_sha256,
        )
        if final_target_stamp != first[0]:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode hardlink diagnostic changed after scans"
            )
        return first

    if (app_boundary is None) != (app_target_relative_path is None):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode hardlink diagnostic app scope is invalid"
        )
    scope = "toolchain"
    try:
        result = stable_scan(
            scan_boundary=boundary,
            scan_target_relative_path=target_relative_path,
            max_entries=_XCODE_HARDLINK_MAX_ENTRIES,
        )
    except support_lock.ToolchainSupportLockError as exc:
        if (
            str(exc)
            != "toolchain support xcode hardlink diagnostic entry bound exceeded"
            or app_boundary is None
            or app_target_relative_path is None
        ):
            raise
        scope = "app"
        result = stable_scan(
            scan_boundary=app_boundary,
            scan_target_relative_path=app_target_relative_path,
            max_entries=_XCODE_HARDLINK_APP_MAX_ENTRIES,
        )
    if (
        len(result[1]) < _XCODE_HARDLINK_ALIAS_COUNT
        and app_boundary is not None
        and app_target_relative_path is not None
        and scope != "app"
    ):
        scope = "app"
        result = stable_scan(
            scan_boundary=app_boundary,
            scan_target_relative_path=app_target_relative_path,
            max_entries=_XCODE_HARDLINK_APP_MAX_ENTRIES,
        )
    target_stamp, digests = result
    message = (
        "toolchain support xcode hardlink aliases "
        f"(scope={scope},nlink={target_stamp.links},count={len(digests)},"
        f"digests={','.join(digests)})"
    )
    if (
        not message.isascii()
        or len(message) > 278
        or any(
            character not in " -_.,()=" and not character.isalnum()
            for character in message
        )
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode hardlink diagnostic output is invalid"
        )
    return message


def _diagnose_exact_xcode_hardlink_aliases(
    plan: object,
    error: BaseException,
) -> str | None:
    from rextio.build import full_c6_toolchain_support as support
    from rextio.build.toolchain_support_lock import ToolchainSupportLockError

    if (
        type(plan) is not support.FullC6ToolchainSupportPlan
        or plan._target_triple != "aarch64-apple-darwin"
        or support.MACOS_DEVELOPER_DIR
        != Path("/Applications/Xcode.app/Contents/Developer")
    ):
        return None
    match: re.Match[str] | None = None
    current: BaseException | None = error
    seen: set[int] = set()
    for _ in range(16):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if type(current) is ToolchainSupportLockError:
            match = _XCODE_HARDLINK_ERROR_RE.fullmatch(str(current))
            if match is not None:
                break
        current = current.__cause__ or current.__context__
    if match is None:
        return None
    expected_stamp_sha256 = match.group("stamp")
    roots = tuple(
        locator
        for locator in plan._root_locators
        if locator.logical_role == _XCODE_HARDLINK_ROLE
    )
    if len(roots) != 1:
        return None
    boundary = (
        support.MACOS_DEVELOPER_DIR
        / "Toolchains"
        / "XcodeDefault.xctoolchain"
    )
    try:
        root_relative = roots[0]._absolute_path.relative_to(boundary)
    except ValueError:
        return None
    if (
        len(root_relative.parts) != 4
        or root_relative.parts[:3] != ("usr", "lib", "clang")
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", root_relative.parts[3]) is None
    ):
        return None
    target_relative = PurePosixPath(*root_relative.parts) / PurePosixPath(
        _XCODE_HARDLINK_RELATIVE_PATH
    )
    app_boundary = Path("/Applications/Xcode.app")
    app_target_relative = PurePosixPath(
        *(boundary.joinpath(*target_relative.parts).relative_to(app_boundary).parts)
    )
    return _bounded_xcode_hardlink_alias_message(
        boundary=boundary,
        target_relative_path=target_relative,
        expected_stamp_sha256=expected_stamp_sha256,
        app_boundary=app_boundary,
        app_target_relative_path=app_target_relative,
    )


def _open_xcode_topology_regular(
    *,
    boundary: Path,
    relative_path: PurePosixPath,
    expected: Any,
) -> None:
    from rextio.build import toolchain_support_lock as support_lock

    logical = relative_path.as_posix()
    if (
        not boundary.is_absolute()
        or relative_path.is_absolute()
        or not relative_path.parts
        or any(part in {"", ".", ".."} for part in relative_path.parts)
        or len(relative_path.parts) > _XCODE_HARDLINK_MAX_DEPTH
        or len(logical.encode("utf-8")) > _XCODE_HARDLINK_MAX_PATH_BYTES
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology final path is invalid"
        )
    target = boundary.joinpath(*relative_path.parts)
    chain = support_lock._open_directory_chain(target.parent)
    descriptor = -1
    try:
        parent_fd = chain[-1][0]
        descriptor = os.open(
            target.name,
            os.O_RDONLY
            | support_lock._require_flag("O_NOFOLLOW")
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        opened = support_lock._stamp(os.fstat(descriptor))
        linked = support_lock._stamp(
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        )
        if opened != expected or linked != opened or not stat.S_ISREG(opened.mode):
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode topology final stamp changed"
            )
        support_lock._verify_directory_chain(chain)
    except support_lock.ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology final entry is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        support_lock._close_directory_chain(chain)


def _bounded_xcode_hardlink_topology_message(
    *,
    support_root: Path,
    app_boundary: Path,
    structured: bool = False,
) -> str | _XcodeHardlinkTopology:
    """Fingerprint every shared regular-file inode in one Xcode support root."""

    from rextio.build import toolchain_support_lock as support_lock

    try:
        support_root.relative_to(app_boundary)
    except ValueError:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology scope is invalid"
        ) from None
    if not support_root.is_absolute() or not app_boundary.is_absolute():
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology scope is invalid"
        )

    def scan_tree(
        *,
        boundary: Path,
        max_entries: int,
        visit: Any,
    ) -> None:
        chain = support_lock._open_directory_chain(boundary)
        entry_count = 0

        def walk(
            directory_fd: int,
            *,
            relative: PurePosixPath,
            parent_chain: tuple[dict[str, str], ...],
        ) -> Any:
            nonlocal entry_count
            directory_before = support_lock._stamp(os.fstat(directory_fd))
            if not stat.S_ISDIR(directory_before.mode):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology directory is invalid"
                )
            current_relative = relative.as_posix() if relative.parts else ""
            current_chain = (
                *parent_chain,
                {
                    "relative_path_sha256": _xcode_hardlink_diagnostic_sha256(
                        "rextio.full-c6-xcode-hardlink-topology-parent-path.v1",
                        {"relative_path": current_relative},
                    ),
                    "full_stamp_sha256": (
                        support_lock._xcode_hardlink_full_stamp_sha256(
                            directory_before
                        )
                    ),
                },
            )
            names = support_lock._bounded_directory_names(directory_fd)
            ordered = sorted(names, key=lambda item: (support_lock._alias(item), item))
            for name in ordered:
                entry_count += 1
                if entry_count > max_entries:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode topology entry bound exceeded"
                    )
                child_relative = relative / name
                logical = child_relative.as_posix()
                if (
                    len(child_relative.parts) > _XCODE_HARDLINK_MAX_DEPTH
                    or len(logical.encode("utf-8"))
                    > _XCODE_HARDLINK_MAX_PATH_BYTES
                ):
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode topology path bound exceeded"
                    )
                observed = support_lock._stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if stat.S_ISDIR(observed.mode):
                    child_fd = support_lock._open_child_directory(directory_fd, name)
                    try:
                        if support_lock._stamp(os.fstat(child_fd)) != observed:
                            raise support_lock.ToolchainSupportLockError(
                                "toolchain support xcode topology directory changed"
                            )
                        child_final = walk(
                            child_fd,
                            relative=child_relative,
                            parent_chain=current_chain,
                        )
                        linked = support_lock._stamp(
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        )
                        if child_final != observed or linked != child_final:
                            raise support_lock.ToolchainSupportLockError(
                                "toolchain support xcode topology directory changed"
                            )
                    finally:
                        os.close(child_fd)
                    continue
                if stat.S_ISREG(observed.mode):
                    visit(
                        directory_fd=directory_fd,
                        name=name,
                        relative_path=child_relative,
                        observed=observed,
                        parent_chain=current_chain,
                    )
            after_names = support_lock._bounded_directory_names(directory_fd)
            if sorted(
                after_names,
                key=lambda item: (support_lock._alias(item), item),
            ) != ordered:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology inventory changed"
                )
            directory_after = support_lock._stamp(os.fstat(directory_fd))
            if not support_lock._same_stable_stamp(
                directory_after,
                directory_before,
            ):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology directory changed"
                )
            return directory_after

        try:
            walk(chain[-1][0], relative=PurePosixPath(), parent_chain=())
            support_lock._verify_directory_chain(chain)
        except support_lock.ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode topology scan failed closed"
            ) from exc
        finally:
            support_lock._close_directory_chain(chain)

    def open_observed_regular(
        *,
        directory_fd: int,
        name: str,
        observed: Any,
    ) -> Any:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | support_lock._require_flag("O_NOFOLLOW")
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            opened = support_lock._stamp(os.fstat(descriptor))
            linked = support_lock._stamp(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            if opened != observed or linked != opened:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology regular entry changed"
                )
            return opened
        except support_lock.ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode topology regular entry is unavailable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def scan_once() -> tuple[
        tuple[tuple[str, str, Any, tuple[str, ...], tuple[str, ...]], ...],
        int,
        int,
    ]:
        support_groups: dict[tuple[int, int], dict[str, object]] = {}

        def visit_support(
            *,
            directory_fd: int,
            name: str,
            relative_path: PurePosixPath,
            observed: Any,
            parent_chain: tuple[dict[str, str], ...],
        ) -> None:
            del parent_chain
            if observed.links <= 1:
                return
            opened = open_observed_regular(
                directory_fd=directory_fd,
                name=name,
                observed=observed,
            )
            key = opened.device, opened.inode
            group = support_groups.get(key)
            if group is None:
                if len(support_groups) >= _XCODE_HARDLINK_TOPOLOGY_MAX_GROUPS:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support xcode topology group bound exceeded"
                    )
                group = {"stamp": opened, "paths": []}
                support_groups[key] = group
            elif group["stamp"] != opened:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology inode stamp changed"
                )
            paths = cast(list[str], group["paths"])
            if len(paths) >= _XCODE_HARDLINK_TOPOLOGY_MAX_MEMBERS:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology member bound exceeded"
                )
            paths.append(relative_path.as_posix())

        scan_tree(
            boundary=support_root,
            max_entries=_XCODE_HARDLINK_MAX_ENTRIES,
            visit=visit_support,
        )
        if not support_groups:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode topology contains no shared files"
            )

        aliases: dict[tuple[int, int], list[tuple[str, str, str]]] = {
            key: [] for key in support_groups
        }

        def visit_app(
            *,
            directory_fd: int,
            name: str,
            relative_path: PurePosixPath,
            observed: Any,
            parent_chain: tuple[dict[str, str], ...],
        ) -> None:
            key = observed.device, observed.inode
            group = support_groups.get(key)
            if group is None:
                return
            opened = open_observed_regular(
                directory_fd=directory_fd,
                name=name,
                observed=observed,
            )
            if group["stamp"] != opened:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology alias stamp differs"
                )
            members = aliases[key]
            if len(members) >= _XCODE_HARDLINK_TOPOLOGY_MAX_MEMBERS:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology alias bound exceeded"
                )
            logical = relative_path.as_posix()
            members.append(
                (
                    logical,
                    _xcode_hardlink_diagnostic_sha256(
                        "rextio.full-c6-xcode-hardlink-topology-alias-path.v1",
                        {"app_relative_path": logical},
                    ),
                    _xcode_hardlink_diagnostic_sha256(
                        "rextio.full-c6-xcode-hardlink-topology-parent-chain.v1",
                        {"directories": list(parent_chain)},
                    ),
                )
            )

        scan_tree(
            boundary=app_boundary,
            max_entries=_XCODE_HARDLINK_APP_MAX_ENTRIES,
            visit=visit_app,
        )

        records: list[
            tuple[str, str, Any, tuple[str, ...], tuple[str, ...]]
        ] = []
        support_member_count = 0
        alias_count = 0
        for key, group in support_groups.items():
            del key
            stamp = group["stamp"]
            support_paths = tuple(sorted(cast(list[str], group["paths"])))
            ordered_aliases = tuple(
                sorted(
                    aliases[(stamp.device, stamp.inode)],
                    key=lambda item: (item[1], item[0]),
                )
            )
            if (
                len(ordered_aliases) != stamp.links
                or len({item[1] for item in ordered_aliases})
                != len(ordered_aliases)
            ):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support xcode topology alias count differs"
                )
            support_path_sha256s = tuple(
                sorted(
                    _xcode_hardlink_diagnostic_sha256(
                        (
                            "rextio.full-c6-xcode-hardlink-topology-"
                            "support-path.v1"
                        ),
                        {"support_relative_path": path},
                    )
                    for path in support_paths
                )
            )
            alias_parent_chain_merkle = _xcode_hardlink_diagnostic_sha256(
                "rextio.full-c6-xcode-hardlink-topology-alias-parents.v1",
                {
                    "aliases": [
                        {
                            "alias_path_sha256": path_sha256,
                            "parent_chain_sha256": parent_sha256,
                        }
                        for _path, path_sha256, parent_sha256 in ordered_aliases
                    ]
                },
            )
            policy_group_sha256 = _xcode_hardlink_diagnostic_sha256(
                "rextio.full-c6-xcode-hardlink-topology-policy-group.v1",
                {
                    "support_relative_path_sha256s": list(
                        support_path_sha256s
                    ),
                    "link_count": stamp.links,
                    "alias_count": len(ordered_aliases),
                    "alias_path_sha256s": [
                        item[1] for item in ordered_aliases
                    ],
                },
            )
            observation_group_sha256 = _xcode_hardlink_diagnostic_sha256(
                "rextio.full-c6-xcode-hardlink-topology-observation-group.v1",
                {
                    "policy_group_sha256": policy_group_sha256,
                    "full_stamp_sha256": (
                        support_lock._xcode_hardlink_full_stamp_sha256(stamp)
                    ),
                    "alias_parent_chain_merkle_sha256": (
                        alias_parent_chain_merkle
                    ),
                },
            )
            records.append(
                (
                    policy_group_sha256,
                    observation_group_sha256,
                    stamp,
                    support_paths,
                    tuple(item[0] for item in ordered_aliases),
                )
            )
            support_member_count += len(support_paths)
            alias_count += len(ordered_aliases)
        ordered_records = tuple(sorted(records, key=lambda item: item[0]))
        if len({item[0] for item in ordered_records}) != len(ordered_records):
            raise support_lock.ToolchainSupportLockError(
                "toolchain support xcode topology groups are ambiguous"
            )
        return ordered_records, support_member_count, alias_count

    first = scan_once()
    second = scan_once()
    if first != second:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology changed across scans"
        )
    for (
        _policy_group_sha256,
        _observation_group_sha256,
        stamp,
        support_paths,
        app_paths,
    ) in first[0]:
        for path in support_paths:
            _open_xcode_topology_regular(
                boundary=support_root,
                relative_path=PurePosixPath(path),
                expected=stamp,
            )
        for path in app_paths:
            _open_xcode_topology_regular(
                boundary=app_boundary,
                relative_path=PurePosixPath(path),
                expected=stamp,
            )
    policy_merkle = _xcode_hardlink_diagnostic_sha256(
        "rextio.full-c6-xcode-hardlink-topology-policy.v1",
        {"policy_group_sha256s": [item[0] for item in first[0]]},
    )
    observation_merkle = _xcode_hardlink_diagnostic_sha256(
        "rextio.full-c6-xcode-hardlink-topology-observation.v1",
        {
            "groups": [
                {
                    "policy_group_sha256": item[0],
                    "observation_group_sha256": item[1],
                }
                for item in first[0]
            ]
        },
    )
    topology = _XcodeHardlinkTopology(
        group_count=len(first[0]),
        support_member_count=first[1],
        alias_count=first[2],
        policy_merkle=policy_merkle,
        observation_merkle=observation_merkle,
    )
    if structured:
        return topology
    return _format_xcode_hardlink_topology_message(topology)


def _format_xcode_hardlink_topology_message(
    topology: _XcodeHardlinkTopology,
) -> str:
    from rextio.build import toolchain_support_lock as support_lock

    if type(topology) is not _XcodeHardlinkTopology:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology result is invalid"
        )
    message = (
        "toolchain support xcode hardlink topology "
        f"(groups={topology.group_count},"
        f"support_members={topology.support_member_count},"
        f"aliases={topology.alias_count},"
        f"policy_merkle={topology.policy_merkle},"
        f"observation_merkle={topology.observation_merkle})"
    )
    if (
        not message.isascii()
        or len(message) > 278
        or any(
            character not in " -_.,()=" and not character.isalnum()
            for character in message
        )
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology output is invalid"
        )
    return message


def _format_xcode_topology_identity(
    *,
    topology: _XcodeHardlinkTopology,
    clang_version: str,
    version_raw_sha256: str,
) -> str:
    from rextio.build import toolchain_support_lock as support_lock

    if (
        type(topology) is not _XcodeHardlinkTopology
        or topology.group_count != _XCODE_HARDLINK_POLICY_GROUP_COUNT
        or topology.support_member_count
        != _XCODE_HARDLINK_POLICY_SUPPORT_MEMBER_COUNT
        or topology.alias_count != _XCODE_HARDLINK_POLICY_ALIAS_COUNT
        or not secrets.compare_digest(
            topology.policy_merkle,
            _XCODE_HARDLINK_POLICY_MERKLE,
        )
        or _XCODE_CLANG_RESOURCE_VERSION_RE.fullmatch(clang_version) is None
        or re.fullmatch(r"[0-9a-f]{64}", version_raw_sha256) is None
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology identity differs"
        )
    message = (
        "toolchain support xcode topology identity "
        f"(groups={topology.group_count},"
        f"members={topology.support_member_count},"
        f"aliases={topology.alias_count},"
        f"policy={topology.policy_merkle},clang={clang_version},"
        f"version_raw={version_raw_sha256})"
    )
    if (
        not message.isascii()
        or len(message) > 278
        or any(
            character not in " -_.,()=" and not character.isalnum()
            for character in message
        )
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology identity output is invalid"
        )
    return message


def _diagnose_xcode_hardlink_topology(
    plan: object,
    error: BaseException,
) -> str | None:
    from rextio.build import full_c6_toolchain_support as support
    from rextio.build import toolchain_support_lock as support_lock
    from rextio.build.toolchain_support_lock import ToolchainSupportLockError

    if (
        type(plan) is not support.FullC6ToolchainSupportPlan
        or plan._target_triple != "aarch64-apple-darwin"
        or support.MACOS_DEVELOPER_DIR
        != Path("/Applications/Xcode.app/Contents/Developer")
    ):
        return None
    current: BaseException | None = error
    seen: set[int] = set()
    matched = False
    for _ in range(16):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if (
            type(current) is ToolchainSupportLockError
            and _XCODE_GENERIC_HARDLINK_ERROR_RE.fullmatch(str(current))
            is not None
        ):
            matched = True
            break
        current = current.__cause__ or current.__context__
    if not matched:
        return None
    roots = tuple(
        locator
        for locator in plan._root_locators
        if locator.logical_role == _XCODE_HARDLINK_ROLE
    )
    if len(roots) != 1:
        return None
    version_manifests = tuple(
        locator
        for locator in plan._manifest_locators
        if locator.logical_role == _XCODE_VERSION_PLIST_ROLE
    )
    if (
        len(version_manifests) != 1
        or version_manifests[0]._absolute_path != _XCODE_VERSION_PLIST
    ):
        return None
    toolchain_boundary = (
        support.MACOS_DEVELOPER_DIR
        / "Toolchains"
        / "XcodeDefault.xctoolchain"
    )
    try:
        root_relative = roots[0]._absolute_path.relative_to(toolchain_boundary)
    except ValueError:
        return None
    if (
        len(root_relative.parts) != 4
        or root_relative.parts[:3] != ("usr", "lib", "clang")
        or _XCODE_CLANG_RESOURCE_VERSION_RE.fullmatch(root_relative.parts[3])
        is None
    ):
        return None
    topology = _bounded_xcode_hardlink_topology_message(
        support_root=roots[0]._absolute_path,
        app_boundary=Path("/Applications/Xcode.app"),
        structured=True,
    )
    if type(topology) is not _XcodeHardlinkTopology:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support xcode topology result is invalid"
        )
    version_receipt = support_lock.capture_toolchain_support_file(
        version_manifests[0]
    )
    return _format_xcode_topology_identity(
        topology=topology,
        clang_version=root_relative.parts[3],
        version_raw_sha256=version_receipt.raw_sha256,
    )


def _bounded_linux_folded_name_topology_message(root: Path) -> str:
    from rextio.build import toolchain_support_lock as support_lock

    def scan_once() -> tuple[tuple[str, int], ...]:
        chain = support_lock._open_directory_chain(root)
        group_receipts: list[tuple[str, int]] = []
        entry_count = 0

        def walk(
            directory_fd: int,
            *,
            relative: PurePosixPath,
        ) -> Any:
            nonlocal entry_count
            directory_before = support_lock._stamp(os.fstat(directory_fd))
            if not stat.S_ISDIR(directory_before.mode):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support linux folded-name directory is invalid"
                )
            names = support_lock._bounded_directory_names(directory_fd)
            groups: dict[str, list[str]] = {}
            for name in names:
                groups.setdefault(support_lock._alias(name), []).append(name)
            directory_relative = relative.as_posix() if relative.parts else ""
            for folded_key, members in sorted(groups.items()):
                if len(members) < 2:
                    continue
                if len(members) > _LINUX_FOLDED_NAME_MAX_GROUP_MEMBERS:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support linux folded-name member bound exceeded"
                    )
                if len(group_receipts) >= _LINUX_FOLDED_NAME_MAX_GROUPS:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support linux folded-name group bound exceeded"
                    )
                group_receipts.append(
                    (
                        _xcode_hardlink_diagnostic_sha256(
                            "rextio.full-c6-linux-folded-name-group.v1",
                            {
                                "directory_relative_path": directory_relative,
                                "folded_key": folded_key,
                                "member_names": sorted(members),
                            },
                        ),
                        len(members),
                    )
                )
            ordered = sorted(
                names,
                key=lambda item: (support_lock._alias(item), item),
            )
            for name in ordered:
                entry_count += 1
                if entry_count > _LINUX_FOLDED_NAME_MAX_ENTRIES:
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support linux folded-name entry bound exceeded"
                    )
                child_relative = relative / name
                logical = child_relative.as_posix()
                if (
                    len(child_relative.parts) > _LINUX_FOLDED_NAME_MAX_DEPTH
                    or len(logical.encode("utf-8"))
                    > _LINUX_FOLDED_NAME_MAX_PATH_BYTES
                ):
                    raise support_lock.ToolchainSupportLockError(
                        "toolchain support linux folded-name path bound exceeded"
                    )
                observed = support_lock._stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if not stat.S_ISDIR(observed.mode):
                    continue
                child_fd = support_lock._open_child_directory(directory_fd, name)
                try:
                    opened = support_lock._stamp(os.fstat(child_fd))
                    if opened != observed:
                        raise support_lock.ToolchainSupportLockError(
                            "toolchain support linux folded-name directory changed"
                        )
                    child_final = walk(
                        child_fd,
                        relative=child_relative,
                    )
                    linked = support_lock._stamp(
                        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    )
                    if linked != child_final:
                        raise support_lock.ToolchainSupportLockError(
                            "toolchain support linux folded-name directory changed"
                        )
                finally:
                    os.close(child_fd)
            after_names = support_lock._bounded_directory_names(directory_fd)
            if sorted(
                after_names,
                key=lambda item: (support_lock._alias(item), item),
            ) != ordered:
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support linux folded-name inventory changed"
                )
            directory_after = support_lock._stamp(os.fstat(directory_fd))
            if not support_lock._same_stable_stamp(
                directory_after,
                directory_before,
            ):
                raise support_lock.ToolchainSupportLockError(
                    "toolchain support linux folded-name directory changed"
                )
            return directory_after

        try:
            walk(chain[-1][0], relative=PurePosixPath())
            support_lock._verify_directory_chain(chain)
        except support_lock.ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise support_lock.ToolchainSupportLockError(
                "toolchain support linux folded-name scan failed closed"
            ) from exc
        finally:
            support_lock._close_directory_chain(chain)
        ordered_receipts = tuple(sorted(group_receipts))
        if (
            len({item[0] for item in ordered_receipts})
            != len(ordered_receipts)
        ):
            raise support_lock.ToolchainSupportLockError(
                "toolchain support linux folded-name group hashes collide"
            )
        return ordered_receipts

    first = scan_once()
    second = scan_once()
    if first != second:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support linux folded-name topology changed across scans"
        )
    if not 1 <= len(first) <= _LINUX_FOLDED_NAME_MAX_GROUPS:
        raise support_lock.ToolchainSupportLockError(
            "toolchain support linux folded-name topology is empty"
        )
    merkle = _xcode_hardlink_diagnostic_sha256(
        "rextio.full-c6-linux-folded-name-topology.v1",
        {
            "groups": [
                {"group_sha256": digest, "member_count": member_count}
                for digest, member_count in first
            ]
        },
    )
    member_count = sum(item[1] for item in first)
    message = (
        "toolchain support linux folded-name topology "
        f"(groups={len(first)},members={member_count},merkle={merkle})"
    )
    if (
        not message.isascii()
        or len(message) > 278
        or any(
            character not in " -_.,()=" and not character.isalnum()
            for character in message
        )
    ):
        raise support_lock.ToolchainSupportLockError(
            "toolchain support linux folded-name output is invalid"
        )
    return message


def _diagnose_exact_linux_folded_name_topology(
    plan: object,
    error: BaseException,
) -> str | None:
    from rextio.build import full_c6_toolchain_support as support
    from rextio.build.toolchain_support_lock import ToolchainSupportLockError

    if (
        type(plan) is not support.FullC6ToolchainSupportPlan
        or plan._target_triple != "x86_64-unknown-linux-gnu"
    ):
        return None
    current: BaseException | None = error
    seen: set[int] = set()
    matched = False
    for _ in range(16):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if (
            type(current) is ToolchainSupportLockError
            and str(current) == _LINUX_FOLDED_NAME_CAUSE
        ):
            matched = True
            break
        current = current.__cause__ or current.__context__
    if not matched:
        return None
    roots = tuple(
        locator
        for locator in plan._root_locators
        if locator.logical_role == _LINUX_FOLDED_NAME_ROLE
    )
    if len(roots) != 1:
        return None
    return _bounded_linux_folded_name_topology_message(roots[0]._absolute_path)


def _format_support_lock_diagnostic(error: BaseException) -> str:
    from rextio.build.full_c6_toolchain_support import (
        FullC6ToolchainSupportError,
    )
    from rextio.build.toolchain_support_lock import ToolchainSupportLockError

    support_message = "<unavailable>"
    os_error_name = "<unavailable>"
    os_error_errno = "<unavailable>"
    other_error_type = "<unavailable>"
    other_error_message = "<unavailable>"
    current: BaseException | None = error
    seen: set[int] = set()
    for _ in range(16):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if type(current) is ToolchainSupportLockError:
            candidate = str(current)
            if (
                candidate.startswith("toolchain support ")
                and len(candidate) <= 278
                and candidate.isascii()
                and (
                    candidate
                    in _PATH_FREE_SUPPORT_LOCK_MESSAGES_WITH_SEMANTIC_SLASH
                    or all(
                        character.isalnum() or character in " -_.,()="
                        for character in candidate
                    )
                )
                and not (
                    candidate == _GENERIC_PERMISSION_MODE_CAUSE
                    and support_message.startswith(
                        f"{_GENERIC_PERMISSION_MODE_CAUSE} ("
                    )
                )
            ):
                support_message = candidate
        elif type(current) is FullC6ToolchainSupportError:
            candidate = str(current)
            if (
                other_error_message == "<unavailable>"
                and candidate.startswith("Full C6 ")
                and len(candidate) <= 278
                and candidate.isascii()
                and all(
                    character.isalnum() or character in " -_.,()="
                    for character in candidate
                )
            ):
                other_error_message = candidate
            if other_error_type == "<unavailable>":
                other_error_type = "FullC6ToolchainSupportError"
        elif (
            isinstance(current, OSError)
            and type(current).__module__ == "builtins"
        ):
            candidate_name = type(current).__name__
            if (
                candidate_name.isascii()
                and candidate_name.isidentifier()
                and len(candidate_name) <= 64
            ):
                os_error_name = candidate_name
            candidate_errno = current.errno
            if (
                type(candidate_errno) is int
                and -4096 <= candidate_errno <= 4096
            ):
                os_error_errno = str(candidate_errno)
        elif other_error_type == "<unavailable>":
            candidate_type = type(current)
            candidate_module = candidate_type.__module__
            candidate_name = candidate_type.__name__
            if (
                type(candidate_module) is str
                and (
                    candidate_module == "builtins"
                    or candidate_module == "rextio"
                    or candidate_module.startswith("rextio.")
                )
                and candidate_name.isascii()
                and candidate_name.isidentifier()
                and len(candidate_name) <= 32
            ):
                other_error_type = candidate_name
        current = current.__cause__ or current.__context__
    if support_message != "<unavailable>":
        other_error_message = "<unavailable>"
    diagnostic = (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={support_message}; "
        f"OSError={os_error_name}; errno={os_error_errno}; "
        f"OtherErrorType={other_error_type}; "
        f"OtherErrorMessage={other_error_message}"
    )
    # Worst case: 120 fixed ASCII bytes + 278 support/other-message bytes +
    # 13 bytes for the mutually exclusive unavailable message +
    # 64 OSError-name bytes + 5 errno bytes + 32 other-type bytes = 512.
    assert diagnostic.isascii()
    assert len(diagnostic.encode("ascii")) <= 512
    return diagnostic


def _format_support_lock_rewalk_difference(first: object, second: object) -> str:
    """Describe only the first path-free receipt delta across two captures."""
    from rextio.build.toolchain_support_lock import ToolchainSupportLock

    if type(first) is not ToolchainSupportLock or type(second) is not ToolchainSupportLock:
        raise ValueError("support-lock diagnostic requires exact typed locks")
    if first.scope != second.scope:
        raise ValueError("support-lock diagnostic scope changed")
    if (
        len(first.manifests) != len(second.manifests)
        or len(first.roots) != len(second.roots)
    ):
        raise ValueError("support-lock diagnostic role count changed")

    manifest_differences = tuple(
        (left, right)
        for left, right in zip(first.manifests, second.manifests, strict=True)
        if left != right
    )
    root_differences = tuple(
        (left, right)
        for left, right in zip(first.roots, second.roots, strict=True)
        if left != right
    )
    if not manifest_differences and not root_differences:
        return (
            "[full-c6-e2e] support-lock diagnostic: "
            "generation-and-immediate-verification-recapture succeeded"
        )

    kind = "manifest" if manifest_differences else "root"
    left, right = (
        manifest_differences[0] if manifest_differences else root_differences[0]
    )
    if (
        left.logical_role != right.logical_role
        or left.logical_role
        not in {
            role
            for manifest_roles, root_roles in _SUPPORT_LOCK_ROLES.values()
            for role in (*manifest_roles, *root_roles)
        }
        or not _is_sha256(left.merkle_sha256)
        or not _is_sha256(right.merkle_sha256)
    ):
        raise ValueError("support-lock diagnostic receipt identity changed")

    hardlink_before = "-"
    hardlink_after = "-"
    if kind == "root":
        for receipt, label in ((left, "before"), (right, "after")):
            dispositions = receipt.hardlink_dispositions
            if len(dispositions) > 1:
                raise ValueError("support-lock diagnostic hardlink count changed")
            if dispositions:
                observation = dispositions[0].observation_merkle_sha256
                if not _is_sha256(observation):
                    raise ValueError("support-lock diagnostic hardlink digest changed")
                if label == "before":
                    hardlink_before = observation
                else:
                    hardlink_after = observation

    diagnostic = (
        "[full-c6-e2e] support-lock diagnostic: verification-recapture-drift "
        f"manifests={len(manifest_differences)} roots={len(root_differences)} "
        f"kind={kind} role={left.logical_role} "
        f"before={left.merkle_sha256} after={right.merkle_sha256} "
        f"hardlink_before={hardlink_before} hardlink_after={hardlink_after}"
    )
    assert diagnostic.isascii()
    assert len(diagnostic.encode("ascii")) <= 512
    return diagnostic


def _diagnose_support_lock_generation(
    project: Path,
    *,
    inherited_environment: dict[str, str],
) -> str:
    from rextio.build import full_c6_toolchain_support as support

    plan: object | None = None
    try:
        config, _configured_pin = support._load_full_c6_support_bootstrap_config(
            project,
            output=_SUPPORT_LOCK_OUTPUT,
            inherited_environment=inherited_environment,
        )
        plan = support._discover_full_c6_bootstrap_plan(
            project_root=project,
            config=config,
            inherited_environment=inherited_environment,
        )
        first = support.generate_full_c6_toolchain_support_lock(plan)
        # Verification's host-dependent step is the same complete receipt
        # capture.  A second generation preserves both typed sides of that
        # comparison so the failure diagnostic can identify a path-free drift.
        second = support.generate_full_c6_toolchain_support_lock(plan)
    except Exception as exc:
        # A generic Xcode hardlink rejection cannot safely expose its source
        # path.  For that exact failure only, replace it with a bounded,
        # path-opaque inventory of every shared inode in the fixed support
        # root.  Ordinary failures remain single-pass diagnostics.
        xcode_topology: str | None = None
        if plan is not None:
            try:
                xcode_topology = _diagnose_xcode_hardlink_topology(plan, exc)
            except Exception as diagnostic_exc:
                return _format_support_lock_diagnostic(diagnostic_exc)
        if xcode_topology is not None:
            from rextio.build.toolchain_support_lock import (
                ToolchainSupportLockError,
            )

            return _format_support_lock_diagnostic(
                ToolchainSupportLockError(xcode_topology)
            )
        return _format_support_lock_diagnostic(exc)
    return _format_support_lock_rewalk_difference(first, second)


def _assert_exact_two_cargo_pids(stage: str, cargo_pids: set[int]) -> None:
    if len(cargo_pids) != 2:
        raise AssertionError(
            f"{stage} must expose exactly two distinct Cargo child processes; "
            f"observed {len(cargo_pids)}: {sorted(cargo_pids)}"
        )


def _failure_report_file_stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_full_c6_build_failure_report(project: Path) -> str:
    """Return one path-free diagnostic line from the fixed build report."""
    report_path = project / ".rextio" / "reports" / "build.json"
    try:
        linked = report_path.lstat()
        if (
            not stat.S_ISREG(linked.st_mode)
            or linked.st_nlink != 1
            or not 0 < linked.st_size <= _FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES
        ):
            raise ValueError("unsafe Full C6 failure report file")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow == 0:
            raise ValueError("no-follow report open is unavailable")
        descriptor = os.open(
            report_path,
            os.O_RDONLY
            | os.O_NONBLOCK
            | nofollow
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or _failure_report_file_stamp(opened)
                != _failure_report_file_stamp(linked)
            ):
                raise ValueError("Full C6 failure report changed before open")
            payload = bytearray()
            while len(payload) <= _FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES:
                chunk = os.read(
                    descriptor,
                    min(
                        8_192,
                        _FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES + 1 - len(payload),
                    ),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            if (
                len(payload) != opened.st_size
                or len(payload) > _FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES
                or _failure_report_file_stamp(os.fstat(descriptor))
                != _failure_report_file_stamp(opened)
            ):
                raise ValueError("Full C6 failure report changed during read")
        finally:
            os.close(descriptor)

        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate Full C6 failure report key")
                result[key] = value
            return result

        document = json.loads(
            bytes(payload).decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
        if type(document) is not dict:
            raise ValueError("Full C6 failure report must be an object")
        error = document.get("error")
        if type(error) is not dict:
            raise ValueError("Full C6 failure report lacks an error object")
        error_code = error.get("code")
        error_domain = error.get("domain")
        reason_code = error.get("reason_code")
        stage = document.get("stage")
        status_value = document.get("status")
        lifecycle = document.get("lifecycle")
        distribution_authorized = document.get("distribution_authorized")
        if (
            type(error_code) is not str
            or error_code != "RXT060"
            or type(error_domain) is not str
            or error_domain not in _FULL_C6_BUILD_FAILURE_DOMAINS
            or type(reason_code) is not str
            or reason_code not in _FULL_C6_BUILD_FAILURE_REASON_CODES
            or type(stage) is not str
            or stage not in _FULL_C6_BUILD_FAILURE_STAGES
            or type(status_value) is not str
            or status_value != "strict-evidence-failed"
            or type(lifecycle) is not str
            or lifecycle != "failed"
            or distribution_authorized is not False
        ):
            raise ValueError("Full C6 failure report fields are not allowlisted")
        return json.dumps(
            {
                "distribution_authorized": distribution_authorized,
                "error_code": error_code,
                "error_domain": error_domain,
                "event": "full-c6-build-failure-report",
                "lifecycle": lifecycle,
                "reason_code": reason_code,
                "stage": stage,
                "status": status_value,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return _FULL_C6_BUILD_FAILURE_UNAVAILABLE


def _emit_full_c6_build_failure_report(project: Path) -> None:
    print(_read_full_c6_build_failure_report(project), file=sys.stderr, flush=True)


def _initial_support_lock_verification_diagnostic(stderr: str) -> str | None:
    """Retain one exact path-free verifier delta from the initial child."""
    prefix = "Diagnostic: "
    matches: list[str] = []
    for line in stderr.splitlines():
        if not line.startswith(prefix):
            continue
        candidate = line[len(prefix) :]
        match = _SUPPORT_LOCK_VERIFICATION_DIAGNOSTIC_RE.fullmatch(candidate)
        if (
            match is None
            or not candidate.isascii()
            or len(candidate.encode("ascii")) > 512
            or any(
                not (character.isalnum() or character in " -_=,()")
                for character in candidate
            )
        ):
            continue
        manifests = int(match.group("manifests"))
        roots = int(match.group("roots"))
        kind = match.group("kind")
        changed_field_mask = int(match.group("fields"), 16)
        if (
            not 0 <= manifests <= 64
            or not 0 <= roots <= 64
            or manifests + roots == 0
            or (kind == "manifest" and manifests == 0)
            or (kind == "root" and roots == 0)
            or match.group("role") not in _SUPPORT_LOCK_FIXED_ROLES
            or (kind == "manifest" and changed_field_mask != 0)
            or (
                kind == "root"
                and not 0 < changed_field_mask <= 0x3FFF
            )
            or (
                kind == "root"
                and changed_field_mask & (1 << 13) == 0
            )
        ):
            continue
        matches.append(candidate)
    if len(matches) != 1:
        return None
    diagnostic = f"[full-c6-e2e] support-lock diagnostic: {matches[0]}"
    if not diagnostic.isascii() or len(diagnostic.encode("ascii")) > 512:
        return None
    return diagnostic


def _run_fresh_rextio(
    command: list[str],
    *,
    cwd: Path,
    stage: str,
    timeout: int,
    expect_two_cargo_builds: bool,
    support_lock_diagnostic_project: Path | None = None,
    build_failure_report_project: Path | None = None,
) -> tuple[str, str, tuple[int, ...]]:
    before_quarantines = _active_quarantine_names()
    child_environment = _child_environment()
    print(f"[full-c6-e2e] START {stage}: {command[0]}", flush=True)
    started = time.monotonic()
    cargo_pids: set[int] = set()
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    with tempfile.TemporaryFile(mode="w+b") as stdout_log, tempfile.TemporaryFile(
        mode="w+b"
    ) as stderr_log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=child_environment,
            stdout=stdout_log,
            stderr=stderr_log,
            start_new_session=True,
        )
        next_heartbeat = started + 15
        try:
            while process.poll() is None:
                cargo_pids.update(_descendant_cargo_pids(process.pid))
                now = time.monotonic()
                if now >= started + timeout:
                    raise TimeoutError(
                        f"{stage} exceeded its {timeout}-second child timeout"
                    )
                if now >= next_heartbeat:
                    print(
                        f"[full-c6-e2e] WAIT {stage}: "
                        f"{int(now - started)}s, "
                        f"observed Cargo PIDs={len(cargo_pids)}",
                        flush=True,
                    )
                    next_heartbeat = now + 15
                time.sleep(0.05)
            process.wait(timeout=10)
            if _process_group_is_alive(process.pid):
                raise AssertionError(
                    f"{stage} root exited while process group {process.pid} remained alive"
                )
        except BaseException as exc:
            failure = exc
            try:
                _terminate_process_group(process, stage=stage)
            except BaseException as cleanup_exc:
                cleanup_failure = cleanup_exc
        stdout = _read_bounded_process_log(stdout_log)
        stderr = _read_bounded_process_log(stderr_log)
    elapsed = time.monotonic() - started
    if stdout:
        print(f"[full-c6-e2e] {stage} stdout:\n{stdout}", end="", flush=True)
    if stderr:
        print(f"[full-c6-e2e] {stage} stderr:\n{stderr}", end="", flush=True)
    leaked = _active_quarantine_names() - before_quarantines
    if failure is not None or cleanup_failure is not None or leaked:
        raise AssertionError(
            f"{stage} did not exit cleanly\n"
            f"failure: {failure!r}\n"
            f"cleanup failure: {cleanup_failure!r}\n"
            f"leaked quarantines: {sorted(leaked)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from (cleanup_failure or failure)
    if process.returncode != 0:
        if build_failure_report_project is not None:
            _emit_full_c6_build_failure_report(build_failure_report_project)
        if support_lock_diagnostic_project is not None:
            diagnostic = _initial_support_lock_verification_diagnostic(stderr)
            if diagnostic is None:
                try:
                    diagnostic = _diagnose_support_lock_generation(
                        support_lock_diagnostic_project,
                        inherited_environment=child_environment,
                    )
                    if (
                        type(diagnostic) is not str
                        or not diagnostic.isascii()
                        or "\n" in diagnostic
                        or "\r" in diagnostic
                        or len(diagnostic.encode("utf-8")) > 512
                    ):
                        raise ValueError("unsafe harness diagnostic")
                except BaseException:
                    diagnostic = (
                        "[full-c6-e2e] support-lock diagnostic: unavailable"
                    )
            print(diagnostic, file=sys.stderr, flush=True)
        raise AssertionError(
            f"{stage} failed with {process.returncode}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    if expect_two_cargo_builds:
        _assert_exact_two_cargo_pids(stage, cargo_pids)
    print(
        f"[full-c6-e2e] DONE {stage}: {elapsed:.1f}s, "
        f"sampled Cargo PIDs={len(cargo_pids)}",
        flush=True,
    )
    return stdout, stderr, tuple(sorted(cargo_pids))


def _bootstrap_toolchain_support_lock(
    project: Path,
    *,
    expected_target: str,
) -> tuple[str, str, str]:
    expected_manifest_roles, expected_root_roles = _SUPPORT_LOCK_ROLES[
        expected_target
    ]
    lock_path = project / _SUPPORT_LOCK_OUTPUT
    if lock_path.exists():
        raise AssertionError("Full C6 support-lock output unexpectedly exists")
    stdout, _stderr, _cargo_pids = _run_fresh_rextio(
        [
            str(_installed_rextio_entrypoint()),
            "policy",
            "bootstrap-support-lock",
            "--project-root",
            str(project),
            "--output",
            _SUPPORT_LOCK_OUTPUT,
            "--format",
            "json",
        ],
        cwd=project.parent,
        stage="policy/bootstrap-support-lock",
        timeout=900,
        expect_two_cargo_builds=False,
        support_lock_diagnostic_project=project,
    )
    try:
        receipt = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError("support-lock bootstrap did not emit JSON") from exc
    if type(receipt) is not dict:
        raise AssertionError("Full C6 support-lock bootstrap receipt is invalid")
    expected_keys = {
        "status",
        "result",
        "target",
        "manifest_roles",
        "root_roles",
        "raw_sha256",
        "merkle_sha256",
        "config",
        "authorizes_build",
        "authorizes_distribution",
    }
    expected_config = {
        "artifact_toolchain_support_lock": _SUPPORT_LOCK_OUTPUT,
        "artifact_toolchain_support_lock_sha256": receipt.get("raw_sha256"),
    }
    if (
        set(receipt) != expected_keys
        or receipt.get("status")
        != "full-c6-toolchain-support-lock-bootstrapped"
        or receipt.get("result") != "created"
        or receipt.get("target") != expected_target
        or receipt.get("manifest_roles") != list(expected_manifest_roles)
        or receipt.get("root_roles") != list(expected_root_roles)
        or not _is_sha256(receipt.get("raw_sha256"))
        or not _is_sha256(receipt.get("merkle_sha256"))
        or receipt.get("config") != expected_config
        or receipt.get("authorizes_build") is not False
        or receipt.get("authorizes_distribution") is not False
    ):
        raise AssertionError("Full C6 support-lock bootstrap receipt is invalid")
    if not lock_path.is_file():
        raise AssertionError("Full C6 support-lock bootstrap did not create its output")
    raw = lock_path.read_bytes()
    raw_sha256 = cast(str, receipt["raw_sha256"])
    merkle_sha256 = cast(str, receipt["merkle_sha256"])
    if _sha256(raw) != raw_sha256:
        raise AssertionError("Full C6 support-lock bytes differ from the receipt")

    from rextio.build.toolchain_support_lock import parse_toolchain_support_lock

    lock = parse_toolchain_support_lock(raw, expected_raw_sha256=raw_sha256)
    manifest_roles = tuple(item.logical_role for item in lock.manifests)
    root_roles = tuple(item.logical_role for item in lock.roots)
    if (
        lock.canonical_bytes != raw
        or lock.scope.target_triple != expected_target
        or manifest_roles != expected_manifest_roles
        or root_roles != expected_root_roles
        or lock.raw_sha256 != raw_sha256
        or lock.merkle_sha256 != merkle_sha256
        or lock.authorizes_build is not False
        or lock.authorizes_distribution is not False
    ):
        raise AssertionError("Full C6 support-lock content is invalid")
    return _SUPPORT_LOCK_OUTPUT, raw_sha256, merkle_sha256


def _assert_executor_invocations(
    project: Path,
    *,
    target: str,
    value: object,
) -> None:
    expected_keys = {
        "ordinal",
        "argv_sha256",
        "argv_count",
        "environment",
        "timeout_seconds",
        "max_output_bytes",
        "inherit_env",
        "sandbox_engine",
        "sandbox_plan_sha256",
        "sandbox_profile_sha256",
        "sandbox_seccomp_sha256",
    }
    if type(value) is not list or len(value) != 2:
        raise AssertionError("Full C6 executor invocation projection is incomplete")
    encoded = _canonical_json_bytes(value)
    if os.fspath(project).encode("utf-8") in encoded:
        raise AssertionError("Full C6 executor invocation leaked the project path")
    expected_engine = {
        "aarch64-apple-darwin": "macos-sandbox-exec-v1",
        "x86_64-unknown-linux-gnu": "linux-bwrap-landlock-v1",
    }[target]
    normalized: list[dict[str, object]] = []
    for ordinal, item in enumerate(value, start=1):
        if type(item) is not dict or set(item) != expected_keys:
            raise AssertionError("Full C6 executor invocation schema is invalid")
        environment = item.get("environment")
        if type(environment) is not list or not environment:
            raise AssertionError("Full C6 executor environment receipt is empty")
        names: list[str] = []
        for binding in environment:
            if (
                type(binding) is not dict
                or set(binding) != {"name", "value_sha256", "value_size"}
                or type(binding.get("name")) is not str
                or not binding["name"]
                or not _is_sha256(binding.get("value_sha256"))
                or type(binding.get("value_size")) is not int
                or not 0 <= binding["value_size"] <= 64 * 1024
            ):
                raise AssertionError("Full C6 executor environment binding is invalid")
            names.append(cast(str, binding["name"]))
        seccomp = item.get("sandbox_seccomp_sha256")
        if (
            item.get("ordinal") != ordinal
            or not _is_sha256(item.get("argv_sha256"))
            or type(item.get("argv_count")) is not int
            or not 5 <= item["argv_count"] <= 256
            or names != sorted(names)
            or len(names) != len(set(names))
            or type(item.get("timeout_seconds")) not in {int, float}
            or item["timeout_seconds"] <= 0
            or type(item.get("max_output_bytes")) is not int
            or item["max_output_bytes"] <= 0
            or item.get("inherit_env") is not False
            or item.get("sandbox_engine") != expected_engine
            or not _is_sha256(item.get("sandbox_plan_sha256"))
            or not _is_sha256(item.get("sandbox_profile_sha256"))
            or (
                target == "aarch64-apple-darwin"
                and seccomp is not None
            )
            or (
                target == "x86_64-unknown-linux-gnu"
                and not _is_sha256(seccomp)
            )
        ):
            raise AssertionError("Full C6 sandbox invocation receipt is invalid")
        normalized.append(dict(item))
    normalized[0].pop("ordinal")
    normalized[1].pop("ordinal")
    if normalized[0] != normalized[1]:
        raise AssertionError("Full C6 two-build sandbox contracts differ")


def _assert_lifecycle_report(
    project: Path,
    *,
    lifecycle: str,
    status: str,
    support_lock_raw_sha256: str,
    support_lock_merkle_sha256: str,
) -> dict[str, object]:
    report_path = project / ".rextio" / "reports" / "build.json"
    raw = report_path.read_bytes()
    report = json.loads(raw)
    if type(report) is not dict or raw != (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8"):
        raise AssertionError("Full C6 build report is not canonical pretty JSON")
    if os.fspath(project).encode("utf-8") in raw:
        raise AssertionError("Full C6 build report leaked the absolute project path")
    expected_keys = {
        "analysis",
        "contract_version",
        "distribution_authorized",
        "fallback",
        "artifact_contract",
        "lifecycle",
        "next_action",
        "status",
    }
    if set(report) != expected_keys:
        raise AssertionError(f"Full C6 build report schema changed: {sorted(report)}")
    if (
        report["lifecycle"] != lifecycle
        or report["status"] != status
        or report["fallback"] != "cpython"
        or type(report["contract_version"]) is not str
        or not report["contract_version"]
    ):
        raise AssertionError(f"Full C6 lifecycle report is invalid: {report}")
    expected_authorized = lifecycle == "publication-required"
    if report["distribution_authorized"] is not expected_authorized:
        raise AssertionError("Full C6 lifecycle reported invalid distribution authority")
    analysis = report["analysis"]
    if type(analysis) is not dict or analysis.get("project_root") != ".":
        raise AssertionError("Full C6 report leaked or changed the project-root contract")
    details = report["artifact_contract"]
    if type(details) is not dict:
        raise AssertionError("Full C6 report details are invalid")
    expected_detail_keys = {
        "bootstrap-required": {"policy_bootstrap", "production_authority"},
        "signing-required": {
            "authorization_request",
            "production_authority",
            "signing_request_receipt",
        },
        "publication-required": {
            "authorization_request",
            "production_authority",
            "publication_receipt",
            "signing_request_receipt",
        },
    }[lifecycle]
    if set(details) != expected_detail_keys:
        raise AssertionError(f"Full C6 {lifecycle} details changed: {sorted(details)}")
    production = details["production_authority"]
    if (
        type(production) is not dict
        or production.get("domain") != "rextio.full-c6-production-authority.v2"
        or production.get("authority")
        != "process-sealed-production-evidence-only"
        or production.get("lifecycle_status") != lifecycle
        or production.get("complete_for_scope") is not True
        or production.get("executor_invocation_count") != 2
        or production.get("signed") is not False
        or production.get("distribution_authorized") is not False
        or production.get("authorizes_distribution") is not False
    ):
        raise AssertionError("Full C6 production authority projection is invalid")
    target = _expected_target()
    if (
        not _is_sha256(production.get("toolchain_support_plan_sha256"))
        or production.get("toolchain_support_lock_raw_sha256")
        != support_lock_raw_sha256
        or production.get("toolchain_support_lock_merkle_sha256")
        != support_lock_merkle_sha256
        or not _is_sha256(production.get("executor_receipt_sha256"))
        or not _is_sha256(production.get("executor_toolchain_sha256"))
    ):
        raise AssertionError("Full C6 support/executor authority projection is invalid")
    _assert_executor_invocations(
        project,
        target=target,
        value=production.get("executor_invocations"),
    )
    aggregate = production.get("authority_aggregate")
    if type(aggregate) is not dict:
        raise AssertionError("Full C6 report lacks the executor-bound authority aggregate")
    aggregate_payload = dict(aggregate)
    aggregate_digest = aggregate_payload.pop("digest", None)
    bindings = aggregate_payload.get("bindings")
    expected_bindings = {
        "analysis_ir_transaction_sha256",
        "license_materials_transaction_sha256",
        "output_license_contract_sha256",
        "cargo_workspace_sha256",
        "native_execution_authority_sha256",
        "native_output_transaction_sha256",
        "subject_wheel_transaction_sha256",
        "native_runtime_authority_sha256",
        "runtime_authorization_sha256",
        "executor_receipt_sha256",
    }
    if (
        set(aggregate) != {
            "domain",
            "schema_version",
            "bindings",
            "complete_for_scope",
            "distribution_authorized",
            "digest",
        }
        or aggregate_payload.get("domain")
        != "rextio.full-c6-authority-aggregate-binding.v1"
        or aggregate_payload.get("schema_version") != 1
        or aggregate_payload.get("complete_for_scope") is not True
        or aggregate_payload.get("distribution_authorized") is not False
        or type(bindings) is not dict
        or set(bindings) != expected_bindings
        or any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in bindings.values()
        )
        or aggregate_digest != _sha256(_canonical_json_bytes(aggregate_payload))
    ):
        raise AssertionError("Full C6 authority aggregate or executor binding is invalid")
    if bindings["executor_receipt_sha256"] != production["executor_receipt_sha256"]:
        raise AssertionError("Full C6 executor receipt projection differs from aggregate")
    return report


def _invoke_build_lifecycle(
    project: Path,
    *,
    lifecycle: str,
    status: str,
    support_lock_raw_sha256: str,
    support_lock_merkle_sha256: str,
) -> dict[str, object]:
    _run_fresh_rextio(
        [
            str(_installed_rextio_entrypoint()),
            "build",
            str(project),
            "--fallback=cpython",
        ],
        cwd=project.parent,
        stage=f"build/{lifecycle}",
        timeout=1_500,
        expect_two_cargo_builds=True,
        build_failure_report_project=project,
    )
    return _assert_lifecycle_report(
        project,
        lifecycle=lifecycle,
        status=status,
        support_lock_raw_sha256=support_lock_raw_sha256,
        support_lock_merkle_sha256=support_lock_merkle_sha256,
    )


def _write_owner_completion(
    project: Path,
    *,
    bootstrap_path: Path,
    bootstrap_receipt: dict[str, object],
    key_sha256: str,
) -> tuple[Path, str]:
    from rextio.build.full_c6_policy import FullC6OwnerDeclaration
    from rextio.build.full_c6_policy_bootstrap import (
        parse_full_c6_policy_bootstrap_request,
    )
    from rextio.build.full_c6_policy_completion import (
        FullC6OwnerLicenseDecision,
        FullC6OwnerPolicyCompletion,
    )

    raw, document = _read_canonical_document(bootstrap_path)
    request = parse_full_c6_policy_bootstrap_request(raw)
    payload = dict(document)
    declared_request_sha256 = payload.pop("request_sha256")
    if (
        declared_request_sha256 != request.request_sha256
        or bootstrap_receipt.get("request_sha256") != request.request_sha256
        or bootstrap_receipt.get("size") != len(raw)
        or _sha256(_canonical_json_bytes(payload)) != request.request_sha256
    ):
        raise AssertionError("Full C6 bootstrap canonical bytes or request hash changed")
    if (
        bootstrap_receipt.get("filename") != bootstrap_path.name
        or bootstrap_receipt.get("status") != "bootstrap-required"
        or bootstrap_receipt.get("distribution_authorized") is not False
    ):
        raise AssertionError("Full C6 bootstrap materialization receipt is invalid")

    template = request.technical_template
    external = template.external_license_observation
    internal = {
        item.observation_sha256: item
        for item in template.internal_license_observations
    }
    decisions = []
    for row in template.rows:
        if row.required_license_disposition != "owner-approved-allow":
            continue
        if row.license_evidence_origin == "production-external-observation":
            if row.license_observation_sha256 != external.observation_sha256:
                raise AssertionError("external row does not bind the public observation")
            declared_spdx = external.declared_spdx
            detected_spdx = external.detected_spdx
            source_receipt = external.source_detector_receipt_sha256
            detector_payload = external.detector_payload_sha256
            files = external.license_files
        elif row.license_evidence_origin == "owner-project-observation":
            observation = internal.get(row.license_observation_sha256)
            if observation is None:
                raise AssertionError("internal row does not bind one public observation")
            declared_spdx = observation.declared_spdx
            detected_spdx = observation.detected_spdx
            source_receipt = observation.source_detector_receipt_sha256
            detector_payload = observation.detector_payload_sha256
            files = observation.license_files
        else:
            raise AssertionError("license-applicable Full C6 row lacks an evidence origin")
        decisions.append(
            FullC6OwnerLicenseDecision(
                authority_identity=row.authority_identity,
                declared_spdx=declared_spdx,
                detected_spdx=detected_spdx,
                source_detector_receipt_sha256=source_receipt,
                detector_payload_sha256=detector_payload,
                license_files=files,
                evidence_origin=cast(
                    Literal[
                        "owner-project-observation",
                        "production-external-observation",
                    ],
                    row.license_evidence_origin,
                ),
            )
        )
    completion = FullC6OwnerPolicyCompletion(
        bootstrap_request_sha256=request.request_sha256,
        transformation_set_sha256=(
            request.technical_template.transformation_set_sha256
        ),
        owner_declaration=FullC6OwnerDeclaration(
            owner_identity=request.technical_template.observed_owner_identity,
            owner_role="organization-owner",
            trusted_public_key_sha256=key_sha256,
        ),
        license_decisions=tuple(
            sorted(decisions, key=lambda item: item.authority_identity)
        ),
    )
    completion_path = project / "policy" / "owner-completion.json"
    completion_bytes = completion.to_bytes()
    completion_path.write_bytes(completion_bytes)
    completion_path.chmod(0o600)
    if _read_canonical_document(completion_path)[0] != completion_bytes:
        raise AssertionError("owner completion bytes changed after materialization")
    print(
        "[full-c6-e2e] owner completion authored from public bootstrap "
        f"{_sha256(raw)} -> {completion.completion_sha256}",
        flush=True,
    )
    return completion_path, request.request_sha256


def _finalize_owner_policy(
    project: Path,
    *,
    bootstrap_path: Path,
    completion_path: Path,
) -> str:
    policy_path = project / "policy" / "rextio.artifact-policy.json"
    stdout, _stderr, _cargo = _run_fresh_rextio(
        [
            str(_installed_rextio_entrypoint()),
            "policy",
            "finalize",
            "--bootstrap",
            str(bootstrap_path),
            "--completion",
            str(completion_path),
            "--output",
            str(policy_path),
            "--format",
            "json",
        ],
        cwd=project.parent,
        stage="policy/finalize",
        timeout=120,
        expect_two_cargo_builds=False,
    )
    raw, _document = _read_canonical_document(policy_path)
    policy_sha256 = _sha256(raw)
    result = json.loads(stdout)
    _bootstrap_raw, bootstrap_document = _read_canonical_document(bootstrap_path)
    _completion_raw, completion_document = _read_canonical_document(completion_path)
    if (
        type(result) is not dict
        or set(result)
        != {
            "status",
            "bootstrap_request_sha256",
            "completion_sha256",
            "manifest_sha256",
            "size",
            "created",
            "signed",
            "distribution_authorized",
            "output",
        }
        or result.get("status") != "full-c6-policy-finalized"
        or result.get("bootstrap_request_sha256")
        != bootstrap_document.get("request_sha256")
        or result.get("completion_sha256")
        != completion_document.get("completion_sha256")
        or result.get("manifest_sha256") != policy_sha256
        or result.get("size") != len(raw)
        or result.get("created") is not True
        or result.get("signed") is not False
        or result.get("distribution_authorized") is not False
        or result.get("output") != str(policy_path)
    ):
        raise AssertionError("policy finalizer returned an invalid exact result")
    return policy_sha256


def _write_final_signature(
    project: Path,
    *,
    seed: bytes,
    public_key: bytes,
    key_sha256: str,
    signing_report: dict[str, object],
) -> str:
    from rextio.build.signing import (
        SIGNED_MESSAGE_PREFIX,
        DetachedSignatureEnvelope,
        FinalAuthorizationRequest,
    )

    request_path = (
        project
        / ".rextio/full-c6-state/rextio.artifact-authorization-request.json"
    )
    raw, document = _read_canonical_document(request_path)
    request = FinalAuthorizationRequest(
        target_triple=document["target_triple"],
        project_sha256=document["project_sha256"],
        artifact_sha256=document["artifact_sha256"],
        evidence_sha256=document["evidence_sha256"],
        reproducibility_sha256=document["reproducibility_sha256"],
        policy_sha256=document["policy_sha256"],
        scope=document["scope"],
    )
    if document != request.to_dict() or raw != request.canonical_manifest_bytes:
        raise AssertionError("materialized Full C6 signing request is noncanonical")
    details = signing_report["artifact_contract"]
    if type(details) is not dict:
        raise AssertionError("signing report details are invalid")
    receipt = details["signing_request_receipt"]
    if (
        details["authorization_request"] != document
        or type(receipt) is not dict
        or receipt.get("request_sha256") != request.manifest_sha256
        or receipt.get("request_size") != len(raw)
        or receipt.get("authorizes_distribution") is not False
    ):
        raise AssertionError("signing report does not bind the canonical request")
    observed_public, signature = _sign(
        seed,
        SIGNED_MESSAGE_PREFIX + request.canonical_manifest_bytes,
    )
    if observed_public != public_key:
        raise AssertionError("ephemeral final signer changed public keys")
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=key_sha256,
        manifest_sha256=request.manifest_sha256,
        signature=signature,
    )
    relative = "authority/rextio.full-c6-final.sig.json"
    path = project / relative
    path.write_bytes(envelope.canonical_json_bytes)
    path.chmod(0o600)
    if path.read_bytes() != envelope.canonical_json_bytes:
        raise AssertionError("external signer output changed after materialization")
    return relative


def _installed_rextio_wheel() -> Path:
    configured = os.environ.get("REXTIO_ARTIFACT_CONTRACT_WHEEL")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file() and candidate.suffix == ".whl":
            return candidate
        raise AssertionError(
            "REXTIO_ARTIFACT_CONTRACT_WHEEL does not name the installed wheel"
        )
    direct_url = metadata.distribution("rextio").read_text("direct_url.json")
    if direct_url is not None:
        raw_url = json.loads(direct_url).get("url")
        if isinstance(raw_url, str):
            parsed = urlparse(raw_url)
            if parsed.scheme == "file":
                candidate = Path(unquote(parsed.path)).resolve()
                if candidate.is_file() and candidate.suffix == ".whl":
                    return candidate
    raise AssertionError(
        "set REXTIO_ARTIFACT_CONTRACT_WHEEL to the exact non-editable wheel "
        "installed in the E2E venv"
    )


def _verify_external_license_wheel_projection(
    dependency_wheel: Path,
    published_wheel: Path,
) -> None:
    source_member = "demo_pkg-1.0.0.dist-info/licenses/LICENSE"
    canonical_license_path = "external/demo-pkg/1.0.0/LICENSE"
    with zipfile.ZipFile(dependency_wheel) as dependency_archive:
        if dependency_archive.namelist().count(source_member) != 1:
            raise AssertionError("dependency wheel external license member is ambiguous")
        expected_payload = dependency_archive.read(source_member)

    with zipfile.ZipFile(published_wheel) as published_archive:
        names = published_archive.namelist()
        metadata_members = tuple(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        record_members = tuple(
            name for name in names if name.endswith(".dist-info/RECORD")
        )
        if len(metadata_members) != 1 or len(record_members) != 1:
            raise AssertionError("published wheel dist-info metadata is ambiguous")
        dist_info = metadata_members[0].removesuffix("/METADATA")
        if record_members[0] != f"{dist_info}/RECORD":
            raise AssertionError("published wheel RECORD belongs to another dist-info")
        output_member = f"{dist_info}/licenses/{canonical_license_path}"
        if names.count(output_member) != 1:
            raise AssertionError("published wheel external license member is not exact")
        output_payload = published_archive.read(output_member)
        if output_payload != expected_payload:
            raise AssertionError("published wheel external license bytes changed")

        metadata_text = published_archive.read(metadata_members[0]).decode("utf-8")
        license_files = tuple(
            line.removeprefix("License-File: ")
            for line in metadata_text.splitlines()
            if line.startswith("License-File: ")
        )
        if license_files.count(canonical_license_path) != 1:
            raise AssertionError("published METADATA lacks the exact external License-File")

        record_text = published_archive.read(record_members[0]).decode("utf-8")
        record_rows = tuple(csv.reader(io.StringIO(record_text, newline="")))
        matching_rows = tuple(
            tuple(row) for row in record_rows if row and row[0] == output_member
        )
        expected_digest = (
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(expected_payload).digest())
            .decode("ascii")
            .rstrip("=")
        )
        if matching_rows != ((output_member, expected_digest, str(len(expected_payload))),):
            raise AssertionError("published RECORD external license binding is not exact")


def _assert_published_toolchain_support_materials(
    *,
    sbom_path: Path,
    provenance_path: Path,
    production: dict[str, object],
) -> None:
    support_materials = {
        "builder-toolchain-support-plan": production.get(
            "toolchain_support_plan_sha256"
        ),
        "builder-toolchain-support-lock-raw": production.get(
            "toolchain_support_lock_raw_sha256"
        ),
        "builder-toolchain-support-lock-merkle": production.get(
            "toolchain_support_lock_merkle_sha256"
        ),
    }
    if not all(_is_sha256(value) for value in support_materials.values()):
        raise AssertionError("publication support material digests are invalid")
    _sbom_raw, sbom = _read_canonical_document(sbom_path)
    _provenance_raw, provenance = _read_canonical_document(provenance_path)
    components = sbom.get("components")
    if type(components) is not list:
        raise AssertionError("publication CycloneDX components are invalid")
    for name, digest in support_materials.items():
        expected_component = {
            "type": "data",
            "bom-ref": f"urn:rextio:full-c6-evidence:{name}:{digest}",
            "name": name,
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": [
                {
                    "name": "rextio:role",
                    "value": "non-authorizing-evidence-receipt",
                }
            ],
        }
        matches = [
            item
            for item in components
            if type(item) is dict and item.get("name") == name
        ]
        if matches != [expected_component]:
            raise AssertionError(f"CycloneDX support material {name} is invalid")

    predicate = provenance.get("predicate")
    if type(predicate) is not dict:
        raise AssertionError("publication SLSA predicate is invalid")
    definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if type(definition) is not dict or type(run_details) is not dict:
        raise AssertionError("publication SLSA build projection is invalid")
    dependencies = definition.get("resolvedDependencies")
    parameters = definition.get("internalParameters")
    metadata_projection = run_details.get("metadata")
    if (
        type(dependencies) is not list
        or type(parameters) is not dict
        or type(metadata_projection) is not dict
    ):
        raise AssertionError("publication SLSA support materials are invalid")
    receipt_bindings = parameters.get("receipt_bindings")
    toolchain_projection = metadata_projection.get("rextio:toolchain")
    if type(receipt_bindings) is not dict or type(toolchain_projection) is not dict:
        raise AssertionError("publication SLSA toolchain projection is invalid")
    for name, digest in support_materials.items():
        expected_dependency = {
            "uri": f"urn:rextio:full-c6-evidence:{name}",
            "digest": {"sha256": digest},
            "annotations": {
                "rextio:role": "non-authorizing-evidence-receipt"
            },
        }
        matches = [
            item
            for item in dependencies
            if type(item) is dict
            and item.get("uri") == expected_dependency["uri"]
        ]
        if matches != [expected_dependency] or receipt_bindings.get(name) != digest:
            raise AssertionError(f"SLSA support material {name} is invalid")
    if {
        "support_plan_sha256": toolchain_projection.get("support_plan_sha256"),
        "support_lock_raw_sha256": toolchain_projection.get(
            "support_lock_raw_sha256"
        ),
        "support_lock_merkle_sha256": toolchain_projection.get(
            "support_lock_merkle_sha256"
        ),
    } != {
        "support_plan_sha256": support_materials[
            "builder-toolchain-support-plan"
        ],
        "support_lock_raw_sha256": support_materials[
            "builder-toolchain-support-lock-raw"
        ],
        "support_lock_merkle_sha256": support_materials[
            "builder-toolchain-support-lock-merkle"
        ],
    }:
        raise AssertionError("publication SLSA toolchain support projection is stale")


def _verify_published_native_wheel(
    project: Path,
    dependency_wheel: Path,
    *,
    publication_report: dict[str, object],
) -> None:
    expected_roles = (
        "wheel",
        "cyclonedx",
        "slsa-provenance",
        "final-evidence",
        "detached-signature",
        "distribution-authorization",
    )
    details = publication_report["artifact_contract"]
    if type(details) is not dict:
        raise AssertionError("publication report details are invalid")
    receipt = details["publication_receipt"]
    if (
        type(receipt) is not dict
        or set(receipt)
        != {
            "domain",
            "target_triple",
            "subject_sha256",
            "evidence_sha256",
            "authorization_sha256",
            "manifest_sha256",
            "bundle_sha256",
            "files",
            "publication_completed",
            "sealed_authorization_observed",
            "authorizes_distribution",
        }
        or receipt.get("publication_completed") is not True
        or receipt.get("sealed_authorization_observed") is not True
        or receipt.get("authorizes_distribution") is not False
    ):
        raise AssertionError("Full C6 publication receipt is invalid")
    files = receipt.get("files")
    if type(files) is not list or tuple(
        item.get("role") if type(item) is dict else None for item in files
    ) != expected_roles:
        raise AssertionError("Full C6 publication role set or order changed")

    dist = project / "dist"
    bundles = tuple(dist.glob("*.full-c6"))
    if len(bundles) != 1 or not bundles[0].is_dir():
        raise AssertionError("Full C6 publication did not produce exactly one bundle")
    if tuple(dist.glob(".rextio-full-c6-stage-*")):
        raise AssertionError("Full C6 publication left a staging directory")
    bundle = bundles[0]
    manifest_name = "rextio.full-c6-manifest.json"
    expected_names = {
        item["logical_name"] for item in files if type(item) is dict
    } | {manifest_name}
    observed_names = {item.name for item in bundle.iterdir()}
    if observed_names != expected_names:
        raise AssertionError(
            f"Full C6 bundle member set changed: {sorted(observed_names)}"
        )
    for item in files:
        if type(item) is not dict:
            raise AssertionError("Full C6 publication file receipt is invalid")
        payload = (bundle / item["logical_name"]).read_bytes()
        if (
            item.get("sha256") != _sha256(payload)
            or item.get("size") != len(payload)
        ):
            raise AssertionError(
                f"Full C6 published {item.get('role')} bytes differ from receipt"
            )

    manifest_raw, manifest = _read_canonical_document(bundle / manifest_name)
    authorization_request = details["authorization_request"]
    if type(authorization_request) is not dict:
        raise AssertionError("publication report authorization request is invalid")
    if (
        receipt.get("manifest_sha256") != _sha256(manifest_raw)
        or set(manifest)
        != {
            "kind",
            "schema_version",
            "domain",
            "scope",
            "target_triple",
            "subject_sha256",
            "evidence_sha256",
            "authorization_request_sha256",
            "payload_file_count",
            "files",
        }
        or manifest.get("kind") != "full-c6-publication-manifest"
        or manifest.get("schema_version") != 1
        or manifest.get("domain") != "rextio.full-c6-atomic-publication.v1"
        or manifest.get("payload_file_count") != len(expected_roles)
        or manifest.get("files") != files
        or manifest.get("target_triple") != receipt.get("target_triple")
        or manifest.get("subject_sha256") != receipt.get("subject_sha256")
        or manifest.get("evidence_sha256") != receipt.get("evidence_sha256")
        or manifest.get("authorization_request_sha256")
        != _sha256(_canonical_json_bytes(authorization_request))
        or authorization_request.get("artifact_sha256")
        != receipt.get("subject_sha256")
    ):
        raise AssertionError("Full C6 publication manifest differs from its receipt")
    expected_bundle_sha256 = _sha256(
        _canonical_json_bytes(
            {
                "domain": "rextio.full-c6-atomic-publication.v1",
                "manifest_sha256": receipt["manifest_sha256"],
                "files": files,
            }
        )
    )
    if receipt.get("bundle_sha256") != expected_bundle_sha256:
        raise AssertionError("Full C6 bundle digest differs from the fixed payload")
    by_role = {item["role"]: item for item in files}
    production = details.get("production_authority")
    if type(production) is not dict:
        raise AssertionError("publication production authority is invalid")
    _assert_published_toolchain_support_materials(
        sbom_path=bundle / by_role["cyclonedx"]["logical_name"],
        provenance_path=bundle / by_role["slsa-provenance"]["logical_name"],
        production=production,
    )
    authorization = (
        bundle / by_role["distribution-authorization"]["logical_name"]
    ).read_bytes()
    if receipt.get("authorization_sha256") != _sha256(authorization):
        raise AssertionError("Full C6 authorization digest differs from published bytes")
    published_wheel = bundle / by_role["wheel"]["logical_name"]
    if receipt.get("subject_sha256") != _sha256(published_wheel.read_bytes()):
        raise AssertionError("Full C6 subject digest differs from published wheel")
    _verify_external_license_wheel_projection(dependency_wheel, published_wheel)

    runtime_venv = project.parent / "runtime-venv"
    print("[full-c6-e2e] START runtime/native-poison-smoke", flush=True)
    venv.create(runtime_venv, with_pip=True, clear=True)
    runtime_python = _venv_python(runtime_venv)
    _run(
        [
            str(runtime_python),
            "-m",
            "pip",
            "install",
            "--no-deps",
            str(_installed_rextio_wheel()),
            str(dependency_wheel),
            str(published_wheel),
        ],
        cwd=project.parent,
        timeout=900,
    )
    runtime_environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
    }
    runtime_environment["REXTIO_NATIVE_MODE"] = "native"
    completed = _run(
        [
            str(runtime_python),
            "-c",
            (
                "import app, demo_pkg\n"
                "def poison(_x):\n"
                "    raise AssertionError('Python external leaf executed')\n"
                "# Admission and runtime-guard identity checks happen during the imports "
                "above. Mutate only afterward so success proves the Rust C5.2 leaf ran.\n"
                "demo_pkg.affine.__code__ = poison.__code__\n"
                "result = app.calculate(41)\n"
                "assert result == 42, result\n"
                "print('FULL_C6_NATIVE_POISON_CALL_OK')\n"
            ),
        ],
        cwd=project.parent,
        env=runtime_environment,
        timeout=180,
    )
    if "FULL_C6_NATIVE_POISON_CALL_OK" not in completed.stdout:
        raise AssertionError("published Full C6 wheel did not execute its native C5.2 leaf")
    print("[full-c6-e2e] DONE runtime/native-poison-smoke", flush=True)


def _run_lifecycle(
    project: Path,
    *,
    seed: bytes,
    public_key: bytes,
    key_sha256: str,
    wheel_sha256: str,
    cargo_lock_sha256: str,
    cargo_vendor_sha256: str,
    support_lock_path: str,
    support_lock_raw_sha256: str,
    support_lock_merkle_sha256: str,
) -> dict[str, object]:
    bootstrap_report = _invoke_build_lifecycle(
        project,
        lifecycle="bootstrap-required",
        status="artifact-policy-bootstrap-required",
        support_lock_raw_sha256=support_lock_raw_sha256,
        support_lock_merkle_sha256=support_lock_merkle_sha256,
    )
    bootstrap_details = bootstrap_report["artifact_contract"]
    if type(bootstrap_details) is not dict:
        raise AssertionError("bootstrap report details are invalid")
    bootstrap_receipt = bootstrap_details["policy_bootstrap"]
    if type(bootstrap_receipt) is not dict:
        raise AssertionError("bootstrap report lacks its public receipt")
    bootstrap_path = (
        project
        / ".rextio"
        / "full-c6-state"
        / str(bootstrap_receipt["filename"])
    )
    completion_path, bootstrap_request_sha256 = _write_owner_completion(
        project,
        bootstrap_path=bootstrap_path,
        bootstrap_receipt=bootstrap_receipt,
        key_sha256=key_sha256,
    )
    policy_sha256 = _finalize_owner_policy(
        project,
        bootstrap_path=bootstrap_path,
        completion_path=completion_path,
    )

    unsigned_config = _typed_config(
        project,
        wheel_sha256=wheel_sha256,
        key_sha256=key_sha256,
        cargo_lock_sha256=cargo_lock_sha256,
        cargo_vendor_sha256=cargo_vendor_sha256,
        support_lock_path=support_lock_path,
        support_lock_sha256=support_lock_raw_sha256,
        policy_sha256=policy_sha256,
    )
    _write_config(project, unsigned_config)
    signing_report = _invoke_build_lifecycle(
        project,
        lifecycle="signing-required",
        status="artifact-signing-required",
        support_lock_raw_sha256=support_lock_raw_sha256,
        support_lock_merkle_sha256=support_lock_merkle_sha256,
    )
    final_signature = _write_final_signature(
        project,
        seed=seed,
        public_key=public_key,
        key_sha256=key_sha256,
        signing_report=signing_report,
    )
    signed_config = _typed_config(
        project,
        wheel_sha256=wheel_sha256,
        key_sha256=key_sha256,
        cargo_lock_sha256=cargo_lock_sha256,
        cargo_vendor_sha256=cargo_vendor_sha256,
        support_lock_path=support_lock_path,
        support_lock_sha256=support_lock_raw_sha256,
        policy_sha256=policy_sha256,
        final_signature=final_signature,
    )
    _write_config(project, signed_config)
    publication_report = _invoke_build_lifecycle(
        project,
        lifecycle="publication-required",
        status="artifact-published",
        support_lock_raw_sha256=support_lock_raw_sha256,
        support_lock_merkle_sha256=support_lock_merkle_sha256,
    )

    reports = (bootstrap_report, signing_report, publication_report)
    production_authorities = []
    for report in reports:
        details = report["artifact_contract"]
        if type(details) is not dict:
            raise AssertionError("Full C6 lifecycle details are invalid")
        production = details["production_authority"]
        if type(production) is not dict:
            raise AssertionError("Full C6 production projection is invalid")
        if production.get("bootstrap_request_sha256") != bootstrap_request_sha256:
            raise AssertionError(
                "fresh Full C6 lifecycle recollection changed bootstrap lineage"
            )
        production_authorities.append(production)
    template_sha256s = {
        item.get("technical_policy_template_sha256")
        for item in production_authorities
    }
    if len(template_sha256s) != 1:
        raise AssertionError(
            "fresh Full C6 lifecycle recollection changed the technical template"
        )
    support_plan_sha256s = {
        item.get("toolchain_support_plan_sha256")
        for item in production_authorities
    }
    executor_toolchain_sha256s = {
        item.get("executor_toolchain_sha256")
        for item in production_authorities
    }
    executor_receipt_sha256s = {
        item.get("executor_receipt_sha256")
        for item in production_authorities
    }
    if (
        len(support_plan_sha256s) != 1
        or len(executor_toolchain_sha256s) != 1
        or len(executor_receipt_sha256s) != 1
    ):
        raise AssertionError(
            "fresh Full C6 lifecycle recollection changed toolchain authority"
        )

    signing_details = signing_report["artifact_contract"]
    publication_details = publication_report["artifact_contract"]
    if type(signing_details) is not dict or type(publication_details) is not dict:
        raise AssertionError("Full C6 signing/publication details are invalid")
    publication_signing_receipt = publication_details["signing_request_receipt"]
    if (
        publication_details["authorization_request"]
        != signing_details["authorization_request"]
        or type(publication_signing_receipt) is not dict
        or publication_signing_receipt.get("already_present") is not True
        or publication_signing_receipt.get("authorizes_distribution") is not False
    ):
        raise AssertionError(
            "publication did not reuse the exact externally signed request"
        )
    return publication_report


def _assert_run_root_isolated(run_root: Path) -> None:
    roots = {"checkout": Path(__file__).resolve().parents[2]}
    github_workspace = os.environ.get("GITHUB_WORKSPACE")
    if github_workspace:
        roots["GITHUB_WORKSPACE"] = Path(github_workspace).resolve()
    for label, root in roots.items():
        if run_root == root or run_root.is_relative_to(root):
            raise AssertionError(
                f"Full C6 run root must remain outside {label}: {run_root}"
            )


def main() -> None:
    if (
        os.environ.get("REXTIO_ARTIFACT_CONTRACT_E2E_CHILD") != "1"
        or len(sys.argv) != 2
    ):
        raise SystemExit("this helper runs only through the dedicated Full C6 E2E test")
    if sys.dont_write_bytecode is not True:
        raise AssertionError("dedicated Full C6 E2E requires a cache-free Python host")
    _assert_record_backed_rextio_install()
    if platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11):
        raise AssertionError("dedicated Full C6 E2E requires exact CPython 3.11")
    expected_target = _expected_target()
    from rextio.artifacts.profiles import detect_host_target_triple

    if detect_host_target_triple() != expected_target:
        raise AssertionError("dedicated Full C6 lane target assertion failed")
    run_root = Path(sys.argv[1]).resolve()
    if Path.cwd().resolve() != run_root:
        raise AssertionError("Full C6 harness cwd must remain outside the checkout")
    _assert_run_root_isolated(run_root)

    project = run_root / "project"
    print("[full-c6-e2e] START fixture/owner-inputs", flush=True)
    _write_project(project)
    seed = secrets.token_bytes(32)
    public_key, _unused_signature = _sign(seed, b"rextio-full-c6-e2e-key-check")
    key_sha256 = _sha256(public_key)
    key_path = project / "authority" / "owner.ed25519.pub"
    key_path.write_bytes(public_key)
    key_path.chmod(0o600)
    dependency_wheel = (
        project / "authority" / "demo_pkg-1.0.0-py3-none-any.whl"
    )
    _write_dependency_wheel(dependency_wheel)
    wheel_sha256 = _sha256(dependency_wheel.read_bytes())
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            str(dependency_wheel),
        ],
        cwd=run_root,
        timeout=300,
    )
    invalidate_caches()
    if metadata.version("demo-pkg") != "1.0.0":
        raise AssertionError("tiny dependency wheel is not installed in the clean venv")
    _write_source_lock(
        project,
        seed=seed,
        public_key=public_key,
        key_sha256=key_sha256,
        wheel_sha256=wheel_sha256,
    )
    print("[full-c6-e2e] DONE fixture/owner-inputs", flush=True)

    print("[full-c6-e2e] START fixture/cargo-vendor-and-license-locks", flush=True)
    placeholder_config = _typed_config(
        project,
        wheel_sha256=wheel_sha256,
        key_sha256=key_sha256,
        cargo_lock_sha256="0" * 64,
        cargo_vendor_sha256="0" * 64,
    )
    cargo_lock_sha256, cargo_vendor_sha256, cargo_workspace = (
        _prepare_cargo_inputs(
            project,
            config=placeholder_config,
        )
    )
    bootstrap_config = _typed_config(
        project,
        wheel_sha256=wheel_sha256,
        key_sha256=key_sha256,
        cargo_lock_sha256=cargo_lock_sha256,
        cargo_vendor_sha256=cargo_vendor_sha256,
    )
    _write_config(project, bootstrap_config)
    support_lock_path, support_lock_raw_sha256, support_lock_merkle_sha256 = (
        _bootstrap_toolchain_support_lock(
            project,
            expected_target=expected_target,
        )
    )
    pinned_config = _typed_config(
        project,
        wheel_sha256=wheel_sha256,
        key_sha256=key_sha256,
        cargo_lock_sha256=cargo_lock_sha256,
        cargo_vendor_sha256=cargo_vendor_sha256,
        support_lock_path=support_lock_path,
        support_lock_sha256=support_lock_raw_sha256,
    )
    _write_config(project, pinned_config)
    from rextio.build.full_c6_host_inputs import collect_full_c6_analysis_scope

    analysis_scope = collect_full_c6_analysis_scope(
        project,
        config=pinned_config,
    )
    preflight = _prepare_preflight(project, pinned_config, analysis_scope)
    _write_license_locks(
        project,
        config=pinned_config,
        preflight=preflight,
        cargo_workspace=cargo_workspace,
    )
    print("[full-c6-e2e] DONE fixture/cargo-vendor-and-license-locks", flush=True)
    publication_report = _run_lifecycle(
        project,
        seed=seed,
        public_key=public_key,
        key_sha256=key_sha256,
        wheel_sha256=wheel_sha256,
        cargo_lock_sha256=cargo_lock_sha256,
        cargo_vendor_sha256=cargo_vendor_sha256,
        support_lock_path=support_lock_path,
        support_lock_raw_sha256=support_lock_raw_sha256,
        support_lock_merkle_sha256=support_lock_merkle_sha256,
    )
    _verify_published_native_wheel(
        project,
        dependency_wheel,
        publication_report=publication_report,
    )
    print("FULL_C6_REAL_E2E_OK")


if __name__ == "__main__":
    main()
