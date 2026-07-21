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
from pathlib import Path
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Literal, cast
from urllib.parse import unquote, urlparse
import venv
import zipfile


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


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
    return RextioConfig(
        build=BuildConfig(
            artifact_evidence_policy="required",
            artifact_distribution_policy="full-c6-required",
            artifact_source_lock_manifest="authority/rextio.external-source.lock.v2.json",
            artifact_source_lock_signature=(
                "authority/rextio.external-source.lock.v2.sig.json"
            ),
            artifact_policy_manifest="policy/rextio.full-c6-policy.json",
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_cargo_vendor="cargo-vendor",
            artifact_cargo_vendor_sha256=cargo_vendor_sha256,
            artifact_cargo_lock="authority/Cargo.lock",
            artifact_cargo_lock_sha256=cargo_lock_sha256,
            artifact_trusted_public_key="authority/owner.ed25519.pub",
            artifact_trusted_public_key_sha256=key_sha256,
            artifact_final_signature=final_signature,
            artifact_signing_request_output=(
                ".rextio/full-c6-state/rextio.full-c6-final-authorization-request.json"
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
        'artifact_distribution_policy = "full-c6-required"',
        f'artifact_source_lock_manifest = "{build.artifact_source_lock_manifest}"',
        f'artifact_source_lock_signature = "{build.artifact_source_lock_signature}"',
        f'artifact_policy_manifest = "{build.artifact_policy_manifest}"',
    ]
    if build.artifact_policy_manifest_sha256 is not None:
        rows.append(
            f'artifact_policy_manifest_sha256 = "{build.artifact_policy_manifest_sha256}"'
        )
    rows.extend(
        (
            f'artifact_cargo_vendor = "{build.artifact_cargo_vendor}"',
            f'artifact_cargo_vendor_sha256 = "{build.artifact_cargo_vendor_sha256}"',
            f'artifact_cargo_lock = "{build.artifact_cargo_lock}"',
            f'artifact_cargo_lock_sha256 = "{build.artifact_cargo_lock_sha256}"',
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


def _assert_exact_two_cargo_pids(stage: str, cargo_pids: set[int]) -> None:
    if len(cargo_pids) != 2:
        raise AssertionError(
            f"{stage} must expose exactly two distinct Cargo child processes; "
            f"observed {len(cargo_pids)}: {sorted(cargo_pids)}"
        )


def _run_fresh_rextio(
    command: list[str],
    *,
    cwd: Path,
    stage: str,
    timeout: int,
    expect_two_cargo_builds: bool,
) -> tuple[str, str, tuple[int, ...]]:
    before_quarantines = _active_quarantine_names()
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
            env=_child_environment(),
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


def _assert_lifecycle_report(
    project: Path,
    *,
    lifecycle: str,
    status: str,
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
        "full_c6",
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
    details = report["full_c6"]
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
    return report


def _invoke_build_lifecycle(
    project: Path,
    *,
    lifecycle: str,
    status: str,
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
    )
    return _assert_lifecycle_report(
        project,
        lifecycle=lifecycle,
        status=status,
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
    policy_path = project / "policy" / "rextio.full-c6-policy.json"
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
        / ".rextio/full-c6-state/rextio.full-c6-final-authorization-request.json"
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
    details = signing_report["full_c6"]
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
    configured = os.environ.get("REXTIO_FULL_C6_WHEEL")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file() and candidate.suffix == ".whl":
            return candidate
        raise AssertionError("REXTIO_FULL_C6_WHEEL does not name the installed wheel")
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
        "set REXTIO_FULL_C6_WHEEL to the exact non-editable wheel installed in the E2E venv"
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
    details = publication_report["full_c6"]
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
) -> dict[str, object]:
    bootstrap_report = _invoke_build_lifecycle(
        project,
        lifecycle="bootstrap-required",
        status="full-c6-bootstrap-required",
    )
    bootstrap_details = bootstrap_report["full_c6"]
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
        policy_sha256=policy_sha256,
    )
    _write_config(project, unsigned_config)
    signing_report = _invoke_build_lifecycle(
        project,
        lifecycle="signing-required",
        status="full-c6-signing-required",
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
        policy_sha256=policy_sha256,
        final_signature=final_signature,
    )
    _write_config(project, signed_config)
    publication_report = _invoke_build_lifecycle(
        project,
        lifecycle="publication-required",
        status="full-c6-published",
    )

    reports = (bootstrap_report, signing_report, publication_report)
    production_authorities = []
    for report in reports:
        details = report["full_c6"]
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

    signing_details = signing_report["full_c6"]
    publication_details = publication_report["full_c6"]
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
    if os.environ.get("REXTIO_FULL_C6_E2E_CHILD") != "1" or len(sys.argv) != 2:
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
    from rextio.build.full_c6_host_inputs import collect_full_c6_analysis_scope

    analysis_scope = collect_full_c6_analysis_scope(
        project,
        config=bootstrap_config,
    )
    preflight = _prepare_preflight(project, bootstrap_config, analysis_scope)
    _write_license_locks(
        project,
        config=bootstrap_config,
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
    )
    _verify_published_native_wheel(
        project,
        dependency_wheel,
        publication_report=publication_report,
    )
    print("FULL_C6_REAL_E2E_OK")


if __name__ == "__main__":
    main()
