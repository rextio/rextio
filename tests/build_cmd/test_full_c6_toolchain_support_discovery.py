"""Focused tests for fixed-profile Full C6 support discovery."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import pickle

import pytest

from rextio.build import full_c6_toolchain_support as support
from rextio.build.full_c6_read_sandbox import MacOSPlatformAnchor
from rextio.build.toolchain_identity import capture_tool_identity
from rextio.build.toolchain_support_lock import (
    ToolchainSupportLockError,
    ToolchainSupportVerificationDriftError,
    create_toolchain_support_locator,
    generate_toolchain_support_lock,
)
from rextio.config.schema import (
    ImportPackagePolicy,
    ImportsConfig,
    RextioConfig,
)


LINUX = "x86_64-unknown-linux-gnu"
MACOS = "aarch64-apple-darwin"


def _file(path: Path, data: bytes = b"fixture", *, executable: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755 if executable else 0o644)
    return path.resolve()


def _tree(path: Path, *, member: str = "member") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _file(path / member, path.name.encode("utf-8"))
    return path.resolve()


def _write_strict_bootstrap_config(
    project: Path,
    *,
    support_path: str | None = None,
    support_sha256: str | None = None,
    source_archive: str = "authority/demo_pkg-1.0.0-py3-none-any.whl",
) -> None:
    digest = "a" * 64
    support_rows: tuple[str, ...] = ()
    if support_path is not None:
        support_rows += (f'artifact_toolchain_support_lock = "{support_path}"',)
    if support_sha256 is not None:
        support_rows += (
            f'artifact_toolchain_support_lock_sha256 = "{support_sha256}"',
        )
    (project / "rextio.toml").write_text(
        "\n".join(
            (
                "[build]",
                'fallback_backend = "cpython"',
                'artifact_evidence_policy = "required"',
                'artifact_distribution_policy = "full-c6-required"',
                'artifact_source_lock_manifest = "authority/source-lock.json"',
                'artifact_source_lock_signature = "authority/source-lock.sig.json"',
                'artifact_policy_manifest = "authority/policy.json"',
                'artifact_cargo_vendor = "cargo-vendor"',
                f'artifact_cargo_vendor_sha256 = "{digest}"',
                'artifact_cargo_lock = "authority/Cargo.lock"',
                f'artifact_cargo_lock_sha256 = "{digest}"',
                *support_rows,
                'artifact_trusted_public_key = "authority/owner.ed25519.pub"',
                f'artifact_trusted_public_key_sha256 = "{digest}"',
                (
                    'artifact_signing_request_output = '
                    '".rextio/full-c6-state/'
                    'rextio.full-c6-final-authorization-request.json"'
                ),
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
                "[imports]",
                'default_external_policy = "fallback"',
                "",
                "[imports.packages.demo_pkg]",
                'policy = "try-native"',
                "max_depth = 1",
                'distribution = "demo-pkg"',
                'version = "1.0.0"',
                f'source_archive = "{source_archive}"',
                f'source_archive_sha256 = "{digest}"',
                "",
                "[embedding]",
                "enabled = false",
                "",
                "[policy]",
                "native_top_level = false",
            )
        )
        + "\n",
        encoding="utf-8",
    )


def _fixed_plan(
    tmp_path: Path,
    *,
    target_triple: str = LINUX,
) -> support.FullC6ToolchainSupportPlan:
    manifests, roots = support.expected_full_c6_toolchain_support_roles(
        target_triple
    )
    material = tmp_path / "material"
    manifest_locators = tuple(
        create_toolchain_support_locator(
            logical_role=role,
            path=_file(
                material
                / "manifests"
                / (
                    (
                        support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME
                        if target_triple == LINUX
                        else "Python"
                    )
                    if role == "python-runtime-library"
                    else role
                ),
                role.encode("utf-8"),
            ),
            kind="file",
        )
        for role in manifests
    )
    root_locators = tuple(
        create_toolchain_support_locator(
            logical_role=role,
            path=_tree(material / "roots" / role),
            kind="tree",
        )
        for role in roots
    )
    python = _file(material / "tools" / "python3.11", executable=True)
    rust_sysroot = next(
        item._absolute_path
        for item in root_locators
        if item.logical_role == "rust-sysroot"
    )
    cargo = _file(rust_sysroot / "bin" / "cargo", executable=True)
    rustc = _file(rust_sysroot / "bin" / "rustc", executable=True)
    linker = _file(material / "tools" / "linker", executable=True)
    inspector = _file(material / "tools" / "inspector", executable=True)
    runtime_leaf = _file(material / "runtime" / "libc.so.6")
    anchor = (
        MacOSPlatformAnchor(
            authenticated_snapshot_id="a" * 64,
            snapshot_uuid="12345678-1234-1234-1234-123456789abc",
            os_build="25A123",
            provider="fixture-provider-v1",
        )
        if target_triple == MACOS
        else None
    )
    locators = (*manifest_locators, *root_locators)
    return support._new_plan(
        target_triple=target_triple,
        python=python,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        inspector=inspector,
        manifests=manifest_locators,
        roots=root_locators,
        base_environment={"PATH": "/tools"},
        anchor=anchor,
        elf_runtime_files=(runtime_leaf,) if target_triple == LINUX else (),
        critical_paths=(
            python,
            linker,
            inspector,
            runtime_leaf,
            *(item._absolute_path for item in locators),
        ),
        platform_inspector_identity=(
            capture_tool_identity(
                "otool",
                inspector,
                reported_version="fixture otool",
            )
            if target_triple == MACOS
            else None
        ),
    )


def test_fixed_roles_generation_verification_and_namespace_round_trip(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    lock = support.generate_full_c6_toolchain_support_lock(plan)

    assert tuple(item.logical_role for item in lock.manifests) == (
        support.LINUX_MANIFEST_ROLES
    )
    assert tuple(item.logical_role for item in lock.roots) == support.LINUX_ROOT_ROLES
    assert support.verify_full_c6_toolchain_support_lock(plan, lock) is True
    mappings = {item.logical_role: item for item in plan.namespace_mappings}
    assert mappings["toolchain-python311"].virtual_path.as_posix() == (
        "/rextio/toolchain/bin/python3.11"
    )
    assert mappings["toolchain-python311-stdlib"].virtual_path.as_posix() == (
        "/rextio/toolchain/lib/python3.11"
    )
    assert mappings["support-landlock-launcher"].virtual_path.as_posix() == (
        "/rextio/support/rextio/full_c6_linux_launcher.py"
    )
    assert mappings["support-runtime-libs"].virtual_path.as_posix() == (
        "/x86_64-linux-gnu"
    )
    assert mappings["support-gcc-toolchain"].virtual_path.as_posix() == (
        "/rextio/support/gcc-toolchain"
    )
    assert mappings["support-python-library-root"].virtual_path.as_posix() == (
        "/rextio/support/python-library-root"
    )
    assert mappings[
        "toolchain-python311-runtime-library"
    ].virtual_path.as_posix() == (
        "/rextio/toolchain/lib/libpython3.11.so.1.0"
    )
    assert mappings["runtime-loader-mirror"].virtual_path.as_posix() == (
        "/lib64/ld-linux-x86-64.so.2"
    )
    assert mappings["toolchain-rust-sysroot"].virtual_path.as_posix() == (
        "/rextio/toolchain"
    )
    for role in ("ar", "cargo", "ld", "linker", "ranlib", "rustc"):
        assert mappings[f"toolchain-{role}"].virtual_path.as_posix() == (
            f"/rextio/toolchain/bin/{role}"
        )
    ordered_roles = [item.logical_role for item in plan.namespace_mappings]
    assert ordered_roles.index("toolchain-rust-sysroot") < ordered_roles.index(
        "toolchain-cargo"
    )
    assert plan.macos_platform_anchor is None


def test_bootstrap_materializes_canonical_lock_and_exactly_reuses(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)

    created = support.materialize_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/rextio.toolchain-support.lock.json",
        plan=plan,
        configured_artifact_paths=(),
    )

    output = authority / "rextio.toolchain-support.lock.json"
    assert created.result == "created"
    assert created.target == LINUX
    assert created.manifest_roles == support.LINUX_MANIFEST_ROLES
    assert created.root_roles == support.LINUX_ROOT_ROLES
    assert created.raw_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert created.config == {
        "artifact_toolchain_support_lock": (
            "authority/rextio.toolchain-support.lock.json"
        ),
        "artifact_toolchain_support_lock_sha256": created.raw_sha256,
    }
    projection = created.to_dict()
    assert projection["authorizes_build"] is False
    assert projection["authorizes_distribution"] is False
    assert str(tmp_path) not in json.dumps(projection, sort_keys=True)

    reused = support.materialize_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/rextio.toolchain-support.lock.json",
        plan=plan,
        configured_artifact_paths=(),
    )
    assert reused.result == "reused"
    assert reused.to_dict() == {**projection, "result": "reused"}


def test_bootstrap_accepts_disjoint_non_json_artifact_paths(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    (tmp_path / "authority").mkdir(mode=0o700)

    result = support.materialize_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/rextio.toolchain-support.lock.json",
        plan=plan,
        configured_artifact_paths=(
            "authority/owner.ed25519.pub",
            "cargo-vendor",
        ),
    )

    assert result.result == "created"


@pytest.mark.parametrize(
    ("output", "source_archive"),
    (
        (
            "authority/demo-pkg.whl",
            "authority/demo-pkg.whl",
        ),
        (
            "authority/support.json",
            "authority/support.json/demo-pkg.whl",
        ),
        (
            "authority/demo-pkg.whl/support.json",
            "authority/demo-pkg.whl",
        ),
    ),
    ids=("exact", "output-ancestor", "output-descendant"),
)
def test_support_output_rejects_configured_source_archive_overlap_lexically(
    output: str,
    source_archive: str,
) -> None:
    config = RextioConfig(
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive=source_archive,
                    source_archive_sha256="a" * 64,
                )
            }
        )
    )
    configured = support._configured_full_c6_artifact_paths(config)

    assert source_archive in configured
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="aliases another configured artifact",
    ):
        support._require_nonaliased_support_output(
            output,
            configured_artifact_paths=configured,
        )


def test_support_output_accepts_unrelated_configured_source_archive() -> None:
    source_archive = "authority/demo-pkg.whl"
    config = RextioConfig(
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    source_archive=source_archive,
                    source_archive_sha256="a" * 64,
                )
            }
        )
    )

    configured = support._configured_full_c6_artifact_paths(config)
    support._require_nonaliased_support_output(
        "authority/rextio.toolchain-support.lock.json",
        configured_artifact_paths=configured,
    )

    assert source_archive in configured


@pytest.mark.parametrize(
    ("output", "source_archive"),
    (
        (
            "authority/support.json",
            "authority/support.json/demo-pkg.whl",
        ),
        (
            "authority/demo-pkg.whl/support.json",
            "authority/demo-pkg.whl",
        ),
    ),
    ids=("output-ancestor", "output-descendant"),
)
def test_bootstrap_rejects_missing_source_archive_path_overlap_before_output_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    source_archive: str,
) -> None:
    _write_strict_bootstrap_config(
        tmp_path,
        source_archive=source_archive,
    )
    plan = _fixed_plan(tmp_path / "plan")
    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        lambda **_kwargs: plan,
    )

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="aliases another configured artifact",
    ):
        support.bootstrap_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output=output,
            inherited_environment={},
        )

    assert not (tmp_path / output).exists()


@pytest.mark.parametrize(
    "output",
    (
        "../escape.json",
        "/tmp/escape.json",
        "authority/../escape.json",
        "authority//escape.json",
        "authority\\escape.json",
        "authority/not-a-json-lock",
    ),
)
def test_bootstrap_rejects_noncanonical_or_outside_output(
    tmp_path: Path,
    output: str,
) -> None:
    plan = _fixed_plan(tmp_path)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="project-relative",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output=output,
            plan=plan,
            configured_artifact_paths=(),
        )


def test_bootstrap_rejects_linked_parent_and_stale_existing_bytes(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    real = tmp_path / "real-authority"
    real.mkdir(mode=0o700)
    (tmp_path / "linked-authority").symlink_to(real, target_is_directory=True)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="unavailable or linked",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="linked-authority/support.json",
            plan=plan,
            configured_artifact_paths=(),
        )

    stale = real / "support.json"
    stale.write_bytes(b"{}")
    stale.chmod(0o600)
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="existing .* bytes differ",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="real-authority/support.json",
            plan=plan,
            configured_artifact_paths=(),
        )
    assert stale.read_bytes() == b"{}"


def test_bootstrap_requires_private_owner_output_parent(tmp_path: Path) -> None:
    plan = _fixed_plan(tmp_path)
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o755)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="output parent must be owner-private mode 0700",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/support.json",
            plan=plan,
            configured_artifact_paths=(),
        )


def test_bootstrap_normalizes_project_root_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = os.open

    def deny_project_anchor(
        path: str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == tmp_path.anchor and dir_fd is None:
            raise PermissionError("denied fixture anchor")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(support.os, "open", deny_project_anchor)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="project root is unavailable",
    ):
        support._open_support_output_parent(
            tmp_path,
            "authority/support.json",
        )


def test_bootstrap_rejects_casefold_artifact_alias_and_hardlink_alias(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="aliases another configured artifact",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/support.json",
            plan=plan,
            configured_artifact_paths=("AUTHORITY/SUPPORT.JSON",),
        )

    original = authority / "original.json"
    original.write_bytes(b"{}")
    original.chmod(0o600)
    os.link(original, authority / "support.json")
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="not one private regular file",
    ):
        support.materialize_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/support.json",
            plan=plan,
            configured_artifact_paths=(),
        )


def test_bootstrap_loads_strict_config_before_support_lock_is_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_strict_bootstrap_config(tmp_path)
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)
    plan = _fixed_plan(tmp_path / "plan")
    seen: dict[str, object] = {}

    def discover(*, project_root: Path, config: object, inherited_environment: object) -> object:
        seen["project_root"] = project_root
        seen["config"] = config
        seen["inherited_environment"] = inherited_environment
        return plan

    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        discover,
        raising=False,
    )

    result = support.bootstrap_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/toolchain-support.json",
        inherited_environment={},
    )

    assert result.result == "created"
    assert seen["project_root"] == tmp_path
    config = seen["config"]
    assert getattr(config, "build").artifact_toolchain_support_lock == (
        "authority/toolchain-support.json"
    )
    assert getattr(config, "build").artifact_toolchain_support_lock_sha256 == (
        "0" * 64
    )
    assert "artifact_toolchain_support_lock" not in (
        tmp_path / "rextio.toml"
    ).read_text(encoding="utf-8")


def test_bootstrap_exactly_reuses_matching_configured_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)
    _write_strict_bootstrap_config(
        tmp_path,
        support_path="authority/toolchain-support.json",
        support_sha256="0" * 64,
    )
    plan = _fixed_plan(tmp_path / "plan")
    initial = support.materialize_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/toolchain-support.json",
        plan=plan,
        configured_artifact_paths=(),
    )
    _write_strict_bootstrap_config(
        tmp_path,
        support_path="authority/toolchain-support.json",
        support_sha256=initial.raw_sha256,
    )
    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        lambda **_kwargs: plan,
    )

    reused = support.bootstrap_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/toolchain-support.json",
        inherited_environment={},
    )

    assert reused.result == "reused"
    assert reused.raw_sha256 == initial.raw_sha256


def test_bootstrap_rejects_partial_or_stale_configured_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)
    _write_strict_bootstrap_config(
        tmp_path,
        support_path="authority/toolchain-support.json",
        support_sha256="0" * 64,
    )
    plan = _fixed_plan(tmp_path / "plan")
    initial = support.materialize_full_c6_toolchain_support_lock(
        project_root=tmp_path,
        output="authority/toolchain-support.json",
        plan=plan,
        configured_artifact_paths=(),
    )
    output = authority / "toolchain-support.json"
    original = output.read_bytes()
    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        lambda **_kwargs: plan,
    )

    _write_strict_bootstrap_config(
        tmp_path,
        support_path="authority/toolchain-support.json",
    )
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="path and SHA-256 must be configured together",
    ):
        support.bootstrap_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/toolchain-support.json",
            inherited_environment={},
        )

    _write_strict_bootstrap_config(
        tmp_path,
        support_sha256="e" * 64,
    )
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="path and SHA-256 must be configured together",
    ):
        support.bootstrap_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/toolchain-support.json",
            inherited_environment={},
        )

    _write_strict_bootstrap_config(
        tmp_path,
        support_path="authority/toolchain-support.json",
        support_sha256="f" * 64,
    )
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="differs from the configured SHA-256",
    ):
        support.bootstrap_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/toolchain-support.json",
            inherited_environment={},
        )
    assert output.read_bytes() == original
    assert initial.raw_sha256 != "f" * 64


def test_bootstrap_rejects_unsupported_host_before_tool_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build import full_c6_host_inputs as host

    authority = tmp_path / "authority"
    authority.mkdir(mode=0o700)

    def unsupported() -> str:
        raise host.FullC6HostInputsError("unsupported Full C6 host")

    monkeypatch.setattr(host, "_require_supported_host", unsupported)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="bootstrap discovery failed closed",
    ):
        support.bootstrap_full_c6_toolchain_support_lock(
            project_root=tmp_path,
            output="authority/toolchain-support.json",
            inherited_environment={},
        )
    assert not (authority / "toolchain-support.json").exists()


def test_macos_plan_exposes_exact_sealed_platform_anchor(tmp_path: Path) -> None:
    plan = _fixed_plan(tmp_path, target_triple=MACOS)

    assert plan.macos_platform_anchor is plan._anchor
    assert plan.platform_anchor is plan.macos_platform_anchor
    assert plan.macos_platform_anchor is not None
    assert plan.macos_platform_anchor.digest == plan.platform_anchor_sha256


@pytest.mark.parametrize("attack", ("missing", "extra", "wrong-kind", "wrong-target"))
def test_lock_role_kind_and_target_drift_fails_before_rewalk(
    tmp_path: Path,
    attack: str,
) -> None:
    plan = _fixed_plan(tmp_path)
    manifests = list(plan.manifest_locators)
    roots = list(plan.root_locators)
    target = LINUX
    if attack == "missing":
        manifests.pop()
    elif attack == "extra":
        manifests.append(
            create_toolchain_support_locator(
                logical_role="unexpected-support",
                path=_file(tmp_path / "unexpected"),
                kind="file",
            )
        )
    elif attack == "wrong-kind":
        replaced = roots.pop()
        manifests.append(
            create_toolchain_support_locator(
                logical_role=replaced.logical_role,
                path=_file(tmp_path / "reclassified"),
                kind="file",
            )
        )
    else:
        target = MACOS
        with pytest.raises(
            ToolchainSupportLockError,
            match="dispositions are missing",
        ):
            generate_toolchain_support_lock(
                target_triple=target,
                manifests=manifests,
                roots=roots,
            )
        return
    lock = generate_toolchain_support_lock(
        target_triple=target,
        manifests=manifests,
        roots=roots,
    )

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="roles, kinds, or target",
    ):
        support.verify_full_c6_toolchain_support_lock(plan, lock)


def test_changed_deep_support_bytes_are_detected_by_explicit_rewalk(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    lock = support.generate_full_c6_toolchain_support_lock(plan)
    rust = next(
        item
        for item in plan.root_locators
        if item.logical_role == "rust-sysroot"
    )
    (rust._absolute_path / "member").write_bytes(b"changed deeply")

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="support bytes differ",
    ) as caught:
        support.verify_full_c6_toolchain_support_lock(plan, lock)

    cause = caught.value.__cause__
    assert type(cause) is ToolchainSupportVerificationDriftError
    assert cause.manifest_difference_count == 0
    assert cause.root_difference_count == 1
    assert cause.first_difference_kind == "root"
    assert cause.first_logical_role == "rust-sysroot"
    assert cause.before_merkle_sha256 != cause.after_merkle_sha256
    assert cause.tree_changed_fields == ("total_bytes", "merkle")
    assert cause.tree_changed_field_mask == "2040"


def test_plan_access_is_cheap_but_stage_revalidation_detects_tool_mutation(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    linker = plan.linker_path
    linker.write_bytes(b"changed linker")

    assert support.require_full_c6_toolchain_support_plan(plan) is plan
    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="critical support path changed",
    ):
        support.revalidate_full_c6_toolchain_support_plan(plan)


def test_plan_is_immutable_nonserializable_sealed_and_path_private(
    tmp_path: Path,
) -> None:
    plan = _fixed_plan(tmp_path)
    rendered = repr(plan)
    assert str(tmp_path) not in rendered
    assert all(str(tmp_path) not in repr(item) for item in plan.namespace_mappings)
    with pytest.raises(TypeError, match="immutable"):
        setattr(plan, "extra", object())
    with pytest.raises(TypeError, match="copied"):
        copy.copy(plan)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(plan)

    object.__setattr__(plan, "_target_triple", MACOS)
    with pytest.raises(support.FullC6ToolchainSupportError, match="seal is invalid"):
        support.require_full_c6_toolchain_support_plan(plan)


def test_python_runtime_discovery_requires_exact_cpython311_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python = _file(tmp_path / "bin" / "python3.11", executable=True)
    stdlib = _tree(tmp_path / "lib" / "python3.11")
    _file(stdlib / "encodings" / "__init__.py")
    _tree(stdlib / "lib-dynload", member="_ctypes.so")
    library = _file(tmp_path / "lib" / "libpython3.11.so")
    document = {
        "executable": os.fspath(python),
        "implementation": "cpython",
        "major": 3,
        "minor": 11,
        "isolated": 1,
        "no_site": 1,
        "stdlib": os.fspath(stdlib),
        "platstdlib": os.fspath(stdlib),
        "libdir": os.fspath(library.parent),
        "ldlibrary": library.name,
        "framework": "",
        "framework_install_dir": "",
    }
    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )

    assert support._discover_python_runtime(
        python,
        cwd=tmp_path,
        environment={},
    ) == (stdlib, library)
    document["minor"] = 12
    with pytest.raises(support.FullC6ToolchainSupportError, match="3.11"):
        support._discover_python_runtime(
            python,
            cwd=tmp_path,
            environment={},
        )


def test_macos_rejects_command_line_tools_and_usr_bin_clang_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    developer = tmp_path / "Xcode.app" / "Contents" / "Developer"
    monkeypatch.setattr(support, "MACOS_DEVELOPER_DIR", developer)
    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: "/Library/Developer/CommandLineTools",
    )
    with pytest.raises(support.FullC6ToolchainSupportError, match="Xcode.app"):
        support.resolve_full_c6_linker_and_inspector(
            target_triple=MACOS,
            cwd=tmp_path,
        )

    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: os.fspath(developer),
    )
    monkeypatch.setattr(
        support,
        "_stable_absolute_output",
        lambda *_args, **_kwargs: Path("/usr/bin/clang"),
    )
    with pytest.raises(support.FullC6ToolchainSupportError, match="not canonical"):
        support.resolve_full_c6_linker_and_inspector(
            target_triple=MACOS,
            cwd=tmp_path,
        )


def test_macos_fixed_xcode_layout_pins_clang_17_and_version_plist() -> None:
    assert support.MACOS_XCODE_DEFAULT_TOOLCHAIN == Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/"
        "XcodeDefault.xctoolchain"
    )
    assert support.MACOS_XCODE_TOOL_BIN == Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/"
        "XcodeDefault.xctoolchain/usr/bin"
    )
    assert support.MACOS_XCODE_CLANG_RESOURCE_VERSION == "17"
    assert support.MACOS_XCODE_CLANG_RESOURCE == Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/"
        "XcodeDefault.xctoolchain/usr/lib/clang/17"
    )
    assert support.MACOS_XCODE_VERSION_PLIST == Path(
        "/Applications/Xcode.app/Contents/version.plist"
    )
    assert support._require_fixed_macos_clang_resource(
        support.MACOS_XCODE_CLANG_RESOURCE
    ) == support.MACOS_XCODE_CLANG_RESOURCE


@pytest.mark.parametrize(
    "candidate",
    (
        Path(
            "/Applications/Xcode.app/Contents/Developer/Toolchains/"
            "XcodeDefault.xctoolchain/usr/lib/clang/18"
        ),
        Path(
            "/Applications/Xcode-Beta.app/Contents/Developer/Toolchains/"
            "XcodeDefault.xctoolchain/usr/lib/clang/17"
        ),
        Path(
            "/Applications/Xcode.app/Contents/Developer/Toolchains/"
            "Alternate.xctoolchain/usr/lib/clang/17"
        ),
        Path(
            "/private/secret/XcodeDefault.xctoolchain/usr/lib/clang/17"
        ),
    ),
    ids=("version", "app-root", "toolchain", "untrusted-root"),
)
def test_macos_fixed_xcode_layout_rejects_resource_near_misses_path_privately(
    candidate: Path,
) -> None:
    with pytest.raises(support.FullC6ToolchainSupportError) as captured:
        support._require_fixed_macos_clang_resource(candidate)

    message = str(captured.value)
    assert message == (
        "Full C6 Xcode clang resource differs from the fixed version profile"
    )
    assert os.fspath(candidate) not in message
    assert "/Applications" not in message
    assert "/private" not in message


def test_macos_platform_tool_keeps_hardlink_out_of_generic_support_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _file(tmp_path / "otool-image", executable=True)
    anchored_path = tmp_path / "otool"
    os.link(original, anchored_path)
    monkeypatch.setattr(support, "MACOS_OTOOL", anchored_path)

    with pytest.raises(support.FullC6ToolchainSupportError, match="aliased"):
        support._require_real_file(anchored_path, executable=True)
    assert support._require_platform_anchored_macos_tool(
        anchored_path
    ) == anchored_path


def test_xcode_ranlib_symlink_is_sealed_separately_from_implementation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_bin = tmp_path / "Xcode.app" / "usr" / "bin"
    implementation = _file(tool_bin / "libtool", executable=True)
    ranlib = tool_bin / "ranlib"
    ranlib.symlink_to(implementation.name)
    monkeypatch.setattr(
        support,
        "_stable_absolute_output",
        lambda *_args, **_kwargs: ranlib,
    )

    assert support._xcrun_tool(
        "ranlib",
        cwd=tmp_path,
        environment={},
        root=tool_bin,
        allow_symlink=True,
    ) == ranlib
    binding = support._capture_path_binding(ranlib, kind="symlink")
    assert binding.raw_sha256 is not None
    with pytest.raises(support.FullC6ToolchainSupportError, match="unexpected"):
        support._xcrun_tool(
            "ranlib",
            cwd=tmp_path,
            environment={},
            root=tool_bin,
        )


def test_linux_resolves_distribution_linker_and_inspector_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    linker = _file(tmp_path / "x86_64-linux-gnu-gcc", executable=True)
    inspector = _file(tmp_path / "x86_64-linux-gnu-readelf", executable=True)
    cc = tmp_path / "cc"
    readelf = tmp_path / "readelf"
    cc.symlink_to(linker.name)
    readelf.symlink_to(inspector.name)
    monkeypatch.setattr(support, "LINUX_CC", cc)
    monkeypatch.setattr(support, "LINUX_READELF", readelf)

    assert support.resolve_full_c6_linker_and_inspector(
        target_triple=LINUX,
        cwd=tmp_path,
    ) == (linker, inspector)


def test_linux_normalizes_cyclic_distribution_inspector_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    linker = _file(tmp_path / "x86_64-linux-gnu-gcc", executable=True)
    readelf = tmp_path / "readelf"
    inspector = tmp_path / "x86_64-linux-gnu-readelf"
    readelf.symlink_to(inspector.name)
    inspector.symlink_to(readelf.name)
    monkeypatch.setattr(support, "LINUX_CC", linker)
    monkeypatch.setattr(support, "LINUX_READELF", readelf)

    with pytest.raises(
        support.FullC6ToolchainSupportError,
        match="support executable could not be resolved",
    ):
        support.resolve_full_c6_linker_and_inspector(
            target_triple=LINUX,
            cwd=tmp_path,
        )


def test_stable_resolved_file_output_accepts_gcc_dot_segments_only_when_absolute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gcc_root = tmp_path / "usr" / "lib" / "gcc" / "x86_64-linux-gnu" / "13"
    gcc_root.mkdir(parents=True)
    crt1 = _file(tmp_path / "usr" / "lib" / "x86_64-linux-gnu" / "crt1.o")
    selected = gcc_root / ".." / ".." / ".." / "x86_64-linux-gnu" / "crt1.o"
    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: os.fspath(selected),
    )

    assert support._stable_resolved_file_output(
        ["cc", "--print-file-name=crt1.o"],
        cwd=tmp_path,
        environment={},
    ) == crt1

    monkeypatch.setattr(
        support,
        "_stable_one_line",
        lambda *_args, **_kwargs: "crt1.o",
    )
    with pytest.raises(support.FullC6ToolchainSupportError, match="absolute"):
        support._stable_resolved_file_output(
            ["cc", "--print-file-name=crt1.o"],
            cwd=tmp_path,
            environment={},
        )


def test_linux_missing_exact_bwrap_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = {
        name: _file(tmp_path / name, executable=True)
        for name in ("python", "cargo", "rustc", "linker", "readelf")
    }
    monkeypatch.setattr(
        support,
        "resolve_full_c6_linker_and_inspector",
        lambda **_kwargs: (tools["linker"], tools["readelf"]),
    )
    monkeypatch.setattr(support, "LINUX_BWRAP", tmp_path / "missing-bwrap")

    with pytest.raises(support.FullC6ToolchainSupportError, match="unavailable"):
        support._discover_linux_support(
            cwd=tmp_path,
            python=tools["python"],
            cargo=tools["cargo"],
            rustc=tools["rustc"],
            linker=tools["linker"],
            inspector=tools["readelf"],
        )


def test_linux_elf_runtime_follows_interp_and_needed_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    seed = _file(tmp_path / "python3.11", executable=True)
    inspector = _file(tmp_path / "readelf", executable=True)
    loader = _file(runtime / "ld-linux-x86-64.so.2", executable=True)
    liba = _file(runtime / "liba.so")
    libc = _file(runtime / "libc.so.6")

    def output(command: list[str], **_kwargs: object) -> str:
        image = Path(command[-1])
        if "-l" in command:
            return (
                f"[Requesting program interpreter: {loader}]\n"
                if image == seed
                else "no interpreter\n"
            )
        needed = {
            seed: "liba.so",
            liba: "libc.so.6",
        }.get(image)
        return f"Shared library: [{needed}]\n" if needed is not None else "none\n"

    monkeypatch.setattr(support, "_stable_output", output)
    files, observed_loader = support._discover_linux_elf_runtime(
        seeds=(seed,),
        inspector=inspector,
        runtime_root=runtime.resolve(),
        search_roots=(runtime.resolve(),),
        cwd=tmp_path,
        environment={},
    )

    assert observed_loader == loader
    assert files == tuple(sorted((loader, liba, libc), key=os.fspath))


def test_linux_elf_runtime_resolves_fixed_multi_root_dependency_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_root = _tree(tmp_path / "system", member="system-member")
    python_root = _tree(tmp_path / "python-root", member="python-member")
    rust_root = _tree(tmp_path / "rust-root", member="rust-member")
    seed = _file(tmp_path / "python3.11", executable=True)
    inspector = _file(tmp_path / "readelf", executable=True)
    loader = _file(system_root / "ld-linux-x86-64.so.2", executable=True)
    libpython = _file(python_root / support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME)
    librust = _file(rust_root / "librust_support.so")

    def output(command: list[str], **_kwargs: object) -> str:
        image = Path(command[-1])
        if "-l" in command:
            return (
                f"[Requesting program interpreter: {loader}]\n"
                if image == seed
                else "no interpreter\n"
            )
        needed = {
            seed: support.LINUX_PYTHON_RUNTIME_LIBRARY_NAME,
            libpython: "librust_support.so",
        }.get(image)
        return f"Shared library: [{needed}]\n" if needed is not None else "none\n"

    monkeypatch.setattr(support, "_stable_output", output)
    files, observed_loader = support._discover_linux_elf_runtime(
        seeds=(seed,),
        inspector=inspector,
        runtime_root=system_root,
        search_roots=(system_root, python_root, rust_root),
        cwd=tmp_path,
        environment={},
    )

    assert observed_loader == loader
    assert files == tuple(sorted((loader, libpython, librust), key=os.fspath))


def test_linux_needed_resolution_rejects_ambiguous_distinct_files(
    tmp_path: Path,
) -> None:
    first = _tree(tmp_path / "first")
    second = _tree(tmp_path / "second")
    _file(first / "libsame.so", b"first")
    _file(second / "libsame.so", b"second")

    with pytest.raises(support.FullC6ToolchainSupportError, match="ambiguous"):
        support._resolve_linux_needed_dependency("libsame.so", (first, second))


def test_linux_needed_resolution_rejects_escape_and_missing(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "root")
    outside = _file(tmp_path / "outside" / "libescape.so")
    (root / "libescape.so").symlink_to(outside)

    with pytest.raises(support.FullC6ToolchainSupportError, match="escaped"):
        support._resolve_linux_needed_dependency("libescape.so", (root,))
    with pytest.raises(support.FullC6ToolchainSupportError, match="missing"):
        support._resolve_linux_needed_dependency("libmissing.so", (root,))


def test_linux_needed_resolution_deduplicates_repeated_canonical_root(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "root")
    dependency = _file(root / "libsame.so")

    assert support._resolve_linux_needed_dependency(
        "libsame.so",
        (root, root),
    ) == dependency


def test_namespace_mapping_rejects_noncanonical_role_destination(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="mapping is invalid"):
        support.FullC6SupportNamespaceMapping(
            logical_role="toolchain-python311",
            host_path=_file(tmp_path / "python", executable=True),
            virtual_path=support.FULL_C6_TOOLCHAIN_SUPPORT_VIRTUAL_ROOT / "python",
            kind="file",
        )
