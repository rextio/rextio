"""Focused tests for C6.2 host-extension wheel evidence emission."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import rextio.artifacts.evidence as evidence_mod
from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
    SourcePosition,
    SourceRange,
)
from rextio.artifacts.evidence import (
    ArtifactEvidenceGate,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    REASON_RUNTIME_INSPECTOR_FAILED,
    WheelEntryRef,
    hash_regular_file,
)
from rextio.artifacts.authorization import (
    ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_RUNTIME_CLOSURE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_RUNTIME_PATH_RESOLUTION_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE,
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import detect_host_target_triple, host_extension_profile
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.cargo_builder import NativeBuildResult
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_cargo_lock_input,
    capture_generated_python_inputs,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
    emit_host_extension_wheel_evidence,
)
from rextio.build.wheel_builder import WheelBuildResult, build_artifact_wheel
from rextio.partition.build_plan import BuildPlan
from rextio.partition.fallback_plan import FallbackPlan
from rextio.partition.native_plan import NativePlan
from rextio.source.models import SourceModule, SourceModuleGraph, SourceOrigin
from rextio.source.planning import HostSourcePlan


@pytest.fixture(autouse=True)
def _synthetic_runtime_inspector(monkeypatch: pytest.MonkeyPatch) -> None:
    from rextio.build import supply_chain as supply_chain_module
    from rextio.build.runtime_resolution import NativeRuntimePathResolutionObservation

    def inspect(
        *,
        installed_path: Path | None,
        expected_python_root: Path,
        wheel_entries: tuple[WheelEntryRef, ...],
        target_triple: str,
        timeout: float,
    ) -> NativeRuntimeInventory:
        del timeout
        assert installed_path is not None
        binary = Path(installed_path).resolve(strict=True)
        member_name = binary.relative_to(expected_python_root.resolve(strict=True)).as_posix()
        entry = next(item for item in wheel_entries if item.name == member_name)
        digest, size = hash_regular_file(binary)
        assert (entry.sha256, entry.uncompressed_size) == (digest, size)
        arch_token = target_triple.split("-", 1)[0]
        architecture = (
            "aarch64"
            if arch_token in {"aarch64", "arm64"}
            else "x86_64"
            if arch_token == "x86_64"
            else "arm"
            if arch_token.startswith("arm")
            else "x86"
        )
        format_name = "mach-o" if "apple-darwin" in target_triple else "elf"
        return NativeRuntimeInventory(
            format=format_name,
            architecture=architecture,
            inspector="otool" if format_name == "mach-o" else "readelf",
            subject_basename=binary.name,
            subject_sha256=digest,
            subject_size=size,
            wheel_member=entry.name,
            wheel_member_sha256=entry.sha256,
            wheel_member_size=entry.uncompressed_size,
            dependencies=(
                NativeRuntimeDependency(
                    name="libSystem.B.dylib" if format_name == "mach-o" else "libc.so.6",
                    origin="system" if format_name == "mach-o" else "unresolved",
                ),
            ),
        )

    monkeypatch.setattr(supply_chain_module, "inspect_native_runtime_inventory", inspect)

    def resolve(*, runtime_inventory: NativeRuntimeInventory, **_kwargs):
        records = tuple(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=dependency.bom_ref(),
                dependency_name=dependency.name,
                dependency_origin=dependency.origin,
                resolution="system-logical",
                mechanism=(
                    "macho-system"
                    if runtime_inventory.format == "mach-o"
                    else "elf-system-name"
                ),
            )
            for dependency in runtime_inventory.dependencies
        )
        return NativeRuntimePathResolutionObservation(
            inventory=NativeRuntimePathResolutionInventory(
                subject_wheel_member=runtime_inventory.wheel_member,
                subject_sha256=runtime_inventory.subject_sha256,
                records=tuple(sorted(records, key=lambda record: record.dependency_bom_ref)),
            ),
            receipts=(),
        )

    monkeypatch.setattr(
        supply_chain_module,
        "collect_native_runtime_path_resolution",
        resolve,
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_project_with_generated_tree(tmp_path: Path) -> tuple[Path, ArtifactLayout, Path]:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source_text = "def add(a: int, b: int) -> int:\n    return a + b\n"
    source.write_bytes(source_text.encode("utf-8"))

    layout = ArtifactLayout(project)
    layout.python_dir.mkdir(parents=True)
    (layout.python_dir / "app.py").write_text(
        "# Generated by Rextio. Do not edit manually.\n" + source_text,
        encoding="utf-8",
    )
    layout.rust_dir.mkdir(parents=True)
    (layout.rust_dir / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "rextio_generated_native"
            version = "0.1.0"
            edition = "2021"

            [lib]
            name = "_rextio_native"
            crate-type = ["cdylib"]
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (layout.rust_dir / "src").mkdir()
    (layout.rust_dir / "src" / "lib.rs").write_text(
        "// Generated by Rextio. Do not edit manually.\npub fn dummy() {}\n",
        encoding="utf-8",
    )
    (layout.rust_dir / "Cargo.lock").write_text(
        textwrap.dedent(
            """
            # This file is automatically @generated by Cargo.
            version = 4

            [[package]]
            name = "rextio_generated_native"
            version = "0.1.0"
            """
        ).lstrip(),
        encoding="utf-8",
    )
    layout.build_python_dir.mkdir(parents=True)
    (layout.build_python_dir / "app.py").write_text(
        (layout.python_dir / "app.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    native_payload = b"synthetic native library"
    (layout.python_dir / "_rextio_native.so").write_bytes(native_payload)
    (layout.build_python_dir / "_rextio_native.so").write_bytes(native_payload)
    wheel = build_artifact_wheel(project, layout.build_python_dir, layout.dist_dir)
    assert wheel.status == "built" and wheel.path is not None
    return project, layout, Path(wheel.path)


def _built_native(layout: ArtifactLayout) -> NativeBuildResult:
    return NativeBuildResult(
        status="built",
        tool="cargo",
        message="ok",
        installed_path=str(layout.python_dir / "_rextio_native.so"),
    )


def _plan(project: Path, profile, source: Path) -> BuildPlan:
    source_bytes = source.read_bytes()
    module = SourceModule(
        module_name="app",
        path="app.py",
        is_package_init=False,
        source_origin=SourceOrigin.PROJECT,
        sha256=_sha(source_bytes),
        dependency_depth=0,
    )
    graph = SourceModuleGraph(modules=(module,))
    host_plan = HostSourcePlan(graph=graph, module_initializers=(), unavailable_reason=None)
    project_analysis = ProjectAnalysis(
        project_root=project,
        modules=[
            ModuleAnalysis(
                module_name="app",
                file_path=str(source),
            ),
        ],
    )
    return BuildPlan(
        analysis=project_analysis,
        native=NativePlan(
            accepted_functions=(),
            rejected_functions=(),
            embedded_functions=(),
        ),
        fallback=FallbackPlan(
            backend="cpython",
            modules=(),
        ),
        host_source_plan=host_plan,
        artifact_profiles=(profile,),
    )


def _plan_with_accepted_function(
    project: Path,
    profile,
    source: Path,
) -> tuple[BuildPlan, FunctionAnalysis]:
    source_text = source.read_text(encoding="utf-8")
    node = ast.parse(source_text).body[0]
    assert isinstance(node, ast.FunctionDef)
    assert node.end_lineno is not None and node.end_col_offset is not None
    function = FunctionAnalysis(
        name=node.name,
        qualname=f"app.{node.name}",
        module_name="app",
        file_path=str(source),
        line=node.lineno,
        column=node.col_offset,
        source_range=SourceRange(
            start=SourcePosition(line=node.lineno, column=node.col_offset),
            end=SourcePosition(line=node.end_lineno, column=node.end_col_offset),
        ),
        is_native_candidate=True,
        accepted=True,
        source_ast_fingerprint=executable_ast_fingerprint(node),
    )
    source_bytes = source.read_bytes()
    graph = SourceModuleGraph(
        modules=(
            SourceModule(
                module_name="app",
                path="app.py",
                is_package_init=False,
                source_origin=SourceOrigin.PROJECT,
                sha256=_sha(source_bytes),
                dependency_depth=0,
            ),
        )
    )
    return (
        BuildPlan(
            analysis=ProjectAnalysis(
                project_root=project,
                modules=[
                    ModuleAnalysis(
                        module_name="app",
                        file_path=str(source),
                        functions=[function],
                    ),
                ],
            ),
            native=NativePlan(
                accepted_functions=(function,),
                rejected_functions=(),
                embedded_functions=(),
            ),
            fallback=FallbackPlan(backend="cpython", modules=()),
            host_source_plan=HostSourcePlan(
                graph=graph,
                module_initializers=(),
                unavailable_reason=None,
            ),
            artifact_profiles=(profile,),
        ),
        function,
    )


def _snapshot(project: Path, layout: ArtifactLayout, plan: BuildPlan) -> EvidenceInputSnapshot:
    snap = capture_project_source_snapshot(project_root=project, plan=plan)
    snap = capture_generated_python_inputs(snap, project_root=project, layout=layout)
    snap = capture_generated_rust_inputs(snap, project_root=project, layout=layout)
    snap = capture_cargo_lock_input(snap, project_root=project, layout=layout)
    return snap


def test_nuitka_host_extension_is_out_of_scope(tmp_path: Path) -> None:
    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(
        detect_host_target_triple(),
        python_fallback_backend="nuitka",
    )
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is None
    assert not list(layout.dist_dir.glob("*.cdx.json"))


def test_non_host_extension_profile_omits_evidence(tmp_path: Path) -> None:
    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    object.__setattr__(plan, "artifact_profiles", ())
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=None,
    )
    assert evidence is None


def test_native_not_built_yields_unavailable_not_failure(tmp_path: Path) -> None:
    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=NativeBuildResult(status="failed", tool="cargo", message="boom"),
        input_snapshot=None,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "native-extension-not-built"
    assert evidence.authority == "evidence-only"
    assert evidence.signature_status == "unsigned"
    assert evidence.composition == "incomplete"
    assert not list(layout.dist_dir.glob("*.cdx.json"))


def test_source_snapshot_mismatch_marks_unavailable(tmp_path: Path) -> None:
    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    # Capture while disk matches the plan, then mutate before evidence emit.
    snap = _snapshot(project, layout, plan)
    assert snap.unavailable_reason is None
    (project / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b + 1\n",
        encoding="utf-8",
    )
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "source-snapshot-mismatch"

    # Capture-time mismatch against a stale plan also fails closed.
    stale = capture_project_source_snapshot(project_root=project, plan=plan)
    assert stale.unavailable_reason == "source-snapshot-mismatch"


def test_preview_ready_writes_sidecars_when_cargo_available(tmp_path: Path) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, function = _plan_with_accepted_function(
        project,
        profile,
        project / "app.py",
    )
    snap = _snapshot(project, layout, plan)
    assert snap.unavailable_reason is None
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")
    sbom_path.write_bytes(b"owner-sbom")
    provenance_path.write_bytes(b"owner-provenance")

    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "preview-ready"
    assert evidence.preview is True
    assert evidence.complete is False
    assert evidence.signed is False
    assert evidence.authority == "evidence-only"
    assert evidence.subject is not None
    assert evidence.subject.logical_path.startswith("dist/")

    sbom_path = project / evidence.sbom.logical_path  # type: ignore[union-attr]
    prov_path = project / evidence.provenance.logical_path  # type: ignore[union-attr]
    assert sbom_path.is_file()
    assert prov_path.is_file()
    assert sbom_path.read_bytes() != b"owner-sbom"
    assert prov_path.read_bytes() != b"owner-provenance"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom["specVersion"] == "1.6"
    assert sbom["compositions"][0]["aggregate"] == "incomplete"
    root_ref = sbom["metadata"]["component"]["bom-ref"]
    assert root_ref not in [c["bom-ref"] for c in sbom["components"]]
    assert str(project) not in sbom_path.read_text(encoding="utf-8")

    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    assert len(prov["subject"]) == 2
    assert "invocationId" not in prov["predicate"]["runDetails"].get("metadata", {})
    material_uris = [
        item["uri"] for item in prov["predicate"]["buildDefinition"]["resolvedDependencies"]
    ]
    assert not any(uri.endswith(".cdx.json") for uri in material_uris)

    report = evidence.to_dict()
    assert report["status"] == "preview-ready"
    assert report["authority"] == "evidence-only"
    assert report["composition"] == "incomplete"
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False
    assert "wheel_entries" in report
    assert "cargo_dependencies" in report
    transformation = report["source_transformation_inventory"]
    assert transformation["kind"] == "source-transformation-inventory"
    assert transformation["record_count"] == 1
    assert transformation["complete"] is False
    transformation_record = evidence.source_transformation_inventory.records[0]  # type: ignore[union-attr]
    source_ref = next(item for item in evidence.inputs if item.role == "project-python-source")
    generated_ref = next(
        item
        for item in evidence.inputs
        if item.role == "generated-rust-input"
        and item.logical_path.endswith("/src/lib.rs")
    )
    assert transformation_record.source_path == source_ref.logical_path == "app.py"
    assert transformation_record.source_sha256 == source_ref.sha256
    assert transformation_record.generated_rust == generated_ref
    assert transformation_record.function_qualname == function.qualname
    assert transformation_record.source_range.start_line == function.source_range.start.line  # type: ignore[union-attr]
    assert transformation_record.source_range.end_line == function.source_range.end.line  # type: ignore[union-attr]
    assert transformation_record.semantic_ast_sha256 == _sha(
        function.source_ast_fingerprint.encode("utf-8")  # type: ignore[union-attr]
    )

    provenance_inventory = prov["predicate"]["runDetails"]["metadata"][
        "rextio:source_transformation_inventory"
    ]
    assert provenance_inventory == transformation
    component_licenses = report["component_license_inventory"]
    assert component_licenses["kind"] == "component-license-inventory"
    assert component_licenses["scope"] == "reachable-cargo-packages"
    assert component_licenses["record_count"] == len(evidence.cargo_packages)
    assert any(record["kind"] == "path-root" for record in component_licenses["records"])
    provenance_metadata = prov["predicate"]["runDetails"]["metadata"]
    assert provenance_metadata["rextio:component_license_inventory"] == component_licenses
    assert provenance_metadata["rextio:component_license_inventory_observed"] is True

    runtime = report["native_runtime_inventory"]
    assert runtime["scope"] == "direct-only"
    assert runtime["transitive_closure"] is False
    assert runtime["runtime_dlopen"] is False
    assert runtime["dependency_count"] == 1
    dependency = runtime["dependencies"][0]
    path_resolution = report["native_runtime_path_resolution"]
    assert path_resolution["scope"] == "direct-native-dependencies"
    assert path_resolution["record_count"] == 1
    assert path_resolution["complete"] is False
    assert path_resolution["records"][0]["dependency_bom_ref"] == dependency["bom_ref"]
    assert provenance_metadata["rextio:native_runtime_path_resolution"] == path_resolution
    assert provenance_metadata["rextio:native_runtime_path_resolution_observed"] is True
    runtime_closure = report["native_runtime_transitive_closure"]
    assert runtime_closure["scope"] == "bounded-static-packaged-native-runtime-graph"
    assert runtime_closure["bounded_graph_observed"] is True
    assert runtime_closure["transitive_closure_complete"] is False
    assert runtime_closure["node_count"] == 2
    assert runtime_closure["edge_count"] == 1
    assert provenance_metadata["rextio:native_runtime_transitive_closure"] == runtime_closure
    assert (
        provenance_metadata["rextio:native_runtime_transitive_closure_observed"]
        is True
    )

    native_component = next(
        component
        for component in sbom["components"]
        if component["name"] == runtime["wheel_member"]
    )
    native_properties = {item["name"]: item["value"] for item in native_component["properties"]}
    assert native_properties["rextio:native_runtime_subject"] == "true"
    assert native_properties["rextio:linkage_scope"] == "direct-only"
    native_edge = next(
        edge for edge in sbom["dependencies"] if edge["ref"] == native_component["bom-ref"]
    )
    assert dependency["bom_ref"] in native_edge["dependsOn"]
    dependency_component = next(
        component
        for component in sbom["components"]
        if component["bom-ref"] == dependency["bom_ref"]
    )
    assert dependency_component["name"] == dependency["name"]

    internal = prov["predicate"]["buildDefinition"]["internalParameters"]
    assert internal["native_runtime_scope"] == "direct-only"
    assert internal["native_runtime_transitive_closure"] is False
    assert internal["native_runtime_dlopen"] is False
    assert internal["native_runtime_path_resolution_observed"] is True
    assert internal["native_runtime_path_resolution_complete"] is False
    assert internal["native_runtime_transitive_closure_observed"] is True
    assert internal["native_runtime_transitive_closure_complete"] is False
    assert internal["distribution_authorized"] is False
    assert internal["component_license_inventory_observed"] is True
    assert internal["component_license_policy_complete"] is False
    assert prov["predicate"]["runDetails"]["metadata"]["rextio:observed_native_runtime"] == runtime


def test_c69_snapshot_receipt_refresh_preserves_c68_and_c69(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")

    from rextio.build import runtime_closure, runtime_resolution
    from rextio.build import supply_chain as supply_chain_module
    from rextio.build.runtime_resolution import NativeRuntimePathResolutionObservation

    project, layout, old_wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    format_name = "mach-o" if "apple-darwin" in profile.target_triple else "elf"
    child_name = "libchild.dylib" if format_name == "mach-o" else "libchild.so"
    child_payload = b"synthetic packaged child"
    for root in (layout.python_dir, layout.build_python_dir):
        (root / child_name).write_bytes(child_payload)
    old_wheel_path.unlink()
    rebuilt = build_artifact_wheel(project, layout.build_python_dir, layout.dist_dir)
    assert rebuilt.status == "built" and rebuilt.path is not None
    wheel_path = Path(rebuilt.path)

    dependency = NativeRuntimeDependency(name=child_name, origin="wheel-candidate")

    def inspect_with_packaged_child(
        *,
        installed_path: Path | None,
        expected_python_root: Path,
        wheel_entries: tuple[WheelEntryRef, ...],
        target_triple: str,
        timeout: float,
    ) -> NativeRuntimeInventory:
        del timeout
        assert installed_path is not None
        binary = Path(installed_path).resolve(strict=True)
        member = binary.relative_to(expected_python_root.resolve(strict=True)).as_posix()
        entry = next(item for item in wheel_entries if item.name == member)
        digest, size = hash_regular_file(binary)
        arch = target_triple.split("-", 1)[0]
        architecture = "aarch64" if arch in {"aarch64", "arm64"} else "x86_64"
        return NativeRuntimeInventory(
            format=format_name,
            architecture=architecture,
            inspector="otool" if format_name == "mach-o" else "readelf",
            subject_basename=binary.name,
            subject_sha256=digest,
            subject_size=size,
            wheel_member=entry.name,
            wheel_member_sha256=entry.sha256,
            wheel_member_size=entry.uncompressed_size,
            dependencies=(dependency,),
        )

    captured: dict[str, object] = {}

    def resolve_with_packaged_receipt(
        *,
        expected_python_root: Path,
        wheel_entries: tuple[WheelEntryRef, ...],
        runtime_inventory: NativeRuntimeInventory,
        **_kwargs,
    ) -> NativeRuntimePathResolutionObservation:
        child_entry = next(item for item in wheel_entries if item.name == child_name)
        record = NativeRuntimePathResolutionRecord(
            dependency_bom_ref=dependency.bom_ref(),
            dependency_name=dependency.name,
            dependency_origin=dependency.origin,
            resolution="wheel-member",
            mechanism=(
                "macho-loader-path" if format_name == "mach-o" else "elf-origin-rpath"
            ),
            wheel_member=child_entry.name,
            sha256=child_entry.sha256,
            size=child_entry.uncompressed_size,
        )
        observation = NativeRuntimePathResolutionObservation(
            inventory=NativeRuntimePathResolutionInventory(
                subject_wheel_member=runtime_inventory.wheel_member,
                subject_sha256=runtime_inventory.subject_sha256,
                records=(record,),
            ),
            receipts=(
                runtime_resolution._read_candidate_secure(
                    root=expected_python_root.resolve(strict=True),
                    parts=(child_name,),
                ),
            ),
        )
        captured["before"] = observation
        return observation

    if format_name == "mach-o":
        inspector_output = (
            "/private/snapshot/libchild.dylib:\n"
            "Load command 0\n"
            "          cmd LC_LOAD_DYLIB\n"
            "      cmdsize 56\n"
            "         name /usr/lib/libSystem.B.dylib (offset 24)\n"
        )
    else:
        inspector_output = (
            "Dynamic section at offset 0x1000 contains 2 entries:\n"
            "  Tag        Type                         Name/Value\n"
            " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
            " 0x0000000000000000 (NULL) 0x0\n"
        )
    monkeypatch.setattr(
        runtime_closure,
        "_inspect_binary_header",
        lambda *_args, **_kwargs: SimpleNamespace(
            format=format_name,
            architecture=(
                "aarch64"
                if profile.target_triple.split("-", 1)[0] in {"aarch64", "arm64"}
                else "x86_64"
            ),
            macho_filetype=runtime_closure._MH_DYLIB,
        ),
    )
    monkeypatch.setattr(
        runtime_closure,
        "_run_resolution_inspector",
        lambda *_args, **_kwargs: inspector_output,
    )
    real_collect = runtime_closure.collect_native_runtime_transitive_closure

    def collect_and_reproduce(**kwargs):
        result = real_collect(**kwargs)
        assert result is not None
        before = captured["before"]
        assert isinstance(before, NativeRuntimePathResolutionObservation)
        assert not runtime_resolution.verify_native_runtime_path_resolution(
            before,
            expected_python_root=layout.python_dir,
        )
        captured["closure"] = result
        return result

    real_refresh = runtime_resolution.refresh_native_runtime_path_resolution_observation

    def refresh_and_capture(observation, *, expected_python_root: Path):
        result = real_refresh(observation, expected_python_root=expected_python_root)
        captured["refreshed"] = result
        return result

    monkeypatch.setattr(
        supply_chain_module,
        "inspect_native_runtime_inventory",
        inspect_with_packaged_child,
    )
    monkeypatch.setattr(
        supply_chain_module,
        "collect_native_runtime_path_resolution",
        resolve_with_packaged_receipt,
    )
    monkeypatch.setattr(
        supply_chain_module,
        "collect_native_runtime_transitive_closure",
        collect_and_reproduce,
    )
    monkeypatch.setattr(
        supply_chain_module,
        "refresh_native_runtime_path_resolution_observation",
        refresh_and_capture,
    )

    plan = _plan(project, profile, project / "app.py")
    snapshot = _snapshot(project, layout, plan)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert evidence.native_runtime_path_resolution is not None
    assert evidence.native_runtime_transitive_closure is not None
    refreshed = captured["refreshed"]
    assert isinstance(refreshed, NativeRuntimePathResolutionObservation)
    assert runtime_resolution.verify_native_runtime_path_resolution(
        refreshed,
        expected_python_root=layout.python_dir,
    )


def _assert_transformation_omission_is_noninterfering(
    *,
    project: Path,
    evidence,
) -> None:
    assert evidence.status == "preview-ready"
    assert evidence.source_transformation_inventory is None
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["source-transformation-inventory-bound"] == "unavailable"
    assert assessment["distribution_authorized"] is False
    assert ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE in assessment["blockers"]
    assert evidence.sbom is not None and (project / evidence.sbom.logical_path).is_file()
    assert evidence.provenance is not None
    provenance_path = project / evidence.provenance.logical_path
    assert provenance_path.is_file()
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    metadata = provenance["predicate"]["runDetails"]["metadata"]
    assert "rextio:source_transformation_inventory" not in metadata
    assert (
        provenance["predicate"]["buildDefinition"]["internalParameters"][
            "source_transformation_inventory_observed"
        ]
        is False
    )


def test_inventory_character_budget_omits_only_c6_6_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(
        project,
        profile,
        project / "app.py",
    )
    snapshot = _snapshot(project, layout, plan)
    monkeypatch.setattr(
        evidence_mod,
        "MAX_SOURCE_TRANSFORMATION_INVENTORY_CHARS",
        1,
    )

    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None
    _assert_transformation_omission_is_noninterfering(
        project=project,
        evidence=evidence,
    )


def test_provenance_ceiling_rebuilds_without_c6_6_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(
        project,
        profile,
        project / "app.py",
    )
    snapshot = _snapshot(project, layout, plan)
    real_builder = supply_chain_module.build_intoto_provenance_document
    inventory_presence: list[bool] = []

    def inflate_only_inventory_provenance(**kwargs):
        present = kwargs.get("source_transformation_inventory") is not None
        inventory_presence.append(present)
        document = real_builder(**kwargs)
        if present:
            document["predicate"]["runDetails"]["metadata"]["test:padding"] = (
                "x" * evidence_mod.MAX_SIDECAR_BYTES
            )
        return document

    monkeypatch.setattr(
        supply_chain_module,
        "build_intoto_provenance_document",
        inflate_only_inventory_provenance,
    )

    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None
    assert inventory_presence == [True, True, True, True, False]
    _assert_transformation_omission_is_noninterfering(
        project=project,
        evidence=evidence,
    )


def test_provenance_ceiling_omits_c6_7_before_preserving_c6_6(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(
        project,
        profile,
        project / "app.py",
    )
    snapshot = _snapshot(project, layout, plan)
    real_builder = supply_chain_module.build_intoto_provenance_document
    inventory_presence: list[tuple[bool, bool, bool]] = []

    def inflate_only_license_provenance(**kwargs):
        transformation_present = kwargs.get("source_transformation_inventory") is not None
        license_present = kwargs.get("component_license_inventory") is not None
        path_present = kwargs.get("native_runtime_path_resolution") is not None
        inventory_presence.append((path_present, transformation_present, license_present))
        document = real_builder(**kwargs)
        if license_present:
            document["predicate"]["runDetails"]["metadata"]["test:padding"] = (
                "x" * evidence_mod.MAX_SIDECAR_BYTES
            )
        return document

    monkeypatch.setattr(
        supply_chain_module,
        "build_intoto_provenance_document",
        inflate_only_license_provenance,
    )
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert inventory_presence == [
        (True, True, True),
        (True, True, True),
        (False, True, True),
        (False, True, False),
    ]
    assert evidence.native_runtime_path_resolution is None
    assert evidence.source_transformation_inventory is not None
    assert evidence.component_license_inventory is None
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["component-license-inventory-bound"] == "unavailable"
    assert ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE in assessment["blockers"]
    provenance_path = project / evidence.provenance.logical_path  # type: ignore[union-attr]
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    metadata = provenance["predicate"]["runDetails"]["metadata"]
    assert metadata["rextio:component_license_inventory_observed"] is False
    assert "rextio:component_license_inventory" not in metadata
    assert "rextio:source_transformation_inventory" in metadata


def test_provenance_ceiling_omits_c6_8_first_and_retains_c6_7_c6_6(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(project, profile, project / "app.py")
    snapshot = _snapshot(project, layout, plan)
    real_builder = supply_chain_module.build_intoto_provenance_document
    presence: list[tuple[bool, bool, bool]] = []

    def inflate_only_path_resolution(**kwargs):
        path_present = kwargs.get("native_runtime_path_resolution") is not None
        transformation_present = kwargs.get("source_transformation_inventory") is not None
        license_present = kwargs.get("component_license_inventory") is not None
        presence.append((path_present, transformation_present, license_present))
        document = real_builder(**kwargs)
        if path_present:
            document["predicate"]["runDetails"]["metadata"]["test:padding"] = (
                "x" * evidence_mod.MAX_SIDECAR_BYTES
            )
        return document

    monkeypatch.setattr(
        supply_chain_module,
        "build_intoto_provenance_document",
        inflate_only_path_resolution,
    )
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert presence == [
        (True, True, True),
        (True, True, True),
        (False, True, True),
    ]
    assert evidence.native_runtime_path_resolution is None
    assert evidence.native_runtime_transitive_closure is None
    assert evidence.source_transformation_inventory is not None
    assert evidence.component_license_inventory is not None
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["direct-native-path-resolution-bound"] == "unavailable"
    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["component-license-inventory-bound"] == "satisfied"
    assert ARTIFACT_AUTHORIZATION_RUNTIME_PATH_RESOLUTION_UNAVAILABLE in assessment[
        "blockers"
    ]


def test_provenance_ceiling_omits_c6_9_before_c6_8(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(project, profile, project / "app.py")
    snapshot = _snapshot(project, layout, plan)
    real_builder = supply_chain_module.build_intoto_provenance_document
    presence: list[tuple[bool, bool]] = []

    def inflate_only_runtime_graph(**kwargs):
        closure_present = kwargs.get("native_runtime_transitive_closure") is not None
        path_present = kwargs.get("native_runtime_path_resolution") is not None
        presence.append((closure_present, path_present))
        document = real_builder(**kwargs)
        if closure_present:
            document["predicate"]["runDetails"]["metadata"]["test:padding"] = (
                "x" * evidence_mod.MAX_SIDECAR_BYTES
            )
        return document

    monkeypatch.setattr(
        supply_chain_module,
        "build_intoto_provenance_document",
        inflate_only_runtime_graph,
    )
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert presence == [(True, True), (False, True)]
    assert evidence.native_runtime_transitive_closure is None
    assert evidence.native_runtime_path_resolution is not None
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["direct-native-path-resolution-bound"] == "satisfied"
    assert statuses["bounded-static-native-runtime-graph-bound"] == "unavailable"
    assert ARTIFACT_AUTHORIZATION_RUNTIME_CLOSURE_UNAVAILABLE in assessment["blockers"]


@pytest.mark.parametrize("failure_stage", ["collection", "final-verification"])
def test_c6_9_failure_retains_c6_8_direct_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(project, profile, project / "app.py")
    snapshot = _snapshot(project, layout, plan)
    real_refresh = (
        supply_chain_module.refresh_native_runtime_path_resolution_observation
    )
    refresh_calls = 0

    def track_refresh(observation, *, expected_python_root: Path):
        nonlocal refresh_calls
        refresh_calls += 1
        return real_refresh(
            observation,
            expected_python_root=expected_python_root,
        )

    monkeypatch.setattr(
        supply_chain_module,
        "refresh_native_runtime_path_resolution_observation",
        track_refresh,
    )
    if failure_stage == "collection":
        monkeypatch.setattr(
            supply_chain_module,
            "collect_native_runtime_transitive_closure",
            lambda **_kwargs: None,
        )
    else:
        monkeypatch.setattr(
            supply_chain_module,
            "verify_native_runtime_transitive_closure",
            lambda *_args, **_kwargs: False,
        )

    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert evidence.native_runtime_path_resolution is not None
    assert evidence.native_runtime_transitive_closure is None
    assert refresh_calls == 1
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["direct-native-path-resolution-bound"] == "satisfied"
    assert statuses["bounded-static-native-runtime-graph-bound"] == "unavailable"


@pytest.mark.parametrize(
    "failure_stage",
    ["collection", "post-c69-refresh", "final-verification"],
)
def test_c6_8_failure_omits_path_resolution_and_dependent_c6_9(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")
    from rextio.build import supply_chain as supply_chain_module

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan, _function = _plan_with_accepted_function(project, profile, project / "app.py")
    snapshot = _snapshot(project, layout, plan)
    if failure_stage == "collection":
        monkeypatch.setattr(
            supply_chain_module,
            "collect_native_runtime_path_resolution",
            lambda **_kwargs: None,
        )
    elif failure_stage == "post-c69-refresh":
        monkeypatch.setattr(
            supply_chain_module,
            "refresh_native_runtime_path_resolution_observation",
            lambda *_args, **_kwargs: None,
        )
    else:
        monkeypatch.setattr(
            supply_chain_module,
            "verify_native_runtime_path_resolution",
            lambda *_args, **_kwargs: False,
        )

    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snapshot,
    )

    assert evidence is not None and evidence.status == "preview-ready"
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"
    assert evidence.native_runtime_inventory is not None
    assert evidence.native_runtime_path_resolution is None
    assert evidence.native_runtime_transitive_closure is None
    assert evidence.source_transformation_inventory is not None
    assert evidence.component_license_inventory is not None
    assessment = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in assessment["checks"]}
    assert statuses["direct-native-linkage-observed"] == "satisfied"
    assert statuses["direct-native-path-resolution-bound"] == "unavailable"
    assert ARTIFACT_AUTHORIZATION_RUNTIME_PATH_RESOLUTION_UNAVAILABLE in assessment[
        "blockers"
    ]


def test_runtime_inspector_failure_is_best_effort_and_preserves_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    wheel_bytes = wheel_path.read_bytes()

    def fail_inspection(**_kwargs):
        raise sc.ArtifactEvidenceError(
            "synthetic inspector failure",
            reason=REASON_RUNTIME_INSPECTOR_FAILED,
        )

    monkeypatch.setattr(sc, "inspect_native_runtime_inventory", fail_inspection)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )

    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == REASON_RUNTIME_INSPECTOR_FAILED
    assert wheel_path.read_bytes() == wheel_bytes
    assert not list(layout.dist_dir.glob("*.cdx.json"))
    assert not list(layout.dist_dir.glob("*.intoto.json"))


def test_native_mutation_during_sidecar_emission_restores_exact_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    installed = layout.python_dir / "_rextio_native.so"
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")
    sbom_path.write_bytes(b"owner-sbom")
    provenance_path.write_bytes(b"owner-provenance")
    owner_sbom = layout.dist_dir / "owner.cdx.json"
    owner_provenance = layout.dist_dir / "owner.intoto.json"
    owner_sbom.write_bytes(b"owner-sbom")
    owner_provenance.write_bytes(b"owner-provenance")

    real_build_provenance = sc.build_intoto_provenance_document

    def mutate_then_build_provenance(**kwargs):
        installed.write_bytes(b"mutated after runtime inventory")
        return real_build_provenance(**kwargs)

    monkeypatch.setattr(sc, "build_intoto_provenance_document", mutate_then_build_provenance)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )

    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == sc.REASON_RUNTIME_BINARY_MISMATCH
    assert sbom_path.read_bytes() == b"owner-sbom"
    assert provenance_path.read_bytes() == b"owner-provenance"
    assert owner_sbom.read_bytes() == b"owner-sbom"
    assert owner_provenance.read_bytes() == b"owner-provenance"


def test_sidecar_preserve_records_recovery_before_post_rename_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "dist"
    parent.mkdir()
    output = parent / "artifact.cdx.json"
    output.write_bytes(b"owner-sidecar")
    transaction = evidence_mod.SidecarWriteTransaction.prepare(
        (output,), project_root=tmp_path, expected_parent=parent
    )
    transaction.write(output, b"new-sidecar")
    real_matches = evidence_mod._receipt_matches_at
    failed = False

    def fail_first_backup_inspection(dir_fd: int, name: str, receipt) -> bool:
        nonlocal failed
        if name == "0" and not failed:
            failed = True
            raise evidence_mod.ArtifactEvidenceError(
                "synthetic post-rename inspection failure",
                reason="sidecar-write-failed",
            )
        return real_matches(dir_fd, name, receipt)

    monkeypatch.setattr(evidence_mod, "_receipt_matches_at", fail_first_backup_inspection)

    with pytest.raises(evidence_mod.ArtifactEvidenceError):
        transaction.commit()
    assert transaction.rollback() is True
    assert output.read_bytes() == b"owner-sidecar"
    assert not transaction._backup_path.exists()


def test_sidecar_rollback_quarantines_before_receipt_and_preserves_racing_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "dist"
    parent.mkdir()
    output = parent / "artifact.cdx.json"
    transaction = evidence_mod.SidecarWriteTransaction.prepare(
        (output,), project_root=tmp_path, expected_parent=parent
    )
    transaction.write(output, b"transaction-sidecar")
    with pytest.raises(RuntimeError, match="stop after publication"):
        transaction.commit(
            claim_sink=lambda _claims: (_ for _ in ()).throw(RuntimeError("stop after publication"))
        )
    real_matches = evidence_mod._receipt_matches_at
    raced = False

    def race_after_receipt(dir_fd: int, name: str, receipt) -> bool:
        nonlocal raced
        matches = real_matches(dir_fd, name, receipt)
        if matches and not raced:
            raced = True
            replacement = parent / ".concurrent-sidecar"
            replacement.write_bytes(b"concurrent-owner-sidecar")
            os.replace(replacement, output)
        return matches

    monkeypatch.setattr(evidence_mod, "_receipt_matches_at", race_after_receipt)
    complete = transaction.rollback()

    assert raced is True
    assert complete is False
    assert output.read_bytes() == b"concurrent-owner-sidecar"


def test_sidecar_stage_cleanup_quarantines_before_receipt_and_preserves_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "dist"
    parent.mkdir()
    output = parent / "artifact.cdx.json"
    transaction = evidence_mod.SidecarWriteTransaction.prepare(
        (output,), project_root=tmp_path, expected_parent=parent
    )
    transaction.write(output, b"transaction-sidecar")
    stage_name = transaction._staged[0][0]
    stage_path = parent / stage_name
    real_matches = evidence_mod._receipt_matches_at
    raced = False

    def race_after_receipt(dir_fd: int, name: str, receipt) -> bool:
        nonlocal raced
        matches = real_matches(dir_fd, name, receipt)
        if matches and not raced:
            raced = True
            replacement = parent / ".concurrent-stage"
            replacement.write_bytes(b"concurrent-owner-stage")
            os.replace(replacement, stage_path)
        return matches

    monkeypatch.setattr(evidence_mod, "_receipt_matches_at", race_after_receipt)
    complete = transaction.rollback()

    assert raced is True
    assert complete is False
    assert stage_path.read_bytes() == b"concurrent-owner-stage"


def test_native_mutation_during_sidecar_emission_removes_only_new_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    installed = layout.python_dir / "_rextio_native.so"
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")

    real_build_provenance = sc.build_intoto_provenance_document

    def mutate_then_build_provenance(**kwargs):
        installed.write_bytes(b"mutated after runtime inventory")
        return real_build_provenance(**kwargs)

    monkeypatch.setattr(sc, "build_intoto_provenance_document", mutate_then_build_provenance)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )

    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == sc.REASON_RUNTIME_BINARY_MISMATCH
    assert not sbom_path.exists()
    assert not provenance_path.exists()


def test_prewrite_failure_preserves_preexisting_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")
    sbom_path.write_bytes(b"owner-sbom")
    provenance_path.write_bytes(b"owner-provenance")

    def fail_before_write(*_args, **_kwargs):
        raise sc.ArtifactEvidenceError("cargo inventory failed", reason="cargo-metadata-failed")

    monkeypatch.setattr(sc, "resolve_cargo_inventory", fail_before_write)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "cargo-metadata-failed"
    assert sbom_path.read_bytes() == b"owner-sbom"
    assert provenance_path.read_bytes() == b"owner-provenance"


def test_late_failure_cleans_written_sidecar_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc
    from rextio.build.cargo_inventory import CargoInventory

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)
    sbom_path = wheel_path.with_suffix(wheel_path.suffix + ".cdx.json")
    provenance_path = wheel_path.with_suffix(wheel_path.suffix + ".intoto.json")
    sbom_path.write_bytes(b"owner-sbom")
    provenance_path.write_bytes(b"owner-provenance")
    inventory = CargoInventory(
        target_triple=profile.target_triple,
        root_package="rextio_generated_native",
        packages=(),
        dependencies=(),
        lockfile_present=True,
    )
    monkeypatch.setattr(sc, "resolve_cargo_inventory", lambda *_a, **_k: inventory)

    def fail_after_sbom(**_kwargs):
        raise sc.ArtifactEvidenceError(
            "provenance construction failed", reason="evidence-internal-error"
        )

    monkeypatch.setattr(sc, "build_intoto_provenance_document", fail_after_sbom)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "evidence-internal-error"
    assert sbom_path.read_bytes() == b"owner-sbom"
    assert provenance_path.read_bytes() == b"owner-provenance"


def test_transaction_rollback_failure_cannot_escape_evidence_emission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)

    def fail_commit(*_args, **_kwargs) -> None:
        raise sc.ArtifactEvidenceError("sidecar commit failed", reason="sidecar-write-failed")

    def fail_rollback(*_args, **_kwargs) -> bool:
        raise OSError("rollback must not escape")

    monkeypatch.setattr(sc.SidecarWriteTransaction, "commit", fail_commit)
    monkeypatch.setattr(sc.SidecarWriteTransaction, "rollback", fail_rollback)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "sidecar-write-failed"
    assert wheel_path.is_file()


def test_illegal_logical_path_segment_marks_unavailable_not_crash(tmp_path: Path) -> None:
    """SourceModule-legal paths that fail evidence path rules must not abort builds."""
    project = tmp_path / "project"
    project.mkdir()
    # Space is legal for SourceModule relative paths but illegal for evidence
    # logical references (strict segment charset).
    source = project / "my file.py"
    source.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    source_bytes = source.read_bytes()
    module = SourceModule(
        module_name="my_file",
        path="my file.py",
        is_package_init=False,
        source_origin=SourceOrigin.PROJECT,
        sha256=_sha(source_bytes),
        dependency_depth=0,
    )
    graph = SourceModuleGraph(modules=(module,))
    host_plan = HostSourcePlan(graph=graph, module_initializers=(), unavailable_reason=None)
    plan = BuildPlan(
        analysis=ProjectAnalysis(
            project_root=project,
            modules=[ModuleAnalysis(module_name="my_file", file_path=str(source))],
        ),
        native=NativePlan(accepted_functions=(), rejected_functions=()),
        fallback=FallbackPlan(backend="cpython", modules=()),
        host_source_plan=host_plan,
        artifact_profiles=(host_extension_profile(detect_host_target_triple()),),
    )
    snap = capture_project_source_snapshot(project_root=project, plan=plan)
    assert snap.unavailable_reason == "source-input-unreadable"
    layout = ArtifactLayout(project)
    layout.dist_dir.mkdir(parents=True)
    wheel_path = layout.dist_dir / "demo-0.1.0-py3-none-any.whl"
    # Minimal valid ZIP wheel for inventory/hash paths if emit proceeds.
    import zipfile

    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr("demo/__init__.py", b"")
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "source-input-unreadable"


def test_host_extension_kind_is_required() -> None:
    assert ArtifactKind.HOST_EXTENSION.value == "host-extension"


def test_wheel_mutation_after_snapshot_marks_unavailable(tmp_path: Path, monkeypatch) -> None:
    """Wheel digest/size change after snapshot must yield wheel-bytes-mutated."""
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")

    from rextio.artifacts import evidence as evidence_mod
    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)

    real_hash = evidence_mod.hash_regular_file
    call_count = {"n": 0}

    def flaky_hash(path, *, max_bytes=evidence_mod.MAX_EVIDENCE_FILE_BYTES):
        # load_wheel_snapshot does not use hash_regular_file; the first hash of
        # the wheel is the final confirmation re-read — flip it to simulate mutation.
        digest, size = real_hash(path, max_bytes=max_bytes)
        if Path(path).resolve() == wheel_path.resolve():
            call_count["n"] += 1
            return ("f" * 64, size)
        return digest, size

    monkeypatch.setattr(sc, "hash_regular_file", flaky_hash)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "wheel-bytes-mutated"
    # Partial sidecars must be cleaned up.
    assert not list(layout.dist_dir.glob("*.cdx.json"))
    assert not list(layout.dist_dir.glob("*.intoto.json"))


def test_input_mutation_after_cargo_marks_unavailable(tmp_path: Path, monkeypatch) -> None:
    """Inputs mutated after cargo metadata must fail re-verify before sidecars."""
    cargo = pytest.importorskip("shutil").which("cargo")
    if cargo is None:
        pytest.skip("cargo is required")

    from rextio.build import supply_chain as sc

    project, layout, wheel_path = _write_project_with_generated_tree(tmp_path)
    profile = host_extension_profile(detect_host_target_triple())
    plan = _plan(project, profile, project / "app.py")
    snap = _snapshot(project, layout, plan)

    real_resolve = sc.resolve_cargo_inventory

    def mutate_then_resolve(*args, **kwargs):
        inv = real_resolve(*args, **kwargs)
        # Mutate a captured project input after cargo returns.
        (project / "app.py").write_text(
            "def add(a: int, b: int) -> int:\n    return a - b\n",
            encoding="utf-8",
        )
        return inv

    monkeypatch.setattr(sc, "resolve_cargo_inventory", mutate_then_resolve)
    evidence = emit_host_extension_wheel_evidence(
        project_root=project,
        layout=layout,
        plan=plan,
        wheel_build=WheelBuildResult(status="built", path=str(wheel_path), message="ok"),
        native_build=_built_native(layout),
        input_snapshot=snap,
    )
    assert evidence is not None
    assert evidence.status == "unavailable"
    assert evidence.reason == "source-snapshot-mismatch"
    assert not list(layout.dist_dir.glob("*.cdx.json"))


def test_bounded_py_walk_counts_entries_before_sort(tmp_path: Path) -> None:
    from rextio.build import supply_chain as sc

    root = tmp_path / "py"
    root.mkdir()
    # Direct unit: max_files=2 with 3 .py files must exceed.
    for i in range(3):
        (root / f"f{i:02d}.py").write_text(f"x = {i}\n", encoding="utf-8")
    walked = sc._bounded_py_walk(root, max_files=2)
    assert walked == "input-count-exceeded"

    # Overflow of children before sort: max_files=1 => max_children_per_dir=64.
    bulk = tmp_path / "bulk"
    bulk.mkdir()
    for i in range(300):
        (bulk / f"n{i}.txt").write_text("x", encoding="utf-8")
    walked2 = sc._bounded_py_walk(bulk, max_files=1)
    assert walked2 == "input-count-exceeded"
