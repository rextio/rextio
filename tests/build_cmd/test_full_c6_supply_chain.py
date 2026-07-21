"""Adversarial tests for complete Full C6 SBOM and provenance evidence."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import runpy
import stat

import pytest

import rextio.build.full_c6_supply_chain as supply_chain_module
from rextio.artifacts.evidence import EvidenceFileRef, WheelEntryRef, canonical_json_bytes
from rextio.build.full_c6_policy import FULL_C6_POLICY_CLASS_IDS, FullC6PolicyReceipt
from rextio.build.full_c6_supply_chain import (
    FULL_C6_BUILD_TYPE,
    FullC6CargoPathSource,
    FullC6SupplyChainError,
    build_full_c6_supply_chain_receipt,
    validate_full_c6_cargo_input_aggregates,
    validate_full_c6_supply_chain_document,
    verify_full_c6_supply_chain_receipt,
)
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
)
from rextio.build.input_closure import (
    FULL_C6_CARGO_INPUT_AGGREGATE_IDS,
    BuildInputAggregateIdentity,
    BuildInputClosure,
    ExactFileIdentity,
    bind_full_c6_cargo_workspace_aggregates,
)
from rextio.build.reproducibility import (
    ReproducibilityBuildReceipt,
    ReproducibilityReceipt,
)
from rextio.build.runtime_authorization import (
    RUNTIME_VERIFICATION_NATIVE_FRESH,
    RuntimeAuthorizationReceipt,
    RuntimeLoadedImage,
)
from rextio.build.toolchain_identity import (
    ArgvIdentity,
    BuildToolchainIdentity,
    CargoSourceIdentity,
    CargoSourcesIdentity,
    RextioIdentity,
    ToolIdentity,
)
from rextio.source.source_lock_v2 import (
    SourceLockV2Admission,
    SourceLockV2AnalysisIdentity,
    SourceLockV2FunctionIdentity,
    SourceLockV2Manifest,
)
from rextio.source.wheel_authority import (
    SourceWheelArchiveIdentity,
    SourceWheelEntryIdentity,
)
TARGET = "x86_64-unknown-linux-gnu"
_POLICY_FIXTURES = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_policy.py"))
)
_INPUT_FIXTURES = runpy.run_path(
    str(Path(__file__).with_name("test_build_input_closure.py"))
)


def _policy_receipt() -> FullC6PolicyReceipt:
    value = _POLICY_FIXTURES["_receipt"]()  # type: ignore[operator]
    assert isinstance(value, FullC6PolicyReceipt)
    return value


def _row(policy: FullC6PolicyReceipt, class_id: str):
    matches = tuple(item for item in policy.rows if item.class_id == class_id)
    assert len(matches) == 1
    return matches[0]


def _exact_file(
    logical_name: str,
    sha256: str,
    size: int,
    *,
    role: str,
    executable: bool = False,
) -> ExactFileIdentity:
    return ExactFileIdentity(logical_name, role, sha256, size, executable)


def _build_inputs(policy: FullC6PolicyReceipt) -> BuildInputClosure:
    files = tuple(
        sorted(
            (
                _exact_file(
                    item.canonical_identity,
                    item.sha256 or "",
                    item.size if item.size is not None else 0,
                    role="build-input",
                )
                for item in policy.rows
                if item.class_id.startswith("file-input:")
            ),
            key=lambda item: (item.role, item.logical_name),
        )
    )
    return BuildInputClosure(files=files)


def _sealed_cargo_workspace(
    tmp_path: Path,
) -> FullC6CargoDependencyWorkspaceReceipt:
    value = _INPUT_FIXTURES["_sealed_cargo_workspace"](tmp_path)  # type: ignore[operator]
    assert isinstance(value, FullC6CargoDependencyWorkspaceReceipt)
    return value


def _authority_aggregate(
    **changes: object,
) -> supply_chain_module.FullC6AuthorityAggregateBinding:
    values: dict[str, object] = {
        field: f"{index:x}" * 64
        for index, field in enumerate(
            supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS,
            start=1,
        )
    }
    values.update(changes)
    return supply_chain_module.FullC6AuthorityAggregateBinding(  # type: ignore[arg-type]
        **values
    )


def _tool(
    name: str,
    digest: str,
    *,
    version: str,
) -> ToolIdentity:
    return ToolIdentity(
        name=name,
        executable=_exact_file(
            f"toolchain/{name}",
            digest,
            200,
            role="toolchain-executable",
            executable=True,
        ),
        reported_version=version,
    )


def _toolchain(policy: FullC6PolicyReceipt) -> BuildToolchainIdentity:
    lock = _row(policy, "file-input:generated-cargo-lock")
    registry = _row(policy, "cargo-component:registry-package")
    return BuildToolchainIdentity(
        python=_tool("python", "1" * 64, version="3.11.9"),
        rextio=RextioIdentity(
            version="0.1.4",
            files=(
                _exact_file(
                    "rextio/__init__.py",
                    "2" * 64,
                    120,
                    role="rextio-python-source",
                ),
            ),
            content_digest="3" * 64,
        ),
        cargo=_tool("cargo", "4" * 64, version="1.90.0"),
        rustc=_tool("rustc", "5" * 64, version="1.90.0"),
        linker=_tool("linker", "6" * 64, version="GNU-2.42"),
        inspectors=(_tool("readelf", "7" * 64, version="GNU-2.42"),),
        argv=ArgvIdentity(
            values=("cargo", "build", "--locked", "--offline", "--frozen")
        ),
        environment=(),
        cargo_sources=CargoSourcesIdentity(
            root_package="rextio-generated",
            lock_file=_exact_file(
                lock.canonical_identity,
                lock.sha256 or "",
                lock.size if lock.size is not None else 0,
                role="cargo-lockfile",
            ),
            packages=(
                CargoSourceIdentity(
                    name="serde",
                    version="1.0.0",
                    source="registry+https://github.com/rust-lang/crates.io-index",
                    checksum=registry.sha256 or "",
                ),
            ),
        ),
    )


def _source_lock(
    policy: FullC6PolicyReceipt,
) -> tuple[SourceLockV2Manifest, SourceLockV2Admission]:
    archive_row = _row(policy, "external-source:wheel-archive")
    source_row = _row(policy, "external-source:python-source")
    metadata_row = _row(policy, "external-source:distribution-metadata")
    license_row = _row(policy, "external-source:license-file")
    archive = SourceWheelArchiveIdentity(
        filename="pkg-1.0-py3-none-any.whl",
        sha256=archive_row.sha256 or "",
        size=archive_row.size if archive_row.size is not None else 0,
    )
    rows_and_paths = (
        (source_row, "pkg/__init__.py"),
        (metadata_row, "pkg-1.0.dist-info/METADATA"),
        (license_row, "pkg-1.0.dist-info/licenses/LICENSE"),
    )
    entries = tuple(
        sorted(
            (
                SourceWheelEntryIdentity(
                    path=path,
                    sha256=row.sha256 or "",
                    size=row.size if row.size is not None else 0,
                    compressed_size=50,
                    crc32=f"{index:08x}",
                    unix_mode=stat.S_IFREG | 0o644,
                )
                for index, (row, path) in enumerate(rows_and_paths, start=1)
            ),
            key=lambda item: item.path,
        )
    )
    manifest = SourceLockV2Manifest(
        package="pkg",
        distribution="pkg",
        version="1.0",
        plan_snapshot_sha256="8" * 64,
        wheel_authority_sha256="9" * 64,
        archive=archive,
        entries=entries,
        analyses=(
            SourceLockV2AnalysisIdentity(
                module_name="pkg",
                source_sha256=source_row.sha256 or "",
                semantic_sha256="a" * 64,
                functions=(
                    SourceLockV2FunctionIdentity(
                        qualname="pkg.affine",
                        semantic_ast_sha256="b" * 64,
                        lowered_ir_sha256="c" * 64,
                    ),
                ),
            ),
        ),
        declared_license="MIT",
        observed_license="MIT",
        license_material_sha256="d" * 64,
        license_evidence_sha256="e" * 64,
        owner="Acme Engineering",
        allow=True,
        redistribute=True,
        transform=True,
        trusted_public_key_sha256="f" * 64,
    )
    admission = SourceLockV2Admission(
        status="admitted",
        reason="signature-verified",
        manifest_sha256=manifest.manifest_sha256,
        public_key_sha256=manifest.trusted_public_key_sha256,
        signature_sha256="0" * 64,
        prebuild_admitted=True,
    )
    return manifest, admission


def _wheel_entries(policy: FullC6PolicyReceipt) -> tuple[WheelEntryRef, ...]:
    native = _row(policy, "wheel-entry:packaged-native-runtime-member")
    other = _row(policy, "wheel-entry:other")
    return (
        WheelEntryRef(
            name="pkg/__init__.py",
            sha256=other.sha256 or "",
            compressed_size=50,
            uncompressed_size=other.size if other.size is not None else 0,
        ),
        WheelEntryRef(
            name="rextio/libnative.so",
            sha256=native.sha256 or "",
            compressed_size=50,
            uncompressed_size=native.size if native.size is not None else 0,
        ),
    )


def _runtime(policy: FullC6PolicyReceipt) -> RuntimeAuthorizationReceipt:
    native = _row(policy, "wheel-entry:packaged-native-runtime-member")
    system = RuntimeLoadedImage(
        path="/usr/lib/libc.so.6",
        device=1,
        inode=2,
        sha256="d" * 64,
        size=4096,
    )
    return RuntimeAuthorizationReceipt(
        target_triple=TARGET,
        extension=RuntimeLoadedImage(
            path="/opt/rextio/libnative.so",
            device=1,
            inode=1,
            sha256=native.sha256 or "",
            size=native.size if native.size is not None else 0,
        ),
        platform_base_sha256="1" * 64,
        declared_system_images=(system,),
        declared_system_platform_images=(),
        newly_loaded_images=(system,),
        newly_loaded_platform_images=(),
        path_resolution_sha256="2" * 64,
        transitive_closure_sha256="3" * 64,
        load_commands_sha256="4" * 64,
        imported_symbols_sha256="5" * 64,
        final_snapshot_sha256="6" * 64,
        verification_mode=RUNTIME_VERIFICATION_NATIVE_FRESH,
    )


def _reproducibility(policy: FullC6PolicyReceipt) -> ReproducibilityReceipt:
    subject = _row(policy, "wheel-output:subject")

    def build(ordinal: int) -> ReproducibilityBuildReceipt:
        return ReproducibilityBuildReceipt(
            ordinal=ordinal,
            unsigned_wheel=_exact_file(
                f"build-{ordinal}/unsigned-wheel.whl",
                subject.sha256 or "",
                subject.size if subject.size is not None else 0,
                role="unsigned-wheel",
            ),
            sbom_json=_exact_file(
                f"build-{ordinal}/sbom.json",
                "6" * 64,
                100,
                role="sbom-json",
            ),
            provenance_input_json=_exact_file(
                f"build-{ordinal}/provenance-input.json",
                "7" * 64,
                100,
                role="provenance-input-json",
            ),
            sbom_canonical_sha256="8" * 64,
            provenance_input_canonical_sha256="9" * 64,
        )

    return ReproducibilityReceipt(builds=(build(1), build(2)))


def _policy_without_stub() -> FullC6PolicyReceipt:
    rows, transformations, coverage, external = _POLICY_FIXTURES["_fixture"](  # type: ignore[operator]
        zero_artifact=frozenset({"file-input:present-project-python-stub"})
    )
    return FullC6PolicyReceipt(
        rows=rows,
        transformations=transformations,
        owner_declaration=_POLICY_FIXTURES["_owner"](),  # type: ignore[operator]
        artifact_coverage=coverage,
        external_authority=external,
    )


def _policy_with_system_identity(identity: str) -> FullC6PolicyReceipt:
    original = _policy_receipt()
    rows = tuple(
        replace(item, canonical_identity=identity)
        if item.class_id == "native-runtime:logical-system-leaf"
        else item
        for item in original.rows
    )
    return FullC6PolicyReceipt(
        rows=rows,
        transformations=original.transformations,
        owner_declaration=original.owner_declaration,
        artifact_coverage=original.artifact_coverage,
        external_authority=original.external_authority,
    )


def _arguments(policy: FullC6PolicyReceipt | None = None) -> dict[str, object]:
    selected = policy or _policy_receipt()
    subject_row = _row(selected, "wheel-output:subject")
    source_lock, source_admission = _source_lock(selected)
    root = _row(selected, "cargo-component:path-root-package")
    runtime = _runtime(selected)
    return {
        "target_triple": TARGET,
        "subject": EvidenceFileRef(
            logical_path=subject_row.canonical_identity,
            sha256=subject_row.sha256 or "",
            size=subject_row.size if subject_row.size is not None else 0,
            role="host-extension-wheel",
        ),
        "build_inputs": _build_inputs(selected),
        "wheel_entries": _wheel_entries(selected),
        "policy": selected,
        "source_lock": source_lock,
        "source_admission": source_admission,
        "toolchain": _toolchain(selected),
        "cargo_path_source": FullC6CargoPathSource(
            name="rextio-generated",
            version="0.1.4",
            source_tree_sha256=root.sha256 or "",
        ),
        "runtime_authorization": runtime,
        "reproducibility": _reproducibility(selected),
        "authority_aggregate": _authority_aggregate(
            runtime_authorization_sha256=runtime.digest,
        ),
    }


def _aggregate_arguments(
    tmp_path: Path,
) -> tuple[dict[str, object], FullC6CargoDependencyWorkspaceReceipt]:
    arguments = _arguments()
    build_inputs = arguments["build_inputs"]
    assert isinstance(build_inputs, BuildInputClosure)
    workspace = _sealed_cargo_workspace(tmp_path)
    bound = bind_full_c6_cargo_workspace_aggregates(build_inputs, workspace)
    authority_aggregate = arguments["authority_aggregate"]
    assert isinstance(
        authority_aggregate,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    return (
        {
            **arguments,
            "build_inputs": bound,
            "cargo_dependency_workspace": workspace,
            "authority_aggregate": replace(
                authority_aggregate,
                cargo_workspace_sha256=workspace.digest,
            ),
        },
        workspace,
    )


def test_authority_aggregate_binding_is_closed_ordered_and_non_authorizing() -> None:
    assert hasattr(supply_chain_module, "FullC6AuthorityAggregateBinding")
    assert hasattr(
        supply_chain_module,
        "FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS",
    )
    binding = _authority_aggregate()
    public = binding.to_dict()

    assert tuple(public) == (
        "domain",
        "schema_version",
        "bindings",
        "complete_for_scope",
        "distribution_authorized",
        "digest",
    )
    bindings = public["bindings"]
    assert isinstance(bindings, dict)
    assert tuple(bindings) == (
        supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
    )
    assert all(
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        for value in bindings.values()
    )
    assert public["complete_for_scope"] is True
    assert public["distribution_authorized"] is False
    assert binding.distribution_authorized is False

    with pytest.raises(FullC6SupplyChainError, match="lowercase SHA-256"):
        _authority_aggregate(analysis_ir_transaction_sha256="A" * 64)
    with pytest.raises(FullC6SupplyChainError, match="lowercase SHA-256"):
        _authority_aggregate(analysis_ir_transaction_sha256="a" * 63)


def test_complete_documents_are_canonical_deterministic_and_non_authorizing() -> None:
    arguments = _arguments()
    first = build_full_c6_supply_chain_receipt(**arguments)  # type: ignore[arg-type]
    second = build_full_c6_supply_chain_receipt(**arguments)  # type: ignore[arg-type]

    assert first == second
    assert first.sbom_json == second.sbom_json
    assert first.provenance_json == second.provenance_json
    assert first.complete_for_scope is True
    assert first.distribution_authorized is False
    assert first.to_dict()["signed"] is False
    assert first.authority_aggregate == arguments["authority_aggregate"]
    assert len(first.sbom_sha256) == len(first.provenance_sha256) == 64
    assert canonical_json_bytes(json.loads(first.sbom_json)) == first.sbom_json
    assert canonical_json_bytes(json.loads(first.provenance_json)) == first.provenance_json

    sbom = validate_full_c6_supply_chain_document(first.sbom_json, document_kind="sbom")
    provenance = validate_full_c6_supply_chain_document(
        first.provenance_json,
        document_kind="provenance",
    )
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    reproducibility = arguments["reproducibility"]
    assert isinstance(reproducibility, ReproducibilityReceipt)
    assert first.reproducible_sbom_input_sha256 == (
        reproducibility.sbom_canonical_sha256
    )
    assert first.reproducible_provenance_input_sha256 == (
        reproducibility.provenance_input_canonical_sha256
    )
    properties = {
        item["name"]: item["value"]
        for item in sbom["metadata"]["properties"]  # type: ignore[index]
    }
    authority = first.authority_aggregate
    assert properties["rextio:authority_aggregate_sha256"] == authority.digest
    for field in supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS:
        assert properties[f"rextio:{field}"] == getattr(authority, field)
    assert properties["rextio:reproducible_sbom_input_sha256"] == (
        reproducibility.sbom_canonical_sha256
    )
    assert properties["rextio:reproducible_provenance_input_sha256"] == (
        reproducibility.provenance_input_canonical_sha256
    )
    assert sbom["compositions"] == [
        {
            "aggregate": "complete",
            "assemblies": [f"urn:rextio:full-c6-wheel:{first.subject.sha256}"],
        }
    ]
    assert [item.class_id for item in first.partition] == list(
        FULL_C6_POLICY_CLASS_IDS
    )
    assert all(item.identities for item in first.partition)
    assert provenance["_type"] == "https://in-toto.io/Statement/v1"
    assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    assert provenance["predicate"]["buildDefinition"]["buildType"] == FULL_C6_BUILD_TYPE  # type: ignore[index]
    assert provenance["predicate"]["buildDefinition"]["internalParameters"][  # type: ignore[index]
        "reproducibility_input_projection"
    ] == {
        "sbom_canonical_sha256": reproducibility.sbom_canonical_sha256,
        "provenance_input_canonical_sha256": (
            reproducibility.provenance_input_canonical_sha256
        ),
    }
    receipt_bindings = provenance["predicate"]["buildDefinition"][  # type: ignore[index]
        "internalParameters"
    ]["receipt_bindings"]
    assert receipt_bindings["full-c6-authority-aggregate"] == authority.digest
    assert {
        name: receipt_bindings[name]
        for name in supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES
    } == dict(
        zip(
            supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES,
            (
                getattr(authority, field)
                for field in supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
            ),
            strict=True,
        )
    )
    metadata = provenance["predicate"]["runDetails"]["metadata"]  # type: ignore[index]
    assert metadata["rextio:authority_aggregate"] == authority.to_dict()
    # These are explicit preauthorization/input projections, not hashes of the
    # final self-referential documents.  Equality is intentionally not claimed.
    assert first.reproducible_sbom_input_sha256 != first.sbom_sha256
    assert first.reproducible_provenance_input_sha256 != first.provenance_sha256
    assert provenance["subject"][1]["digest"] == {"sha256": first.sbom_sha256}  # type: ignore[index]
    assert verify_full_c6_supply_chain_receipt(first) == first


def test_authority_aggregate_is_mandatory_and_workspace_runtime_drift_fails_closed(
    tmp_path: Path,
) -> None:
    arguments = _arguments()
    omitted = dict(arguments)
    omitted.pop("authority_aggregate")
    with pytest.raises(TypeError, match="authority_aggregate"):
        build_full_c6_supply_chain_receipt(**omitted)  # type: ignore[arg-type]

    binding = arguments["authority_aggregate"]
    assert isinstance(
        binding,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    with pytest.raises(FullC6SupplyChainError, match="runtime authorization"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{
                **arguments,
                "authority_aggregate": replace(
                    binding,
                    runtime_authorization_sha256="f" * 64,
                ),
            }
        )

    aggregate_arguments, workspace = _aggregate_arguments(tmp_path)
    aggregate_binding = aggregate_arguments["authority_aggregate"]
    assert isinstance(
        aggregate_binding,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    with pytest.raises(FullC6SupplyChainError, match="Cargo workspace"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{
                **aggregate_arguments,
                "authority_aggregate": replace(
                    aggregate_binding,
                    cargo_workspace_sha256="f" * 64,
                ),
                "cargo_dependency_workspace": workspace,
            }
        )


def test_authority_aggregate_document_omission_duplicate_drift_and_json_tamper_fail_closed() -> None:
    receipt = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **_arguments()
    )
    binding_names = set(
        supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES
    )

    sbom = json.loads(receipt.sbom_json)
    components = sbom["components"]
    authority_component = next(
        item for item in components if item["name"] in binding_names
    )

    omitted = dict(sbom)
    omitted["components"] = [
        item for item in components if item is not authority_component
    ]
    with pytest.raises(FullC6SupplyChainError, match="authority aggregate"):
        replace(receipt, sbom_json=canonical_json_bytes(omitted))

    duplicated = dict(sbom)
    duplicated["components"] = [*components, authority_component]
    with pytest.raises(FullC6SupplyChainError, match="authority aggregate"):
        replace(receipt, sbom_json=canonical_json_bytes(duplicated))

    drifted = json.loads(receipt.provenance_json)
    parameters = drifted["predicate"]["buildDefinition"]["internalParameters"]
    parameters["receipt_bindings"][
        supply_chain_module.FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES[0]
    ] = (
        "f" * 64
    )
    with pytest.raises(FullC6SupplyChainError, match="provenance"):
        replace(receipt, provenance_json=canonical_json_bytes(drifted))

    duplicate_key = receipt.sbom_json.replace(
        b'"bomFormat":"CycloneDX"',
        b'"bomFormat":"CycloneDX","bomFormat":"CycloneDX"',
        1,
    )
    with pytest.raises(FullC6SupplyChainError, match="duplicate object key"):
        validate_full_c6_supply_chain_document(duplicate_key, document_kind="sbom")


def test_cargo_aggregate_receipt_round_trip_binds_safe_document_materials(
    tmp_path: Path,
) -> None:
    arguments, workspace = _aggregate_arguments(tmp_path)
    build_inputs = arguments["build_inputs"]
    assert isinstance(build_inputs, BuildInputClosure)

    trusted = validate_full_c6_cargo_input_aggregates(build_inputs, workspace)
    untrusted_arguments = dict(arguments)
    untrusted_arguments.pop("cargo_dependency_workspace")
    with pytest.raises(FullC6SupplyChainError, match="process-sealed Cargo workspace"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **untrusted_arguments
        )
    receipt = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **arguments
    )

    assert trusted == build_inputs
    assert receipt.cargo_input_aggregates == build_inputs.aggregates
    assert tuple(item.aggregate_id for item in receipt.cargo_input_aggregates) == (
        tuple(sorted(FULL_C6_CARGO_INPUT_AGGREGATE_IDS))
    )
    with pytest.raises(FullC6SupplyChainError, match="process-sealed Cargo workspace"):
        verify_full_c6_supply_chain_receipt(receipt)
    assert verify_full_c6_supply_chain_receipt(
        receipt,
        cargo_dependency_workspace=workspace,
    ) == receipt

    binding_prefix = "full-c6-cargo-input-aggregate:"
    public = receipt.to_dict()
    bindings = public["bindings"]
    assert isinstance(bindings, dict)
    aggregate_bindings = {
        name: digest
        for name, digest in bindings.items()
        if name.startswith(binding_prefix)
    }
    assert len(aggregate_bindings) == 7
    assert all(len(digest) == 64 for digest in aggregate_bindings.values())
    assert str(tmp_path) not in repr(public)
    assert "MIT aggregate fixture" not in repr(public)

    sbom = json.loads(receipt.sbom_json)
    components = [
        item
        for item in sbom["components"]
        if item["name"].startswith(binding_prefix)
    ]
    assert len(components) == 7
    for component in components:
        properties = {
            item["name"]: item["value"] for item in component["properties"]
        }
        assert properties["rextio:role"] == (
            "process-sealed-cargo-input-aggregate"
        )
        assert properties["rextio:aggregate_digest"]
        assert properties["rextio:member_count"]

    provenance = json.loads(receipt.provenance_json)
    definition = provenance["predicate"]["buildDefinition"]
    dependencies = [
        item
        for item in definition["resolvedDependencies"]
        if item["uri"].startswith(
            "urn:rextio:full-c6-evidence:full-c6-cargo-input-aggregate:"
        )
    ]
    assert len(dependencies) == 7
    assert {
        item["uri"].removeprefix("urn:rextio:full-c6-evidence:"): item[
            "digest"
        ]["sha256"]
        for item in dependencies
    } == aggregate_bindings


def test_cargo_aggregate_missing_extra_alias_and_reorder_fail_closed(
    tmp_path: Path,
) -> None:
    arguments, workspace = _aggregate_arguments(tmp_path)
    bound = arguments["build_inputs"]
    assert isinstance(bound, BuildInputClosure)

    missing = BuildInputClosure(
        files=bound.files,
        aggregates=bound.aggregates[:-1],
    )
    extra_row = BuildInputAggregateIdentity(
        aggregate_id="full-c6-cargo-z-extra",
        kind="cargo-z-extra",
        digest="e" * 64,
        member_count=1,
    )
    extra = BuildInputClosure(
        files=bound.files,
        aggregates=tuple(
            sorted(
                (*bound.aggregates, extra_row),
                key=lambda item: (item.kind, item.aggregate_id),
            )
        ),
    )
    aliased_rows = tuple(
        replace(
            item,
            aggregate_id=item.aggregate_id.upper(),
        )
        if item.aggregate_id == "full-c6-cargo-workspace"
        else item
        for item in bound.aggregates
    )
    aliased = BuildInputClosure(files=bound.files, aggregates=aliased_rows)
    reordered = BuildInputClosure(files=bound.files, aggregates=bound.aggregates)
    object.__setattr__(reordered, "aggregates", tuple(reversed(reordered.aggregates)))

    for candidate in (missing, extra, aliased, reordered):
        with pytest.raises(
            FullC6SupplyChainError,
            match="missing, extra, aliased, or reordered",
        ):
            validate_full_c6_cargo_input_aggregates(candidate, workspace)


@pytest.mark.parametrize(
    ("aggregate_id", "changes"),
    (
        ("full-c6-cargo-sources", {"digest": "f" * 64}),
        ("full-c6-cargo-vendor-tree", {"member_count": 999}),
        (
            "full-c6-cargo-package-receipts",
            {"metadata_digest": "f" * 64},
        ),
    ),
)
def test_cargo_aggregate_digest_count_and_metadata_tamper_fail_closed(
    tmp_path: Path,
    aggregate_id: str,
    changes: dict[str, object],
) -> None:
    arguments, workspace = _aggregate_arguments(tmp_path)
    bound = arguments["build_inputs"]
    assert isinstance(bound, BuildInputClosure)
    tampered_rows = tuple(
        replace(item, **changes) if item.aggregate_id == aggregate_id else item
        for item in bound.aggregates
    )
    tampered = BuildInputClosure(files=bound.files, aggregates=tampered_rows)

    with pytest.raises(
        FullC6SupplyChainError,
        match="do not match the process-sealed workspace",
    ):
        validate_full_c6_cargo_input_aggregates(tampered, workspace)
    with pytest.raises(
        FullC6SupplyChainError,
        match="do not match the process-sealed workspace",
    ):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "build_inputs": tampered}
        )


def test_legacy_empty_aggregate_closure_remains_compatible(tmp_path: Path) -> None:
    arguments = _arguments()
    legacy = arguments["build_inputs"]
    assert isinstance(legacy, BuildInputClosure)
    assert legacy.aggregates == ()
    assert supply_chain_module._rebuild_build_inputs(legacy) == legacy

    receipt = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **arguments
    )
    assert receipt.cargo_input_aggregates == ()
    assert "cargo_input_aggregates" not in receipt.to_dict()
    assert verify_full_c6_supply_chain_receipt(receipt) == receipt

    workspace = _sealed_cargo_workspace(tmp_path)
    with pytest.raises(FullC6SupplyChainError, match="legacy build-input closure"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "cargo_dependency_workspace": workspace}
        )


def test_exact_partition_supports_an_explicit_zero_class() -> None:
    receipt = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **_arguments(_policy_without_stub())
    )
    stub = next(
        item
        for item in receipt.partition
        if item.class_id == "file-input:present-project-python-stub"
    )
    assert stub.identities == ()
    assert stub.to_dict()["count"] == 0
    assert stub.to_dict()["explicit_zero"] is True


def test_partition_projection_sorts_multiple_members_by_canonical_identity() -> None:
    """Policy authority order must not leak into the public class partition."""
    original = _row(_policy_receipt(), "external-source:distribution-metadata")
    wheel = replace(
        original,
        canonical_identity="distributions/demo-math/demo_math-1.2.3.dist-info/WHEEL",
    )
    metadata = replace(
        original,
        canonical_identity="distributions/demo-math/demo_math-1.2.3.dist-info/METADATA",
    )
    # A real policy sorts rows by its authority identities, whose hashes are
    # independent of canonical path order. Exercise that projection directly
    # with the opposite order to prevent valid multi-metadata wheels failing.
    projected = supply_chain_module._partition_from_policy(  # type: ignore[attr-defined]
        type("PolicyRows", (), {"rows": (wheel, metadata)})()
    )
    bucket = next(
        item
        for item in projected
        if item.class_id == "external-source:distribution-metadata"
    )

    assert tuple(item.canonical_identity for item in bucket.identities) == (
        metadata.canonical_identity,
        wheel.canonical_identity,
    )


def test_omission_and_duplicate_or_alias_fail_closed() -> None:
    arguments = _arguments()
    entries = arguments["wheel_entries"]
    assert isinstance(entries, tuple)
    with pytest.raises(FullC6SupplyChainError, match="wheel entries"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "wheel_entries": entries[:-1]}
        )
    with pytest.raises(FullC6SupplyChainError, match="unique canonical"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "wheel_entries": (*entries, entries[0])}
        )
    aliased = (replace(entries[0], name="PKG/__init__.py"), entries[1])
    with pytest.raises(FullC6SupplyChainError, match="stale content identity"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "wheel_entries": aliased}
        )


def test_stale_subject_and_unbound_runtime_leaf_fail_closed() -> None:
    arguments = _arguments()
    subject = arguments["subject"]
    assert isinstance(subject, EvidenceFileRef)
    with pytest.raises(FullC6SupplyChainError, match="subject wheel"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{**arguments, "subject": replace(subject, sha256="f" * 64)}
        )

    runtime = arguments["runtime_authorization"]
    assert isinstance(runtime, RuntimeAuthorizationReceipt)
    changed = replace(
        runtime.declared_system_images[0],
        path="/usr/lib/libm.so.6",
        inode=3,
    )
    changed_runtime = replace(
        runtime,
        declared_system_images=(changed,),
        newly_loaded_images=(changed,),
    )
    authority_aggregate = arguments["authority_aggregate"]
    assert isinstance(
        authority_aggregate,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    with pytest.raises(FullC6SupplyChainError, match="runtime leaves"):
        build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
            **{
                **arguments,
                "runtime_authorization": changed_runtime,
                "authority_aggregate": replace(
                    authority_aggregate,
                    runtime_authorization_sha256=changed_runtime.digest,
                ),
            }
        )


def test_darwin_shared_cache_leaf_uses_bound_platform_identity() -> None:
    policy = _policy_with_system_identity("system:libSystem.B.dylib")
    arguments = _arguments(policy)
    native = _row(policy, "wheel-entry:packaged-native-runtime-member")

    def runtime(platform_base_sha256: str) -> RuntimeAuthorizationReceipt:
        return RuntimeAuthorizationReceipt(
            target_triple="aarch64-apple-darwin",
            extension=RuntimeLoadedImage(
                path="/opt/rextio/libnative.dylib",
                device=1,
                inode=1,
                sha256=native.sha256 or "",
                size=native.size if native.size is not None else 0,
            ),
            platform_base_sha256=platform_base_sha256,
            declared_system_images=(),
            declared_system_platform_images=("/usr/lib/libSystem.B.dylib",),
            newly_loaded_images=(),
            newly_loaded_platform_images=("/usr/lib/libSystem.B.dylib",),
            path_resolution_sha256="2" * 64,
            transitive_closure_sha256="3" * 64,
            load_commands_sha256="4" * 64,
            imported_symbols_sha256="5" * 64,
            final_snapshot_sha256="6" * 64,
            verification_mode=RUNTIME_VERIFICATION_NATIVE_FRESH,
        )

    authority_aggregate = arguments["authority_aggregate"]
    assert isinstance(
        authority_aggregate,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    first_runtime = runtime("a" * 64)
    second_runtime = runtime("b" * 64)
    first = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **{
            **arguments,
            "target_triple": "aarch64-apple-darwin",
            "runtime_authorization": first_runtime,
            "authority_aggregate": replace(
                authority_aggregate,
                runtime_authorization_sha256=first_runtime.digest,
            ),
        }
    )
    second = build_full_c6_supply_chain_receipt(  # type: ignore[arg-type]
        **{
            **arguments,
            "target_triple": "aarch64-apple-darwin",
            "runtime_authorization": second_runtime,
            "authority_aggregate": replace(
                authority_aggregate,
                runtime_authorization_sha256=second_runtime.digest,
            ),
        }
    )
    sbom = json.loads(first.sbom_json)
    system = next(
        component
        for component in sbom["components"]
        if {item["name"]: item["value"] for item in component["properties"]}.get(
            "rextio:class_id"
        )
        == "native-runtime:logical-system-leaf"
    )
    properties = {item["name"]: item["value"] for item in system["properties"]}
    assert properties["rextio:identity_mode"] == "platform-identity"
    assert properties["rextio:runtime_path"] == "/usr/lib/libSystem.B.dylib"
    assert first.sbom_sha256 != second.sbom_sha256


def test_noncanonical_json_and_duplicate_keys_are_rejected() -> None:
    receipt = build_full_c6_supply_chain_receipt(**_arguments())  # type: ignore[arg-type]
    pretty = json.dumps(json.loads(receipt.sbom_json), indent=2).encode()
    with pytest.raises(FullC6SupplyChainError, match="not canonical"):
        validate_full_c6_supply_chain_document(pretty, document_kind="sbom")
    with pytest.raises(FullC6SupplyChainError, match="duplicate"):
        validate_full_c6_supply_chain_document(
            b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6","version":1}',
            document_kind="sbom",
        )


def test_forged_public_input_and_output_dataclasses_are_reconstructed() -> None:
    arguments = _arguments()
    toolchain = arguments["toolchain"]
    assert isinstance(toolchain, BuildToolchainIdentity)
    object.__setattr__(toolchain.cargo_sources.packages[0], "checksum", "f" * 64)
    with pytest.raises(FullC6SupplyChainError, match="checksum"):
        build_full_c6_supply_chain_receipt(**arguments)  # type: ignore[arg-type]

    clean = build_full_c6_supply_chain_receipt(**_arguments())  # type: ignore[arg-type]
    object.__setattr__(clean, "policy_sha256", "0" * 64)
    with pytest.raises(FullC6SupplyChainError, match="provenance"):
        verify_full_c6_supply_chain_receipt(clean)

    projected = build_full_c6_supply_chain_receipt(**_arguments())  # type: ignore[arg-type]
    object.__setattr__(projected, "reproducible_sbom_input_sha256", "0" * 64)
    with pytest.raises(FullC6SupplyChainError, match="SBOM"):
        verify_full_c6_supply_chain_receipt(projected)
