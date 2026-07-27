"""Immutable semantic dialects for persisted artifact contracts.

The public product terminology changed after 0.1.7.  Persisted policy,
authorization, and SourceLock documents cannot be migrated by partially
matching their metadata, however: their exact root identity and signing domain
are part of the bytes that were reviewed or signed.

New objects always use :data:`CURRENT`.  :data:`LEGACY_0_1_7` exists only so
strict parsers and verifiers can consume exact historical documents.  It must
never be selected for a newly emitted, authorizing, or published artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


POLICY_BOOTSTRAP = "policy-bootstrap"
POLICY_TEMPLATE = "policy-template"
POLICY_COMPLETION = "policy-completion"
POLICY_MANIFEST = "policy-manifest"
AUTHORIZATION_REQUEST = "authorization-request"
AUTHORIZATION_SIGNATURE = "authorization-signature"
SOURCE_LOCK_MANIFEST = "source-lock-manifest"
SOURCE_LOCK_SIGNATURE = "source-lock-signature"
PUBLICATION_MANIFEST = "publication-manifest"
TOOLCHAIN_SUPPORT_LOCK = "toolchain-support-lock"

POLICY_BOOTSTRAP_FILENAME = "policy-bootstrap"
POLICY_MANIFEST_FILENAME = "policy-manifest"
AUTHORIZATION_REQUEST_FILENAME = "authorization-request"
PUBLICATION_MANIFEST_FILENAME = "publication-manifest"
FINAL_EVIDENCE_FILENAME = "final-evidence"
DETACHED_SIGNATURE_FILENAME = "detached-signature"
DISTRIBUTION_AUTHORIZATION_FILENAME = "distribution-authorization"

AUTHORIZATION_SIGNED_MESSAGE = "authorization-signed-message"
AUTHORIZATION_VERIFICATION_RECEIPT = "authorization-verification-receipt"
SOURCE_LOCK_SIGNED_MESSAGE = "source-lock-signed-message"
SOURCE_LOCK_VERIFICATION_RECEIPT = "source-lock-verification-receipt"
SOURCE_LOCK_INDEPENDENT_DETECTION = "source-lock-independent-detection"

# Purpose-specific identities used inside evidence, policy, authorization, and
# native-build receipts.  These are not independently discoverable dialects:
# the enclosing root contract selects one dialect and every nested value must
# come from that same immutable table.
ARTIFACT_DISTRIBUTION_POLICY = "artifact-distribution-policy"
ARTIFACT_PREAUTHORIZATION_EVIDENCE_KIND = "artifact-preauthorization-evidence-kind"
ARTIFACT_PREAUTHORIZATION_EVIDENCE_AUTHORITY = "artifact-preauthorization-evidence-authority"
ARTIFACT_EVIDENCE_KIND = "artifact-evidence-kind"
ARTIFACT_EVIDENCE_AUTHORITY = "artifact-evidence-authority"
ARTIFACT_AUTHORIZATION_AUTHORITY = "artifact-authorization-authority"
ANALYSIS_IR_TRANSACTION_DOMAIN = "analysis-ir-transaction-domain"
ANALYSIS_PROJECTION_DOMAIN = "analysis-projection-domain"
GENERATOR_PROJECTION_DOMAIN = "generator-projection-domain"
LOWERED_IR_PROJECTION_DOMAIN = "lowered-ir-projection-domain"
CARGO_WORKSPACE_DOMAIN = "cargo-workspace-domain"
CARGO_VENDOR_TREE_DOMAIN = "cargo-vendor-tree-domain"
CARGO_VENDOR_PACKAGE_DOMAIN = "cargo-vendor-package-domain"
EFFECTIVE_CONFIG_DOMAIN = "effective-config-domain"
EFFECTIVE_CONFIG_AGGREGATE_ID = "effective-config-aggregate-id"
FINAL_SIGNATURE_LIFECYCLE_MARKER = "final-signature-lifecycle-marker"
POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER = "policy-manifest-digest-lifecycle-marker"
NATIVE_EXECUTOR_DOMAIN = "native-executor-domain"
NATIVE_EXECUTION_DRIVER = "native-execution-driver"
NATIVE_DRIVER_MANIFEST = "native-driver-manifest"
NATIVE_DRIVER_DOMAIN = "native-driver-domain"
EXTERNAL_EXECUTION_DOMAIN = "external-execution-domain"
EXTERNAL_ARCHIVE_RECEIPT_DOMAIN = "external-archive-receipt-domain"
SOURCE_LOCK_RECEIPT_DOMAIN = "source-lock-receipt-domain"
FINAL_OUTPUT_RECEIPT_DOMAIN = "final-output-receipt-domain"
LICENSE_MATERIALS_DOMAIN = "license-materials-domain"
LICENSE_OBSERVATION_DOMAIN = "license-observation-domain"
LICENSE_DETECTOR_PAYLOAD_DOMAIN = "license-detector-payload-domain"
LICENSE_DETECTOR_RECEIPT_DOMAIN = "license-detector-receipt-domain"
LICENSE_DETECTOR_KIND = "license-detector-kind"
NATIVE_OUTPUT_TRANSACTION_DOMAIN = "native-output-transaction-domain"
NATIVE_OUTPUT_DIRECTORY = "native-output-directory"
NATIVE_RUNTIME_AUTHORITY_DOMAIN = "native-runtime-authority-domain"
OUTPUT_LICENSE_DERIVATION_DOMAIN = "output-license-derivation-domain"
OUTPUT_LICENSE_EXPRESSION_DOMAIN = "output-license-expression-domain"
OUTPUT_LICENSE_CONTRACT_DOMAIN = "output-license-contract-domain"
OUTPUT_LICENSE_MAPPING_DOMAIN = "output-license-mapping-domain"
OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN = "output-license-source-lock-domain"
POLICY_RECEIPT_DOMAIN = "policy-receipt-domain"
POLICY_PAYLOAD_DOMAIN = "policy-payload-domain"
POLICY_BOOTSTRAP_INPUT_SET_DOMAIN = "policy-bootstrap-input-set-domain"
LICENSE_PROJECTION_DOMAIN = "license-projection-domain"
TRANSFORMATION_PROJECTION_DOMAIN = "transformation-projection-domain"
TECHNICAL_TRANSFORMATION_SET_DOMAIN = "technical-transformation-set-domain"
INTERNAL_LICENSE_OBSERVATION_DOMAIN = "internal-license-observation-domain"
EXTERNAL_LICENSE_OBSERVATION_DOMAIN = "external-license-observation-domain"
POLICY_RECEIPT_KIND = "policy-receipt-kind"
EXTERNAL_AUTHORITY_PARTITION_DOMAIN = "external-authority-partition-domain"
EXTERNAL_AUTHORITY_IDENTITY_SCHEME = "external-authority-identity-scheme"
AUTHORITY_PARTITION_DOMAIN = "authority-partition-domain"
LICENSE_FILE_SET_DOMAIN = "license-file-set-domain"
POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN = "policy-license-detector-payload-domain"
POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN = "policy-license-detector-receipt-domain"
POLICY_LICENSE_DETECTOR_RECEIPT_KIND = "policy-license-detector-receipt-kind"
TRANSFORMATION_SOURCE_SET_DOMAIN = "transformation-source-set-domain"
ANALYSIS_RECEIPT_DOMAIN = "analysis-receipt-domain"
ANALYSIS_RECEIPT_KIND = "analysis-receipt-kind"
LOWERED_IR_RECEIPT_DOMAIN = "lowered-ir-receipt-domain"
LOWERED_IR_RECEIPT_KIND = "lowered-ir-receipt-kind"
OWNER_ACKNOWLEDGEMENT = "owner-acknowledgement"
OWNER_AUTHENTICATION = "owner-authentication"
PRODUCTION_AUTHORITY_DOMAIN = "production-authority-domain"
PYO3_CONFIG_DOMAIN = "pyo3-config-domain"
LINUX_LAUNCHER_DOMAIN = "linux-launcher-domain"
READ_SANDBOX_DOMAIN = "read-sandbox-domain"
SUBJECT_WHEEL_TRANSACTION_DOMAIN = "subject-wheel-transaction-domain"
CARGO_PACKAGE_SET_DOMAIN = "cargo-package-set-domain"
CARGO_PACKAGE_RECEIPTS_DOMAIN = "cargo-package-receipts-domain"
CARGO_METADATA_SET_DOMAIN = "cargo-metadata-set-domain"
SUPPLY_CHAIN_DOMAIN = "supply-chain-domain"
SBOM_KIND = "sbom-kind"
PROVENANCE_KIND = "provenance-kind"
SUPPLY_CHAIN_BUILD_TYPE = "supply-chain-build-type"
SUPPLY_CHAIN_BUILDER_ID = "supply-chain-builder-id"
PLATFORM_IDENTITY_DOMAIN = "platform-identity-domain"
CARGO_AGGREGATE_BINDING_DOMAIN = "cargo-aggregate-binding-domain"
EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN = "effective-config-aggregate-binding-domain"
AUTHORITY_AGGREGATE_BINDING_DOMAIN = "authority-aggregate-binding-domain"
AUTHORITY_AGGREGATE_MATERIAL_NAME = "authority-aggregate-material-name"
ANALYSIS_INPUT_VERIFICATION_SCOPE = "analysis-input-verification-scope"
ARTIFACT_EVIDENCE_URN_PREFIX = "artifact-evidence-urn-prefix"
ARTIFACT_COMPONENT_URN_PREFIX = "artifact-component-urn-prefix"
ARTIFACT_INPUT_URN_PREFIX = "artifact-input-urn-prefix"
ARTIFACT_TOOL_URN_PREFIX = "artifact-tool-urn-prefix"
ARTIFACT_WHEEL_URN_PREFIX = "artifact-wheel-urn-prefix"
SBOM_SUBJECT_SUFFIX = "sbom-subject-suffix"
NATIVE_BUILD_TYPE = "native-build-type"


@dataclass(frozen=True, slots=True)
class ArtifactContractIdentity:
    """The exact root identity of one closed JSON contract."""

    kind: str
    schema_version: int
    domain: str

    @property
    def triple(self) -> tuple[str, int, str]:
        """Return the exact registry key portion encoded by this identity."""
        return (self.kind, self.schema_version, self.domain)


@dataclass(frozen=True, slots=True)
class ArtifactContractDialect:
    """One immutable, internally consistent persisted-contract dialect."""

    name: str
    semantic_version: str
    production_capable: bool
    identities: Mapping[str, ArtifactContractIdentity]
    filenames: Mapping[str, str]
    byte_values: Mapping[str, bytes]
    string_values: Mapping[str, str]

    def identity(self, artifact: str) -> ArtifactContractIdentity:
        """Return the exact root identity for ``artifact``."""
        try:
            return self.identities[artifact]
        except KeyError as exc:
            raise ValueError(f"unknown artifact contract: {artifact}") from exc

    def filename(self, artifact: str) -> str:
        """Return the canonical filename assigned to ``artifact``."""
        try:
            return self.filenames[artifact]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no filename: {artifact}") from exc

    def byte_value(self, name: str) -> bytes:
        """Return one dialect-specific domain-separation byte string."""
        try:
            return self.byte_values[name]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no byte value: {name}") from exc

    def string_value(self, name: str) -> str:
        """Return one dialect-specific semantic string value."""
        try:
            return self.string_values[name]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no string value: {name}") from exc


def _identity(kind: str, schema_version: int, domain: str) -> ArtifactContractIdentity:
    return ArtifactContractIdentity(
        kind=kind,
        schema_version=schema_version,
        domain=domain,
    )


CURRENT = ArtifactContractDialect(
    name="current",
    semantic_version="0.1.8",
    production_capable=True,
    identities=MappingProxyType(
        {
            POLICY_BOOTSTRAP: _identity(
                "artifact-policy-completion-request",
                3,
                "rextio.artifact-policy-bootstrap.v3",
            ),
            POLICY_TEMPLATE: _identity(
                "artifact-policy-technical-template",
                2,
                "rextio.artifact-policy-template.v2",
            ),
            POLICY_COMPLETION: _identity(
                "artifact-policy-owner-completion",
                2,
                "rextio.artifact-policy-owner-completion.v2",
            ),
            POLICY_MANIFEST: _identity(
                "artifact-policy-manifest",
                3,
                "rextio.artifact-policy-manifest.v3",
            ),
            AUTHORIZATION_REQUEST: _identity(
                "artifact-authorization-request",
                2,
                "rextio.artifact-authorization-request.v2",
            ),
            AUTHORIZATION_SIGNATURE: _identity(
                "artifact-authorization-detached-signature",
                2,
                "rextio.artifact-authorization-detached-signature.v2",
            ),
            SOURCE_LOCK_MANIFEST: _identity(
                "rextio.external-source-lock",
                3,
                "rextio.external-source-lock.v3",
            ),
            SOURCE_LOCK_SIGNATURE: _identity(
                "rextio.external-source-lock-detached-signature",
                2,
                "rextio.external-source-lock-signature.v3",
            ),
            PUBLICATION_MANIFEST: _identity(
                "artifact-publication-manifest",
                2,
                "rextio.artifact-atomic-publication.v2",
            ),
            TOOLCHAIN_SUPPORT_LOCK: _identity(
                "artifact-toolchain-support-lock",
                5,
                "rextio.artifact-toolchain-support-lock.v5",
            ),
        }
    ),
    filenames=MappingProxyType(
        {
            POLICY_BOOTSTRAP_FILENAME: "rextio.artifact-policy.bootstrap.json",
            POLICY_MANIFEST_FILENAME: "rextio.artifact-policy.json",
            AUTHORIZATION_REQUEST_FILENAME: "rextio.artifact-authorization-request.json",
            PUBLICATION_MANIFEST_FILENAME: ("rextio.artifact-publication-manifest.json"),
            FINAL_EVIDENCE_FILENAME: "rextio.artifact-evidence.json",
            DETACHED_SIGNATURE_FILENAME: ("rextio.artifact-authorization-signature.json"),
            DISTRIBUTION_AUTHORIZATION_FILENAME: ("rextio.artifact-authorization.json"),
        }
    ),
    byte_values=MappingProxyType(
        {
            AUTHORIZATION_SIGNED_MESSAGE: (b"REXTIO-ARTIFACT-AUTHORIZATION-ED25519-V2\0"),
            SOURCE_LOCK_SIGNED_MESSAGE: (b"REXTIO-EXTERNAL-SOURCE-LOCK-ED25519-V3\0"),
        }
    ),
    string_values=MappingProxyType(
        {
            AUTHORIZATION_VERIFICATION_RECEIPT: ("rextio.artifact-authorization-verification.v2"),
            SOURCE_LOCK_VERIFICATION_RECEIPT: ("rextio.external-source-lock-verification.v3"),
            SOURCE_LOCK_INDEPENDENT_DETECTION: ("pending-independent-license-detection"),
            ARTIFACT_DISTRIBUTION_POLICY: "rextio-artifact-distribution-v2",
            ARTIFACT_PREAUTHORIZATION_EVIDENCE_KIND: ("artifact-preauthorization-evidence"),
            ARTIFACT_PREAUTHORIZATION_EVIDENCE_AUTHORITY: ("artifact-preauthorization-only"),
            ARTIFACT_EVIDENCE_KIND: "artifact-evidence",
            ARTIFACT_EVIDENCE_AUTHORITY: "artifact-verified-evidence",
            ARTIFACT_AUTHORIZATION_AUTHORITY: ("artifact-authorization-hard-gate"),
            ANALYSIS_IR_TRANSACTION_DOMAIN: ("rextio.artifact-analysis-ir-transaction.v2"),
            ANALYSIS_PROJECTION_DOMAIN: "rextio.artifact-analysis-projection.v2",
            GENERATOR_PROJECTION_DOMAIN: "rextio.artifact-generator-projection.v2",
            LOWERED_IR_PROJECTION_DOMAIN: "rextio.artifact-lowered-ir-projection.v2",
            CARGO_WORKSPACE_DOMAIN: "rextio.artifact-cargo-dependency-workspace.v2",
            CARGO_VENDOR_TREE_DOMAIN: "rextio.artifact-cargo-vendor-tree.v2",
            CARGO_VENDOR_PACKAGE_DOMAIN: "rextio.artifact-cargo-vendor-package.v2",
            EFFECTIVE_CONFIG_DOMAIN: "rextio.artifact-effective-config.v2",
            EFFECTIVE_CONFIG_AGGREGATE_ID: "artifact-evidence-effective-config",
            FINAL_SIGNATURE_LIFECYCLE_MARKER: ("artifact-final-signature-is-separately-bound"),
            POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER: (
                "artifact-policy-manifest-digest-is-separately-bound"
            ),
            NATIVE_EXECUTOR_DOMAIN: "rextio.artifact-native-two-build-executor.v2",
            NATIVE_EXECUTION_DRIVER: "rextio-artifact-native-orchestrator-v2",
            NATIVE_DRIVER_MANIFEST: "rextio.artifact-native-driver.json",
            NATIVE_DRIVER_DOMAIN: "rextio.artifact-native-driver.v3",
            EXTERNAL_EXECUTION_DOMAIN: "rextio.artifact-external-execution.v2",
            EXTERNAL_ARCHIVE_RECEIPT_DOMAIN: ("rextio.artifact-external-source-archive-bound.v2"),
            SOURCE_LOCK_RECEIPT_DOMAIN: ("rextio.artifact-source-lock-verified.v2"),
            FINAL_OUTPUT_RECEIPT_DOMAIN: ("rextio.artifact-final-output-revalidated.v2"),
            LICENSE_MATERIALS_DOMAIN: "rextio.artifact-license-materials.v2",
            LICENSE_OBSERVATION_DOMAIN: "rextio.artifact-license-observation.v2",
            LICENSE_DETECTOR_PAYLOAD_DOMAIN: ("rextio.artifact-license-detector-payload.v2"),
            LICENSE_DETECTOR_RECEIPT_DOMAIN: ("rextio.artifact-license-detector-receipt.v2"),
            LICENSE_DETECTOR_KIND: ("artifact-machine-readable-spdx-metadata-observation"),
            NATIVE_OUTPUT_TRANSACTION_DOMAIN: ("rextio.artifact-native-output.v2"),
            NATIVE_OUTPUT_DIRECTORY: "artifact-native-output",
            NATIVE_RUNTIME_AUTHORITY_DOMAIN: ("rextio.artifact-native-runtime.v2"),
            OUTPUT_LICENSE_DERIVATION_DOMAIN: ("rextio.artifact-output-license-derivation.v3"),
            OUTPUT_LICENSE_EXPRESSION_DOMAIN: ("rextio.artifact-output-license-expression.v2"),
            OUTPUT_LICENSE_CONTRACT_DOMAIN: ("rextio.artifact-output-license-contract.v3"),
            OUTPUT_LICENSE_MAPPING_DOMAIN: ("rextio.artifact-output-license-mapping.v3"),
            OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN: (
                "rextio.artifact-output-license-source-lock-verification.v2"
            ),
            POLICY_RECEIPT_DOMAIN: ("rextio.artifact-license-transformation-policy.v3"),
            POLICY_PAYLOAD_DOMAIN: ("rextio.artifact-policy-owner-declaration-payload.v3"),
            POLICY_BOOTSTRAP_INPUT_SET_DOMAIN: ("rextio.artifact-policy-bootstrap-input-set.v2"),
            LICENSE_PROJECTION_DOMAIN: "rextio.artifact-license-policy.v2",
            TRANSFORMATION_PROJECTION_DOMAIN: ("rextio.artifact-transformation-policy.v2"),
            TECHNICAL_TRANSFORMATION_SET_DOMAIN: ("rextio.artifact-transformation-set.v2"),
            INTERNAL_LICENSE_OBSERVATION_DOMAIN: (
                "rextio.artifact-internal-license-observation.v2"
            ),
            EXTERNAL_LICENSE_OBSERVATION_DOMAIN: (
                "rextio.artifact-external-license-observation.v2"
            ),
            POLICY_RECEIPT_KIND: ("artifact-license-transformation-policy-receipt"),
            EXTERNAL_AUTHORITY_PARTITION_DOMAIN: (
                "rextio.artifact-external-authority-partition.v2"
            ),
            EXTERNAL_AUTHORITY_IDENTITY_SCHEME: (
                "urn:rextio:artifact-external-authority-component:v2"
            ),
            AUTHORITY_PARTITION_DOMAIN: ("rextio.artifact-authority-partition.v2"),
            LICENSE_FILE_SET_DOMAIN: "rextio.artifact-license-file-set.v2",
            POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN: (
                "rextio.artifact-policy-license-detector-payload.v2"
            ),
            POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN: (
                "rextio.artifact-policy-license-detector-receipt.v2"
            ),
            POLICY_LICENSE_DETECTOR_RECEIPT_KIND: ("artifact-independent-license-detection"),
            TRANSFORMATION_SOURCE_SET_DOMAIN: ("rextio.artifact-transformation-source-set.v2"),
            ANALYSIS_RECEIPT_DOMAIN: "rextio.artifact-analysis-receipt.v2",
            ANALYSIS_RECEIPT_KIND: "artifact-analysis-receipt",
            LOWERED_IR_RECEIPT_DOMAIN: ("rextio.artifact-lowered-ir-receipt.v2"),
            LOWERED_IR_RECEIPT_KIND: "artifact-lowered-ir-receipt",
            OWNER_ACKNOWLEDGEMENT: ("REXTIO_ARTIFACT_OWNER_LEGAL_RESPONSIBILITY_ACK_V2"),
            OWNER_AUTHENTICATION: "pending-artifact-authorization-signature",
            PRODUCTION_AUTHORITY_DOMAIN: ("rextio.artifact-production-authority.v3"),
            PYO3_CONFIG_DOMAIN: "rextio.artifact-pyo3-config.v2",
            LINUX_LAUNCHER_DOMAIN: "rextio.artifact-linux-launcher.v1",
            READ_SANDBOX_DOMAIN: "rextio.artifact-read-sandbox.v2",
            SUBJECT_WHEEL_TRANSACTION_DOMAIN: ("rextio.artifact-subject-wheel.v2"),
            CARGO_PACKAGE_SET_DOMAIN: "rextio.artifact-cargo-package-set.v2",
            CARGO_PACKAGE_RECEIPTS_DOMAIN: ("rextio.artifact-cargo-package-receipts.v2"),
            CARGO_METADATA_SET_DOMAIN: "rextio.artifact-cargo-metadata-set.v2",
            SUPPLY_CHAIN_DOMAIN: "rextio.artifact-supply-chain.v2",
            SBOM_KIND: "artifact-cyclonedx-sbom",
            PROVENANCE_KIND: "artifact-slsa-provenance",
            SUPPLY_CHAIN_BUILD_TYPE: (
                "https://rextio.dev/buildtypes/artifact-evidence-host-extension-wheel/v2"
            ),
            SUPPLY_CHAIN_BUILDER_ID: (
                "https://rextio.dev/builder/artifact-evidence-host-extension-wheel/v2"
            ),
            PLATFORM_IDENTITY_DOMAIN: ("rextio.artifact-runtime-platform-identity.v2"),
            CARGO_AGGREGATE_BINDING_DOMAIN: ("rextio.artifact-cargo-input-aggregate-binding.v2"),
            EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN: (
                "rextio.artifact-effective-config-aggregate-binding.v2"
            ),
            AUTHORITY_AGGREGATE_BINDING_DOMAIN: ("rextio.artifact-authority-aggregate-binding.v2"),
            AUTHORITY_AGGREGATE_MATERIAL_NAME: ("artifact-evidence-authority-aggregate"),
            ANALYSIS_INPUT_VERIFICATION_SCOPE: ("project-source-sibling-stubs-v2"),
            ARTIFACT_EVIDENCE_URN_PREFIX: ("urn:rextio:artifact-evidence:evidence:"),
            ARTIFACT_COMPONENT_URN_PREFIX: ("urn:rextio:artifact-evidence:component:"),
            ARTIFACT_INPUT_URN_PREFIX: "urn:rextio:artifact-evidence:input:",
            ARTIFACT_TOOL_URN_PREFIX: "urn:rextio:artifact-evidence:tool:",
            ARTIFACT_WHEEL_URN_PREFIX: "urn:rextio:artifact-evidence:wheel:",
            SBOM_SUBJECT_SUFFIX: ".artifact-evidence.cdx.json",
            NATIVE_BUILD_TYPE: ("https://rextio.dev/build/artifact-native-orchestrator/v2"),
        }
    ),
)


LEGACY_0_1_7 = ArtifactContractDialect(
    name="legacy-0.1.7",
    semantic_version="0.1.7",
    production_capable=False,
    identities=MappingProxyType(
        {
            POLICY_BOOTSTRAP: _identity(
                "full-c6-owner-policy-completion-request",
                2,
                "rextio.full-c6-owner-policy-bootstrap.v2",
            ),
            POLICY_TEMPLATE: _identity(
                "full-c6-owner-policy-technical-template",
                1,
                "rextio.full-c6-owner-policy-template.v1",
            ),
            POLICY_COMPLETION: _identity(
                "full-c6-owner-policy-completion",
                1,
                "rextio.full-c6-owner-policy-completion.v1",
            ),
            POLICY_MANIFEST: _identity(
                "full-c6-owner-policy-manifest",
                2,
                "rextio.full-c6-owner-policy-manifest.v2",
            ),
            AUTHORIZATION_REQUEST: _identity(
                "full-c6-final-authorization-request",
                1,
                "rextio.full-c6-final-authorization-request.v1",
            ),
            AUTHORIZATION_SIGNATURE: _identity(
                "full-c6-detached-signature",
                1,
                "rextio.full-c6-detached-signature.v1",
            ),
            SOURCE_LOCK_MANIFEST: _identity(
                "rextio.external-source-lock",
                2,
                "rextio.external-source-lock.v2",
            ),
            SOURCE_LOCK_SIGNATURE: _identity(
                "rextio.external-source-lock-detached-signature",
                1,
                "rextio.external-source-lock-signature.v2",
            ),
            PUBLICATION_MANIFEST: _identity(
                "full-c6-publication-manifest",
                1,
                "rextio.full-c6-atomic-publication.v1",
            ),
        }
    ),
    filenames=MappingProxyType(
        {
            POLICY_BOOTSTRAP_FILENAME: "rextio.full-c6-policy.bootstrap.json",
            POLICY_MANIFEST_FILENAME: "rextio.full-c6-policy.json",
            AUTHORIZATION_REQUEST_FILENAME: ("rextio.full-c6-final-authorization-request.json"),
            PUBLICATION_MANIFEST_FILENAME: "rextio.full-c6-manifest.json",
            FINAL_EVIDENCE_FILENAME: "rextio.full-c6-evidence.json",
            DETACHED_SIGNATURE_FILENAME: "rextio.full-c6-signature.json",
            DISTRIBUTION_AUTHORIZATION_FILENAME: ("rextio.full-c6-authorization.json"),
        }
    ),
    byte_values=MappingProxyType(
        {
            AUTHORIZATION_SIGNED_MESSAGE: b"REXTIO-FULL-C6-ED25519-V1\0",
            SOURCE_LOCK_SIGNED_MESSAGE: (b"REXTIO-EXTERNAL-SOURCE-LOCK-ED25519-V2\0"),
        }
    ),
    string_values=MappingProxyType(
        {
            AUTHORIZATION_VERIFICATION_RECEIPT: ("rextio.full-c6-signature-verification.v1"),
            SOURCE_LOCK_VERIFICATION_RECEIPT: ("rextio.external-source-lock-verification.v2"),
            SOURCE_LOCK_INDEPENDENT_DETECTION: ("pending-final-full-c6-detector"),
            ARTIFACT_DISTRIBUTION_POLICY: "rextio-full-c6-distribution-v1",
            ARTIFACT_PREAUTHORIZATION_EVIDENCE_KIND: ("full-c6-preauthorization-evidence"),
            ARTIFACT_PREAUTHORIZATION_EVIDENCE_AUTHORITY: ("full-c6-preauthorization-only"),
            ARTIFACT_EVIDENCE_KIND: "full-c6-artifact-evidence",
            ARTIFACT_EVIDENCE_AUTHORITY: "full-c6-verified-evidence",
            ARTIFACT_AUTHORIZATION_AUTHORITY: "full-c6-hard-gate",
            ANALYSIS_IR_TRANSACTION_DOMAIN: ("rextio.full-c6-analysis-ir-transaction.v1"),
            ANALYSIS_PROJECTION_DOMAIN: "rextio.full-c6-analysis-projection.v1",
            GENERATOR_PROJECTION_DOMAIN: "rextio.full-c6-generator-projection.v1",
            LOWERED_IR_PROJECTION_DOMAIN: "rextio.full-c6-lowered-ir-projection.v1",
            CARGO_WORKSPACE_DOMAIN: "rextio.full-c6-cargo-dependency-workspace.v1",
            CARGO_VENDOR_TREE_DOMAIN: "rextio.full-c6-cargo-vendor-tree.v1",
            CARGO_VENDOR_PACKAGE_DOMAIN: "rextio.full-c6-cargo-vendor-package.v1",
            EFFECTIVE_CONFIG_DOMAIN: "rextio.full-c6-effective-config.v1",
            EFFECTIVE_CONFIG_AGGREGATE_ID: "full-c6-effective-config",
            FINAL_SIGNATURE_LIFECYCLE_MARKER: ("full-c6-final-signature-is-separately-bound"),
            POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER: (
                "full-c6-policy-manifest-digest-is-separately-bound"
            ),
            NATIVE_EXECUTOR_DOMAIN: "rextio.full-c6-two-build-executor.v1",
            NATIVE_EXECUTION_DRIVER: "rextio-native-orchestrator-v1",
            NATIVE_DRIVER_MANIFEST: "rextio.full-c6-native-driver.json",
            NATIVE_DRIVER_DOMAIN: "rextio.full-c6-native-driver.v2",
            EXTERNAL_EXECUTION_DOMAIN: "rextio.full-c6-external-execution.v1",
            EXTERNAL_ARCHIVE_RECEIPT_DOMAIN: ("rextio.full-c6-external-source-archive-bound.v1"),
            SOURCE_LOCK_RECEIPT_DOMAIN: "rextio.full-c6-source-lock-verified.v1",
            FINAL_OUTPUT_RECEIPT_DOMAIN: ("rextio.full-c6-final-output-revalidated.v1"),
            LICENSE_MATERIALS_DOMAIN: "rextio.full-c6-license-materials.v1",
            LICENSE_OBSERVATION_DOMAIN: "rextio.full-c6-license-observation.v1",
            LICENSE_DETECTOR_PAYLOAD_DOMAIN: ("rextio.full-c6-machine-readable-license-payload.v1"),
            LICENSE_DETECTOR_RECEIPT_DOMAIN: ("rextio.full-c6-machine-readable-license-receipt.v1"),
            LICENSE_DETECTOR_KIND: ("full-c6-machine-readable-spdx-metadata-observation"),
            NATIVE_OUTPUT_TRANSACTION_DOMAIN: "rextio.full-c6-native-output.v1",
            NATIVE_OUTPUT_DIRECTORY: "full-c6-native-output",
            NATIVE_RUNTIME_AUTHORITY_DOMAIN: "rextio.full-c6-native-runtime.v1",
            OUTPUT_LICENSE_DERIVATION_DOMAIN: ("rextio.full-c6-output-license-derivation.v2"),
            OUTPUT_LICENSE_EXPRESSION_DOMAIN: ("rextio.full-c6-output-license-expression.v1"),
            OUTPUT_LICENSE_CONTRACT_DOMAIN: ("rextio.full-c6-output-license-contract.v2"),
            OUTPUT_LICENSE_MAPPING_DOMAIN: ("rextio.full-c6-output-license-mapping.v2"),
            OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN: (
                "rextio.full-c6-output-license-source-lock-verification.v1"
            ),
            POLICY_RECEIPT_DOMAIN: ("rextio.full-c6-license-transformation-policy.v2"),
            POLICY_PAYLOAD_DOMAIN: ("rextio.full-c6-policy-owner-declaration-payload.v2"),
            POLICY_BOOTSTRAP_INPUT_SET_DOMAIN: ("rextio.full-c6-policy-bootstrap-input-set.v1"),
            LICENSE_PROJECTION_DOMAIN: "rextio.full-c6-license-policy.v1",
            TRANSFORMATION_PROJECTION_DOMAIN: ("rextio.full-c6-transformation-policy.v1"),
            TECHNICAL_TRANSFORMATION_SET_DOMAIN: ("rextio.full-c6-transformation-set.v1"),
            INTERNAL_LICENSE_OBSERVATION_DOMAIN: ("rextio.full-c6-internal-license-observation.v1"),
            EXTERNAL_LICENSE_OBSERVATION_DOMAIN: ("rextio.full-c6-external-license-observation.v1"),
            POLICY_RECEIPT_KIND: ("full-c6-license-transformation-policy-receipt"),
            EXTERNAL_AUTHORITY_PARTITION_DOMAIN: ("rextio.full-c6-external-authority-partition.v1"),
            EXTERNAL_AUTHORITY_IDENTITY_SCHEME: (
                "urn:rextio:full-c6-external-authority-component:v1"
            ),
            AUTHORITY_PARTITION_DOMAIN: ("rextio.full-c6-authority-partition.v1"),
            LICENSE_FILE_SET_DOMAIN: "rextio.full-c6-license-file-set.v1",
            POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN: ("rextio.full-c6-license-detector-payload.v1"),
            POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN: ("rextio.full-c6-license-detector-receipt.v1"),
            POLICY_LICENSE_DETECTOR_RECEIPT_KIND: ("full-c6-independent-license-detection"),
            TRANSFORMATION_SOURCE_SET_DOMAIN: ("rextio.full-c6-transformation-source-set.v1"),
            ANALYSIS_RECEIPT_DOMAIN: "rextio.full-c6-analysis-receipt.v1",
            ANALYSIS_RECEIPT_KIND: "full-c6-analysis-receipt",
            LOWERED_IR_RECEIPT_DOMAIN: ("rextio.full-c6-lowered-ir-receipt.v1"),
            LOWERED_IR_RECEIPT_KIND: "full-c6-lowered-ir-receipt",
            OWNER_ACKNOWLEDGEMENT: ("REXTIO_FULL_C6_OWNER_LEGAL_RESPONSIBILITY_ACK_V1"),
            OWNER_AUTHENTICATION: "pending-final-full-c6-signature",
            PRODUCTION_AUTHORITY_DOMAIN: ("rextio.full-c6-production-authority.v2"),
            PYO3_CONFIG_DOMAIN: "rextio.full-c6-pyo3-config.v1",
            READ_SANDBOX_DOMAIN: "rextio.full-c6-read-sandbox.v1",
            SUBJECT_WHEEL_TRANSACTION_DOMAIN: "rextio.full-c6-subject-wheel.v1",
            CARGO_PACKAGE_SET_DOMAIN: "rextio.full-c6-cargo-package-set.v1",
            CARGO_PACKAGE_RECEIPTS_DOMAIN: ("rextio.full-c6-cargo-package-receipts.v1"),
            CARGO_METADATA_SET_DOMAIN: "rextio.full-c6-cargo-metadata-set.v1",
            SUPPLY_CHAIN_DOMAIN: "rextio.full-c6-supply-chain.v1",
            SBOM_KIND: "full-c6-cyclonedx-sbom",
            PROVENANCE_KIND: "full-c6-slsa-provenance",
            SUPPLY_CHAIN_BUILD_TYPE: (
                "https://rextio.dev/buildtypes/full-c6-host-extension-wheel/v1"
            ),
            SUPPLY_CHAIN_BUILDER_ID: ("https://rextio.dev/builder/full-c6-host-extension-wheel/v1"),
            PLATFORM_IDENTITY_DOMAIN: ("rextio.full-c6-runtime-platform-identity.v1"),
            CARGO_AGGREGATE_BINDING_DOMAIN: ("rextio.full-c6-cargo-input-aggregate-binding.v1"),
            EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN: (
                "rextio.full-c6-effective-config-aggregate-binding.v1"
            ),
            AUTHORITY_AGGREGATE_BINDING_DOMAIN: ("rextio.full-c6-authority-aggregate-binding.v1"),
            AUTHORITY_AGGREGATE_MATERIAL_NAME: "full-c6-authority-aggregate",
            ANALYSIS_INPUT_VERIFICATION_SCOPE: ("c6.10-project-source-sibling-stubs-v1"),
            ARTIFACT_EVIDENCE_URN_PREFIX: "urn:rextio:full-c6-evidence:",
            ARTIFACT_COMPONENT_URN_PREFIX: "urn:rextio:artifact-component:",
            ARTIFACT_INPUT_URN_PREFIX: "urn:rextio:input:",
            ARTIFACT_TOOL_URN_PREFIX: "urn:rextio:tool:",
            ARTIFACT_WHEEL_URN_PREFIX: "urn:rextio:full-c6-wheel:",
            SBOM_SUBJECT_SUFFIX: ".full-c6.cdx.json",
            NATIVE_BUILD_TYPE: ("https://rextio.dev/build/full-c6-native-orchestrator/v1"),
        }
    ),
)


ARTIFACT_CONTRACT_DIALECTS: Mapping[str, ArtifactContractDialect] = MappingProxyType(
    {
        CURRENT.name: CURRENT,
        LEGACY_0_1_7.name: LEGACY_0_1_7,
    }
)

_EXACT_ROOT_REGISTRY: Mapping[
    tuple[str, str, int, str],
    ArtifactContractDialect,
] = MappingProxyType(
    {
        (artifact, identity.kind, identity.schema_version, identity.domain): dialect
        for dialect in ARTIFACT_CONTRACT_DIALECTS.values()
        for artifact, identity in dialect.identities.items()
    }
)


def resolve_artifact_contract_dialect(
    artifact: str,
    *,
    kind: object,
    schema_version: object,
    domain: object,
) -> ArtifactContractDialect:
    """Resolve only one exact ``(kind, schema_version, domain)`` root triple."""
    if type(kind) is not str or type(schema_version) is not int or type(domain) is not str:
        raise ValueError("artifact contract root identity has invalid types")
    dialect = _EXACT_ROOT_REGISTRY.get((artifact, kind, schema_version, domain))
    if dialect is None:
        raise ValueError("artifact contract root identity is unknown or hybrid")
    return dialect


def require_current_dialect(dialect: ArtifactContractDialect) -> None:
    """Reject read-only dialects at production authorization/publication gates."""
    if dialect is not CURRENT or not dialect.production_capable:
        raise ValueError("legacy artifact contracts are read/verify-only")


__all__ = [
    "ARTIFACT_CONTRACT_DIALECTS",
    "AUTHORIZATION_REQUEST",
    "AUTHORIZATION_REQUEST_FILENAME",
    "AUTHORIZATION_SIGNATURE",
    "AUTHORIZATION_SIGNED_MESSAGE",
    "AUTHORIZATION_VERIFICATION_RECEIPT",
    "ArtifactContractDialect",
    "ArtifactContractIdentity",
    "CURRENT",
    "LEGACY_0_1_7",
    "LINUX_LAUNCHER_DOMAIN",
    "POLICY_BOOTSTRAP",
    "POLICY_BOOTSTRAP_FILENAME",
    "POLICY_COMPLETION",
    "POLICY_MANIFEST",
    "POLICY_MANIFEST_FILENAME",
    "POLICY_TEMPLATE",
    "SOURCE_LOCK_INDEPENDENT_DETECTION",
    "SOURCE_LOCK_MANIFEST",
    "SOURCE_LOCK_SIGNATURE",
    "SOURCE_LOCK_SIGNED_MESSAGE",
    "SOURCE_LOCK_VERIFICATION_RECEIPT",
    "TOOLCHAIN_SUPPORT_LOCK",
    "require_current_dialect",
    "resolve_artifact_contract_dialect",
]
