"""Default configuration values."""

from __future__ import annotations

from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


DEFAULT_CONFIG: dict[str, dict[str, object]] = {
    "build": {
        "native_backend": "rust",
        "fallback_backend": "cpython",
        "fallback_threshold": DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
        "build_timeout_seconds": DEFAULT_BUILD_TIMEOUT_SECONDS,
        "artifact_evidence_policy": "best-effort",
        "artifact_distribution_policy": "disabled",
        "artifact_source_lock_manifest": None,
        "artifact_source_lock_signature": None,
        "artifact_policy_manifest": None,
        "artifact_policy_manifest_sha256": None,
        "artifact_cargo_vendor": None,
        "artifact_cargo_vendor_sha256": None,
        "artifact_cargo_lock": None,
        "artifact_cargo_lock_sha256": None,
        "artifact_toolchain_support_lock": None,
        "artifact_toolchain_support_lock_sha256": None,
        "artifact_trusted_public_key": None,
        "artifact_trusted_public_key_sha256": None,
        "artifact_final_signature": None,
        "artifact_signing_request_output": None,
        "artifact_repeat_builds": 2,
    },
    "rust": {
        "binding": "pyo3",
        "build_tool": "cargo",
        "importable": False,
        "crate_name": "rextio_generated_rust",
    },
    "fallback": {
        "nuitka": "experimental",
    },
    "target": {
        "version": None,
        "build_options": {},
        "device_provider": None,
        "device_capability": None,
        "device_options": {},
    },
    "plugins": {
        "enabled": (),
    },
    "imports": {
        "default_external_policy": "fallback",
        "packages": {},
    },
    "embedding": {
        "enabled": False,
    },
    "executable": {
        "entrypoint": None,
        "name": None,
        "backend": "zipapp",
        "nuitka_mode": "standalone",
        "python": None,
        # Keep both spellings unspecified here so the loader can distinguish an
        # explicit compatibility alias from the python-subprocess default.
        "fallback": None,
        "hybrid_runtime": None,
    },
    "toolchain": {
        "cargo": None,
        "maturin": None,
        "nuitka": None,
        "python": None,
        "rust_toolchain": None,
        "cargo_version": None,
        "maturin_version": None,
        "nuitka_version": None,
        "python_version": None,
    },
    "policy": {
        "native_marker": "auto",
        "require_type_hints": True,
        "allow_dynamic_features": False,
        "boundary_warnings": True,
        "native_top_level": False,
    },
}
