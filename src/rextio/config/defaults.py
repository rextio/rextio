"""Default configuration values."""

from __future__ import annotations

from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


DEFAULT_CONFIG = {
    "build": {
        "native_backend": "rust",
        "fallback_backend": "cpython",
        "fallback_threshold": DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
        "build_timeout_seconds": DEFAULT_BUILD_TIMEOUT_SECONDS,
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
    },
    "plugins": {
        "enabled": (),
    },
    "imports": {
        "default_external_policy": "fallback",
        "packages": {},
    },
    "jit": {
        "enabled": False,
        "backend": "cranelift",
        "hot_threshold": 25,
    },
    "executable": {
        "entrypoint": None,
        "name": None,
        "backend": "zipapp",
        "nuitka_mode": "standalone",
    },
    "policy": {
        "native_marker": "auto",
        "require_type_hints": True,
        "allow_dynamic_features": False,
        "boundary_warnings": True,
        "native_top_level": False,
    },
}
