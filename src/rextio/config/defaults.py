from __future__ import annotations

from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


DEFAULT_CONFIG = {
    "build": {
        "native_backend": "rust",
        "fallback_backend": "cpython",
        "fallback_threshold": DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    },
    "rust": {
        "binding": "pyo3",
        "build_tool": "maturin",
    },
    "fallback": {
        "nuitka": "experimental",
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
    },
}
