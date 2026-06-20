from __future__ import annotations

DEFAULT_CONFIG = {
    "build": {
        "native_backend": "rust",
        "fallback_backend": "cpython",
    },
    "rust": {
        "binding": "pyo3",
        "build_tool": "maturin",
    },
    "fallback": {
        "nuitka": "experimental",
    },
    "policy": {
        "native_marker": "auto",
        "require_type_hints": True,
        "allow_dynamic_features": False,
        "boundary_warnings": True,
    },
}
