"""Render the strict C5.2 installed-distribution runtime guard."""

from __future__ import annotations

from rextio.codegen.rust.rust_format import rust_string_literal
from rextio.source.external_linkage import ExternalRuntimeGuard


def render_external_runtime_guard(guard: ExternalRuntimeGuard) -> str:
    """Render one fail-closed PyO3 module-initialization guard function."""
    if type(guard) is not ExternalRuntimeGuard:
        raise TypeError("external runtime guard has an invalid type")
    distribution = rust_string_literal(guard.distribution)
    version = rust_string_literal(guard.version)
    lines = [
        "fn __rextio_external_guard_error() -> PyErr {",
        "    pyo3::exceptions::PyImportError::new_err(",
        '        "RXT060 external source runtime identity verification failed",',
        "    )",
        "}",
        "",
        "fn __rextio_verify_external_source(py: Python<'_>) -> PyResult<()> {",
        '    let metadata = PyModule::import(py, "importlib.metadata")',
        "        .map_err(|_| __rextio_external_guard_error())?;",
        f'    let installed_version: String = metadata.call_method1("version", ({distribution},))',
        "        .and_then(|value| value.extract())",
        "        .map_err(|_| __rextio_external_guard_error())?;",
        f"    if installed_version != {version} {{",
        "        return Err(__rextio_external_guard_error());",
        "    }",
        f'    let distribution = metadata.call_method1("distribution", ({distribution},))',
        "        .map_err(|_| __rextio_external_guard_error())?;",
        '    let os = PyModule::import(py, "os")',
        "        .map_err(|_| __rextio_external_guard_error())?;",
    ]
    for module_index, module in enumerate(guard.modules):
        module_name = rust_string_literal(module.module_name)
        source_member = rust_string_literal(module.source_member)
        source_sha256 = rust_string_literal(module.source_sha256)
        suffix = str(module_index)
        lines.extend(
            [
                f'    let located_{suffix} = distribution.call_method1("locate_file", ({source_member},))',
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f'    let expected_path_{suffix}: String = os.call_method1("fspath", (located_{suffix},))',
                "        .and_then(|value| value.extract())",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    let expected_metadata_{suffix} = std::fs::symlink_metadata(&expected_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    if !expected_metadata_{suffix}.is_file() || expected_metadata_{suffix}.file_type().is_symlink() {{",
                "        return Err(__rextio_external_guard_error());",
                "    }",
                f"    let expected_real_{suffix} = std::fs::canonicalize(&expected_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    let expected_source_{suffix} = std::fs::read(&expected_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f'    let expected_digest_{suffix} = format!("{{:x}}", sha2::Sha256::digest(&expected_source_{suffix}));',
                f"    if expected_digest_{suffix} != {source_sha256} {{",
                "        return Err(__rextio_external_guard_error());",
                "    }",
                f"    let module_{suffix} = PyModule::import(py, {module_name})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f'    let actual_path_{suffix}: String = module_{suffix}.getattr("__file__")',
                "        .and_then(|value| value.extract())",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    let source_metadata_{suffix} = std::fs::symlink_metadata(&actual_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    if !source_metadata_{suffix}.is_file() || source_metadata_{suffix}.file_type().is_symlink() {{",
                "        return Err(__rextio_external_guard_error());",
                "    }",
                f"    let actual_real_{suffix} = std::fs::canonicalize(&actual_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f"    if expected_real_{suffix} != actual_real_{suffix} {{",
                "        return Err(__rextio_external_guard_error());",
                "    }",
                f"    let actual_source_{suffix} = std::fs::read(&actual_path_{suffix})",
                "        .map_err(|_| __rextio_external_guard_error())?;",
                f'    let actual_digest_{suffix} = format!("{{:x}}", sha2::Sha256::digest(&actual_source_{suffix}));',
                f"    if actual_digest_{suffix} != {source_sha256} {{",
                "        return Err(__rextio_external_guard_error());",
                "    }",
            ]
        )
        for callable_index, callable_identity in enumerate(module.callables):
            name = rust_string_literal(callable_identity.name)
            qualname = rust_string_literal(callable_identity.qualname)
            callable_suffix = f"{module_index}_{callable_index}"
            lines.extend(
                [
                    f"    let callable_{callable_suffix} = module_{suffix}.dict().get_item({name})",
                    "        .map_err(|_| __rextio_external_guard_error())?",
                    "        .ok_or_else(__rextio_external_guard_error)?;",
                    f"    if !callable_{callable_suffix}.is_instance_of::<pyo3::types::PyFunction>() {{",
                    "        return Err(__rextio_external_guard_error());",
                    "    }",
                    f'    let callable_module_{callable_suffix}: String = callable_{callable_suffix}.getattr("__module__")',
                    "        .and_then(|value| value.extract())",
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f'    let callable_qualname_{callable_suffix}: String = callable_{callable_suffix}.getattr("__qualname__")',
                    "        .and_then(|value| value.extract())",
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f"    if callable_module_{callable_suffix} != {module_name}",
                    f"        || callable_qualname_{callable_suffix} != {name} {{",
                    "        return Err(__rextio_external_guard_error());",
                    "    }",
                    f'    let code_{callable_suffix} = callable_{callable_suffix}.getattr("__code__")',
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f'    let first_line_{callable_suffix}: i64 = code_{callable_suffix}.getattr("co_firstlineno")',
                    "        .and_then(|value| value.extract())",
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f'    let code_path_{callable_suffix}: String = code_{callable_suffix}.getattr("co_filename")',
                    "        .and_then(|value| value.extract())",
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f"    let code_real_{callable_suffix} = std::fs::canonicalize(&code_path_{callable_suffix})",
                    "        .map_err(|_| __rextio_external_guard_error())?;",
                    f"    if first_line_{callable_suffix} != {callable_identity.first_line}",
                    f"        || code_real_{callable_suffix} != actual_real_{suffix}",
                    f'        || format!("{{}}.{{}}", callable_module_{callable_suffix}, callable_qualname_{callable_suffix}) != {qualname} {{',
                    "        return Err(__rextio_external_guard_error());",
                    "    }",
                ]
            )
    lines.extend(["    Ok(())", "}"])
    return "\n".join(lines)


__all__ = ["render_external_runtime_guard"]
