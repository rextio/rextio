from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis
from rextio.codegen.native_names import native_function_name
from rextio.fallback.fallback_marker import GENERATED_PYTHON_HEADER
from rextio.fallback.module_copy import fallback_module_name
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


def render_wrapper_module(
    module: ModuleAnalysis,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> str:
    accepted = sorted(
        [
            function
            for function in module.functions
            if function.is_native_candidate and function.accepted
        ],
        key=lambda function: function.name,
    )
    if not accepted:
        raise ValueError(f"module has no accepted native functions: {module.module_name}")

    function_nodes = _function_nodes(Path(module.file_path))
    fallback_name = fallback_module_name(module)
    import_prefix = "." if "." in module.module_name or Path(module.file_path).name == "__init__.py" else ""
    lines = [
        GENERATED_PYTHON_HEADER,
        "",
        "from rextio.runtime.boundary_fallback import boundary_fallback_required",
        "from rextio.runtime.flags import native_disabled, native_required",
        "from rextio.runtime.native_loader import load_native_function",
        "",
        *_fallback_module_import_lines(import_prefix, fallback_name),
        f"from {import_prefix}{fallback_name} import *  # noqa: F401,F403",
    ]
    for function in accepted:
        lines.append(
            f"from {import_prefix}{fallback_name} import {function.name} as _fallback_{function.name}"
        )
    lines.append("")

    for function in accepted:
        lines.extend(_render_native_binding(function))
        lines.append("")

    for function in accepted:
        node = function_nodes[function.name]
        lines.extend(_render_wrapper_function(function, node, boundary_fallback_threshold))
        lines.append("")

    for function in accepted:
        lines.append(f"_rextio_fallback_module.{function.name} = {function.name}")
    lines.append("")

    return "\n".join(lines)


def _fallback_module_import_lines(import_prefix: str, fallback_name: str) -> list[str]:
    if import_prefix == ".":
        return [f"from . import {fallback_name} as _rextio_fallback_module"]
    return [f"import {fallback_name} as _rextio_fallback_module"]


def _render_native_binding(function: FunctionAnalysis) -> list[str]:
    return [
        f"_native_{function.name} = load_native_function(",
        '    module_name="_rextio_native",',
        f'    function_name="{native_function_name(function.qualname)}",',
        ")",
    ]


def _render_wrapper_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef,
    boundary_fallback_threshold: int,
) -> list[str]:
    signature = _signature(node)
    call_args = _call_args(node)
    native_call_args = _native_call_args(node)
    native_return = f"_native_{function.name}({native_call_args})"
    if _is_set_annotation(node.returns):
        native_return = f"set({native_return})"
    return [
        f"def {function.name}({signature}){_return_annotation(node)}:",
        "    if native_disabled():",
        f"        return _fallback_{function.name}({call_args})",
        f"    if _native_{function.name} is None:",
        "        if native_required():",
        "            raise RuntimeError(",
        f'                "native mode requires generated native function: {function.qualname}"',
        "            )",
        f"        return _fallback_{function.name}({call_args})",
        (
            f'    if not native_required() and boundary_fallback_required("{function.qualname}", '
            f"{boundary_fallback_threshold}):"
        ),
        f"        return _fallback_{function.name}({call_args})",
        f"    return {native_return}",
    ]


def _signature(node: ast.FunctionDef) -> str:
    parts: list[str] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    for arg, default in zip(positional, defaults, strict=True):
        parts.append(_render_arg(arg, default))
    if node.args.kwonlyargs:
        parts.append("*")
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            parts.append(_render_arg(arg, default))
    return ", ".join(parts)


def _render_arg(arg: ast.arg, default: ast.expr | None) -> str:
    rendered = arg.arg
    if arg.annotation is not None:
        rendered += f": {ast.unparse(arg.annotation)}"
    if default is not None:
        rendered += f" = {ast.unparse(default)}"
    return rendered


def _return_annotation(node: ast.FunctionDef) -> str:
    if node.returns is None:
        return ""
    return f" -> {ast.unparse(node.returns)}"


def _call_args(node: ast.FunctionDef) -> str:
    args = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args]]
    args.extend(f"{arg.arg}={arg.arg}" for arg in node.args.kwonlyargs)
    return ", ".join(args)


def _native_call_args(node: ast.FunctionDef) -> str:
    args = [
        _native_arg(arg.arg, arg.annotation)
        for arg in [*node.args.posonlyargs, *node.args.args]
    ]
    args.extend(
        f"{arg.arg}={_native_arg(arg.arg, arg.annotation)}" for arg in node.args.kwonlyargs
    )
    return ", ".join(args)


def _native_arg(name: str, annotation: ast.AST | None) -> str:
    if _annotation_name(annotation) == "set[float]":
        return f"list({name})"
    return name


def _is_set_annotation(node: ast.AST | None) -> bool:
    annotation = _annotation_name(node)
    return annotation is not None and annotation.startswith("set[") and annotation.endswith("]")


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).replace(" ", "")
    except Exception:
        return None


def _function_nodes(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
