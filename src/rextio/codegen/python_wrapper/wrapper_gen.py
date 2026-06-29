"""Generation of the Python wrapper module that dispatches to native or fallback."""

from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, TopLevelAnalysis
from rextio.codegen.native_names import native_function_name, runtime_original_name
from rextio.fallback.fallback_marker import GENERATED_PYTHON_HEADER
from rextio.fallback.module_copy import (
    fallback_module_name,
    native_top_level_fallback_module_name,
)
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


def render_wrapper_module(
    module: ModuleAnalysis,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> str:
    """Render the Python wrapper module source that dispatches to native or fallback."""
    accepted = sorted(
        [
            function
            for function in module.functions
            if function.is_native_candidate and function.accepted
        ],
        key=lambda function: function.qualname,
    )
    top_level = (
        module.top_level
        if module.top_level is not None
        and module.top_level.is_native_candidate
        and module.top_level.accepted
        else None
    )
    if not accepted and top_level is None:
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
    ]
    if top_level is not None:
        lines.append("import importlib as _rextio_importlib")
        lines.append("")
        lines.extend(_render_native_top_level_binding(top_level))
        lines.append("")
        lines.extend(
            _render_dynamic_fallback_selection(
                module,
                fallback_name,
                native_top_level_fallback_module_name(module),
                top_level,
            )
        )
    else:
        lines.extend(_fallback_module_import_lines(import_prefix, fallback_name))
        lines.append(f"from {import_prefix}{fallback_name} import *  # noqa: F401,F403")
    lines.append("")
    for function in accepted:
        lines.extend(_render_fallback_binding(function, import_prefix, fallback_name, top_level is not None))
    lines.append("")

    for function in accepted:
        lines.extend(_render_native_binding(function))
        lines.append("")

    for function in accepted:
        node = function_nodes[_function_node_key(function)]
        lines.extend(_render_wrapper_function(function, node, boundary_fallback_threshold))
        lines.append("")

    for function in accepted:
        lines.extend(_render_fallback_replacement(function))
    lines.append("")

    return "\n".join(lines)


def _fallback_module_import_lines(import_prefix: str, fallback_name: str) -> list[str]:
    if import_prefix == ".":
        return [f"from . import {fallback_name} as _rextio_fallback_module"]
    return [f"import {fallback_name} as _rextio_fallback_module"]


def _render_native_binding(function: FunctionAnalysis) -> list[str]:
    return [
        f"{_native_binding_name(function)} = load_native_function(",
        '    module_name="_rextio_native",',
        f'    function_name="{native_function_name(function.qualname)}",',
        ")",
    ]


def _render_native_top_level_binding(top_level: TopLevelAnalysis) -> list[str]:
    return [
        "_native___rextio_top_level__ = load_native_function(",
        '    module_name="_rextio_native",',
        f'    function_name="{native_function_name(top_level.qualname)}",',
        ")",
    ]


def _render_dynamic_fallback_selection(
    module: ModuleAnalysis,
    fallback_name: str,
    native_fallback_name: str,
    top_level: TopLevelAnalysis,
) -> list[str]:
    return [
        f'_REXTIO_FALLBACK_MODULE_NAME = "{fallback_name}"',
        f'_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME = "{native_fallback_name}"',
        "",
        "def _rextio_import_fallback_module(name):",
        "    if __package__:",
        '        return _rextio_importlib.import_module(f".{name}", __package__)',
        "    return _rextio_importlib.import_module(name)",
        "",
        "def _rextio_public_names(module):",
        '    explicit = getattr(module, "__all__", None)',
        "    if explicit is not None:",
        "        return list(explicit)",
        "    return [name for name in module.__dict__ if not name.startswith('_')]",
        "",
        "def _rextio_apply_public_names(module):",
        "    globals().update({name: getattr(module, name) for name in _rextio_public_names(module)})",
        "",
        "def _rextio_select_fallback_module():",
        "    if native_disabled():",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME)",
        "    if _native___rextio_top_level__ is None:",
        "        if native_required():",
        "            raise RuntimeError(",
        f'                "native mode requires generated native top-level initializer: {top_level.qualname}"',
        "            )",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME)",
        "    module = _rextio_import_fallback_module(_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME)",
        "    updates = _native___rextio_top_level__()",
        "    module.__dict__.update(updates)",
        "    globals().update(updates)",
        "    return module",
        "",
        "_rextio_fallback_module = _rextio_select_fallback_module()",
        "_rextio_apply_public_names(_rextio_fallback_module)",
    ]


def _render_wrapper_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    boundary_fallback_threshold: int,
) -> list[str]:
    signature = _signature(node)
    call_args = _call_args(node)
    native_call_args = _native_call_args(function, node)
    native_call = f"{_native_binding_name(function)}({native_call_args})"
    fallback_call = f"{_fallback_binding_name(function)}({call_args})"
    if isinstance(node, ast.AsyncFunctionDef):
        native_call = f"await {native_call}"
        fallback_call = f"await {fallback_call}"
    native_return = native_call
    if not function.native_runtime_semantics and _is_set_type(_return_type_name(function, node)):
        native_return = f"set({native_return})"
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    wrapper_name = function.name if not _is_method(function) else _wrapper_method_name(function)
    return [
        f"{prefix} {wrapper_name}({signature}){_return_annotation(node)}:",
        "    if native_disabled():",
        f"        return {fallback_call}",
        f"    if {_native_binding_name(function)} is None:",
        "        if native_required():",
        "            raise RuntimeError(",
        f'                "native mode requires generated native function: {function.qualname}"',
        "            )",
        f"        return {fallback_call}",
        (
            f'    if not native_required() and boundary_fallback_required("{function.qualname}", '
            f"{boundary_fallback_threshold}):"
        ),
        f"        return {fallback_call}",
        f"    return {native_return}",
    ]


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    parts: list[str] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    for arg, default in zip(positional, defaults, strict=True):
        parts.append(_render_arg(arg, default))
    if node.args.vararg is not None:
        parts.append(f"*{_render_arg(node.args.vararg, None)}")
    if node.args.kwonlyargs:
        if node.args.vararg is None:
            parts.append("*")
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
            parts.append(_render_arg(arg, default))
    if node.args.kwarg is not None:
        parts.append(f"**{_render_arg(node.args.kwarg, None)}")
    return ", ".join(parts)


def _render_arg(arg: ast.arg, default: ast.expr | None) -> str:
    rendered = arg.arg
    if arg.annotation is not None:
        rendered += f": {ast.unparse(arg.annotation)}"
    if default is not None:
        rendered += f" = {ast.unparse(default)}"
    return rendered


def _return_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    if node.returns is None:
        return ""
    return f" -> {ast.unparse(node.returns)}"


def _call_args(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args]]
    if node.args.vararg is not None:
        args.append(f"*{node.args.vararg.arg}")
    args.extend(f"{arg.arg}={arg.arg}" for arg in node.args.kwonlyargs)
    if node.args.kwarg is not None:
        args.append(f"**{node.args.kwarg.arg}")
    return ", ".join(args)


def _native_call_args(function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [
        _native_arg(arg.arg, _arg_type_name(function, arg))
        for arg in [*node.args.posonlyargs, *node.args.args]
    ]
    if node.args.vararg is not None:
        args.append(f"*{node.args.vararg.arg}")
    args.extend(
        f"{arg.arg}={_native_arg(arg.arg, _arg_type_name(function, arg))}" for arg in node.args.kwonlyargs
    )
    if node.args.kwarg is not None:
        args.append(f"**{node.args.kwarg.arg}")
    return ", ".join(args)


def _native_arg(name: str, type_name: str | None) -> str:
    if type_name == "set[float]":
        return f"list({name})"
    return name


def _is_set_type(type_name: str | None) -> bool:
    return type_name is not None and type_name.startswith("set[") and type_name.endswith("]")


def _arg_type_name(function: FunctionAnalysis, arg: ast.arg) -> str | None:
    return _annotation_name(arg.annotation) or function.inferred_arg_types.get(arg.arg)


def _return_type_name(function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    return _annotation_name(node.returns) or function.inferred_return_type


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).replace(" ", "")
    except Exception:
        return None


def _function_nodes(path: Path) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nodes[f"{node.name}.{child.name}"] = child
    return nodes


def _render_fallback_binding(
    function: FunctionAnalysis,
    import_prefix: str,
    fallback_name: str,
    dynamic_fallback: bool,
) -> list[str]:
    binding = _fallback_binding_name(function)
    lines: list[str]
    if _is_method(function):
        lines = [f"{binding} = {_fallback_lookup(function)}"]
    elif dynamic_fallback:
        lines = [f"{binding} = _rextio_fallback_module.{function.name}"]
    else:
        lines = [f"from {import_prefix}{fallback_name} import {function.name} as {binding}"]
    if function.native_runtime_semantics:
        lines.append(
            f'setattr(_rextio_fallback_module, "{runtime_original_name(function.qualname)}", {binding})'
        )
    return lines


def _render_fallback_replacement(function: FunctionAnalysis) -> list[str]:
    if _is_method(function):
        return [f"{_fallback_lookup(function)} = {_wrapper_method_name(function)}"]
    return [f"_rextio_fallback_module.{function.name} = {function.name}"]


def _function_node_key(function: FunctionAnalysis) -> str:
    return _local_qualname(function)


def _fallback_binding_name(function: FunctionAnalysis) -> str:
    if not _is_method(function):
        return f"_fallback_{function.name}"
    return f"_fallback_{_local_qualname(function).replace('.', '_')}"


def _native_binding_name(function: FunctionAnalysis) -> str:
    if not _is_method(function):
        return f"_native_{function.name}"
    return f"_native_{_local_qualname(function).replace('.', '_')}"


def _wrapper_method_name(function: FunctionAnalysis) -> str:
    return f"_rextio_wrapper_{_local_qualname(function).replace('.', '_')}"


def _fallback_lookup(function: FunctionAnalysis) -> str:
    target = "_rextio_fallback_module"
    for item in _local_qualname(function).split("."):
        target = f"{target}.{item}"
    return target


def _is_method(function: FunctionAnalysis) -> bool:
    return "." in _local_qualname(function)


def _local_qualname(function: FunctionAnalysis) -> str:
    if function.module_name and function.qualname.startswith(f"{function.module_name}."):
        return function.qualname[len(function.module_name) + 1:]
    return function.qualname
