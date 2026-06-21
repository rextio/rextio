from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis
from rextio.analyzer.native_marker import dotted_name, has_exempt_marker, has_native_marker
from rextio.analyzer.type_collector import is_supported_type
from rextio.analyzer.unsupported_patterns import validate_native_function


def parse_module(path: Path, project_root: Path, native_marker: str = "auto") -> ModuleAnalysis:
    module_name = module_name_for_path(path, project_root)
    module = ModuleAnalysis(module_name=module_name, file_path=str(path))
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        module.diagnostics.append(
            Diagnostic(
                code="RXT000",
                severity="error",
                message=f"Python parse error: {exc.msg}",
                file_path=str(path),
                line=exc.lineno,
                column=exc.offset,
            )
        )
        return module

    module.imports = _collect_imports(
        tree,
        module_name=module_name,
        is_package_module=path.name == "__init__.py",
    )
    module.functions = _collect_module_functions(tree, module, native_marker)
    module.functions.extend(_collect_native_methods(tree, module))
    return module


def module_name_for_path(path: Path, project_root: Path) -> str:
    relative = path.relative_to(project_root)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _collect_imports(
    tree: ast.Module,
    module_name: str,
    is_package_module: bool,
) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible = alias.asname or alias.name.split(".", 1)[0]
                imports[visible] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base_module = _resolve_import_from_base(
                module_name,
                node.module,
                node.level,
                is_package_module,
            )
            if base_module is None:
                continue
            for alias in node.names:
                visible = alias.asname or alias.name
                imports[visible] = f"{base_module}.{alias.name}" if base_module else alias.name
    return imports


def _resolve_import_from_base(
    module_name: str,
    imported_module: str | None,
    level: int,
    is_package_module: bool,
) -> str | None:
    if level == 0:
        return imported_module

    package_parts = module_name.split(".") if module_name else []
    if not is_package_module and package_parts:
        package_parts = package_parts[:-1]

    drop_count = level - 1
    if drop_count:
        if drop_count > len(package_parts):
            return None
        package_parts = package_parts[:-drop_count]

    if imported_module:
        package_parts.extend(imported_module.split("."))
    return ".".join(package_parts)


def _collect_module_functions(
    tree: ast.Module,
    module: ModuleAnalysis,
    native_marker: str,
) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef):
            if has_native_marker(node) and not has_exempt_marker(node):
                functions.append(_rejected_async_function(node, module))
            continue
        if not isinstance(node, ast.FunctionDef):
            continue
        calls = collect_call_sites(node)
        has_exempt = has_exempt_marker(node)
        has_marker = has_native_marker(node)
        function = FunctionAnalysis(
            name=node.name,
            qualname=f"{module.module_name}.{node.name}" if module.module_name else node.name,
            module_name=module.module_name,
            file_path=module.file_path,
            line=node.lineno,
            column=node.col_offset,
            is_native_candidate=has_marker,
            calls=calls,
        )
        if has_exempt:
            function.is_native_candidate = False
        elif has_marker:
            validate_native_function(node, function)
        elif native_marker == "auto" and _is_auto_native_candidate(node, function):
            function.is_native_candidate = True
            function.accepted = True
        functions.append(function)
    return functions


def _is_auto_native_candidate(node: ast.FunctionDef, function: FunctionAnalysis) -> bool:
    if node.decorator_list or not _has_supported_signature(node):
        return False
    probe = FunctionAnalysis(
        name=function.name,
        qualname=function.qualname,
        module_name=function.module_name,
        file_path=function.file_path,
        line=function.line,
        column=function.column,
        is_native_candidate=True,
        calls=list(function.calls),
    )
    validate_native_function(node, probe)
    return probe.accepted


def _has_supported_signature(node: ast.FunctionDef) -> bool:
    if node.args.vararg is not None or node.args.kwarg is not None:
        return False
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if any(arg.annotation is None or not is_supported_type(arg.annotation) for arg in args):
        return False
    return node.returns is not None and is_supported_type(node.returns)


def _collect_native_methods(tree: ast.Module, module: ModuleAnalysis) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) or not has_native_marker(child):
                continue
            qualname = (
                f"{module.module_name}.{node.name}.{child.name}"
                if module.module_name
                else f"{node.name}.{child.name}"
            )
            function = FunctionAnalysis(
                name=child.name,
                qualname=qualname,
                module_name=module.module_name,
                file_path=module.file_path,
                line=child.lineno,
                column=child.col_offset,
                is_native_candidate=True,
                accepted=False,
                calls=collect_call_sites(child),
            )
            function.add_diagnostic(
                Diagnostic(
                    code="RXT010",
                    severity="error",
                    message="instance methods are not supported as Public 1 native functions",
                    file_path=module.file_path,
                    line=child.lineno,
                    column=child.col_offset,
                    function_name=qualname,
                    suggestion="Move the hot path into a module-level typed function.",
                )
            )
            functions.append(function)
    return functions


def _rejected_async_function(
    node: ast.AsyncFunctionDef,
    module: ModuleAnalysis,
) -> FunctionAnalysis:
    function = FunctionAnalysis(
        name=node.name,
        qualname=f"{module.module_name}.{node.name}" if module.module_name else node.name,
        module_name=module.module_name,
        file_path=module.file_path,
        line=node.lineno,
        column=node.col_offset,
        is_native_candidate=True,
        accepted=False,
        calls=[],
    )
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message="async functions are not supported as native functions",
            file_path=module.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion="Keep async code on Python fallback and move synchronous hot paths into typed native functions.",
        )
    )
    return function


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[CallSite] = []
        self.loop_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_For(self, node: ast.For) -> None:
        self.loop_depth += 1
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        self.loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self.loop_depth += 1
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        self.loop_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        target = dotted_name(node.func) or "<dynamic>"
        self.calls.append(
            CallSite(
                target=target,
                line=node.lineno,
                column=node.col_offset,
                in_loop=self.loop_depth > 0,
            )
        )
        self.generic_visit(node)


def collect_call_sites(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[CallSite]:
    collector = _CallCollector()
    collector.visit(node)
    return collector.calls
