from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis
from rextio.analyzer.native_marker import dotted_name, has_native_marker
from rextio.analyzer.unsupported_patterns import validate_native_function


def parse_module(path: Path, project_root: Path) -> ModuleAnalysis:
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

    module.imports = _collect_imports(tree)
    module.functions = _collect_module_functions(tree, module)
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


def _collect_imports(tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible = alias.asname or alias.name.split(".", 1)[0]
                imports[visible] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                visible = alias.asname or alias.name
                imports[visible] = f"{node.module}.{alias.name}"
    return imports


def _collect_module_functions(tree: ast.Module, module: ModuleAnalysis) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        function = FunctionAnalysis(
            name=node.name,
            qualname=f"{module.module_name}.{node.name}" if module.module_name else node.name,
            module_name=module.module_name,
            file_path=module.file_path,
            line=node.lineno,
            column=node.col_offset,
            is_native_candidate=has_native_marker(node),
            calls=collect_call_sites(node),
        )
        if function.is_native_candidate:
            validate_native_function(node, function)
        functions.append(function)
    return functions


def _collect_native_methods(tree: ast.Module, module: ModuleAnalysis) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if not isinstance(child, ast.FunctionDef) or not has_native_marker(child):
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


def collect_call_sites(node: ast.FunctionDef) -> list[CallSite]:
    collector = _CallCollector()
    collector.visit(node)
    return collector.calls
