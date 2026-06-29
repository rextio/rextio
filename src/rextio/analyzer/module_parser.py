from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.common_calls import canonical_call_target, is_logging_get_logger_call
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import classify_import_policies
from rextio.analyzer.jit import is_cranelift_jit_candidate
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis
from rextio.analyzer.native_marker import (
    NativeMarker,
    dotted_name,
    has_exempt_marker,
    native_marker_for_function,
)
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.analyzer.top_level import analyze_native_top_level
from rextio.analyzer.unsupported_patterns import _validate_function_name, validate_native_function
from rextio.config.schema import ImportsConfig
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import normalize_target_language


def parse_module(
    path: Path,
    project_root: Path,
    native_marker: str = "auto",
    target_language: str = "rust",
    native_top_level: bool = False,
    project_modules: set[str] | None = None,
    imports_config: ImportsConfig | None = None,
    active_plugins: Iterable[RextioPlugin] = (),
    native_jit_enabled: bool = False,
    jit_hot_threshold: int = 25,
) -> ModuleAnalysis:
    target_language = normalize_target_language(target_language)
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
    module.import_policies = classify_import_policies(
        module.imports,
        module_name=module_name,
        project_modules=project_modules or set(),
        imports_config=imports_config,
        active_plugins=active_plugins,
    )
    module.logger_names = _collect_logger_names(tree, module.imports)
    stub_signatures = _load_stub_signatures(path)
    module.functions = _collect_module_functions(
        tree,
        module,
        native_marker,
        stub_signatures,
        target_language,
        native_jit_enabled,
        jit_hot_threshold,
    )
    module.functions.extend(_collect_native_methods(tree, module, target_language))
    if native_top_level:
        module.top_level = analyze_native_top_level(tree, module)
    return module


@dataclass(frozen=True)
class StubSignature:
    arg_types: dict[str, str] = field(default_factory=dict)
    return_type: str | None = None


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


def _collect_logger_names(tree: ast.Module, imports: dict[str, str]) -> tuple[str, ...]:
    names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and is_logging_get_logger_call(node.value, imports):
            names.add(target.id)
    return tuple(sorted(names))


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
    stub_signatures: dict[str, StubSignature],
    target_language: str,
    native_jit_enabled: bool,
    jit_hot_threshold: int,
) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef):
            marker = native_marker_for_function(node)
            if marker is not None and not has_exempt_marker(node):
                if marker.error:
                    functions.append(
                        _rejected_native_marker_function(node, module, marker, target_language)
                    )
                elif _native_marker_applies(marker, target_language):
                    functions.append(_runtime_semantics_function(node, module, marker, target_language))
            continue
        if not isinstance(node, ast.FunctionDef):
            continue
        calls = collect_call_sites(node, module.imports, module.logger_names)
        has_exempt = has_exempt_marker(node)
        marker = native_marker_for_function(node)
        has_marker = marker is not None
        stub_signature = stub_signatures.get(node.name, StubSignature())
        function = FunctionAnalysis(
            name=node.name,
            qualname=f"{module.module_name}.{node.name}" if module.module_name else node.name,
            module_name=module.module_name,
            file_path=module.file_path,
            line=node.lineno,
            column=node.col_offset,
            is_native_candidate=has_marker,
            explicitly_marked=has_marker,
            calls=calls,
            inferred_arg_types=dict(stub_signature.arg_types),
            inferred_return_type=stub_signature.return_type,
            native_target_language=_marker_target_language(marker, target_language),
            imports=dict(module.imports),
            logger_names=module.logger_names,
        )
        if has_exempt:
            function.is_native_candidate = False
            function.native_target_language = None
        elif marker is not None and marker.error:
            _add_native_marker_diagnostic(function, node, marker)
        elif marker is not None and not _native_marker_applies(marker, target_language):
            function.is_native_candidate = False
        elif has_marker:
            _classify_native_function(node, function)
        elif native_marker == "auto" and _is_auto_native_candidate(
            node,
            function,
            target_language,
        ):
            function.is_native_candidate = True
            function.accepted = True
        elif native_jit_enabled and _mark_jit_candidate(
            node,
            function,
            target_language,
            jit_hot_threshold,
        ):
            pass
        functions.append(function)
    return functions


def _mark_jit_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    target_language: str,
    jit_hot_threshold: int,
) -> bool:
    if node.decorator_list:
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
        inferred_arg_types=dict(function.inferred_arg_types),
        inferred_return_type=function.inferred_return_type,
        native_target_language=target_language,
        imports=dict(function.imports),
        logger_names=function.logger_names,
    )
    validate_native_function(node, probe)
    accepted, reason = is_cranelift_jit_candidate(node, probe)
    if not accepted:
        # Surface the specific case where an otherwise-eligible int helper is kept
        # on the checked native path because the Cranelift JIT cannot raise
        # OverflowError (council M1 follow-up: make the fallback observable).
        if "overflow-prone arithmetic" in reason:
            function.jit_skipped_reason = reason
        return False
    function.inferred_arg_types = dict(probe.inferred_arg_types)
    function.inferred_return_type = probe.inferred_return_type
    function.native_target_language = target_language
    function.is_jit_candidate = True
    function.jit_hot_threshold = jit_hot_threshold
    function.jit_reason = reason
    return True


def _is_auto_native_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    target_language: str,
) -> bool:
    if node.decorator_list:
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
        inferred_arg_types=dict(function.inferred_arg_types),
        inferred_return_type=function.inferred_return_type,
        native_target_language=target_language,
        imports=dict(function.imports),
        logger_names=function.logger_names,
    )
    validate_native_function(node, probe)
    if probe.accepted:
        function.inferred_arg_types = dict(probe.inferred_arg_types)
        function.inferred_return_type = probe.inferred_return_type
        function.native_target_language = target_language
        return True
    # Auto-discovered (undecorated) functions are accepted only when they fall
    # within the direct-Rust subset. The Python runtime-semantics shim (RXT080)
    # is reserved for functions a developer explicitly opts into with
    # `@rextio.native`; auto-promoting dynamic functions (e.g. dynamic attribute
    # access) to the shim is too broad. Marked functions are still handled by
    # `_classify_native_function`.
    return False


def _classify_native_function(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    probe = FunctionAnalysis(
        name=function.name,
        qualname=function.qualname,
        module_name=function.module_name,
        file_path=function.file_path,
        line=function.line,
        column=function.column,
        is_native_candidate=True,
        calls=list(function.calls),
        inferred_arg_types=dict(function.inferred_arg_types),
        inferred_return_type=function.inferred_return_type,
        native_target_language=function.native_target_language,
        imports=dict(function.imports),
        logger_names=function.logger_names,
    )
    validate_native_function(node, probe)
    function.inferred_arg_types = dict(probe.inferred_arg_types)
    function.inferred_return_type = probe.inferred_return_type
    if probe.accepted:
        function.accepted = True
        return
    if not _requires_runtime_semantics(node):
        for diagnostic in probe.diagnostics:
            function.add_diagnostic(diagnostic)
        function.accepted = False
        return
    # Promotion to the RXT080 runtime shim: the shim emits only `fn {name}` (its
    # signature is the generic `(py, args, kwargs)` and the body is a runtime call),
    # so parameter/local identifiers the probe flagged with RXT011 are irrelevant —
    # only the function name itself must be representable. Validate just the name
    # (mirrors the async path in `_runtime_semantics_function`); keep it on Python
    # fallback when the name cannot be lowered, otherwise promote.
    _validate_function_name(node, function)
    if function.error_diagnostics:
        function.accepted = False
        return
    function.native_runtime_semantics = True
    function.accepted = True
    _add_runtime_semantics_warning(function, node)


def _requires_runtime_semantics(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    # Used only on the explicit `@rextio.native` path (`_classify_native_function`).
    # Auto-discovered functions are never promoted to the runtime shim on the
    # strength of this check alone (see `_is_auto_native_candidate`).
    if isinstance(node, ast.AsyncFunctionDef):
        return True
    body_nodes = (child for statement in node.body for child in ast.walk(statement))
    for child in body_nodes:
        if isinstance(
            child,
            (
                ast.ClassDef,
                ast.Try,
                ast.With,
                ast.AsyncWith,
                ast.Await,
                ast.Yield,
                ast.YieldFrom,
                ast.Raise,
                ast.Assert,
            ),
        ):
            return True
        if isinstance(child, ast.Attribute) and not _is_known_static_attribute(child):
            return True
        if isinstance(child, ast.Call):
            target = dotted_name(child.func)
            if target in {"getattr", "setattr", "hasattr"}:
                return True
    return False


def _is_known_static_attribute(node: ast.Attribute) -> bool:
    if node.attr == "append":
        return True
    return dotted_name(node) in {
        "math.sqrt",
        "math.sin",
        "math.cos",
        "math.floor",
    }


def _runtime_semantics_function(
    node: ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    marker: NativeMarker,
    target_language: str,
) -> FunctionAnalysis:
    function = FunctionAnalysis(
        name=node.name,
        qualname=f"{module.module_name}.{node.name}" if module.module_name else node.name,
        module_name=module.module_name,
        file_path=module.file_path,
        line=node.lineno,
        column=node.col_offset,
        is_native_candidate=True,
        accepted=True,
        explicitly_marked=True,
        calls=[],
        native_target_language=_marker_target_language(marker, target_language),
        native_runtime_semantics=True,
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    # The shim emits `fn {name}`; a function name that can't be lowered (non-raw-able
    # keyword / non-ASCII / `_`) keeps it on Python fallback even though the body
    # qualifies for the shim.
    _validate_function_name(node, function)
    if function.error_diagnostics:
        function.accepted = False
        function.native_runtime_semantics = False
        return function
    _add_runtime_semantics_warning(function, node)
    return function


def _add_runtime_semantics_warning(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    function.add_diagnostic(
        Diagnostic(
            code="RXT080",
            severity="warning",
            message="native function uses Python runtime semantics shim",
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion=(
                "Rextio will generate a Rust/PyO3 native wrapper that calls the "
                "Python fallback implementation to preserve dynamic Python semantics."
            ),
        )
    )


def _native_marker_applies(marker: NativeMarker, target_language: str) -> bool:
    return marker.target_language is None or marker.target_language == target_language


def _marker_target_language(marker: NativeMarker | None, target_language: str) -> str | None:
    if marker is None:
        return None
    return marker.target_language or target_language


def _add_native_marker_diagnostic(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    marker: NativeMarker,
) -> None:
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=marker.error or "unsupported @rextio.native marker",
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion='Use @rextio.native or @rextio.native(target="rust").',
        )
    )


def _has_supported_signature(node: ast.FunctionDef) -> bool:
    if node.args.vararg is not None or node.args.kwarg is not None:
        return False
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if any(arg.annotation is None or not is_supported_type(arg.annotation) for arg in args):
        return False
    return node.returns is not None and is_supported_type(node.returns)


def _load_stub_signatures(path: Path) -> dict[str, StubSignature]:
    stub_path = path.with_suffix(".pyi")
    if not stub_path.exists():
        return {}
    try:
        tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    except SyntaxError:
        return {}
    signatures: dict[str, StubSignature] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        arg_types: dict[str, str] = {}
        for arg in args:
            if arg.annotation is not None and is_supported_type(arg.annotation):
                arg_types[arg.arg] = annotation_name(arg.annotation)
        return_type = None
        if node.returns is not None and is_supported_type(node.returns):
            return_type = annotation_name(node.returns)
        signatures[node.name] = StubSignature(arg_types=arg_types, return_type=return_type)
    return signatures


def _collect_native_methods(
    tree: ast.Module,
    module: ModuleAnalysis,
    target_language: str,
) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            marker = native_marker_for_function(child)
            if marker is None or has_exempt_marker(child):
                continue
            if marker.error:
                functions.append(
                    _rejected_native_marker_method(child, module, node.name, marker, target_language)
                )
                continue
            if not _native_marker_applies(marker, target_language):
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
                accepted=True,
                explicitly_marked=True,
                calls=collect_call_sites(child, module.imports, module.logger_names),
                native_target_language=_marker_target_language(marker, target_language),
                native_runtime_semantics=True,
                imports=dict(module.imports),
                logger_names=module.logger_names,
            )
            # The class-method shim emits `fn {name}(py, args, kwargs)` like the
            # module-level shim, so the method name must be representable in Rust;
            # keep it on Python fallback when it is not (mirrors the validation in
            # `_classify_native_function` / `_runtime_semantics_function`).
            _validate_function_name(child, function)
            if function.error_diagnostics:
                function.accepted = False
                function.native_runtime_semantics = False
                functions.append(function)
                continue
            _add_runtime_semantics_warning(function, child)
            functions.append(function)
    return functions


def _rejected_async_function(
    node: ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    target_language: str,
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
        native_target_language=target_language,
        imports=dict(module.imports),
        logger_names=module.logger_names,
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


def _rejected_native_marker_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    marker: NativeMarker,
    target_language: str,
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
        native_target_language=_marker_target_language(marker, target_language),
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    _add_native_marker_diagnostic(function, node, marker)
    return function


def _rejected_native_marker_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    class_name: str,
    marker: NativeMarker,
    target_language: str,
) -> FunctionAnalysis:
    qualname = (
        f"{module.module_name}.{class_name}.{node.name}"
        if module.module_name
        else f"{class_name}.{node.name}"
    )
    function = FunctionAnalysis(
        name=node.name,
        qualname=qualname,
        module_name=module.module_name,
        file_path=module.file_path,
        line=node.lineno,
        column=node.col_offset,
        is_native_candidate=True,
        accepted=False,
        calls=collect_call_sites(node, module.imports, module.logger_names),
        native_target_language=_marker_target_language(marker, target_language),
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    _add_native_marker_diagnostic(function, node, marker)
    return function


class _CallCollector(ast.NodeVisitor):
    def __init__(self, imports: dict[str, str], logger_names: tuple[str, ...]) -> None:
        self.imports = imports
        self.logger_names = logger_names
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
        target = canonical_call_target(node, self.imports, self.logger_names)
        if target is None:
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


def collect_call_sites(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str] | None = None,
    logger_names: tuple[str, ...] = (),
) -> list[CallSite]:
    collector = _CallCollector(imports or {}, logger_names)
    collector.visit(node)
    return collector.calls
