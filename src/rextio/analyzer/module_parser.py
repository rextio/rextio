"""Parsing a Python module file into per-function analysis records."""

from __future__ import annotations

import ast
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.callable_metadata import project_final_binding_kinds
from rextio.analyzer.common_calls import (
    MUTATION_WATCHED_EXTERNAL_MODULES,
    RUNTIME_FIDELITY_TARGETS,
    canonical_call_target,
    is_logging_get_logger_call,
)
from rextio.analyzer.executable_identity import (
    class_construction_stability_reason,
    executable_ast_fingerprint,
)
from rextio.analyzer.final_bindings import (
    _EMPTY_MUTATIONS,
    BindingKind,
    ModuleBindings,
    ProjectBindings,
    LoggerNameValues,
    ProjectMutations,
    build_module_bindings,
    collect_module_mutations,
    definition_is_final,
    logger_call_group_targets,
    logger_object_target,
    marker_decorator_is_proven,
    static_logger_name_values,
)
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import classify_import_policies
from rextio.analyzer.embedding import is_embedding_candidate
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis
from rextio.analyzer.native_marker import (
    NativeMarker,
    dotted_name,
    external_accelerator_for_function,
    parse_native_marker,
    parse_native_marker_shape,
)
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.analyzer.top_level import analyze_native_top_level
from rextio.analyzer.unsupported_patterns import _validate_function_name, validate_native_function
from rextio.config.schema import ImportsConfig
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import normalize_target_language


def _syntax_error_column(exc: SyntaxError, source: str) -> int | None:
    """Normalize ``SyntaxError.offset`` to the diagnostic column contract.

    CPython's ``SyntaxError.offset`` is a **1-based Unicode code-point** index
    into the error line. Every AST-derived diagnostic ``column`` is a **0-based
    UTF-8 byte** offset into that line. Convert a present offset into the UTF-8
    byte length of the prefix before the error site; return ``None`` when the
    runtime supplies no meaningful offset (do not invent precision).
    """
    offset = exc.offset
    if offset is None or offset < 1:
        return None

    line_text = exc.text
    if line_text is None:
        lineno = exc.lineno
        if lineno is None or lineno < 1:
            return None
        lines = source.splitlines(keepends=True)
        if lineno > len(lines):
            return None
        line_text = lines[lineno - 1]

    # 1-based code-point index -> prefix before the error site. String slicing
    # clamps past end-of-line (CPython sometimes reports EOF offsets that way).
    prefix = line_text[: offset - 1]
    return len(prefix.encode("utf-8"))


def parse_module(
    path: Path,
    project_root: Path,
    native_marker: str = "auto",
    target_language: str = "rust",
    native_top_level: bool = False,
    project_modules: set[str] | None = None,
    imports_config: ImportsConfig | None = None,
    active_plugins: Iterable[RextioPlugin] = (),
    embedding_enabled: bool = False,
    project_return_types: dict[str, str] | None = None,
    claim_engine: object | None = None,
    project_mutations: ProjectMutations | None = None,
    project_bindings: ProjectBindings | None = None,
) -> ModuleAnalysis:
    """Parse a module file into a ModuleAnalysis (functions, imports, top level).

    ``claim_engine`` is the active lowering plugins' claim engine (or None);
    it rides on each FunctionAnalysis so the validators can resolve plugin
    annotation vocabularies and offer claim sites.
    """
    target_language = normalize_target_language(target_language)
    module_name = module_name_for_path(path, project_root)
    module = ModuleAnalysis(module_name=module_name, file_path=str(path))
    # Read once so SyntaxError location normalization can fall back to the same
    # source the parser saw (do not re-read the file after a failed parse).
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        module.diagnostics.append(
            Diagnostic(
                code="RXT000",
                severity="error",
                message=f"Python parse error: {exc.msg}",
                file_path=str(path),
                line=exc.lineno,
                column=_syntax_error_column(exc, source),
            )
        )
        return module

    effective_project_modules = project_modules or ({module_name} if module_name else set())
    module.project_modules = frozenset(effective_project_modules)
    if project_mutations is None:
        effective_mutations = ProjectMutations({}, frozenset())
        while True:
            specific, unknown = collect_module_mutations(
                tree,
                {},
                effective_project_modules,
                module_name=module_name,
                watched_modules=MUTATION_WATCHED_EXTERNAL_MODULES,
                is_package_module=path.name == "__init__.py",
                known_mutations=effective_mutations,
            )
            merged_specific = {
                receiver: frozenset(paths)
                for receiver, paths in effective_mutations.by_module.items()
            }
            for receiver, paths in specific.items():
                merged_specific[receiver] = merged_specific.get(receiver, frozenset()) | frozenset(
                    paths
                )
            merged = ProjectMutations(
                merged_specific,
                effective_mutations.unknown_modules | frozenset(unknown),
            )
            if merged == effective_mutations:
                break
            effective_mutations = merged
    else:
        effective_mutations = project_mutations

    # Reuse the single shared project-wide final-binding authority when available
    # (built once by ``analyze_project``); otherwise build this module's bindings
    # locally so a standalone ``parse_module`` call stays self-contained (P1-4).
    module_bindings = (
        project_bindings.for_module(module_name)
        if project_bindings is not None
        else build_module_bindings(
            tree,
            module_name,
            project_mutations=effective_mutations,
            project_modules=effective_project_modules,
        )
    )
    module.module_bindings = module_bindings
    module.project_mutations = effective_mutations
    module.imports = _collect_imports(
        tree,
        module_name=module_name,
        is_package_module=path.name == "__init__.py",
        module_bindings=module_bindings,
    )
    module.import_policies = classify_import_policies(
        module.imports,
        module_name=module_name,
        project_modules=project_modules or set(),
        imports_config=imports_config,
        active_plugins=active_plugins,
    )
    module.logger_names, module.logger_group_targets = _collect_logger_bindings(
        tree,
        module.imports,
        module_bindings,
        module.project_mutations,
        effective_project_modules,
    )
    stub_signatures = _load_stub_signatures(path)
    module.functions = _collect_module_functions(
        tree,
        module,
        native_marker,
        stub_signatures,
        target_language,
        embedding_enabled,
        project_return_types or {},
        effective_project_modules,
        claim_engine,
        effective_mutations,
        module_bindings,
    )
    module.functions.extend(
        _collect_native_methods(
            tree,
            module,
            target_language,
            module_bindings,
            effective_mutations,
        )
    )
    if native_top_level:
        module.top_level = analyze_native_top_level(tree, module)
    return module


@dataclass(frozen=True)
class StubSignature:
    """A signature extracted from annotations: argument types and return type."""

    arg_types: dict[str, str] = field(default_factory=dict)
    return_type: str | None = None


def module_name_for_path(path: Path, project_root: Path) -> str:
    """Return the dotted module name for a file path within the project root."""
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
    module_bindings: ModuleBindings | None = None,
) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    # `import pkg.sub as s` binds the visible name to the full target.
                    imports[alias.asname] = alias.name
                else:
                    # `import pkg.sub` binds ONLY the top package `pkg -> pkg` (Python
                    # does not bind `pkg.sub` to the visible name); a later
                    # `pkg.sub.good()` resolves through the package prefix. Binding
                    # `pkg -> pkg.sub` here produced a bogus `pkg.sub.sub.good` target
                    # and rejected a valid call (director follow-up 7, P1-1). Matches
                    # the shared final-binding authority's `import` handling.
                    top = alias.name.split(".", 1)[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__" and not node.level:
                # `from __future__ import annotations` binds no runtime name; it must
                # not enter the import map (director follow-up 7, P1-3).
                continue
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
    # The import map must reflect each name's FINAL source-order module binding
    # (the shared plugin-API-1.3 authority): an alias overwritten by a later
    # def/class/assignment/``del`` — or a conditional binder that may rebind it —
    # no longer resolves to the import, and a later restoring import wins. Keeping
    # a stale ``sin -> math.sin`` after a project ``def sin`` would let core lower a
    # math call Python never makes, so drop every non-``import`` final binding here.
    bindings = module_bindings or build_module_bindings(tree, module_name)
    return {
        name: target
        for name, target in imports.items()
        if bindings.lookup(name).kind is BindingKind.IMPORT
    }


def _collect_fidelity_shim_names(tree: ast.Module) -> frozenset[str]:
    """Return bare names whose FINAL module-level binder is a fidelity import.

    Walks the module body in source order (descending into control-flow
    bodies the way `_collect_module_assigned_names` does) and records, for
    each top-level name, the last statement that binds it: an import, a
    `def`/`class`, an assignment, a loop/with target, or a `del`. A bare call
    to one of these names promotes a marked function to the RXT080 shim ONLY
    when the last binder is a `from`-import resolving into
    `RUNTIME_FIDELITY_TARGETS` - so `def mean` followed by
    `from statistics import mean` promotes (the runtime binding IS the
    stdlib), while the reverse order, a class, or an assignment shadowing the
    import rejects loudly like any project-code call. For conditional bodies
    the last binder in SOURCE ORDER is used - a deterministic approximation;
    when it guesses "project code" the result is a loud rejection, never a
    silent mis-compile. (A from-import that only exists inside control flow
    can enter this set while staying absent from the module's import map; the
    validation probe then accepts the call unresolved and the boundary pass
    rejects it with RXT030 before this set is ever consulted - the star-import
    case follows the same sequencing.)
    """
    final: dict[str, str | None] = {}

    def clear_fidelity_bindings() -> None:
        # A star import with unknown exports can rebind ANY name - including
        # a fidelity name bound earlier. Keeping the stale binding would be
        # the unsafe direction for this collector, so drop every current
        # fidelity binding (a later fidelity import re-registers).
        for name, target in list(final.items()):
            if target in RUNTIME_FIDELITY_TARGETS:
                final[name] = None

    def bind_import_from(node: ast.ImportFrom) -> None:
        if not node.module or node.level != 0:
            # A relative (or module-less) import still REBINDS its names at
            # module scope - to project code - so it must override an earlier
            # fidelity binding rather than being invisible.
            for alias in node.names:
                if alias.name == "*":
                    clear_fidelity_bindings()
                else:
                    bind_other(alias.asname or alias.name)
            return
        for alias in node.names:
            if alias.name == "*":
                fidelity_module = any(
                    qualname.rpartition(".")[0] == node.module
                    for qualname in RUNTIME_FIDELITY_TARGETS
                )
                if not fidelity_module:
                    # Unknown exports: the star may rebind fidelity names.
                    clear_fidelity_bindings()
                    continue
                for qualname in RUNTIME_FIDELITY_TARGETS:
                    module, _, attr = qualname.rpartition(".")
                    if module == node.module:
                        final[attr] = qualname
                continue
            visible = alias.asname or alias.name
            final[visible] = f"{node.module}.{alias.name}"

    def bind_other(name: str) -> None:
        final[name] = None

    def add_target(target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            bind_other(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                add_target(element)
        elif isinstance(target, ast.Starred):
            add_target(target.value)

    def bind_walrus_targets(node: ast.AST) -> None:
        # A module-level walrus (`(mean := ...)`, `if (mean := ...):`) binds at
        # module scope - including inside a module-level comprehension (PEP
        # 572 leaks the target to the containing scope). Recurse without
        # entering nested function/class BODIES, whose walruses bind in their
        # own scope - but a def/class HEADER (decorators, base list, keyword
        # arguments, parameter defaults, annotations, the return annotation)
        # is evaluated at module scope and can rebind there.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            header_exprs: list[ast.AST] = list(getattr(node, "decorator_list", []))
            if isinstance(node, ast.ClassDef):
                header_exprs.extend(node.bases)
                header_exprs.extend(keyword.value for keyword in node.keywords)
            else:
                arguments = node.args
                header_exprs.extend(default for default in arguments.defaults)
                header_exprs.extend(
                    default for default in arguments.kw_defaults if default is not None
                )
                if not isinstance(node, ast.Lambda):
                    for argument in (
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                        *((arguments.vararg,) if arguments.vararg else ()),
                        *((arguments.kwarg,) if arguments.kwarg else ()),
                    ):
                        if argument.annotation is not None:
                            header_exprs.append(argument.annotation)
                    if node.returns is not None:
                        header_exprs.append(node.returns)
            for expr in header_exprs:
                bind_walrus_targets(expr)
            return
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            bind_other(node.target.id)
        for child in ast.iter_child_nodes(node):
            bind_walrus_targets(child)

    def bind_match_captures(pattern: ast.AST) -> None:
        # Captures live on MatchAs/MatchStar `.name` and MatchMapping `.rest`;
        # the recursion also passes through expression nodes (mapping keys,
        # MatchValue values), which carry no `.name`/`.rest` str attributes -
        # their walruses are collected by the statement-level pre-scan.
        name = getattr(pattern, "name", None)
        if isinstance(name, str):
            bind_other(name)
        rest = getattr(pattern, "rest", None)
        if isinstance(rest, str):
            bind_other(rest)
        for child in ast.iter_child_nodes(pattern):
            bind_match_captures(child)

    def walk(statements: list[ast.stmt]) -> None:
        for node in statements:
            bind_walrus_targets(node)
            if isinstance(node, ast.ImportFrom):
                bind_import_from(node)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bind_other(alias.asname or alias.name.split(".", 1)[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bind_other(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    add_target(target)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                add_target(node.target)
            elif isinstance(node, ast.AugAssign):
                add_target(node.target)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    add_target(target)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                add_target(node.target)
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        add_target(item.optional_vars)
                walk(node.body)
            elif isinstance(node, ast.If):
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, ast.While):
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                walk(node.body)
                for handler in node.handlers:
                    if handler.name is not None:
                        # `except E as name` binds (and later unbinds) the
                        # name at module scope - either way the name does not
                        # denote the fidelity import.
                        bind_other(handler.name)
                    walk(handler.body)
                walk(node.orelse)
                walk(node.finalbody)
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    bind_match_captures(case.pattern)
                    walk(case.body)

    walk(tree.body)
    return frozenset(name for name, target in final.items() if target in RUNTIME_FIDELITY_TARGETS)


def _collect_module_assigned_names(tree: ast.Module) -> frozenset[str]:
    """Names bound by a module-level assignment (for the shadow checker).

    Descends into module-level control-flow bodies (a binding under `if`/`for`/
    `while`/`with`/`try` still shadows at module scope) but not into nested
    function or class bodies (those bind in their own scope). Handles tuple/list
    unpacking and starred targets, augmented assignment, `with ... as`, and `for`
    targets. A bare `AnnAssign` with no value (`len: int`) is *not* a binding, so
    it is excluded (it must not be treated as a shadow).
    """
    names: set[str] = set()

    def add_target(target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Starred):
            add_target(target.value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                add_target(element)

    def walk(statements: list[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    add_target(target)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    add_target(node.target)
            elif isinstance(node, ast.AugAssign):
                add_target(node.target)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                add_target(node.target)
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.While, ast.If)):
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for with_item in node.items:
                    if with_item.optional_vars is not None:
                        add_target(with_item.optional_vars)
                walk(node.body)
            elif isinstance(node, ast.Try):
                walk(node.body)
                walk(node.orelse)
                walk(node.finalbody)
                for handler in node.handlers:
                    walk(handler.body)

    walk(tree.body)
    return frozenset(names)


def _logger_constant_rebinds(node: ast.stmt) -> tuple[frozenset[str], bool]:
    """Return module names a statement may rebind before a logger factory.

    Logger-name constants are a source-order MUST fact.  A conditional store,
    import, definition, or deletion therefore invalidates the previous exact
    value even when it is not a plain top-level ``Assign``.  Nested callable
    bodies are deferred and excluded; their definition-time header expressions
    are still visited.  A star import can replace any existing spelling and is
    represented by the boolean result.
    """

    class RebindVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()
            self.unknown_star = False

        def visit_Name(self, candidate: ast.Name) -> None:
            if isinstance(candidate.ctx, (ast.Store, ast.Del)):
                self.names.add(candidate.id)

        def visit_Import(self, candidate: ast.Import) -> None:
            for imported in candidate.names:
                self.names.add(imported.asname or imported.name.split(".", 1)[0])

        def visit_ImportFrom(self, candidate: ast.ImportFrom) -> None:
            for imported in candidate.names:
                if imported.name == "*":
                    self.unknown_star = True
                else:
                    self.names.add(imported.asname or imported.name)

        def visit_FunctionDef(self, candidate: ast.FunctionDef) -> None:
            self.names.add(candidate.name)
            self._visit_function_header(candidate)

        def visit_AsyncFunctionDef(self, candidate: ast.AsyncFunctionDef) -> None:
            self.names.add(candidate.name)
            self._visit_function_header(candidate)

        def _visit_function_header(self, candidate: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            for decorator in candidate.decorator_list:
                self.visit(decorator)
            for default in candidate.args.defaults:
                self.visit(default)
            for kw_default in candidate.args.kw_defaults:
                if kw_default is not None:
                    self.visit(kw_default)
            for argument in (
                *candidate.args.posonlyargs,
                *candidate.args.args,
                *candidate.args.kwonlyargs,
                *((candidate.args.vararg,) if candidate.args.vararg else ()),
                *((candidate.args.kwarg,) if candidate.args.kwarg else ()),
            ):
                if argument.annotation is not None:
                    self.visit(argument.annotation)
            if candidate.returns is not None:
                self.visit(candidate.returns)

        def visit_Lambda(self, candidate: ast.Lambda) -> None:
            for default in candidate.args.defaults:
                self.visit(default)
            for kw_default in candidate.args.kw_defaults:
                if kw_default is not None:
                    self.visit(kw_default)

        def visit_ClassDef(self, candidate: ast.ClassDef) -> None:
            self.names.add(candidate.name)
            for decorator in candidate.decorator_list:
                self.visit(decorator)
            for base in candidate.bases:
                self.visit(base)
            for keyword in candidate.keywords:
                self.visit(keyword.value)

        def visit_ExceptHandler(self, candidate: ast.ExceptHandler) -> None:
            if candidate.name is not None:
                self.names.add(candidate.name)
            self.generic_visit(candidate)

        def visit_MatchAs(self, candidate: ast.MatchAs) -> None:
            if candidate.name is not None:
                self.names.add(candidate.name)
            if candidate.pattern is not None:
                self.visit(candidate.pattern)

        def visit_MatchStar(self, candidate: ast.MatchStar) -> None:
            if candidate.name is not None:
                self.names.add(candidate.name)

        def visit_MatchMapping(self, candidate: ast.MatchMapping) -> None:
            if candidate.rest is not None:
                self.names.add(candidate.rest)
            self.generic_visit(candidate)

        def _visit_comprehension(self, candidate: ast.AST) -> None:
            generators = candidate.generators  # type: ignore[attr-defined]
            for generator in generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)

        def visit_ListComp(self, candidate: ast.ListComp) -> None:
            self._visit_comprehension(candidate)
            self.visit(candidate.elt)

        def visit_SetComp(self, candidate: ast.SetComp) -> None:
            self._visit_comprehension(candidate)
            self.visit(candidate.elt)

        def visit_GeneratorExp(self, candidate: ast.GeneratorExp) -> None:
            self._visit_comprehension(candidate)
            self.visit(candidate.elt)

        def visit_DictComp(self, candidate: ast.DictComp) -> None:
            self._visit_comprehension(candidate)
            self.visit(candidate.key)
            self.visit(candidate.value)

    visitor = RebindVisitor()
    visitor.visit(node)
    return frozenset(visitor.names), visitor.unknown_star


def _collect_logger_bindings(
    tree: ast.Module,
    imports: dict[str, str],
    module_bindings: ModuleBindings,
    project_mutations: ProjectMutations,
    project_modules: Collection[str],
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """Collect only exact final logger bindings from a clean stdlib constructor."""
    if project_mutations.target_is_mutated("logging.getLogger"):
        return (), {}
    names: set[str] = set()
    groups_by_name: dict[str, tuple[str, ...]] = {}
    constants: dict[str, LoggerNameValues] = {"__name__": frozenset({module_bindings.module_name})}
    for node in tree.body:
        rebound, unknown_star = _logger_constant_rebinds(node)
        if unknown_star:
            constants = {name: None for name in constants}
        else:
            for name in rebound:
                constants[name] = None

        if isinstance(node, ast.Assign):
            value = static_logger_name_values(node.value, constants)
            for assignment_target in node.targets:
                if isinstance(assignment_target, ast.Name):
                    constants[assignment_target.id] = value
            if len(node.targets) != 1:
                continue
            target = node.targets[0]
            groups = (
                logger_call_group_targets(
                    node.value,
                    module_bindings.module_name,
                    constants,
                )
                if isinstance(node.value, ast.Call)
                else ()
            )
            if (
                isinstance(target, ast.Name)
                and is_logging_get_logger_call(node.value, imports, project_modules)
                and module_bindings.lookup(target.id).kind is BindingKind.VALUE
                and module_bindings.lookup(target.id).matches_origin(target)
                and not any(project_mutations.target_is_mutated(group) for group in groups)
                and not project_mutations.target_is_mutated(
                    logger_object_target(module_bindings.module_name, target.id)
                )
            ):
                names.add(target.id)
                groups_by_name[target.id] = groups
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            constants[node.target.id] = static_logger_name_values(node.value, constants)
    ordered = tuple(sorted(names))
    return ordered, {name: groups_by_name[name] for name in ordered}


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
    embedding_enabled: bool,
    project_return_types: dict[str, str],
    project_modules: set[str],
    claim_engine: object | None = None,
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS,
    module_bindings: ModuleBindings | None = None,
) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    # Module-level map of function name -> annotated return type, so the signature
    # inferencer can resolve the type of a nested call argument (callee(producer())).
    return_types: dict[str, str] = {
        item.name: annotation_name(item.returns)
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.returns is not None
        and is_supported_type(item.returns)
    }
    # Every same-module function name (regardless of return annotation), so the
    # shadow check can detect a local that rebinds any sibling function — including
    # forward-referenced or unannotated ones absent from return_types.
    module_function_names: set[str] = {
        item.name for item in tree.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    # Every name bound by a module-level assignment. A module global rebinds the
    # builtin/import/sibling of the same name for all functions in the module
    # (e.g. `len = 5` makes `len(xs)` a TypeError), so the shadow checker treats a
    # call to such a name as shadowed.
    module_assigned_names = _collect_module_assigned_names(tree)
    if module_bindings is None:
        module_bindings = build_module_bindings(tree, module.module_name)
    module_final_bindings = project_final_binding_kinds(module_bindings)
    module.module_bindings = module_bindings
    fidelity_shim_names = _collect_fidelity_shim_names(tree)
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef):
            marker = _proven_native_marker(node, module_bindings)
            raw_marker = next(
                (
                    parsed
                    for decorator in node.decorator_list
                    if (parsed := parse_native_marker(decorator)) is not None
                ),
                None,
            )
            marker_identity_unproven = marker is None and raw_marker is not None
            if marker_identity_unproven:
                marker = _unproven_marker_identity()
            if marker is not None and not _has_proven_exempt_marker(node, module_bindings):
                if marker.error:
                    rejected = _rejected_native_marker_function(
                        node, module, marker, target_language
                    )
                    if marker_identity_unproven:
                        rejected.is_native_candidate = False
                        rejected.explicitly_marked = False
                        rejected.native_target_language = None
                    functions.append(rejected)
                elif _native_marker_applies(marker, target_language):
                    functions.append(
                        _runtime_semantics_function(node, module, marker, target_language)
                    )
            continue
        if not isinstance(node, ast.FunctionDef):
            continue
        calls = collect_call_sites(node, module.imports, module.logger_names)
        has_exempt = _has_proven_exempt_marker(node, module_bindings)
        marker = _proven_native_marker(node, module_bindings)
        raw_marker = next(
            (
                parsed
                for decorator in node.decorator_list
                if (parsed := parse_native_marker(decorator)) is not None
            ),
            None,
        )
        marker_identity_unproven = marker is None and raw_marker is not None
        if marker_identity_unproven:
            marker = _unproven_marker_identity()
        has_marker = marker is not None and not marker_identity_unproven
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
            source_ast_fingerprint=executable_ast_fingerprint(node),
            calls=calls,
            inferred_arg_types=dict(stub_signature.arg_types),
            inferred_return_type=stub_signature.return_type,
            annotated_return_type=(
                annotation_name(node.returns) if node.returns is not None else None
            ),
            native_target_language=_marker_target_language(marker, target_language),
            imports=dict(module.imports),
            logger_names=module.logger_names,
            module_assigned_names=module_assigned_names,
            module_function_names=frozenset(module_function_names),
            module_final_bindings=module_final_bindings,
            module_bindings=module_bindings,
            project_mutations=project_mutations,
            project_modules=frozenset(project_modules),
            call_return_types={**project_return_types, **return_types},
        )
        function.claim_engine = claim_engine  # type: ignore[assignment]
        function.external_accelerator = external_accelerator_for_function(
            node, module.imports, project_modules
        )
        if has_exempt:
            function.is_native_candidate = False
            function.native_target_language = None
        elif marker is not None and marker.error:
            _add_native_marker_diagnostic(function, node, marker)
            if marker_identity_unproven:
                function.native_target_language = None
        elif marker is not None and not _native_marker_applies(marker, target_language):
            function.is_native_candidate = False
        elif has_marker:
            _classify_native_function(
                node, function, return_types, module_function_names, fidelity_shim_names
            )
        elif function.external_accelerator is not None:
            # A recognized external-accelerator decorator (e.g. @numba.njit) keeps
            # the function on the Python fallback intentionally: no auto-discovery,
            # no embedding candidacy, and no RXT010 decorator noise - the external
            # tool compiles it under its own contract. (An explicit @rextio.native
            # marker above still wins and is rejected loudly for the unsupported
            # decorator, surfacing the conflict.)
            function.is_native_candidate = False
            function.native_target_language = None
        elif native_marker == "auto" and _is_auto_native_candidate(
            node,
            function,
            target_language,
            return_types,
            module_function_names,
        ):
            function.is_native_candidate = True
            function.accepted = True
        elif embedding_enabled and _mark_embedding_candidate(
            node,
            function,
            target_language,
            return_types,
            module_function_names,
        ):
            pass
        # Make this function's resolved return type available to later functions'
        # nested-call argument resolution, even when the return type was inferred
        # rather than annotated (annotations are already seeded above). A function
        # defined before its caller is the common case; this closes the false-reject
        # of `caller(): return take(producer())` where producer's int return is
        # inferred. A name not already present (annotated returns take precedence).
        if (
            node.name not in return_types
            and function.inferred_return_type is not None
            and function.inferred_return_type != "None"
        ):
            return_types[node.name] = function.inferred_return_type
        functions.append(function)
    return functions


def _mark_embedding_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    target_language: str,
    return_types: dict[str, str] | None = None,
    module_function_names: set[str] | None = None,
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
        module_assigned_names=function.module_assigned_names,
        module_function_names=function.module_function_names,
        module_final_bindings=function.module_final_bindings,
        module_bindings=function.module_bindings,
        project_mutations=function.project_mutations,
        project_modules=function.project_modules,
        call_return_types=dict(function.call_return_types),
    )
    validate_native_function(node, probe, return_types, module_function_names)
    accepted, reason = is_embedding_candidate(node, probe)
    if not accepted:
        return False
    function.inferred_arg_types = dict(probe.inferred_arg_types)
    function.signature_arg_types = dict(probe.signature_arg_types)
    function.signature_return_type = probe.signature_return_type
    function.call_arg_types = dict(probe.call_arg_types)
    function.call_arg_targets = dict(probe.call_arg_targets)
    function.positional_param_count = probe.positional_param_count
    function.has_keyword_only_params = probe.has_keyword_only_params
    function.inferred_return_type = probe.inferred_return_type
    function.native_target_language = target_language
    function.is_embedding_candidate = True
    function.embedding_reason = reason
    return True


def _is_auto_native_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    target_language: str,
    return_types: dict[str, str] | None = None,
    module_function_names: set[str] | None = None,
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
        module_assigned_names=function.module_assigned_names,
        module_function_names=function.module_function_names,
        module_final_bindings=function.module_final_bindings,
        module_bindings=function.module_bindings,
        project_mutations=function.project_mutations,
        project_modules=function.project_modules,
        call_return_types=dict(function.call_return_types),
        claim_engine=function.claim_engine,
    )
    validate_native_function(node, probe, return_types, module_function_names)
    if probe.accepted:
        function.inferred_arg_types = dict(probe.inferred_arg_types)
        function.signature_arg_types = dict(probe.signature_arg_types)
        function.signature_return_type = probe.signature_return_type
        function.call_arg_types = dict(probe.call_arg_types)
        function.call_arg_targets = dict(probe.call_arg_targets)
        function.positional_param_count = probe.positional_param_count
        function.has_keyword_only_params = probe.has_keyword_only_params
        function.inferred_return_type = probe.inferred_return_type
        function.plugin_claims = list(probe.plugin_claims)
        function.plugin_claim_rejections = list(probe.plugin_claim_rejections)
        function.plugin_type_keys = list(probe.plugin_type_keys)
        function.positional_param_names = probe.positional_param_names
        function.signature_plugin_keys = dict(probe.signature_plugin_keys)
        function.has_resident_signature = probe.has_resident_signature
        function.has_materialized_plugin_type = probe.has_materialized_plugin_type
        function.declared_schemas = dict(probe.declared_schemas)
        # Also preserve the probe's local-binding scope on the accepted auto-native
        # path (declared_schemas above was already copied here) so both accepted
        # routes retain the same analysis facts consistently (WP-4).
        function.local_binding_names = probe.local_binding_names
        function.native_target_language = target_language
        # Carry the probe's non-error diagnostics (e.g. RXT090 divergence
        # notes); an accepted probe has no errors.
        for diagnostic in probe.diagnostics:
            function.add_diagnostic(diagnostic)
        return True
    # Auto-discovered (undecorated) functions are accepted only when they fall
    # within the direct-Rust subset. The Python runtime-semantics shim (RXT080)
    # is reserved for functions a developer explicitly opts into with
    # `@rextio.native`; auto-promoting dynamic functions (e.g. dynamic attribute
    # access) to the shim is too broad. Marked functions are still handled by
    # `_classify_native_function`.
    return False


def _classify_native_function(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    return_types: dict[str, str] | None = None,
    module_function_names: set[str] | None = None,
    fidelity_shim_names: frozenset[str] = frozenset(),
) -> None:
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
        module_assigned_names=function.module_assigned_names,
        module_function_names=function.module_function_names,
        module_final_bindings=function.module_final_bindings,
        module_bindings=function.module_bindings,
        project_mutations=function.project_mutations,
        project_modules=function.project_modules,
        call_return_types=dict(function.call_return_types),
        claim_engine=function.claim_engine,
    )
    validate_native_function(node, probe, return_types, module_function_names)
    function.inferred_arg_types = dict(probe.inferred_arg_types)
    function.signature_arg_types = dict(probe.signature_arg_types)
    function.signature_return_type = probe.signature_return_type
    function.call_arg_types = dict(probe.call_arg_types)
    function.call_arg_targets = dict(probe.call_arg_targets)
    function.positional_param_count = probe.positional_param_count
    function.has_keyword_only_params = probe.has_keyword_only_params
    function.inferred_return_type = probe.inferred_return_type
    function.plugin_claims = list(probe.plugin_claims)
    function.plugin_claim_rejections = list(probe.plugin_claim_rejections)
    function.plugin_type_keys = list(probe.plugin_type_keys)
    function.positional_param_names = probe.positional_param_names
    function.signature_plugin_keys = dict(probe.signature_plugin_keys)
    function.has_resident_signature = probe.has_resident_signature
    function.has_materialized_plugin_type = probe.has_materialized_plugin_type
    # Signature-level analysis facts (computed before/at body validation, so valid
    # for accepted, rejected, and shim probes alike): copy them unconditionally so
    # the finalized analysis never silently loses the probe's local-binding scope or
    # declared schemas — deliberately including the RXT080 shim path, whose generic
    # body ignores them but whose FunctionAnalysis should still be complete (WP-4).
    function.local_binding_names = probe.local_binding_names
    function.declared_schemas = dict(probe.declared_schemas)
    if probe.accepted:
        # Carry the probe's non-error diagnostics (e.g. RXT090 divergence
        # notes) onto the real function; an accepted probe has no errors.
        for diagnostic in probe.diagnostics:
            function.add_diagnostic(diagnostic)
        function.accepted = True
        return
    if _has_source_mutated_receiver_call(node, function):
        # A receiver whose module-visible object/method state was changed cannot
        # enter either direct codegen or the generic runtime-semantics promotion.
        # In particular, logger calls erase the Python receiver when recognized;
        # accepting the same spelling after its proof was invalidated would make
        # route selection depend on whether validation happened before or after
        # logger canonicalization.  Keep the explicit candidate on Python fallback.
        for diagnostic in probe.diagnostics:
            function.add_diagnostic(diagnostic)
        function.accepted = False
        return
    if not _requires_runtime_semantics(node, fidelity_shim_names):
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


def _has_source_mutated_receiver_call(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        receiver = child.func.value
        if not isinstance(receiver, ast.Name):
            continue
        if function.project_mutations.target_is_mutated(
            logger_object_target(function.module_name, receiver.id)
        ):
            return True
    return False


def _requires_runtime_semantics(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    fidelity_shim_names: frozenset[str] = frozenset(),
) -> bool:
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
            # A fidelity-kept stdlib call spelled as a bare from-import name
            # (`from statistics import mean; mean(xs)`): the attribute form
            # already promotes via the unknown-attribute rule above, and the
            # import STYLE must not change the documented marked-function
            # behavior (rejected vs RXT080 shim). `fidelity_shim_names` holds
            # names whose FINAL module-level binder is such an import (order-
            # aware: a def/class/assignment shadowing the import - in either
            # order - rebinds the name to project code and rejects loudly).
            if target is not None and target in fidelity_shim_names:
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
        source_ast_fingerprint=executable_ast_fingerprint(node),
        calls=[],
        native_target_language=_marker_target_language(marker, target_language),
        native_runtime_semantics=True,
        imports=dict(module.imports),
        logger_names=module.logger_names,
        module_bindings=module.module_bindings,
        project_mutations=module.project_mutations,
    )
    # The shim emits `fn {name}`; a function name that can't be lowered (non-raw-able
    # keyword / non-ASCII / `_`) keeps it on Python fallback even though the body
    # qualifies for the shim.
    _validate_function_name(node, function)
    if function.error_diagnostics:
        _mark_shim_rejected(function)
        return function
    _add_runtime_semantics_warning(function, node)
    return function


def _mark_shim_rejected(function: FunctionAnalysis) -> None:
    """Drop a shim candidate to Python fallback after a failed name validation.

    The shim builders pre-set ``native_runtime_semantics=True`` before validating the
    name; clearing it together with ``accepted`` keeps a rejected function from looking
    like a live shim to any consumer that reads the flag without also checking
    ``accepted``. Centralized so a future rejection site cannot reintroduce the
    ``accepted is False and native_runtime_semantics is True`` inconsistency.
    """
    function.accepted = False
    function.native_runtime_semantics = False


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


def _unproven_marker_identity() -> NativeMarker:
    """Return a deterministic rejection for marker-shaped but unproven syntax."""
    return NativeMarker(
        error=(
            "@rextio.native spelling does not resolve to the exact real "
            "Rextio marker at decorator execution time"
        )
    )


def _proven_native_marker(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    bindings: ModuleBindings | None,
) -> NativeMarker | None:
    """Return only a syntactically valid *identity-proven* Rextio marker."""
    if bindings is None:
        return None
    for decorator in node.decorator_list:
        if marker_decorator_is_proven(decorator, bindings, "native"):
            return parse_native_marker_shape(decorator)
    return None


def _has_proven_exempt_marker(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    bindings: ModuleBindings | None,
) -> bool:
    """Whether an exact real ``rextio.exempt`` binding decorates ``node``."""
    if bindings is None:
        return False
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            continue
        if marker_decorator_is_proven(decorator, bindings, "exempt"):
            return True
    return False


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


def _class_construction_instability_reason(
    node: ast.ClassDef,
    module_bindings: ModuleBindings,
    project_mutations: ProjectMutations,
) -> str | None:
    """Return why native method installation cannot trust this runtime class.

    The experimental method surface intentionally proves only ordinary class
    construction: no class decorator, custom base, metaclass/keyword, dynamic
    descriptor, or executing class-body control flow.  Those hooks can replace
    or delete a method after its syntactic ``def`` even when the class name and
    class-body final-binding table look exact.
    """
    return class_construction_stability_reason(
        node,
        module_bindings,
        project_mutations=project_mutations,
    )


def _collect_native_methods(
    tree: ast.Module,
    module: ModuleAnalysis,
    target_language: str,
    module_bindings: ModuleBindings | None = None,
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS,
) -> list[FunctionAnalysis]:
    functions: list[FunctionAnalysis] = []
    if module_bindings is None:
        module_bindings = build_module_bindings(tree, module.module_name)
    trusted_outer_functions = {
        statement.name: statement
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not statement.decorator_list
        and definition_is_final(
            module_bindings,
            statement.name,
            BindingKind.FUNCTION,
            statement.lineno,
            statement.col_offset,
        )
    }
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        # The class must be the module's EXACT final CLASS binding (a later
        # duplicate `class`, or a class overwritten by an assignment/`del`/
        # conditional binder, means Python resolves a different object). And each
        # method must be the class body's final binding for its name — build the
        # class-namespace final bindings from the same source-order authority so a
        # later method/assignment/`del`/conditional in the class body invalidates
        # an earlier method (director follow-up 7, P0-2).
        class_is_final = definition_is_final(
            module_bindings, node.name, BindingKind.CLASS, node.lineno, node.col_offset
        )
        class_instability = _class_construction_instability_reason(
            node,
            module_bindings,
            project_mutations,
        )
        class_bindings = build_module_bindings(
            ast.Module(body=node.body, type_ignores=[]),
            module.module_name,
            trusted_marker_sites=module_bindings.proven_marker_sites,
            trusted_annotation_targets=module_bindings.trusted_annotation_targets,
            trusted_function_bindings=trusted_outer_functions,
        )
        direct_method_ids = {
            id(child)
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        # Walk the class scope (descending class-body control flow) so a method
        # defined under `if`/`for`/`try` is found, not just direct children;
        # round 12 migrated nested-class discovery to this walk but left method
        # collection on direct children (council round 13). Nested-class methods
        # are still handled separately by `_reject_nested_class_methods` (the
        # walk stops at ClassDef boundaries).
        for child in _walk_class_scope(node.body):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            marker = _proven_native_marker(child, module_bindings)
            raw_marker = next(
                (
                    parsed
                    for decorator in child.decorator_list
                    if (parsed := parse_native_marker(decorator)) is not None
                ),
                None,
            )
            marker_identity_unproven = marker is None and raw_marker is not None
            if marker_identity_unproven:
                marker = _unproven_marker_identity()
            if marker is None or _has_proven_exempt_marker(child, module_bindings):
                continue
            if marker.error:
                rejected = _rejected_native_marker_method(
                    child, module, node.name, marker, target_language
                )
                if marker_identity_unproven:
                    rejected.is_native_candidate = False
                    rejected.native_target_language = None
                functions.append(rejected)
                continue
            if not _native_marker_applies(marker, target_language):
                continue
            if id(child) not in direct_method_ids:
                # Defined inside class-body control flow: its definition is
                # conditional and the direct-child ordering the reassignment scan
                # relies on does not apply, so it cannot be safely wrapped. Reject
                # so it stays an ordinary Python method on the fallback and the
                # marker is reported, not dropped silently (council round 13).
                functions.append(
                    _rejected_control_flow_method(child, module, node.name, target_language)
                )
                continue
            non_instance_reason = _non_instance_method_reason(child, node, module_bindings)
            if non_instance_reason is not None:
                # Only regular instance methods are supported (AGENTS.md /
                # docs/unsupported-features.md). A native shim for anything that
                # carries a descriptor - a static/class/property method
                # (aliased or not), an implicit-descriptor dunder, or a method
                # reassigned to one in the class body - would replace the class
                # attribute with a plain function and strip the descriptor,
                # breaking the calling convention; reject so it stays an
                # ordinary Python method on the fallback (council rounds 9-10).
                functions.append(
                    _rejected_non_instance_method(
                        child, module, node.name, target_language, non_instance_reason
                    )
                )
                continue
            if not class_is_final:
                functions.append(
                    _rejected_stale_class_method(
                        child,
                        node,
                        module,
                        module_bindings,
                        f"class {node.name!r} is not the module's final class binding",
                    )
                )
                continue
            if class_instability is not None:
                functions.append(
                    _rejected_stale_class_method(
                        child,
                        node,
                        module,
                        module_bindings,
                        class_instability,
                    )
                )
                continue
            if not definition_is_final(
                class_bindings, child.name, BindingKind.FUNCTION, child.lineno, child.col_offset
            ):
                functions.append(
                    _rejected_stale_class_method(
                        child,
                        node,
                        module,
                        module_bindings,
                        f"method {child.name!r} is not the class body's final binding",
                    )
                )
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
                source_ast_fingerprint=executable_ast_fingerprint(child),
                calls=collect_call_sites(child, module.imports, module.logger_names),
                native_target_language=_marker_target_language(marker, target_language),
                native_runtime_semantics=True,
                imports=dict(module.imports),
                logger_names=module.logger_names,
                module_bindings=module_bindings,
                project_mutations=project_mutations,
                enclosing_class_name=node.name,
                enclosing_class_line=node.lineno,
                enclosing_class_column=node.col_offset,
            )
            # The class-method shim emits `fn {name}(py, args, kwargs)` like the
            # module-level shim, so the method name must be representable in Rust;
            # keep it on Python fallback when it is not (mirrors the validation in
            # `_classify_native_function` / `_runtime_semantics_function`).
            _validate_function_name(child, function)
            if function.error_diagnostics:
                _mark_shim_rejected(function)
                functions.append(function)
                continue
            _add_runtime_semantics_warning(function, child)
            functions.append(function)
        functions.extend(_reject_nested_class_methods(node, node.name, module, target_language))
    return functions


def _reject_nested_class_methods(
    class_node: ast.ClassDef,
    class_path: str,
    module: ModuleAnalysis,
    target_language: str,
) -> list[FunctionAnalysis]:
    """Reject @rextio.native markers on methods of classes nested in a class.

    The analyzer and wrapper generator only collect methods of top-level
    classes; a native marker on a method inside a nested (inner) class was
    previously dropped silently -- neither accepted nor rejected, with no
    diagnostic. Emit an RXT010 diagnostic so the marker is reported as
    unsupported instead of being ignored, honoring the explicit-rejection
    reporting contract (council round 11). Recurses to any nesting depth.
    Nested classes wrapped in class-body control flow (``if``/``for``/``try``/
    ...) are found via ``_walk_class_scope`` too -- round 11's direct-children
    scan missed them (council round 12). Classes nested inside functions are
    out of scope.
    """
    rejected: list[FunctionAnalysis] = []
    for node in _walk_class_scope(class_node.body):
        if not isinstance(node, ast.ClassDef):
            continue
        nested_path = f"{class_path}.{node.name}"
        # Walk the nested class body (descending its own control flow) so a
        # native method defined under `if`/`for`/`try` inside the nested class is
        # rejected too, not silently dropped -- round 13 applied this walk to
        # top-level method collection but left the nested path on direct children
        # (council round 14). The walk stops at ClassDef boundaries, so a
        # deeper-nested class is reached only by the recursive call below.
        for child in _walk_class_scope(node.body):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            marker = _proven_native_marker(child, module.module_bindings)
            raw_marker = next(
                (
                    parsed
                    for decorator in child.decorator_list
                    if (parsed := parse_native_marker(decorator)) is not None
                ),
                None,
            )
            marker_identity_unproven = marker is None and raw_marker is not None
            if marker_identity_unproven:
                marker = _unproven_marker_identity()
            if marker is None or _has_proven_exempt_marker(child, module.module_bindings):
                continue
            if marker.error:
                # Preserve the specific marker-shape error (e.g. an unsupported
                # target) instead of only the nested-class message -- both would
                # carry code RXT010 at the same site and de-dup to one, so route
                # to the marker-error path so the user fixes the marker itself
                # first (council round 12).
                function = _rejected_native_marker_method(
                    child, module, nested_path, marker, target_language
                )
                if marker_identity_unproven:
                    function.is_native_candidate = False
                    function.native_target_language = None
                rejected.append(function)
                continue
            if not _native_marker_applies(marker, target_language):
                continue
            rejected.append(
                _rejected_nested_class_method(child, module, nested_path, target_language)
            )
        rejected.extend(_reject_nested_class_methods(node, nested_path, module, target_language))
    return rejected


def _rejected_nested_class_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    class_path: str,
    target_language: str,
) -> FunctionAnalysis:
    qualname = (
        f"{module.module_name}.{class_path}.{node.name}"
        if module.module_name
        else f"{class_path}.{node.name}"
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
        native_target_language=target_language,
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=(
                "@rextio.native is supported only on methods of top-level classes, "
                "but this method is defined in a nested (inner) class; it stays on "
                "the Python fallback"
            ),
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion="Move the class to module top level, or remove @rextio.native.",
        )
    )
    return function


def _rejected_control_flow_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    class_name: str,
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
        native_target_language=target_language,
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=(
                "@rextio.native is supported only on methods defined directly in the "
                "class body, but this method is defined inside class-body control flow "
                "(if/for/while/with/try); it stays on the Python fallback"
            ),
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion=("Define the method directly in the class body, or remove @rextio.native."),
        )
    )
    return function


def _rejected_stale_class_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_node: ast.ClassDef,
    module: ModuleAnalysis,
    module_bindings: ModuleBindings,
    reason: str,
) -> FunctionAnalysis:
    """Build a rejection for a method whose class/method is not the final binding.

    Python resolves the name to a different class / attribute (a later duplicate
    ``class``, a ``class`` overwritten by an assignment/``del``, or a later
    method/assignment/``del`` in the class body), so installing this method would
    add a stale or missing attribute and diverge from CPython — fail closed to the
    Python fallback (plugin API 1.3, WP-4, director follow-up 7 P0-2).
    """
    qualname = (
        f"{module.module_name}.{class_node.name}.{node.name}"
        if module.module_name
        else f"{class_node.name}.{node.name}"
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
        imports=dict(module.imports),
        logger_names=module.logger_names,
        module_bindings=module_bindings,
        enclosing_class_name=class_node.name,
        enclosing_class_line=class_node.lineno,
        enclosing_class_column=class_node.col_offset,
    )
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=(
                f"native method {qualname} is not installable: {reason}; Python resolves "
                "a different class or attribute, so the wrapper would install a stale or "
                "missing method"
            ),
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion=(
                "Remove the duplicate/overwriting class or method binding, or leave the "
                "method on the Python fallback."
            ),
        )
    )
    return function


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


# Dunder methods Python treats as implicit static/class methods even without a
# decorator: __new__ is an implicit staticmethod; __init_subclass__ and
# __class_getitem__ are implicit classmethods. Wrapping any of them as a plain
# function breaks Python's special dispatch (council round 10).
_IMPLICIT_DESCRIPTOR_METHODS = frozenset({"__new__", "__init_subclass__", "__class_getitem__"})


def _target_binds_name(target: ast.expr, name: str) -> bool:
    """Return True if an assignment target binds ``name`` (bare, unpacked, starred)."""
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, ast.Starred):
        return _target_binds_name(target.value, name)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_binds_name(elt, name) for elt in target.elts)
    return False


# Statement/expression nodes that open a new binding scope. A walk over a class
# body must not descend into these -- their inner assignments and nested classes
# bind that scope, not the enclosing class namespace -- but the boundary node is
# still yielded so a nested class remains discoverable (council round 12).
_SCOPE_BOUNDARY_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
)


def _walk_class_scope(nodes: Iterable[ast.AST]) -> Iterable[ast.AST]:
    """Yield every node reachable from ``nodes`` within one class scope.

    Descends through compound statements (``if``/``for``/``while``/``with``/
    ``try``/``match``) and expressions so a class-body assignment or nested
    class wrapped in control flow is still found, but stops at nested
    function/class/lambda scopes (yielding the boundary node itself, not its
    body). Python executes a class body -- including its compound statements --
    at class-definition time, so anything reached here binds the class
    namespace; round 11's direct-children-only scan missed these (round 12).
    """
    for node in nodes:
        yield node
        if isinstance(node, _SCOPE_BOUNDARY_NODES):
            continue
        yield from _walk_class_scope(ast.iter_child_nodes(node))


def _header_scope_exprs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda,
) -> list[ast.AST]:
    """Return a def/class/lambda's sub-expressions evaluated in the enclosing scope.

    These are decorators, base list, keyword args, parameter defaults, and
    annotations -- a walrus in any of them binds the enclosing (class) scope
    even though the node's body does not (council round 13).
    """
    header: list[ast.AST] = list(getattr(node, "decorator_list", []))
    if isinstance(node, ast.ClassDef):
        header.extend(node.bases)
        header.extend(keyword.value for keyword in node.keywords)
        return header
    arguments = node.args  # FunctionDef / AsyncFunctionDef / Lambda
    header.extend(arguments.defaults)
    header.extend(default for default in arguments.kw_defaults if default is not None)
    if not isinstance(node, ast.Lambda):
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *((arguments.vararg,) if arguments.vararg else ()),
            *((arguments.kwarg,) if arguments.kwarg else ()),
        ):
            if argument.annotation is not None:
                header.append(argument.annotation)
        if node.returns is not None:
            header.append(node.returns)
    return header


def _expr_walrus_binds(node: ast.AST, name: str) -> bool:
    """Return True if a walrus (``:=``) target binds ``name`` at the enclosing scope.

    Does not enter a nested function/class/lambda BODY (its walruses bind that
    scope), but does inspect the node's HEADER expressions, which are evaluated
    in the enclosing scope (council round 13).
    """
    if isinstance(node, _SCOPE_BOUNDARY_NODES):
        return any(_expr_walrus_binds(expr, name) for expr in _header_scope_exprs(node))
    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        if node.target.id == name:
            return True
    return any(_expr_walrus_binds(child, name) for child in ast.iter_child_nodes(node))


def _match_pattern_binds_name(pattern: ast.AST, name: str) -> bool:
    """Return True if a match capture pattern binds ``name``.

    Covers ``case x``, ``case [*x]``, ``case {**x}``, and ``case ... as x``.
    """
    captured = getattr(pattern, "name", None)
    if isinstance(captured, str) and captured == name:
        return True
    rest = getattr(pattern, "rest", None)
    if isinstance(rest, str) and rest == name:
        return True
    return any(_match_pattern_binds_name(child, name) for child in ast.iter_child_nodes(pattern))


def _statements_bind_name(statements: Iterable[ast.stmt], name: str) -> bool:
    return any(_statement_rebinds_name(statement, name) for statement in statements)


_AST_TYPE_ALIAS = getattr(ast, "TypeAlias", None)  # Python 3.12+ `type X = ...`


def _statement_rebinds_name(statement: ast.stmt, name: str) -> bool:
    """Return True if executing ``statement`` in a class body rebinds ``name``.

    Comprehensive over Python's class-scope binding forms, mirroring the
    module-scope enumeration in ``_collect_fidelity_shim_names``: plain/annotated
    (value-bearing)/augmented assignment and walrus targets; ``for``/``with``/
    ``except``-as; ``match`` captures; ``import``-as; ``del``; a later ``def``/
    ``class`` of the same name; a ``type`` alias (3.12+); and a walrus in a
    def/class HEADER (decorators, bases, defaults, annotations). Descends into
    class-body compound statements but not into nested function/class/lambda
    BODIES, whose bindings are local to that scope. Round 12's scan only handled
    Assign/AnnAssign/AugAssign/NamedExpr and missed the rest (council round 13).
    """
    # Walrus anywhere in this statement's expressions (incl. def/class headers).
    if _expr_walrus_binds(statement, name):
        return True
    if isinstance(statement, ast.Assign):
        return any(_target_binds_name(target, name) for target in statement.targets)
    if isinstance(statement, ast.AnnAssign):
        return statement.value is not None and _target_binds_name(statement.target, name)
    if isinstance(statement, ast.AugAssign):
        return _target_binds_name(statement.target, name)
    if isinstance(statement, ast.Delete):
        return any(_target_binds_name(target, name) for target in statement.targets)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return any(
            (alias.asname or alias.name.split(".", 1)[0]) == name for alias in statement.names
        )
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        # A later def/class of the same name overrides the method (its header
        # walrus was already handled above).
        return statement.name == name
    if _AST_TYPE_ALIAS is not None and isinstance(statement, _AST_TYPE_ALIAS):
        alias_name = getattr(statement, "name", None)
        return isinstance(alias_name, ast.Name) and alias_name.id == name
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return (
            _target_binds_name(statement.target, name)
            or _statements_bind_name(statement.body, name)
            or _statements_bind_name(statement.orelse, name)
        )
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        if any(
            item.optional_vars is not None and _target_binds_name(item.optional_vars, name)
            for item in statement.items
        ):
            return True
        return _statements_bind_name(statement.body, name)
    if isinstance(statement, ast.If):
        return _statements_bind_name(statement.body, name) or _statements_bind_name(
            statement.orelse, name
        )
    if isinstance(statement, ast.While):
        return _statements_bind_name(statement.body, name) or _statements_bind_name(
            statement.orelse, name
        )
    if isinstance(statement, (ast.Try, ast.TryStar)):
        if any(handler.name == name for handler in statement.handlers):
            return True
        if _statements_bind_name(statement.body, name):
            return True
        if any(_statements_bind_name(handler.body, name) for handler in statement.handlers):
            return True
        return _statements_bind_name(statement.orelse, name) or _statements_bind_name(
            statement.finalbody, name
        )
    if isinstance(statement, ast.Match):
        for case in statement.cases:
            if _match_pattern_binds_name(case.pattern, name):
                return True
            if _statements_bind_name(case.body, name):
                return True
        return False
    return False


def _non_instance_method_reason(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_node: ast.ClassDef,
    module_bindings: ModuleBindings,
) -> str | None:
    """Return why a native-marked method is not a plain instance method, else None.

    Only a plain instance method can be safely replaced by the generated
    wrapper; anything that carries or becomes a descriptor would have that
    descriptor stripped (council round 10). Covers: any decorator besides the
    native marker (``@property``/``@cached_property``/``@staticmethod``/
    ``@classmethod``, aliased or not, and custom descriptors); the implicit
    descriptor dunders; and a class-body reassignment of the method name.
    """
    extra = [
        decorator
        for decorator in node.decorator_list
        if not marker_decorator_is_proven(decorator, module_bindings, "native")
    ]
    if extra:
        names = ", ".join(
            dotted_name(d.func if isinstance(d, ast.Call) else d) or "<decorator>" for d in extra
        )
        return f"it carries a non-@rextio.native decorator ({names})"
    if node.name in _IMPLICIT_DESCRIPTOR_METHODS:
        return f"{node.name} is an implicit descriptor method"
    # A `global name` / `nonlocal name` declaration anywhere in the class body
    # redirects the method's own `def` to bind the module/enclosing scope, so the
    # class attribute is never created -- CPython leaves `Cls.name` absent, and a
    # generated wrapper resolving `<fallback>.Cls.name` would fail at import. The
    # declaration must lexically precede the def (`global` after an assignment is
    # a SyntaxError), so it is missed by the after-def reassignment scan below;
    # check the whole class scope for it (council round 14).
    if any(
        isinstance(statement, (ast.Global, ast.Nonlocal)) and node.name in statement.names
        for statement in _walk_class_scope(class_node.body)
    ):
        return (
            f"{node.name} is declared global/nonlocal in the class body "
            f"(its definition binds an outer scope, not a class attribute)"
        )
    # A class-body reassignment of the method name AFTER its definition makes the
    # final class attribute something other than this plain method: a descriptor
    # (``name = staticmethod(name)``, aliased or dotted), or any other binding.
    # Wrapping it would strip/replace that binding, so reject conservatively --
    # mirroring the decorator branch's "any non-native decorator => reject" stance
    # so no new spelling (annotated, unpacked, aliased-wrapper) can slip through
    # (council round 11). Only reassignments that lexically FOLLOW the definition
    # count; an assignment before the def is overridden by the def itself.
    seen_def = False
    for statement in class_node.body:
        if statement is node:
            seen_def = True
            continue
        if not seen_def:
            continue
        if _statement_rebinds_name(statement, node.name):
            return (
                "it is reassigned after its definition in the class body "
                "(the final class attribute would not be this instance method)"
            )
    return None


def _rejected_non_instance_method(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    class_name: str,
    target_language: str,
    reason: str,
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
        native_target_language=target_language,
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=(
                f"@rextio.native is supported only on regular instance methods, "
                f"but {reason}; the method stays on the Python fallback"
            ),
            file_path=function.file_path,
            line=node.lineno,
            column=node.col_offset,
            function_name=function.qualname,
            suggestion="Remove @rextio.native, or make it a plain instance method.",
        )
    )
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


def _literal_arg_type(node: ast.expr) -> str | None:
    """Return the scalar type name of a literal-constant argument, else None.

    Only directly-readable literals (``ast.Constant``) yield a type here; this is
    intentionally env-free so it can run at call-collection time. ``bool`` is
    checked before ``int`` because ``True``/``False`` are ``int`` instances.
    """
    if not isinstance(node, ast.Constant):
        return None
    value = node.value
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, bytes):
        return "bytes"
    return None


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
        # The iterable expression is evaluated once, before the first
        # iteration, so its calls carry the ENCLOSING loop depth only.
        self.visit(node.iter)
        self.loop_depth += 1
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        self.loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        # The test expression re-evaluates on every iteration, so its calls
        # are loop-positioned just like calls in the body.
        self.loop_depth += 1
        self.visit(node.test)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        self.loop_depth -= 1

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        # A comprehension is a loop: its element expression, conditions, and
        # every generator after the first run once per iteration. Only the
        # FIRST generator's iterable is evaluated once, before iteration
        # starts, so it keeps the enclosing depth (same rule as a for-loop
        # iterable).
        generators = node.generators
        if generators:
            self.visit(generators[0].iter)
        self.loop_depth += 1
        for index, comprehension in enumerate(generators):
            if index > 0:
                self.visit(comprehension.iter)
            self.visit(comprehension.target)
            for condition in comprehension.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.loop_depth -= 1

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

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
                arg_types=tuple(_literal_arg_type(arg) for arg in node.args),
            )
        )
        self.generic_visit(node)


def collect_call_sites(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str] | None = None,
    logger_names: tuple[str, ...] = (),
) -> list[CallSite]:
    """Collect the call sites within a function body, noting which are inside loops."""
    collector = _CallCollector(imports or {}, logger_names)
    collector.visit(node)
    return collector.calls
