"""Project file discovery and the analyze_project entry point."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import replace
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.boundary import apply_boundary_checks
from rextio.analyzer.callable_metadata import index_project_symbols
from rextio.analyzer.common_calls import (
    MUTATION_WATCHED_EXTERNAL_MODULES,
)
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.final_bindings import (
    BindingKind,
    ModuleBindings,
    ProjectBindings,
    ProjectCallable,
    ProjectMutations,
    build_module_bindings,
    collect_module_mutations,
)
from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.module_parser import (
    _collect_imports,
    module_name_for_path,
    parse_module,
)
from rextio.analyzer.stub_inputs import (
    StubInputSnapshot,
    capture_sibling_stub_inputs,
)
from rextio.analyzer.plugin_claims import ClaimEngine
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.config.schema import ImportsConfig, RextioConfig
from rextio.plugins.models import PluginRegistry, RextioPlugin
from rextio.source.authorization import verify_external_source_authorization
from rextio.source.external import resolve_external_source_plan
from rextio.targets.models import normalize_target_language

if TYPE_CHECKING:
    from rextio.build.full_c6_host_inputs import FullC6AnalysisScope
    from rextio.source.external_linkage import ExternalNativeRegistry

IGNORED_PARTS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".rextio",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


def scan_python_files(
    project_root: Path,
    *,
    full_c6_analysis_scope: FullC6AnalysisScope | None = None,
    full_c6_config: RextioConfig | None = None,
) -> list[Path]:
    """Return project Python files under ordinary or sealed Full C6 rules."""
    root = project_root.resolve()
    vendor_root: Path | None = None
    if full_c6_analysis_scope is None:
        ignore_patterns = load_rextioignore(root)
    else:
        from rextio.build.full_c6_host_inputs import (
            FullC6HostInputsError,
            require_full_c6_analysis_scope,
        )

        if type(full_c6_config) is not RextioConfig:
            raise FullC6HostInputsError(
                "Full C6 analysis scope lacks its exact typed config"
            )
        vendor_root = require_full_c6_analysis_scope(
            full_c6_analysis_scope,
            project_root=root,
            config=full_c6_config,
        )
        # Custom ignore bytes are not part of the bounded Full C6 input
        # closure.  Scope validation requires absence, and strict discovery
        # never reads the file even during a create/delete race.
        ignore_patterns = []
    files: list[Path] = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if vendor_root is not None and path.is_relative_to(vendor_root):
            continue
        if _is_ignored(relative, ignore_patterns):
            continue
        files.append(path)
    result = sorted(files)
    if full_c6_analysis_scope is not None:
        assert full_c6_config is not None  # exact type established above
        final_vendor_root = require_full_c6_analysis_scope(
            full_c6_analysis_scope,
            project_root=root,
            config=full_c6_config,
        )
        if final_vendor_root != vendor_root:
            raise FullC6HostInputsError("Full C6 analysis vendor identity changed")
    return result


def load_rextioignore(project_root: Path) -> list[str]:
    """Load the .rextioignore patterns for the project, if present."""
    path = project_root / ".rextioignore"
    if not path.exists():
        return []
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _is_ignored(relative: Path, ignore_patterns: list[str]) -> bool:
    parts = relative.parts
    if any(part in IGNORED_PARTS for part in parts):
        return True
    relative_text = relative.as_posix()
    for pattern in ignore_patterns:
        normalized = pattern.strip("/")
        if not normalized:
            continue
        if pattern.endswith("/"):
            if normalized in parts or relative_text.startswith(f"{normalized}/"):
                return True
            continue
        if fnmatch(relative_text, normalized) or fnmatch(relative.name, normalized):
            return True
        if relative_text == normalized or relative_text.startswith(f"{normalized}/"):
            return True
    return False


def analyze_project(
    project_root: Path | str,
    boundary_warnings: bool = True,
    native_marker: str = "auto",
    target_language: str = "rust",
    native_top_level: bool = False,
    imports_config: ImportsConfig | None = None,
    active_plugins: Iterable[RextioPlugin] = (),
    embedding_enabled: bool = False,
    delegate_fallback: bool = False,
    plugin_registry: PluginRegistry | None = None,
    plugin_config: RextioConfig | None = None,
    external_native_registry: ExternalNativeRegistry | None = None,
    full_c6_analysis_scope: FullC6AnalysisScope | None = None,
) -> ProjectAnalysis:
    """Analyze a project directory and return its ProjectAnalysis.

    When ``delegate_fallback`` is set (the Rust-executable delegate mode), a
    direct-native function that calls a project function living on the Python
    fallback records it as a delegated call instead of being rejected, so the
    generated binary can invoke it through the external CPython dispatcher.

    ``plugin_registry``/``plugin_config`` enable the plugin claim pass
    (docs/specs/plugin-lowering.md): when the registry carries lowering
    providers, their annotation vocabularies resolve and covered sites are
    offered for claiming.
    """
    root = Path(project_root).resolve()
    target_language = normalize_target_language(target_language)
    analysis = ProjectAnalysis(project_root=root)
    files = scan_python_files(
        root,
        full_c6_analysis_scope=full_c6_analysis_scope,
        full_c6_config=plugin_config,
    )
    analysis._full_c6_analysis_scope = full_c6_analysis_scope
    stub_inputs = capture_sibling_stub_inputs(root, tuple(files))
    analysis._stub_inputs = stub_inputs
    project_modules = _project_module_names(files, root)
    project_return_types = _project_annotated_return_types(files, root, stub_inputs)
    trusted_annotation_targets = frozenset(
        annotation
        for binding in (() if plugin_registry is None else plugin_registry.types)
        for annotation in binding.plugin_type.annotations
    )
    trusted_annotation_modules = frozenset(
        target.split(".", 1)[0] for target in trusted_annotation_targets
    )
    project_mutations = _collect_project_mutations(
        files,
        root,
        project_modules,
        watched_modules=trusted_annotation_modules,
    )
    project_bindings = _build_project_bindings(
        files,
        root,
        project_mutations,
        project_modules,
        trusted_annotation_targets,
    )
    claim_engine: ClaimEngine | None = None
    if plugin_registry is not None and plugin_registry.providers:
        # Build the project-wide function/class index BEFORE the claim pass so
        # callable- and schema-metadata resolution is order-independent across
        # modules (a callable defined in a not-yet-parsed module still resolves).
        symbol_index = index_project_symbols(
            files,
            root,
            module_name_for_path,
            _collect_imports,
            project_bindings=project_bindings,
            project_mutations=project_mutations,
            project_modules=project_modules,
        )
        claim_engine = ClaimEngine(
            plugin_registry, plugin_config or RextioConfig(), symbol_index=symbol_index
        )
    analysis.project_mutations = project_mutations
    analysis.project_bindings = project_bindings
    analysis.modules = [
        parse_module(
            path,
            root,
            native_marker=native_marker,
            target_language=target_language,
            native_top_level=native_top_level,
            project_modules=project_modules,
            imports_config=imports_config,
            active_plugins=active_plugins,
            embedding_enabled=embedding_enabled,
            project_return_types=project_return_types,
            claim_engine=claim_engine,
            project_mutations=project_mutations,
            project_bindings=project_bindings,
            stub_inputs=stub_inputs,
        )
        for path in files
    ]
    apply_boundary_checks(
        analysis,
        boundary_warnings=boundary_warnings,
        embedding_enabled=embedding_enabled,
        delegate_fallback=delegate_fallback,
        external_native_registry=external_native_registry,
    )
    _strip_divergence_notes_from_non_native(analysis)
    _note_plugin_lowerable_accelerated(analysis, tuple(active_plugins))
    if imports_config is not None:
        plan = resolve_external_source_plan(imports_config, analysis)
        if plan is not None:
            authorization = verify_external_source_authorization(root, plan)
            analysis.external_source_plan = replace(plan, authorization=authorization)
    return analysis


def _note_plugin_lowerable_accelerated(
    analysis: ProjectAnalysis, active_plugins: tuple[RextioPlugin, ...]
) -> None:
    """Attach the RXT091 hint to accelerator-decorated, plugin-covered functions.

    Informational and non-rejecting: an accelerator decorator is the user's
    explicit opt-in to that tool's semantics, so the function stays on the
    ``fallback-accelerated`` route. The hint only notes that an active
    rule-providing (v2) plugin covers a package the function's module imports,
    so removing the decorator could promote the function to plugin-lowered,
    CPython-exact native code.
    """
    rule_plugins = [
        plugin
        for plugin in active_plugins
        # Require lowering, not just rule records: a describe-only plugin
        # cannot lower anything, so removing the decorator would not
        # promote the function through it (council round 8).
        if plugin.rules_provided and plugin.lowering_provided and plugin.packages
    ]
    if not rule_plugins:
        return
    for module in analysis.modules:
        imported_packages = {target.split(".")[0] for target in module.imports.values()}
        if not imported_packages:
            continue
        for function in module.functions:
            if function.external_accelerator is None:
                continue
            covering = [
                plugin for plugin in rule_plugins if imported_packages.intersection(plugin.packages)
            ]
            if not covering:
                continue
            plugin_ids = ", ".join(sorted(plugin.id for plugin in covering))
            function.add_diagnostic(
                Diagnostic(
                    code="RXT091",
                    severity="info",
                    message=(
                        f"{function.external_accelerator}-decorated function is in a "
                        f"module importing a package covered by an active Rextio plugin "
                        f"({plugin_ids}); it MAY be plugin-lowerable if the decorator is "
                        "removed (import-based hint - the function body is not analyzed)"
                    ),
                    file_path=function.file_path,
                    line=function.line,
                    column=function.column,
                    function_name=function.qualname,
                    suggestion=(
                        "The decorator is an explicit opt-in to the accelerator's "
                        "semantics and is respected as-is. Remove it only if "
                        "CPython-exact native lowering is preferred over "
                        f"{function.external_accelerator} for this function."
                    ),
                )
            )


def _strip_divergence_notes_from_non_native(analysis: ProjectAnalysis) -> None:
    """Drop RXT090 divergence notes from functions not on the direct native path.

    The notes are emitted during body validation, before acceptance is decided;
    a function that ends up rejected or on the runtime-semantics shim executes
    real CPython, so the noted divergence cannot occur there.
    """
    for module in analysis.modules:
        for function in module.functions:
            direct_native = function.accepted and not function.native_runtime_semantics
            if not direct_native:
                function.diagnostics = [
                    diagnostic for diagnostic in function.diagnostics if diagnostic.code != "RXT090"
                ]


def _project_annotated_return_types(
    files: list[Path],
    project_root: Path,
    snapshot: StubInputSnapshot | None = None,
) -> dict[str, str]:
    """Collect supported top-level function return annotations by qualified name.

    A sibling ``.pyi`` stub's return annotation overrides the source annotation,
    mirroring the per-function resolution order used everywhere else
    (``signature_return_type or inferred_return_type or annotated_return_type``,
    where the stub return is the *inferred* type). Without the stub pass, a
    callee typed only in a ``.pyi`` stayed untyped at cross-module call sites, so
    a type-incompatible use of its result (e.g. ``stub_str_fn(x) + 1``) slipped
    past validation into a Rust compile failure instead of a clean rejection.
    """
    return_types: dict[str, str] = {}
    for path in files:
        module_name = module_name_for_path(path, project_root)

        def _qualname(name: str) -> str:
            return f"{module_name}.{name}" if module_name else name

        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for item in tree.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.returns is not None
                and is_supported_type(item.returns)
            ):
                return_types[_qualname(item.name)] = annotation_name(item.returns)
        if snapshot is None:
            stub_path = path.with_suffix(".pyi")
            if not stub_path.exists():
                continue
            try:
                stub_source = stub_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            stub_filename = str(stub_path)
        else:
            record = snapshot.for_source(path)
            if not record.analyzer_consumable:
                continue
            record_text = record.text
            if not isinstance(record_text, str):
                continue
            stub_source = record_text
            stub_filename = record.stub_path
        try:
            stub_tree = ast.parse(stub_source, filename=stub_filename)
        except (MemoryError, SyntaxError, RecursionError):
            continue
        for item in stub_tree.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.returns is not None
                and is_supported_type(item.returns)
            ):
                return_types[_qualname(item.name)] = annotation_name(item.returns)
    return return_types


def _build_project_bindings(
    files: list[Path],
    project_root: Path,
    project_mutations: ProjectMutations,
    project_modules: set[str],
    trusted_annotation_targets: frozenset[str] = frozenset(),
) -> ProjectBindings:
    """Build the single shared final-binding authority for every project module.

    One ``ModuleBindings`` per module, built once here and threaded everywhere
    (module parsing, the resolver, the build gate) so no path re-derives a
    divergent copy — even when no plugin is active (director follow-up 7, P1-4).
    """
    by_module: dict[str, ModuleBindings] = {}
    for path in files:
        module_name = module_name_for_path(path, project_root)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        by_module[module_name] = build_module_bindings(
            tree,
            module_name,
            project_mutations=project_mutations,
            project_modules=project_modules,
            trusted_annotation_targets=trusted_annotation_targets,
        )
    return ProjectBindings(by_module)


def _collect_project_mutations(
    files: list[Path],
    project_root: Path,
    project_modules: set[str],
    *,
    watched_modules: Iterable[str] = (),
) -> ProjectMutations:
    """Aggregate every project module's module-load attribute mutations.

    A pre-pass (like ``_project_annotated_return_types``) so the mutation
    authority is known before any module is parsed and is shared project-wide:
    a ``pkg/app.py`` doing ``import pkg.helper as h; h.good = …`` marks
    ``pkg.helper.good`` mutated for the WHOLE project, blocking a direct-native
    call/import/re-export that reaches it (director follow-up 7, P0-4).
    """
    watched = frozenset({*MUTATION_WATCHED_EXTERNAL_MODULES, *watched_modules})
    project_callables = _build_project_callable_registry(
        files,
        project_root,
        project_modules,
    )

    def scan_with(
        callable_registry: dict[str, ProjectCallable],
        known_mutations: ProjectMutations,
    ) -> ProjectMutations:
        specific: dict[str, set[str]] = {}
        unknown: set[str] = set()
        for path in files:
            module_name = module_name_for_path(path, project_root)
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except SyntaxError:
                continue
            imports = _collect_imports(tree, module_name, path.name == "__init__.py")
            module_specific, module_unknown = collect_module_mutations(
                tree,
                imports,
                project_modules,
                module_name=module_name,
                watched_modules=watched,
                is_package_module=path.name == "__init__.py",
                project_callables=callable_registry,
                known_mutations=known_mutations,
            )
            for target_module, attrs in module_specific.items():
                specific.setdefault(target_module, set()).update(attrs)
            unknown |= module_unknown
        return ProjectMutations(
            {module: frozenset(attrs) for module, attrs in specific.items()},
            frozenset(unknown),
        )

    # A source-final function is executable by exact identity only while its
    # owning module attribute is itself untouched during project import.  The
    # first replay can discover such a mutation; remove every affected target
    # and replay until the registry stabilizes.  Removal is monotone and
    # bounded by the finite registry.  A subsequent call through a removed
    # target then fails closed in ``collect_module_mutations`` instead of
    # replaying stale source (follow-up 11).
    mutations = ProjectMutations({}, frozenset())
    while True:
        # Builtin/stdlib identity is process-global.  Re-scan all modules until
        # facts discovered by one module have revoked every other module's
        # purity shortcuts.  The union is monotone, so this finite authority
        # always converges even when callable replay is subsequently narrowed.
        while True:
            discovered = scan_with(project_callables, mutations)
            merged_specific: dict[str, frozenset[str]] = {
                receiver: frozenset(paths) for receiver, paths in mutations.by_module.items()
            }
            for receiver, paths in discovered.by_module.items():
                merged_specific[receiver] = merged_specific.get(receiver, frozenset()) | paths
            merged = ProjectMutations(
                merged_specific,
                mutations.unknown_modules | discovered.unknown_modules,
            )
            if merged == mutations:
                break
            mutations = merged
        exact_callables = {
            target: record
            for target, record in project_callables.items()
            if not mutations.target_is_mutated(target)
        }
        if len(exact_callables) == len(project_callables):
            return mutations
        project_callables = exact_callables


def _build_project_callable_registry(
    files: list[Path],
    project_root: Path,
    project_modules: set[str],
) -> dict[str, ProjectCallable]:
    """Index exact undecorated project functions for module-load replay.

    This is deliberately a source-only registry: no function is executed.  A
    decorated, conditional, overwritten, deleted, star-shadowed, or otherwise
    non-final function is absent so an import-time call through it fails closed
    in :func:`collect_module_mutations`.
    """
    parsed: dict[str, tuple[ast.Module, bool, ModuleBindings]] = {}
    for path in files:
        module_name = module_name_for_path(path, project_root)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        bindings = build_module_bindings(
            tree,
            module_name,
            project_modules=project_modules,
        )
        parsed[module_name] = (tree, path.name == "__init__.py", bindings)

    exact_nodes: dict[str, ast.FunctionDef] = {}
    # A project function reads globals when it is *called*, not when the source
    # file has reached its final statement.  This distinction is observable for
    # circular imports: another module can call a function while its owner is
    # paused in the middle of execution.  Keep the complete source-order import
    # history from the definition onward instead of taking one final snapshot.
    # Import-edge snapshots below let a replay in the same strongly connected
    # component select the state at which the owner can be suspended; ordinary
    # non-cyclic calls still receive the exact final environment.
    import_history_by_target: dict[str, dict[str, set[str]]] = {}
    import_edge_states: dict[str, list[tuple[str, dict[str, str]]]] = {}
    import_graph: dict[str, set[str]] = {module: set() for module in parsed}
    final_imports_by_module: dict[str, dict[str, str]] = {}

    def imported_project_module(target: str) -> str | None:
        candidates = [
            candidate
            for candidate in parsed
            if target == candidate or target.startswith(f"{candidate}.")
        ]
        return max(candidates, key=len) if candidates else None

    for module_name, (tree, is_package, bindings) in parsed.items():
        final_imports_by_module[module_name] = _collect_imports(
            tree,
            module_name,
            is_package,
            bindings,
        )
        current_imports: dict[str, str] = {}
        active_targets: list[str] = []

        def remember_current_imports() -> None:
            for target in active_targets:
                history = import_history_by_target[target]
                for name, import_target in current_imports.items():
                    history.setdefault(name, set()).add(import_target)

        def import_from_base(node: ast.ImportFrom) -> str | None:
            if not node.level:
                return node.module
            package = module_name.split(".") if module_name else []
            if not is_package and package:
                package.pop()
            ascend = node.level - 1
            if ascend > len(package):
                return None
            if ascend:
                package = package[:-ascend]
            if node.module:
                package.extend(node.module.split("."))
            return ".".join(package)

        def remember_import_edge(import_target: str | None, state: dict[str, str]) -> None:
            if import_target is None:
                return
            imported_module = imported_project_module(import_target)
            if imported_module is None:
                return
            import_graph[module_name].add(imported_module)
            for callable_target in active_targets:
                import_edge_states.setdefault(callable_target, []).append(
                    (imported_module, dict(state))
                )

        class ExecutedImportVisitor(ast.NodeVisitor):
            """Collect imports that execute now, excluding deferred bodies."""

            def __init__(self) -> None:
                self.nodes: list[ast.Import | ast.ImportFrom] = []

            def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
                self.nodes.append(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
                self.nodes.append(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
                del node

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
                del node

            def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
                del node

        def nested_executed_imports(node: ast.stmt) -> list[ast.Import | ast.ImportFrom]:
            visitor = ExecutedImportVisitor()
            visitor.visit(node)
            return visitor.nodes

        def remember_import_node_edges(
            import_node: ast.Import | ast.ImportFrom,
            state: dict[str, str],
        ) -> None:
            if isinstance(import_node, ast.Import):
                for imported in import_node.names:
                    remember_import_edge(imported.name, state)
                return
            if import_node.module == "__future__" and not import_node.level:
                return
            base = import_from_base(import_node)
            for imported in import_node.names:
                import_target = (
                    base
                    if imported.name == "*"
                    else f"{base}.{imported.name}"
                    if base
                    else imported.name
                )
                remember_import_edge(import_target, state)

        for node in tree.body:
            if (
                isinstance(node, ast.FunctionDef)
                and not node.decorator_list
                and bindings.lookup(node.name).kind is BindingKind.FUNCTION
                and bindings.lookup(node.name).matches_origin(node)
            ):
                target = f"{module_name}.{node.name}" if module_name else node.name
                exact_nodes[target] = node
                current_imports.pop(node.name, None)
                import_history_by_target[target] = {
                    name: {import_target} for name, import_target in current_imports.items()
                }
                active_targets.append(target)
                remember_current_imports()
                continue

            if isinstance(node, ast.Import):
                for imported in node.names:
                    # IMPORT_NAME executes the dependency before STORE_NAME
                    # publishes this alias.  A circular callback therefore sees
                    # the exact pre-binding environment.
                    remember_import_edge(imported.name, current_imports)
                    visible = imported.asname or imported.name.split(".", 1)[0]
                    current_imports[visible] = imported.name if imported.asname else visible
            elif isinstance(node, ast.ImportFrom):
                if node.module == "__future__" and not node.level:
                    remember_current_imports()
                    continue
                base = import_from_base(node)
                for imported in node.names:
                    import_target = (
                        base
                        if imported.name == "*"
                        else f"{base}.{imported.name}"
                        if base
                        else imported.name
                    )
                    # As above, the imported module can call back before
                    # IMPORT_FROM/STORE_NAME replaces the visible name.
                    remember_import_edge(import_target, current_imports)
                    if imported.name == "*":
                        current_imports.clear()
                        continue
                    visible = imported.asname or imported.name
                    assert import_target is not None
                    current_imports[visible] = import_target
            else:
                # Reuse the final-binding walk for every module-scope binder,
                # including walrus and binders nested in if/for/with/try/match.
                # Forgetting a possibly rebound import alias is deliberate: its
                # absence makes callable replay widen instead of resurrecting a
                # stale root.  Imports nested in immediately executed control
                # flow/class bodies still contribute graph edges, using this
                # widened pre-edge state.
                statement_authority = build_module_bindings(
                    ast.Module(body=[node], type_ignores=[]),
                    module_name,
                    project_modules=project_modules,
                )
                for bound_name in statement_authority.entries:
                    current_imports.pop(bound_name, None)
                if statement_authority.last_unknown_star_order is not None:
                    current_imports.clear()
                widened_state = dict(current_imports)
                for nested_import in nested_executed_imports(node):
                    remember_import_node_edges(nested_import, widened_state)
            # Record the state after every top-level statement.  In particular,
            # an import statement can suspend here while a dependency calls back
            # into one of the already-defined functions.
            remember_current_imports()

    def reachable(start: str) -> set[str]:
        seen: set[str] = set()
        pending = [start]
        while pending:
            current = pending.pop()
            for neighbor in import_graph.get(current, ()):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                pending.append(neighbor)
        return seen

    reachable_by_module = {module: reachable(module) for module in parsed}
    cycle_modules_by_module = {
        module: frozenset(
            candidate
            for candidate in reachable_by_module[module]
            if module in reachable_by_module.get(candidate, set())
        )
        for module in parsed
    }

    functions_by_module: dict[str, dict[str, str]] = {}
    for target in exact_nodes:
        owner, _, name = target.rpartition(".")
        functions_by_module.setdefault(owner, {})[name] = target

    registry: dict[str, ProjectCallable] = {}
    for target, node in exact_nodes.items():
        module_name = target.rpartition(".")[0]
        tree, is_package, _ = parsed[module_name]
        del tree
        cycle_modules = cycle_modules_by_module[module_name]
        cycle_aliases: dict[str, set[str]] = {}
        cycle_states = [
            state
            for imported_module, state in import_edge_states.get(target, ())
            if imported_module in cycle_modules
        ]
        for state in cycle_states:
            for name, import_target in state.items():
                cycle_aliases.setdefault(name, set()).add(import_target)
        registry[target] = ProjectCallable(
            target=target,
            module_name=module_name,
            is_package_module=is_package,
            node=node,
            global_aliases={
                name: frozenset(import_targets)
                for name, import_targets in import_history_by_target.get(target, {}).items()
            },
            final_global_aliases={
                name: frozenset({import_target})
                for name, import_target in final_imports_by_module[module_name].items()
            },
            cycle_global_aliases={
                name: frozenset(import_targets) for name, import_targets in cycle_aliases.items()
            },
            cycle_snapshot_available=bool(cycle_states),
            cycle_modules=cycle_modules,
            global_functions=functions_by_module.get(module_name, {}),
        )
    return registry


def _project_module_names(files: list[Path], project_root: Path) -> set[str]:
    names: set[str] = set()
    for path in files:
        module_name = module_name_for_path(path, project_root)
        if not module_name:
            continue
        parts = module_name.split(".")
        for index in range(1, len(parts) + 1):
            names.add(".".join(parts[:index]))
    return names
