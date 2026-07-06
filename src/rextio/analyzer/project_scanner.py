"""Project file discovery and the analyze_project entry point."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from fnmatch import fnmatch
from pathlib import Path

from rextio.analyzer.boundary import apply_boundary_checks
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.module_parser import module_name_for_path, parse_module
from rextio.analyzer.plugin_claims import ClaimEngine
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.config.schema import ImportsConfig, RextioConfig
from rextio.plugins.models import PluginRegistry, RextioPlugin
from rextio.targets.models import normalize_target_language

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


def scan_python_files(project_root: Path) -> list[Path]:
    """Return the project's Python files, honoring .rextioignore."""
    root = project_root.resolve()
    ignore_patterns = load_rextioignore(root)
    files: list[Path] = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if _is_ignored(relative, ignore_patterns):
            continue
        files.append(path)
    return sorted(files)


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
    claim_engine: ClaimEngine | None = None
    if plugin_registry is not None and plugin_registry.providers:
        claim_engine = ClaimEngine(plugin_registry, plugin_config or RextioConfig())
    analysis = ProjectAnalysis(project_root=root)
    files = scan_python_files(root)
    project_modules = _project_module_names(files, root)
    project_return_types = _project_annotated_return_types(files, root)
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
        )
        for path in files
    ]
    apply_boundary_checks(
        analysis,
        boundary_warnings=boundary_warnings,
        embedding_enabled=embedding_enabled,
        delegate_fallback=delegate_fallback,
    )
    _strip_divergence_notes_from_non_native(analysis)
    _note_plugin_lowerable_accelerated(analysis, tuple(active_plugins))
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
    rule_plugins = [plugin for plugin in active_plugins if plugin.rules_provided and plugin.packages]
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
                plugin
                for plugin in rule_plugins
                if imported_packages.intersection(plugin.packages)
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
                    diagnostic
                    for diagnostic in function.diagnostics
                    if diagnostic.code != "RXT090"
                ]


def _project_annotated_return_types(files: list[Path], project_root: Path) -> dict[str, str]:
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
        stub_path = path.with_suffix(".pyi")
        if not stub_path.exists():
            continue
        try:
            stub_tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
        except SyntaxError:
            continue
        for item in stub_tree.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.returns is not None
                and is_supported_type(item.returns)
            ):
                return_types[_qualname(item.name)] = annotation_name(item.returns)
    return return_types


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
