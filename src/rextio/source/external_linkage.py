"""Strict C5.2 linkage for signed, exact external scalar source.

The registry is deliberately separate from :class:`ProjectAnalysis`: external
modules never become project modules or Python exports.  It proves direct,
final import call sites and re-lowers only the reached exact-byte helpers as
private Rust functions.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.final_bindings import (
    BindingKind,
    ProjectBindings,
    build_module_bindings,
)
from rextio.analyzer.models import (
    CallSite,
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
)
from rextio.analyzer.unsupported_patterns import validate_native_function
from rextio.ir.lowering import LoweringError, lower_function
from rextio.ir.nodes import FunctionIR
from rextio.ir.types import normalize_type_name
from rextio.source.external import MAX_FILE_BYTES
from rextio.source.external_analysis import (
    EXTERNAL_FUNCTION_IR_DOMAIN,
    ExternalFunctionBinding,
    ExternalSourceNativePlan,
    analyze_external_source_snapshot,
)
from rextio.source.graph import resolve_import_from_base


class ExternalLinkageError(ValueError):
    """One external call or exact-byte helper failed the strict linkage gate."""


_SAFE_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_SAFE_DISTRIBUTION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_SAFE_VERSION = re.compile(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SCALAR_TYPES = frozenset({"bool", "float", "int", "str"})
_DYNAMIC_NAMESPACE_NAMES = frozenset(
    {
        "__builtins__",
        "__import__",
        "__loader__",
        "__spec__",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "vars",
    }
)
_DYNAMIC_NAMESPACE_PATHS = frozenset(
    {
        "builtins.__import__",
        "builtins.__dict__",
        "builtins.eval",
        "builtins.exec",
        "builtins.globals",
        "builtins.locals",
        "builtins.vars",
        "ctypes.PyDLL",
        "ctypes.pythonapi",
        "gc.get_objects",
        "gc.get_referents",
        "gc.get_referrers",
        "importlib.import_module",
        "importlib.__import__",
        "importlib.__dict__",
        "importlib.reload",
        "inspect.currentframe",
        "inspect.getclosurevars",
        "inspect.getattr_static",
        "inspect.getinnerframes",
        "inspect.getmembers",
        "inspect.getmembers_static",
        "inspect.getmodule",
        "inspect.getouterframes",
        "inspect.stack",
        "inspect.trace",
        "operator.attrgetter",
        "operator.methodcaller",
        "sys.__dict__",
        "sys._current_exceptions",
        "sys._current_frames",
        "sys._getframe",
        "sys.exc_info",
        "sys.modules",
        "sys.setprofile",
        "sys.settrace",
        "traceback.walk_stack",
        "traceback.walk_tb",
    }
)
_DYNAMIC_NAMESPACE_MEMBERS = {
    "builtins": frozenset(
        {"__import__", "__dict__", "eval", "exec", "getattr", "globals", "locals", "vars"}
    ),
    "importlib": frozenset({"__import__", "__dict__", "import_module", "reload"}),
    "pkgutil": frozenset({"resolve_name"}),
    "pydoc": frozenset({"locate"}),
    "sys": frozenset(
        {
            "__dict__",
            "_current_exceptions",
            "_current_frames",
            "_getframe",
            "exc_info",
            "modules",
            "setprofile",
            "settrace",
        }
    ),
}
_DYNAMIC_NAMESPACE_PREFIXES = frozenset({"importlib"})
_REFLECTIVE_ATTRIBUTE_NAMES = frozenset(
    {
        "__builtins__",
        "__dict__",
        "__getattr__",
        "__getattribute__",
        "__globals__",
        "ag_frame",
        "cr_frame",
        "f_builtins",
        "f_globals",
        "f_locals",
        "frame",
        "gi_frame",
        "tb_frame",
    }
)
_NAMESPACE_CONTAINER_NAMES = frozenset(
    {
        "__builtins__",
        "__dict__",
        "__globals__",
    }
)
_MUTATING_METHOD_NAMES = frozenset(
    {
        "__delitem__",
        "__setitem__",
        "clear",
        "pop",
        "popitem",
        "setdefault",
        "update",
    }
)


@dataclass(frozen=True, slots=True)
class _SourceImportOccurrence:
    """One syntactic import with its exact runtime-visible binding target."""

    bound_name: str | None
    binding_target: str | None
    imported_target: str | None
    line: int
    column: int
    alias_node_id: int
    module_body_unconditional: bool
    relative: bool
    star: bool


@dataclass(slots=True)
class _ProjectExternalBindingGraph:
    """Resolve project import slots that can reach one external namespace.

    A Python import is a mutable module-global slot.  The external target
    ``demo_pkg.affine`` can therefore also be reached as ``app.p.affine`` when
    ``app.p`` is ``import demo_pkg as p``.  Keep that project slot distinct from
    the external callable while resolving both to the same capability.
    """

    package: str
    external_targets: frozenset[str]
    imports_by_module: dict[str, dict[str, str]]
    project_functions: frozenset[str]
    sensitive_slots: frozenset[str]
    sensitive_owner_modules: frozenset[str]

    def resolve(self, path: str) -> str:
        """Follow final/source import slots without executing project code."""
        current = path
        seen: set[str] = set()
        limit = max(8, sum(len(value) for value in self.imports_by_module.values()) + 1)
        for _ in range(limit):
            if current in seen:
                break
            seen.add(current)
            replacement = self._replace_one_project_slot(current)
            if replacement is None or replacement == current:
                break
            current = replacement
        return current

    def is_sensitive_capability(self, path: str) -> bool:
        """Return whether ``path`` exposes a live external/project namespace."""
        resolved = self.resolve(path)
        if resolved == self.package or resolved.startswith(f"{self.package}."):
            return True
        if any(
            resolved == slot or resolved.startswith(f"{slot}.") or slot.startswith(f"{resolved}.")
            for slot in self.sensitive_slots
        ):
            return True
        return any(
            resolved == owner
            or resolved.startswith(f"{owner}.")
            or owner.startswith(f"{resolved}.")
            for owner in self.sensitive_owner_modules
        )

    def is_safe_direct_call(self, path: str) -> bool:
        """Allow only an exact external leaf or statically known project call."""
        resolved = self.resolve(path)
        return resolved in self.external_targets or resolved in self.project_functions

    def _replace_one_project_slot(self, path: str) -> str | None:
        for module_name in sorted(self.imports_by_module, key=len, reverse=True):
            prefix = f"{module_name}."
            if not path.startswith(prefix):
                continue
            remainder = path.removeprefix(prefix)
            alias, separator, tail = remainder.partition(".")
            imported = self.imports_by_module[module_name].get(alias)
            if imported is None:
                continue
            return f"{imported}.{tail}" if separator else imported
        return None


@dataclass(frozen=True, slots=True)
class ExternalLinkedCall:
    """One project call site proven to target one exact external helper."""

    caller_qualname: str
    line: int
    column: int
    target: str
    import_head: str
    import_target: str
    import_line: int
    import_column: int
    import_order: int
    caller_ast_fingerprint: str
    argument_types: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.caller_qualname) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.caller_qualname) is None
            or type(self.target) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.target) is None
            or type(self.import_head) is not str
            or not self.import_head.isascii()
            or not self.import_head.isidentifier()
            or type(self.import_target) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.import_target) is None
            or type(self.line) is not int
            or self.line < 1
            or type(self.column) is not int
            or self.column < 0
            or type(self.import_line) is not int
            or self.import_line < 1
            or type(self.import_column) is not int
            or self.import_column < 0
            or type(self.import_order) is not int
            or self.import_order < 0
            or type(self.caller_ast_fingerprint) is not str
            or not self.caller_ast_fingerprint
            or len(self.caller_ast_fingerprint) > 1_048_576
            or "\x00" in self.caller_ast_fingerprint
            or type(self.argument_types) is not tuple
            or any(value not in _SCALAR_TYPES for value in self.argument_types)
        ):
            raise ValueError("external linked call identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalNativeRegistry:
    """Closed call-site registry plus reachable private external Rust IR."""

    package: str
    distribution: str
    version: str
    linked_calls: tuple[ExternalLinkedCall, ...]
    private_functions: tuple[FunctionIR, ...]

    def __post_init__(self) -> None:
        calls = tuple(self.linked_calls)
        functions = tuple(self.private_functions)
        if (
            type(self.package) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.package) is None
            or type(self.distribution) is not str
            or _SAFE_DISTRIBUTION.fullmatch(self.distribution) is None
            or type(self.version) is not str
            or _SAFE_VERSION.fullmatch(self.version) is None
            or type(self.linked_calls) is not tuple
            or type(self.private_functions) is not tuple
            or not all(type(item) is ExternalLinkedCall for item in calls)
            or not all(type(item) is FunctionIR for item in functions)
        ):
            raise ValueError("external native registry identity is invalid")
        if not calls or not functions:
            raise ValueError("external native registry must have reachable linkage")
        if calls != tuple(
            sorted(calls, key=lambda item: (item.caller_qualname, item.line, item.column))
        ):
            raise ValueError("external linked calls are not canonical")
        if len({(item.caller_qualname, item.line, item.column) for item in calls}) != len(calls):
            raise ValueError("external linked call sites are duplicated")
        if functions != tuple(sorted(functions, key=lambda item: item.qualname)):
            raise ValueError("external private functions are not canonical")
        if any(not function.embedded for function in functions):
            raise ValueError("external functions must be private embedded functions")
        targets = {item.target for item in calls}
        function_names = {item.qualname for item in functions}
        if targets != function_names or any(
            not target.startswith(f"{self.package}.") for target in targets
        ):
            raise ValueError("external registry linkage coverage is invalid")

    def resolve(self, caller_qualname: str, line: int, column: int) -> str | None:
        """Resolve one already-proven project call site without spelling guesses."""
        for call in self.linked_calls:
            if (call.caller_qualname, call.line, call.column) == (
                caller_qualname,
                line,
                column,
            ):
                return call.target
        return None

    def resolve_for(
        self,
        module: ModuleAnalysis,
        function: FunctionAnalysis,
        call: CallSite,
    ) -> str | None:
        """Revalidate one call against freshly analyzed source and bindings."""
        linked = next(
            (
                item
                for item in self.linked_calls
                if (item.caller_qualname, item.line, item.column)
                == (function.qualname, call.line, call.column)
            ),
            None,
        )
        if linked is None or module.module_bindings is None:
            return None
        final = module.module_bindings.lookup(linked.import_head)
        current_types = function.call_arg_types.get((call.line, call.column), ())
        normalized_types = tuple(
            normalize_type_name(value) if value is not None else "" for value in current_types
        )
        if (
            function.source_ast_fingerprint != linked.caller_ast_fingerprint
            or call.target != linked.target
            or linked.import_head in function.local_binding_names
            or module.imports.get(linked.import_head) != linked.import_target
            or final.kind is not BindingKind.IMPORT
            or final.target != linked.import_target
            or final.line != linked.import_line
            or final.column != linked.import_column
            or final.order != linked.import_order
            or normalized_types != linked.argument_types
            or analysis_target_is_mutated(module, linked.target)
        ):
            return None
        return linked.target

    def require_fresh_analysis(self, analysis: ProjectAnalysis) -> None:
        """Fail unless every registered site survives one fresh strict analysis."""
        modules = {module.module_name: module for module in analysis.modules}
        functions = {
            function.qualname: (module, function)
            for module in analysis.modules
            for function in module.functions
        }
        targets = frozenset(item.target for item in self.linked_calls)
        try:
            binding_graph = _build_project_external_binding_graph(
                analysis,
                package=self.package,
                targets=targets,
            )
            _require_project_external_binding_integrity(
                analysis,
                targets=targets,
                binding_graph=binding_graph,
            )
        except ExternalLinkageError as error:
            raise ExternalLinkageError("external-linkage-project-analysis-stale") from error
        for linked in self.linked_calls:
            entry = functions.get(linked.caller_qualname)
            if entry is None:
                raise ExternalLinkageError("external-linkage-project-analysis-stale")
            module, function = entry
            tree = _read_project_tree(module)
            function_name_count = sum(
                1
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and f"{module.module_name}.{node.name}" == linked.caller_qualname
            )
            call = next(
                (
                    item
                    for item in function.calls
                    if (item.line, item.column) == (linked.line, linked.column)
                ),
                None,
            )
            if (
                modules.get(module.module_name) is not module
                or function_name_count != 1
                or not function.accepted
                or call is None
                or self.resolve_for(module, function, call) != linked.target
            ):
                raise ExternalLinkageError("external-linkage-project-analysis-stale")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeCallable:
    """Callable identity proven from signed source during analysis/codegen.

    The generated extension never imports or introspects this callable.  The
    record selects exact signed source for private Rust lowering; runtime checks
    are limited to installed distribution/version, RECORD, and source bytes.
    """

    name: str
    qualname: str
    first_line: int

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name.isascii()
            or not self.name.isidentifier()
            or type(self.qualname) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.qualname) is None
            or type(self.first_line) is not int
            or self.first_line < 1
        ):
            raise ValueError("external runtime callable identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeModule:
    """Exact installed module source and reached callable identities."""

    module_name: str
    source_member: str
    source_sha256: str
    source_size: int
    callables: tuple[ExternalRuntimeCallable, ...]

    def __post_init__(self) -> None:
        path = (
            PurePosixPath(self.source_member)
            if type(self.source_member) is str
            else PurePosixPath(".")
        )
        if (
            type(self.module_name) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.module_name) is None
            or type(self.source_member) is not str
            or not self.source_member.endswith(".py")
            or path.is_absolute()
            or path.as_posix() != self.source_member
            or any(part in {"", ".", ".."} for part in path.parts)
            or type(self.source_sha256) is not str
            or _SHA256.fullmatch(self.source_sha256) is None
            or type(self.source_size) is not int
            or not 1 <= self.source_size <= MAX_FILE_BYTES
            or type(self.callables) is not tuple
            or not self.callables
            or not all(type(item) is ExternalRuntimeCallable for item in self.callables)
            or self.callables != tuple(sorted(self.callables, key=lambda item: item.qualname))
            or len({item.qualname for item in self.callables}) != len(self.callables)
            or any(item.qualname != f"{self.module_name}.{item.name}" for item in self.callables)
        ):
            raise ValueError("external runtime module identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeGuard:
    """Frozen runtime guard material for one exact external distribution."""

    distribution: str
    version: str
    modules: tuple[ExternalRuntimeModule, ...]

    def __post_init__(self) -> None:
        if (
            type(self.distribution) is not str
            or _SAFE_DISTRIBUTION.fullmatch(self.distribution) is None
            or type(self.version) is not str
            or _SAFE_VERSION.fullmatch(self.version) is None
            or type(self.modules) is not tuple
            or not self.modules
            or not all(type(item) is ExternalRuntimeModule for item in self.modules)
            or self.modules != tuple(sorted(self.modules, key=lambda item: item.module_name))
            or len({item.module_name for item in self.modules}) != len(self.modules)
        ):
            raise ValueError("external runtime guard modules are invalid")


def build_external_native_registry(
    analysis: ProjectAnalysis,
    plans: tuple[ExternalSourceNativePlan, ...],
    *,
    package: str,
    distribution: str,
    version: str,
) -> ExternalNativeRegistry:
    """Prove direct final aliases and lower exactly the reached helpers.

    The input plans must all be fresh results for the same pinned distribution.
    No external module is inserted into ``analysis.modules``.
    """
    if type(analysis) is not ProjectAnalysis or type(plans) is not tuple or not plans:
        raise ExternalLinkageError("external-linkage-input-invalid")
    if not all(type(plan) is ExternalSourceNativePlan for plan in plans):
        raise ExternalLinkageError("external-linkage-plan-invalid")
    if any(
        module.module_name == package or module.module_name.startswith(f"{package}.")
        for module in analysis.modules
    ):
        raise ExternalLinkageError("external-linkage-project-shadow")

    bindings: dict[str, tuple[ExternalSourceNativePlan, ExternalFunctionBinding]] = {}
    for plan in plans:
        snapshot = plan.snapshot.module
        if (
            snapshot.distribution != distribution
            or snapshot.version != version
            or not (
                snapshot.module_name == package or snapshot.module_name.startswith(f"{package}.")
            )
        ):
            raise ExternalLinkageError("external-linkage-identity-mismatch")
        if analyze_external_source_snapshot(plan.snapshot) != plan:
            raise ExternalLinkageError("external-linkage-analysis-stale")
        for binding in plan.functions:
            if binding.qualname in bindings:
                raise ExternalLinkageError("external-linkage-function-duplicate")
            bindings[binding.qualname] = (plan, binding)

    external_targets = frozenset(bindings)
    binding_graph = _build_project_external_binding_graph(
        analysis,
        package=package,
        targets=external_targets,
    )
    _require_project_external_binding_integrity(
        analysis,
        targets=external_targets,
        binding_graph=binding_graph,
    )

    linked: list[ExternalLinkedCall] = []
    caller_definition_counts: dict[str, int] = {}
    for module in analysis.modules:
        tree = _read_project_tree(module)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{module.module_name}.{node.name}"
                caller_definition_counts[qualname] = caller_definition_counts.get(qualname, 0) + 1
        calls_by_position = {
            (node.lineno, node.col_offset): node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        for function in module.functions:
            for call in function.calls:
                call_node = calls_by_position.get((call.line, call.column))
                if call_node is None:
                    continue
                resolved = _direct_external_target(
                    call_node,
                    module=module,
                    function=function,
                    external_bindings=bindings,
                )
                if resolved is None:
                    continue
                target, import_head = resolved
                _require_call_signature(
                    function,
                    call.line,
                    call.column,
                    call_node,
                    bindings[target][1],
                )
                assert module.module_bindings is not None
                final = module.module_bindings.lookup(import_head)
                argument_types = function.call_arg_types.get((call.line, call.column), ())
                normalized_argument_types: list[str] = []
                for value in argument_types:
                    normalized = normalize_type_name(value) if value is not None else None
                    if normalized is None or normalized not in _SCALAR_TYPES:
                        raise ExternalLinkageError("external-linkage-call-type-unknown")
                    normalized_argument_types.append(normalized)
                if function.source_ast_fingerprint is None:
                    raise ExternalLinkageError("external-linkage-caller-identity-missing")
                linked.append(
                    ExternalLinkedCall(
                        caller_qualname=function.qualname,
                        line=call.line,
                        column=call.column,
                        target=target,
                        import_head=import_head,
                        import_target=module.imports[import_head],
                        import_line=final.line if final.line is not None else -1,
                        import_column=final.column if final.column is not None else -1,
                        import_order=final.order,
                        caller_ast_fingerprint=function.source_ast_fingerprint,
                        argument_types=tuple(normalized_argument_types),
                    )
                )

    linked_tuple = tuple(
        sorted(linked, key=lambda item: (item.caller_qualname, item.line, item.column))
    )
    if any(caller_definition_counts.get(item.caller_qualname) != 1 for item in linked_tuple):
        raise ExternalLinkageError("external-linkage-caller-duplicate")
    linked_positions = [(item.caller_qualname, item.line, item.column) for item in linked_tuple]
    if len(linked_positions) != len(set(linked_positions)):
        raise ExternalLinkageError("external-linkage-call-position-duplicate")
    reachable = {item.target for item in linked_tuple}
    private_functions = tuple(
        sorted(
            (
                _lower_exact_external_function(plan, binding)
                for qualname in reachable
                for plan, binding in (bindings[qualname],)
            ),
            key=lambda item: item.qualname,
        )
    )
    try:
        return ExternalNativeRegistry(
            package=package,
            distribution=distribution,
            version=version,
            linked_calls=linked_tuple,
            private_functions=private_functions,
        )
    except (TypeError, ValueError) as error:
        raise ExternalLinkageError("external-linkage-no-reachable-helper") from error


def build_external_runtime_guard(
    registry: ExternalNativeRegistry,
    plans: tuple[ExternalSourceNativePlan, ...],
) -> ExternalRuntimeGuard:
    """Bind signed helper identities to runtime-verifiable source material.

    Callable names and source positions are analysis/codegen authority only.
    Runtime does not import or introspect the external module or callable; it
    verifies the installed distribution/version, RECORD, and exact source bytes.
    """
    if type(registry) is not ExternalNativeRegistry or type(plans) is not tuple:
        raise ExternalLinkageError("external-runtime-guard-input-invalid")
    reachable = {function.qualname for function in registry.private_functions}
    modules: list[ExternalRuntimeModule] = []
    observed: set[str] = set()
    for plan in plans:
        if type(plan) is not ExternalSourceNativePlan:
            raise ExternalLinkageError("external-runtime-guard-plan-invalid")
        if analyze_external_source_snapshot(plan.snapshot) != plan:
            raise ExternalLinkageError("external-runtime-guard-analysis-stale")
        module = plan.snapshot.module
        if module.distribution != registry.distribution or module.version != registry.version:
            raise ExternalLinkageError("external-runtime-guard-identity-mismatch")
        callables = tuple(
            ExternalRuntimeCallable(
                name=binding.name,
                qualname=binding.qualname,
                first_line=binding.source_range.start.line,
            )
            for binding in plan.functions
            if binding.qualname in reachable
        )
        if not callables:
            continue
        prefix = f"distributions/{registry.distribution}/"
        if not module.path.startswith(prefix):
            raise ExternalLinkageError("external-runtime-guard-source-path-invalid")
        source_member = module.path.removeprefix(prefix)
        modules.append(
            ExternalRuntimeModule(
                module_name=module.module_name,
                source_member=source_member,
                source_sha256=module.sha256,
                source_size=len(plan.snapshot.source_bytes),
                callables=callables,
            )
        )
        observed.update(item.qualname for item in callables)
    if observed != reachable:
        raise ExternalLinkageError("external-runtime-guard-coverage-incomplete")
    try:
        return ExternalRuntimeGuard(
            distribution=registry.distribution,
            version=registry.version,
            modules=tuple(sorted(modules, key=lambda item: item.module_name)),
        )
    except ValueError as error:
        raise ExternalLinkageError("external-runtime-guard-invalid") from error


def _read_project_tree(module: ModuleAnalysis) -> ast.Module:
    try:
        source = Path(module.file_path).read_text(encoding="utf-8")
        return ast.parse(source, filename=module.file_path, type_comments=True)
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ExternalLinkageError("external-linkage-project-source-unavailable") from error


def _build_project_external_binding_graph(
    analysis: ProjectAnalysis,
    *,
    package: str,
    targets: frozenset[str],
) -> _ProjectExternalBindingGraph:
    if type(analysis) is not ProjectAnalysis or not targets:
        raise ExternalLinkageError("external-linkage-binding-graph-input-invalid")
    imports_by_module: dict[str, dict[str, str]] = {}
    project_functions: set[str] = set()
    for module in analysis.modules:
        imports_by_module[module.module_name] = dict(module.imports)
        if module.module_bindings is None:
            continue
        for function in module.functions:
            final = module.module_bindings.lookup(function.name)
            if (
                final.kind is BindingKind.FUNCTION
                and final.target == function.qualname
                and final.line == function.line
                and final.column == function.column
            ):
                project_functions.add(function.qualname)

    graph = _ProjectExternalBindingGraph(
        package=package,
        external_targets=targets,
        imports_by_module=imports_by_module,
        project_functions=frozenset(project_functions),
        sensitive_slots=frozenset(),
        sensitive_owner_modules=frozenset(),
    )
    slots: set[str] = set()
    owners: set[str] = set()
    while True:
        graph.sensitive_slots = frozenset(slots)
        graph.sensitive_owner_modules = frozenset(owners)
        previous = (len(slots), len(owners))
        for module_name, imports in imports_by_module.items():
            for alias, imported in imports.items():
                resolved = graph.resolve(imported)
                reaches_external = resolved == package or resolved.startswith(f"{package}.")
                reaches_owner = any(
                    resolved == owner
                    or resolved.startswith(f"{owner}.")
                    or owner.startswith(f"{resolved}.")
                    for owner in owners
                )
                reaches_slot = any(
                    resolved == slot
                    or resolved.startswith(f"{slot}.")
                    or slot.startswith(f"{resolved}.")
                    for slot in slots
                )
                if reaches_external or reaches_owner or reaches_slot:
                    slots.add(f"{module_name}.{alias}")
                    owners.add(module_name)
        if previous == (len(slots), len(owners)):
            break
    graph.sensitive_slots = frozenset(slots)
    graph.sensitive_owner_modules = frozenset(owners)
    return graph


def _source_import_occurrences(
    module: ModuleAnalysis,
    tree: ast.Module,
) -> tuple[_SourceImportOccurrence, ...]:
    """Collect every import, retaining scope and canonical relative identity."""
    direct_statement_ids = {
        id(statement)
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
    }
    is_package_init = Path(module.file_path).name == "__init__.py"
    occurrences: list[_SourceImportOccurrence] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                bound_name = imported.asname or imported.name.split(".", maxsplit=1)[0]
                binding_target = imported.name if imported.asname else bound_name
                occurrences.append(
                    _SourceImportOccurrence(
                        bound_name=bound_name,
                        binding_target=binding_target,
                        imported_target=imported.name,
                        line=node.lineno,
                        column=node.col_offset,
                        alias_node_id=id(imported),
                        module_body_unconditional=id(node) in direct_statement_ids,
                        relative=False,
                        star=False,
                    )
                )
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        base = resolve_import_from_base(
            module.module_name,
            node.module,
            node.level,
            is_package_init,
        )
        for imported in node.names:
            star = imported.name == "*"
            target = (
                None
                if base is None
                else base
                if star
                else f"{base}.{imported.name}"
                if base
                else imported.name
            )
            occurrences.append(
                _SourceImportOccurrence(
                    bound_name=None if star else imported.asname or imported.name,
                    binding_target=None if star else target,
                    imported_target=target,
                    line=node.lineno,
                    column=node.col_offset,
                    alias_node_id=id(imported),
                    module_body_unconditional=id(node) in direct_statement_ids,
                    relative=bool(node.level),
                    star=star,
                )
            )
    return tuple(
        sorted(
            occurrences,
            key=lambda item: (
                item.line,
                item.column,
                item.bound_name or "",
                item.imported_target or "",
            ),
        )
    )


def _require_safe_sensitive_import_occurrences(
    module: ModuleAnalysis,
    *,
    occurrences: tuple[_SourceImportOccurrence, ...],
    binding_graph: _ProjectExternalBindingGraph,
) -> None:
    """Admit only exact final module-body imports of a sensitive capability."""
    for occurrence in occurrences:
        if occurrence.star:
            raise ExternalLinkageError("external-linkage-target-escaped")
        if occurrence.relative and occurrence.imported_target is None:
            raise ExternalLinkageError("external-linkage-target-escaped")
        paths = tuple(
            path
            for path in (occurrence.binding_target, occurrence.imported_target)
            if path is not None
        )
        if not any(binding_graph.is_sensitive_capability(path) for path in paths):
            continue
        if any(
            path.rpartition(".")[2] in _NAMESPACE_CONTAINER_NAMES for path in paths
        ):
            raise ExternalLinkageError("external-linkage-target-escaped")
        if (
            not occurrence.module_body_unconditional
            or occurrence.bound_name is None
            or occurrence.binding_target is None
            or module.imports.get(occurrence.bound_name) != occurrence.binding_target
            or module.module_bindings is None
        ):
            raise ExternalLinkageError("external-linkage-target-escaped")
        final = module.module_bindings.lookup(occurrence.bound_name)
        if (
            final.kind is not BindingKind.IMPORT
            or final.target not in {None, occurrence.binding_target}
            or final.line != occurrence.line
            or final.column != occurrence.column
        ):
            raise ExternalLinkageError("external-linkage-target-escaped")


def _require_project_external_binding_integrity(
    analysis: ProjectAnalysis,
    *,
    targets: frozenset[str],
    binding_graph: _ProjectExternalBindingGraph,
) -> None:
    """Reject mutation/escape anywhere in the complete fresh project graph."""
    for module in analysis.modules:
        tree = _read_project_tree(module)
        occurrences = _source_import_occurrences(module, tree)
        _require_safe_sensitive_import_occurrences(
            module,
            occurrences=occurrences,
            binding_graph=binding_graph,
        )
        for target in targets:
            if analysis_target_is_mutated(
                module,
                target,
                binding_graph=binding_graph,
                tree=tree,
                import_occurrences=occurrences,
            ):
                raise ExternalLinkageError("external-linkage-target-mutated")
        for function in module.functions:
            positions = [(call.line, call.column) for call in function.calls]
            if len(positions) != len(set(positions)):
                raise ExternalLinkageError("external-linkage-call-position-duplicate")
        _require_no_external_value_escape(
            tree,
            module=module,
            targets=targets,
            binding_graph=binding_graph,
            import_occurrences=occurrences,
        )


def _direct_external_target(
    node: ast.Call,
    *,
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    external_bindings: dict[str, tuple[ExternalSourceNativePlan, ExternalFunctionBinding]],
) -> tuple[str, str] | None:
    head: str
    target: str | None
    if isinstance(node.func, ast.Name):
        head = node.func.id
        target = module.imports.get(head)
    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        head = node.func.value.id
        imported = module.imports.get(head)
        target = f"{imported}.{node.func.attr}" if imported is not None else None
    else:
        return None
    if target not in external_bindings:
        return None
    if head in function.local_binding_names or module.module_bindings is None:
        raise ExternalLinkageError("external-linkage-call-head-shadowed")
    final = module.module_bindings.lookup(head)
    if final.kind is not BindingKind.IMPORT or final.target != module.imports.get(head):
        raise ExternalLinkageError("external-linkage-import-not-final")
    if analysis_target_is_mutated(module, target):
        raise ExternalLinkageError("external-linkage-target-mutated")
    return target, head


def analysis_target_is_mutated(
    module: ModuleAnalysis,
    target: str,
    *,
    binding_graph: _ProjectExternalBindingGraph | None = None,
    tree: ast.Module | None = None,
    import_occurrences: tuple[_SourceImportOccurrence, ...] | None = None,
) -> bool:
    """Reject project-authority or exact-source mutation of an external target.

    The ordinary project mutation index is intentionally rooted in project and
    known runtime symbols.  A C5.2 package is neither, so a write such as
    ``pkg.external_helper = replacement`` can otherwise fall outside that
    index.  Re-read the exact project module and conservatively collect writes
    through every import alias that resolves to the external target.
    """
    if module.project_mutations.target_is_mutated(target):
        return True
    observed_tree = tree if tree is not None else _read_project_tree(module)
    occurrences = (
        import_occurrences
        if import_occurrences is not None
        else _source_import_occurrences(module, observed_tree)
    )
    source_imports = {
        occurrence.bound_name: occurrence.binding_target
        for occurrence in occurrences
        if occurrence.bound_name is not None and occurrence.binding_target is not None
    }
    effective_imports = {**source_imports, **module.imports}
    if _has_dynamic_namespace_access(
        observed_tree,
        effective_imports,
        import_occurrences=occurrences,
    ):
        return True
    sensitive_aliases = _sensitive_import_aliases(
        targets=frozenset({target}),
        imports=effective_imports,
        import_occurrences=occurrences,
        binding_graph=binding_graph,
    )
    for node in ast.walk(observed_tree):
        mutation: str | None = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets: tuple[ast.expr, ...]
            if isinstance(node, ast.Assign):
                targets = tuple(node.targets)
            elif isinstance(node, ast.Delete):
                targets = tuple(node.targets)
            else:
                targets = (node.target,)
            for candidate in targets:
                if _expression_references_alias(candidate, sensitive_aliases):
                    return True
                mutation = _external_alias_path(candidate, effective_imports)
                if mutation is not None and _mutation_path_is_sensitive(
                    mutation,
                    target=target,
                    binding_graph=binding_graph,
                ):
                    return True
        if (
            isinstance(node, ast.NamedExpr)
            and (mutation := _external_alias_path(node.target, effective_imports)) is not None
            and _mutation_path_is_sensitive(
                mutation,
                target=target,
                binding_graph=binding_graph,
            )
        ):
            return True
        if isinstance(node, ast.NamedExpr) and _expression_references_alias(
            node.target,
            sensitive_aliases,
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
        ):
            base = _external_alias_path(node.args[0], effective_imports)
            attribute = node.args[1]
            if base is not None:
                mutation = (
                    f"{base}.{attribute.value}"
                    if isinstance(attribute, ast.Constant)
                    and isinstance(attribute.value, str)
                    and attribute.value
                    else base
                )
                if _mutation_path_is_sensitive(
                    mutation,
                    target=target,
                    binding_graph=binding_graph,
                ):
                    return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _MUTATING_METHOD_NAMES
            and _expression_references_alias(node.func.value, sensitive_aliases)
        ):
            return True
    return False


def _mutation_path_is_sensitive(
    path: str,
    *,
    target: str,
    binding_graph: _ProjectExternalBindingGraph | None,
) -> bool:
    if binding_graph is not None and binding_graph.is_sensitive_capability(path):
        return True
    resolved = binding_graph.resolve(path) if binding_graph is not None else path
    return _qualified_paths_overlap(resolved, target)


def _external_alias_path(
    node: ast.expr,
    imports: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _external_alias_path(node.value, imports)
        return f"{base}.{node.attr}" if base is not None else None
    if isinstance(node, ast.Subscript):
        base = _external_alias_path(node.value, imports)
        key = node.slice
        if (
            base is not None
            and isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.isascii()
            and key.value.isidentifier()
            and base.rpartition(".")[2] in _NAMESPACE_CONTAINER_NAMES
        ):
            owner, _, _namespace = base.rpartition(".")
            return f"{owner}.{key.value}" if owner else key.value
        return base
    if isinstance(node, ast.Starred):
        return _external_alias_path(node.value, imports)
    if isinstance(node, (ast.Tuple, ast.List)):
        paths = {
            path for item in node.elts if (path := _external_alias_path(item, imports)) is not None
        }
        return next(iter(paths)) if len(paths) == 1 else None
    return None


def _qualified_paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(f"{right}.") or right.startswith(f"{left}.")


def _require_no_external_value_escape(
    tree: ast.Module,
    *,
    module: ModuleAnalysis,
    targets: frozenset[str],
    binding_graph: _ProjectExternalBindingGraph | None = None,
    import_occurrences: tuple[_SourceImportOccurrence, ...],
) -> None:
    if _has_dynamic_namespace_access(
        tree,
        module.imports,
        import_occurrences=import_occurrences,
    ):
        raise ExternalLinkageError("external-linkage-dynamic-namespace")
    sensitive_aliases = _sensitive_import_aliases(
        targets=targets,
        imports=module.imports,
        import_occurrences=import_occurrences,
        binding_graph=binding_graph,
    )
    allowed_call_references = _direct_external_call_reference_ids(
        tree,
        module=module,
        targets=targets,
        import_occurrences=import_occurrences,
        binding_graph=binding_graph,
    )
    _require_sensitive_imports_are_directly_called(
        tree,
        sensitive_aliases=sensitive_aliases,
        allowed_call_references=allowed_call_references,
        import_occurrences=import_occurrences,
    )
    _require_no_sensitive_non_name_binders(tree, sensitive_aliases)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in sensitive_aliases
            and id(node) not in allowed_call_references
        ):
            raise ExternalLinkageError("external-linkage-target-escaped")


def _sensitive_import_aliases(
    *,
    targets: frozenset[str],
    imports: dict[str, str],
    import_occurrences: tuple[_SourceImportOccurrence, ...],
    binding_graph: _ProjectExternalBindingGraph | None = None,
) -> frozenset[str]:
    """Return aliases owning or directly binding any reachable helper."""
    candidates: list[tuple[str, tuple[str, ...]]] = [
        (alias, (imported,)) for alias, imported in imports.items()
    ]
    candidates.extend(
        (
            occurrence.bound_name,
            tuple(
                path
                for path in (occurrence.binding_target, occurrence.imported_target)
                if path is not None
            ),
        )
        for occurrence in import_occurrences
        if occurrence.bound_name is not None
    )
    return frozenset(
        alias
        for alias, paths in candidates
        if any(
            (binding_graph is not None and binding_graph.is_sensitive_capability(path))
            or (binding_graph is None and _path_exposes_external_namespace(path, targets))
            for path in paths
        )
    )


def _path_exposes_external_namespace(
    path: str,
    targets: frozenset[str],
) -> bool:
    for target in targets:
        module_name, separator, _name = target.rpartition(".")
        if (
            path == target
            or target.startswith(f"{path}.")
            or path.startswith(f"{target}.")
            or (bool(separator) and (path == module_name or path.startswith(f"{module_name}.")))
        ):
            return True
    return False


def _require_no_sensitive_non_name_binders(
    tree: ast.Module,
    sensitive_aliases: frozenset[str],
) -> None:
    """Cover binder spellings whose names are strings/aliases, not ``ast.Name``."""
    if not sensitive_aliases:
        return
    top_level_import_aliases = {
        id(imported)
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for imported in statement.names
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and sensitive_aliases.intersection(
            node.names
        ):
            raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, ast.alias):
            bound = node.asname or node.name.split(".", maxsplit=1)[0]
            if bound in sensitive_aliases and id(node) not in top_level_import_aliases:
                raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, ast.arg) and node.arg in sensitive_aliases:
            raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in sensitive_aliases:
                raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, ast.ExceptHandler):
            if node.name is not None and node.name in sensitive_aliases:
                raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name is not None and node.name in sensitive_aliases:
                raise ExternalLinkageError("external-linkage-target-escaped")
        if isinstance(node, ast.MatchMapping):
            if node.rest is not None and node.rest in sensitive_aliases:
                raise ExternalLinkageError("external-linkage-target-escaped")


def _require_sensitive_imports_are_directly_called(
    tree: ast.Module,
    *,
    sensitive_aliases: frozenset[str],
    allowed_call_references: frozenset[int],
    import_occurrences: tuple[_SourceImportOccurrence, ...],
) -> None:
    """Do not let an otherwise-unused live capability become a module export."""
    imported_aliases = {
        occurrence.bound_name
        for occurrence in import_occurrences
        if occurrence.bound_name in sensitive_aliases
    }
    directly_called_aliases = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and id(node) in allowed_call_references
    }
    if imported_aliases - directly_called_aliases:
        raise ExternalLinkageError("external-linkage-target-escaped")


def _expression_references_alias(
    node: ast.AST,
    aliases: frozenset[str],
) -> bool:
    return any(isinstance(item, ast.Name) and item.id in aliases for item in ast.walk(node))


def _direct_external_call_reference_ids(
    tree: ast.Module,
    *,
    module: ModuleAnalysis,
    targets: frozenset[str],
    import_occurrences: tuple[_SourceImportOccurrence, ...],
    binding_graph: _ProjectExternalBindingGraph | None = None,
) -> frozenset[int]:
    """Whitelist exact calls whose lexical head is the final module import."""
    if module.module_bindings is None:
        return frozenset()
    functions_by_origin: dict[tuple[str, int, int], FunctionAnalysis] = {}
    duplicate_origins: set[tuple[str, int, int]] = set()
    for function in module.functions:
        origin = (function.name, function.line, function.column)
        if origin in functions_by_origin:
            duplicate_origins.add(origin)
        functions_by_origin[origin] = function

    final_import_occurrences = {
        (
            occurrence.bound_name,
            occurrence.binding_target,
            occurrence.line,
            occurrence.column,
        )
        for occurrence in import_occurrences
        if occurrence.module_body_unconditional
        and occurrence.bound_name is not None
        and occurrence.binding_target is not None
    }

    class _LexicalCallCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.calls: list[ast.Call] = []

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            self.calls.append(node)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            del node

        def visit_AsyncFunctionDef(  # noqa: N802
            self,
            node: ast.AsyncFunctionDef,
        ) -> None:
            del node

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
            del node

        def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
            del node

        def _skip_comprehension(self, node: ast.expr) -> None:
            del node

        visit_ListComp = _skip_comprehension
        visit_SetComp = _skip_comprehension
        visit_DictComp = _skip_comprehension
        visit_GeneratorExp = _skip_comprehension

    allowed: set[int] = set()
    for function_node in tree.body:
        if not isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        origin = (function_node.name, function_node.lineno, function_node.col_offset)
        observed_function = functions_by_origin.get(origin)
        if observed_function is None or origin in duplicate_origins:
            continue
        collector = _LexicalCallCollector()
        for statement in function_node.body:
            collector.visit(statement)
        calls_by_position: dict[tuple[int, int], list[CallSite]] = {}
        for call in observed_function.calls:
            calls_by_position.setdefault((call.line, call.column), []).append(call)
        for node in collector.calls:
            if not isinstance(node.func, (ast.Name, ast.Attribute)):
                continue
            head = _call_head_name(node.func)
            if head is None or head in observed_function.local_binding_names:
                continue
            import_target = module.imports.get(head)
            if import_target is None:
                continue
            final = module.module_bindings.lookup(head)
            if (
                final.kind is not BindingKind.IMPORT
                or final.target not in {None, import_target}
                or (
                    head,
                    import_target,
                    final.line,
                    final.column,
                )
                not in final_import_occurrences
            ):
                continue
            resolved = _external_alias_path(node.func, module.imports)
            safe = (
                binding_graph.is_safe_direct_call(resolved)
                if binding_graph is not None and resolved is not None
                else resolved in targets
            )
            analyzed_calls = calls_by_position.get((node.lineno, node.col_offset), [])
            if (
                not safe
                or resolved is None
                or len(analyzed_calls) != 1
                or analyzed_calls[0].target != resolved
            ):
                continue
            allowed.update(
                id(item) for item in ast.walk(node.func) if isinstance(item, ast.Name)
            )
    return frozenset(allowed)


def _call_head_name(node: ast.expr) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _has_dynamic_namespace_access(
    tree: ast.Module,
    imports: dict[str, str],
    *,
    import_occurrences: tuple[_SourceImportOccurrence, ...] = (),
) -> bool:
    """Detect reflective routes able to recover or rewrite import bindings."""
    import_maps = (
        imports,
        *(
            {occurrence.bound_name: occurrence.binding_target}
            for occurrence in import_occurrences
            if occurrence.bound_name is not None and occurrence.binding_target is not None
        ),
    )
    namespace_modules = frozenset({"builtins", "importlib", "sys"})
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _DYNAMIC_NAMESPACE_NAMES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in _REFLECTIVE_ATTRIBUTE_NAMES:
            return True
        if isinstance(node, ast.expr):
            for import_map in import_maps:
                path = _external_alias_path(node, import_map)
                if path is not None and _path_is_dynamic_namespace_access(path):
                    return True
        if (
            isinstance(node, ast.Call)
            and node.args
            and (
                (isinstance(node.func, ast.Name) and node.func.id == "getattr")
                or "builtins.getattr" in _resolved_external_paths(node.func, import_maps)
            )
        ):
            attribute = node.args[1] if len(node.args) > 1 else None
            if (
                isinstance(attribute, ast.Constant)
                and isinstance(attribute.value, str)
                and attribute.value in _REFLECTIVE_ATTRIBUTE_NAMES
            ):
                return True
            if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
                return True
            bases = {
                base
                for import_map in import_maps
                if (base := _external_alias_path(node.args[0], import_map)) is not None
            }
            if not bases.intersection({"builtins", "importlib", "sys"}):
                continue
            assert isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)
            if any(f"{base}.{attribute.value}" in _DYNAMIC_NAMESPACE_PATHS for base in bases):
                return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__getattr__", "__getattribute__"}
        ):
            reflective_values = (node.func.value, *node.args)
            if any(
                _resolved_external_paths(value, import_maps).intersection(namespace_modules)
                for value in reflective_values
            ):
                return True
    return False


def _path_is_dynamic_namespace_access(path: str) -> bool:
    """Classify one resolved path by namespace capability, not source spelling."""
    if any(
        path == prefix or path.startswith(f"{prefix}.")
        for prefix in _DYNAMIC_NAMESPACE_PREFIXES
    ):
        return True
    for module, members in _DYNAMIC_NAMESPACE_MEMBERS.items():
        prefix = f"{module}."
        if not path.startswith(prefix):
            continue
        member = path.removeprefix(prefix).partition(".")[0]
        if member in members:
            return True
    return any(
        path == dangerous or path.startswith(f"{dangerous}.")
        for dangerous in _DYNAMIC_NAMESPACE_PATHS
    )


def _resolved_external_paths(
    node: ast.expr,
    import_maps: tuple[dict[str, str], ...],
) -> frozenset[str]:
    return frozenset(
        path
        for import_map in import_maps
        if (path := _external_alias_path(node, import_map)) is not None
    )


def _require_call_signature(
    function: FunctionAnalysis,
    line: int,
    column: int,
    node: ast.Call,
    binding: ExternalFunctionBinding,
) -> None:
    if node.keywords or any(isinstance(argument, ast.Starred) for argument in node.args):
        raise ExternalLinkageError("external-linkage-call-shape-unsupported")
    if len(node.args) != len(binding.parameters):
        raise ExternalLinkageError("external-linkage-call-arity-mismatch")
    argument_types = function.call_arg_types.get((line, column), ())
    if len(argument_types) != len(binding.parameters):
        raise ExternalLinkageError("external-linkage-call-type-unknown")
    for observed, parameter in zip(argument_types, binding.parameters, strict=True):
        if normalize_type_name(observed) != normalize_type_name(parameter.type_name):
            raise ExternalLinkageError("external-linkage-call-type-mismatch")


def _lower_exact_external_function(
    plan: ExternalSourceNativePlan,
    binding: ExternalFunctionBinding,
) -> FunctionIR:
    source = plan.snapshot.source_bytes.decode("utf-8")
    tree = ast.parse(
        source,
        filename=plan.snapshot.module.path,
        mode="exec",
        type_comments=True,
    )
    nodes = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    node = nodes.get(binding.name)
    if node is None:
        raise ExternalLinkageError("external-linkage-function-missing")
    bindings = build_module_bindings(tree, binding.module_name)
    module = ModuleAnalysis(
        module_name=binding.module_name,
        file_path=binding.source_path,
        module_bindings=bindings,
        project_modules=frozenset({binding.module_name}),
    )
    function_names = frozenset(nodes)
    function = FunctionAnalysis(
        name=binding.name,
        qualname=binding.qualname,
        module_name=binding.module_name,
        file_path=binding.source_path,
        line=node.lineno,
        column=node.col_offset,
        source_range=binding.source_range,
        marker_kind="none",
        is_native_candidate=True,
        explicitly_marked=False,
        source_ast_fingerprint=executable_ast_fingerprint(node),
        annotated_return_type=binding.return_type,
        native_target_language="rust",
        imports={},
        module_function_names=function_names,
        module_bindings=bindings,
        project_modules=frozenset({binding.module_name}),
    )
    return_types = {item.name: item.return_type for item in plan.functions}
    validate_native_function(
        node,
        function,
        return_types=return_types,
        module_function_names=set(function_names),
    )
    if not function.accepted:
        raise ExternalLinkageError("external-linkage-function-no-longer-lowerable")
    module.functions = [function]
    analysis = ProjectAnalysis(
        project_root=Path("."),
        modules=[module],
        project_bindings=ProjectBindings({binding.module_name: bindings}),
    )
    try:
        function_ir = lower_function(
            function,
            node,
            module,
            FunctionResolver(analysis),
        )
    except LoweringError as error:
        raise ExternalLinkageError("external-linkage-function-no-longer-lowerable") from error
    payload = json.dumps(
        function_ir.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    observed_ir_sha256 = hashlib.sha256(
        EXTERNAL_FUNCTION_IR_DOMAIN.encode("ascii") + b"\0" + payload
    ).hexdigest()
    if observed_ir_sha256 != binding.lowered_ir_sha256:
        raise ExternalLinkageError("external-linkage-function-ir-stale")
    return replace(function_ir, embedded=True)


__all__ = [
    "ExternalLinkageError",
    "ExternalLinkedCall",
    "ExternalNativeRegistry",
    "ExternalRuntimeCallable",
    "ExternalRuntimeGuard",
    "ExternalRuntimeModule",
    "build_external_native_registry",
    "build_external_runtime_guard",
]
