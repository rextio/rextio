"""Resolution of a raw call target to the concrete native function it refers to."""

from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.final_bindings import BindingKind, definition_is_final
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis


@dataclass(frozen=True)
class ResolvedCall:
    """The resolution of a call target: the concrete function (if any) and how it was reached."""

    raw_target: str
    resolved_target: str
    function: FunctionAnalysis | None


class FunctionResolver:
    """Resolves raw call targets within a module to concrete native functions."""

    def __init__(self, analysis: ProjectAnalysis) -> None:
        self.modules_by_name = {module.module_name: module for module in analysis.modules}
        self.functions_by_qualname = {
            function.qualname: function
            for module in analysis.modules
            for function in module.functions
        }
        self.project_mutations = analysis.project_mutations
        self.project_bindings = analysis.project_bindings

    def resolve(self, module: ModuleAnalysis, raw_target: str) -> ResolvedCall:
        """Resolve a raw call target against the module's imports and functions.

        Consults the shared final-binding authority so a resolved project function
        is returned ONLY when its defining module's final binding for its own name
        is exactly that definition (plugin API 1.3, WP-4). A cross-module (or
        same-module) target whose defining module later rebinds the name to a
        class/assignment/``del``/conditional binder — or shadows it with a wildcard
        import — is stale: Python would not call that function, so it resolves to
        no native function (``function=None``) and the boundary pass treats the
        call as a non-native crossing rather than lowering a stale direct call.
        """
        local_target = _local_qualname(module, raw_target)
        if local_target is not None and local_target in self.functions_by_qualname:
            return self._resolved(raw_target, local_target)

        if raw_target in self.functions_by_qualname:
            return self._resolved(raw_target, raw_target)

        imported_target = _resolve_import_alias(module, raw_target)
        if imported_target in self.functions_by_qualname:
            return self._resolved(raw_target, imported_target)

        # Re-export chain (plugin API 1.3, WP-4, P1-4/P1-2): a target that resolves
        # to a module name which only *re-exports* the definition (``b`` does
        # ``from c import good``; ``a`` calls ``b.good``) is followed recursively
        # through the shared final-binding authority's IMPORT targets, with cycle
        # detection. Every hop must be a proven final IMPORT/def and unmutated;
        # a stale / cyclic / ambiguous / mutated link fails closed to no function.
        chained = self._follow_reexport(imported_target, set())
        if chained is not None and chained in self.functions_by_qualname:
            return self._resolved(raw_target, chained)

        return ResolvedCall(raw_target, imported_target, None)

    def _follow_reexport(self, qualname: str, seen: set[str]) -> str | None:
        """Follow a project re-export chain to the defining qualname, or None.

        ``qualname`` is a project ``module.name`` target. If ``module`` re-exports
        ``name`` via an absolute ``from other import name``, recurse to
        ``other.name``; a defined function ends the chain. A cycle, an unbound /
        ambiguous / non-final link, or a module-load mutation of any hop fails
        closed (returns None).
        """
        if qualname in seen:
            return None  # cyclic re-export: fail closed
        seen.add(qualname)
        if self.project_mutations.target_is_mutated(qualname):
            return None
        module_name, separator, name = qualname.rpartition(".")
        if not separator:
            return None
        entry = self.project_bindings.for_module(module_name).lookup(name)
        if entry.kind is BindingKind.FUNCTION:
            return qualname if qualname in self.functions_by_qualname else None
        if entry.kind is BindingKind.IMPORT:
            target = entry.target
            if target is None:
                # Relative imports deliberately carry no target in the generic
                # final-binding record because resolution needs package context.
                # ModuleAnalysis.imports is built from that same exact final
                # IMPORT authority and has already expanded the package-relative
                # spelling without importing or executing user code.
                module = self.modules_by_name.get(module_name)
                target = module.imports.get(name) if module is not None else None
            if target is not None:
                return self._follow_reexport(target, seen)
        return None

    def _resolved(self, raw_target: str, resolved_target: str) -> ResolvedCall:
        function = self.functions_by_qualname[resolved_target]
        if self.project_mutations.target_is_mutated(resolved_target):
            # The resolved project target is a module attribute rebound at module
            # load (`h.good = …`), so Python would call the rebound object, not this
            # compiled function. Resolve to no native function so the boundary pass
            # treats the call as a non-native crossing and fails closed (P0-4). This
            # also blocks a re-export / stale `.pyi` from resurrecting the target.
            return ResolvedCall(raw_target, resolved_target, None)
        if definition_is_final(
            function.module_bindings,
            function.name,
            BindingKind.FUNCTION,
            function.line,
            function.column,
        ):
            return ResolvedCall(raw_target, resolved_target, function)
        # Stale: the defining module's final binding is not this function.
        return ResolvedCall(raw_target, resolved_target, None)


def _local_qualname(module: ModuleAnalysis, raw_target: str) -> str | None:
    if "." in raw_target:
        return None
    if not module.module_name:
        return raw_target
    return f"{module.module_name}.{raw_target}"


def _resolve_import_alias(module: ModuleAnalysis, raw_target: str) -> str:
    head, separator, tail = raw_target.partition(".")
    imported = module.imports.get(head)
    if imported is None:
        return raw_target
    if separator:
        return f"{imported}.{tail}"
    return imported
