"""Recognition of the @rextio.native / @rextio.exempt decorators on functions."""

from __future__ import annotations

import ast
from pathlib import Path
from dataclasses import dataclass

from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, normalize_target_language


@dataclass(frozen=True)
class NativeMarker:
    """The result of recognizing a native/exempt marker: its kind and optional target."""

    target_language: str | None = None
    error: str | None = None

    @property
    def valid(self) -> bool:
        """Report whether the marker is well-formed."""
        return self.error is None


def dotted_name(node: ast.AST) -> str | None:
    """Return the dotted name of a Name/Attribute node, or None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def parse_native_marker(node: ast.AST) -> NativeMarker | None:
    """Parse a decorator AST node into a NativeMarker, or None if it is not one."""
    if isinstance(node, ast.Call):
        name = dotted_name(node.func)
    else:
        name = dotted_name(node)
    if name not in {"rextio.native", "native"}:
        return None
    if not isinstance(node, ast.Call):
        return NativeMarker()
    if node.args:
        return NativeMarker(error="@rextio.native only accepts keyword arguments")
    target_language: str | None = None
    for keyword in node.keywords:
        if keyword.arg != "target":
            return NativeMarker(
                error=f"unsupported @rextio.native keyword: {keyword.arg or '**kwargs'}"
            )
        if target_language is not None:
            return NativeMarker(error="duplicate @rextio.native target keyword")
        if not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, str):
            return NativeMarker(error="@rextio.native target must be a string literal")
        target_language = normalize_target_language(keyword.value.value)
        if target_language not in SUPPORTED_TARGET_LANGUAGES:
            options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
            return NativeMarker(
                target_language=target_language,
                error=(
                    f"unsupported @rextio.native target: {target_language!r}. "
                    f"Use one of: {options}."
                ),
            )
    return NativeMarker(target_language=target_language)


def native_marker_for_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> NativeMarker | None:
    """Return the native marker applied to a function, or None."""
    for decorator in node.decorator_list:
        marker = parse_native_marker(decorator)
        if marker is not None:
            return marker
    return None


def is_native_decorator(node: ast.AST) -> bool:
    """Report whether the node is the @rextio.native decorator."""
    return parse_native_marker(node) is not None


def is_exempt_decorator(node: ast.AST) -> bool:
    """Report whether the node is the @rextio.exempt decorator."""
    name = dotted_name(node)
    return name in {"rextio.exempt", "exempt"}


def has_native_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Report whether the function carries an @rextio.native marker."""
    return native_marker_for_function(node) is not None


def has_exempt_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Report whether the function carries an @rextio.exempt marker."""
    return any(is_exempt_decorator(decorator) for decorator in node.decorator_list)


# Decorators from external accelerator packages Rextio recognizes as "this
# function intentionally stays on the Python fallback and is compiled by an
# external tool". Keys are fully-resolved dotted names (module import map
# applied), values name the tool for report labeling. The function's semantics
# are then the TOOL's contract (e.g. Numba nopython int arithmetic wraps on
# overflow), not Rextio's CPython-exact native contract - the same opt-out
# philosophy as @rextio.exempt.
#
# These keys are EXTERNAL API names owned by the accelerator packages. They
# must never be swept up in Rextio-internal renames (e.g. the jit->embedding
# surface rename): `numba.jit` is Numba's decorator, not Rextio's.
_EXTERNAL_ACCELERATOR_QUALNAMES = {
    "numba.jit": "numba",
    "numba.njit": "numba",
    "numba.vectorize": "numba",
    "numba.guvectorize": "numba",
    "numba.cuda.jit": "numba",
}


def external_accelerator_for_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str],
    project_modules: set[str] | None = None,
) -> str | None:
    """Return the external accelerator a decorator applies, or None.

    Resolves the decorator through the module's import map so ``@numba.njit``,
    ``from numba import njit`` + ``@njit``, aliases, and the call forms
    (``@njit(cache=True)``) are all recognized precisely - a user-defined
    decorator that merely shares a bare name is not, and neither is a
    PROJECT-LOCAL module that happens to be named ``numba`` (``project_modules``
    holds the project's own top-level module names; an import resolving into one
    of them is the user's code, not the external package).
    """
    project_modules = project_modules or set()
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted_name(target)
        if name is None:
            continue
        head, _, rest = name.partition(".")
        resolved_head = imports.get(head)
        if resolved_head is None:
            continue
        if resolved_head.split(".", 1)[0] in project_modules:
            continue
        resolved = f"{resolved_head}.{rest}" if rest else resolved_head
        tool = _EXTERNAL_ACCELERATOR_QUALNAMES.get(resolved)
        if tool is not None:
            return tool
    return None


def external_accelerator_for_source(
    source: str,
    project_modules: frozenset[str] | set[str] = frozenset(),
) -> str | None:
    """Return the external accelerator a module's functions use, or None.

    A lightweight, self-contained scan for build backends that only have the
    generated source text (no project analysis). It walks the WHOLE tree:
    imports are collected wherever they appear (module top level, ``try``/``if``
    guard bodies, ``except``/``finally`` handlers, class bodies, and inside
    function bodies - the deferred-import pattern), ``from numba import *``
    exposes the known entry points and submodules (``cuda``), and every
    function definition anywhere (top level, class methods, nested functions)
    is checked. Used to keep externally-accelerated modules OUT of Nuitka
    compilation (the tool needs the original bytecode at runtime); an import
    that resolves into ``project_modules`` (the tree's own top-level names) is
    the user's code, not the external package. Over-detection (e.g. an import
    under ``if False``) merely keeps a module as plain Python - the safe
    direction.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    def resolves_to_accelerator(dotted: str) -> bool:
        return any(
            qualname == dotted or qualname.startswith(f"{dotted}.")
            for qualname in _EXTERNAL_ACCELERATOR_QUALNAMES
        )

    imports: dict[str, str] = {}

    def bind(visible: str, target: str) -> None:
        # The walk flattens scopes, so two bindings of one name can collide
        # (top-level `import numba` vs a nested `import local_numba as
        # numba`). Never let a non-accelerator binding overwrite an
        # accelerator-resolving one: dropping the accelerator binding is
        # UNDER-detection (a Nuitka-compiled module whose accelerated
        # function dies at first call), while the reverse is at most an
        # over-skip - the safe direction. This also makes the result
        # independent of ast.walk's traversal order.
        current = imports.get(visible)
        if current is not None and resolves_to_accelerator(current) and not resolves_to_accelerator(target):
            return
        imports[visible] = target

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible = alias.asname or alias.name.split(".", 1)[0]
                bind(visible, alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    # `from numba import *`: make the known accelerator entry
                    # points AND their submodule heads (`cuda` for
                    # `numba.cuda.jit`) visible under their bare names.
                    for qualname in _EXTERNAL_ACCELERATOR_QUALNAMES:
                        prefix = f"{node.module}."
                        if qualname.startswith(prefix):
                            visible = qualname[len(prefix):].split(".", 1)[0]
                            bind(visible, f"{node.module}.{visible}")
                    continue
                visible = alias.asname or alias.name
                bind(visible, f"{node.module}.{alias.name}")
    if not imports:
        return None

    module_names = set(project_modules)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = external_accelerator_for_function(node, imports, module_names)
            if tool is not None:
                return tool
    return None


def project_module_names_for_tree(python_dir: Path) -> frozenset[str]:
    """Return the top-level importable names a generated Python tree defines.

    Used to keep the source scan from mistaking a PROJECT-LOCAL module named
    ``numba`` for the external package: the generated tree always contains
    every project module, so top-level presence in the tree means local.
    """
    names: set[str] = set()
    for entry in python_dir.iterdir():
        if entry.is_file() and entry.suffix == ".py":
            names.add(entry.stem)
        elif entry.is_dir():
            # Count every package directory, including NAMESPACE packages
            # (no __init__.py): a local `numba/` namespace package is still
            # the user's code and must not be mistaken for the external
            # accelerator.
            names.add(entry.name)
    return frozenset(names)
