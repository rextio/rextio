"""Recognition of supported stdlib/builtin call targets for direct-Rust lowering."""

from __future__ import annotations

import ast
from collections.abc import Collection, Mapping

from rextio.analyzer.native_marker import dotted_name

LOGGING_METHODS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
}

LOGGING_CANONICAL_TARGETS = {
    "logging.debug": "logging.debug",
    "logging.info": "logging.info",
    "logging.warning": "logging.warning",
    "logging.warn": "logging.warning",
    "logging.error": "logging.error",
    "logging.exception": "logging.error",
    "logging.critical": "logging.error",
}

DATETIME_NOW_TARGETS = {
    "datetime.datetime.now",
    "datetime.datetime.utcnow",
}

DATETIME_ISOFORMAT_TARGETS = {
    "datetime.datetime.now.isoformat",
    "datetime.datetime.utcnow.isoformat",
}

# `utcnow().timestamp()` is intentionally excluded: CPython interprets the naive
# `utcnow()` wall-clock as *local* time, so its timestamp is `trueUTC - localOffset`,
# whereas a native `Utc::now().timestamp()` returns the true POSIX timestamp -- a
# divergence of the local offset (hours) in any non-UTC zone. It stays on the
# Python fallback. `now().timestamp()` (naive local interpreted as local) is
# correct and remains native.
DATETIME_TIMESTAMP_TARGETS = {
    "datetime.datetime.now.timestamp",
}

MATH_FLOAT_UNARY_TARGETS = {
    "math.acos",
    "math.asin",
    "math.atan",
    "math.cos",
    "math.exp",
    "math.log",
    "math.log10",
    "math.log2",
    "math.sin",
    "math.sqrt",
    "math.tan",
}

MATH_FLOAT_BINARY_TARGETS = {
    "math.atan2",
}

MATH_FLOAT_TO_INT_TARGETS = {
    "math.ceil",
    "math.floor",
    "math.trunc",
}

MATH_FLOAT_TO_BOOL_TARGETS = {
    "math.isfinite",
    "math.isinf",
    "math.isnan",
}

MATH_CONSTANT_TARGETS = {
    "math.e",
    "math.pi",
}

STR_METHOD_TARGETS = {
    "str.encode",
    "str.endswith",
    "str.lower",
    "str.replace",
    "str.startswith",
    # `str.strip` is intentionally excluded: it lowers to Rust `trim()`
    # (`char::is_whitespace`), but CPython strips per `str.isspace()`, which also
    # treats the C0 separators U+001C-U+001F (FS/GS/RS/US) as whitespace. So
    # `'\x1cx\x1c'.strip()` is `'x'` in CPython but unchanged natively -- a silent
    # divergence. It stays on the Python fallback. (lstrip/rstrip are not
    # supported either.)
    "str.upper",
}

BYTES_METHOD_TARGETS = {
    "bytes.decode",
}

LIST_METHOD_TARGETS = {
    "list.copy",
    "list.count",
    "list.index",
}

HASHLIB_CHAIN_TARGETS = {
    "hashlib.sha256.hexdigest",
}

HASHLIB_INTERNAL_TARGETS = {
    "hashlib.sha256",
}

BASE64_TARGETS = {
    "base64.b64decode",
    "base64.b64encode",
}

JSON_TARGETS = {
    "json.dumps",
    "json.loads",
}

STATISTICS_TARGETS = {
    "statistics.fmean",
    "statistics.mean",
}

# Stdlib calls with NO direct native lowering for fidelity reasons (naive
# native behavior would diverge from CPython): an explicitly marked function
# using one rides the RXT080 runtime shim, an auto-discovered one stays on
# the Python fallback - regardless of import form (attribute or bare
# from-import name).
RUNTIME_FIDELITY_TARGETS = frozenset(
    {
        *JSON_TARGETS,
        *STATISTICS_TARGETS,
        "base64.b64decode",
    }
)

TIME_TARGETS = {
    "time.time",
}

COMMON_DIRECT_RUST_CALLS = {
    "all",
    "any",
    "reversed",
    "sorted",
    "print",
    # Only b64encode lowers to direct Rust; b64decode is recognized (see
    # BASE64_TARGETS uses) but rejected for fidelity - it must not appear in
    # a set whose name promises direct-Rust lowering.
    "base64.b64encode",
    *BYTES_METHOD_TARGETS,
    *DATETIME_TIMESTAMP_TARGETS,
    *LOGGING_CANONICAL_TARGETS.values(),
    *HASHLIB_CHAIN_TARGETS,
    *HASHLIB_INTERNAL_TARGETS,
    *LIST_METHOD_TARGETS,
    *MATH_CONSTANT_TARGETS,
    *MATH_FLOAT_BINARY_TARGETS,
    *MATH_FLOAT_TO_BOOL_TARGETS,
    *MATH_FLOAT_TO_INT_TARGETS,
    *MATH_FLOAT_UNARY_TARGETS,
    *STR_METHOD_TARGETS,
    *TIME_TARGETS,
    *DATETIME_NOW_TARGETS,
    *DATETIME_ISOFORMAT_TARGETS,
}


# Module-qualified stdlib call/constant targets whose native lowering IGNORES the
# receiver expression and emits a static Rust call/constant. Native lowering is
# sound only when the source receiver name is a PROVEN final import to that module:
# a never-imported spelling (`math.sin(x)` with no `import math`, or bare `math.pi`
# with no import) raises `NameError` in CPython, it does NOT call the stdlib target
# — `canonical_call_target`/`resolve_import_target` recognize the spelling even with
# no import, so the import must be proven separately. (Bare builtins like `abs`/`min`
# are NOT here — they need no import; str/bytes/list method targets are NOT here —
# their receiver is a real value, not an ignored module name.)
IMPORT_QUALIFIED_STDLIB_TARGETS = frozenset(
    {
        *BASE64_TARGETS,
        *DATETIME_ISOFORMAT_TARGETS,
        *DATETIME_NOW_TARGETS,
        *DATETIME_TIMESTAMP_TARGETS,
        *HASHLIB_CHAIN_TARGETS,
        *HASHLIB_INTERNAL_TARGETS,
        *JSON_TARGETS,
        *MATH_CONSTANT_TARGETS,
        *MATH_FLOAT_BINARY_TARGETS,
        *MATH_FLOAT_TO_BOOL_TARGETS,
        *MATH_FLOAT_TO_INT_TARGETS,
        *MATH_FLOAT_UNARY_TARGETS,
        *STATISTICS_TARGETS,
        *TIME_TARGETS,
    }
)

# External module roots whose attributes are replaced by static lowering or
# marker recognition.  Source-visible mutation of any such target participates
# in the same project-wide qualified-mutation authority.  Kept here so full
# project analysis and standalone ``parse_module`` use one exact watch set.
MUTATION_WATCHED_EXTERNAL_MODULES = frozenset(
    {
        "builtins",
        "rextio",
        *(target.split(".", 1)[0] for target in IMPORT_QUALIFIED_STDLIB_TARGETS),
        *(target.split(".", 1)[0] for target in LOGGING_CANONICAL_TARGETS),
    }
)


def stdlib_receiver_root(node: ast.expr) -> ast.Name | None:
    """Return the root receiver ``Name`` of a (possibly chained) attribute/call.

    Walks through ``Attribute``/``Call`` links to the base name — ``math`` for
    ``math.sin``, ``hashlib`` for ``hashlib.sha256(x).hexdigest()``, ``sqrt`` for
    a bare ``sqrt(x)`` — or ``None`` when the base is not a plain name.
    """
    root: ast.AST = node
    while isinstance(root, (ast.Attribute, ast.Call)):
        root = root.value if isinstance(root, ast.Attribute) else root.func
    return root if isinstance(root, ast.Name) else None


def stdlib_receiver_is_proven_import(
    node: ast.expr,
    imports: Mapping[str, str],
    local_names: Collection[str] = (),
    project_modules: Collection[str] = (),
) -> bool:
    """Whether a module-qualified stdlib target's receiver is a proven final import.

    The receiver root name must be present in the (final-binding-filtered) import
    map, must not be shadowed by a function-local binding, and must not resolve
    into the analyzed project's own module namespace. A never-imported spelling,
    a local rebinding, a project-local module named like stdlib (for example
    ``math.py``), or a name the import map dropped because a later class/
    assignment/``del``/wildcard shadowed the import all fail closed.
    """
    root = stdlib_receiver_root(node)
    if root is None:
        return False
    if root.id in local_names:
        return False
    imported = imports.get(root.id)
    if imported is None:
        return False
    return not any(
        imported == module or imported.startswith(f"{module}.") for module in project_modules
    )


def canonical_call_target(
    node: ast.Call,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> str | None:
    """Return the canonical dotted target of a call, or None if it is not a recognized form."""
    chained_target = canonical_chained_call(node, imports)
    if chained_target is not None:
        return chained_target
    method_target = canonical_method_call(node, imports)
    if method_target is not None:
        return method_target
    datetime_target = canonical_datetime_terminal_call(node, imports)
    if datetime_target is not None:
        return datetime_target
    raw_target = dotted_name(node.func)
    if raw_target is None:
        return None
    return canonical_simple_call_target(raw_target, imports, logger_names)


def canonical_simple_call_target(
    target: str,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> str:
    """Return the canonical target of a simple name/attribute call, or None."""
    if target == "print":
        return target

    resolved = resolve_import_target(target, imports)
    if resolved in LOGGING_CANONICAL_TARGETS:
        return LOGGING_CANONICAL_TARGETS[resolved]

    parts = target.split(".")
    if len(parts) == 2 and parts[0] in set(logger_names) and parts[1] in LOGGING_METHODS:
        return LOGGING_CANONICAL_TARGETS.get(f"logging.{parts[1]}", "logging.error")

    return resolved


def canonical_attribute_target(node: ast.Attribute, imports: dict[str, str]) -> str | None:
    """Return the canonical dotted name of an attribute access, or None."""
    raw_target = dotted_name(node)
    if raw_target is None:
        return None
    return resolve_import_target(raw_target, imports)


def canonical_chained_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    """Return the canonical target of a supported chained call (e.g. hashlib), or None."""
    if not isinstance(node.func, ast.Attribute):
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call):
        return None
    raw_inner = dotted_name(receiver.func)
    if raw_inner is None:
        return None
    inner = resolve_import_target(raw_inner, imports)
    target = f"{inner}.{node.func.attr}"
    if target in HASHLIB_CHAIN_TARGETS:
        return target
    return None


def canonical_datetime_terminal_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    """Return the canonical target of a supported datetime terminal call, or None."""
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"isoformat", "timestamp"}:
        return None
    if node.args or node.keywords:
        # `.isoformat(sep=, timespec=)` / `.timestamp(...)` carry argument
        # semantics the native lowering does not reproduce; returning None keeps
        # the function on the Python fallback instead of crashing codegen.
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call) or receiver.args or receiver.keywords:
        return None
    raw_inner = dotted_name(receiver.func)
    if raw_inner is None:
        return None
    inner = resolve_import_target(raw_inner, imports)
    candidate = f"{inner}.{node.func.attr}"
    # Only the canonical targets that are actually supported natively (e.g. NOT
    # `utcnow().timestamp()`, which is excluded from DATETIME_TIMESTAMP_TARGETS).
    if candidate in DATETIME_ISOFORMAT_TARGETS or candidate in DATETIME_TIMESTAMP_TARGETS:
        return candidate
    return None


def canonical_method_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    """Return the canonical target of a supported str/bytes/list method call, or None."""
    if not isinstance(node.func, ast.Attribute):
        return None
    attr = node.func.attr
    if attr in {target.rsplit(".", 1)[1] for target in STR_METHOD_TARGETS}:
        return f"str.{attr}"
    if attr in {target.rsplit(".", 1)[1] for target in BYTES_METHOD_TARGETS}:
        return f"bytes.{attr}"
    if attr in {target.rsplit(".", 1)[1] for target in LIST_METHOD_TARGETS}:
        return f"list.{attr}"
    return None


def is_logging_get_logger_call(
    node: ast.AST,
    imports: dict[str, str],
    project_modules: Collection[str] = (),
) -> bool:
    """Report whether the node is a proven imported ``logging.getLogger`` call.

    ``resolve_import_target`` intentionally leaves an unknown raw spelling
    unchanged, so comparing only the resolved string would treat an unbound
    ``logging.getLogger`` as the stdlib constructor.  Logger receivers are later
    lowered without consulting their Python object; require the final import root
    here just as other receiver-ignored stdlib calls do.
    """
    if not isinstance(node, ast.Call):
        return False
    raw_target = dotted_name(node.func)
    if raw_target is None:
        return False
    return resolve_import_target(
        raw_target, imports
    ) == "logging.getLogger" and stdlib_receiver_is_proven_import(
        node.func,
        imports,
        project_modules=project_modules,
    )


def is_supported_effect_call(
    node: ast.AST,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> bool:
    """Report whether a call is a supported statement-level effect (e.g. list.append, logging)."""
    if not isinstance(node, ast.Call):
        return False
    target = canonical_call_target(node, imports, logger_names)
    return target == "print" or target in LOGGING_CANONICAL_TARGETS.values()


def resolve_import_target(target: str, imports: dict[str, str]) -> str:
    """Resolve a target name through import aliases to its canonical dotted path."""
    head, separator, tail = target.partition(".")
    imported = imports.get(head)
    if imported is None:
        return target
    if not separator:
        return imported
    return f"{imported}.{tail}"
