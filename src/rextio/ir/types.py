"""Rextio's type lattice (``RxtType``) and annotation parsing.

The supported native types and the helpers that resolve a Python annotation (AST or
string) into one. An unsupported annotation raises ``ValueError`` so the caller can
reject the function rather than mis-type it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from rextio.devices.api import DeviceValueMetadata


class RxtType:
    """Base class for every supported Rextio type.

    Subclasses must override :meth:`display_name`; the base raises
    ``NotImplementedError`` and ``to_dict`` relies on it.
    """

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type (subclasses override)."""
        raise NotImplementedError

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {"kind": self.display_name()}


@dataclass(frozen=True)
class RxtInt(RxtType):
    """The ``int`` type (lowered to a fixed-width i64)."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "int"


@dataclass(frozen=True)
class RxtFloat(RxtType):
    """The ``float`` type (f64)."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "float"


@dataclass(frozen=True)
class RxtBool(RxtType):
    """The ``bool`` type."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "bool"


@dataclass(frozen=True)
class RxtStr(RxtType):
    """The ``str`` type."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "str"


@dataclass(frozen=True)
class RxtBytes(RxtType):
    """The ``bytes`` type."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "bytes"


@dataclass(frozen=True)
class RxtNone(RxtType):
    """The ``None`` type."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "None"


@dataclass(frozen=True)
class RxtPyObject(RxtType):
    """An opaque Python object (the dynamic-semantics escape hatch)."""

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return "object"


@dataclass(frozen=True)
class RxtList(RxtType):
    """A homogeneous ``list[item_type]``."""

    item_type: RxtType

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return f"list[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "kind": "list",
            "item_type": self.item_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtSet(RxtType):
    """A homogeneous ``set[item_type]``."""

    item_type: RxtType

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return f"set[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "kind": "set",
            "item_type": self.item_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtTuple(RxtType):
    """A fixed-shape ``tuple[...]`` of element types."""

    item_types: tuple[RxtType, ...]

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return f"tuple[{', '.join(item.display_name() for item in self.item_types)}]"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "kind": "tuple",
            "item_types": [item.to_dict() for item in self.item_types],
        }


@dataclass(frozen=True)
class RxtDict(RxtType):
    """A homogeneous ``dict[key_type, value_type]``."""

    key_type: RxtType
    value_type: RxtType

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return f"dict[{self.key_type.display_name()}, {self.value_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "kind": "dict",
            "key_type": self.key_type.to_dict(),
            "value_type": self.value_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtOptional(RxtType):
    """An ``Optional[item_type]`` (i.e. ``item_type | None``)."""

    item_type: RxtType

    def display_name(self) -> str:
        """Return the human-readable Python-style name of this type."""
        return f"Optional[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "kind": "optional",
            "item_type": self.item_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtPluginType(RxtType):
    """A plugin-provided type resolved from a plugin's annotation vocabulary.

    ``key`` is the plugin type's stable id (e.g. ``rextio-numpy/f64-1d``);
    ``native_rust`` is its native representation inside generated code; the
    remaining fields carry the boundary conversion (PyO3 parameter/return
    types and the conversion expressions) from the plugin's
    ``BoundaryConversion`` (docs/specs/plugin-lowering.md section 4).

    ``resident`` (plugin API 1.3) marks an opaque, native-only value with no
    Python boundary conversion: the conversion fields are empty and the type
    NEVER crosses an exported PyO3 boundary. A resident value flows only
    through claimed plugin expressions, locals, and accepted native helper
    calls (native-to-native chaining).
    """

    key: str
    native_rust: str
    param_rust: str = ""
    param_expr: str = ""
    return_rust: str = ""
    return_expr: str = ""
    resident: bool = False
    # Exact-text Rust module support this type OWNS (plugin API 1.3), threaded
    # from ``PluginType.uses``/``helpers`` through the build/type-map path. A
    # function whose signature references this type contributes these ``use``
    # lines / module-level items so a signature-only accepted function (zero
    # claims) still emits the symbols its conversion/native type references.
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()
    device_value_metadata: DeviceValueMetadata | None = None

    def display_name(self) -> str:
        """Return the human-readable name of this type (the plugin type key)."""
        return self.key

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type.

        Materialized (boundary-converting) types with no module support keep
        their exact legacy byte-shape — no ``resident``/``uses``/``helpers``
        keys. Only a resident (opaque, native-only — plugin API 1.3) type adds
        ``resident: true``; non-empty support is emitted as order-preserving
        lists so IR identity moves when the support changes.
        """
        result: dict[str, object] = {
            "kind": "plugin",
            "key": self.key,
            "native_rust": self.native_rust,
        }
        if self.resident:
            result["resident"] = True
        if self.uses:
            result["uses"] = list(self.uses)
        if self.helpers:
            result["helpers"] = list(self.helpers)
        if self.device_value_metadata is not None:
            result["device_value_metadata"] = self.device_value_metadata.to_dict()
        return result


# Capitalized typing aliases (`List[int]`, `typing.List[int]`, ...) that are not
# the lowercase builtin form. Normalizing them lets a `typing`-style annotation be
# recognized as its builtin equivalent (e.g. by the delegation wire-type checks and
# by `type_from_string` in codegen) instead of being mis-parsed or over-rejected.
_TYPING_ALIASES = {
    "List": "list",
    "Dict": "dict",
    "Set": "set",
    "Tuple": "tuple",
    "FrozenSet": "frozenset",
}


def normalize_type_name(type_name: str | None) -> str | None:
    """Map capitalized/`typing.`-qualified aliases to the builtin form.

    ``List[int]``/``typing.List[int]`` -> ``list[int]`` (recursively). A ``None``
    input, a bare scalar, or an already-lowercase form is returned unchanged.

    Single-parameter generics only: the inner slot is normalized as one unit, so a
    comma-separated parameter list (``Dict[str, List[int]]``) or a union
    (``list[int] | None``) is *not* recursively normalized. That is safe for every
    current caller because only immutable scalars are delegatable wire types, so a
    multi-parameter or union annotation is rejected by the membership check
    regardless of how it normalizes. Use ``type_from_annotation`` for a full parse.
    """
    if type_name is None:
        return None
    name = type_name.strip()
    if name.startswith("typing."):
        name = name[len("typing.") :]
    head, sep, rest = name.partition("[")
    head = _TYPING_ALIASES.get(head.strip(), head.strip())
    if not sep:
        return head
    inner = rest[:-1] if rest.endswith("]") else rest
    return f"{head}[{normalize_type_name(inner)}]"


def type_from_annotation(node: ast.AST | None) -> RxtType:
    """Resolve a type-annotation AST node into an ``RxtType``.

    Raises ``ValueError`` for a missing or unsupported annotation.
    """
    if node is None:
        raise ValueError("missing type annotation")
    if isinstance(node, ast.Name):
        if node.id == "int":
            return RxtInt()
        if node.id == "float":
            return RxtFloat()
        if node.id == "bool":
            return RxtBool()
        if node.id == "str":
            return RxtStr()
        if node.id == "bytes":
            return RxtBytes()
        if node.id == "None":
            return RxtNone()
    if isinstance(node, ast.Constant) and node.value is None:
        return RxtNone()
    optional_inner = _optional_inner(node)
    if optional_inner is not None:
        return RxtOptional(type_from_annotation(optional_inner))
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id == "list":
            return RxtList(type_from_annotation(node.slice))
        if node.value.id == "set":
            return RxtSet(type_from_annotation(node.slice))
        if node.value.id == "tuple":
            return RxtTuple(
                tuple(type_from_annotation(item) for item in _tuple_slice_items(node.slice))
            )
        if node.value.id == "dict":
            items = _tuple_slice_items(node.slice)
            if len(items) == 2:
                return RxtDict(type_from_annotation(items[0]), type_from_annotation(items[1]))
    raise ValueError(f"unsupported type annotation: {ast.unparse(node)}")


def type_from_string(value: str) -> RxtType:
    """Resolve a type annotation given as a string into an ``RxtType``."""
    node = ast.parse(value, mode="eval").body
    return type_from_annotation(node)


def _optional_inner(node: ast.AST) -> ast.AST | None:
    """Return the inner annotation of an ``Optional[...]`` / ``X | None``, else None."""
    if isinstance(node, ast.Subscript) and _annotation_dotted_name(node.value) in {
        "Optional",
        "typing.Optional",
    }:
        return node.slice
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left_is_none = _is_none_annotation(node.left)
        right_is_none = _is_none_annotation(node.right)
        if left_is_none and not right_is_none:
            return node.right
        if right_is_none and not left_is_none:
            return node.left
    return None


def _is_none_annotation(node: ast.AST) -> bool:
    """Report whether the annotation node denotes ``None``."""
    return (isinstance(node, ast.Name) and node.id == "None") or (
        isinstance(node, ast.Constant) and node.value is None
    )


def _annotation_dotted_name(node: ast.AST) -> str | None:
    """Return the dotted name of a ``Name``/``Attribute`` annotation, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _annotation_dotted_name(node.value)
        if prefix is None:
            return None
        return f"{prefix}.{node.attr}"
    return None


def _tuple_slice_items(node: ast.AST) -> list[ast.AST]:
    """Return the elements of a subscript slice, treating a non-tuple as a single item."""
    if isinstance(node, ast.Tuple):
        return list(node.elts)
    return [node]
