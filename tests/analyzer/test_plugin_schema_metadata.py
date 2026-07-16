"""Plugin API 1.3 declared-schema metadata: record shape + static grammar (WP-4).

The declared-schema surface exposes an immutable, ordered schema identity and
fields (name + resolved scalar/plugin type) derived ONLY from a documented
static annotation grammar. It never infers a runtime object and never executes
an annotation expression. Malformed schemas fail closed via
:class:`SchemaGrammarError`.
"""

from __future__ import annotations

import ast
import json

import pytest

from rextio.analyzer.callable_metadata import (
    SchemaGrammarError,
    build_declared_schema,
)
from rextio.plugins.api import SchemaField, SchemaMeta

_SCALARS = {"int", "float", "bool", "str", "bytes"}


def _resolve(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name) and node.id in _SCALARS:
        return node.id
    if isinstance(node, ast.Name) and node.id == "Frame":
        return "rextio-frame/frame"
    return None


def _class(src: str) -> ast.ClassDef:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.ClassDef)
    return node


# --- record shape --------------------------------------------------------


def test_schema_is_ordered_frozen_hashable_serializable() -> None:
    schema = SchemaMeta(
        identity="app.Row",
        fields=(SchemaField("a", "int"), SchemaField("b", "float")),
    )
    # order preserved
    assert [f.name for f in schema.fields] == ["a", "b"]
    # hashable / cache-safe
    assert isinstance(hash(schema), int)
    # JSON-serializable through to_dict
    assert json.loads(json.dumps(schema.to_dict())) == {
        "identity": "app.Row",
        "fields": [
            {"name": "a", "field_type": "int"},
            {"name": "b", "field_type": "float"},
        ],
    }
    # value equality → determinism across builds
    assert schema == SchemaMeta(
        identity="app.Row", fields=(SchemaField("a", "int"), SchemaField("b", "float"))
    )


def test_schema_field_lookup() -> None:
    schema = SchemaMeta("app.Row", (SchemaField("a", "int"), SchemaField("b", "float")))
    assert schema.field_type("b") == "float"
    assert schema.field_type("missing") is None


def test_duplicate_field_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="duplicate schema field name"):
        SchemaMeta("app.Row", (SchemaField("a", "int"), SchemaField("a", "float")))


def test_schema_identity_must_be_non_empty() -> None:
    with pytest.raises(ValueError, match="identity must be a non-empty string"):
        SchemaMeta("", (SchemaField("a", "int"),))


def test_schema_field_rejects_empty_name_or_type() -> None:
    with pytest.raises(ValueError, match="name must be a non-empty string"):
        SchemaField("", "int")
    with pytest.raises(ValueError, match="non-empty string field_type"):
        SchemaField("a", "")


# --- static grammar ------------------------------------------------------


def test_grammar_builds_ordered_typed_fields() -> None:
    schema = build_declared_schema(
        "app.Row",
        _class('class Row:\n    """doc"""\n    a: int\n    b: float\n    c: Frame\n'),
        _resolve,
        plugin_type_keys={"rextio-frame/frame"},
    )
    assert schema.identity == "app.Row"
    assert [(f.name, f.field_type) for f in schema.fields] == [
        ("a", "int"),
        ("b", "float"),
        ("c", "rextio-frame/frame"),
    ]


def test_grammar_allows_empty_schema() -> None:
    schema = build_declared_schema("app.Empty", _class("class Empty:\n    pass\n"), _resolve)
    assert schema.fields == ()


_FAIL_CASES = [
    ("class X:\n    a: int\n    a: float\n", "duplicate"),
    ("class X:\n    a: int = 5\n", "default value"),
    ("class X:\n    a: make()\n", "dynamic"),
    ("class X:\n    a: Unknown\n", "does not resolve"),
    ("class X:\n    def m(self):\n        pass\n", "unsupported metadata"),
    ("class X:\n    x = 1\n", "unsupported metadata"),
    # A based / keyworded / decorated class carries class-level machinery the
    # documented schema grammar forbids (both surfaces must reject it).
    ("class X(Base):\n    a: int\n", "base classes"),
    ("class X(metaclass=Meta):\n    a: int\n", "base classes"),
    ("@deco\nclass X:\n    a: int\n", "base classes"),
]


@pytest.mark.parametrize(("src", "fragment"), _FAIL_CASES)
def test_grammar_fails_closed(src: str, fragment: str) -> None:
    with pytest.raises(SchemaGrammarError, match=fragment):
        build_declared_schema("X", _class(src), _resolve)


# --- the index path (build_schema_from_class) enforces the same grammar ------


def _indexed(src: str):
    from rextio.analyzer.callable_metadata import IndexedSymbol

    node = _class(src)
    return IndexedSymbol(qualname="app.X", name="X", node=node, module_name="app", imports={})


def _resolve_with_imports(node: ast.expr, _imports: dict[str, str]) -> str | None:
    return _resolve(node)


# --- section 5: field vocabulary is EXACTLY scalar or registered plugin key ---

from rextio.analyzer.type_collector import annotation_name, is_supported_type  # noqa: E402


def _resolve_broad(node: ast.expr) -> str | None:
    """A general type resolver: it can also name collections/optionals/unions."""
    if isinstance(node, ast.Name) and node.id == "Frame":
        return "rextio-frame/frame"
    return annotation_name(node) if is_supported_type(node) else None


_REJECTED_FIELD_TYPES = [
    "class X:\n    a: list[int]\n",
    "class X:\n    a: dict[str, float]\n",
    "class X:\n    a: set[int]\n",
    "class X:\n    a: tuple[int, float]\n",
    "class X:\n    a: Optional[int]\n",
    "class X:\n    a: int | None\n",
]


@pytest.mark.parametrize("src", _REJECTED_FIELD_TYPES)
def test_collection_optional_union_field_types_rejected(src: str) -> None:
    # The general resolver can name these, but the schema field vocabulary is
    # narrowed to a scalar or registered plugin key, so they fail closed.
    with pytest.raises(SchemaGrammarError, match="scalar or plugin type"):
        build_declared_schema("app.X", _class(src), _resolve_broad, plugin_type_keys=())


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("class X:\n    a: int\n    b: str\n", [("a", "int"), ("b", "str")]),
        ("class X:\n    a: Frame\n", [("a", "rextio-frame/frame")]),
    ],
)
def test_scalar_and_plugin_field_types_accepted(src: str, expected: list) -> None:
    schema = build_declared_schema(
        "app.X", _class(src), _resolve_broad, plugin_type_keys={"rextio-frame/frame"}
    )
    assert [(f.name, f.field_type) for f in schema.fields] == expected


def test_plugin_field_rejected_when_key_not_registered() -> None:
    # A plugin key that is not among the active registered keys is not part of
    # the vocabulary and fails closed even though the resolver named it.
    with pytest.raises(SchemaGrammarError, match="scalar or plugin type"):
        build_declared_schema("app.X", _class("class X:\n    a: Frame\n"), _resolve_broad)


def test_index_path_builds_valid_schema() -> None:
    from rextio.analyzer.callable_metadata import build_schema_from_class

    schema = build_schema_from_class(
        "app.X", _indexed("class X:\n    a: int\n    b: float\n"), _resolve_with_imports
    )
    assert schema is not None
    assert [(f.name, f.field_type) for f in schema.fields] == [("a", "int"), ("b", "float")]


@pytest.mark.parametrize(("src", "_fragment"), _FAIL_CASES)
def test_index_path_fails_closed_to_none(src: str, _fragment: str) -> None:
    # The project-index path shares the canonical grammar: every shape the public
    # builder rejects yields NO association (None) rather than a wrong schema.
    from rextio.analyzer.callable_metadata import build_schema_from_class

    assert build_schema_from_class("app.X", _indexed(src), _resolve_with_imports) is None


def test_grammar_never_executes_annotation() -> None:
    # A dynamic annotation is rejected BEFORE resolve_type is asked to evaluate
    # anything: the resolver here would raise if ever called on a Call node.
    def strict_resolve(node: ast.expr) -> str | None:
        if isinstance(node, ast.Call):  # pragma: no cover - must never run
            raise AssertionError("annotation expression was evaluated")
        return _resolve(node)

    with pytest.raises(SchemaGrammarError, match="dynamic"):
        build_declared_schema("X", _class("class X:\n    a: danger()\n"), strict_resolve)
