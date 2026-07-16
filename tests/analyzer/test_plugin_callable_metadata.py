"""Plugin API 1.3 callable metadata: record shape + closed body grammar (WP-4).

Callable metadata exposes, for a callable argument that resolves to a project
function, only immutable structured facts — qualname, ordered typed signature,
return type, accepted-native/runtime status, a closed typed body for the safe
scalar/row-UDF subset, and (at lower time) the resolved native Rust symbol. It
never exposes raw source, mutable AST, closures/globals, or executed objects.
Unsupported bodies are explicitly unavailable (fail closed).
"""

from __future__ import annotations

import json

import pytest

from rextio.plugins.api import (
    UNAVAILABLE_CALLABLE_BODY,
    CallableBody,
    CallableBodyExpr,
    CallableMeta,
    CallableParam,
    ClaimSite,
    ScalarLiteral,
)


def _row_udf_body() -> CallableBody:
    # x + 1.0
    return CallableBody(
        available=True,
        expression=CallableBodyExpr(
            kind="binop",
            op="+",
            result_type="float",
            children=(
                CallableBodyExpr(kind="param", param_index=0, name="x", result_type="float"),
                CallableBodyExpr(
                    kind="literal", literal=ScalarLiteral("float", 1.0), result_type="float"
                ),
            ),
        ),
    )


# --- record shape --------------------------------------------------------


def test_callable_meta_is_frozen_hashable_serializable() -> None:
    meta = CallableMeta(
        arg_index=1,
        qualname="app.mod.udf",
        params=(CallableParam("x", "float"),),
        return_type="float",
        accepts_native=True,
        native_symbol=None,
        body=_row_udf_body(),
    )
    assert isinstance(hash(meta), int)
    data = meta.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["arg_index"] == 1
    assert data["qualname"] == "app.mod.udf"
    assert data["params"] == [{"name": "x", "param_type": "float"}]
    assert data["accepts_native"] is True
    assert data["native_symbol"] is None
    assert data["body"]["available"] is True
    assert data["body"]["expression"]["kind"] == "binop"


def test_default_body_is_shared_unavailable_sentinel() -> None:
    meta = CallableMeta(arg_index=0, qualname="app.mod.f")
    assert meta.body is UNAVAILABLE_CALLABLE_BODY
    assert meta.body.available is False
    assert meta.body.expression is None
    assert meta.to_dict()["body"] == {
        "available": False,
        "unavailable_reason": None,
        "expression": None,
    }


def test_native_symbol_carried_after_resolution() -> None:
    # The native symbol is filled at lower time; a resolved meta round-trips it.
    meta = CallableMeta(
        arg_index=0,
        qualname="app.mod.udf",
        return_type="float",
        accepts_native=True,
        native_symbol="app_mod_udf",
    )
    assert meta.to_dict()["native_symbol"] == "app_mod_udf"


# --- closed body grammar -------------------------------------------------


def test_body_availability_consistency() -> None:
    with pytest.raises(ValueError, match="available CallableBody must carry an expression"):
        CallableBody(available=True, expression=None)
    with pytest.raises(ValueError, match="unavailable CallableBody must not carry an expression"):
        CallableBody(
            available=False,
            expression=CallableBodyExpr(kind="param", param_index=0, name="x"),
        )


def test_unavailable_body_records_reason() -> None:
    body = CallableBody(available=False, unavailable_reason="contains a loop")
    assert body.to_dict() == {
        "available": False,
        "unavailable_reason": "contains a loop",
        "expression": None,
    }


def test_supported_body_node_kinds() -> None:
    param = CallableBodyExpr(kind="param", param_index=0, name="row")
    field = CallableBodyExpr(kind="field", name="price", children=(param,), result_type="float")
    sub = CallableBodyExpr(kind="subscript", name="qty", children=(param,), result_type="int")
    unary = CallableBodyExpr(kind="unary", op="-", children=(field,))
    binop = CallableBodyExpr(kind="binop", op="*", children=(field, sub))
    boolean = CallableBodyExpr(
        kind="boolop",
        op="and",
        children=(
            CallableBodyExpr(kind="literal", literal=ScalarLiteral("bool", True)),
            CallableBodyExpr(kind="literal", literal=ScalarLiteral("bool", False)),
        ),
    )
    compare = CallableBodyExpr(kind="compare", ops=("<", "<="), children=(field, sub, field))
    call = CallableBodyExpr(kind="call", target="math.sqrt", children=(field,), result_type="float")
    cond = CallableBodyExpr(kind="cond", children=(compare, binop, unary))
    # All construct and serialize without error.
    for node in (param, field, sub, unary, binop, boolean, compare, call, cond):
        assert json.loads(json.dumps(node.to_dict()))["kind"] == node.kind


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        (dict(kind="whoops"), "unsupported CallableBodyExpr kind"),
        (dict(kind="param"), "param requires a non-negative param_index"),
        (dict(kind="literal"), "literal requires a ScalarLiteral"),
        (dict(kind="field", name="a"), "requires a name and one child"),
        (dict(kind="unary", op="!!"), "unary requires a unary op and one child"),
        (dict(kind="binop", op="or"), "binop requires a binary op and two children"),
        (dict(kind="boolop", op="and"), "boolop requires a bool op and >=2 children"),
        (dict(kind="compare", ops=("~",)), "compare requires ops from the closed set"),
        (dict(kind="cond"), "cond requires"),
        (dict(kind="call"), "call requires a dotted target"),
    ],
)
def test_body_node_grammar_fails_closed(kwargs: dict, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        CallableBodyExpr(**kwargs)


@pytest.mark.parametrize(
    ("kind", "value", "fragment"),
    [
        ("int", True, "non-bool int"),
        ("bool", 1, "requires a bool value"),
        ("float", 1, "requires a float value"),
        ("str", 5, "requires a str value"),
        ("none", 0, "must have value=None"),
        ("bytes", b"x", "unsupported ScalarLiteral kind"),
    ],
)
def test_scalar_literal_fails_closed(kind: str, value: object, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        ScalarLiteral(kind, value)  # type: ignore[arg-type]


def test_scalar_literal_serialization() -> None:
    assert ScalarLiteral("none").to_dict() == {"kind": "none", "value": None}
    assert ScalarLiteral("str", "hi").to_dict() == {"kind": "str", "value": "hi"}
    assert ScalarLiteral("bool", False).to_dict() == {"kind": "bool", "value": False}


# --- record invariants (canonical form / cache-key safety) --------------


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_float_literal_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        ScalarLiteral("float", value)


def test_callable_meta_rejects_negative_arg_index() -> None:
    with pytest.raises(ValueError, match="arg_index must be non-negative"):
        CallableMeta(arg_index=-1, qualname="a.b")


def test_callable_meta_rejects_empty_qualname() -> None:
    with pytest.raises(ValueError, match="qualname must be a non-empty string"):
        CallableMeta(arg_index=0, qualname="")


def test_callable_meta_rejects_duplicate_params() -> None:
    with pytest.raises(ValueError, match="duplicate parameter"):
        CallableMeta(
            arg_index=0,
            qualname="a.b",
            params=(CallableParam("x", "int"), CallableParam("x", "float")),
        )


def test_native_symbol_requires_accepts_native() -> None:
    with pytest.raises(ValueError, match="not accepts_native"):
        CallableMeta(arg_index=0, qualname="a.b", accepts_native=False, native_symbol="sym")


def test_callable_param_rejects_empty_name() -> None:
    with pytest.raises(ValueError, match="name must be a non-empty string"):
        CallableParam("")


def test_claim_site_rejects_duplicate_callable_arg_index() -> None:
    with pytest.raises(ValueError, match="multiple callables at arg_index"):
        ClaimSite(
            kind="call",
            target="obj.apply",
            operand_types=(),
            file_path="",
            line=0,
            column=0,
            callables=(
                CallableMeta(arg_index=0, qualname="a.f"),
                CallableMeta(arg_index=0, qualname="a.g"),
            ),
        )


# --- canonical invariants (WP-4 director review) -------------------------


def test_callable_meta_keyword_is_omitted_when_empty() -> None:
    # A positional callable keeps its exact pre-keyword serialization shape.
    positional = CallableMeta(arg_index=0, qualname="app.mod.udf")
    assert "keyword" not in positional.to_dict()
    # A keyword callable identifies its keyword name unambiguously and survives
    # a JSON round-trip (and hashes, for cache-key stability).
    keyed = CallableMeta(arg_index=0, qualname="app.mod.udf", keyword="func")
    assert keyed.to_dict()["keyword"] == "func"
    assert json.loads(json.dumps(keyed.to_dict()))["keyword"] == "func"
    assert hash(keyed) != hash(positional)  # the keyword participates in the key


def test_receiver_meta_is_safe_must_match_expr_kind() -> None:
    from rextio.plugins.api import ReceiverMeta

    # Only a plain name is safe; a name that claims to be unsafe is contradictory.
    with pytest.raises(ValueError, match="is_safe must be"):
        ReceiverMeta(arg_type="k", expr_kind="name", is_safe=False)
    # A non-name that claims to be safe is equally contradictory.
    with pytest.raises(ValueError, match="is_safe must be"):
        ReceiverMeta(arg_type="k", expr_kind="subscript", is_safe=True)
    # The consistent pairings construct fine.
    assert ReceiverMeta(arg_type="k", expr_kind="name", is_safe=True).is_safe is True
    assert ReceiverMeta(arg_type="k", expr_kind="call", is_safe=False).is_safe is False


def test_available_callable_body_rejects_unavailable_reason() -> None:
    with pytest.raises(ValueError, match="must not carry an unavailable_reason"):
        CallableBody(
            available=True,
            unavailable_reason="contradiction",
            expression=CallableBodyExpr(kind="literal", literal=ScalarLiteral("int", 1)),
        )


def test_callable_body_expr_rejects_empty_result_type() -> None:
    with pytest.raises(ValueError, match="result_type must be a non-empty string or None"):
        CallableBodyExpr(kind="param", param_index=0, name="x", result_type="")


def test_callable_body_expr_rejects_irrelevant_payload() -> None:
    # A binop must not also carry an irrelevant name/target/literal payload, so
    # two semantically identical nodes never split their cache keys.
    kids = (
        CallableBodyExpr(kind="param", param_index=0, name="x", result_type="int"),
        CallableBodyExpr(kind="literal", literal=ScalarLiteral("int", 1), result_type="int"),
    )
    with pytest.raises(ValueError, match="must not carry a 'name'"):
        CallableBodyExpr(kind="binop", op="+", children=kids, result_type="int", name="stray")
    # A param must not carry stray operator/children payloads.
    with pytest.raises(ValueError, match="must not carry a 'children'"):
        CallableBodyExpr(kind="param", param_index=0, name="x", result_type="int", children=kids)


# --- canonical record string types (director follow-up 2, item 10) ----------
#
# A truthy NON-string value must not slip past the non-empty checks: every
# string-typed field on the API 1.3 records is enforced to be an actual string
# (non-empty where required, string-or-None where optional), so it can never
# split a cache key or break JSON serialization.


def test_callable_body_expr_rejects_non_string_result_type() -> None:
    with pytest.raises(ValueError, match="result_type must be a non-empty string or None"):
        CallableBodyExpr(kind="param", param_index=0, name="x", result_type=5)  # type: ignore[arg-type]


def test_callable_body_expr_rejects_non_string_name() -> None:
    with pytest.raises(ValueError, match="name must be a string"):
        CallableBodyExpr(kind="param", param_index=0, name=5, result_type="int")  # type: ignore[arg-type]


def test_callable_body_expr_rejects_non_string_op() -> None:
    child = CallableBodyExpr(kind="param", param_index=0, name="x", result_type="int")
    with pytest.raises(ValueError, match="op must be a string"):
        CallableBodyExpr(kind="unary", op=1, children=(child,), result_type="int")  # type: ignore[arg-type]


def test_callable_body_expr_rejects_non_string_ops_entry() -> None:
    left = CallableBodyExpr(kind="param", param_index=0, name="a", result_type="int")
    right = CallableBodyExpr(kind="param", param_index=1, name="b", result_type="int")
    with pytest.raises(ValueError, match="ops must contain only non-empty strings"):
        CallableBodyExpr(
            kind="compare",
            ops=(1,),
            children=(left, right),
            result_type="bool",  # type: ignore[arg-type]
        )


def test_callable_param_rejects_non_string_name_and_type() -> None:
    with pytest.raises(ValueError, match="name must be a non-empty string"):
        CallableParam(5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="param_type must be a non-empty string or None"):
        CallableParam("x", 7)  # type: ignore[arg-type]


def test_callable_meta_rejects_non_string_qualname_and_fields() -> None:
    with pytest.raises(ValueError, match="qualname must be a non-empty string"):
        CallableMeta(arg_index=0, qualname=5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="return_type must be a non-empty string or None"):
        CallableMeta(arg_index=0, qualname="a.b", return_type=3)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="native_symbol must be a non-empty string or None"):
        CallableMeta(arg_index=0, qualname="a.b", accepts_native=True, native_symbol=9)  # type: ignore[arg-type]


def test_receiver_meta_rejects_non_string_arg_type() -> None:
    from rextio.plugins.api import ReceiverMeta

    with pytest.raises(ValueError, match="arg_type must be a non-empty string or None"):
        ReceiverMeta(arg_type=5, expr_kind="name", is_safe=True)  # type: ignore[arg-type]


def test_receiver_meta_rejects_non_string_expr_kind() -> None:
    from rextio.plugins.api import ReceiverMeta

    with pytest.raises(ValueError, match="unsupported ReceiverMeta expr_kind"):
        ReceiverMeta(arg_type="k", expr_kind=7, is_safe=False)  # type: ignore[arg-type]


def test_schema_records_reject_non_string_values() -> None:
    from rextio.plugins.api import SchemaField, SchemaMeta

    with pytest.raises(ValueError, match="name must be a non-empty string"):
        SchemaField(5, "int")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty string field_type"):
        SchemaField("a", 3)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="identity must be a non-empty string"):
        SchemaMeta(5)  # type: ignore[arg-type]
