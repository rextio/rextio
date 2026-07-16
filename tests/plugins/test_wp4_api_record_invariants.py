"""WP-4 follow-up 4, section 4: canonical API 1.3 record invariants.

Every successfully constructed API 1.3 metadata record must be immutable,
hashable/cache-key safe, and deterministically serializable. Malformed shapes
(a non-string unavailable_reason, a mutable list container, a wrong-typed member,
an out-of-range/bool scalar literal) must fail closed at construction.
"""

from __future__ import annotations

import json

import pytest

from rextio.plugins.api import (
    CallableBody,
    CallableBodyExpr,
    CallableMeta,
    CallableParam,
    ReceiverMeta,
    ScalarLiteral,
    SchemaField,
    SchemaMeta,
)

_I64_MAX = 2**63 - 1
_I64_MIN = -(2**63)


def _param(index: int = 0, name: str = "x", result_type: str = "int") -> CallableBodyExpr:
    return CallableBodyExpr(kind="param", param_index=index, name=name, result_type=result_type)


def _compare_expr() -> CallableBodyExpr:
    return CallableBodyExpr(
        kind="compare",
        ops=("==",),
        children=(
            _param(),
            CallableBodyExpr(kind="literal", literal=ScalarLiteral("int", 1), result_type="int"),
        ),
        result_type="bool",
    )


def test_records_are_hashable_and_cache_key_safe() -> None:
    meta = CallableMeta(
        arg_index=0,
        qualname="m.f",
        params=(CallableParam("x", "int"),),
        return_type="bool",
        accepts_native=True,
        body=CallableBody(available=True, expression=_compare_expr()),
    )
    # Hashable and usable as a cache/dedup key.
    assert isinstance(hash(meta), int)
    assert len({meta, meta}) == 1
    # Value equality → deterministic across builds.
    other = CallableMeta(
        arg_index=0,
        qualname="m.f",
        params=(CallableParam("x", "int"),),
        return_type="bool",
        accepts_native=True,
        body=CallableBody(available=True, expression=_compare_expr()),
    )
    assert meta == other and hash(meta) == hash(other)
    # JSON-serializable.
    assert json.loads(json.dumps(meta.to_dict()))["qualname"] == "m.f"


@pytest.mark.parametrize("reason", [5, {}, "", b"x", 0])
def test_unavailable_reason_must_be_nonempty_string_or_none(reason: object) -> None:
    with pytest.raises(ValueError, match="unavailable_reason must be a non-empty string or None"):
        CallableBody(available=False, unavailable_reason=reason)  # type: ignore[arg-type]


def test_unavailable_reason_none_is_allowed() -> None:
    assert CallableBody(available=False, unavailable_reason=None).unavailable_reason is None
    assert CallableBody(available=False, unavailable_reason="calls a shim").unavailable_reason


def test_mutable_list_containers_are_rejected() -> None:
    with pytest.raises(ValueError, match="ops must be a tuple"):
        CallableBodyExpr(kind="compare", ops=["=="], children=(_param(), _param(1, "y")))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="children must be a tuple"):
        CallableBodyExpr(kind="binop", op="+", children=[_param(), _param(1, "y")])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="params must be a tuple"):
        CallableMeta(arg_index=0, qualname="m.f", params=[CallableParam("x", "int")])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="fields must be a tuple"):
        SchemaMeta(identity="R", fields=[SchemaField("a", "int")])  # type: ignore[arg-type]


def test_wrong_member_types_are_rejected() -> None:
    with pytest.raises(ValueError, match="children must be a tuple of CallableBodyExpr"):
        CallableBodyExpr(kind="binop", op="+", children=(_param(), "y"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="params must be a tuple of CallableParam"):
        CallableMeta(arg_index=0, qualname="m.f", params=("x",))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="body must be a CallableBody"):
        CallableMeta(arg_index=0, qualname="m.f", body="nope")  # type: ignore[arg-type]


def test_flag_and_index_types_are_enforced() -> None:
    with pytest.raises(ValueError, match="accepts_native/runtime_semantics must be bools"):
        CallableMeta(arg_index=0, qualname="m.f", accepts_native=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="arg_index must be a non-bool int"):
        CallableMeta(arg_index=True, qualname="m.f")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="param_index must be a non-bool int"):
        CallableBodyExpr(kind="param", param_index=True, name="x", result_type="int")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="is_safe must be a bool"):
        ReceiverMeta(arg_type="T", expr_kind="name", is_safe=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="available must be a bool"):
        CallableBody(available=1)  # type: ignore[arg-type]


def test_scalar_literal_i64_boundaries() -> None:
    assert ScalarLiteral("int", _I64_MAX).value == _I64_MAX
    assert ScalarLiteral("int", _I64_MIN).value == _I64_MIN
    for beyond in (_I64_MAX + 1, _I64_MIN - 1, 2**63):
        with pytest.raises(ValueError, match="outside the supported i64 range"):
            ScalarLiteral("int", beyond)


def test_scalar_literal_bool_and_kind_separation() -> None:
    with pytest.raises(ValueError, match="kind='int' requires a non-bool int"):
        ScalarLiteral("int", True)
    with pytest.raises(ValueError, match="kind='bool' requires a bool"):
        ScalarLiteral("bool", 1)
    with pytest.raises(ValueError, match="unsupported ScalarLiteral kind"):
        ScalarLiteral(5, 1)  # type: ignore[arg-type]


def test_scalar_literal_finite_float_rule() -> None:
    assert ScalarLiteral("float", 1.5).value == 1.5
    for bad in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(ValueError, match="finite"):
            ScalarLiteral("float", bad)
