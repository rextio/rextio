"""Consistency tests between the capability registry and the Rust backend.

These pin the invariant that motivates `rextio.capabilities` (mod-proposal P2-5):
every type the analyzer is willing to accept into the native subset must have a
Rust lowering, so the analyzer and code generator cannot drift into the
"analysis accepts, codegen fails" state.
"""

from __future__ import annotations

import ast

import pytest

from rextio import capabilities
from rextio.codegen.rust.type_map import rust_type
from rextio.ir.types import RxtDict, RxtList, RxtSet, RxtStr, type_from_annotation


def _rxt(name: str):
    return type_from_annotation(ast.parse(name, mode="eval").body)


@pytest.mark.parametrize("name", sorted(capabilities.SCALAR_TYPES))
def test_every_scalar_type_has_a_rust_mapping(name: str) -> None:
    assert rust_type(_rxt(name))


@pytest.mark.parametrize("name", sorted(capabilities.LIST_ITEM_TYPES))
def test_every_list_item_type_has_a_rust_mapping(name: str) -> None:
    assert rust_type(RxtList(_rxt(name)))


@pytest.mark.parametrize("name", sorted(capabilities.SET_ITEM_TYPES))
def test_every_set_item_type_has_a_rust_mapping(name: str) -> None:
    assert rust_type(RxtSet(_rxt(name)))


@pytest.mark.parametrize("name", sorted(capabilities.DICT_KEY_TYPES))
def test_every_dict_key_type_has_a_rust_mapping(name: str) -> None:
    # str values keep the dict generic enough to exercise key + value mapping.
    assert rust_type(RxtDict(_rxt(name), RxtStr()))


def test_registry_values_are_pinned() -> None:
    # Deliberate "tripwire": snapshotting the exact element sets (rather than only
    # invariants like subset relationships) means any change to the capability
    # matrix — adding a type, or accidentally dropping e.g. `bytes` — must be made
    # here too, turning it into a reviewable decision instead of silent drift. The
    # duplication with rextio.capabilities is the point, not a maintenance smell.
    assert capabilities.SCALAR_TYPES == frozenset({"int", "float", "bool", "str", "bytes"})
    assert capabilities.NUMERIC_TYPES == frozenset({"int", "float"})
    assert capabilities.LIST_ITEM_TYPES == frozenset({"int", "float", "bool", "str"})
    assert capabilities.DICT_KEY_TYPES == frozenset({"int", "bool", "str"})
    assert capabilities.SET_ITEM_TYPES == frozenset({"int", "float", "bool", "str"})
    assert capabilities.JSON_VALUE_TYPES == frozenset({"int", "float", "bool", "str", "bytes"})


def test_capability_sets_are_immutable() -> None:
    # The shared matrix must not be mutable, so a caller cannot corrupt it.
    for value in (
        capabilities.SCALAR_TYPES,
        capabilities.NUMERIC_TYPES,
        capabilities.LIST_ITEM_TYPES,
        capabilities.DICT_KEY_TYPES,
        capabilities.SET_ITEM_TYPES,
        capabilities.JSON_VALUE_TYPES,
    ):
        assert isinstance(value, frozenset)


def test_capability_subsets_are_coherent() -> None:
    # Numeric scalars are a subset of all scalars; list/dict/set item/key types
    # must themselves be supported scalar types (no container can hold a type the
    # subset does not otherwise accept).
    assert capabilities.NUMERIC_TYPES <= capabilities.SCALAR_TYPES
    assert capabilities.LIST_ITEM_TYPES <= capabilities.SCALAR_TYPES
    assert capabilities.SET_ITEM_TYPES <= capabilities.SCALAR_TYPES
    assert capabilities.DICT_KEY_TYPES <= capabilities.SCALAR_TYPES
    assert capabilities.JSON_VALUE_TYPES <= capabilities.SCALAR_TYPES
