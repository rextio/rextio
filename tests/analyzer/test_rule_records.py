from __future__ import annotations

import pytest

from rextio.analyzer.diagnostic_codes import DIAGNOSTIC_CODES
from rextio.analyzer.rule_records import core_rule_records
from rextio.plugins.api import RuleRecord, RuleScope


def test_core_rule_ids_are_unique_and_namespaced() -> None:
    records = core_rule_records()
    ids = [record.id for record in records]
    assert len(ids) == len(set(ids))
    assert all(record.id.startswith("core/") for record in records)
    assert all(record.provider == "core" for record in records)


def test_core_rule_diagnostic_codes_are_registered() -> None:
    unregistered = sorted(
        record.diagnostic_code
        for record in core_rule_records()
        if record.diagnostic_code is not None and record.diagnostic_code not in DIAGNOSTIC_CODES
    )
    assert unregistered == [], f"rule records reference unregistered codes: {unregistered}"


def test_core_rules_carry_guidance_and_constraint() -> None:
    for record in core_rule_records():
        assert record.constraint.strip(), record.id
        assert record.guidance.strip(), record.id


def test_core_rules_are_sorted_by_id() -> None:
    ids = [record.id for record in core_rule_records()]
    assert ids == sorted(ids)


def test_rule_record_rejects_unknown_outcome() -> None:
    with pytest.raises(ValueError, match="unsupported rule outcome"):
        RuleRecord(
            id="core/x",
            provider="core",
            scope=RuleScope(kind="type", pattern="x"),
            constraint="c",
            outcome="maybe",
            diagnostic_code=None,
            guidance="g",
        )


def test_rule_scope_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unsupported rule scope kind"):
        RuleScope(kind="vibe", pattern="x")


def test_rule_record_to_dict_omits_absent_l3_fields() -> None:
    record = core_rule_records()[0]
    data = record.to_dict()
    assert "fix_template" not in data
    assert "examples" not in data
    assert set(data) == {
        "id",
        "provider",
        "scope",
        "constraint",
        "outcome",
        "diagnostic_code",
        "guidance",
        "stability",
    }


def test_rule_record_to_dict_includes_l3_fields_when_present() -> None:
    record = RuleRecord(
        id="core/x",
        provider="core",
        scope=RuleScope(kind="type", pattern="x"),
        constraint="c",
        outcome="fallback",
        diagnostic_code="RXT002",
        guidance="g",
        fix_template={"kind": "rewrite-hint", "before": "a", "after": "b"},
        examples=({"before": "a", "after": "b", "note": "n"},),
    )
    data = record.to_dict()
    assert data["fix_template"] == {"kind": "rewrite-hint", "before": "a", "after": "b"}
    assert data["examples"] == [{"before": "a", "after": "b", "note": "n"}]
