"""Shared record types for the machine-readable tooling contract.

These dataclasses are the L2 "rule record" surface defined by
docs/specs/tooling-contract.md: structured, machine-readable descriptions of
the rules that decide whether code lowers to native. Core emits its own records
(see ``rextio.analyzer.rule_records``); plugin protocol v2 will emit plugin
records through ``describe()``. They live in the plugins package because the
record shape is the contract third-party plugins implement against.

Rule records are deliberately declarative data, not behavior: the analyzer
remains the authority on what actually lowers. A record's ``diagnostic_code``
ties it to the registry in ``rextio.analyzer.diagnostic_codes`` so consumers
can key remediation guidance off the codes that appear in ``rextio check``
output.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

RULE_SCOPE_KINDS = frozenset({"type", "syntax", "call", "import", "decorator"})
RULE_OUTCOMES = frozenset({"native", "fallback", "reject", "shim", "boundary"})
RULE_STABILITY_TIERS = frozenset({"stable", "experimental"})


@dataclass(frozen=True)
class RuleScope:
    """Where a rule applies: the construct kind and a human-readable pattern."""

    kind: str
    pattern: str

    def __post_init__(self) -> None:
        """Validate the scope kind against the contract's closed set."""
        if self.kind not in RULE_SCOPE_KINDS:
            options = ", ".join(sorted(RULE_SCOPE_KINDS))
            raise ValueError(f"unsupported rule scope kind: {self.kind!r}. Use {options}.")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this scope."""
        return {"kind": self.kind, "pattern": self.pattern}


@dataclass(frozen=True)
class RuleRecord:
    """A single L2 rule record of the tooling contract.

    Required fields are the L2 tier (mandatory for every provider, including
    third-party plugins). ``fix_template`` and ``examples`` are the optional
    L3 tier — recommended, filled per rule as capacity allows.
    """

    id: str
    provider: str
    scope: RuleScope
    constraint: str
    outcome: str
    # The RXT/RXTP code emitted when the rule fires; None for rules that apply
    # silently (e.g. an accelerator decorator routing a function to fallback
    # without a diagnostic).
    diagnostic_code: str | None
    guidance: str
    stability: str = "stable"
    fix_template: Mapping[str, str] | None = None
    examples: tuple[Mapping[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Validate the closed-set fields against the contract."""
        if self.outcome not in RULE_OUTCOMES:
            options = ", ".join(sorted(RULE_OUTCOMES))
            raise ValueError(f"unsupported rule outcome: {self.outcome!r}. Use {options}.")
        if self.stability not in RULE_STABILITY_TIERS:
            options = ", ".join(sorted(RULE_STABILITY_TIERS))
            raise ValueError(f"unsupported rule stability: {self.stability!r}. Use {options}.")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this rule record.

        The optional L3 fields are emitted only when present, so L2-only
        records keep a stable, compact shape.
        """
        data: dict[str, object] = {
            "id": self.id,
            "provider": self.provider,
            "scope": self.scope.to_dict(),
            "constraint": self.constraint,
            "outcome": self.outcome,
            "diagnostic_code": self.diagnostic_code,
            "guidance": self.guidance,
            "stability": self.stability,
        }
        if self.fix_template is not None:
            data["fix_template"] = dict(self.fix_template)
        if self.examples:
            data["examples"] = [dict(example) for example in self.examples]
        return data
