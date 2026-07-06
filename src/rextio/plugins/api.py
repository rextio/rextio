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

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from rextio.config.schema import RextioConfig

RULE_SCOPE_KINDS = frozenset({"type", "syntax", "call", "import", "decorator"})
RULE_OUTCOMES = frozenset({"native", "fallback", "reject", "shim", "boundary"})
RULE_STABILITY_TIERS = frozenset({"stable", "experimental"})

# The plugin-API version this core implements. SemVer over the protocol
# surface: a v2 plugin declares the api_version it was built against, and the
# loader accepts it when the major version matches.
PLUGIN_API_VERSION = "1.0"

# Plugin diagnostic codes are namespaced ``RXTP-<PLUGIN>-NNN`` where <PLUGIN>
# is the plugin's code segment (its id, uppercased, with a leading "rextio-"
# stripped and non-alphanumerics removed): rextio-numpy -> RXTP-NUMPY-001.
PLUGIN_DIAGNOSTIC_CODE_PATTERN = re.compile(r"^RXTP-([A-Z0-9]+)-\d{3}$")


def plugin_code_segment(plugin_id: str) -> str:
    """Return the ``<PLUGIN>`` segment plugin diagnostic codes must carry."""
    stem = plugin_id[len("rextio-"):] if plugin_id.startswith("rextio-") else plugin_id
    return re.sub(r"[^A-Z0-9]", "", stem.upper())


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


@dataclass(frozen=True)
class CoverageDecl:
    """What a plugin can lower: the packages, modules, and symbols it covers.

    ``packages`` drives the ``plugin`` import policy and the RXT091
    plugin-lowerable hint; ``modules`` and ``symbols`` refine coverage for
    future per-call-site decisions and may be empty.
    """

    packages: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this coverage."""
        return {
            "packages": list(self.packages),
            "modules": list(self.modules),
            "symbols": list(self.symbols),
        }


class RextioPluginV2(Protocol):
    """The self-describing plugin protocol (tooling contract, protocol v2).

    A v2 plugin entry point returns an object that provides the v1 metadata
    (a ``to_rextio_plugin()`` method returning :class:`RextioPlugin`, or an
    equivalent metadata mapping) **plus** the members below. The loader
    recognizes v2 by the presence of a callable ``describe``. Metadata-only
    (v1) plugins keep loading unchanged and simply provide no rules.

    The actual lowering hook (``lower``) is intentionally not part of this
    protocol yet; rule records are declarative descriptions, and the analyzer
    remains the authority on what lowers.
    """

    plugin_id: str
    api_version: str

    def covers(self) -> CoverageDecl:
        """Return the coverage declaration for this plugin."""
        ...

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        """Return this plugin's rule records for the resolved configuration."""
        ...
