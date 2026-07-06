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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Union

from rextio.analyzer.diagnostics import Diagnostic

if TYPE_CHECKING:
    from rextio.config.schema import RextioConfig

# "binop" describes operator lowering surfaces (ClaimSite kind "binop"), so a
# plugin claiming `+`/`-`/`*`/`/` can label the rule accurately (council
# round 4: the closed set had no vocabulary for operator rules and the
# first-party numpy elementwise rule was mislabeled "call").
RULE_SCOPE_KINDS = frozenset({"type", "syntax", "call", "binop", "import", "decorator"})
RULE_OUTCOMES = frozenset({"native", "fallback", "reject", "shim", "boundary"})
RULE_STABILITY_TIERS = frozenset({"stable", "experimental"})

# The plugin-API version this core implements. SemVer over the protocol
# surface: a v2 plugin declares the api_version it was built against, and the
# loader accepts it when the major version matches. 1.1 added the optional
# lowering members (type_vocabulary/claim/lower/crate_dependencies) from
# docs/specs/plugin-lowering.md.
PLUGIN_API_VERSION = "1.1"

# Crate dependency pins are exact by decree of the lowering spec: a plugin
# without an exact pin fails to load.
CRATE_PIN_PATTERN = re.compile(r"^=\d+\.\d+\.\d+$")

# Plugin diagnostic codes are namespaced ``RXTP-<PLUGIN>-NNN`` where <PLUGIN>
# is the plugin's code segment (its id, uppercased, with a leading "rextio-"
# stripped and non-alphanumerics removed): rextio-numpy -> RXTP-NUMPY-001.
PLUGIN_DIAGNOSTIC_CODE_PATTERN = re.compile(r"^RXTP-([A-Z0-9]+)-\d{3}$")


def plugin_code_segment(plugin_id: str) -> str:
    """Return the ``<PLUGIN>`` segment plugin diagnostic codes must carry."""
    stem = plugin_id[len("rextio-"):] if plugin_id.startswith("rextio-") else plugin_id
    segment = re.sub(r"[^A-Z0-9]", "", stem.upper())
    if not segment:
        raise ValueError(
            f"plugin id {plugin_id!r} yields an empty diagnostic-code segment; "
            "plugin ids must contain at least one alphanumeric character "
            "(after the optional 'rextio-' prefix)"
        )
    return segment


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
    # Certification status (docs/specs/plugin-lowering.md section 6): True when
    # the rule's lowering passed the plugin certification kit, False when it
    # failed or was skipped, None when certification does not apply (e.g.
    # describe-only rules). Emitted only when set.
    verified: bool | None = None
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
        if self.verified is not None:
            data["verified"] = self.verified
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


@dataclass(frozen=True)
class BoundaryConversion:
    """How a plugin type crosses the Python<->Rust boundary of a PyO3 function.

    Placeholders: ``{param}`` in ``param_expr`` is the PyO3 parameter name;
    ``{value}`` in ``return_expr`` is the native result expression. Arguments
    are read-only borrows and returns transfer ownership of newly allocated
    values (docs/specs/plugin-lowering.md section 4).

    Both expressions are ``str.format`` templates: literal braces in the Rust
    text (closures, struct literals, blocks) must be doubled — ``{{`` and
    ``}}`` — or formatting fails at codegen.
    """

    param_rust: str
    param_expr: str
    return_rust: str
    return_expr: str

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this conversion."""
        return {
            "param_rust": self.param_rust,
            "param_expr": self.param_expr,
            "return_rust": self.return_rust,
            "return_expr": self.return_expr,
        }


@dataclass(frozen=True)
class PluginType:
    """A plugin-provided type the analyzer can resolve from annotations.

    ``annotations`` are the dotted spellings that resolve to this type (the
    plugin's explicit annotation vocabulary); ``rust_type`` is the native
    representation inside generated code.
    """

    key: str
    annotations: tuple[str, ...]
    rust_type: str
    conversion: BoundaryConversion

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type."""
        return {
            "key": self.key,
            "annotations": list(self.annotations),
            "rust_type": self.rust_type,
            "conversion": self.conversion.to_dict(),
        }


@dataclass(frozen=True)
class ClaimSite:
    """One candidate construct offered to a plugin's ``claim``.

    ``kind`` is ``call`` (dotted call target in ``target``) or ``binop``
    (operator token in ``target``); ``operand_types`` are the resolved operand
    or argument types in positional order (plugin type keys or core type
    names, ``None`` when unresolved).
    """

    kind: str
    target: str
    operand_types: tuple[str | None, ...]
    file_path: str
    line: int
    column: int

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this site."""
        return {
            "kind": self.kind,
            "target": self.target,
            "operand_types": list(self.operand_types),
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
        }


@dataclass(frozen=True)
class Claimed:
    """The plugin will lower this site under the given rule.

    ``result_type`` is the expression type the claimed site produces (a core
    type name or a plugin type key), so the analyzer's inference can keep
    typing the enclosing expression; ``None`` means unknown. (Spec amendment:
    added to the shape shown in docs/specs/plugin-lowering.md section 2 —
    without it, claimed sites would be untyped in the analyzer.)
    """

    rule_id: str
    result_type: str | None = None


@dataclass(frozen=True)
class NotCovered:
    """The site is not this plugin's business; core proceeds as usual."""


@dataclass(frozen=True)
class Rejected:
    """The site is covered but not lowerable; the diagnostic explains why."""

    diagnostic: Diagnostic


ClaimResult = Union[Claimed, NotCovered, Rejected]


@dataclass(frozen=True)
class LoweredExpr:
    """A plugin-lowered expression: one Rust expression plus its support items.

    ``rust`` is a single expression with no trailing semicolon; core owns
    statements, control flow, and temporaries. ``uses`` are deduplicated
    ``use`` lines; ``helpers`` are module-level items deduplicated by exact
    text.
    """

    rust: str
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoweringContext:
    """The codegen-side context handed to a plugin's ``lower()``.

    ``operands`` are the rendered Rust sub-expressions of the claimed site's
    operands/arguments in positional order (already lowered by core or by
    prior plugin claims); ``target_language`` names the active codegen backend
    (``"rust"``); ``fresh_name`` allocates a fresh temporary identifier in the
    enclosing function's namespace from a given prefix.
    """

    operands: tuple[str, ...]
    target_language: str
    fresh_name: Callable[[str], str]


@dataclass(frozen=True)
class CrateDependency:
    """A crate a plugin's generated code depends on, with a mandatory exact pin."""

    name: str
    version: str
    features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate the mandatory exact version pin (``=X.Y.Z``)."""
        if CRATE_PIN_PATTERN.match(self.version) is None:
            raise ValueError(
                f"crate dependency {self.name!r} must carry an exact version pin "
                f"(=X.Y.Z), got {self.version!r}"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this dependency."""
        return {
            "name": self.name,
            "version": self.version,
            "features": list(self.features),
        }


class RextioPluginV2(Protocol):
    """The self-describing plugin protocol (tooling contract, protocol v2).

    A v2 plugin entry point returns an object that provides the v1 metadata
    (a ``to_rextio_plugin()`` method returning :class:`RextioPlugin`, or an
    equivalent metadata mapping) **plus** the members below. The loader
    recognizes v2 by the presence of a callable ``describe``. Metadata-only
    (v1) plugins keep loading unchanged and simply provide no rules.

    Rule records are declarative descriptions; the lowering hooks live on the
    :class:`RextioLoweringPlugin` extension (plugin API 1.1). The analyzer
    remains the authority on which sites are offered and accepted.
    """

    plugin_id: str
    api_version: str

    def covers(self) -> CoverageDecl:
        """Return the coverage declaration for this plugin."""
        ...

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        """Return this plugin's rule records for the resolved configuration."""
        ...


class RextioLoweringPlugin(RextioPluginV2, Protocol):
    """A protocol-v2 plugin that also lowers code (plugin API 1.1).

    All four members below arrive together: the loader rejects a plugin that
    implements ``claim`` without ``lower`` or vice versa, and lowering
    requires the v2 base (``describe``/``covers``). The claim decision MUST
    be deterministic — identical (site, config) inputs always produce the
    identical result; core may cache it across analysis and codegen
    (docs/specs/plugin-lowering.md section 2).
    """

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        """Return the annotation vocabulary this plugin adds to the analyzer."""
        ...

    def claim(self, site: ClaimSite, config: RextioConfig) -> ClaimResult:
        """Decide, at analysis time, whether this plugin lowers the site."""
        ...

    def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
        """Emit the Rust expression for a previously claimed site.

        ``ctx`` is the codegen-side :class:`LoweringContext`: rendered operand
        sub-expressions in positional order, the target language, and
        fresh-name allocation. (Typed ``object`` here so 1.1 providers with
        looser annotations keep matching the protocol structurally.)
        """
        ...

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        """Return the pinned crates this plugin's generated code depends on."""
        ...
