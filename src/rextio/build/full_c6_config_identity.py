"""Path-safe identity for the exact resolved artifact build configuration.

artifact build consumes the resolved :class:`~rextio.config.schema.RextioConfig`, not
only ``rextio.toml``.  CLI and environment overrides therefore have to be
part of the signed build-input graph as well.  This module canonicalizes the
complete typed configuration and exposes only an opaque digest and a bounded
member count.

Two lifecycle values have independent authority.  The finalized policy digest
is bound by the owner-policy bootstrap lineage and receipt, while the final
detached-signature path is opened and verified by the final gate.  They
necessarily change at the stage-1/stage-2 and stage-2/stage-3 boundaries,
respectively.  Replacing only those values with constant markers keeps the
three-stage lineage stable without excluding any other resolved value.  The
policy *path* remains part of this identity.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math
import re
from typing import Mapping
import unicodedata

from rextio.artifacts.contract_dialects import (
    CURRENT,
    EFFECTIVE_CONFIG_AGGREGATE_ID,
    EFFECTIVE_CONFIG_DOMAIN,
    FINAL_SIGNATURE_LIFECYCLE_MARKER,
    POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER,
)
from rextio.build.input_closure import BuildInputAggregateIdentity
from rextio.config.schema import (
    BuildConfig,
    EmbeddingConfig,
    ExecutableConfig,
    FallbackConfig,
    ImportPackagePolicy,
    ImportsConfig,
    PluginConfig,
    PolicyConfig,
    RextioConfig,
    RustConfig,
    TargetConfig,
    ToolchainConfig,
)


FULL_C6_EFFECTIVE_CONFIG_DOMAIN = CURRENT.string_value(EFFECTIVE_CONFIG_DOMAIN)
FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID = CURRENT.string_value(
    EFFECTIVE_CONFIG_AGGREGATE_ID
)
FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_KIND = "effective-config"
FULL_C6_FINAL_SIGNATURE_LIFECYCLE_MARKER = CURRENT.string_value(
    FINAL_SIGNATURE_LIFECYCLE_MARKER
)
FULL_C6_POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER = (
    CURRENT.string_value(POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER)
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_FULL_C6_EFFECTIVE_CONFIG_DEPTH = 32
MAX_FULL_C6_EFFECTIVE_CONFIG_NODES = 8192
MAX_FULL_C6_EFFECTIVE_CONFIG_MEMBERS = 4096
MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS = 4096
MAX_FULL_C6_EFFECTIVE_CONFIG_STRING_BYTES = 64 * 1024
MAX_FULL_C6_EFFECTIVE_CONFIG_TOTAL_STRING_BYTES = 512 * 1024
MAX_FULL_C6_EFFECTIVE_CONFIG_CANONICAL_BYTES = 1024 * 1024
_MAX_EFFECTIVE_CONFIG_INTEGER_BITS = 256

_CONFIG_SECTION_TYPES = (
    BuildConfig,
    RustConfig,
    FallbackConfig,
    TargetConfig,
    PluginConfig,
    ImportsConfig,
    EmbeddingConfig,
    ExecutableConfig,
    ToolchainConfig,
    PolicyConfig,
)


class FullC6ConfigIdentityError(RuntimeError):
    """The resolved artifact build configuration has no safe canonical identity."""


@dataclass(slots=True)
class _NormalizationBudget:
    nodes: int = 0
    leaves: int = 0
    string_bytes: int = 0

    def consume_node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_FULL_C6_EFFECTIVE_CONFIG_NODES:
            raise ValueError("artifact build effective config exceeds its node bound")

    def consume_leaf(self) -> None:
        self.leaves += 1
        if self.leaves > MAX_FULL_C6_EFFECTIVE_CONFIG_MEMBERS:
            raise ValueError("artifact build effective config exceeds its member bound")

    def consume_string(self, value: str) -> None:
        if value != unicodedata.normalize("NFC", value) or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("artifact build effective config contains noncanonical text")
        size = len(value.encode("utf-8"))
        if size > MAX_FULL_C6_EFFECTIVE_CONFIG_STRING_BYTES:
            raise ValueError("artifact build effective config string exceeds its byte bound")
        self.string_bytes += size
        if self.string_bytes > MAX_FULL_C6_EFFECTIVE_CONFIG_TOTAL_STRING_BYTES:
            raise ValueError(
                "artifact build effective config strings exceed their aggregate byte bound"
            )


@dataclass(frozen=True, slots=True)
class EffectiveFullC6ConfigIdentity:
    """Opaque public identity for one complete resolved configuration."""

    digest: str
    member_count: int
    domain: str = FULL_C6_EFFECTIVE_CONFIG_DOMAIN

    def __post_init__(self) -> None:
        if self.domain != FULL_C6_EFFECTIVE_CONFIG_DOMAIN:
            raise ValueError("artifact build effective-config domain is invalid")
        if type(self.digest) is not str or _SHA256_RE.fullmatch(self.digest) is None:
            raise ValueError("artifact build effective-config digest is invalid")
        if (
            type(self.member_count) is not int
            or isinstance(self.member_count, bool)
            or not 1 <= self.member_count <= MAX_FULL_C6_EFFECTIVE_CONFIG_MEMBERS
        ):
            raise ValueError("artifact build effective-config member count is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return only the canonical domain, digest, and bounded count."""
        return {
            "domain": self.domain,
            "digest": self.digest,
            "member_count": self.member_count,
        }

    def to_build_input_aggregate(self) -> BuildInputAggregateIdentity:
        """Return the generic build-input row carrying this identity."""
        return BuildInputAggregateIdentity(
            aggregate_id=FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID,
            kind=FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_KIND,
            digest=self.digest,
            member_count=self.member_count,
        )


def capture_effective_full_c6_config_identity(
    config: RextioConfig,
) -> EffectiveFullC6ConfigIdentity:
    """Canonicalize every resolved config field and return its opaque identity."""
    if type(config) is not RextioConfig:
        raise FullC6ConfigIdentityError("artifact build effective config requires an exact RextioConfig")
    _require_exact_config_model(config)
    try:
        budget = _NormalizationBudget()
        normalized = _normalize_value(
            config,
            field_name=None,
            depth=0,
            budget=budget,
        )
        payload = {
            "domain": FULL_C6_EFFECTIVE_CONFIG_DOMAIN,
            "config": normalized,
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(canonical) > MAX_FULL_C6_EFFECTIVE_CONFIG_CANONICAL_BYTES:
            raise ValueError("artifact build effective config canonical JSON is too large")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise FullC6ConfigIdentityError(
            "artifact build effective config cannot be canonicalized exactly"
        ) from exc
    return EffectiveFullC6ConfigIdentity(
        digest=hashlib.sha256(canonical).hexdigest(),
        member_count=budget.leaves,
    )


def effective_full_c6_config_identity_from_aggregate(
    value: BuildInputAggregateIdentity,
) -> EffectiveFullC6ConfigIdentity:
    """Rebuild the public config identity from its one canonical aggregate row."""
    if (
        type(value) is not BuildInputAggregateIdentity
        or value.aggregate_id != FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID
        or value.kind != FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_KIND
        or value.metadata_digest is not None
    ):
        raise FullC6ConfigIdentityError(
            "artifact build effective-config aggregate is missing or noncanonical"
        )
    try:
        return EffectiveFullC6ConfigIdentity(
            digest=value.digest,
            member_count=value.member_count,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ConfigIdentityError("artifact build effective-config aggregate is invalid") from exc


def _require_exact_config_model(config: RextioConfig) -> None:
    sections = tuple(getattr(config, item.name) for item in fields(RextioConfig))
    if len(sections) != len(_CONFIG_SECTION_TYPES) or any(
        type(section) is not expected
        for section, expected in zip(sections, _CONFIG_SECTION_TYPES, strict=True)
    ):
        raise FullC6ConfigIdentityError(
            "artifact build effective config contains a noncanonical typed section"
        )
    target_options = config.target.build_options
    if type(target_options) is not dict or any(
        type(key) is not str or type(value) is not str for key, value in target_options.items()
    ):
        raise FullC6ConfigIdentityError(
            "artifact build target build options are not an exact string mapping"
        )
    packages = config.imports.packages
    if type(packages) is not dict or any(
        type(key) is not str or type(value) is not ImportPackagePolicy
        for key, value in packages.items()
    ):
        raise FullC6ConfigIdentityError(
            "artifact build import package policies are not in canonical typed form"
        )


def _normalize_value(
    value: object,
    *,
    field_name: str | None,
    depth: int,
    budget: _NormalizationBudget,
) -> object:
    if depth > MAX_FULL_C6_EFFECTIVE_CONFIG_DEPTH:
        raise ValueError("artifact build effective config exceeds its depth bound")
    budget.consume_node()
    if is_dataclass(value) and not isinstance(value, type):
        dataclass_fields = fields(value)
        if len(dataclass_fields) > MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS:
            raise ValueError("artifact build effective config dataclass is too large")
        return {
            item.name: _normalize_value(
                (
                    FULL_C6_FINAL_SIGNATURE_LIFECYCLE_MARKER
                    if type(value) is BuildConfig
                    and item.name == "artifact_final_signature"
                    else FULL_C6_POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER
                    if type(value) is BuildConfig
                    and item.name == "artifact_policy_manifest_sha256"
                    else getattr(value, item.name)
                ),
                field_name=item.name,
                depth=depth + 1,
                budget=budget,
            )
            for item in dataclass_fields
        }
    if isinstance(value, Enum):
        return _normalize_value(
            value.value,
            field_name=field_name,
            depth=depth + 1,
            budget=budget,
        )
    if type(value) is dict:
        mapping = value
        if (
            len(mapping) > MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS
            or any(type(key) is not str for key in mapping)
        ):
            raise TypeError("artifact build config mapping keys must be strings")
        normalized: dict[str, object] = {}
        for key, item in mapping.items():
            budget.consume_string(key)
            normalized[key] = _normalize_value(
                item,
                field_name=field_name,
                depth=depth + 1,
                budget=budget,
            )
        return normalized
    if isinstance(value, Mapping):
        raise TypeError("artifact build config mappings must be exact dictionaries")
    if type(value) is tuple:
        if len(value) > MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS:
            raise ValueError("artifact build config tuple exceeds its item bound")
        return [
            _normalize_value(
                item,
                field_name=field_name,
                depth=depth + 1,
                budget=budget,
            )
            for item in value
        ]
    if type(value) is list:
        raise TypeError("artifact build config sequences must use their typed tuple model")
    if value is None or type(value) is bool:
        budget.consume_leaf()
        return value
    if type(value) is str:
        budget.consume_string(value)
        budget.consume_leaf()
        return value
    if type(value) is int:
        if value.bit_length() > _MAX_EFFECTIVE_CONFIG_INTEGER_BITS:
            raise ValueError("artifact build config integer exceeds its bit bound")
        budget.consume_leaf()
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("artifact build config floats must be finite")
        budget.consume_leaf()
        return value
    raise TypeError(f"artifact build config field {field_name or '<root>'} has an unsupported value")
__all__ = [
    "EffectiveFullC6ConfigIdentity",
    "FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID",
    "FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_KIND",
    "FULL_C6_EFFECTIVE_CONFIG_DOMAIN",
    "FULL_C6_FINAL_SIGNATURE_LIFECYCLE_MARKER",
    "FULL_C6_POLICY_MANIFEST_DIGEST_LIFECYCLE_MARKER",
    "FullC6ConfigIdentityError",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_CANONICAL_BYTES",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_DEPTH",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_MEMBERS",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_NODES",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_STRING_BYTES",
    "MAX_FULL_C6_EFFECTIVE_CONFIG_TOTAL_STRING_BYTES",
    "capture_effective_full_c6_config_identity",
    "effective_full_c6_config_identity_from_aggregate",
]
