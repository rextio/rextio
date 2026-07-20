"""Version of the machine-readable tooling contract.

The tooling contract (docs/specs/tooling-contract.md) is the JSON surface that
external tooling — agent skills, LSP servers, editor extensions — consumes
instead of re-implementing analyzer rules. Its version is SemVer over the
*contract shape and position semantics*, independent of the rextio package
version: additive fields bump minor, renames/removals/semantic changes that
would mislead old consumers bump major. Consumers tolerate unknown fields and
degrade to generic guidance when the major version is outside what they know.

Both contract surfaces embed this value: ``rextio check --format json`` (and
the ``.rextio/reports/check.json`` report) and ``rextio capabilities``.
"""

from __future__ import annotations

# Protocol SemVer (not a package release claim). Major 2 broke RXT000 column
# semantics so every diagnostic column is a 0-based UTF-8 byte offset
# (ast.col_offset convention); contract 1.x left RXT000 as CPython's 1-based
# Unicode code-point SyntaxError.offset. Core 0.1.2 emitted 2.0.0. Core 0.1.3
# emitted 2.1.0 for additive producer-shape fields (plugin_claims.receiver /
# callables when present; always-on module.logger_group_targets). Same major
# remains compatible with dual-map 2.x consumers that tolerate unknown fields.
# Contract 2.2.0 adds isolated promotion-assessment evidence plus reliable
# function/name ranges without changing route/status or position semantics.
# Contract 2.3.0 adds behavior-neutral host source plans to check/build plans,
# declared artifact profiles, and the draft device-provider contract marker.
# Contract 2.4.0 adds plugin standalone-artifact capability presence/declaration
# and generate/build resolved per-profile allow/deny details without changing
# lowering_provided, route, native-status, rejection, or promotion semantics.
# Contract 2.5.0 adds a sanitized, preview-only external_source_plan.
# Contract 2.6.0 adds C6.1 authority material and SourceLock authorization
# evidence under that plan (plan_snapshot, sizes, source_inventory/provenance/
# closed license attestation). Verified authorization still does not grant
# source-native lowering, packaging, or redistribution; remaining C5.2
# linkage/codegen are unimplemented.
# Contract 2.7.0 adds optional build.json.artifact_evidence for the bounded
# C6.2 host-extension wheel SBOM/provenance preview (incomplete, unsigned).
# Contract 2.8.0 adds the opt-in C6.3 required artifact-evidence gate without
# granting distribution authorization or changing C6.2 evidence semantics.
# Contract 2.9.0 adds C6.4 sanitized direct native runtime linkage inventory
# (macOS Mach-O / Linux ELF) under artifact_evidence without claiming a
# transitive closure, signatures, or distribution authorization.
# Contract 2.10.0 adds C6.5's deterministic, always-blocked distribution-
# authorization readiness assessment. It distinguishes preview evidence and
# the required preview gate from any future hard distribution authorization.
# Contract 2.11.0 adds C6.6's bounded source-transformation inventory
# observation and policy-version-2 readiness check. It still does not claim
# complete source-transformation provenance or distribution authorization.
# Contract 2.12.0 adds C6.7's exact reachable-Cargo component-license string
# inventory and policy-version-3 observation check. Strings remain unvalidated,
# and the component license policy remains incomplete and non-authorizing.
# Contract 2.13.0 adds C6.8's exact one-hop native runtime path-resolution
# observation and policy-version-4 check. It observes only packaged candidates
# and system logical leaves; loader selection and transitive closure stay open.
# Contract 2.14.0 adds C6.9's deterministic, cycle-safe, strictly bounded
# static graph across recursively inspected packaged native members and logical
# system leaves plus policy-version-5 observation. Complete transitive closure,
# actual loader selection, runtime dlopen, and authorization remain blocked.
# Contract 2.15.0 adds C6.10's narrowly scoped source-transformation replay
# verification and policy-version-6 observation. It securely rereads the exact
# project-source set, rederives function identities, relowers the complete
# plugin-free PyO3 closure, and requires byte-identical src/lib.rs regeneration.
# Global transformation provenance and distribution authorization stay blocked.
# Contract 2.16.0 adds C6.11's exact project-owner Cargo license-policy lock
# receipt and policy-version-7 observation. It binds the full C6.7 inventory,
# exact raw registry-license rows, and exact lock bytes, but does not authenticate
# the attestor, validate SPDX/license files, grant legal approval, or authorize
# distribution. Global component-license policy therefore remains incomplete.
# Contract 2.17.0 adds C6.12's exact project-owner source-license declaration
# receipt and policy-version-8 observation. It binds one present C6.10 replay,
# its complete scoped project-source set, generated Rust src/lib.rs, and exact
# lock bytes. It does not authenticate ownership, validate SPDX/license files
# or obligations, establish derivative-work rights, grant legal approval, or
# authorize distribution. Global source-transformation and license policy
# therefore remain incomplete.
# Contract 2.18.0 adds C6.13's scoped analysis-input verification observation
# to artifact-distribution authorization readiness. It remains additive,
# unsigned, non-authorizing evidence and does not complete build-input closure,
# reproducibility, signing, policy, or distribution authorization.
# See docs/specs/tooling-contract.md §Contract versioning and §Positions.
TOOLING_CONTRACT_VERSION = "2.18.0"
