# Spec: Machine-Readable Tooling Contract

Status: **draft** (experimental tier; current producer `contract_version` is
`2.1.0`)
Consumers: rextio-agent-skill, rextio-lsp, rextio-vscode, third-party Rextio plugins

## Purpose

External tools (agent skills, LSP servers, editor extensions) must tell developers
what promotes to native and how to fix what does not — without re-implementing
analyzer rules that change every release. This spec defines the contract they
consume instead:

1. A **route taxonomy**: one label per function describing where it executes.
2. Extensions to the existing `rextio check --json` output.
3. A new `rextio capabilities --json` command: the config-resolved **capability
   manifest** of a project (core subset rules + active plugin rules).
4. A **plugin self-description protocol** so plugin rules appear in the manifest.

## Contract versioning

Both JSON surfaces carry a top-level field:

```json
{ "contract_version": "2.1.0" }
```

SemVer over the *contract* (shape **and** position semantics), independent of
the rextio package version. Additive fields bump minor; renames, removals, or
semantics changes that would mislead old consumers bump major. Consumers must
tolerate unknown fields and check `contract_version` compatibility, degrading
to generic guidance when the major is outside what they support.

| Version | Meaning |
|---|---|
| `1.0.0` | First public producer line (rextio 0.1.1). Route/status fields + capability manifest. **Exception:** `RXT000` (syntax-error) `column` was CPython `SyntaxError.offset` — a **1-based Unicode code-point** index — not the UTF-8 byte offset used by every other diagnostic. |
| `2.0.0` | **Breaking position semantics.** Every diagnostic `column` / `end_column`, including `RXT000`, is a **0-based UTF-8 byte offset** into the line (`ast.col_offset` convention). No field renames. Emitted by core **0.1.2**. |
| `2.1.0` | **Additive producer shape** (same major; dual-map `2.x` consumers stay supported). Core **0.1.3** always serializes module-level `logger_group_targets`, and conditionally serializes plugin-claim fields `receiver` and `callables` when present (plugin API 1.3 method/callable metadata). Position semantics unchanged from `2.0.0`. Consumers that ignore unknown fields continue to work. |

Why a major, not a minor: released consumers (notably rextio-lsp 0.1.0) gate only
on the contract **major** and applied a special-case RXT000 code-point map.
A minor bump (`1.1.0`) would be silently accepted and would **misplace**
RXT000 under the new UTF-8 producer. A major forces major-1-only consumers to
the unsupported/degraded path instead of a false “supported” mapping.

`1.0.0` covered the entire pre-release 0.1.1 line: fields added before the first
tagged release (`plugin_type_keys`, rule records, RXT091/RXT092) did not bump
the version because no consumer could have shipped against an earlier manifest
generation. From the first release onward that shortcut is closed — **any
post-release additive change MUST bump the contract minor**, and **any
incompatible position or field semantics change MUST bump the major**.

### Positions

- `line` / `end_line`: **1-based** (Python `ast` line numbers).
- `column` / `end_column`: **0-based UTF-8 byte offsets** into that line
  (Python `ast.col_offset` / `end_col_offset`), for **every** diagnostic code
  under contract `2.x`.
- A missing/null position (CPython can emit `None` for some `SyntaxError`
  locations) serializes as JSON `null`; consumers should coerce to safe
  defaults rather than aborting the whole report.

LSP and other UTF-16 editors must convert byte offsets to UTF-16 code units
using the document line text. Do not treat columns as code points or as
UTF-16 units.

### Compatibility and release ordering

This is a **protocol** contract change, not a package SemVer claim. Package
versions (rextio / rextio-lsp) ship on their own schedules.

| Producer (core) | Consumer (LSP) | RXT000 placement |
|---|---|---|
| contract `1.x` (legacy column) | major-1-only (rextio-lsp 0.1.0) | Correct via legacy code-point special case |
| contract `1.x` | majors `{1,2}` with dual map | Correct via legacy branch |
| contract `2.x` (UTF-8 column) | majors `{1,2}` with dual map | Correct via standardized branch |
| contract `2.x` | major-1-only | **Unsupported major** → degraded guidance; do not treat as supported. Residual risk: pre-dual-map servers may still render a range using the old RXT000 special case |

**Release-order gate (required; strict sequence, not simultaneous)**

Publish related packages in this order only:

1. **rextio-lsp 0.1.1 first** — dual-map consumer for contract majors `{1, 2}`
   with version-aware RXT000 mapping. Must be available before any
   contract-`2.x` core is published.
2. **Core 0.1.2 second** — emits `contract_version` `2.0.0`.
3. **rextio-numpy 0.1.1 third** — plugin API 1.2 consumer (literal-axis /
   fusion / leaves-mode surface). Must not publish before core ships API 1.2.

Do **not** ship LSP simultaneously with or after core, and do **not** ship
rextio-numpy 0.1.1 before core 0.1.2. Core has no runtime dependency on
rextio-lsp or rextio-numpy — these are deployment ordering constraints, not
package dependencies.

**Core must not publish alone first.** A contract-`2.x` producer against
major-1-only rextio-lsp 0.1.0 is an unsupported pairing (degraded guidance at
best; residual risk of mis-rendered RXT000 ranges if a server still applies
the old special case).

## Route taxonomy

Today classification is spread across `FunctionAnalysis` booleans
(`is_native_candidate`, `accepted`, `native_runtime_semantics`,
`external_accelerator`; see `src/rextio/analyzer/models.py`). The contract
derives two orthogonal serialized fields from them — the **execution route**
(where the code actually runs) and the **native status** (what the analyzer
decided about promotion):

| `route` | Meaning | Derivation (current model) |
|---|---|---|
| `native-direct` | Direct core-subset Rust lowering | `is_native_candidate and accepted and not native_runtime_semantics`, no plugin rule involved |
| `native-plugin:<plugin_id>[+<plugin_id>...]` | Lowered by a Rextio plugin (AOT Rust, Rextio contract) | accepted via a plugin rule record (new; requires plugin protocol v2). When several plugins contribute (claimed sites and/or plugin-typed parameters from different plugins in one signature), their ids are joined with `+` in sorted order — consumers MUST parse the segment after `:` as a `+`-separated set, not a single id |
| `native-shim` | RXT080 runtime-semantics shim (behavior-preserving, not a speedup) | `accepted and native_runtime_semantics`. Any `plugin_claims`/`plugin_type_keys` reported on a shim-routed function are informational only — the shim executes the Python fallback, so claims are never lowered |
| `fallback-python` | Generated Python fallback | everything not otherwise labeled |
| `fallback-accelerated:<tool>` | External accelerator on the fallback (its own semantics contract) | `external_accelerator` set (today: `"numba"`) |

| `native_status` | Meaning |
|---|---|
| `accepted` | Native candidate, accepted |
| `rejected` | Native candidate, rejected — see `rejection_codes` |
| `not-candidate` | Never a candidate (unmarked in decorator mode, unresolved types, exempt, accelerator-decorated) |

A rejected candidate therefore serializes as `route: "fallback-python"`,
`native_status: "rejected"`, `rejection_codes: ["RXT0xx", ...]` — the function
*runs* on fallback; the rejection is the promotion verdict. (Design documents
elsewhere may write this pair as the shorthand `rejected:<RXT>`.)

Embedded scalar helpers (`is_embedding_candidate`) are internal native functions
not exported to Python; they are reported through the existing
`embedding_candidates` list, not as a route.

### Precedence (decided)

**Explicit decorator > plugin auto-lowering > default fallback.**

A `@numba.*`-decorated function stays `fallback-accelerated:numba` even when an
active plugin could lower it — the decorator is the user's explicit opt-in to
Numba's semantics, exactly like `@rextio.exempt` opts out. When an active plugin
*could* lower a decorated function, the analyzer emits a new informational,
non-rejecting diagnostic:

| Code | Title | Stability |
|---|---|---|
| RXT091 | Accelerator-decorated function is plugin-lowerable if the decorator is removed | experimental |

Registered in `src/rextio/analyzer/diagnostic_codes.py` like every other code.
It informs; it never forces.

## `rextio check --json` extensions

`check --format json` already emits `ProjectAnalysis.to_dict()` and writes the
same payload to `.rextio/reports/check.json`. Additive changes:

1. Top-level `contract_version`.
2. Each serialized function gains `route`, `native_status`, and
   `rejection_codes` (empty list when not rejected).
3. Each `Diagnostic` already carries a `suggestion` field; the contract promotes
   it to the guidance seam — analyzer rejection sites should populate it with
   the same guidance string the capability manifest carries for that rule
   (single-sourced via the rule registry, below).
4. **Contract `2.1.0` (core 0.1.3) additive report fields** — same major as
   `2.0.0`; old `2.x` consumers that ignore unknown keys remain correct:

   | Location | Field | Presence | Meaning |
   |---|---|---|---|
   | `modules[]` | `logger_group_targets` | **Always** (object; may be empty) | Map of accepted logger receiver name → list of process-global `logging.getLogger` cache-group targets proven for that receiver. Equal exact names share a group across modules; dynamic names use the global unknown group. |
   | `modules[].functions[].plugin_claims[]` | `receiver` | When non-null method-receiver metadata is present | Plugin API 1.3 `ReceiverMeta` (`arg_type`, `schema`, `expr_kind`, `is_safe`) for method claim sites. Omitted when there is no receiver (module-qualified calls, plain functions). |
   | `modules[].functions[].plugin_claims[]` | `callables` | When the claim has one or more callable-argument metadata entries | Ordered plugin API 1.3 `CallableMeta` records for project-function arguments at the claim site. Omitted when empty. |

   Earlier additive claim keys from plugin API 1.2 (`operand_literals`,
   `keywords`, `expression`, `operand_mode` when not `"direct"`) remain
   conditional the same way. No existing key changes meaning or disappears.

## `rextio capabilities --json`

New subcommand (wired like the others in `src/rextio/cli/main.py`, handler
module `src/rextio/cli/capabilities_cmd.py`, output through the existing
`Reporter` seam). It answers: *"in THIS project, with THIS `rextio.toml`, what
can become native, and what should I do when it can't?"*

Resolution is config-aware: it loads the project config (same
CLI > env > `rextio.toml` > default chain), resolves active plugins via the
existing `PluginRegistry`, and merges rule records from core and plugins.
Note: resolving the registry imports and executes enabled plugin packages'
module-level code — with plugins enabled, `capabilities` is configuration
introspection but not side-effect-free. The command never analyzes project
sources or writes report files. Output ordering is deterministic: core rules
in registry order, then plugin rules and the `plugins` array sorted by id.

```json
{
  "contract_version": "2.1.0",
  "rextio_version": "0.1.3",
  "project_root": "/abs/path",
  "config_fingerprint": "<sha256 of resolved config>",
  "target": { "language": "rust" },
  "type_capabilities": {
    "scalar_types": ["int", "float", "bool", "str", "bytes"],
    "list_item_types": ["int", "float", "bool", "str"],
    "dict_key_types": ["int", "bool", "str"],
    "set_item_types": ["int", "bool", "str"]
  },
  "rules": [ <RuleRecord>, ... ],
  "plugins": [ { "id": "rextio-numpy", "version": "0.1.0",
                 "api_version": "1.0", "rules_provided": true }, ... ]
}
```

`type_capabilities` is emitted from the existing single-source-of-truth
constants in `src/rextio/capabilities.py`. `config_fingerprint` lets consumers
cache the manifest keyed on (fingerprint, rextio version, plugin versions) —
each plugin entry carries its distribution `version` (null when the provider
has no entry-point distribution metadata — a null version is NOT cache-safe:
consumers must treat manifests containing it as uncacheable or key on their
own knowledge of that plugin's revision) so the key is computable from the
manifest alone. The `plugins` array (each entry's `id` + `version`) IS the
plugin-version component of the cache key; consumers MUST fold it into their
key alongside `config_fingerprint` — the fingerprint itself hashes only the
resolved config (which contains plugin ids, not versions). `--no-plugins` emits the core-only manifest without importing
or executing any plugin package code.

### RuleRecord (L2 — required)

```json
{
  "id": "core/set-float-item-type",
  "provider": "core",
  "scope": { "kind": "type", "pattern": "set[float]" },
  "constraint": "set[float] has no faithful Rust lowering (NaN-identity dedup)",
  "outcome": "fallback",
  "diagnostic_code": "RXT002",
  "guidance": "Use list[float] and dedupe explicitly, or keep the function on the Python fallback.",
  "stability": "stable"
}
```

- `id`: stable slug, namespaced by provider (`core/...`, `rextio-numpy/...`).
- `scope.kind`: `type` | `syntax` | `call` | `binop` | `import` | `decorator`.
  `binop` labels operator lowering surfaces (a plugin claiming `+`/`-`/`*`/`/`
  sites); `call` is reserved for call-shaped sites.
- `outcome`: `native` | `fallback` | `reject` | `shim` | `boundary`.
- `diagnostic_code`: the RXT/RXTP code emitted when the rule fires (1:1 where
  possible; the registry in `diagnostic_codes.py` remains the code
  authority, and a contract test asserts every referenced code is registered).
- `guidance`: human- and agent-readable "how to promote" text. The same string
  feeds `Diagnostic.suggestion` at rejection sites — one source, two surfaces.
- `stability`: reuses the existing DiagnosticCode tiers (`stable` |
  `experimental`).

### Fix templates (L3 — optional, recommended)

Rule records MAY carry:

```json
{
  "fix_template": { "kind": "rewrite-hint",
                    "before": "def f(xs: set[float]) -> float: ...",
                    "after": "def f(xs: list[float]) -> float: ..." },
  "examples": [ { "before": "...", "after": "...", "note": "..." } ]
}
```

First-party plugins ship rule records first and add fix templates as capacity
allows. Third-party plugins are required to provide L2 only.

## Plugin protocol v2

Today plugins are metadata-only (`RextioPlugin` frozen dataclass discovered via
the `rextio.plugins` entry-point group; a legacy `rules` key is deprecated and
ignored). Protocol v2 adds self-description without breaking v1 plugins:

```python
class RextioPluginV2(Protocol):
    plugin_id: str          # e.g. "rextio-numpy"
    api_version: str        # plugin-API SemVer, checked by core

    def covers(self) -> CoverageDecl: ...
        # packages / modules / symbols / dtypes the plugin can lower

    def describe(self, config: RextioConfig) -> RuleManifest: ...
        # -> list of RuleRecord (L2 required, L3 fields optional)

    # Lowering hooks (type_vocabulary/claim/lower/crate_dependencies) are
    # plugin API 1.1+ (1.2 additive claim metadata) - specified separately in plugin-lowering.md.
```

- **Discovery** stays on the `rextio.plugins` entry-point group. A v2 plugin is
  recognized by exposing `describe`; v1 metadata-only plugins keep loading and
  appear in the manifest with `"rules_provided": false`.
- **Diagnostic namespacing**: plugin codes use `RXTP-<PLUGIN>-NNN` (e.g.
  `RXTP-NUMPY-001`). Core validates uniqueness at registry load and rejects
  collisions loudly (same posture as enabled-plugin id validation today).
- `RuleManifest` entries from plugins are merged into the capabilities output
  with `provider: "<plugin_id>"`.
- The Protocol and record dataclasses live in `rextio.plugins.api` (inside
  core) during 0.x; a separate contract package is deliberately deferred.

## Non-goals

- No lowering/codegen behavior changes; this spec is contract surface only.
- No LSP or editor logic; those live in rextio-lsp / rextio-vscode.
- No incremental-analysis API (deferred until latency measurements demand it;
  v1 tooling calls the batch analyzer).
- No name-based reservation of route strings beyond this document; new routes
  bump the contract minor version.

## Rollout

1. **0.1.1 (published on PyPI):** land route fields + `contract_version`
   `1.0.0` in check JSON; add `capabilities` command with core rules only; add
   RXT091 to the registry; document in `docs/stability.md` as experimental.
2. rextio-numpy becomes the first `describe()` implementation; its rule records
   validate the plugin merge path.
3. **0.1.2 (published 2026-07-14):** contract `2.0.0` normalizes `RXT000`
   columns to 0-based UTF-8 byte offsets. The strict release-order gate —
   rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1 — completed in that
   order (see §Compatibility and release ordering). Consumers that support
   only major 1 must degrade; dual-map consumers keep mapping both 1.x and
   2.x correctly. Historical evidence: core 0.1.2 emitted `contract_version`
   `2.0.0`.
4. **0.1.3 (published 2026-07-17):** package ships plugin API **1.3**
   (additive; Experimental). Tooling contract advances to **`2.1.0`**
   (same major): additive producer fields
   `modules[].logger_group_targets` (always) and conditional
   `plugin_claims[].receiver` / `plugin_claims[].callables` when present.
   Column semantics unchanged from `2.0.0`. Dual-map `2.x` consumers that
   tolerate unknown fields remain compatible.
5. Promote the contract to stable once rextio-agent-skill and rextio-lsp have
   consumed it across one release cycle without breaking changes.
