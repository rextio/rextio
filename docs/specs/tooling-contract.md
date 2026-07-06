# Spec: Machine-Readable Tooling Contract

Status: **draft** (targets 0.1.1, experimental tier)
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

Everything here is additive. Existing `check.json` consumers keep working.

## Contract versioning

Both JSON surfaces gain a top-level field:

```json
{ "contract_version": "1.0.0" }
```

SemVer over the *contract*, independent of the rextio package version. Additive
fields bump minor; renames/removals bump major. Consumers must tolerate unknown
fields and check `contract_version` compatibility, degrading to generic guidance
on mismatch.

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
| `native-plugin:<plugin_id>` | Lowered by a Rextio plugin (AOT Rust, Rextio contract) | accepted via a plugin rule record (new; requires plugin protocol v2) |
| `native-shim` | RXT080 runtime-semantics shim (behavior-preserving, not a speedup) | `accepted and native_runtime_semantics` |
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

No existing key changes meaning or disappears.

## `rextio capabilities --json`

New subcommand (wired like the others in `src/rextio/cli/main.py`, handler
module `src/rextio/cli/capabilities_cmd.py`, output through the existing
`Reporter` seam). It answers: *"in THIS project, with THIS `rextio.toml`, what
can become native, and what should I do when it can't?"*

Resolution is config-aware: it loads the project config (same
CLI > env > `rextio.toml` > default chain), resolves active plugins via the
existing `PluginRegistry`, and merges rule records from core and plugins.

```json
{
  "contract_version": "1.0.0",
  "rextio_version": "0.1.1",
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
  "plugins": [ { "id": "rextio-numpy", "api_version": "1.0",
                 "rules_provided": true }, ... ]
}
```

`type_capabilities` is emitted from the existing single-source-of-truth
constants in `src/rextio/capabilities.py`. `config_fingerprint` lets consumers
cache the manifest keyed on (fingerprint, rextio version, plugin versions).

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
- `scope.kind`: `type` | `syntax` | `call` | `import` | `decorator`.
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
    # plugin API 1.1 - specified separately in plugin-lowering.md.
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

1. 0.1.1: land route fields + `contract_version` in check JSON; add
   `capabilities` command with core rules only; add RXT091 to the registry;
   document in `docs/stability.md` as experimental.
2. rextio-numpy becomes the first `describe()` implementation; its rule records
   validate the plugin merge path.
3. Promote the contract to stable once rextio-agent-skill and rextio-lsp have
   consumed it across one release cycle without breaking changes.
