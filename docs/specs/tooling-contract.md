# Spec: Machine-Readable Tooling Contract

Status: **draft** (experimental tier). The current published producer is core
0.1.4, released on 2026-07-18 with `contract_version` `2.2.0` and plugin API
**1.3**. The Release Train C branch contains the additive, **unreleased**
`2.7.0` producer (plugin API **1.4**) described below; it is not yet a PyPI
contract. Package version on the branch remains **0.1.4**.
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

Both JSON surfaces carry a top-level field. The published 0.1.4 producer emits:

```json
{ "contract_version": "2.2.0" }
```

The unreleased Train C branch emits:

```json
{ "contract_version": "2.7.0" }
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
| `2.2.0` | **Additive promotion-assessment shape.** Each reportable function adds `marker_kind`, a separate `promotion_assessment` evidence channel, and reliable `source_range` / `name_range`. Runtime `route`, `native_status`, and `rejection_codes` semantics remain unchanged. Failed automatic probes stay normal fallback rather than becoming compiler/build errors. Published with core **0.1.4**. |
| `2.3.0` | **Unreleased additive host-planning shape** (Train C intermediate). Check/generate/build reports gain a fail-closed `host_source_plan`; generate/build plans carry resolved `artifact_profiles`; Rust executable closures add `module_initializers`; capabilities declares `artifact_contract` and a non-operational `device_provider_contract`. |
| `2.4.0` | **Unreleased additive plugin standalone-capability shape** (Train C intermediate). Capabilities plugins gain `artifact_capability_declared` (presence only; no profile-hook execution). Generate/build may emit `standalone_plugin_capabilities` with resolved per-profile allow/deny details. `lowering_provided`, route, native-status, rejection, and promotion-assessment semantics remain unchanged. |
| `2.5.0` | **Unreleased additive external-source preview shape** (Train C intermediate). Import-policy decisions add nullable exact `distribution` / `version` metadata; check/generate and blocked-build reports may add one sanitized `external_source_plan`. The plan is inventory evidence only (`execution_authority: "preview-only"`, `distributable: false`, `c6_gate: "required"`) and never grants source execution, lowering, build, packaging, or redistribution authority. |
| `2.6.0` | **Unreleased additive C6.1 authorization-contract shape** (Train C intermediate). The sanitized `external_source_plan` adds authority material (`source_files`, `metadata_files`, `plan_snapshot`, `plan_snapshot_sha256`, `license_material_sha256`, `inventory_schema`) and may nest `authorization` for project-owned `rextio.external-source.lock.json` verification (`*_verified` booleans). `c6_gate` is `required` or `authorization-verified`. Verified authorization still never grants source-native lowering, packaging, or redistribution; remaining C5.2 linkage/codegen is unimplemented (`external-source-c5-not-implemented`). |
| `2.7.0` | **Unreleased additive C6.2 host-extension wheel artifact-evidence preview** (current Train C producer). In-scope successful host-extension+`cpython` wheels always add top-level `build.json.artifact_evidence` with `status` exactly `preview-ready` or `unavailable`, `authority: "evidence-only"`, `signature_status: "unsigned"`, and `composition: "incomplete"`. Preview-ready may emit bounded CycloneDX 1.6 / unsigned in-toto Statement (SLSA Provenance v1) sidecars; unavailable uses a sanitized fixed reason and never changes ordinary build success. Host-executable, rust-crate, Nuitka host-extension fallback, WASM, and external-package source-native builds omit the field. `ArtifactProvenance` remains planning metadata only. |

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

Release Train B reused the consumer-first gate for the additive 2.2 shape:
**rextio-lsp 0.1.2 → core 0.1.4**. That required sequence completed on
2026-07-18; the LSP consumer was available before the 2.2 producer.

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

5. **Contract `2.2.0` additive promotion fields** — every reportable
   `modules[].functions[]` record adds the required fields defined below. A
   consumer that does not know them continues to use the existing route/status
   fields unchanged.
6. **Contract `2.3.0` additive host-planning field (unreleased)** — command
   reports add the `host_source_plan` and artifact/executable fields defined in
   [Host source and artifact planning](#host-source-and-artifact-planning-contract-230).
   No existing diagnostic or function record changes meaning.

### Promotion assessment (contract 2.2.0)

The execution route and the promotion assessment answer different questions.
`route` says where the function executes. `promotion_assessment` says whether
the applicable native-promotion attempt succeeded, failed, or was intentionally
not attempted. In particular, a failed initial automatic probe must remain
`route: "fallback-python"`, `native_status: "not-candidate"`, and
`rejection_codes: []`; the new object preserves its assessment evidence
without changing those legacy semantics. An automatic candidate that passes
that probe but is rejected by later boundary/project checks retains its
existing legacy `native_status: "rejected"` and rejection codes.

A 2.2 producer emits this exact additive shape on every reportable function:

```json
{
  "marker_kind": "none",
  "promotion_assessment": {
    "status": "ineligible",
    "provenance": "auto",
    "diagnostic_codes": ["RXT001"],
    "diagnostics": [
      {
        "kind": "blocker",
        "code": "RXT001",
        "message": "native promotion requires resolved parameter and return types",
        "suggestion": "Add supported type annotations.",
        "line": 8,
        "column": 0,
        "end_line": 8,
        "end_column": 11
      }
    ],
    "skip_reason": null
  },
  "source_range": {
    "start": {"line": 8, "column": 0},
    "end": {"line": 9, "column": 12}
  },
  "name_range": {
    "start": {"line": 8, "column": 4},
    "end": {"line": 8, "column": 11}
  }
}
```

All four top-level keys above are required on a reportable 2.2 function.

#### Marker and assessment enums

`marker_kind` is exactly `none | native | exempt`. It records a statically
proven Rextio marker, not arbitrary decorator spelling. `exempt` wins when
both Rextio markers are present. An external accelerator decorator alone uses
`none`. A malformed or unsupported but statically proven native marker uses
`native`; an unproven/rebound marker spelling is not trusted.

`promotion_assessment.status` is exactly:

- `eligible`: the applicable core/plugin/explicit assessment succeeded;
- `ineligible`: an assessment ran and found at least one promotion blocker;
- `skipped`: no assessment ran because user intent, policy, or the supported
  structural scope excluded it. Skipped is not a compiler rejection.

`promotion_assessment.provenance` is exactly:

```text
auto | explicit-native | explicit-exempt | external-accelerator |
plugin-managed | policy-skip | structural-skip
```

Choose provenance in this order: explicit exemption; an owning external
accelerator; structural/policy skip; a plugin-owned eligible route or failed
probe; explicit native; automatic core assessment. `marker_kind` and plugin
provenance are deliberately orthogonal: an explicitly native function may be
plugin-managed, in which case it serializes `marker_kind: "native"` and
`provenance: "plugin-managed"`. Informational plugin claims on a
`native-shim` do not execute and do not make that assessment plugin-managed.

`skip_reason` is always present. It is null for `eligible` and `ineligible`.
For `skipped`, it is exactly one of:

```text
explicit-exemption
external-accelerator
automatic-promotion-disabled
async-auto-promotion-not-supported
method-auto-promotion-not-supported
```

The corresponding provenance is, respectively, `explicit-exempt`,
`external-accelerator`, `policy-skip`, or `structural-skip` for either of the
last two reasons. Skipped assessments have empty `diagnostic_codes` and
`diagnostics` arrays.

#### Assessment diagnostics are not build diagnostics

`promotion_assessment.diagnostic_codes` is an always-present, sorted, unique
list derived from `promotion_assessment.diagnostics`. The diagnostics array is
always present and deterministically ordered by
`(line, column, code, message)`. Each record has required `kind`, `code`,
`message`, `suggestion`, `line`, `column`, `end_line`, and `end_column` keys;
`suggestion` and the end positions may be null. `kind` is exactly
`blocker | advisory`. Positions use the normal contract-2 units and the
enclosing function supplies `file_path`.

This array is an isolated promotion-evidence channel. Its records MUST NOT be
added to legacy `functions[].diagnostics`, the project-wide diagnostics list,
`ProjectAnalysis.has_error_diagnostics`, CLI error status, or build failure
state. A failed automatic probe is expected fallback, not a compiler error.
The producer maps the probe's original errors to assessment `blocker` records
and its warnings/information to `advisory` records. `ineligible` requires at
least one blocker; `eligible` permits advisories but no blockers.

An explicit-native rejection can have the same underlying diagnostic in both
the legacy and assessment channels. Both serializations must agree on code,
message, suggestion, and span. Consumers de-duplicate on
`(code, line, column, end_line, end_column, message)`. When an assessment
suggestion is null, a consumer may use the matching capability rule's
`guidance`.

#### Function ranges and reportable set

`source_range` and `name_range` are half-open `[start, end)` objects with
`start` / `end`, each containing required integer `line` / `column` keys.
`source_range` starts at the `def` or `async` token (decorators excluded) and
ends at the AST function node's end position. `name_range` covers exactly the
identifier token after `def`. Existing `line` / `column` remain present and
equal the source-range start. The producer derives the name span by tokenizing
source; it must not guess with substring search. Null, partial, or zero-width
ranges are not valid 2.2 records.

The bounded 2.2 reportable set is every module-body sync/async definition and
every direct sync/async method in a top-level class for which both ranges are
reliable. Existing explicit-native method rejection records (including
nested-class/class-control-flow cases already reported by 2.1) must not
disappear. This train does not newly enumerate undecorated nested functions,
lambdas, local classes, or methods of nested classes; stable qualname, closure
ownership, and overlapping-range policy for those definitions remain
deferred. `(file_path, source_range)`, not `qualname` alone, identifies an
editor source record when duplicate definitions exist.

An unmarked async function or direct method in automatic mode is
`structural-skip`, not a rejection. An explicitly native async function or
method continues through its existing assessment/runtime-shim behavior and is
not automatically classified as skipped. A normal unmarked function under
decorator-only policy is `policy-skip`.

Explicit exemptions are still serialized so tools can retain source truth,
but a valid `marker_kind: "exempt"` suppresses promotion CodeLens, promotion
diagnostics, and promotion hover. Unrelated analyzer diagnostics are not
erased.

For a valid assessment the LSP presents exactly one CodeLens for each
reportable non-exempt function; its title contains the route and assessment
status, and a skipped title includes the skip reason. Assessment blockers map
to LSP Warning, advisories follow the existing informational-code policy, and
neither maps to LSP Error. Matching legacy/assessment diagnostics are emitted
only once under the de-duplication key above.

#### Legacy defaults

For a contract-major 1 or 2 record where these additive fields are absent,
consumers use `marker_kind = "none"` and represent
`promotion_assessment`, `source_range`, and `name_range` as unavailable. They
must not synthesize an assessment from legacy route/status fields, which
cannot distinguish failed auto assessment, exemption, and structural/policy
skips. Legacy hover and route CodeLens continue to use `line` / `column`.
Malformed objects or unknown enum values are treated as unavailable rather
than aborting the report parser; only an exact valid `marker_kind: "exempt"`
suppresses promotion UI.

The LSP remains a JSON-only consumer. Contract 2.2 requires no VS Code
initialization option or custom protocol, and does not change the existing
`rextio.showRouteInfo` CodeLens command or its string qualname argument.

## Host source and artifact planning (contract 2.3.0)

This section describes the **unreleased** Release Train C additive shape.
Published core 0.1.4 stops at contract 2.2.0.

### `host_source_plan`

`rextio check --format json` and `.rextio/reports/check.json` add a top-level
`host_source_plan`. `generate.json` and `build.json` carry the same object at
`plan.host_source_plan`:

```json
{
  "host_source_plan": {
    "availability": "available",
    "execution_authority": "descriptive-only",
    "graph": {
      "modules": [],
      "local_edges": [],
      "external_references": [],
      "strongly_connected_components": [],
      "cycles": [],
      "scc_membership": {}
    },
    "module_initializers": [],
    "unavailable_reason": null
  }
}
```

`availability` is exactly `available | unavailable`.
`execution_authority` is always `descriptive-only`: the record is evidence,
not permission to execute source. `graph` is null when source-graph or
module-initializer assembly cannot establish a project-contained snapshot.
`unavailable_reason` is null only when the graph and every initializer plan form
one coherent snapshot. A graph/initializer module-set, relative-path, SHA-256,
or availability mismatch makes the complete plan unavailable rather than
approximating source order.

Each graph `modules[]` item is a serialized `SourceModule`: module name,
project-relative path, package-init flag, source origin, SHA-256, optional
distribution/version/license metadata, dependency depth, source-ordered import
records, and sanitized provenance. Graph edges retain source ranges, import
ordinals, and whether the import is deferred. Strongly connected components
and cycle membership are deterministic.

Each `module_initializers[]` item is a `ModuleInitIR` with module name,
project-relative path, source SHA-256, availability, exact source-order
segments, metadata ranges, an unavailable reason, and provenance. Segments
record their disposition, source range, statement indexes, dependency/binding/
export/deletion sets, namespace uncertainty, and any fallback-barrier reason.
An unavailable initializer carries no approximate segments.

### External source inventory preview (contract 2.5.0) and C6.1 authorization (2.6.0)

This section describes the C5.1 inventory/gate slice plus the additive C6.1
SourceLock authorization-contract preview. It is intentionally smaller than
external-package source AOT and must not be interpreted as build authority or
full C6 completion.

A project may opt in through `rextio.toml` for exactly one imported package:

```toml
[imports.packages.small_math_pkg]
policy = "try-native"
max_depth = 1
distribution = "small-math-pkg"
version = "1.0.0"
```

The full declaration is config-only. Policy-only CLI/environment overrides do
not supply the exact distribution identity. A `try-native` declaration without
both `distribution` and `version` keeps its previous metadata-only behavior.
Serialized import-policy decisions add nullable `distribution` and `version`
fields; they are non-null only when carried from an exact package declaration.

When the configured package is imported, `check.json` and `check --format json`
add top-level `external_source_plan`. `generate.json` mirrors the same sanitized
object at top level and does not copy external source into generated Python
fallback output. A blocked `build.json` includes the plan both through
`analysis.external_source_plan` and as top-level failure evidence:

```json
{
  "external_source_plan": {
    "status": "unavailable",
    "execution_authority": "preview-only",
    "distributable": false,
    "c6_gate": "required",
    "package": "small_math_pkg",
    "distribution": "small-math-pkg",
    "requested_version": "1.0.0",
    "installed_version": "1.0.0",
    "max_depth": 1,
    "license_observed": "MIT",
    "license_material_sha256": null,
    "inventory_schema": "rextio-external-source-inventory-v1",
    "modules": [],
    "source_files": [],
    "metadata_files": [],
    "candidate_functions": [],
    "plan_snapshot": null,
    "plan_snapshot_sha256": null,
    "reason": "depth-1 preview source contains an unresolved import",
    "license_warning": "...",
    "authorization": {
      "status": "plan-unavailable",
      "path": "rextio.external-source.lock.json",
      "reason": "depth-1 preview source contains an unresolved import",
      "snapshot_sha256": null,
      "attestor": null,
      "attestor_kind": null,
      "license_observed": null,
      "license_attestation_verified": false,
      "source_inventory_verified": false,
      "provenance_verified": false
    }
  }
}
```

`status` is exactly `preview-ready | unavailable`. An unavailable record has a
sanitized `reason` and no approximate modules/candidates. Both statuses remain
non-distributable and build-blocking. `license_warning` always states that
translation/redistribution can create derivative-work obligations, calls out
GNU/copyleft risk, and says the inventory is not legal advice; check, generate,
and blocked build also emit it on stderr.

Contract **2.6.0** adds authority material on every resolved plan so projects
can author a SourceLock from check/generate JSON alone:

- `inventory_schema` (`rextio-external-source-inventory-v1`)
- `source_files[]` / `metadata_files[]` with sanitized `path`, `sha256`, `size`,
  and `role` (`source-module` | `record` | `metadata` | `wheel` | `license-file`)
- `license_material_sha256` — shared digest over observed license + METADATA +
  license-file authority material (same algorithm as lock
  `reviewed_license_material_sha256`)
- `plan_snapshot` — domain-separated document hashed into `plan_snapshot_sha256`
  (compact sorted JSON; excludes free-text reason/warning/authorization;
  includes sorted `candidate_functions` and `license_material_sha256`)
- nested `authorization` only (no top-level mirror):
  `status` is exactly
  `missing | invalid | incomplete | stale | plan-unavailable | verified`;
  booleans are `license_attestation_verified`, `source_inventory_verified`,
  `provenance_verified` (true only after successful verification)

Absolute install paths and source bodies never serialize. `c6_gate` is
`required` until verification succeeds, then `authorization-verified`.

#### SourceLock schema (project-owned file)

File name (exact): `rextio.external-source.lock.json` at the project root.

**Mechanical copy rules from `rextio check` JSON** (preview-ready plan only):

1. `package` ← `external_source_plan.package`
2. `distribution` / `version` ← `distribution` / `requested_version`
3. `content_hashes.source_files` ← exact `source_files[]` objects
4. `content_hashes.metadata_files` ← exact `metadata_files[]` objects
   (must include RECORD, METADATA, WHEEL, and every license-file entry)
5. `content_hashes.snapshot_sha256` ← `plan_snapshot_sha256`
6. `source_inventory.components[0].files` ← union of `source_files` and
   `metadata_files` with **identical** path/sha256/size/**role**
7. `source_inventory.components[0].license_observed` ← `license_observed`
8. `provenance.subject_snapshot_sha256` ← `plan_snapshot_sha256`
9. `provenance.installed_wheel.metadata_files` ← exact `metadata_files[]`
10. `provenance.evidence` ← exactly
    `["installed-distribution-record", "project-vcs-review"]` in that order
11. `license_attestation.reviewed_license` ← `license_observed`
12. `license_attestation.reviewed_license_material_sha256` ←
    `license_material_sha256`
13. Set attestor/producer after human/org review; relationship matrix:
    `organization-owner` → `attestor_kind: organization`;
    `human-owner` / `project-maintainer` / `security-reviewer` →
    `attestor_kind: human`

```json
{
  "schema_version": "1",
  "kind": "rextio.external-source-authorization",
  "package": "small_math_pkg",
  "distribution": "small-math-pkg",
  "version": "1.0.0",
  "content_hashes": {
    "source_files": [
      {
        "module_name": "small_math_pkg",
        "path": "distributions/small-math-pkg/small_math_pkg/__init__.py",
        "sha256": "<from plan source_files>",
        "size": 123,
        "role": "source-module"
      }
    ],
    "metadata_files": [
      {
        "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/RECORD",
        "sha256": "<from plan>",
        "size": 200,
        "role": "record"
      },
      {
        "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/METADATA",
        "sha256": "<from plan>",
        "size": 456,
        "role": "metadata"
      },
      {
        "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/WHEEL",
        "sha256": "<from plan>",
        "size": 80,
        "role": "wheel"
      },
      {
        "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/licenses/LICENSE",
        "sha256": "<from plan>",
        "size": 64,
        "role": "license-file"
      }
    ],
    "snapshot_sha256": "<plan_snapshot_sha256>"
  },
  "source_inventory": {
    "format": "rextio-source-inventory-v1",
    "components": [
      {
        "type": "pypi-distribution",
        "name": "small-math-pkg",
        "version": "1.0.0",
        "license_observed": "MIT",
        "files": [
          {
            "path": "distributions/small-math-pkg/small_math_pkg/__init__.py",
            "sha256": "<same as source_files>",
            "size": 123,
            "role": "source-module"
          },
          {
            "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/RECORD",
            "sha256": "<same>",
            "size": 200,
            "role": "record"
          },
          {
            "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/METADATA",
            "sha256": "<same>",
            "size": 456,
            "role": "metadata"
          },
          {
            "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/WHEEL",
            "sha256": "<same>",
            "size": 80,
            "role": "wheel"
          },
          {
            "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/licenses/LICENSE",
            "sha256": "<same>",
            "size": 64,
            "role": "license-file"
          }
        ]
      }
    ]
  },
  "provenance": {
    "subject_snapshot_sha256": "<plan_snapshot_sha256>",
    "producer": "Acme Engineering",
    "attestor_relationship": "organization-owner",
    "installed_wheel": {
      "distribution": "small-math-pkg",
      "version": "1.0.0",
      "metadata_files": [
        {
          "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/RECORD",
          "sha256": "<same>",
          "size": 200,
          "role": "record"
        },
        {
          "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/METADATA",
          "sha256": "<same>",
          "size": 456,
          "role": "metadata"
        },
        {
          "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/WHEEL",
          "sha256": "<same>",
          "size": 80,
          "role": "wheel"
        },
        {
          "path": "distributions/small-math-pkg/small_math_pkg-1.0.0.dist-info/licenses/LICENSE",
          "sha256": "<same>",
          "size": 64,
          "role": "license-file"
        }
      ]
    },
    "evidence": [
      "installed-distribution-record",
      "project-vcs-review"
    ]
  },
  "license_attestation": {
    "attestor": "Acme Engineering",
    "attestor_kind": "organization",
    "reviewed_license": "MIT",
    "reviewed_license_material_sha256": "<license_material_sha256 from plan>",
    "decision": "allow",
    "action_scopes": [
      "analysis",
      "translation",
      "local-build",
      "package",
      "redistribution"
    ],
    "acknowledgement": "REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1"
  }
}
```

Authoring workflow: (1) install the exact distribution, (2) declare the C5.1
import pin, (3) run `rextio check`, (4) copy authority fields per the rules
above, (5) fill attestor/producer after human/org review. Trust boundary is
project/VCS review; this preview has no cryptographic signature.
`source_inventory` is a custom inventory, not a standards-compliant full SBOM.
Full/signed authorization, recursive inventory, native dylib/runtime completeness,
and source-native implementation remain deferred (remaining full C6 / C5.2).
Contract **2.7.0** adds a separate, bounded host-extension wheel evidence
preview (see below); it does not complete full C6 and does not authorize
external-source packaging.

### Host-extension wheel artifact evidence preview (contract 2.7.0)

**In scope:** ordinary successful host-extension wheels whose profile has
`python_fallback_backend = "cpython"`. **Out of scope (field omitted):**
host-executable, rust-crate, host-extension with `nuitka` fallback, WASM, and
external-package source-native builds.

For every in-scope wheel, `build.json` always includes `artifact_evidence` and
the ordinary build still succeeds. Status is exactly:

- `preview-ready` — sidecars written; subject/inputs/cargo graph/wheel ZIP
  inventory are bound with SHA-256 digests
- `unavailable` — sanitized fixed `reason` only; no sidecars; never a false
  provenance claim

Shared fields on both statuses: `authority: "evidence-only"`,
`signature_status: "unsigned"`, `composition: "incomplete"`, `preview: true`,
`complete: false`, `signed: false`.

| Artifact | Location | Notes |
|---|---|---|
| CycloneDX 1.6 JSON | `dist/<wheel>.whl.cdx.json` | Only when `preview-ready`. Primary component is only in `metadata.component` (not duplicated in `components`). `compositions[].aggregate = "incomplete"`. Includes input files, wheel ZIP entry digests, and the **reachable** Cargo resolve graph with top-level `dependencies`. |
| Unsigned in-toto Statement v1 | `dist/<wheel>.whl.intoto.json` | Only when `preview-ready`. SLSA Provenance v1 predicate. Subjects are the wheel **and** the SBOM (outputs). `resolvedDependencies` are inputs/cargo packages only (not the SBOM). No `invocationId`. |
| Report field | `build.json.artifact_evidence` | Always present for in-scope wheels; `preview-ready` or `unavailable` |

Preview-ready shape (additive; omitted when out of scope):

```json
{
  "artifact_evidence": {
    "kind": "host-extension-wheel",
    "status": "preview-ready",
    "authority": "evidence-only",
    "signature_status": "unsigned",
    "composition": "incomplete",
    "preview": true,
    "complete": false,
    "signed": false,
    "target_triple": "aarch64-apple-darwin",
    "subject": {
      "logical_path": "dist/demo-0.1.0-cp311-cp311-macosx_14_0_arm64.whl",
      "sha256": "…",
      "size": 12345,
      "role": "host-extension-wheel"
    },
    "sbom": {
      "format": "CycloneDX",
      "logical_path": "dist/demo-0.1.0-cp311-cp311-macosx_14_0_arm64.whl.cdx.json",
      "sha256": "…",
      "size": 6789,
      "spec_version": "1.6",
      "aggregate": "incomplete",
      "signed": false
    },
    "provenance": {
      "format": "in-toto-Statement",
      "logical_path": "dist/demo-0.1.0-cp311-cp311-macosx_14_0_arm64.whl.intoto.json",
      "sha256": "…",
      "size": 4567,
      "predicate_type": "https://slsa.dev/provenance/v1",
      "statement_type": "https://in-toto.io/Statement/v1",
      "signed": false
    },
    "inputs": [],
    "wheel_entries": [],
    "cargo_packages": [],
    "cargo_dependencies": [],
    "limitations": [
      "preview-only",
      "composition-incomplete",
      "unsigned",
      "not-reproducible-claim",
      "not-hermetic-claim",
      "not-completeness-claim",
      "not-external-source-authorization",
      "no-native-dylib-runtime-inventory",
      "no-recursive-package-inventory",
      "evidence-only-authority"
    ]
  }
}
```

Unavailable shape:

```json
{
  "artifact_evidence": {
    "kind": "host-extension-wheel",
    "status": "unavailable",
    "authority": "evidence-only",
    "signature_status": "unsigned",
    "composition": "incomplete",
    "preview": true,
    "complete": false,
    "signed": false,
    "reason": "source-snapshot-mismatch",
    "limitations": ["preview-only", "composition-incomplete", "unsigned", "…"]
  }
}
```

Cargo packages come only from the **reachable** resolve graph of sanitized
`cargo metadata --locked --offline --filter-platform <target>` (streaming
stdout/stderr hard-capped; POSIX nonblocking select in short intervals with
prompt stop when the direct child exits while a detached holder keeps pipes
open; Windows bounded reader threads with an event-aware short wait so
overflow returns code `125` promptly). The generated root is the only allowed
path/source-less package; other path packages and all git packages are
rejected. Registry packages require an exact `Cargo.lock` checksum for the
same name/version/canonical registry source (no cross-registry fallback).
Registry sources are canonicalized; credential-bearing, query, fragment, and
local-file sources are rejected. Reports and sidecars expose only SHA-256
`source_fingerprint` values — never raw registry URIs. Dependency edges are
keyed by unique package bom-refs (duplicate normalized bom-refs fail closed)
and aggregated/deduplicated in CycloneDX `dependencies`. License fields use
CycloneDX `expression` form. Project/generated inputs are snapshot-hashed
only for in-scope host-extension+cpython builds before native compilation and
re-verified after `cargo metadata` and again immediately before a
`preview-ready` return. Concurrent mutation of those inputs yields
`unavailable` with a fixed reason (for example `source-snapshot-mismatch`);
this is best-effort detection, **not** a race-free or TOCTOU-proof guarantee.
The wheel is read once as an immutable byte snapshot for both subject SHA-256
and ZIP inventory; immediately before `preview-ready` return the wheel path is
re-hashed only to confirm digest and size still match that subject (mismatch
→ `wheel-bytes-mutated` / `unavailable`). Sidecar writes verify path
containment, reject symlink parents, and on supported POSIX pin the output
directory with a dirfd for exclusive temp create/replace/fsync/unlink;
elsewhere a conservative contained path fallback is used. Cleanup removes only
sidecars actually created by that emission (no directory sweep). A `dist`
directory that is a symlink pointing outside the project must not alter outside
sentinels. Sidecars and the report field never serialize absolute paths, source
bytes, credentials, environment secrets, machine-private paths, or unbounded
tool output. Planning `ArtifactProvenance` is unchanged.

#### `artifact_evidence` item shapes and fixed reason enum

Top-level `build.json` and `generate.json` carry additive
`contract_version` (currently `"2.7.0"`). Item fields under
`artifact_evidence` when `status` is `preview-ready`:

| Field | Shape |
|---|---|
| `subject` | `{logical_path, sha256, size, role}` — host-extension wheel subject |
| `sbom` / `provenance` | `{format, logical_path, sha256, size, …extra}` sidecar refs |
| `inputs[]` | `{logical_path, sha256, size, role}` project/generated/Cargo.lock refs |
| `wheel_entries[]` | `{name, sha256, compressed_size, uncompressed_size}` ZIP members |
| `cargo_packages[]` | `{name, version, source_fingerprint, checksum, kind, features, license, purl, bom_ref}` (no raw registry URI) |
| `cargo_dependencies[]` | `{dependent_ref, dependency_ref}` bom-ref edges |

When `status` is `unavailable`, `reason` is exactly one of this fixed
allowlist (no free-text paths or tool output):

| Reason | Meaning |
|---|---|
| `native-extension-not-built` | Native extension did not build |
| `source-snapshot-mismatch` | Captured input digest/size no longer matches |
| `source-input-unreadable` | An input path could not be read safely |
| `input-count-exceeded` | Input file/directory bound exceeded |
| `cargo-lock-missing` | Generated `Cargo.lock` / lock inputs missing |
| `cargo-metadata-failed` | `cargo metadata` failed or was unusable |
| `cargo-metadata-output-exceeded` | Metadata stdout/stderr exceeded the byte cap |
| `cargo-resolve-graph-invalid` | Resolve graph / package graph rejected |
| `wheel-inventory-invalid` | Wheel ZIP inventory failed closed |
| `sidecar-write-failed` | Contained atomic sidecar write failed |
| `evidence-internal-error` | Unexpected evidence path failure |
| `input-snapshot-missing` | Orchestrator did not supply an input snapshot |
| `wheel-bytes-mutated` | Wheel digest/size changed after the subject snapshot |

Resolution uses installed metadata only and never imports or executes the
package. It requires the exact configured distribution name and version, one
well-formed WHEEL 1.0 record with only `Tag: py3-none-any`, one dist-info metadata root, safe
unique RECORD paths, contained non-symlink files, and matching RECORD SHA-256
and size for WHEEL, METADATA, and selected source. The preview reads only direct
depth-1 UTF-8 `.py` files under the configured package and rejects a selected
module containing any import. `modules` uses sanitized
`distributions/<canonical-name>/...` references; installed absolute paths and
source bytes never serialize.

`candidate_functions` contains deterministic lexical hints only: undecorated
top-level `def` names with scalar annotations (`bool`, `int`, `float`, `str`),
no variadic parameters, and a scalar return annotation. C5.1 does not prove the
body is lowerable, connect the function to project call sites, produce Rust,
or authorize a native closure.

`rextio build` returns `RXT060` before configured CPython/Nuitka/Cargo probes or
artifact work. Without a verified SourceLock the status is
`external-source-c6-blocked` and programmatic hybrid builds raise
`ExternalSourceBuildBlockedError`. With a verified SourceLock the distinct
status is `external-source-c5-not-implemented` and programmatic builds raise
`ExternalSourceC5NotImplementedError`: remaining call-site linkage, body
lowerability, Rust codegen, and packaging are not implemented. Neither path
creates artifact directories or grants redistribution authority. Null/unknown
`license_observed` never verifies.

### Resolved `artifact_profiles`

`generate.json` and `build.json` add `plan.artifact_profiles`; the same exact
array is mirrored as top-level `artifact_profiles` for report consumers.
`BuildPlan.artifact_profiles` is the canonical authority. Profiles are resolved
only for outputs the command actually requests and only during generate/build:
a fallback-only command therefore emits an empty array and does not probe a
host target triple. If a requested native output has no supported host triple,
generate/build fails with a structured `RXT060` report instead of guessing a
profile.

One profile has this deterministic shape:

```json
{
  "kind": "host-executable",
  "target_triple": "x86_64-pc-windows-msvc",
  "packaging_backend": "rust-binary",
  "fallback": "python-subprocess",
  "python_fallback_backend": null,
  "abi_requirements": [
    {"name": "rextio-scalar-ipc", "version": "1", "features": []}
  ],
  "runtime_requirements": [
    {"name": "cpython", "version": null, "features": []}
  ],
  "device_requirements": [],
  "provenance": {
    "producer": "rextio",
    "source_references": [],
    "evidence": []
  }
}
```

The closed artifact-kind enum is `host-extension | host-executable |
rust-crate`. Only a host executable carries `fallback`, which is required and
is exactly `error | python-subprocess | nuitka-sidecar`. Only a host extension
carries `python_fallback_backend`, exactly `cpython | nuitka`. ABI, runtime,
and device requirements are descriptive requirements; they do not themselves
prove support or authorize a provider.

### Rust executable closure initializers

For a requested Rust executable, `build.json` adds
`executable_build.closure.module_initializers`, an ordered array of initializer
qualnames already authorized by the executable source gate. The adjacent
closure `strategy` must equal `profile.fallback`. Duplicate or empty initializer
names are invalid.

The initial executable gate accepts only one source module, with the initializer
and direct-native entrypoint in that module; no load-time imports or cycles; and
exact, unconditional single-name assignments to `bool`, `int`, `float`, or
`str` literals. The source hash and statement indexes are revalidated before
lowering. The generated `() -> None` initializer runs before argv handling and
the entrypoint. Its values are discarded: they are not Rust globals and a
native function that reads one blocks the executable. Any initializer
uncertainty makes the closure unavailable and prevents external build work for
all three fallback strategies.

The broader Python-wrapper `native_top_level` path is separate; its returned
update map does not grant Rust-executable initializer authority. See
[Host source-AOT and native executables](../source-aot-and-executables.md).

### Capabilities declarations

Contract 2.3 adds two declarative objects to `rextio capabilities`:

```json
{
  "artifact_contract": {
    "status": "experimental",
    "profile_resolution": "generate-build-only",
    "kinds": ["host-extension", "host-executable", "rust-crate"],
    "host_executable_fallbacks": [
      "error",
      "python-subprocess",
      "nuitka-sidecar"
    ]
  },
  "device_provider_contract": {
    "status": "draft",
    "discovery": false,
    "provider_selected": false,
    "local_probe_performed": false
  }
}
```

Capabilities is declaration/configuration introspection. It does not resolve an
`ArtifactProfile`, inspect local hardware, select a device provider, or claim
device support. The draft provider records and the CUDA Driver API inventory
tool (Windows + Linux hosts) are documented in the
[device-provider draft](device-provider.md) and
[CUDA driver validation guide](../testing/cuda-driver-validation.md). Every
draft preflight/probe result has `support_claim: false`.

## `rextio capabilities --json`

This subcommand is wired like the others in `src/rextio/cli/main.py`, handler
module `src/rextio/cli/capabilities_cmd.py`, output through the existing
`Reporter` seam. It answers: *"in THIS project, with THIS `rextio.toml`, what
can become native, and what should I do when it can't?"*

Resolution is config-aware: it loads the project config (same
CLI > env > `rextio.toml` > default chain), resolves active plugins via the
existing `PluginRegistry`, and merges rule records from core and plugins.
Note: resolving the registry imports and executes enabled plugin packages'
module-level code — with plugins enabled, `capabilities` is configuration
introspection but not side-effect-free. The command never analyzes project
sources or writes report files. Output ordering is deterministic: core rules
in registry order, then plugin rules and the `plugins` array sorted by id.

The following is the published 2.2-era base shape. The unreleased 2.3 producer
adds the two declaration objects shown in
[Capabilities declarations](#capabilities-declarations).

```json
{
  "contract_version": "2.2.0",
  "rextio_version": "0.1.4",
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

- Contract records do not independently authorize lowering or execution. The
  Train C initializer-before-main behavior is authorized by its separate,
  fail-closed executable source/closure gate.
- No LSP or editor logic; those live in rextio-lsp / rextio-vscode.
- No incremental-analysis API (deferred until latency measurements demand it;
  v1 tooling calls the batch analyzer).
- No recursive third-party-package source promotion, device-provider discovery,
  provider build/link hook, CUDA execution, or device support claim through 2.7.0.
  C5.1 inventories one exact distribution but authorizes no lowering or build.
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
5. **0.1.4 / contract 2.2.0 (published 2026-07-18):** Release Train B shipped
   rextio-lsp 0.1.2 before core 0.1.4. The producer adds the frozen
   promotion-assessment and range fields above without reclassifying expected
   automatic fallback as a build error. Plugin API remains 1.3.
6. **Release Train C / contract 2.3.0 (unreleased):** add the descriptive host
   source plan, resolved artifact profiles, explicit executable fallback and
   initializer closure fields, plus declarative artifact/device capability
   markers. Preserve all 2.2 function and position semantics. This is a branch
   candidate, not a published core release.
7. **Release Train C / contract 2.4.0 (unreleased):** add presence-only plugin
   standalone-capability introspection and resolved per-profile allow/deny
   evidence without executing profile hooks during capabilities inspection.
8. **Release Train C / contract 2.5.0 (unreleased):** add exact nullable
   distribution/version import-policy metadata and the sanitized,
   preview-only `external_source_plan`. Keep every such plan non-distributable
   and hard-blocked at the C6 authority gate.
9. **Release Train C / contract 2.6.0 (unreleased):** add C6.1 authority material
   and SourceLock authorization evidence under
   `external_source_plan.authorization`, verified against project-owned lock
   content hashes/sizes/source_inventory/provenance/closed license
   attestation. Verified authorization still fails closed with the distinct
   post-authorization C5-not-implemented block.
10. **Release Train C / contract 2.7.0 (unreleased):** add optional
    `build.json.artifact_evidence` plus bounded incomplete CycloneDX 1.6 and
    unsigned in-toto/SLSA provenance sidecars for ordinary successful
    host-extension wheels only. Do not claim signatures, completeness,
    hermeticity, reproducibility, or external-source authorization. Full C6
    remains pending.
11. Promote the contract to stable once rextio-agent-skill and rextio-lsp have
   consumed it across one release cycle without breaking changes.
