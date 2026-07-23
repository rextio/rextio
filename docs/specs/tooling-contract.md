# Spec: Machine-Readable Tooling Contract

Status: **draft** (experimental tier). The current published producer is core
**0.1.5**, released on 2026-07-23 with `contract_version` **`2.24.0`**, plugin
API **1.4**, and readiness policy **11**, superseding core 0.1.4 / contract
2.2.0. The Train C surfaces described below ship in 0.1.5 but remain
Experimental/Alpha.
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

Both JSON surfaces carry a top-level field. The published 0.1.5 producer emits:

```json
{ "contract_version": "2.24.0" }
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
| `2.7.0` | **Unreleased additive C6.2 host-extension wheel artifact-evidence preview** (Train C intermediate). In-scope successful host-extension+`cpython` wheels always add top-level `build.json.artifact_evidence` with `status` exactly `preview-ready` or `unavailable`, `authority: "evidence-only"`, `signature_status: "unsigned"`, and `composition: "incomplete"`. Preview-ready may emit bounded CycloneDX 1.6 / unsigned in-toto Statement (SLSA Provenance v1) sidecars; unavailable uses a sanitized fixed reason and never changes ordinary build success. Host-executable, rust-crate, Nuitka host-extension fallback, WASM, and external-package source-native builds omit the field. `ArtifactProvenance` remains planning metadata only. |
| `2.8.0` | **Unreleased additive C6.3 required-evidence gate** (Train C intermediate). Required mode adds top-level `build.json.artifact_evidence_gate` and succeeds only when the exact single host-extension + CPython wheel path produces C6.2 `preview-ready` evidence. Scope and evidence failures are `RXT060` / `artifact-evidence-required-failed`; the gate remains incomplete, unsigned, and explicitly non-authorizing. Default best-effort behavior and all C6.2 shapes remain unchanged. |
| `2.9.0` | **Unreleased additive C6.4 direct native runtime linkage preview** (Train C intermediate). Preview-ready evidence for the same bounded host-extension + CPython wheel adds a sanitized `native_runtime_inventory`: macOS Mach-O uses bounded `otool -L`, Linux ELF uses bounded `readelf -W -d`, and the contained installed native extension is bound to one exact wheel member by relative member name, SHA-256, and byte size. It records normalized architecture plus only closed-allowlist direct dependencies, each with sanitized `origin` and stable `bom_ref`. Path resolution, transitive closure, runtime `dlopen`, Windows PE, runtime-bearing plugins, and signatures remain excluded. Best-effort inspection failure reports fixed-reason `unavailable`; required mode preserves the C6.3 `RXT060` transactional rollback. Success remains incomplete, unsigned, and non-authorizing. |
| `2.10.0` | **Unreleased additive C6.5 hard-authorization readiness shape** (Train C intermediate). The same in-scope evidence path adds `build.json.artifact_distribution_authorization`, derived from final `artifact_evidence` after required-mode revalidation/transaction handling. It is always blocked, readiness-only, incomplete, unsigned, and non-authorizing. Closed ordered checks distinguish four deeply reconstructed structural/model bindings from selected current-scope missing license/runtime-closure/source-transformation-provenance/build-identity/reproducibility/signature/composition requirements. Invalid preview structure degrades to all checks `not-evaluated` plus only `readiness-assessment-unavailable`, without changing best-effort or C6.3 outcomes; unavailable evidence retains its fixed reason plus `evidence-unavailable`. |
| `2.11.0` | **Unreleased additive C6.6 source-transformation observation** (Train C intermediate). Preview-ready evidence may add an immutable bounded `source_transformation_inventory` binding accepted project-owned native functions to source/hash/range/semantic-AST-hash, exact generated Rust input, closed generator/backend id, and sorted plugin ids. Collection cross-checks exact ordered value-level coverage against the analyzer list used by code generation and caps records, plugin references/ids, and total deterministic inventory characters. Authorization policy version 2 adds `source-transformation-inventory-bound`; valid inventory may satisfy only that structural/reference-binding observation while complete transformation provenance remains blocked. Missing or over-budget inventory uses one dedicated fixed unavailable blocker; malformed, noncanonical, or exact-reference-binding-breaking models retain the total all-`not-evaluated` readiness-unavailable shape. Build, C6.3 gate, transaction, and publication outcomes are unchanged. |
| `2.12.0` | **Unreleased additive C6.7 component-license observation** (Train C intermediate). Preview-ready evidence may add an immutable bounded `component_license_inventory` exactly covering every reachable Cargo package, including the generated path root, in canonical `bom_ref` order. Null/whitespace-only Cargo metadata values are `missing`; every other bounded value is preserved verbatim as `declared-unvalidated`. This is not SPDX parsing, normalization, classification, owner policy, legal approval, or authorization. Authorization policy version 3 adds `component-license-inventory-bound`; missing inventory affects only that observation, while malformed/noncanonical/non-exact binding fails the whole readiness assessment closed. Provenance records presence and omits C6.7 first at its ceiling so C6.6 is retained whenever possible. Build and C6.3 semantics remain unchanged; `component-license-policy-complete` remains blocked. |
| `2.13.0` | **Unreleased additive C6.8 one-hop native path-resolution observation** (Train C intermediate). Preview-ready evidence may add immutable `native_runtime_path_resolution` schema 1, exactly covering C6.4 direct dependency identities. Trusted system names are logical leaves; contained Mach-O loader-path/self-rpath and ELF ORIGIN RPATH/RUNPATH candidates bind one exact non-symlink wheel member by logical name, SHA-256, and size. Policy version 4 adds `direct-native-path-resolution-bound` and its dedicated unavailable blocker. Collection is optional/noninterfering and C6.8 is omitted before C6.7/C6.6 at the provenance ceiling. Actual loader selection/environment, transitive closure, system-library bytes, `dlopen`, Windows PE, plugin runtime closure, signatures, and authorization remain absent. |
| `2.14.0` | **Unreleased additive C6.9 bounded static native-runtime graph observation** (Train C intermediate). Preview-ready evidence may add immutable `native_runtime_transitive_closure` schema 1 rooted in the exact C6.4 subject and C6.8 direct edges. Exact packaged Mach-O/ELF wheel members are recursively inspected under closed path semantics, while trusted system names remain byte-unbound terminal leaves. The deterministic cycle-safe graph is bounded by node, edge, depth, candidate, inspector, output, deadline, and serialized-size limits and explicitly keeps `transitive_closure_complete`, actual loader selection, and runtime `dlopen` false. Policy version 5 adds `bounded-static-native-runtime-graph-bound` plus a dedicated unavailable blocker. C6.9-only failure retains C6.8; C6.8 failure necessarily omits both. At that contract's provenance ceiling the omission order was C6.9, C6.8, C6.7, then C6.6. Complete loader-faithful closure, system-library bytes, Windows PE, signatures, and authorization remain absent. |
| `2.15.0` | **Unreleased additive C6.10 scoped source-transformation replay verification** (Train C intermediate). Preview-ready evidence may add immutable `source_transformation_verification` schema 1 for the fixed `project-functions-pyo3-plugin-free-v1` scope. The collector securely rereads the exact project-source input set, rederives function AST identities/ranges, reanalyzes and relowers the complete accepted plugin-free PyO3 closure, and requires byte-identical full `src/lib.rs` regeneration. The receipt binds the canonical C6.6 inventory, source-input set, ModuleIR, qualnames, and captured/regenerated Rust. Policy version 6 adds `scoped-source-transformation-verified` plus a dedicated unavailable blocker. Scope/replay failure omits only C6.10; at that contract's provenance ceiling C6.10 was omitted before C6.9/C6.8/C6.7/C6.6. `complete_for_scope` never makes global transformation provenance complete, signed, or distribution-authorizing. |
| `2.16.0` | **Unreleased additive C6.11 scoped Cargo component-license policy verification** (Train C intermediate). Preview-ready evidence may add immutable `component_license_policy_verification` schema 1 for exact reachable registry-license metadata. A strict project-owner lock must reproduce every raw C6.7 registry row, bind the full C6.7 digest and exact lock bytes, and attest the fixed allow scopes. Policy version 7 adds `scoped-component-license-policy-verified` plus a dedicated unavailable blocker. Attestor identity, SPDX/license-file/legal analysis, signatures, global policy completion, and distribution authority remain unverified. At that contract's provenance ceiling C6.11 was omitted before C6.10/C6.9/C6.8/C6.7/C6.6, and it never changed ordinary-build or C6.3 gate outcomes. |
| `2.17.0` | **Unreleased additive C6.12 scoped project-source license-policy verification** (Train C intermediate). Preview-ready evidence may add immutable `project_source_license_policy_verification` schema 1 only for an exact present C6.10 receipt. A strict project-owner lock binds the full C6.10 digest, exact source-input set, generated `src/lib.rs`, separate project-source/generated-output license declarations, exact lock bytes, and fixed allow scopes. Policy version 8 adds `scoped-project-source-license-policy-verified` plus a dedicated unavailable blocker. Final admission reruns C6.10 with identical inputs, requires full receipt equality, and then recollects C6.12. This does not prove attestor identity, SPDX validity, license/NOTICE files, obligations, compatibility, ownership or output/derivative-work rights, legal approval, signatures, global policy completion, or distribution authority. C6.12 is omitted before C6.11/C6.10/C6.9/C6.8/C6.7/C6.6 at the provenance ceiling and never changes ordinary-build or C6.3 gate outcomes. |
| `2.18.0` | **Unreleased additive C6.13 scoped analysis-input verification** (Train C intermediate). Preview-ready evidence may add an optional receipt for every C6.10 source's sibling `.pyi`, binding present logical path, byte SHA-256/size, and deterministic supported-signature projection/version to the exact replay/source set. Present stubs are `project-python-stub` materials; absent records are metadata only. Secure immutable snapshots are evidence-eligible, compatibility snapshots are analyzer-only. Policy version 9 adds the twelfth observation `scoped-analysis-inputs-verified` and its dedicated unavailable blocker; malformed/forged present receipts fail readiness closed. At that contract's ceiling omission started with C6.13, then C6.12/C6.11/C6.10/C6.9/C6.8/C6.7/C6.6, and removing C6.10 removed dependent C6.12/C6.13. |
| `2.19.0` | **Unreleased additive C6.14 artifact-policy coverage inventory** (Train C intermediate). Preview-ready evidence may add an immutable, bounded `artifact_policy_coverage_inventory` that partitions only the exact C6.2-C6.13 observed component universe into thirteen fixed disjoint classes. Each row carries a count, domain-qualified canonical identity-set SHA-256, identity strength, separate license-policy and transformation-provenance states, and only the exact applicable prerequisite receipt kind/digest. It never infers coverage beyond C6.10-C6.13 receipts, adds no provenance material, and keeps scope/global completeness, signing, and distribution authority false. Policy version 10 adds the thirteenth observation `artifact-policy-coverage-bound` and `artifact-policy-coverage-unavailable`; all ten global readiness checks remain blocked. At that contract's ceiling omission started with C6.14. |
| `2.20.0` | **Unreleased additive C6.15 scoped artifact-class policy verification** (Train C intermediate). Preview-ready evidence may add immutable `artifact_class_policy_verification` bound to strict `rextio.artifact-policy.lock.json` bytes, the full semantic C6.14 SHA-256 and partition digest, and exactly thirteen ordered nested coverage rows. A deterministic closed disposition matrix cannot weaken applicable C6.10-C6.13 receipt bindings. The lock is one provenance material outside C6.14; final collection recollects C6.10-C6.13, re-derives C6.14, and rereads the lock. Policy version 11 adds the fourteenth observation `scoped-artifact-class-policy-declaration-bound` and its dedicated unavailable blocker. All identity/SPDX/files/notices/obligations/compatibility/ownership/rights/legal/provenance/global/signature/authority claims remain false. Omission order starts C6.15, then C6.14/C6.13/C6.12/C6.11/C6.10/C6.9/C6.8/C6.7/C6.6. |
| `2.21.0` | **Unreleased additive strict Full-C6 primitive shape** (Train C intermediate). Adds immutable preauthorization/final evidence, complete frozen owner policy, two-isolated-build executor/reproducibility, toolchain/input/runtime/supply-chain receipts, external detached-signature verification, a sealed distribution-authorization token, and create-if-absent atomic bundle publication. This is a separate hard-authority chain; it does not promote or reinterpret C6.2-C6.15 preview evidence/readiness. The frozen scope is CPython/PyO3/Cargo on macOS arm64 or Linux x86_64, one exact depth-1 pure-Python wheel, and no plugins/executable/rust-crate/top-level/embedding/Windows. |
| `2.22.0` | **Unreleased additive bounded C5.2 and initial CLI-coordinator shape** (Train C intermediate). Adds a sealed same-transaction external build context, direct typed scalar leaf-call linkage, private external Rust IR, an exact output-wheel `Requires-Dist`/runtime-guard contract, and a three-stage lifecycle: non-authorizing owner-policy bootstrap; pinned-policy signing request; then externally detached-signed publication. Rextio never accepts, creates, or retains a private key. General external-source AOT and every scope excluded in 2.21.0 remain unsupported. |
| `2.23.0` | **Unreleased exact Full-C6 owner-policy handoff and closure hardening** (Train C intermediate). Bootstrap schema/domain v2 embeds the canonical C6.14+C5.2 technical template, transformation set, and exact project/Cargo plus external-wheel license observations. A separate explicit owner completion is combined by `rextio policy finalize` into manifest/policy v2 with bootstrap lineage; every later production run recollects and rederives those facts. Every lifecycle still performs two actual isolated builds, while `FullC6ProductionAuthority` remains an uncopyable, unserializable process seal rather than distribution authority. Strict analysis binds the complete bounded Python namespace and forbids `.rextioignore`; preanalysis failure is stderr-only. Runtime admission never imports/introspects the external dependency module/callable and descriptor-relatively verifies exact installed source bytes. Exact external PEP 639 payloads are final-wheel license members under `external/<distribution>/<version>/`. Cargo lock/vendor pins prove owner-selected integrity, not registry/publisher origin. All prior frozen-scope exclusions remain. |
| `2.24.0` | **Published Full-C6 host support closure and production sandbox receipts** (core 0.1.5; Experimental/Alpha). Adds the public, non-authorizing `policy bootstrap-support-lock` result and config pair; rejects exact/ancestor/descendant aliasing between that output and every configured lifecycle artifact or source archive; binds the fixed platform support plan plus canonical raw/Merkle lock identities; records path-free, engine-specific semantic sandbox profile digests for Linux bwrap/seccomp/isolated-CPython/Landlock or macOS sandbox-exec/Xcode/SDK/SSV execution in both invocation receipts; denies inherited macOS mutable-volume executable mappings; and carries those identities into strict SBOM/SLSA materials. Each strict build verifies the complete support tree once during host collection and twice inside the executor. This remains the frozen narrow Alpha, not a general hermetic-build claim. |
| `2.25.0` | **Unreleased additive plugin expression shape.** Plugin API 1.5 adds the explicitly version-gated `compare` rule/claim kind for one non-chained `== != < <= > >=` expression. A claimed comparison may report a plugin-owned non-scalar result type, which Core preserves as an operand type for a later claimed expression and through IR/codegen. Pre-1.5 providers are never offered the new site; existing call/binop, routing, diagnostics, and position semantics are unchanged. |
| `2.26.0` | **Unreleased additive selected Device Provider shape.** Advanced `[target]` config may explicitly name one provider/capability and a bounded string option map. `capabilities` reports only the public configured selection, without provider discovery/import, preflight, or option disclosure; its unselected object retains the prior exact shape. `generate.json` / `build.json` conditionally add `device_provider_plans` only after selected-only entry-point loading and successful preflight. Each plan binds the entry-point group/name/module target, installed distribution name/version, manifest, exact artifact profile, validated contribution, redacted option keys/digest, deterministic lock, and non-authorizing report. Bounded host-extension generation may add `build.rs` plus `device-provider.lock.json`; both become captured artifact-evidence/SBOM/provenance inputs. Non-empty Cargo-feature, package-reference, helper, or runtime-check contributions remain unmaterialized and fail closed. No selection preserves the prior generate/build report shape and never imports installed providers. Accelerator selection additionally requires a matching typed non-CPU `DeviceRequirement`; every unselected artifact profile is checked for one. This contract alone is not CUDA framework support. |

Contracts 2.3.0-2.23.0 above are labeled unreleased because they were
unpublished internal Train C intermediates, not because the final 2.24.0
surface is absent from the published 0.1.5 package.

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

This section describes an additive shape first staged in the unpublished
internal Train C contract 2.3.0 and now included in published core 0.1.5 /
contract 2.24.0. Published core 0.1.4 stopped at contract 2.2.0.

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
`complete: false`, `signed: false`, `distribution_authorized: false`.

| Artifact | Location | Notes |
|---|---|---|
| CycloneDX 1.6 JSON | `dist/<wheel>.whl.cdx.json` | Only when `preview-ready`. Primary component is only in `metadata.component` (not duplicated in `components`). `compositions[].aggregate = "incomplete"`. Includes input files, wheel ZIP entry digests, and the **reachable** Cargo resolve graph with top-level `dependencies`. |
| Unsigned in-toto Statement v1 | `dist/<wheel>.whl.intoto.json` | Only when `preview-ready`. SLSA Provenance v1 predicate. Subjects are the wheel **and** the SBOM (outputs). `resolvedDependencies` are inputs/cargo packages only (not the SBOM). No `invocationId`. |
| Report field | `build.json.artifact_evidence` | Always present for in-scope wheels; `preview-ready` or `unavailable` |

Preview-ready shape (abridged; additive; omitted when out of scope):

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
    "distribution_authorized": false,
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
      "direct-native-linkage-only",
      "one-hop-static-native-path-resolution-only",
      "bounded-static-native-runtime-graph-only",
      "no-loader-environment-selection-claim",
      "no-transitive-dylib-closure",
      "no-runtime-dlopen-inventory",
      "no-recursive-package-inventory",
      "evidence-only-authority"
    ]
  }
}
```

The 2.9.0 producer also requires the `native_runtime_inventory` record
described below; that nested record is omitted from this abridged shared-fields
example. Producers before 2.9.0 did not emit it.

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
    "distribution_authorized": false,
    "reason": "source-snapshot-mismatch",
    "limitations": ["preview-only", "composition-incomplete", "unsigned", "…"]
  }
}
```

`artifact_evidence.distribution_authorized` is mandatory and exactly `false`
for both statuses. Neither `preview-ready` nor required-mode gate satisfaction
may omit it or change it to `true`; artifact evidence remains observational and
cannot authorize distribution.

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
containment, reject symlink parents, and pin the output-parent identity across
publication. Each replacement/removal/restoration is authorized by an exact
receipt for the expected path identity and content digest/size, and published
bytes are verified against that receipt. Cleanup never sweeps a directory and
never removes or overwrites pre-existing or concurrently replaced content that
does not still match this transaction's receipt. A parent/receipt/content
mismatch fails closed; required rollback reports itself incomplete rather than
claiming cleanup succeeded. A `dist` directory that is a symlink pointing
outside the project must not alter outside sentinels. Sidecars and the report
field never serialize absolute paths, source bytes, credentials, environment
secrets, machine-private paths, or unbounded tool output. Planning
`ArtifactProvenance` is unchanged.

Required-mode wheel publication is stricter than an observational receipt: the
wheel is first built under the private output transaction directory and then
hard-linked into the pinned `dist` parent with create-if-absent semantics. A
file merely observed at the final path is never claimed by this run. Rollback
first atomically renames a public candidate into that private quarantine and
only then checks its receipt; a mismatch is restored without replacement when
possible and otherwise remains quarantined for manual recovery. Preservation
of a pre-existing output is write-ahead recorded before its rename, including
the post-rename inspection-failure path.

#### `artifact_evidence` item shapes and fixed reason enum

Top-level `build.json` and `generate.json` carry additive
`contract_version` (currently `"2.24.0"`). Item fields under
`artifact_evidence` when `status` is `preview-ready`:

| Field | Shape |
|---|---|
| `distribution_authorized` | Required on both statuses and always `false`; evidence cannot authorize distribution |
| `subject` | `{logical_path, sha256, size, role}` — host-extension wheel subject |
| `sbom` / `provenance` | `{format, logical_path, sha256, size, …extra}` sidecar refs |
| `inputs[]` | `{logical_path, sha256, size, role}` project/generated/Cargo.lock refs |
| `wheel_entries[]` | `{name, sha256, compressed_size, uncompressed_size}` ZIP members |
| `cargo_packages[]` | `{name, version, source_fingerprint, checksum, kind, features, license, purl, bom_ref}` (no raw registry URI) |
| `cargo_dependencies[]` | `{dependent_ref, dependency_ref}` bom-ref edges |
| `native_runtime_inventory` | Introduced in 2.9.0; retained in current 2.24.0: `{format, architecture, inspector, subject_basename, subject_sha256, subject_size, wheel_member, wheel_member_sha256, wheel_member_size, dependency_count, dependencies, scope, transitive_closure, runtime_dlopen}`; exact native/wheel identity+hash+size binding and closed-allowlist direct dependencies shaped `{name, origin, bom_ref}` |
| `native_runtime_path_resolution` | Introduced in 2.13.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, authority, complete, subject_wheel_member, subject_sha256, record_count, records}`. The canonical subject wheel member and SHA-256 exactly bind the C6.4 native runtime subject. Records exactly cover direct dependency identities as `{dependency_bom_ref, dependency_name, dependency_origin, resolution, mechanism, wheel_member, sha256, size}`; wheel fields are all exact/non-null only for `wheel-member`, otherwise all null. |
| `native_runtime_transitive_closure` | Introduced in 2.14.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, authority, complete, bounded_graph_observed, transitive_closure_complete, actual_loader_selection, runtime_dlopen, format, architecture, subject_wheel_member, subject_sha256, subject_size, root_node_ref, node_count, edge_count, max_depth_observed, limits, nodes, edges}`. It is a deterministic bounded static graph rooted in C6.4/C6.8, not a complete loader-faithful closure. Wheel-member nodes carry exact member/hash/size bytes; system-logical terminal leaves carry no byte identity. |
| `source_transformation_inventory` | Introduced in 2.11.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, authority, complete, record_count, records}`. Each record binds `{source_path, source_sha256, function_module, function_qualname, source_range, semantic_ast_sha256, generated_rust, generator_backend, plugin_ids}`; `generated_rust` is the exact declared `generated-rust-input` ref for `src/lib.rs`. |
| `source_transformation_verification` | Introduced in 2.15.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, authority, complete, complete_for_scope, global_provenance_complete, scoped_verification, plugin_free, full_accepted_function_closure, source_transformation_inventory_sha256, source_input_set_sha256, module_ir_sha256, function_count, function_qualnames, source_input_count, source_inputs, generated_rust, regenerated_rust_sha256, regenerated_rust_size, generator_backend}`. The fixed scope is `project-functions-pyo3-plugin-free-v1`; exact replay completeness does not imply global provenance completeness. |
| `component_license_inventory` | Introduced in 2.12.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, authority, complete, record_count, records}`. Each record exactly binds one reachable Cargo component as `{bom_ref, name, version, kind, license_observed, license_observation}` in canonical `bom_ref` order. `license_observation` is exactly `declared-unvalidated | missing`; no SPDX or legal/policy meaning is inferred. |
| `component_license_policy_verification` | Introduced in 2.16.0; retained in current 2.24.0: immutable scoped receipt `{kind, schema_version, scope, policy, authority, complete, signed, distribution_authorized, complete_for_scope, global_license_policy_complete, metadata_only, generated_root_excluded, license_files_verified, legal_approval_verified, owner_attestation_bound, attestor_identity_verified, component_license_inventory_sha256, lock_file, policy_snapshot_sha256, registry_component_count, registry_component_bom_refs, attestor, attestor_kind, attestor_relationship, decision, action_scopes, acknowledgement}`. It exactly binds the full C6.7 digest, registry `bom_ref` coverage, and project-owner lock bytes but remains observation-only and non-authorizing. |
| `project_source_license_policy_verification` | Introduced in 2.17.0; retained in current 2.24.0: immutable scoped receipt `{kind, schema_version, scope, policy, authority, complete, signed, distribution_authorized, complete_for_scope, global_license_policy_complete, owner_attestation_bound, attestor_identity_verified, license_declarations_only, source_ownership_verified, generated_output_rights_verified, derivative_work_rights_verified, spdx_verified, license_files_verified, notice_files_verified, obligations_verified, license_compatibility_verified, legal_approval_verified, source_transformation_verification_sha256, source_input_set_sha256, source_input_count, source_inputs, generated_rust, lock_file, policy_snapshot_sha256, project_source_license_declared, generated_rust_license_declared, attestor, attestor_kind, attestor_relationship, decision, action_scopes, acknowledgement}`. It exactly binds a full present C6.10 receipt, project-source set, generated `src/lib.rs`, separate declarations, and owner-lock bytes but remains observation-only and non-authorizing. |
| `analysis_input_verification` | Introduced in 2.18.0; retained in current 2.24.0: immutable scoped receipt `{kind, schema_version, scope, authority, complete_for_scope, global_build_input_closure_complete, complete, signed, distribution_authorized, source_transformation_verification_sha256, source_input_set_sha256, source_paths, records, analysis_input_set_sha256, analysis_input_set_version, supported_signature_projection_set_sha256, supported_signature_projection_set_version}`. Records are exact `absent` or `present`; present records bind a `project-python-stub` logical path, byte SHA-256/size, and supported-signature projection/version. Raw bytes, source text, absolute roots, and exception text are excluded. |
| `artifact_policy_coverage_inventory` | Introduced in 2.19.0; retained in current 2.24.0: immutable observation-only `{kind, schema_version, scope, identity_scheme, authority, scope_complete, global_license_policy_complete, global_transformation_provenance_complete, complete, signed, distribution_authorized, class_count, observed_component_count, canonical_partition_sha256, classes}`. It always has exactly thirteen canonical class rows; each row is `{class_id, observed_count, canonical_identity_set_sha256, identity_state, license_policy_state, license_policy_receipt_kind, license_policy_receipt_sha256, transformation_provenance_state, transformation_provenance_receipt_kind, transformation_provenance_receipt_sha256}`. It classifies only already-observed components and all completeness/authority booleans remain false. |
| `artifact_class_policy_verification` | Introduced in 2.20.0; retained in current 2.24.0: immutable scoped receipt `{kind, schema_version, scope, policy, authority, complete, signed, distribution_authorized, complete_for_observed_classes, scope_complete, global_license_policy_complete, global_transformation_provenance_complete, declarations_only, spdx_verified, license_files_verified, notice_files_verified, obligations_verified, license_compatibility_verified, source_ownership_verified, derivative_work_rights_verified, legal_approval_verified, technical_provenance_verified, owner_attestation_bound, attestor_identity_verified, artifact_policy_coverage_inventory_sha256, canonical_partition_sha256, class_count, classes, lock_file, policy_snapshot_sha256, attestor, attestor_kind, attestor_relationship, decision, action_scopes, acknowledgement}`. Exactly thirteen ordered rows nest the full C6.14 coverage row plus closed license/transformation dispositions. The lock is one provenance material outside C6.14; every global/signature/authority claim remains false. |

When `status` is `unavailable`, `reason` is exactly one member of the fixed
allowlist (no free-text paths or tool output). The C6.2 entries are below;
C6.4 adds the fixed linkage-inspection entries listed in its section:

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

### Required artifact-evidence gate (contract 2.8.0)

The build-only setting `[build] artifact_evidence_policy` is exactly
`best-effort | required` and defaults to `best-effort`. It also has the CLI
spelling `--artifact-evidence-policy` and environment spelling
`REXTIO_ARTIFACT_EVIDENCE_POLICY`, resolved by the normal CLI > environment >
TOML > default precedence.

`best-effort` preserves contract 2.7.0: evidence unavailability is non-fatal
and `artifact_evidence_gate` is omitted. `required` is valid only for exactly
one ordinary host-extension profile with CPython wheel fallback, at least one
accepted native region that requires a host extension (an accepted function
and/or native top-level segment), no executable request, no Rust-importable crate,
and no additional artifact profile. An invalid artifact set stops before
configured CPython/Nuitka/Cargo/maturin work with `RXT060`, exit code 1,
`build.json.status = "artifact-evidence-required-failed"`, and reason
`artifact-set-out-of-scope`. External-source C6.1/C5.2 blocks retain precedence.

In-scope required builds succeed only when `artifact_evidence.status` is
`preview-ready`. `unavailable` evidence fails with the same report status and
reason `evidence-unavailable`; `evidence_reason` carries the fixed C6.2/C6.4
reason.
Programmatic `build_hybrid_artifact` raises rather than returning an apparently
successful result. A failed required run removes only its exact wheel and two
sidecar paths, restores pre-existing exact outputs, preserves unrelated files,
and keeps generated source plus reports for debugging. Output parents must be
real contained directories whose identity stays pinned through the transaction.
Removal or restoration requires the current path identity and digest/size to
match the exact publication/backup receipt; concurrently replaced content is
left untouched. The transaction also rolls back on exceptional exits. If parent
identity, ownership, content, cleanup, or restoration cannot be verified, the
build report says the rollback was incomplete rather than claiming those files
were removed or restored.

The immutable gate is emitted only in required mode:

```json
{
  "artifact_evidence_gate": {
    "mode": "required",
    "status": "satisfied",
    "scope": "host-extension-wheel-cpython-v1",
    "required_status": "preview-ready",
    "observed_status": "preview-ready",
    "reason": null,
    "evidence_reason": null,
    "distribution_authorized": false,
    "complete": false,
    "signed": false
  }
}
```

For scope rejection, `observed_status` and `evidence_reason` are null. For
evidence rejection, `observed_status` is `unavailable`. Even `satisfied` never
means distribution authorization, evidence completeness, signature presence,
reproducibility, hermeticity, or full C6 completion.

### Direct native runtime linkage inventory (contract 2.9.0)

C6.4 extends the same bounded host-extension + CPython wheel evidence path; it
does not widen artifact-profile scope. A `preview-ready` record from the 2.9.0
producer includes `native_runtime_inventory` for the generated extension. The
inventory is an observation made after the native build and wheel snapshot, not
a loader simulation or a claim that dependency names are verified build
materials.

Inspection is platform-fixed and bounded:

- macOS Mach-O invokes `otool -L` and may invoke `otool -D` only for the
  bounded private-self-ID check described below;
- Linux ELF invokes `readelf -W -d` and accepts direct `NEEDED` observations;
- every child uses a reviewed absolute system-tool path, no shell, a short
  timeout, and fixed stdout/stderr cap;
- inspector children do not inherit the parent process environment: their
  environment is limited to the minimal C-locale settings needed for stable
  parser output;
- inspector absolute paths, raw output, environment values, credentials, source
  bytes, and machine-private absolute paths never serialize; and
- Windows and every other platform produce fixed-reason `unavailable` evidence.

Before accepting the inventory, Rextio requires the builder-reported native
extension to be a contained regular file. Exactly one wheel member at the
corresponding generated-Python relative path must match the installed native
file's SHA-256 and byte size. Inspection then uses one private same-byte snapshot
bound to both that original and wheel member: binary-header parsing and every
`otool`/`readelf` read target the snapshot, not the mutable original. Original
and snapshot identity plus digest/size are revalidated before
`preview-ready`; binary format and normalized architecture must agree with the
host artifact profile. Mutation or any identity/hash/size mismatch fails closed.
The serialized linkage contains bounded sanitized logical names only;
CycloneDX represents native-binary-to-dependency edges from that list.

The exact 2.9.0 wire shape is flat and additive:

```json
{
  "native_runtime_inventory": {
    "format": "mach-o",
    "architecture": "aarch64",
    "inspector": "otool",
    "subject_basename": "_rextio_native.cpython-311-darwin.so",
    "subject_sha256": "…",
    "subject_size": 123456,
    "wheel_member": "demo/_rextio_native.cpython-311-darwin.so",
    "wheel_member_sha256": "…",
    "wheel_member_size": 123456,
    "dependency_count": 1,
    "dependencies": [
      {
        "name": "libSystem.B.dylib",
        "origin": "system",
        "bom_ref": "urn:rextio:native-dep:e15cd9b72bba39b815217f5bd6b134680"
      }
    ],
    "scope": "direct-only",
    "transitive_closure": false,
    "runtime_dlopen": false
  }
}
```

`subject_sha256 == wheel_member_sha256`, `subject_size == wheel_member_size`,
and `dependency_count == len(dependencies)` are required invariants. `format` is
exactly `mach-o | elf`; `inspector` is exactly `otool | readelf`;
`architecture` is one normalized value from `aarch64 | arm | powerpc |
powerpc64 | riscv64 | s390x | x86 | x86_64`. Dependencies are unique and
bounded, `origin` is exactly `system | unresolved`, and `bom_ref` is a stable
path-free identity derived from origin plus name. They are not resolved paths.
No raw inspector output or inspector executable path is part of the wire shape.

The C6.4 inventory always states direct-only scope. It does **not** resolve
`RPATH`/`RUNPATH`, Mach-O install names, or dependency files; compute a
transitive dylib closure; observe libraries loaded later through `dlopen` or an
equivalent API; cover Windows PE; inspect runtime-bearing plugin payloads; or
provide signatures. Unsupported or unsafe search-path/loading metadata fails
closed; allowed logical tokens are recorded but never resolved. CycloneDX and
provenance carry only the same sanitized direct observation and never upgrade
it into a closure or verified material claim.

Dependency admission is deliberately closed rather than observationally
permissive. Mach-O accepts only install names rooted in `/usr/lib` or
`/System/Library`, reduces them to safe basenames, and records `origin:
"system"`. Linux accepts only the target-specific expected runtime `NEEDED`
set; arbitrary libraries and alternate loader dependency tags are rejected.
Accepted ELF names remain `origin: "unresolved"` because C6.4 does not resolve
them to files. A syntactically safe ELF basename outside the target-specific
runtime allowlist uses `native-runtime-unexpected-dependency`, not a free-text
tool/path error. Mach-O relative, `@...`, traversal-bearing, and non-system
absolute install names instead fail the earlier closed path policy with
`native-runtime-unsafe-dependency-path`; they are never admitted as normalized
dependency names for allowlist comparison.

Mach-O self-reference handling is also fail closed. The first `otool -L` row
may be excluded as the generated private Cargo self-ID only when the private
snapshot's header is `MH_DYLIB` **and** a separate bounded `otool -D` result is
an exact match for that row. Neither first-row position, a path-like name, nor
Cargo provenance is sufficient by itself. If the two independent observations
do not agree, the row remains an ordinary dependency and must pass the same
closed allowlist; malformed or unexpected content makes evidence unavailable.

The fixed C6.4 additions to the `unavailable.reason` allowlist are:

| Reason | Meaning |
|---|---|
| `native-runtime-platform-unsupported` | Host platform has no C6.4 inspector contract (including Windows) |
| `native-runtime-inspector-missing` | Required `otool` or `readelf` executable is unavailable |
| `native-runtime-inspector-failed` | Inspector returned a bounded non-success result |
| `native-runtime-inspector-timeout` | Inspector exceeded its short timeout |
| `native-runtime-output-exceeded` | Inspector output exceeded the byte cap |
| `native-runtime-inventory-malformed` | Output or linkage metadata did not match the closed parser grammar |
| `native-runtime-unsafe-dependency-path` | A dependency/search-path observation was unsafe or ambiguous |
| `native-runtime-dependency-count-exceeded` | Dependency/name/graph bounds were exceeded |
| `native-extension-binary-missing` | The exact contained builder-reported native extension was unavailable |
| `native-extension-binary-mismatch` | Native format, bytes, SHA-256, size, or revalidation did not match |
| `native-wheel-member-mismatch` | No single exact wheel-member identity matched the native extension |
| `native-runtime-architecture-mismatch` | Observed architecture did not match the host profile |
| `native-runtime-unexpected-dependency` | A dependency or alternate loader edge fell outside the closed expected-runtime allowlist |

In default `best-effort` mode, any of these reasons produces `unavailable`, no
sidecars, and an otherwise successful ordinary wheel build. Under `required`,
the same result follows C6.3: `RXT060`, report status
`artifact-evidence-required-failed`, reason `evidence-unavailable`, and
transactional rollback of only this run's exact wheel and sidecars (with
pre-existing exact outputs restored). Even a successful inventory keeps
`composition: "incomplete"`, `signed: false`, and
`distribution_authorized: false`; it is not release authorization.

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

### Source-transformation inventory observation (contract 2.11.0)

C6.6 keeps the C6.2-C6.4 artifact scope unchanged and adds
`artifact_evidence.source_transformation_inventory` only as bounded
observation metadata. Normal in-scope native wheel evidence constructs it from
the actual `BuildPlan`, project `SourceModuleGraph`, analyzer function records,
and the generated-Rust input snapshot already used by evidence.

The fixed inventory envelope is:

```json
{
  "kind": "source-transformation-inventory",
  "schema_version": 1,
  "scope": "accepted-project-native-functions",
  "authority": "observation-only",
  "complete": false,
  "record_count": 1,
  "records": [
    {
      "source_path": "src/demo/math.py",
      "source_sha256": "…",
      "function_module": "demo.math",
      "function_qualname": "demo.math.add",
      "source_range": {
        "start": {"line": 1, "column": 0},
        "end": {"line": 2, "column": 16}
      },
      "semantic_ast_sha256": "…",
      "generated_rust": {
        "logical_path": ".rextio/generated/rust/src/lib.rs",
        "sha256": "…",
        "size": 1234,
        "role": "generated-rust-input"
      },
      "generator_backend": "rextio-core-rust-pyo3-v1",
      "plugin_ids": []
    }
  ]
}
```

Records use canonical source/module/qualname/range order and reject duplicates,
ambiguous source ranges or function identities, non-project/external modules,
orphan source/generated-input bindings, malformed logical paths/hashes/ranges,
unknown generator/backend ids, and unsorted/duplicate/unsafe plugin ids. The
semantic identity is SHA-256 of the analyzer's deterministic attribute-free AST
identity; the AST dump itself is never serialized. Raw source, absolute paths,
exception text, credentials, environment values, and unbounded output are also
excluded. Before constructing records, the collector requires the exact same
canonical ordered accepted functions and essential fields from both
`NativePlan.accepted_functions` and
`ProjectAnalysis.accepted_native_functions`, the list consumed by code
generation. It caps accepted records, total scanned plugin references, unique
plugin ids per record, and the complete compact deterministic JSON character
count.

Unsigned in-toto provenance carries the same inventory under
`runDetails.metadata.rextio:source_transformation_inventory`. Records reference
only source and generated Rust inputs, never the provenance sidecar, so there is
no circular digest. This is not complete transformation provenance: top-level
initializers, embedded helpers, external-package source, executables, Rust
crates, Nuitka, WASM, Windows, and runtime-bearing plugin payloads are outside
the observation.

If construction is unsupported or exceeds a bound, the inventory is omitted
without changing best-effort build success, sidecar publication, C6.3
satisfaction, transaction, or rollback. If an otherwise valid inventory alone
would push provenance over the sidecar ceiling, provenance is deterministically
rebuilt with only that inventory omitted. Authorization policy version 2 then marks only
`source-transformation-inventory-bound` as `unavailable` and adds the dedicated
`source-transformation-inventory-unavailable` blocker alongside the existing
readiness blockers. Low-level malformed/noncanonical inventory, or one with a
broken exact source/generated evidence-reference binding, instead uses the
existing all-`not-evaluated`, sole `readiness-assessment-unavailable` shape.

### Component-license inventory observation (contract 2.12.0)

C6.7 keeps the C6.2-C6.6 artifact scope and C6.3 gate unchanged. It adds
`artifact_evidence.component_license_inventory`, constructed only from the
already admitted reachable `cargo_packages` metadata. The fixed envelope is:

```json
{
  "kind": "component-license-inventory",
  "schema_version": 1,
  "scope": "reachable-cargo-packages",
  "authority": "observation-only",
  "complete": false,
  "record_count": 2,
  "records": [
    {
      "bom_ref": "urn:rextio:cargo:…",
      "name": "rextio_generated_native",
      "version": "0.1.0",
      "kind": "path-root",
      "license_observed": null,
      "license_observation": "missing"
    },
    {
      "bom_ref": "urn:rextio:cargo:…",
      "name": "pyo3",
      "version": "0.23.5",
      "kind": "registry",
      "license_observed": "MIT OR Apache-2.0",
      "license_observation": "declared-unvalidated"
    }
  ]
}
```

Records cover exactly every reachable package, including the generated path
root, in canonical unique `bom_ref` order. The package `bom_ref`, name,
version, and kind must exactly match the corresponding `cargo_packages` item.
Cargo metadata null and whitespace-only values become null/`missing`. Every
other value is retained verbatim, including surrounding whitespace, subject to
fixed type, per-string, record-count, and compact deterministic JSON bounds;
NUL and ASCII control characters are rejected. `UNKNOWN`, `NOASSERTION`,
sentinel-looking values, and compound expressions remain ordinary
`declared-unvalidated` strings.

This record does no SPDX parsing, normalization, compatibility or obligation
analysis, license-file reading, owner allow/deny policy, SourceLock decision,
legal approval, or distribution authorization. Existing CycloneDX package
metadata represents an unvalidated nonblank Cargo string as
`licenses[].license.name`, never as a validated SPDX `expression`.
`component-license-policy-complete` therefore remains blocked.

Unsigned provenance records
`component_license_inventory_observed` and
`runDetails.metadata.rextio:component_license_inventory_observed`; when
present, it also carries the exact inventory under
`runDetails.metadata.rextio:component_license_inventory`. Under the retained
C6.15 preview rules,
the provenance ceiling first omits C6.14, then C6.13, C6.12, C6.11, C6.10,
C6.9, and C6.8. If still oversized, C6.7
is omitted next and the document is rebuilt while retaining C6.6. Only if it
remains oversized does the existing C6.6 omission rule apply.

Missing C6.7 inventory marks `component-license-inventory-bound` and dependent
`scoped-component-license-policy-verified` as unavailable and adds both fixed
unavailable blockers. A malformed,
noncanonical, low-level-mutated, reordered, duplicated, missing, extra, stale,
or non-exact Cargo binding uses the all-`not-evaluated`, sole
`readiness-assessment-unavailable` shape. Neither case changes ordinary build,
publication, transaction/rollback, or the independent C6.3 gate outcome.

### One-hop native runtime path resolution (contract 2.13.0)

C6.8 keeps ordinary build and C6.3 required-evidence semantics unchanged. Its
optional `artifact_evidence.native_runtime_path_resolution` is exact-bound to
the C6.4 native subject wheel member, SHA-256, and every direct dependency
identity:

```json
{
  "kind": "native-runtime-path-resolution-inventory",
  "schema_version": 1,
  "scope": "direct-native-dependencies",
  "authority": "observation-only",
  "complete": false,
  "subject_wheel_member": "pkg/_rextio_native.so",
  "subject_sha256": "…",
  "record_count": 2,
  "records": [
    {
      "dependency_bom_ref": "urn:rextio:native-dep:…",
      "dependency_name": "libfoo.so",
      "dependency_origin": "wheel-candidate",
      "resolution": "wheel-member",
      "mechanism": "elf-origin-rpath",
      "wheel_member": "pkg/lib/libfoo.so",
      "sha256": "…",
      "size": 1234
    },
    {
      "dependency_bom_ref": "urn:rextio:native-dep:…",
      "dependency_name": "libc.so.6",
      "dependency_origin": "unresolved",
      "resolution": "system-logical",
      "mechanism": "elf-system-name",
      "wheel_member": null,
      "sha256": null,
      "size": null
    }
  ]
}
```

`subject_wheel_member` is one canonical non-directory wheel member and exactly
equals the C6.4 `native_runtime_inventory.wheel_member`; `subject_sha256`
likewise exactly equals the C6.4 subject digest. Records use canonical unique
`dependency_bom_ref` order and exactly reproduce
each C6.4 dependency `bom_ref`, name, and origin once. Non-null wheel members
are unique and bind exactly one canonical `WheelEntryRef` by name, SHA-256, and
uncompressed size. The successful format/origin table is closed: Mach-O
`system` uses `system-logical/macho-system`, while `wheel-candidate` uses
`wheel-member/macho-loader-path|macho-rpath`; ELF preserves the existing C6.4
`unresolved` origin for allowlisted system names and observes them as
`system-logical/elf-system-name`, while `wheel-candidate` uses
`wheel-member/elf-origin-rpath`. The generic model retains `unresolved/none`
for closed vocabulary evolution, but a present successful C6.8 evidence record
does not accept that shape.

macOS resolution uses fixed bounded `otool -l`. Only strong
`LC_LOAD_DYLIB` candidates under contained `@loader_path`, or `@rpath` with
usable self `@loader_path`-anchored `LC_RPATH` values, are eligible. Weak,
re-export, upward, executable/inherited/private, traversing, unsupported,
missing, ambiguous, symlinked, or byte-mismatched candidates fail C6.8 closed.
Linux reuses fixed bounded `readelf -W -d`; a non-system safe SONAME requires
one explicit RUNPATH or RPATH whose nonempty segments are strictly `$ORIGIN`
or `${ORIGIN}` anchored and contained. Absolute/empty segments, other
variables, parent traversal, conflicting path tags, alternate loader tags,
ambient loader variables, caches, `ldd`, `ldconfig`, and `dlopen` are excluded.
RPATH and RUNPATH have different real loader precedence/transitivity semantics;
C6.8 records neither as actual selection, only the same static
`elf-origin-rpath` packaged-candidate mechanism.

Candidate files are opened through bounded dirfd/`O_NOFOLLOW` traversal and
hashed from pinned regular-file descriptors. Exact filesystem receipts are
revalidated before evidence return and are never serialized. Directory stamps
strictly above the generated Python root bind device, inode, and mode but allow
size/ctime/mtime churn caused by unrelated ambient siblings. The generated
root and every relative descendant remain exact. Raw inspector output/stderr,
rejected path values, host/temp absolute paths, environment, inode/device
values, and credentials never enter evidence or sidecars.

Unsupported, unavailable, malformed, unsafe, over-bound, or changed C6.8
collection omits C6.8 and its dependent C6.9 graph while retaining C6.7/C6.6
and all earlier evidence. Under current policy version 11 both
`direct-native-path-resolution-bound` and
`bounded-static-native-runtime-graph-bound` become unavailable, with their two
dedicated blockers. A malformed present model still produces the total
all-`not-evaluated`, sole `readiness-assessment-unavailable` shape. At the
provenance ceiling the omission order is C6.15, C6.14, C6.13, C6.12, C6.11, C6.10,
C6.9, C6.8, C6.7, then C6.6. The
independent `native-runtime-resolution-complete`, complete transitive-closure,
and dynamic-loading checks remain blocked. Actual loader selection/environment,
system library bytes, runtime `dlopen`, Windows PE, WASM, runtime-bearing
plugins, complete license/legal policy, signatures, and distribution
authorization remain deferred.

### Bounded static native-runtime graph observation (contract 2.14.0)

C6.9 keeps the C6.2-C6.8 artifact scope, ordinary build result, and C6.3
required-evidence gate unchanged. Its optional
`artifact_evidence.native_runtime_transitive_closure` starts from the exact
C6.4 subject and the complete set of C6.8 direct path-resolution records:

```json
{
  "kind": "native-runtime-transitive-closure-inventory",
  "schema_version": 1,
  "scope": "bounded-static-packaged-native-runtime-graph",
  "authority": "observation-only",
  "complete": false,
  "bounded_graph_observed": true,
  "transitive_closure_complete": false,
  "actual_loader_selection": false,
  "runtime_dlopen": false,
  "format": "elf",
  "architecture": "x86_64",
  "subject_wheel_member": "pkg/_rextio_native.so",
  "subject_sha256": "…",
  "subject_size": 123456,
  "root_node_ref": "urn:rextio:native-runtime-node:…",
  "node_count": 2,
  "edge_count": 1,
  "max_depth_observed": 1,
  "limits": {
    "nodes": 128,
    "edges": 512,
    "depth": 8,
    "candidates_per_dependency": 64,
    "candidate_attempts": 2048,
    "inspector_invocations": 128,
    "inspector_output_bytes": 2097152,
    "serialized_chars": 524288
  },
  "nodes": [
    {
      "node_ref": "urn:rextio:native-runtime-node:…",
      "kind": "wheel-member",
      "format": "elf",
      "name": "_rextio_native.so",
      "wheel_member": "pkg/_rextio_native.so",
      "sha256": "…",
      "size": 123456,
      "terminal": false
    },
    {
      "node_ref": "urn:rextio:native-runtime-node:…",
      "kind": "system-logical",
      "format": "elf",
      "name": "libc.so.6",
      "wheel_member": null,
      "sha256": null,
      "size": null,
      "terminal": true
    }
  ],
  "edges": [
    {
      "source_ref": "urn:rextio:native-runtime-node:…",
      "target_ref": "urn:rextio:native-runtime-node:…",
      "dependency_name": "libc.so.6",
      "mechanism": "elf-system-name"
    }
  ]
}
```

The root node exactly reproduces the C6.4 wheel member, SHA-256, size, format,
and architecture; its outgoing edges exactly reproduce every C6.8 direct
resolution. Every reached packaged node is a canonical non-symlink wheel
member bound to one exact `WheelEntryRef` by SHA-256 and uncompressed size.
Every system dependency is a name-only terminal leaf and never claims system
library bytes. Nodes and edges are unique, canonically ordered, and reachable
from the root. Packaged nodes are content-bound by member/hash/size; system
leaves are deterministically name-bound but byte-unbound. Both forms receive
stable `node_ref` values. Cycles remain visible as edges while each packaged
node is inspected at most once. The root binary basename may use the generated
extension's leading underscore; every dependency node/edge name follows the
closed parser grammar `[A-Za-z0-9][A-Za-z0-9._+-]{0,254}`.

Only exact packaged Mach-O/ELF members are recursively inspected. The object
format and normalized architecture must equal the root; a non-root Mach-O
member must also be `MH_DYLIB`. Child dependencies reuse the same closed C6.8
Mach-O loader-path/self-rpath and Linux ORIGIN RPATH/RUNPATH semantics. Missing,
ambiguous, case-fold/Unicode-normalization-colliding, symlinked,
hardlink/device-inode-aliasing, byte-mismatched, unsafe, or over-bound
candidates omit C6.9. On Linux, an allowlisted system SONAME is rejected as a
logical leaf if any filesystem entry (including a dangling symlink) or
wheel-member basename could shadow it. Multiple static candidates are never ranked as if
Rextio knew the real loader choice. Recursive ELF output must satisfy both the
C6.8 path parser and C6.4's strict closed `readelf` parser with identical
dependency coverage; malformed, unexpected, or partially parsed rows fail
closed. Every ELF system leaf is rechecked against the target triple's exact
C6.4 allowlist during `ArtifactEvidence` cross-binding.

All recursive inspection uses immutable private snapshots, fixed absolute
inspectors, a minimal deterministic environment, bounded output, no shell, and
one cooperative total deadline clamped to at most ten seconds. Synchronous
filesystem reads are checked before and after and cannot yield accepted evidence
after that deadline, but an in-flight read is not preempted. Final private filesystem
receipts for every packaged node are revalidated before evidence return. Raw
tool output, absolute paths, rejected names, environment values, inode/device
values, and credentials never serialize.

C6.9 is optional and noninterfering. A C6.9-only collection or final receipt
failure omits only this graph and retains C6.8. A C6.8 final receipt failure
omits both because the graph cannot outlive its root resolution. Policy version
5 then marks only `bounded-static-native-runtime-graph-bound` unavailable when
C6.8 remains present and appends
`bounded-static-native-runtime-graph-unavailable`; malformed present graph
models use the all-`not-evaluated`, sole `readiness-assessment-unavailable`
shape. Provenance records both observation presence and the exact graph when
present; the current ceiling omits C6.15 first, then C6.14, C6.13, C6.12, C6.11,
C6.10, C6.9, C6.8, C6.7, and C6.6.

Because each C6.9 private snapshot directory is created and removed below the
generated Python root, that safe lifecycle changes directory stamps captured
by C6.8. Immediately after every C6.9 attempt—even one returning no graph after
partial work—the producer read-only refreshes C6.8 packaged receipts only when
the prior receipts exactly cover every packaged record. File identity and all
generated-root descendants remain exact. Ambient ancestors above that root
retain exact device/inode/mode while allowing unrelated size/ctime/mtime churn;
only this bounded C6.9 refresh additionally allows the generated root's own
size/ctime/mtime delta while keeping its device, inode, and mode fixed. Refresh
creates no snapshot and performs no mutation; failure omits C6.8 and the
dependent C6.9 graph. Snapshot cleanup securely unlinks the exact held file,
verifies/rmdirs the held directory link, and confirms absence through the pinned
root. Any cleanup failure fails closed without replacing an already active
inspection exception.

Even a valid graph keeps `native-runtime-transitive-closure-complete` blocked.
C6.9 does not observe actual loader selection or environment/cache precedence,
system-library bytes, weak/optional or dynamically loaded dependencies,
runtime `dlopen`, Windows PE, runtime-bearing plugins, WASM, signatures, or a
complete loader-faithful closure. It grants no distribution authority.

### Scoped source-transformation replay verification (contract 2.15.0)

C6.10 keeps the C6.2-C6.9 artifact scope, ordinary build result, and C6.3
required-evidence gate unchanged. Its optional
`artifact_evidence.source_transformation_verification` is a sibling of, and
requires, the exact C6.6 inventory. The sole initial scope is
`project-functions-pyo3-plugin-free-v1`: one nonempty complete accepted closure
of project-owned module-level direct-native functions for an ordinary
CPython/PyO3 host-extension wheel. Plugins, embedded helpers, native top-level
segments, runtime-semantics shims, delegated fallback calls, Python boundary
calls, external source, additional artifact profiles, Nuitka, WASM, and Windows
are excluded.

The fixed envelope is:

```json
{
  "kind": "source-transformation-verification",
  "schema_version": 1,
  "scope": "project-functions-pyo3-plugin-free-v1",
  "authority": "observation-only",
  "complete": false,
  "complete_for_scope": true,
  "global_provenance_complete": false,
  "scoped_verification": true,
  "plugin_free": true,
  "full_accepted_function_closure": true,
  "source_transformation_inventory_sha256": "…",
  "source_input_set_sha256": "…",
  "module_ir_sha256": "…",
  "function_count": 1,
  "function_qualnames": ["demo.math.add"],
  "source_input_count": 1,
  "source_inputs": [
    {
      "logical_path": "src/demo/math.py",
      "sha256": "…",
      "size": 42,
      "role": "project-python-source"
    }
  ],
  "generated_rust": {
    "logical_path": ".rextio/generated/rust/src/lib.rs",
    "sha256": "…",
    "size": 1234,
    "role": "generated-rust-input"
  },
  "regenerated_rust_sha256": "…",
  "regenerated_rust_size": 1234,
  "generator_backend": "rextio-core-rust-pyo3-v1"
}
```

Collection securely reopens the lexical project root and each project-source
and generated-Rust path through component-by-component dirfd traversal with
`O_NOFOLLOW`. The producer rejects symlinked roots/components, hardlinks,
path escape, nonregular files, size overflow, and file/directory identity or
timestamp drift. Source is decoded as UTF-8 and parsed without import or
execution. For every accepted function the collector independently rederives
the module-level qualname, half-open UTF-8 AST range, and semantic AST identity
and requires exact agreement with both the build analysis and C6.6 record.

The producer then reanalyzes the complete project with automatic native intent,
no active plugin registry, no embedding, no native top-level, and no delegated
fallback. It requires the same complete accepted-function identity set, lowers
the canonical ModuleIR, rejects runtime/plugin/boundary/embedded IR flags, and
regenerates the full Rust module with empty plugin and boundary bindings. The
regenerated `src/lib.rs` bytes, SHA-256, and size must exactly equal the captured
generated-Rust input. Source and generated receipts are reopened once more
after replay. The receipt binds SHA-256 of canonical compact JSON for the exact
C6.6 inventory, exact sorted project-source input set, and canonical ModuleIR,
plus the sorted accepted qualnames and the captured/regenerated Rust identity.

Unsigned in-toto provenance exposes
`buildDefinition.internalParameters.scoped_source_transformation_verified`,
keeps `source_transformation_provenance_complete: false`, records
`runDetails.metadata.rextio:source_transformation_verification_observed`, and,
when present, carries the exact receipt under
`runDetails.metadata.rextio:source_transformation_verification`. No source bytes,
AST dump, absolute path, inode/device value, exception text, environment value,
credential, or unbounded output is serialized.

Unsupported scope, replay mismatch, race, or bound exhaustion omits only C6.10
and current policy version 11 marks `scoped-source-transformation-verified` unavailable
with `scoped-source-transformation-verification-unavailable`. C6.6 and the C6.3
gate retain their independent outcomes. A malformed present receipt or broken
inventory/source/generated cross-binding uses the total all-`not-evaluated`,
sole `readiness-assessment-unavailable` shape. At the closed provenance ceiling
the omission order is C6.15, C6.14, C6.13, C6.12, C6.11, C6.10, C6.9, C6.8, C6.7,
then C6.6.

`complete_for_scope: true` is deliberately local. `complete: false`,
`global_provenance_complete: false`, the blocked
`source-transformation-provenance-complete` readiness check, unsigned
attestation, and false distribution authority are invariant.

### Scoped Cargo component-license policy verification (contract 2.16.0)

C6.11 keeps the existing host-extension + CPython-wheel artifact scope,
ordinary build result, and C6.3
required-evidence gate unchanged. Its optional
`artifact_evidence.component_license_policy_verification` requires the exact
C6.7 inventory and at least one reachable registry component. Every registry
record must carry a nonblank `declared-unvalidated` raw license string that is
not an exact or compound unknown sentinel. Values are still not parsed or
normalized as SPDX.

The fixed project-root input is `rextio.cargo-license.lock.json`:

```json
{
  "schema_version": "1",
  "kind": "rextio.cargo-license-policy-lock",
  "scope": "reachable-registry-cargo-license-metadata-v1",
  "policy": "project-owner-exact-license-metadata-v1",
  "component_license_inventory_sha256": "…",
  "registry_components": [
    {
      "bom_ref": "urn:rextio:cargo:…",
      "name": "pyo3",
      "version": "0.23.5",
      "kind": "registry",
      "license_observed": "MIT OR Apache-2.0",
      "license_observation": "declared-unvalidated"
    }
  ],
  "attestation": {
    "attestor": "Acme Engineering",
    "attestor_kind": "organization",
    "attestor_relationship": "organization-owner",
    "decision": "allow",
    "action_scopes": ["local-build", "package", "redistribution"],
    "acknowledgement": "REXTIO_CARGO_LICENSE_POLICY_ACK_V1"
  }
}
```

Top-level and attestation keys are exact. `attestor_kind` / relationship is
exactly `human` / `human-owner` or `organization` /
`organization-owner`. Registry rows must equal the canonical C6.7 registry
subsequence byte-for-string, including surrounding whitespace and order. The
inventory digest covers the full C6.7 model, including the generated path root,
although that root is excluded from the owner allow rows.

The collector uses bounded component-by-component no-follow traversal and an
exact regular single-link file receipt. It rejects root/file identity or stamp
changes, symlinks, hardlinks, directories/FIFOs, empty/oversized or malformed
UTF-8, duplicate JSON keys, nonfinite values, excessive depth, stale digests,
nonexact rows, unknown/missing registry license values, and any noncanonical
attestation. The receipt hashes exact lock bytes separately from canonical
parsed policy JSON. Before final evidence construction the producer recollects
and compares the whole immutable receipt; it never adopts a changed valid lock.

Unsigned provenance sets
`buildDefinition.internalParameters.scoped_component_license_policy_verified`,
keeps `component_license_policy_complete: false`, and records
`runDetails.metadata.rextio:component_license_policy_verification_observed`.
When present it carries the exact receipt under
`runDetails.metadata.rextio:component_license_policy_verification` and adds the
receipt's `lock_file` as one resolved `file:` material with exact SHA-256, size,
and role `cargo-license-policy-lock`. The lock is not added to C6.2 `inputs` or
the CycloneDX SBOM.

Collection failure, final mismatch, material-count pressure caused only by the
lock, or sidecar-ceiling pressure omits C6.11 alone. Under the current producer,
C6.15 is omitted first; the full order is C6.15, C6.14, C6.13, C6.12, C6.11, C6.10,
C6.9, C6.8, C6.7, then C6.6. Dropping C6.7 also drops its
dependent C6.11 receipt/material. Policy version 7 marks the tenth observation
`scoped-component-license-policy-verified` unavailable with
`scoped-component-license-policy-verification-unavailable`. A malformed present
or cross-binding-broken receipt uses the total all-`not-evaluated` fallback.

The receipt explicitly keeps `attestor_identity_verified`,
`license_files_verified`, `legal_approval_verified`,
`global_license_policy_complete`, `complete`, `signed`, and
`distribution_authorized` false. It neither authenticates the claimed owner nor
checks SPDX syntax, license/NOTICE files, obligations, compatibility, legal
approval, signatures, global policy, or distribution authority.

### Scoped project-source license-policy verification (contract 2.17.0)

C6.12 keeps the same bounded host-extension + CPython-wheel scope, ordinary
build outcome, and C6.3 gate semantics. Its optional
`artifact_evidence.project_source_license_policy_verification` exists only
when the exact C6.10 `source_transformation_verification` is present. The sole
initial scope is `project-functions-pyo3-plugin-free-source-license-v1`.

The fixed project-root input is `rextio.source-license.lock.json`. This is the
exact key set and fixed-value shape (the evidence references and digests must
equal the current C6.10 receipt):

```json
{
  "schema_version": "1",
  "kind": "rextio.project-source-license-policy-lock",
  "scope": "project-functions-pyo3-plugin-free-source-license-v1",
  "policy": "project-owner-exact-source-license-declaration-v1",
  "source_transformation_verification_sha256": "…",
  "source_input_set_sha256": "…",
  "project_sources": [
    {
      "logical_path": "src/demo/math.py",
      "sha256": "…",
      "size": 42,
      "role": "project-python-source"
    }
  ],
  "generated_rust": {
    "logical_path": ".rextio/generated/rust/src/lib.rs",
    "sha256": "…",
    "size": 1234,
    "role": "generated-rust-input"
  },
  "license_declarations": {
    "project_sources": "MIT",
    "generated_rust": "MIT"
  },
  "attestation": {
    "attestor": "Acme Engineering",
    "attestor_kind": "organization",
    "attestor_relationship": "organization-owner",
    "decision": "allow",
    "action_scopes": ["local-build", "package", "redistribution"],
    "acknowledgement": "REXTIO_PROJECT_SOURCE_LICENSE_POLICY_ACK_V1"
  }
}
```

The top-level, declaration, and attestation keys are exact. Project-source
references must reproduce the nonempty canonical C6.10 source sequence, and
`generated_rust` must reproduce its exact `src/lib.rs` reference. Each license
declaration is a bounded, nonempty, trimmed, control-free string that must not
be an unknown-license sentinel; it is still not parsed or validated as SPDX.
The attestor pair is exactly `human` / `human-owner` or `organization` /
`organization-owner`.

The bounded strict reader shared with C6.11 pins the full project-root chain,
uses no-follow directory-relative access, accepts one regular single-link
file, and rejects identity/stamp/size drift, symlinks, hardlinks, unsafe file
types, empty/oversized or invalid UTF-8, duplicate keys, nonfinite values,
excessive depth, unknown keys, stale digests, reordered/changed source records,
and a changed generated-Rust reference. The receipt binds both exact lock
bytes and the canonical semantic policy snapshot.

Unsigned provenance sets
`buildDefinition.internalParameters.scoped_project_source_license_policy_verified`,
keeps `project_source_license_policy_complete: false`, records
`runDetails.metadata.rextio:project_source_license_policy_verification_observed`,
and, when present, carries the exact receipt under
`runDetails.metadata.rextio:project_source_license_policy_verification`. Its
lock is one separate resolved `file:` material with role
`project-source-license-policy-lock`; it is not a C6.2 input or CycloneDX SBOM
component.

C6.15 is the first optional provenance payload omitted for count or sidecar-
ceiling pressure and contributes one lock material. C6.14 follows it and adds
no material; C6.13 and then C6.12 follow C6.14, and
provenance is rebuilt
without the omitted observation. Immediately
before final evidence return the producer reruns C6.10 using the same plan,
input snapshot, transformation inventory, and embedding setting, requires full
C6.10 receipt equality, and only then fully recollects C6.12. Any replay,
source, generated-output, or lock mismatch omits only C6.12 and never adopts
changed evidence. The current omission order is C6.15, C6.14, C6.13, C6.12, C6.11,
C6.10, C6.9, C6.8, C6.7, then C6.6.

Policy version 8 adds the eleventh observation
`scoped-project-source-license-policy-verified`. An absent receipt makes only
that observation `unavailable` and adds
`scoped-project-source-license-policy-verification-unavailable` after the
unchanged readiness and earlier observation blockers. A malformed, forged, or
cross-binding-broken present receipt makes every readiness check
`not-evaluated` with the sole blocker `readiness-assessment-unavailable`.

The receipt keeps `attestor_identity_verified`, `spdx_verified`,
`license_files_verified`, `notice_files_verified`, `obligations_verified`,
`license_compatibility_verified`, `source_ownership_verified`,
`generated_output_rights_verified`, `derivative_work_rights_verified`,
`legal_approval_verified`, `global_license_policy_complete`, `complete`,
`signed`, and `distribution_authorized` false. It provides no attestor identity
proof, SPDX validation, license/NOTICE-file verification, obligation or
compatibility analysis, source ownership proof, generated-output or
derivative-work rights proof, legal approval, signing, global license-policy
completion, or distribution authority. Existing readiness blockers remain
blocked. This is not Full C6.

### C6.13 scoped analysis-input verification (contract 2.18.0)

C6.13 adds optional `artifact_evidence.analysis_input_verification` for the
fixed `c6.10-project-source-sibling-stubs-v1` scope. It binds the exact C6.10
replay receipt digest, source-input-set digest, ordered C6.10 source paths, and
one record for every sibling `.pyi`. Each record is exactly `absent` or
`present`. A present record binds the logical stub path, byte SHA-256, size,
and deterministic supported-signature projection/version; its stub reference
is an in-toto `project-python-stub` material. Absent records are metadata
observations and create no material.

The receipt serializes metadata only: raw stub bytes, source text, absolute
roots, and exception text are excluded. Secure immutable byte snapshots are
eligible for evidence. Compatibility snapshots on Windows or platforms that
lack the required secure-open behavior may support conservative analyzer
operation but are explicitly evidence-ineligible. The receipt's
`complete_for_scope: true` means only that the C6.10 sibling-stub scope is
complete; global build-input closure, reproducibility, signing, policy
satisfaction, and distribution authorization remain false or blocked.

Readiness policy version 9 has twelve observations followed by ten readiness
checks. Missing C6.13 makes only `scoped-analysis-inputs-verified`
`unavailable` and adds `scoped-analysis-input-verification-unavailable`.
Malformed, forged, or cross-binding-broken present receipts fail readiness
closed: every check is `not-evaluated` and the sole blocker is
`readiness-assessment-unavailable`. The deterministic resource/sidecar
omission order is C6.13, C6.12, C6.11, C6.10, C6.9, C6.8, C6.7, C6.6;
removing C6.10 also removes dependent C6.12 and C6.13.

### C6.14 artifact-policy coverage inventory (contract 2.19.0)

C6.14 adds optional
`artifact_evidence.artifact_policy_coverage_inventory` schema 1 for the same
`host-extension-wheel-cpython-v1` scope. It is derived only when the exact
C6.9-C6.13 prerequisite chain is present and valid. It partitions components
already observed by C6.2-C6.13; it does not discover a complete artifact
closure. Evidence sidecars and C6.14 itself are excluded.

The inventory uses identity scheme `rextio-artifact-component-v1`, carries an
`observed_component_count` and canonical partition SHA-256, and always emits
these thirteen rows in this order:

| Class id | Identity | License policy | Transformation provenance |
|---|---|---|---|
| `file-input:project-python-source` | `byte-bound` | `scoped-owner-declaration-bound` (C6.12) | `scoped-replay-input-bound` (C6.10) |
| `file-input:present-project-python-stub` | `byte-bound` | `unassessed` | `scoped-analysis-input-projection-bound` (C6.13) |
| `file-input:generated-python-input` | `byte-bound` | `unassessed` | `unassessed` |
| `file-input:generated-rust-lib` | `byte-bound` | `scoped-owner-declaration-bound` (C6.12) | `scoped-replay-output-verified` (C6.10) |
| `file-input:generated-rust-build-input` | `byte-bound` | `unassessed` | `unassessed` |
| `file-input:generated-cargo-lock` | `byte-bound` | `unassessed` | `unassessed` |
| `cargo-component:registry-package` | `declared-checksum-bound` | `scoped-cargo-owner-receipt-bound` (C6.11) | `not-applicable` |
| `cargo-component:path-root-package` | `logical-only` | `unassessed` | `not-applicable` |
| `wheel-entry:packaged-native-runtime-member` | `byte-bound` | `unassessed` | `not-applicable` |
| `native-runtime:logical-system-leaf` | `logical-only` | `unassessed` | `not-applicable` |
| `file-input:policy-lock` | `byte-bound` | `unassessed` | `unassessed` |
| `wheel-output:subject` | `byte-bound` | `unassessed` | `unassessed` |
| `wheel-entry:other` | `byte-bound` | `unassessed` | `unassessed` |

Every row carries its observed count and a class-qualified canonical identity-
set SHA-256. Empty classes remain distinct because the class id is part of the
digest domain. A covered dimension includes the exact prerequisite receipt
kind and canonical receipt SHA-256; an `unassessed` or `not-applicable`
dimension carries neither. C6.11/C6.12 declarations are reported only at
their exact scoped meaning and are not treated as SPDX validation, ownership
proof, legal approval, or global license policy. Likewise, C6.10 replay and
C6.13 signature projection do not complete global transformation provenance
or build-input closure.

The producer deeply reconstructs and cross-binds all prerequisite models,
rejects canonical-path/case aliases and cross-class overlaps, deduplicates the
C6.4 root with C6.9 packaged nodes by exact wheel bytes, and keeps logical
system leaves byte-unbound. Collection is bounded and fail-closed: absence or
failure omits only C6.14 and adds `artifact-policy-coverage-unavailable`; a
malformed present inventory makes the complete readiness assessment
`not-evaluated` with only `readiness-assessment-unavailable`. Policy version 10
adds the thirteenth observation `artifact-policy-coverage-bound`; all ten
global readiness checks stay blocked. `scope_complete`, both global coverage
booleans, `complete`, `signed`, and `distribution_authorized` are always
false.

Unsigned provenance records the exact inventory as metadata and adds no new
material. The current count/sidecar-ceiling omission order is C6.15, C6.14, C6.13,
C6.12, C6.11, C6.10, C6.9, C6.8, C6.7, then C6.6. Removing any prerequisite
also removes dependent C6.14. Ordinary-build and C6.3 gate outcomes are
unchanged.

### C6.15 scoped artifact-class policy verification (contract 2.20.0)

C6.15 adds optional
`artifact_evidence.artifact_class_policy_verification` schema 1 only when an
exact C6.14 inventory is present. The root
`rextio.artifact-policy.lock.json` has fixed kind
`rextio.artifact-class-policy-lock`, scope
`host-extension-wheel-cpython-v1`, and policy
`project-owner-exact-artifact-class-policy-v1`. It binds the canonical SHA-256
of the complete C6.14 serialization, that inventory's partition digest, and
exactly thirteen rows in C6.14 order. Each row nests the full C6.14 coverage
row and adds closed `license_policy_disposition` and
`transformation_provenance_disposition` tokens.

The disposition pair is deterministic rather than owner-selectable. A
receipt-backed license or transformation state must use
`prerequisite-receipt-bound`; it cannot be weakened. Empty unassessed rows use
`not-observed`; a nonempty logical system leaf may use the dedicated license
not-applicable token; C6.14 transformation `not-applicable` stays
not-applicable; remaining nonempty unassessed rows use bounded owner-declared
tokens that explicitly do not verify technical provenance.

The strict bounded policy-lock reader rejects links, ancestor/path swaps,
duplicate keys, non-finite/deep/oversized JSON, wrong primitive types including
JSON booleans in integer fields, and any missing/extra/reordered/stale row or
disposition mismatch. Final collection recollects C6.10-C6.13, re-derives
C6.14, and rereads C6.15, requiring full equality. The C6.15 lock is added
exactly once as provenance
material outside C6.14, so the C6.14 digest is not cyclic. Path aliases against
inputs, present stubs, and prior policy-lock materials fail closed.

Policy version 11 adds the fourteenth observation
`scoped-artifact-class-policy-declaration-bound` and blocker
`scoped-artifact-class-policy-declaration-unavailable`. Absence or collection
failure omits only C6.15; malformed/forged present receipts make all checks
`not-evaluated`. At count or sidecar ceilings C6.15 is removed first, then
C6.14 and the prior order. `complete_for_observed_classes: true` means only the
fixed thirteen declarations were bound. `scope_complete`, global
license/transformation completion, attestor identity, SPDX/files/notices/
obligations/compatibility, ownership/derivative rights, legal approval,
technical provenance, `complete`, `signed`, and `distribution_authorized`
remain false.

### Full C6 and bounded C5.2 hard authority (contracts 2.21.0-2.24.0)

The strict contract is independent from the preview records above. It accepts
only CPython 3.11/PyO3/Cargo host-extension wheels on
`aarch64-apple-darwin` or `x86_64-unknown-linux-gnu`, exactly one
SourceLock-authorized and digest-pinned depth-1 `py3-none-any` external source
wheel, two isolated
reproducibility builds, one configured canonical host support lock, and no
plugins, executable, rust-crate, native-top-level,
embedding, Windows, or recursive dependency promotion.

Host admission also requires a non-editable installed Rextio distribution whose
running version/import origin and complete `rextio/` package tree exactly match
the `rextio/` members of one bounded wheel `RECORD` inventory. Missing, extra, changed, aliased,
symlinked, or hard-linked package files fail closed. Strict installation uses
`pip --no-compile`, and every lifecycle process starts with
`PYTHONDONTWRITEBYTECODE=1` or `python -B` and must observe
`sys.dont_write_bytecode is True`. Both the `rextio/` RECORD-member inventory
and both physical-tree walks reject every `__pycache__` directory, `.pyc` file,
unrecorded directory/member, and entry added between the walks. The cumulative
installed-tree input budget is 256 MiB: declared `rextio/` RECORD-member sizes
are aggregated and rejected before walking, then actual member `stat` sizes and
bounded reads are independently aggregated and rechecked during the walk.
These rules protect evidence integrity in an already-running owner-controlled
process; they are not hostile-process secure boot and do not defend against
hostile same-UID concurrent replacement, a compromised kernel or operating
system, or provide complete time, randomness, scheduling, or CPU
virtualization.

Cargo and rustc must be the verified rustup-selected tools; the project
supplies SHA-256-pinned `Cargo.lock` and vendor-tree inputs, and both builds use
exactly `cargo build --release --locked --offline --frozen`.
Those pins establish the integrity of the exact inputs selected by the owner;
they do not authenticate a Cargo registry, crate publisher, or upstream origin.

The native executor owns exactly one target-linker environment binding. On
macOS arm64 it is `CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER`; on Linux x86_64 it
is `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`. The value is the absolute
path of the linker already captured in `BuildToolchainIdentity` and is verified
again at invocation. `PATH` remains limited to the selected Cargo directory;
caller overrides, missing/different bindings, same-name shadows, and the
inactive target's variable fail closed.

Runtime validation uses the live absolute executor-owned project, build,
`HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, linker, and remap values exactly.
Only the semantic invocation receipt maps executor-owned `HOME`, `CARGO_HOME`,
and `CARGO_TARGET_DIR` below `/rextio/build`, and maps the project/build sides
of the two remap flags to `/rextio/project` and `/rextio/build`, so independently
fresh lifecycle runs compare without leaking host paths. Caller-controlled
environment values remain exact and are never tokenized.

For `aarch64-apple-darwin`, the executor-owned encoded Rust flags additionally
set the exact Mach-O install name `@rpath/lib_rextio_native.dylib`. They do not
override the linker's default, content-derived deterministic `LC_UUID`, because
dyld requires that load command. The Linux flag set is unchanged. The Mach-O
parser may discard that install name only as row zero of a section when the
expected Cargo basename matches and the bounded `otool -D` identity set
independently contains the exact same value. The value in a later row, an
unverified value, or any other `@rpath` self-lookalike fails closed. A real
two-build experiment observed byte-identical unsigned wheel/native/UUID/
signature/`RECORD` bytes, no private quarantine path, and a successful native
import after this normalization. That narrower experiment covered only the
two-build normalization boundary. Separately, the final local real-E2E at `f9eb5e6`
certified the complete three-stage installed-wheel lifecycle on macOS arm64
with CPython 3.11.15 and Cargo 1.93.1: each stage used exactly two distinct
Cargo PIDs, final state was published/authorized, a fresh installation preserved
the external LICENSE/METADATA/RECORD bindings and runtime poison check, and no
bytecode cache appeared. The subsequent 256 MiB installed-input hardening is
unit-tested; evidence for the current `HEAD` on macOS arm64 and Linux x86_64 requires
manual host validation and is not CI-certified.

macOS shared-cache provider resolution has one additional exact singleton for
the direct `/usr/lib/libSystem.B.dylib` root:
`/usr/lib/system/libcommonCrypto.dylib`. The relation is bounded to one hop and
does not authorize the `/usr/lib/system/*` namespace generally. The provider
must be present in the final platform-image snapshot; scoped and global lookup
must yield the same address; and `dladdr` must identify the same exact provider
path. Missing observation, address disagreement, a different provider path, or
an arbitrary descendant fails closed. This preserves the final snapshot's
OS-build binding and does not relax any existing native-runtime authority.
Provider identity probes must leave the final loaded-image snapshot exactly
unchanged, and every later process-local native-runtime authority validation
recollects and compares that snapshot. Any image loaded after the accepted
snapshot taints the process; it cannot mint or retain Full-C6 authority.

Full-C6 Cargo-license ingestion recognizes one exact legacy Cargo spelling:
`MIT/Apache-2.0` is canonicalized semantically to `MIT OR Apache-2.0` for the
license observation and owner-policy template. The captured `Cargo.toml`
payload, SHA-256, size, and Cargo-workspace receipt still bind the unmodified
legacy bytes. No general slash-expression normalization exists; whitespace,
operand reversal, alternate licenses, or any other variant is rejected.

The strict analysis scope separately snapshots the complete bounded,
built-in-filtered project Python file/directory namespace and the one verified
Cargo vendor exclusion. A project `.rextioignore` is forbidden because it is not
build authority. The same process-sealed scope is required by initial analysis,
C5.2 reanalysis, and transformation replay; path/file/directory/content or
temporal drift fails closed. A failure before this authority is established is
stderr-only and must not create a project report or follow a project `.rextio`
symlink.

Contract 2.21.0 introduces the typed primitives: complete frozen owner policy,
build-input/toolchain/runtime/source/supply-chain receipts, preauthorization
evidence, detached-signature receipt, final-output revalidation, final evidence,
sealed distribution authorization, and atomic publication receipt. Constructors
deeply rebuild and cross-bind their inputs; serialized preview evidence or a
previous receipt cannot be deserialized into authority. Rextio accepts a pinned
public key and detached signature only. It never accepts, creates, or retains a
private signing key.

Contract 2.22.0 adds bounded C5.2 and the initial CLI coordinator. A
same-transaction sealed external context binds one fresh project analysis to exact SourceLock-v2 source
bytes, direct final-import scalar call sites, the private reached-function Rust
IR, the runtime guard, and the complete source-wheel member inventory. The
output wheel must retain exactly `Requires-Dist: <distribution>==<version>`.
The installed plan and source archive bind their possibly different `RECORD`
bytes separately (pip may rewrite installed `RECORD`), while shared source,
METADATA, WHEEL, and license members remain byte-identical.

Capability resolution follows the complete project import/re-export graph.
Direct use or laundering through aliases, multi-hop re-exports, or package
initializers of reflective/loader authority such as
`importlib.import_module`, `globals`/`vars`, `sys.modules`, `__builtins__`,
`__dict__`, loader state, or equivalent dynamic namespace access fails closed.
Mutation, value escape, and dynamic call targets are likewise outside the
bounded C5.2 linkage contract.

Contract 2.23.0 closes the public policy handoff. Canonical bootstrap
schema/domain v2 (`rextio.full-c6-owner-policy-bootstrap.v2`) embeds one exact
technical template (`rextio.full-c6-owner-policy-template.v1`): the combined
C6.14+C5.2 partitions/rows, exact transformation set, fresh project/Cargo
internal license observations, independently verified external-wheel license
observation, completion requirements, owner/key identity, and aggregate
digests. Observations bind declared/detected SPDX values, exact license-file
logical path/hash/size, and detector payload/receipt identities, but never infer
legal approval. The bootstrap remains host-path-free and contains no
source/license payload bytes, owner decision, private key, signature, or
distribution authority.

The four public JSON documents are exact-field, canonical-UTF-8 contracts:

| Document | Exact identity and lineage |
| --- | --- |
| Bootstrap request | `kind: "full-c6-owner-policy-completion-request"`, `schema_version: 2`, `domain: "rextio.full-c6-owner-policy-bootstrap.v2"`; `request_sha256` binds the complete payload, including `technical_template_sha256`, `input_aggregate_set_sha256`, target/profile, trusted owner-key digest, completion requirements, and the embedded template. |
| Technical template | `kind: "full-c6-owner-policy-technical-template"`, `schema_version: 1`, `domain: "rextio.full-c6-owner-policy-template.v1"`; `template_sha256` binds both authority partitions, ordered rows, exact transformations/`transformation_set_sha256`, internal/external license observations, and owner-completion requirements. Every `owner_decision` is null and every authority claim is false. |
| Owner completion | `kind: "full-c6-owner-policy-completion"`, `schema_version: 1`, `domain: "rextio.full-c6-owner-policy-completion.v1"`; `completion_sha256` binds `bootstrap_request_sha256`, the exact `accept-exact-observed-transformation-set` decision/digest, closed owner declaration, and canonical per-row `allow` license decisions with exact observation evidence. Private-key/signature/legal-advice/distribution booleans are false. |
| Final policy manifest | `kind: "full-c6-owner-policy-manifest"`, `schema_version: 2`, `domain: "rextio.full-c6-owner-policy-manifest.v2"`; `policy_sha256` and `receipt_digest` bind exact artifact/external partitions, completed rows, transformations, owner declaration, and `bootstrap_request_sha256`. It is still unsigned and non-authorizing. |

Parsers reject missing or extra fields, duplicate keys, non-finite JSON,
boolean-as-integer substitution, noncanonical ordering/encoding, excessive
depth/bytes, stale nested digests, and path/file aliases. Canonical JSON bytes,
not a semantically similar reserialization, are the file identity.

The owner supplies a distinct canonical completion document
(`rextio.full-c6-owner-policy-completion.v1`) that explicitly allows every
license-applicable observed row and accepts the exact transformation-set digest.
The offline command:

```text
rextio policy finalize \
  --bootstrap state/rextio.full-c6-policy.bootstrap.json \
  --completion locks/rextio.full-c6-policy.completion.json \
  --output locks/rextio.full-c6-policy.json
```

atomically creates or exactly reuses canonical manifest schema/domain v2
(`rextio.full-c6-owner-policy-manifest.v2`). The manifest binds
`bootstrap_request_sha256`; finalization neither builds, signs, gives legal
advice, nor authorizes distribution. Signing and publication collection rederive
the entire bootstrap/template from the current graph, reload the manifest, and
require exact partition/row/transformation/internal-license/external-license and
bootstrap-lineage equality before proceeding.

With `--format json`, successful `rextio policy finalize` output has exactly
these top-level fields (the `output` value is the resolved output path):

```json
{
  "status": "full-c6-policy-finalized",
  "bootstrap_request_sha256": "…",
  "completion_sha256": "…",
  "manifest_sha256": "…",
  "size": 1234,
  "created": true,
  "signed": false,
  "distribution_authorized": false,
  "output": "/resolved/output/path"
}
```

#### Host support-lock bootstrap and sandbox receipts (2.24.0)

Before the first strict lifecycle, the owner creates an existing project
directory with exact owner-private mode `0700` and runs:

```text
rextio policy bootstrap-support-lock \
  --project-root . \
  --output authority/rextio.toolchain-support.lock.json \
  --format json
```

The command either creates one canonical, single-link, owner-owned regular
file with mode `0600` or exactly reuses identical canonical bytes. It rejects
linked/aliased parents, an output that overlaps another configured artifact,
changed or noncanonical existing bytes, a different configured path or digest,
and a conflicting concurrent creator. Before opening the output, exact,
ancestor, and descendant lexical aliases are rejected after NFC/case-folded
path-part normalization against every configured artifact path, including
every `imports.packages.*.source_archive` whether or not it exists. It never
edits `rextio.toml`. The owner copies the returned `config` pair into
`[build]`:

```toml
artifact_toolchain_support_lock = "authority/rextio.toolchain-support.lock.json"
artifact_toolchain_support_lock_sha256 = "<raw_sha256 from the command>"
```

Successful JSON has exactly these top-level fields; role arrays are the closed,
target-specific ordered sets and `result` is exactly `created | reused`:

```json
{
  "status": "full-c6-toolchain-support-lock-bootstrapped",
  "result": "created",
  "target": "aarch64-apple-darwin",
  "manifest_roles": ["…"],
  "root_roles": ["…"],
  "raw_sha256": "…",
  "merkle_sha256": "…",
  "config": {
    "artifact_toolchain_support_lock": "authority/rextio.toolchain-support.lock.json",
    "artifact_toolchain_support_lock_sha256": "…"
  },
  "authorizes_build": false,
  "authorizes_distribution": false
}
```

The lock binds the fixed manifest and tree closure to one process-sealed,
path-private support plan. Production separately binds
`toolchain_support_plan_sha256`, `toolchain_support_lock_raw_sha256`, and
`toolchain_support_lock_merkle_sha256`. Linux x86_64 admits its fixed
GNU/Python/Rust support closure and launches Cargo through `bwrap`, a sealed
seccomp filter, the support-locked isolated CPython launcher, and Landlock.
macOS arm64 launches Cargo through `sandbox-exec` and binds the exact full
Xcode developer root, SDK/toolchain trees, required system sandbox profiles,
and captured sealed-system-volume platform anchor. The base profile denies
inherited `file-map-executable` together with mutable/data-volume reads or
writes below `/private/var`, `/private/etc`, `/Library/Preferences`, `/Library`,
`/dev`, `/cores`, and `/System/Volumes/Preboot`; sealed-system executable
admission remains intact. A later generated allow grants
`file-map-executable` plus `process-exec` only for an explicitly bound
`read-execute` path or bound read-write directory capability. A read-only path,
read-write file, or ambient mutable path receives no executable-map authority.

The complete support tree is verified **three** times in each strict
`rextio build` invocation: configured host-input collection performs the first
walk, native-executor entry performs the second, and the executor performs the
third immediately before authority mint. Thus the executor itself performs
exactly two full rewalks, and every owner-policy lifecycle stage repeats this
sequence independently. External, production, internal, and per-build
boundaries perform zero additional full walks; they require the sealed plan,
critical leaves, and exact plan/raw/Merkle digest identity.

Each authoritative `FullC6InvocationReceipt` adds these exact sandbox fields:

| Field | Contract |
| --- | --- |
| `sandbox_engine` | `linux-bwrap-landlock-v1` or `macos-sandbox-exec-v1` for the admitted target |
| `sandbox_plan_sha256` | Path-free semantic execution-plan digest |
| `sandbox_profile_sha256` | Path-tokenized, engine-specific semantic profile digest; equal for both builds and stable across equivalent lifecycle runs |
| `sandbox_seccomp_sha256` | Sealed Linux seccomp-program digest; `null` on macOS |

The raw rendered sandbox profile may contain process-local quarantine/PyO3
paths and is never serialized as a public identity or used as the signed
semantic receipt identity. Both build receipts and equivalent lifecycle runs
must carry an equal semantic profile digest. The strict SBOM/SLSA material set
adds `builder-toolchain-support-plan`,
`builder-toolchain-support-lock-raw`, and
`builder-toolchain-support-lock-merkle`; reconstruction rejects a missing or
changed binding.

One local macOS arm64 collection observed approximately **104,645** support
members and **2.67 GB**, with about **45 seconds** per full verification. This
is a machine-specific observation, not a member/byte/time limit, performance
claim, or CI guarantee. Evidence for the current `HEAD` on macOS arm64 and Linux x86_64
requires `python scripts/validate-full-c6-host.py` on the target host and is not
CI-certified.

The bounded threat model excludes hostile same-UID concurrent replacement,
kernel or operating-system compromise, and complete time, randomness,
scheduling, or CPU virtualization. The support closure and sandbox receipts do
not make a general hermetic-build claim.

Runtime admission in the current contract checks normalized installed
distribution identity, exact version, `RECORD` membership, canonical located
paths, and exact reached-module source size/SHA-256. On macOS/Linux it opens `/`
and walks every distribution-root and source-member path component with
descriptor-relative `openat`, using `O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC` for
directories. The final file open also uses `O_NONBLOCK`; it must be a regular,
single-link file before a bounded read and matching pre/post
device/inode/link/size/mtime/ctime checks. Linked roots or ancestors, symlinks,
hard links, FIFOs, and other special files fail closed without a blocking open.
The guard deliberately never imports or introspects the external dependency
module/callable; signed source analysis has already bound callable
name/qualname/first-line identity.

The final wheel now includes the exact SourceLock wheel's PEP 639 license
payloads. METADATA declares
`License-File: external/<normalized-distribution>/<version>/<relative-path>` and
each byte payload appears under the output `.dist-info/licenses/` tree. The
output contract admits a nonempty, canonical, alias-free set of at most **128**
files and at most 64 MiB total. The frozen real PyO3 dependency graph exercises
108 files (project 1 + Cargo 106 + external 1); 129 files are outside the
profile. Per-file, path-length, ordering, alias, and aggregate-byte bounds remain
independent and fail closed. The
output-license v2 contract/mapping binds SourceLock verification, external
subject/distribution/version, source observation, output path/hash/size, final
METADATA and `RECORD`, subject wheel, policy, SBOM/provenance, and both builds.

#### Detached signature and atomic bundle

The only accepted Ed25519 message is the domain-separated byte string

```text
b"REXTIO-FULL-C6-ED25519-V1\0" + canonical_request_bytes
```

The public-key file contains exactly 32 raw Ed25519 bytes and is independently
SHA-256-pinned. The signature is exactly 64 raw bytes, encoded as canonical
Base64 inside this closed seven-field canonical envelope:

```json
{"algorithm":"ed25519","domain":"rextio.full-c6-detached-signature.v1","kind":"full-c6-detached-signature","manifest_sha256":"<request-bytes-sha256>","public_key_sha256":"<raw-public-key-sha256>","schema_version":1,"signature":"<base64-raw-64-byte-signature>"}
```

The envelope is compact sorted-key UTF-8 JSON with no trailing newline.
Signing only `canonical_request_bytes`, without the prefix and NUL separator,
fails verification. The request is limited to 64 KiB and the envelope to
16 KiB. Rextio receives public verification material only and never accepts a
private key.

The coordinator exposes exactly three lifecycle stages:

1. `bootstrap-required` creates canonical
   `rextio.full-c6-policy.bootstrap.json` v2 as its only lifecycle artifact.
   The strict `check.json` and `build.json` reports are also written. Rextio
   does not turn the bootstrap into owner policy; the owner creates the
   separate completion and runs `rextio policy finalize` before pinning the
   resulting manifest.
2. `signing-required` is possible only after the owner supplies the complete
   canonical policy and pins its SHA-256. Its only lifecycle artifact is
   `rextio.full-c6-final-authorization-request.json`; the strict reports are
   also written. This stage has no gate or publication receipt.
3. `publication-required` requires the externally produced detached signature.
   A new run revalidates the exact request, signature, final output, policy,
   reproducibility, and supply chain before it can mint sealed distribution
   authorization and create the exact atomic bundle under
   `<project>/dist/<wheel-stem>.full-c6`.

The retained state directory is owner-owned with exact mode `0700`. Publication
contains six payload files in this exact role order:

1. the subject wheel;
2. `rextio.cyclonedx.json`;
3. `rextio.slsa-provenance.json`;
4. `rextio.full-c6-evidence.json`;
5. `rextio.full-c6-signature.json`; and
6. `rextio.full-c6-authorization.json`.

The seventh file, `rextio.full-c6-manifest.json`, is the canonical
publication manifest. It has `kind: "full-c6-publication-manifest"`, schema 1,
domain `rextio.full-c6-atomic-publication.v1`, the frozen scope, target triple,
subject/evidence/authorization-request digests, `payload_file_count: 6`, and
six ordered `{role, logical_name, sha256, size}` payload references. The wheel,
CycloneDX, and SLSA files are each limited to 16 MiB; final evidence and sealed
authorization are each limited to 2 MiB; and the signature envelope is limited
to 16 KiB.

A mismatch, alternate destination or name, or pre-commit input/staging mutation
fails closed. An existing or concurrently created destination also fails closed
unless it meets the exact recovery exception below. All temporary host-output
and private-quarantine cleanup completes before the final no-replace directory
rename; that successful rename is the publication commit point. If interruption
occurs after that commit point but before the caller receives its receipt, a
retry may return the same receipt only when the existing target is still an
owner-private mode-`0700` directory containing the exact closed bundle
independently derived for the current verified request. Rextio
opens it without following links, validates the target, safely recaptures every
original payload source and the trusted public-key path against their initial
captures, and then repeats member-byte, directory-descriptor, and name-to-inode
binding validation before accepting it. A different, mutated, unsafe, or
concurrently replaced destination remains a fail-closed collision and is never
overwritten. A later external mutation does not retroactively
invalidate the completed transaction receipt, but the changed bytes no longer
match the receipt or manifest and consumers must treat that mismatching bundle
as invalid.

#### Strict lifecycle report shapes

Each successful strict `build.json` has exactly these top-level keys:
`analysis`, `contract_version`, `distribution_authorized`, `fallback`,
`full_c6`, `lifecycle`, `next_action`, and `status`. The exact `full_c6` keys
depend on the lifecycle:

| Lifecycle | Exact `full_c6` keys |
| --- | --- |
| `bootstrap-required` | `policy_bootstrap`, `production_authority` |
| `signing-required` | `authorization_request`, `production_authority`, `signing_request_receipt` |
| `publication-required` | `authorization_request`, `production_authority`, `signing_request_receipt`, `publication_receipt` |

In 2.24.0, every `production_authority` projection also binds
`toolchain_support_plan_sha256`, `toolchain_support_lock_raw_sha256`,
`toolchain_support_lock_merkle_sha256`, `executor_receipt_sha256`, and exactly
two `executor_invocations`. Each invocation contains the path-free sandbox
fields above; no host support path or raw rendered sandbox profile is
serialized.

A post-analysis lifecycle failure writes `build.json` with exactly
`analysis`, `contract_version`, `distribution_authorized: false`,
`error`, `fallback`, `lifecycle: "failed"`, `stage`, and
`status: "strict-evidence-failed"`. The `error` object has exactly four keys:
`{code, domain, message, reason_code}`. `code` is `RXT060`; `domain` is the
public exception class name; and `message` is the fixed, path-free stage
failure message. `reason_code` is a non-empty lowercase kebab-case member of
the producer's closed 2.24.0 strict-failure vocabulary. That vocabulary is
the static exact-exception registry for production, external-execution,
executor, sandbox, PyO3, toolchain, native-build, macOS/Linux permission, and
Linux-launcher failures; it never contains exception text, paths, or other
host-derived data. The most deeply nested exact registered cause wins. If no
member of the exception chain is registered, `reason_code` is exactly
`production-authority-unclassified`; consumers must treat that value as a
fail-closed unclassified result, not infer details from `domain` or `message`,
and must tolerate newly added kebab-case reason codes within contract major 2.
A scope failure before trusted analysis emits sanitized stderr only and writes
no report, because even the project `.rextio` path is not yet trusted.

Each lifecycle `rextio build` run recollects the current production graph and
performs exactly two actual isolated, offline, frozen Cargo invocations. The
public production projection records `executor_invocation_count: 2`; no earlier
report, receipt, or wheel substitutes for either build. The internal
`FullC6ProductionAuthority` is an immutable, uncopyable, unserializable
process-local evidence seal. Its projection remains unsigned and explicitly
non-authorizing; only the later signature hard gate can mint the separate
publication authorization.

`[build] artifact_distribution_policy = "strict-evidence"` is the only opt-in.
It also requires `artifact_evidence_policy = "required"`, CPython fallback,
Cargo/PyO3, two builds, one exact import declaration/source archive, signed
SourceLock v2 material, SHA-256-pinned Cargo lock/vendor inputs, an owner-policy
manifest path, the paired project-relative
`artifact_toolchain_support_lock` / lowercase raw-SHA-256 pin, a
SHA-256-pinned trusted public key, and the exact signing-request filename. The
owner-policy digest is absent only for bootstrap and mandatory
for signing/publication. The detached signature is produced entirely outside
Rextio and configured only for the publication stage.

This contract ships in 0.1.5 as Experimental/Alpha. Its sealed distribution
authorization applies only to the bounded generated artifact bundle; it is not
Rextio release automation and does not imply broad Full C6, general package
AOT, general hermeticity, CUDA support, or heavy host-lifecycle CI
certification.

This strict chain does not change `artifact_distribution_authorization` below:
that C6.5-C6.15 record remains readiness-only, always blocked, and incapable of
granting authority.

### Preview distribution-authorization readiness (2.10.0-2.20.0; retained in 2.24.0)

C6.5 adds `build.json.artifact_distribution_authorization` only where the same
ordinary host-extension + CPython wheel path emits `artifact_evidence`. It is
derived from a revalidated immutable evidence model after final evidence
handling; required mode derives it only after output revalidation and the
required transaction has committed or rolled back. Out-of-scope artifact sets
omit both the evidence and this assessment.

This record is deliberately **not a gate** and cannot authorize any action.
Contract 2.10.0 emitted policy version 1 with four observation checks; contract
2.11.0 emitted policy version 2 with the fifth C6.6 transformation-inventory
check; 2.12.0 emitted policy version 3 with the sixth C6.7 component-license
inventory check; 2.13.0 emits policy version 4 with the seventh C6.8 direct
path-resolution check; 2.14.0 emits policy version 5 with the eighth C6.9
bounded static runtime-graph check; 2.15.0 emits policy version 6 with the ninth
C6.10 scoped replay-verification check; 2.16.0 emits policy version 7 with the
tenth C6.11 scoped Cargo license-policy check; 2.17.0 emits policy version 8
with the eleventh C6.12 scoped project-source license-policy check; 2.18.0
emits policy version 9 with the twelfth C6.13 scoped analysis-input
verification check; 2.19.0 emits policy version 10 with the thirteenth C6.14
artifact-policy coverage check; 2.20.0 emits policy version 11 with the
fourteenth C6.15 scoped artifact-class policy declaration check. The current fixed envelope is `kind:
"artifact-distribution-authorization"`, both `policy` and `scope` equal
`host-extension-wheel-cpython-v1`, `policy_version: 11`, `status: "blocked"`, and
`authority: "readiness-assessment-only"`. `complete`, `signed`, and
`distribution_authorized` are mandatory and always `false`; no configuration
setting or constructor value can change them. C6.3's required evidence gate
continues to answer only whether bounded preview evidence is present. A
`satisfied` C6.3 gate and a C6.5-C6.15 `blocked` readiness assessment therefore
coexist on a successful required build.

For the retained preview record with `evidence_status: "preview-ready"`, the exact
shape is:

```json
{
  "artifact_distribution_authorization": {
    "kind": "artifact-distribution-authorization",
    "policy": "host-extension-wheel-cpython-v1",
    "policy_version": 11,
    "scope": "host-extension-wheel-cpython-v1",
    "status": "blocked",
    "authority": "readiness-assessment-only",
    "evidence_status": "preview-ready",
    "evidence_reason": null,
    "checks": [
      {"id": "artifact-subject-bound", "status": "satisfied"},
      {"id": "declared-input-snapshot-bound", "status": "satisfied"},
      {"id": "cargo-resolve-graph-bound", "status": "satisfied"},
      {"id": "direct-native-linkage-observed", "status": "satisfied"},
      {"id": "direct-native-path-resolution-bound", "status": "satisfied"},
      {"id": "bounded-static-native-runtime-graph-bound", "status": "satisfied"},
      {"id": "source-transformation-inventory-bound", "status": "satisfied"},
      {"id": "scoped-source-transformation-verified", "status": "satisfied"},
      {"id": "component-license-inventory-bound", "status": "satisfied"},
      {"id": "scoped-component-license-policy-verified", "status": "satisfied"},
      {"id": "scoped-project-source-license-policy-verified", "status": "satisfied"},
      {"id": "scoped-analysis-inputs-verified", "status": "satisfied"},
      {"id": "artifact-policy-coverage-bound", "status": "satisfied"},
      {"id": "scoped-artifact-class-policy-declaration-bound", "status": "satisfied"},
      {"id": "component-license-policy-complete", "status": "blocked"},
      {"id": "native-runtime-resolution-complete", "status": "blocked"},
      {"id": "native-runtime-transitive-closure-complete", "status": "blocked"},
      {"id": "runtime-dynamic-loading-verified", "status": "blocked"},
      {"id": "build-input-closure-complete", "status": "blocked"},
      {"id": "source-transformation-provenance-complete", "status": "blocked"},
      {"id": "builder-toolchain-identity-bound", "status": "blocked"},
      {"id": "reproducibility-verified", "status": "blocked"},
      {"id": "attestation-signed", "status": "blocked"},
      {"id": "sbom-composition-complete", "status": "blocked"}
    ],
    "blockers": [
      "component-license-policy-incomplete",
      "native-runtime-resolution-incomplete",
      "native-runtime-transitive-closure-incomplete",
      "runtime-dynamic-loading-unverified",
      "build-input-closure-incomplete",
      "source-transformation-provenance-incomplete",
      "builder-toolchain-identity-unbound",
      "reproducibility-unverified",
      "attestation-unsigned",
      "sbom-composition-incomplete"
    ],
    "complete": false,
    "signed": false,
    "distribution_authorized": false
  }
}
```

Check IDs, statuses, blocker IDs, coverage, uniqueness, and order are a closed
contract. Unknown, duplicated, reordered, or free-text items are rejected.
Before the fourteen observation statuses become `satisfied`, the producer
reconstructs every nested evidence model and structurally validates the wheel
subject/sidecar relationships, all required declared-input role snapshots, one
bound Cargo path root and its fully reachable package graph, and the exact
direct-native-to-wheel-member target/format/architecture relationship. For the
C6.6 inventory it validates closed model invariants and cross-binds the exact
source and generated-Rust `EvidenceFileRef` values. It does **not** independently
re-derive the recorded module/qualname, range, or semantic-AST hash from source,
`BuildPlan`, code generation, or unsigned provenance. A structurally valid
changed value can therefore retain a `satisfied` status for
`source-transformation-inventory-bound`;
`source-transformation-provenance-complete` remains blocked and the
assessment remains unsigned and non-authorizing. This is model/reference-binding
validation only: the C6.5-C6.15 assessment does not reopen artifacts, re-hash
outputs, or rerun C6.4 inspectors.

For C6.10 the reconstructed evidence must bind the canonical C6.6-inventory
digest, exact full project-source input set and its canonical digest, the same
sorted qualname coverage, a plugin-free fixed backend, and one exact generated
Rust input shared by every C6.6 record. The receipt itself also enforces
regenerated-Rust digest/size equality with that captured input. The readiness
pass does not independently reparse source, recompute ModuleIR, or regenerate
Rust; those operations already occurred in the in-process collector before the
immutable receipt was admitted. The global transformation-provenance check
therefore remains blocked.

For C6.7 the same reconstruction requires exact full coverage and canonical
order against every Cargo package identity and its raw/null metadata value.
This validates only model/reference binding; it does not validate SPDX or make
a component-license policy decision.

For C6.8 reconstruction requires exact direct-dependency coverage, subject
SHA-256 binding, the closed format/origin/result/mechanism table, and exact
unique `WheelEntryRef` hash/size binding for packaged records. This validates
the emitted observation model; it does not reopen candidates or promote the
separate resolution/transitive/dynamic-loading readiness checks.

For C6.9 reconstruction requires exact root binding to C6.4, exact outgoing
root-edge binding to C6.8, canonical and reachable node/edge coverage, the
closed format/mechanism/node-kind table, exact unique `WheelEntryRef` binding
for every packaged node, terminal system leaves, and all serialized graph
bounds. This validates only the emitted bounded model; it does not reopen
members, rerun inspectors, infer actual loader selection, or satisfy the
separate complete-transitive-closure check.

For C6.11 reconstruction requires the canonical full C6.7 inventory digest,
exact sorted coverage of every registry-component `bom_ref`, and the fixed
lock reference, policy, action scopes, acknowledgement, owner relationship,
and safety booleans. The exact lock SHA-256 and size remain provenance material
only while the C6.11 receipt is present. Readiness does not reopen the lock,
authenticate the attestor, parse SPDX, inspect license files, or perform legal
analysis. Consequently a satisfied scoped observation never changes
`component-license-policy-complete` from `blocked` and cannot authorize
distribution.

For C6.12 reconstruction requires the canonical full C6.10 receipt digest,
exact source-input-set digest and ordered `EvidenceFileRef` coverage, the exact
generated `src/lib.rs` reference, fixed lock reference/policy/action
scopes/acknowledgement, closed owner relationship, separate bounded license
declarations, and every false safety/authority claim. The lock SHA-256 and size
remain provenance material only while the receipt is present. Readiness does
not reopen the lock or source/output files, rerun C6.10, authenticate the
attestor, validate SPDX, inspect license or NOTICE files, analyze obligations
or compatibility, prove source ownership or generated-output/derivative-work
rights, perform legal review, sign evidence, complete global policy, or
authorize distribution.

For C6.14 reconstruction requires exactly thirteen canonical, disjoint class
rows derived from the complete present C6.9-C6.13 chain. Counts, class-
qualified identity-set digests, the partition digest, identity strengths, and
the exact applicable C6.10-C6.13 receipt kind/digest bindings must all match
fresh derivation. This validates only the compact observed-component
partition; it neither discovers omitted components nor changes any global
readiness check from `blocked`.

For C6.15 reconstruction requires the exact C6.14 semantic digest and partition
digest, exactly thirteen ordered nested coverage rows, the sole closed
disposition pair permitted for each row's count/states/receipt bindings, the
fixed lock reference/policy/action scopes/acknowledgement and owner
relationship, and every false global/safety/authority claim. Readiness does
not reopen the lock, authenticate the attestor, validate licenses or files,
prove rights, perform legal review, verify technical provenance, sign evidence,
or authorize distribution.

For `evidence_status: "unavailable"`, `evidence_reason` is exactly the existing
fixed `artifact_evidence.reason`; the fourteen observation checks use
`"unavailable"`, the ten downstream readiness checks use `"not-evaluated"`,
and `blockers` is exactly `["evidence-unavailable"]`: unavailable evidence is
14 `unavailable` observations plus 10 `not-evaluated` readiness checks. This
avoids inventing downstream findings and prevents raw errors, tool output,
credentials, or machine-private paths from entering the report.

When preview evidence is otherwise structurally valid but the C6.8 inventory
is absent, the first four mandatory observation checks stay `satisfied`, both
`direct-native-path-resolution-bound` and its dependent
`bounded-static-native-runtime-graph-bound` are `unavailable`, and downstream
readiness checks stay `blocked`. Blockers are the ordinary ten readiness
blockers plus `native-runtime-path-resolution-inventory-unavailable` and
`bounded-static-native-runtime-graph-unavailable`, in that order, followed by
any independent C6.6/C6.10/C6.7/C6.11/C6.12/C6.13 unavailable blockers and the
dependent `artifact-policy-coverage-unavailable` and
`scoped-artifact-class-policy-declaration-unavailable` blockers last. This does not
change either complete-runtime readiness check from blocked.

When C6.8 is present but the C6.9 graph is absent, the first five observations
stay `satisfied`, `bounded-static-native-runtime-graph-bound` alone is
`unavailable`, the independent C6.6/C6.10/C6.7/C6.11/C6.12/C6.13 observations retain
their own states, and dependent C6.14 is `unavailable`. The dedicated
`bounded-static-native-runtime-graph-unavailable` blocker follows the ordinary
ten readiness blockers and precedes any C6.6/C6.10/C6.7/C6.11/C6.12/C6.13 unavailable
blockers; `artifact-policy-coverage-unavailable` remains last. A valid bounded graph still never changes
`native-runtime-transitive-closure-complete` from `blocked`.

When the C6.6 inventory is absent, the first four mandatory observations and
the independent C6.8/C6.9 observations retain their own states,
`source-transformation-inventory-bound`, the dependent
`scoped-source-transformation-verified` (C6.10), and the further dependent
`scoped-project-source-license-policy-verified` and
`scoped-analysis-inputs-verified` plus `artifact-policy-coverage-bound` and
`scoped-artifact-class-policy-declaration-bound` are
`unavailable`, and downstream readiness
checks stay `blocked`. After the ordinary ten readiness blockers, any C6.8/C6.9
unavailable blockers come first, followed by exactly
`source-transformation-inventory-unavailable` and
`scoped-source-transformation-verification-unavailable`, then any C6.7/C6.11
blockers, followed by
`scoped-project-source-license-policy-verification-unavailable` and finally
`scoped-analysis-input-verification-unavailable`, followed by
`artifact-policy-coverage-unavailable`, then
`scoped-artifact-class-policy-declaration-unavailable`.
This dedicated shape is distinct from a malformed,
noncanonical, or
exact-reference-binding-breaking evidence model.

When C6.6 is present but C6.10 is absent, the other nine observations retain
their own `satisfied | unavailable` states. The C6.10 observation,
`scoped-source-transformation-verified`, and its dependent
`scoped-project-source-license-policy-verified` and
`scoped-analysis-inputs-verified` plus `artifact-policy-coverage-bound` and
`scoped-artifact-class-policy-declaration-bound` are
`unavailable`.
`scoped-source-transformation-verification-unavailable` follows any C6.8/C6.9
and C6.6 unavailable blockers but precedes any C6.7/C6.11 blocker; the C6.12
and then C6.13 unavailable blockers follow those later optional blockers. The
C6.14 blocker is followed by the C6.15 blocker. A valid
scoped receipt still never changes
`source-transformation-provenance-complete` from `blocked`.

The C6.7 missing shape is independent of both C6.12 and C6.13: the preceding
eight observations and those two later observations retain their own
`satisfied | unavailable` states, while C6.14/C6.15 and both
`component-license-inventory-bound` and its dependent
`scoped-component-license-policy-verified` are `unavailable`, and the fixed
`component-license-inventory-unavailable` plus
`scoped-component-license-policy-verification-unavailable` blockers follow the
ordinary ten readiness blockers and any C6.8/C6.9/C6.6/C6.10 unavailable
blockers. A valid C6.7 inventory never changes
`component-license-policy-complete` from `blocked`.

When C6.7 is present but C6.11 is absent, the preceding nine observations and
the independent C6.12 and C6.13 observations retain their own
`satisfied | unavailable` states and only
`scoped-component-license-policy-verified` plus dependent C6.14/C6.15 are
`unavailable`. Its dedicated
`scoped-component-license-policy-verification-unavailable` blocker follows C6.7
and earlier observation-unavailable blockers but precedes both the C6.12 and C6.13
unavailable blockers when present; the C6.14 blocker is followed by C6.15. The ordinary ten readiness blockers,
including `component-license-policy-incomplete`, remain unchanged.

When C6.10 is present but C6.12 is absent, the other eleven observations
retain their own `satisfied | unavailable` states and
`scoped-project-source-license-policy-verified` plus dependent C6.14/C6.15 are
`unavailable`; C6.13 retains its independent state. The C6.12 dedicated
`scoped-project-source-license-policy-verification-unavailable` blocker follows
every earlier observation-unavailable blocker and precedes the C6.14/C6.15 blockers. Existing readiness blockers and
all build/C6.3 outcomes remain unchanged.

When C6.13 is absent, the preceding eleven observations retain their own
`satisfied | unavailable` states and both the twelfth observation,
`scoped-analysis-inputs-verified`, and dependent C6.14/C6.15 are `unavailable`. Its dedicated
`scoped-analysis-input-verification-unavailable` blocker is last among the
optional observation-unavailable blockers, after
`scoped-project-source-license-policy-verification-unavailable`; the canonical
optional blocker order remains C6.8, C6.9, C6.6, C6.10, C6.7, C6.11, C6.12,
then C6.13, C6.14, and C6.15 wherever those observations are unavailable.

When all C6.9-C6.13 prerequisites are present but C6.14 is absent, the first
twelve observations retain their own `satisfied | unavailable` states and
both `artifact-policy-coverage-bound` and dependent
`scoped-artifact-class-policy-declaration-bound` are `unavailable`. Their
dedicated blockers appear in that order. When C6.14 is present but C6.15 is
absent, the first thirteen observations retain their states and only the
fourteenth observation is `unavailable`; its dedicated
`scoped-artifact-class-policy-declaration-unavailable` blocker is last.

If an object still says `evidence_status: "preview-ready"` but fails the
stricter structural readiness evaluation, C6.5-C6.15 preserves that evidence status,
sets **every** check to `"not-evaluated"`, keeps `evidence_reason: null`, and
sets `blockers` exactly to `["readiness-assessment-unavailable"]`. Evaluation
is total and exception text never serializes. This fallback is report-only: a
best-effort build still succeeds, and a required build whose independent C6.3
gate is satisfied remains successful with that gate still `satisfied`.

The assessment has no effect on ordinary best-effort build success, required
gate satisfaction/failure, rollback, or artifact publication. Actual loader
selection/environment, transitive native dependency closure, system-library
byte binding, runtime `dlopen` discovery, Windows PE, runtime-bearing plugins,
host executables, Rust-importable crates,
Nuitka/WASM evidence, signatures, and final distribution authorization remain
outside C6.5-C6.15.

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
`ArtifactProfile`, inspect local hardware, resolve/load a device provider, or
claim device support. The draft provider records and the CUDA Driver API inventory
tool (Windows + Linux hosts) are documented in the
[device-provider draft](device-provider.md) and
[CUDA driver validation guide](../testing/cuda-driver-validation.md). Every
draft preflight/probe result has `support_claim: false`.

Tooling contract 2.26 preserves that exact object when no device provider is
configured. When `[target].device_provider` and `device_capability` are both
present, passive configuration introspection instead emits:

```json
{
  "device_provider_contract": {
    "status": "configured",
    "discovery": false,
    "provider_selected": true,
    "selection": {
      "provider_id": "rextio-device-cuda",
      "capability_id": "cuda-linux-x86_64"
    },
    "local_probe_performed": false
  }
}
```

Here `provider_selected: true` means **configured selection only**. The command
does not enumerate or import a provider, validate its manifest/distribution,
run preflight, or claim support. Provider options are absent in both key and
value form; their raw values remain build-only inputs. Generate/build performs
the authoritative selected-provider resolution.

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
  provider build/link hook, CUDA execution, or device support claim through 2.24.0.
  The 2.22.0+ exception is one exact direct-scalar-leaf dependency in the frozen
  strict profile; C5.1 preview alone authorizes no lowering or build.
- No actual loader selection, complete transitive dynamic-library closure,
  system-library byte binding, runtime `dlopen` observation, Windows PE linkage
  inventory or runtime-bearing plugin inventory through 2.24.0. Strict 2.21+
  signatures cover only the frozen profile; C6.8 observes one-hop packaged candidates and C6.9 recursively
  observes only a bounded static packaged graph from the generated macOS/Linux
  extension; neither is loader authority.
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
11. **Release Train C / contract 2.8.0 (unreleased):** add the opt-in required
    evidence policy and immutable gate for the exact single host-extension +
    CPython wheel scope. Fail closed without granting distribution authority;
    keep C6.2 best-effort behavior as the default.
12. **Release Train C / contract 2.9.0 (unreleased):** add C6.4's sanitized
    direct native runtime linkage inventory for macOS `otool -L` and Linux
    `readelf -W -d`, with exact installed-native-to-wheel-member
    identity/hash/size binding, normalized architecture, and closed-allowlist
    dependency records carrying `origin` plus stable `bom_ref`. Preserve
    fixed-reason best-effort unavailability and C6.3 required-mode `RXT060`
    rollback. Do not claim path resolution,
    transitive closure, `dlopen` visibility, Windows/plugin-runtime coverage,
    signatures, completeness, or distribution authority.
13. **Release Train C / contract 2.10.0 (unreleased):** add C6.5's immutable,
    always-blocked `artifact_distribution_authorization` readiness assessment
    for the same bounded host-extension + CPython wheel evidence path. Keep a
    closed ordered check/blocker vocabulary, distinguish preview evidence gate
    satisfaction from hard distribution authorization, and preserve all build,
    rollback, and publication semantics. Do not implement the missing runtime
    closure, reproducibility, signature, or final authorization work.
14. **Release Train C / contract 2.11.0 (unreleased):** add C6.6's bounded
    source-transformation inventory observation, policy-version-2 readiness
    check, and dedicated unavailable shape. Bind only accepted project-owned
    functions to existing source/generated inputs; preserve C6.3 and all build,
    rollback, and publication semantics. Do not claim complete transformation
    provenance, signatures, or distribution authorization.
15. **Release Train C / contract 2.12.0 (unreleased):** add C6.7's exact
    reachable-Cargo component-license string observation, policy-version-3
    readiness check, explicit provenance presence metadata, and dedicated
    unavailable shape. Preserve nonblank metadata strings verbatim without
    SPDX/legal/policy claims; omit this newest payload first at the sidecar
    ceiling. Keep component-license policy completion blocked and preserve all
    build/C6.3 outcomes.
16. **Release Train C / contract 2.13.0 (unreleased):** add C6.8's exact
   one-hop direct native path-resolution observation and policy-version-4
   readiness check. Bind only trusted system logical leaves or exact contained
   Mach-O loader-path/self-rpath and ELF ORIGIN RPATH/RUNPATH wheel candidates;
   never claim actual loader selection or transitive closure. Omit C6.8 before
   C6.7/C6.6 at the sidecar ceiling and preserve all build/C6.3 outcomes.
17. **Release Train C / contract 2.14.0 (unreleased):** add C6.9's deterministic,
   cycle-safe bounded static graph rooted in C6.4/C6.8. Recursively inspect only
   exact contained Mach-O/ELF wheel members, retain system names as terminal
   logical leaves, enforce closed graph/inspection/deadline/serialization
   bounds, and add the policy-version-5 observation/unavailable shape. Preserve
   C6.8 on C6.9-only failure, omit both when C6.8 fails, and use provenance
   omission order C6.9 → C6.8 → C6.7 → C6.6. Keep complete closure, actual
   loader selection, runtime `dlopen`, signatures, and authorization blocked.
18. **Release Train C / contract 2.15.0 (unreleased):** add C6.10's immutable
   scoped replay receipt for one nonempty project-owned, plugin-free,
   module-level PyO3 function closure. Securely reread the exact source/input
   set, rederive AST identities and UTF-8 ranges, relower the complete accepted
   set, and require byte-identical full `src/lib.rs` regeneration. Add the
   policy-version-6 observation/unavailable shape and omit C6.10 first at the
   provenance ceiling. Keep global transformation provenance, signatures, and
   authorization blocked.
19. **Release Train C / contract 2.16.0 (unreleased):** add C6.11's immutable
   scoped Cargo component-license policy receipt for one exact project-owner
   lock. Bind the canonical full C6.7 digest, every raw registry row and
   `bom_ref`, exact lock bytes, and fixed allow scopes/acknowledgement. Add the
   policy-version-7 observation/unavailable shape and omit C6.11 before all
   earlier additive observations at the provenance ceiling. Keep SPDX,
   license-file, attestor-identity, legal, signature, global-policy, and
   distribution authorization claims false.
20. **Release Train C / contract 2.17.0 (unreleased):** add C6.12's immutable
   project-source license-policy receipt for one exact present C6.10 replay.
   Bind the canonical C6.10 digest, exact project-source set, generated
   `src/lib.rs`, separate source/output declarations, exact lock bytes, and
   fixed owner scopes/acknowledgement. Rerun C6.10 and recollect C6.12 before
   final admission; add the policy-version-8 observation/unavailable shape and
   omit C6.12 before all earlier additive observations. Keep identity, SPDX,
   license/NOTICE, obligation/compatibility, ownership/output-rights, legal,
   signature, global-policy, and distribution-authorization claims false.
21. **Release Train C / contract 2.18.0 (unreleased):** add C6.13's optional,
   scoped analysis-input verification for C6.10 sibling `.pyi` inputs. Bind
   only secure immutable snapshots of present stubs and keep compatibility
   snapshots analyzer-only; preserve independent C6.12 state and the exact
   twelve-observation/ten-readiness-check shape. Do not claim global build-input
   closure, reproducibility, signing, policy satisfaction, or authorization.
22. **Release Train C / contract 2.19.0 (unreleased):** add C6.14's exact
   thirteen-class coverage partition over the already-observed C6.2-C6.13
   universe. Keep identity, scoped license receipt, and transformation/input
   provenance states orthogonal and all global/signature/authority claims false.
23. **Release Train C / contract 2.20.0 (unreleased):** add C6.15's strict
   artifact-class policy lock bound to the complete C6.14 partition and closed
   per-class dispositions. Preserve prerequisite receipt bindings and keep the
   ordinary preview readiness record always blocked and non-authorizing.
24. **Release Train C / contract 2.21.0 (unreleased):** add the separate frozen
   Full-C6 primitive chain: two-build reproducibility, complete typed inputs and
   supply-chain receipts, external detached-signature verification, sealed
   publication authorization, and create-if-absent atomic bundle publication.
25. **Release Train C / contract 2.22.0 (unreleased):** add one-package C5.2
   direct typed scalar leaf linkage, private external Rust IR, exact
   `Requires-Dist`/runtime identity contract, and initial three-stage CLI
   coordination. Keep plugins, executables, crates, top level, embedding,
   Windows, recursion, and general package promotion out of scope.
26. **Release Train C / contract 2.23.0 (unreleased):** replace the initial
   policy bootstrap with exact technical-template/bootstrap v2, require a
   separate explicit owner completion and offline `rextio policy finalize`, and
   bind final manifest/policy v2 back to fresh production recollection. Seal the
   strict Python namespace, retain stderr-only preanalysis failure, avoid all
   external module/callable import or introspection in the runtime guard, verify
   source bytes descriptor-relatively, and carry exact external PEP 639 license
   payloads into the final wheel. Preserve two actual isolated builds per
   lifecycle and process-local-only production evidence authority.
27. **0.1.5 / Release Train C / contract 2.24.0 (published 2026-07-23):** add the public
   non-authorizing support-lock bootstrap and exact config pair, fixed
   platform support closure, production Linux/macOS sandbox execution, and
   path-free semantic sandbox/support receipt bindings in executor,
   production, SBOM, and SLSA surfaces. Verify the full support tree once at
   host collection and twice inside the executor; preserve the narrow Alpha
   scope and make no general hermetic-build claim.
28. Promote the contract to stable once rextio-agent-skill and rextio-lsp have
   consumed it across one release cycle without breaking changes.
