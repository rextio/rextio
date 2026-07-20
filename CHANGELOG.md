# Changelog

## Unreleased — Release Train C

**Experimental branch work; not tagged or published to PyPI.** The latest
published package remains Rextio **0.1.4** with plugin API **1.3** and tooling
contract **2.2.0**. This branch advances the unreleased producer to plugin API
**1.4** and tooling contract **2.12.0** (package version stays **0.1.4**). Prior
Train C host-planning work remains under the same unreleased line. Unreleased
feature PRs target the `0.1.5` integration branch; `main` stays at the published
0.1.4 commit until the final authorized release PR.

### C6.7 reachable Cargo component-license observation

- Add immutable `artifact_evidence.component_license_inventory` with exact
  coverage of every reachable `cargo_package`, including the generated path
  root, in canonical `bom_ref` order. Each record binds only package identity,
  kind, the bounded Cargo metadata license string or null, and the closed
  `declared-unvalidated | missing` observation.
- Treat null and whitespace-only metadata as missing. Preserve every other
  string verbatim (including surrounding whitespace) while rejecting control
  characters and fixed per-string/count/serialized-size bounds. Do not parse or
  normalize SPDX, classify sentinel/compound strings, read license files, make
  owner allow/deny decisions, change SourceLock, or claim legal approval.
- Advance the always-blocked readiness assessment to `policy_version: 3` and
  add `component-license-inventory-bound`. Missing inventory makes only that
  observation unavailable with the fixed
  `component-license-inventory-unavailable` blocker; malformed, reordered,
  duplicated, stale, extra, omitted, or non-exactly-bound models retain the
  all-`not-evaluated` `readiness-assessment-unavailable` shape.
- Emit the inventory in `build.json` and unsigned provenance with explicit
  observation-presence metadata. Under the closed sidecar ceiling, omit C6.7
  first and preserve C6.6 whenever possible; only then apply the existing C6.6
  omission rule. Ordinary build and C6.3 gate outcomes are unchanged.
- Keep package version **0.1.4** and plugin API **1.4**. Advance only the
  unreleased tooling contract to **2.12.0**. The existing
  `component-license-policy-complete` check and blocker remain blocked, and all
  completeness/signature/distribution-authority fields remain false.

### C6.6 bounded source-transformation provenance observation

- Add immutable `artifact_evidence.source_transformation_inventory` for the
  existing ordinary host-extension + CPython wheel evidence scope. Every
  accepted project-owned native function is bound to one project-relative
  source path and exact source SHA-256, module/qualname, reliable half-open
  source range, SHA-256 of the analyzer's semantic AST identity, the exact
  generated Rust `src/lib.rs` input path/hash/size, the closed
  `rextio-core-rust-pyo3-v1` generator/backend id, and sorted unique plugin ids.
- Serialize the same bounded observation into unsigned provenance metadata
  without binding the provenance sidecar back into the inventory. Never emit
  raw source, AST dumps, absolute paths, exception text, credentials, or
  unbounded output. Cross-check the exact ordered accepted-function coverage
  against the analyzer list used by code generation; reject malformed
  hashes/ranges/paths, duplicates, noncanonical order, stale/omitted/extra
  functions, and orphan, ambiguous, external-source bindings. Cap records,
  total plugin references, unique plugin ids, and deterministic serialized
  inventory size.
- Advance the always-blocked authorization assessment to `policy_version: 2`
  and add `source-transformation-inventory-bound`. A valid inventory may satisfy
  that observation, but `source-transformation-provenance-complete` and its
  blocker remain blocked; completeness, signatures, and distribution authority
  remain false. Do not claim component-license policy completion.
- Preserve independent build and C6.3 semantics. Missing/unsupported inventory
  uses the fixed `source-transformation-inventory-unavailable` observation and
  blocker without changing best-effort success or required-evidence
  transaction/publication outcomes. If adding the inventory would exceed the
  provenance sidecar ceiling, rebuild the provenance with only that observation
  omitted. Malformed, noncanonical, or source/generated-binding-breaking
  inventory retains the total all-`not-evaluated`
  `readiness-assessment-unavailable` shape. The evaluator does not independently
  re-derive structurally valid observation values from source or `BuildPlan`.
- Keep package version **0.1.4** and plugin API **1.4**; advance only the
  unreleased tooling contract to **2.11.0**. Validated license policy, runtime path/transitive
  closure, `dlopen`, signatures, executables, Rust crates, Nuitka/WASM/Windows,
  runtime-bearing plugins, full C6, and C5.2 remain out of scope.

### C6.5 hard distribution-authorization readiness contract

- Add top-level `build.json.artifact_distribution_authorization` for the same
  bounded ordinary host-extension + CPython wheel path that emits
  `artifact_evidence`. The immutable assessment is derived only from the final
  validated evidence record, after required-mode evidence revalidation and
  output transaction handling.
- Keep the assessment unconditionally `status: "blocked"` with
  `authority: "readiness-assessment-only"`, `complete: false`, `signed: false`,
  and `distribution_authorized: false`. No configuration or constructor input
  can promote it, and ordinary build success plus the C6.3 preview-evidence
  gate retain their existing semantics.
- Use a closed, canonical check/blocker vocabulary and order. Preview-ready
  evidence satisfies only subject, declared-input snapshot, reachable Cargo
  graph, and direct-native-linkage observations; fixed blockers identify the
  remaining license policy, native-runtime resolution/transitive closure,
  runtime dynamic loading, complete build-input closure, source-transformation
  provenance, builder identity, reproducibility, signature, and SBOM-composition
  gaps. Unavailable evidence
  carries only `evidence-unavailable` plus its existing sanitized fixed reason,
  without raw paths/errors or speculative downstream blockers.
- Make readiness evaluation total and report-only. It deeply reconstructs the
  nested evidence models and validates structural/model bindings without
  reopening output files or re-inspecting bytes. If a preview model fails that
  stricter validation, the build and C6.3 gate keep their prior outcome while
  all readiness checks become `not-evaluated` and the sole closed blocker is
  `readiness-assessment-unavailable`; exception text is never serialized.
- Keep dependency path resolution, transitive native closure, runtime
  `dlopen`, Windows PE, runtime-bearing plugins, host executables, Rust crates,
  Nuitka/WASM evidence, signatures, and final distribution authorization out
  of scope. Package version remains **0.1.4**, plugin API remains **1.4**, and
  the additive tooling contract advances to **2.10.0**.

### C6.4 direct native runtime linkage inventory preview

- Extend `artifact_evidence` for an otherwise preview-ready ordinary
  host-extension + CPython wheel with a sanitized inventory of directly
  observed dynamic linkage only: macOS Mach-O uses bounded `otool -L`, and
  Linux ELF uses bounded `readelf -W -d`. Inspector children run reviewed
  absolute system tools without a shell or inherited parent environment, using
  only a minimal C locale, short timeout, and capped output; tool paths, raw
  output, and machine-private absolute paths are never serialized.
- Bind the inspected, contained installed native extension to one exact wheel
  member by generated-Python relative identity, SHA-256, and byte size, and
  create one private same-byte snapshot bound to both. Binary-header and
  `otool`/`readelf` inspection read only that snapshot; original and snapshot
  identity/digest are revalidated before evidence is accepted. Architecture,
  binary format, ambiguous search paths, unexpected loading tags, unsafe names,
  count/size bounds, and mutation mismatches fail closed to a fixed sanitized
  reason.
- Record the direct native-binary-to-dependency edges in the incomplete
  CycloneDX preview and the corresponding sanitized observation in provenance.
  This is not dependency path resolution, a transitive dylib closure, runtime
  `dlopen` discovery, or a claim that observed dependencies were build inputs.
- Record the normalized binary-header architecture. Each accepted dependency
  carries `origin = system | unresolved` and a deterministic, path-free
  `bom_ref`. Apply a closed expected-runtime allowlist: Mach-O admits only
  `/usr/lib` and `/System/Library` install roots (serialized as basenames), and
  rejects other Mach-O path forms as unsafe; ELF rejects arbitrary `NEEDED`
  libraries with the fixed allowlist reason
  `native-runtime-unexpected-dependency`.
- Treat the first `otool -L` row as an ignorable private Cargo self-ID only when
  the private snapshot is an `MH_DYLIB` and a separate bounded `otool -D`
  observation exactly matches that row. Otherwise the row remains a dependency
  and normal closed-allowlist validation applies.
- Preserve policy semantics: `best-effort` keeps a successful wheel but reports
  evidence `unavailable`; `required` emits `RXT060` and transactionally rolls
  back this run's exact wheel and sidecars. Required wheels are built in a
  private transaction directory and published only by a create-if-absent hard
  link carrying an exact receipt; an observed public file is never claimed as
  this run's output. Rollback atomically moves a candidate into private
  quarantine before checking its receipt, so a concurrent replacement is
  restored or retained for recovery rather than deleted. Pre-existing-output
  preservation is write-ahead recorded before rename. A receipt/content
  mismatch fails publication closed and reports incomplete rollback. Success
  remains
  `composition: incomplete`, `signed: false`, and
  `distribution_authorized: false`.
- Windows PE, runtime-bearing plugins, host executables, Rust-importable crates,
  Nuitka/WASM paths, signatures, and path/transitive dependency resolution are
  outside C6.4. Package version remains **0.1.4**, plugin API remains **1.4**,
  and tooling contract advances additively to **2.9.0**.

### C6.3 opt-in required artifact-evidence gate

- Add `[build] artifact_evidence_policy = "best-effort" | "required"`,
  `--artifact-evidence-policy`, and `REXTIO_ARTIFACT_EVIDENCE_POLICY` with the
  normal CLI > environment > TOML > default precedence. `best-effort` remains
  the default and preserves C6.2 behavior.
- `required` accepts only one native host-extension + CPython wheel backed by
  an accepted native region (a function and/or native top-level segment), with
  no executable, Rust-importable crate, or additional artifact profile. Other
  artifact sets fail before external toolchain work with `RXT060`, status
  `artifact-evidence-required-failed`, and reason
  `artifact-set-out-of-scope`.
- Required builds succeed only for `artifact_evidence.status =
  "preview-ready"`. Unavailable evidence fails closed, removes only this run's
  exact wheel/sidecars while preserving pre-existing outputs, and retains
  generated source and reports for debugging. The output transaction rejects
  symlinked parents, pins parent identity, verifies exact ownership/content
  receipts, restores on exceptional exits, preserves concurrently replaced
  content, and reports an incomplete rollback explicitly instead of claiming
  cleanup succeeded.
- Add immutable `artifact_evidence_gate` only in required mode. A satisfied
  gate still reports `distribution_authorized: false`, `complete: false`, and
  `signed: false`; C6.2 remains preview-only and is not full distribution
  authorization. Tooling contract **2.8.0** (additive minor).

### C6.2 bounded host-extension wheel artifact-evidence preview

This is **not** full C6 completion. The preview is incomplete and unsigned
(`authority: evidence-only`). It does not claim reproducibility, hermeticity,
completeness, recursive package inventory, signatures, or external-source
authorization. C6.2 itself had no native dylib/runtime inventory; C6.4 adds only
the bounded direct observation described above. Host-executable, rust-crate,
host-extension+Nuitka, WASM, and external-package source-native builds omit
the field.

- In-scope host-extension+`cpython` wheels always write
  `build.json.artifact_evidence` as `preview-ready` or `unavailable` with a
  sanitized fixed reason. Evidence unavailability never changes ordinary build
  success or suppresses `build.json`.
- Snapshot project/generated inputs before native compile; re-verify at evidence
  time. Concurrent mutation → `unavailable`, never a false claim. No silent
  skip of unreadable inputs or truncation at count limits.
- Bounded final-wheel ZIP inventory without extraction (path/dup/encrypt/
  symlink/zip-bomb bounds) included in incomplete CycloneDX output.
- Reachable Cargo resolve graph only (`resolve.root`/`nodes`); only the
  generated root may be path/source-less; reject other path and all git
  packages; registry packages require lock checksums; streaming metadata output
  is hard-capped (process group terminated on overflow).
- CycloneDX: primary component only in `metadata.component`; real wheel version;
  top-level `dependencies`. Provenance: wheel+SBOM as subjects; SBOM is not a
  resolvedDependency; no wheel-hash `invocationId`.
- Tooling contract **2.7.0** (additive minor).

### C6.1 bounded prebuild authorization-contract preview

This is **not** full C6 completion. Full/signed authorization beyond the
project SourceLock prebuild contract, and C5.2 source-native implementation,
remain pending. C6.2 wheel evidence is a separate host-extension path and
does not authorize external-source packaging.

- Extend C5.1 plans with verified byte sizes only on `AuthorityFile` entries
  (not the shared host `SourceModule` wire shape). Bind RECORD, METADATA,
  WHEEL, and every PEP 639 `License-File` under
  `<dist-info>/licenses/<value>` (Metadata ≥ 2.4; reject backslashes; reject
  License-Expression+License). Reject missing/blank/UNKNOWN licenses before
  preview-ready. Enforce module/file/size bounds so every preview-ready plan
  can fit a valid 256 KiB SourceLock.
- Publish `plan_snapshot`, `plan_snapshot_sha256`, and shared
  `license_material_sha256` in check/generate JSON so projects can author
  locks without internal helpers or local paths.
- Project-owned `rextio.external-source.lock.json` binds exact identity,
  path/hash/size/**role**, custom `source_inventory` (not full SPDX/CycloneDX),
  provenance (`subject_snapshot_sha256`, exact ordered evidence, closed
  relationship→attestor_kind matrix), and closed license attestation
  (`decision: allow`, fixed scopes, exact ack constant). Rextio validates
  structure/binding only — never legality. Project/VCS review is the trust
  boundary (no signature).
- Safe lock I/O: single-descriptor open/fstat/read with no-follow and
  nonblocking where supported; reject symlink/FIFO/non-regular/oversized
  locks. Strict JSON rejects duplicate keys, NaN/Infinity, excessive depth,
  and never echoes attacker-controlled key names.
- Authorization nested only under `external_source_plan.authorization`.
  Verified still stops with `external-source-c5-not-implemented` and never
  opens a build path.

### C5.1 external pure-Python source inventory/gate preview

- Add a config-only preview for exactly one imported external package declared
  with `policy = "try-native"`, `max_depth = 1`, and exact `distribution` plus
  `version` fields. Existing `try-native` declarations without the exact pair
  remain metadata-only; CLI/environment policy overrides cannot activate this
  authority-sensitive path.
- Resolve installed metadata without importing or executing the package. Require
  exact distribution identity/version, one purelib `py3-none-any` WHEEL tag,
  one contained dist-info root, safe unique RECORD paths, and matching SHA-256
  plus size for WHEEL, METADATA, and selected source files. Reject symlinks,
  path escapes, unresolved imports, non-UTF-8/unparseable source, and every
  source module below the direct depth-1 slice.
- Emit only sanitized `external_source_plan` inventory and lexical names of
  fully annotated scalar function candidates. Absolute installation paths and
  source bytes are not serialized, package source is not copied into generated
  fallback output, and no project-call linkage or Rust lowering is claimed.
- Block every build carrying an available or unavailable external-source plan
  before configured CPython/Nuitka/Cargo probes or artifact work. Without a
  verified C6 SourceLock the status is `external-source-c6-blocked`; with a
  verified lock the distinct post-authorization block is
  `external-source-c5-not-implemented`. Programmatic build orchestration fails
  closed as well. Actual packaging, executable/crate output, and redistribution
  remain unavailable until remaining C5.2 source-native work exists.
- Serialize and emit a mandatory warning that dependency source translation can
  create derivative-work or redistribution obligations, especially for
  GNU/copyleft licenses, and that the preview is not legal advice.

### Plugin API 1.4 — standalone artifact capability (fail-closed)

- Bump `PLUGIN_API_VERSION` to **1.4** (same major as 1.1–1.3). Host-extension
  lowering for API 1.1–1.3 providers is unchanged.
- Add the optional `artifact_capability(profile: ArtifactProfile)` hook on a
  **separate** `RextioArtifactCapabilityPlugin` Protocol (not on
  `RextioLoweringPlugin`), so legacy Protocol inheritance does not create a
  callable stub. Concrete-implementation detection ignores Protocol stubs.
  Presence requires `api_version >= 1.4` **and** a lowering provider;
  describe-only providers that declare the hook fail load. Absence is valid and
  means standalone unsupported. The hook is **not** part of the all-or-none
  lowering member set (`type_vocabulary` / `claim` / `lower` /
  `crate_dependencies`).
- Add immutable `PluginArtifactTypeSupport` and `PluginArtifactCapability`
  records covering exact plugin type keys, claim rule ids, and profile-specific
  crate dependencies plus uses/helpers. Validate namespace ownership, membership
  against actual `describe()` rules and `type_vocabulary()` keys, duplicates
  (canonicalized uses/helpers/deps), malformed returns, reserved core crates,
  and conflicting pins. Hook exceptions / invalid returns are `PluginError`
  (CLI `RXT060` with failure evidence; programmatic paths fail-closed).
- Resolve capability **exactly once per exact** `ArtifactProfile` per
  generate/build command via immutable `StandalonePluginContext` (reuse for
  closure, codegen, dependency selection, and JSON — never re-call the hook for
  reporting). A function is standalone-capable only when every claim rule and
  every plugin type it uses is covered: signature keys **plus** claim
  operand/result/receiver types. Never infer support from `PluginType`
  conversion, resident status, host-extension `crate_dependencies()`, uses, or
  helpers.
- `LoweringContext` gains defaulted `backend` (`pyo3` | `standalone-rust`) and
  `artifact_profile` (exact resolved profile on standalone lowers). Host-
  extension construction remains valid without those fields.
- Thread profile-resolved standalone context through rust-crate and
  host-executable codegen: capable plugin functions render with native Rust types
  only (no PyO3 boundary). Codegen defense-in-depth rejects uncovered claim type
  keys and undeclared uses/helpers. Legacy functions without matching capability
  stay excluded transitively.
- Inject only profile-specific exact capability crates from functions **actually
  emitted after transitive exclusion**. Unsupported reachable plugin functions
  block pre-Cargo for native-only executables; unreachable ones do not. Rust
  executable CLI preflight uses the capability-aware exact closure / precomputed
  context so a valid plugin executable is not misclassified as unavailable.
- Capabilities introspection reports additive `artifact_capability_declared`
  presence only (no host probe, no profile-hook execution). Generate/build JSON
  may include resolved `standalone_plugin_capabilities` with deterministic
  per-function decisions (`function_decisions`); rejected/fallback functions
  never appear in `capable_functions`. `lowering_provided` semantics are
  unchanged.

### Host source and artifact planning

- Add immutable `ArtifactProfile`, `SourceModule`/`SourceModuleGraph`, and
  source-ordered `ModuleInitIR` records with deterministic serialization,
  project-relative provenance, source hashes, and fail-closed coherence checks.
- Add a descriptive-only `host_source_plan` to check and build-plan reports.
  A missing source, unavailable initializer, or module/path/hash mismatch makes
  the plan unavailable instead of approximating Python import order.
- Resolve artifact profiles only for outputs actually requested during
  generate/build. `BuildPlan.artifact_profiles` is authoritative; fallback-only
  work does not probe or advertise a host target triple.

### Native executable architecture

- Make the Rust executable fallback strategy explicit and closed:
  `error | python-subprocess | nuitka-sidecar`. Preserve
  `hybrid_runtime = source | nuitka` as a compatibility alias.
- Extend executable closure reports with ordered `module_initializers` and fail
  before external build work when source/initializer authority is unavailable.
- Connect a deliberately narrow initializer-before-main vertical slice:
  exactly one source module, no load-time imports/cycles, same-module
  direct-native entrypoint, and plain single-name assignments to exact scalar
  literals (`bool`, `int`, `float`, `str`). Revalidate the source hash, plan,
  and statement indexes before lowering; run the `() -> None` initializer before
  argv handling and the entrypoint.
- Do not publish initializer values as Rust globals or Python module values.
  Native reads of those values remain blocked; broader top-level semantics are
  deferred.

### Tooling contract 2.7.0 (and prior Train C additions)

- Advance the unreleased producer to **2.7.0** for the C6.2 host-extension
  wheel artifact-evidence preview. Prior **2.6.0** covers the C6.1 authorization-
  contract preview: plan authority material (`source_files`, `metadata_files`,
  `plan_snapshot`, `plan_snapshot_sha256`) plus nested
  `external_source_plan.authorization`. The plan remains non-distributable;
  `c6_gate` is `required` or `authorization-verified`; verified authorization
  still does not grant source-native lowering or packaging.
- Contract **2.4.0** added plugin standalone-capability
  presence/declaration and generate/build resolved per-profile allow/deny
  details, without changing route, native-status, rejection, promotion, or
  `lowering_provided` semantics.
- Contract **2.3.0** (still on this branch history) added `host_source_plan`,
  resolved `artifact_profiles`, closure `module_initializers`, and capabilities
  `artifact_contract` fields.
- Add a non-operational `device_provider_contract` marker and immutable draft
  `manifest()` / `preflight()` records. There is no provider discovery,
  selection, build/link hook, or runtime dispatch; every preflight result has
  `support_claim: false`.
- Add a no-dependency CUDA Driver API inventory probe and Windows/Linux
  validation workflows. On Windows x64 the probe resolves `nvcuda.dll` from
  System32 only; on Linux x86_64/aarch64 it loads arch-split reviewed absolute
  `libcuda.so.1` candidates (specialized WSL2/NVIDIA-container/Jetson mounts
  before generic distro paths), canonicalizes under reviewed system roots with
  a group-/world-writable ancestry provenance guard (`0o022`), distinguishes
  `LIBCUDA_SO_NOT_FOUND` from `LIBCUDA_SO_LOAD_FAILED` without path/`dlerror`
  leakage, and fails closed otherwise. Loose and strict (`--require-device` /
  `REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1`) Linux validation modes are documented;
  ordinary e2e CI runs host `cargo test` on ubuntu/macOS and a loose Linux
  validate plus aarch64 compile-only `cargo check`. Both OS paths share the
  same six-symbol inventory surface, never create a context or launch a kernel,
  and always report `support_claim: false`; this is not CUDA support or
  certification.
- Document the released-versus-unreleased boundary, explicit executable
  fallback, source initializer limitations, device-provider draft, and
  Windows/Linux CUDA inventory validation procedure.

## 0.1.4 — 2026-07-18

**Published release.** Package version `0.1.4` is tagged and published to PyPI
on 2026-07-18, superseding **0.1.3** (2026-07-17). `pip install rextio`
installs 0.1.4. Plugin API stays at **1.3** and the tooling contract advances
to **2.2.0**.

Release Train B completed in strict consumer-first order: **rextio-lsp 0.1.2**
was published before **core 0.1.4**.

### Tooling contract 2.2.0

- Add per-function `marker_kind`, isolated `promotion_assessment` evidence,
  and reliable half-open `source_range` / `name_range` records using 1-based
  lines and 0-based UTF-8 byte columns.
- Preserve failed automatic-promotion probe diagnostics and actionable
  suggestions without adding them to legacy function/project diagnostics,
  build errors, or CLI failure state.
- Serialize explicit exemptions and report unmarked module async functions
  plus direct methods of top-level classes as intentional skipped assessments.
- Keep the legacy meanings of `route`, `native_status`, and
  `rejection_codes` unchanged; expected automatic fallback remains
  `fallback-python` / `not-candidate` with no rejection codes.

## 0.1.3 — 2026-07-17

**Published release.** Package version `0.1.3` is tagged and published to PyPI
on 2026-07-17, superseding **0.1.2** (2026-07-14). Install this historical
release with `pip install rextio==0.1.3`.

Tooling contract advances to **2.1.0** (same major as the **2.0.0** shape
emitted by core 0.1.2; additive producer fields only — dual-map `2.x`
consumers that tolerate unknown keys remain compatible). Plugin API is **1.3**
(additive over 1.1/1.2; API 1.1/1.2 providers keep loading with their legacy
shapes). Plugin API 1.3 remains Experimental.

### Tooling contract 2.1.0 (protocol)

- **Additive producer shape** (minor bump; position semantics unchanged from
  `2.0.0`): `rextio check --format json` / `.rextio/reports/check.json` always
  serializes `modules[].logger_group_targets`, and conditionally serializes
  `plugin_claims[].receiver` and `plugin_claims[].callables` when plugin API
  1.3 method/callable metadata is present. `rextio capabilities` continues to
  embed the same top-level `contract_version`. See
  [docs/specs/tooling-contract.md](docs/specs/tooling-contract.md).

### Analyzer / identity

- Close the class-body ``global`` + assignment-expression rebinding gap in the
  project-wide final-binding authority: a walrus under class-body ``global``
  (assignment RHS, bare expression statement, control-flow conditions, or
  nested function/class/lambda headers evaluated while the class body runs)
  rebinds the module global and invalidates a prior ``FUNCTION`` final binding.
  Nested function/lambda/class *bodies* remain other scopes and do not create
  false module writes; class-body comprehensions with walruses are SyntaxError
  and are skipped safely.

### Plugin API 1.3

- Add plugin-owned opaque resident values and immutable-borrow native chaining,
  with RXT092 fail-closed boundaries when ownership or Python materialization
  cannot be proved.
- Add type-level Rust module support (`PluginType.uses`/`helpers`) so a
  signature-only accepted function (a plugin-typed parameter/return with zero
  claims) emits the `use`/helper items that define its rendered boundary
  conversion or named native type, instead of calling into undefined plugin
  functions/types. Support is collected only from the plugin types that appear
  directly in an accepted function's signature, threaded through
  `RxtPluginType` and the build/type-map path, and merged into the existing
  module collectors: `plugin_uses` is a set deduplicated and sorted at
  emission, while `plugin_helpers` is deduplicated by exact text in first-seen
  insertion order — including against identical `LoweredExpr` support. Empty support
  keeps the exact legacy 1.1/1.2 serialized bytes; non-empty support serializes
  deterministically (so report/cache identity moves) and requires
  `api_version >= 1.3` (rejected for lower-versioned providers).
- Add frozen receiver, structured callable-body/native-symbol, and ordered
  annotation-derived schema metadata for method-oriented plugins. API 1.1/1.2
  providers retain their exact legacy offer and serialization shapes.
- Extend named-keyword `ClaimLiteral` metadata with static `bool` and `str`
  values for API 1.3 providers only. Mixed-version registries project those
  sites exclusively to 1.3 providers; dynamic keyword values, `**kwargs`,
  floats, bytes, and non-int tuples remain fail-closed. A derived literal-kind
  discriminator keeps bool and int cache/equality keys distinct despite
  Python's `True == 1`, while legacy none/int/int-tuple serialization is
  unchanged.
- Thread one project-wide source-order binding/effect/mutation authority through
  analysis, callable metadata, claims, IR, and wrapper planning. Native markers,
  imported/static targets, re-exports, methods, and callable UDFs are accepted
  only when their exact executable identities remain proven.

### Correctness hardening

- Fail closed on source-visible module/class/stdlib/builtin mutation, aliases and
  control-flow joins, executed local mutators, consumed generators, implicit
  protocol hooks, decorator replacement, class construction hooks, descriptors,
  and post-class member replacement/deletion.
- Track exact tuple/list destructuring aliases and package-resolved relative
  re-exports while rejecting starred, mismatched, dynamic, cyclic, or mutated
  paths. Logger receiver/method aliases, `builtins.__build_class__` mutation,
  and module-load operator/attribute/subscript/f-string/comprehension protocol
  effects now also prevent unsafe direct-native promotion.
- Preserve API 1.3 `Frame[Schema]`-style metadata without weakening the new
  protocol-effect gate: only an exact, unmutated annotation target from the
  active validated plugin type vocabulary is trusted in annotation context,
  and that trust set is carried through shared binding, IR, and wrapper source
  revalidation. Shadowed, rebound, mutated, unregistered, or arbitrary
  subscriptions remain fail-closed.
- Revalidate semantic AST fingerprints before lowering or wrapper generation so
  an edit after analysis cannot reuse stale types or plugin claims. Generated
  method wrappers also verify the fallback owner/function identity before
  installation and fail loudly on mismatch.
- Dynamic monkeypatching performed externally after wrapper import remains
  outside this static proof boundary; source-visible mutations are rejected or
  routed through Python fallback.
- Close the follow-up 11 module-execution gaps: loop alias/effect replay now
  reaches a sound fixed point (with conservative widening), logger identity is
  process-global and keyed by exact names, implicit ``__builtins__`` mutations
  enter the builtin authority, and exact imported project mutators are replayed
  with defining-module imports plus positional/keyword/default binding. Unknown
  imported callables, recursive summary cycles, dynamic defaults, and complex
  argument expansion fail closed.
- Close the follow-up 12 execution gaps: project-call replay now selects
  source-order global bindings at circular-import suspension edges and final
  bindings for ordinary calls; narrow exact return summaries preserve root,
  scalar, conditional, default, and logger-factory identities. Generalized
  expression roots cover direct/conditional/container/walrus logger factories
  and module-dict ``__builtins__`` forms, while unknown external callees that
  receive project roots (including container-nested roots), unknown identities,
  or globals fail closed. Source constructors and protocol-dispatching builtins
  are no longer assumed pure without a closed proof; function-local ``vars()``
  remains local rather than being mistaken for module globals.
- Construct fallback/native bindings, factories, function wrappers, and method
  wrappers in one isolated bootstrap scope with ordinal local slots. Terminal
  publication preserves callable user exports of any ``_rextio_*`` spelling;
  native top-level updates cannot overwrite runtime captures before method and
  closure initialization. Correct stale release-candidate wording for the
  published core 0.1.2 and rextio-numpy 0.1.1 releases.
- Close the follow-up 13 identity/effect gaps: builtin and
  ``logging.getLogger`` purity now consult a project-wide fixed-point mutation
  authority; post-definition constructor changes, source-class protocol hooks,
  executed ``nonlocal`` cells, opaque module-scope exposure (including nested
  containers and deferred generators), and structurally unknown callable
  returns widen rather than inventing identities. RXT080 originals live in an
  isolated runtime ordinal registry instead of synthetic fallback/public module
  attributes. Native top-level results are filtered against exact final
  bindings and published only at the terminal wrapper step, so assignment vs
  function/class name collisions follow Python source order.
- Close the follow-up 14 mutation-summary gaps: bounded container summaries
  retain project exposure without flattening roots into invented subscript
  paths, while unsupported or externally mutated shapes widen. Bare
  `id`/`len`/`range`
  aliases preserve their builtin-slot identity across chained and destructured
  assignments, so monkeypatching revokes purity. Opaque calls now recursively
  account for project roots yielded by list/set/dict comprehensions and
  generator expressions; unknown comprehension inputs fail closed while
  closed scalar comprehensions remain clean.
- Close the follow-up 15 mutable-container alias gap: dict/list/set summaries
  now discard exact shape at the first alias, parameter, shared binding, or
  callable return while retaining every exposed project root. Stores, deletes,
  and modeled mutating methods through any resulting alias invalidate all such
  roots (including newly inserted values); nested tuples containing mutable
  members follow the same rule, while immutable tuple/scalar summaries and
  fresh literal direct selection remain precise.

## 0.1.2 — 2026-07-14

**Published release.** Package version `0.1.2` is tagged and published to PyPI
on 2026-07-14, superseding **0.1.1** (2026-07-12). Install this historical
release with `pip install rextio==0.1.2`.

**Release-order gate (tooling contract 2.0; strict sequence):** publish
related packages in this order only — **rextio-lsp 0.1.1** (dual-map contract
majors `{1, 2}`) **first**, then **core 0.1.2**, then **rextio-numpy 0.1.1**
(plugin API 1.2 consumer). Do not ship LSP simultaneously with or after core,
and do not ship rextio-numpy 0.1.1 before core. Core **must not** publish alone
first: a contract-`2.0.0` producer against major-1-only LSP mis-pairs RXT000
columns. See `docs/specs/tooling-contract.md`. Core has no runtime dependency
on `rextio-lsp` or `rextio-numpy`.

### Tooling contract 2.0.0 (protocol)

- **Breaking protocol change:** `contract_version` advances to `2.0.0`.
  `RXT000` (syntax-error) diagnostic `column` is now a **0-based UTF-8 byte
  offset** into the line, matching every other diagnostic and `ast.col_offset`.
  Contract `1.x` (PyPI 0.1.1) left `RXT000.column` as CPython's 1-based Unicode
  code-point `SyntaxError.offset`.
- Major (not minor) so consumers that gate only on major 1 refuse the
  unsupported path instead of silently mis-mapping RXT000. See
  `docs/specs/tooling-contract.md` (positions, compatibility, release
  ordering).

### Plugin API 1.2 (backward-compatible)

- Additive plugin API **1.2** on the same major as 1.1 (API 1.1 plugins keep
  loading). Core advertises `PLUGIN_API_VERSION = "1.2"`.
- **Static literal / ordered keyword metadata** on claim sites
  (`operand_literals`, ordered `keywords`) for version-gated offers to API
  ≥ 1.2 providers. This surface **enables literal-axis claims and lowering**
  (for example `axis=0` keyword literals).
- **Structured `ClaimExpr` trees** so plugins can reason about nested covered
  expressions without seeing core IR.
- **Leaves-mode lowering** (`operand_mode` `direct` | `leaves` with
  `leaf_operands` on `LoweringContext`) **enables fusion-aware** expression
  emission (one helper over non-literal leaves of a multi-op tree). Leaves
  mode is the fusion path; it is **not** the literal-axis path.
- Together these Wave 2 surfaces are used by rextio-numpy **0.1.1**, published
  later on 2026-07-14 after LSP 0.1.1 and core 0.1.2 in the required order.
  API 1.1 providers retain legacy keyword-not-offered semantics and never
  receive leaves-mode data. See `docs/specs/plugin-lowering.md`.

### Diagnostics and CLI

- User-visible release-version strings now derive from
  `rextio.__about__.__version__` instead of a hardcoded `0.1.0` /
  `0.1.0-alpha`. This fixes stale version text in RXT diagnostic suggestions and
  messages, `rextio` CLI `--help` output, config-validation errors, target-spec
  warnings, and the `rextio init` `REXTIO.md` template, so they track the
  installed version. Wording of version-agnostic messages was reworded to the
  "native subset" where no version belongs.

### Documentation

- Hybrid Rust executable (subprocess delegate): document that a delegated
  `SystemExit` / `sys.exit(n)` int code is honored only when representable as
  a signed `i64` (Rust client `serde_json::Value::as_i64`). After consume the
  value is cast to `i32` and OS process-status width applies — prefer portable
  `0..255`. Python ints outside signed `i64` still serialize on the wire but
  are not faithfully modeled as process exits: the client surfaces a
  malformed-response `RuntimeError` rather than terminating with the intended
  status (not CPython-equivalent for oversized codes). This is distinct from
  direct-native `main` return semantics (compile-time `int`→`i64` lowering,
  then the same `i64`→`i32` / platform truncation). See README and
  `docs/unsupported-features.md`.

## 0.1.1 — 2026-07-12

Contract-and-plugins release: the machine-readable tooling contract for
external tooling (agent skills, LSP servers, editor extensions) and the
plugin protocol that lets plugins describe AND lower covered constructs.
All new surfaces are Experimental (see docs/stability.md); no analyzer or
codegen behavior changed for plugin-free projects.

### Machine-readable tooling contract

- `rextio check --format json` (and `.rextio/reports/check.json`) carries a
  top-level `contract_version` plus per-function `route` (`native-direct`,
  `native-shim`, `native-plugin:<id>`, `fallback-accelerated:<tool>`,
  `fallback-python`), `native_status` (`accepted`/`rejected`/`not-candidate`),
  and `rejection_codes`. Additive: no existing key changed.
- New `rextio capabilities [project_root] --format json`: the config-resolved
  capability manifest — the supported type matrix, structured L2 rule records
  (constraint + diagnostic code + remediation guidance per rule, core and
  active plugins merged), a `config_fingerprint` for consumer caching, and the
  active plugin list. Introspection-only: no source analysis, no report files.
- Specs: `docs/specs/tooling-contract.md` and `docs/specs/plugin-lowering.md`.

### Plugin protocol v2 and lowering (plugin API 1.1)

- Entry-point plugins can now self-describe declarative rule records via
  `describe()`/`covers()` (`rextio.plugins.api`), with `RXTP-<PLUGIN>-NNN`
  diagnostic namespacing validated at load. Metadata-only plugins keep
  loading unchanged.
- Plugin API 1.1 adds the lowering members (`type_vocabulary`, `claim`,
  `lower`, `crate_dependencies` — all-or-nothing): a plugin registers an
  annotation vocabulary the analyzer resolves through the module import map,
  claims covered call/binop sites at analysis time (deterministic by
  contract; claims are matched to IR nodes on the full kind+span signature),
  and emits expression-level Rust through `lower(site, LoweringContext)` at
  codegen time. Claimed functions route as `native-plugin:<id>`; plugin
  claim rejections surface at the boundary pass with the plugin's own
  diagnostics; plugin codegen failures demote to the Python fallback exactly
  like core codegen failures.
- Plugin-typed PyO3 boundaries: plugin types declare their parameter/return
  conversions (read-only borrows in, owned returns out); plugin types never
  cross scalar boundary calls or executable delegation, and plugin-lowered
  functions are excluded from the Rust-importable crate.
- Pinned crate injection: a lowering plugin declares exact-pinned crate
  dependencies; they are appended to the generated Cargo.toml only when a
  plugin-lowered function exists, listed in `build.json`
  (`plugin_crate_dependencies`) and the text report, and cross-plugin pin
  conflicts fail loudly up front.
- New diagnostics: `RXT091` (informational: an accelerator-decorated function
  may be plugin-lowerable if the decorator is removed — the decorator is
  respected; precedence is explicit decorator > plugin > fallback) and the
  plugin-owned `RXTP-*` code space.

### Plugin certification kit

- `rextio.plugins.testing`: builds a fixture project once, then runs each
  input through the generated wrapper on both legs
  (`REXTIO_NATIVE_MODE=native`/`fallback`) with deep-copied arguments,
  comparing results (NaN-aware, type-strict; custom comparators for richer
  types) and exceptions (type + message). Rule records gain an optional
  `verified` field for certification status.
- First consumer: the rextio-numpy plugin's initial float64 1-D surface
  (element-wise arithmetic, `numpy.dot`, whole-array `sum`/`mean`) is
  certified with this kit against CPython NumPy under real cargo builds.

### Correctness and robustness hardening

Semantics- and safety-focused fixes to the analyzer, the generated wrapper,
the plugin pipeline, and the hybrid-executable delegate, verified end-to-end
(generate → import → call, and against real cargo builds). None change behavior
for a plugin-free project whose native candidates already compiled cleanly;
they tighten the reject-to-fallback boundary so more edge cases stay on the
CPython-equivalent fallback instead of being mis-accelerated.

- `@rextio.native` on a **method** is now accepted only for a plain instance
  method defined directly in a top-level class body whose name is never
  rebound. Every other shape is rejected with `RXT010` and left on the Python
  fallback with its original behavior intact: any non-native decorator
  (`@staticmethod`/`@classmethod`/`@property`/`functools.cached_property`,
  aliased or not); an implicit-descriptor dunder (`__new__`/`__init_subclass__`/
  `__class_getitem__`); any class-body rebinding of the method name after its
  definition — plain/annotated/augmented/walrus/tuple-unpack assignment, a
  `for`/`with`/`except`-as target, a `match` capture, `import ... as`, `del`, a
  later `def`/`class`/`type` of the same name, or a walrus in a def/class
  header, including any of these nested inside class-body control flow; a method
  in a nested (inner) class; a method defined inside class-body control flow;
  and a method whose name is declared `global`/`nonlocal`. Previously several of
  these were silently accepted and the generated wrapper could strip a
  descriptor, change the calling convention, bind the wrong scope, or fail at
  import.
- Generated Python wrapper fidelity: annotations stay as PEP 563 strings (no
  eager evaluation that could `NameError` on private or `__all__`-excluded
  names); `__defaults__`/`__kwdefaults__`, `__doc__`, and `__all__` are mirrored
  from the fallback at runtime (including an `__all__` defined by control flow or
  import); the positional-only `/` marker is preserved; and runtime helpers are
  aliased under a `_rextio_` prefix so they cannot be clobbered or leak through
  `from module import *`.
- Plugin lowering and routing: claim validation (result type required and
  known, advertised rule ids, `RXTP-*` rejection codes namespaced and declared),
  expression typing over plugin types, deterministic claim-to-IR matching,
  same-site multi-plugin claim rejection, crate-pin format validation with a
  core-crate-name collision guard, and deterministic merging of duplicate
  cross-plugin pins. A claim-only plugin function (one that claims a core-typed
  call site without plugin-typed parameters/returns) is now exempt from the
  boundary-fallback threshold like a plugin-typed one, so it never flips to the
  fallback leg mid-run and changes an observable per-leg divergence.
- Hybrid-executable subprocess delegate: a protocol-version handshake and
  dead-bridge re-spawn, and a delegated `sys.exit()`/`KeyboardInterrupt` is
  forwarded as a distinct `{"exit": code}` frame that the Rust executable
  honors when the int code is representable as signed `i64` (bool codes
  normalized to `0`/`1`; then cast to `i32` / platform status width — prefer
  `0..255`) instead of always exiting `1`. Python ints outside signed `i64`
  are not CPython-equivalent on this path (see 0.1.2 documentation).
- Certification kit: dual-leg equivalence uses deep-copied arguments and sets
  the native/fallback env before import; strided (non-contiguous) arrays are
  certified for real rather than being silently flattened.

## 0.1.0 — 2026-07-04

Initial public release (alpha stage) of Rextio as a local hybrid build tool.

### Text and formatting fidelity

- `print`/`logging` of `bool` and `float` are textually CPython-exact
  (`True`/`False`; shortest correctly-rounded float repr with CPython's
  positional/scientific thresholds, `nan`/`inf`/`-0.0` spellings, and signed
  two-digit exponents). Logging `%` conversions are validated per argument
  type (`%d`/`%i`: int and bool; `%f`: float only, fixed six decimals with
  the CPython `nan` spelling; count mismatches, unknown conversions, and
  dynamic format strings with arguments fall back), and `%r` renders CPython
  repr. Printable containers (list, fixed tuple, `Optional`, nested) compose
  CPython repr recursively in `print`/logging; `print` of a `set` or `dict`
  is rejected (native iteration order is not CPython's). `__rextio_repr_str`
  escapes quotes, backslash, `\n`/`\r`/`\t`, C0/C1 controls, and U+00A0
  exactly like CPython repr.
- Iterating a `set` in a native function is rejected to the Python fallback
  with a dedicated diagnostic (Rust hash-set iteration order is per-instance
  seeded and diverges from CPython's deterministic-within-process order).
  Building a set from an ordered iterable and order-independent set
  operations stay native.
- `RXT090` non-rejecting note marks direct-native functions relying on the
  statically attributable documented divergence (`bytes.decode()` raises
  `ValueError` where CPython raises `UnicodeDecodeError`); `rextio check`
  lists the notes. (The other documented divergence - repr of str values
  containing non-printables above U+00A0 - is value-dependent and cannot
  carry a per-function note.)
- `list.index` failure messages interpolate the needle repr exactly like
  CPython ("5 is not in list", "'x' is not in list", "[3] is not in list").

### Scalar boundary calls

- An explicitly marked native function may call a fallback-only project
  function whose signature is immutable scalars end to end: the call is an
  in-process boundary call (`RXT075`, informational) executed by the host
  interpreter, so values and exceptions are CPython-exact and runtime
  replacement of the callee (monkeypatching) is honored by the native path.
  Scalars cross by value: argument identity (`is`) is not preserved
  (`None`/`bool` singletons are). Containers never cross; a boundary call
  inside a native loop - including comprehension bodies and while-loop
  tests - keeps the caller on the Python fallback (`RXT076`), while a call
  in a for-loop iterable (evaluated once) stays an accepted `RXT075`;
  auto-discovered candidates are
  excluded (marker-only). Every crossing counts against the caller's
  boundary-fallback threshold (one native call performing `k` boundary calls
  adds `k + 1` crossings), so a chattering native demotes itself to the
  Python fallback at run time. The importable Rust crate does not export
  boundary-calling functions or their transitive native callers (they need
  the interpreter), and the rust-executable delegate mode is unchanged.

### Toolchain selection and version pins

- A `[toolchain]` configuration section (CLI flag > `REXTIO_*` variable >
  `rextio.toml` > PATH) selects the cargo, maturin, Nuitka, and CPython a
  build uses: paths accept a binary or a home directory, a configured path
  that does not resolve fails the build up front, and symlinks and `..`
  components are traversed exactly as at the shell. `rust_toolchain`
  forwards a rustup channel; `[toolchain] python` drives the PyO3 build
  target (`PYO3_PYTHON`), Nuitka's interpreter (`python -m nuitka`), and the
  hybrid binary's delegated-call runtime, and must be a CPython sharing the
  build interpreter's minor version. For PyO3 specifically, when
  `[toolchain] python` is unset the target defaults to the running build
  interpreter (not PATH `python3`); an explicitly exported `PYO3_PYTHON` is
  respected as an override.
- `*_version` pins verify (never install) tool versions: bare pins are
  prefix matches, `==` is exact, `>=` is a minimum. A pin is enforced under
  the environment the build runs the tool with, exactly when the build uses
  the tool - including the hybrid dispatcher and the maturin-to-cargo
  fallback - and an unresolvable or unprobeable pinned tool fails the build.

### Packaging and accelerator-scan behavior

- The wheel built from a Nuitka fallback tree excludes `.py` sources
  shadowed by their compiled extension module (import-loadable suffixes
  only, so a same-stem ctypes `.dylib`/`.dll` payload keeps its Python
  wrapper) and carries a platform tag rather than `py3-none-any`;
  accelerated modules keep their `.py`.
- The external-accelerator source scan walks the whole module tree (deferred
  imports in function bodies, nested functions, `except`/`finally` bodies,
  `from numba import *` submodules), keeps accelerator-resolving import
  bindings over scope-flattened collisions, and all three Nuitka build paths
  recognize project-local modules (a local `numba.py` shim neither skips nor
  blocks builds).
- A Nuitka standalone build whose `.dist` directory lacks the launcher
  binary is reported as failed rather than returning the directory as the
  artifact.

### Added

- CLI commands: `rextio init`, `rextio check`, `rextio build`, `rextio bench`, and `rextio clean`.
- Source-only generation command: `rextio generate`.
- Automatic native discovery for eligible typed module-level Python functions, with `@rextio.native` still supported and decorator-only mode available.
- `@rextio.exempt` decorator for functions that must remain Python fallback.
- Conservative 0.1.0 subset checks for supported scalar/list types, simple control flow, indexing, and native-to-native calls.
- Experimental restricted native `try`/`except`/`finally` subset (built-in exception handlers only; a `finally` block carries an `RXT090` note for the documented `__context__` divergence).
- Deterministic diagnostics for unsupported syntax, dynamic Python features, external calls, and unsafe boundaries.
- Static boundary policy:
  - reject native functions that call fallback-only functions;
  - reject native functions that depend on rejected native candidates;
  - warn when fallback Python loops call native functions repeatedly.
- Rextio IR lowering and deterministic Rust/PyO3 code generation for accepted native functions.
- Cargo and maturin build orchestration with Cargo fallback when maturin is unavailable.
- Optional Rust-importable crate artifact generation with `--rust-importable`
  and `--rust-crate-name`, allowing Rust projects to consume accepted
  direct-Rust functions as a path dependency.
- CPython fallback packaging and generated wrappers that preserve fallback behavior.
- Experimental Nuitka fallback packaging with clear unavailable-tool reporting.
- Runtime control: `REXTIO_NATIVE_MODE=auto|native|fallback` (one switch for disable/require/default).
- Runtime boundary fallback threshold for repeated Python-to-native wrapper crossings.
- `--fallback-threshold` for embedding a generated-code default threshold in `rextio build` and `rextio generate`.
- Configurable external build-tool timeout via `--build-timeout`,
  `REXTIO_BUILD_TIMEOUT`, and `[build] build_timeout_seconds` (CLI > env > toml >
  default, default 600s).
- Generated hybrid artifact wheel under `dist/`.
- Zipapp executable artifact generation with `rextio build --entrypoint=module:function`.
- Nuitka standalone/onefile executable artifact generation with `--executable-backend=nuitka`.
- Native Rust binary executable generation with `--executable-backend=rust`: a
  native executable whose `main` calls a direct-native `def main(argv: list[str])
  -> int` entrypoint, mirrors `sys.argv`, uses the returned `int` as the process
  exit code (converted to the platform's exit-status width, like CPython's
  `sys.exit`), and prints a returned error CPython-style (`TypeName: message`) to
  stderr. The crate-mode `RextioError` carries the CPython exception type name
  so these binaries emit Python-style diagnostics.
- Subprocess hybrid for the Rust executable: a call the entrypoint makes to a
  project function that stays on the Python fallback is delegated to an external
  CPython process (a generated dispatcher + the project source shipped as
  `dist/<binary>.runtime/`, driven over a JSON stdio protocol) instead of being
  rejected, so hard-to-compile-to-Rust logic can be "left as Python." The
  delegated function runs real CPython (result is CPython-equivalent, exceptions
  forwarded CPython-style). Delegated-call arguments and results must both be
  immutable scalars (`int`/`float`/`bool`/`str`/`None`) — a mutable container
  (`list`/`dict`/`set`) is not delegated in either direction because it crosses the
  wire by value, which severs the aliasing CPython preserves (a mutated argument or
  a mutated aliased return would diverge silently); non-finite floats are rejected
  rather than silently dropped. A delegated function's stdout/stderr is redirected
  to the binary's stderr so it cannot corrupt the wire protocol, the dispatcher
  survives a delegated `SystemExit`/`KeyboardInterrupt` or non-serializable result
  instead of dying, and it runs without `rextio` installed (a no-op decorator stub
  is supplied when absent). RXT080 runtime-shim functions are not delegated. A
  hybrid binary needs a Python interpreter at runtime; a fully-direct-native binary
  remains standalone. `--executable-python` (`[executable] python`,
  `REXTIO_EXECUTABLE_PYTHON`) pins the interpreter the binary launches (bare name,
  absolute path, or a path relative to `<binary>.runtime` to bundle one).
  `--hybrid-runtime=nuitka` (`[executable] hybrid_runtime`, `REXTIO_HYBRID_RUNTIME`)
  instead ships the delegated Python as a self-contained Nuitka-compiled dispatcher
  executable, so no separate Python install is needed at runtime (requires Nuitka
  at build time).
- Mirrored build and analysis settings across CLI parameters, environment variables, and `rextio.toml`.
- Target planning metadata for future native backends and installed package plugins.
- Experimental opt-in scalar-helper embedding for narrow unmarked helpers
  represented in Rextio IR, with `--embed-helpers`, `REXTIO_EMBED_HELPERS`, and `[embedding] enabled`
  controls (`rextio bench` accepts the same flag pair, so both embedding
  modes can be benchmarked): an eligible helper compiles ahead of time as an internal native
  function through the normal checked lowering (int overflow raises
  OverflowError; float `/` raises ZeroDivisionError), and in the Rust
  executable backend it compiles into the binary instead of being delegated
  per call. There is no JIT: everything compiles ahead of time, and the built
  artifact contains no runtime compiler.
- Numba coexists with the Nuitka fallback backend (experimental): modules using a recognized
  external accelerator are automatically kept as plain Python (skipped from
  per-module Nuitka compilation, so the importable `.py` retains the bytecode
  the accelerator needs), and the build result lists them. The detection scan
  sees through the optional-dependency guard (`try: from numba import njit`),
  `from numba import *`, conditional top-level imports, and class-contained
  methods. Nuitka *executable* builds fail early with guidance when
  accelerated modules are present, and the `nuitka` hybrid-runtime dispatcher
  fails early when *any* project module uses an accelerator (the whole tree
  ships in the runtime and Nuitka follows imports into it), instead of
  producing a binary that fails at the first call.
- Numba (`numba.jit`/`njit`/`vectorize`/`guvectorize`) is recognized as an
  external accelerator (experimental) for Python fallback code: decorated
  functions stay on the fallback cleanly (no auto-discovery, no diagnostic
  noise), are labeled `external_accelerator: numba` in reports and
  `rextio check` output, and run under Numba's own semantics (documented,
  including the nopython int-overflow wrap divergence). Not compatible with
  Nuitka-compiled fallbacks.
- Python runtime semantics native shim (`RXT080`) for compatibility coverage of
  object behavior, marked instance methods, exceptions, context managers,
  async functions, generators, and dynamic attribute access.
- Limited direct Rust lowering for expanded builtin and standard-library
  patterns including `math`, `all`/`any`, `sorted`/`reversed`, selected
  `str`/`bytes`/`list` methods, `time`/`datetime`, `hashlib.sha256`, and
  `base64.b64encode`. (`statistics.mean`/`fmean`, `json.dumps`/`json.loads`,
  and `base64.b64decode` have no faithful native equivalent and stay on the
  fallback/runtime-shim path.)
- Conservative Python/Rust ownership handling for direct Rust lowering:
  generated clones for reused owned values and fallback diagnostics for mutable
  collection alias mutation.
- Feature-oriented README and example documentation that explains generated
  artifacts, native/fallback behavior, executable outputs, and Rust-importable
  crate usage.
- Example projects for pure math, application-shell scoring, fallback safety, and boundary diagnostics.
- Focused end-to-end tests for build/import/runtime behavior, real Cargo builds, generated wheels, and Nuitka when installed.
- Global CLI output options on every command: `--format text|json`, and mutually
  exclusive `-v/--verbose` and `-q/--quiet`. All commands emit their result on
  stdout (text or JSON) while diagnostics and configuration errors go to stderr, so
  a `--format json` run produces clean machine-parseable stdout.
- Project documentation and governance: a `CONTRIBUTING.md` guide, GitHub issue forms
  and a pull-request template, a feature-stability table (`docs/stability.md`) and a
  versioning policy (`docs/versioning.md`) documenting the SemVer pre-1.0 stance and
  what is stable versus experimental.

### Semantics and safety guarantees

- `@rextio.native` validates its `target` against the recognized target
  languages, and both `@rextio.native`/`@rextio.exempt` reject classes
  and non-callables at decoration time, surfacing typos and misuse immediately.
- Plugins are metadata-only; a legacy `rules` key in plugin metadata is
  accepted and ignored so such plugins still load.
- Generated `str` literals are escaped into always-valid Rust (non-ASCII is
  emitted literally; escaping is injection-safe) through a single escaper that
  funnels every Python-string-to-Rust-literal path — plain `str` constants,
  the runtime-semantics shim's fallback module/attr names, logging format
  strings, and error messages embedding variable names. Lone surrogates, which
  a Python `str` can hold but Rust cannot represent, are rejected with a clear
  diagnostic.
- External build tools (`cargo`/`maturin`/`nuitka`) are invoked through a
  shared no-shell, bounded-timeout helper: a hung toolchain fails the build
  with a clear message, and on timeout the whole process tree is terminated
  (POSIX process-group / Windows `CREATE_NEW_PROCESS_GROUP`) so child
  `rustc`/linker/`python` processes are not left running.
- A native candidate's function name, parameters, and locals that collide with
  a Rust keyword (`fn`, `match`, `type`, …) are carried as raw identifiers
  (`r#match`), so the function stays native. Only the keywords a raw
  identifier cannot express (`crate`/`self`/`Self`/`super`) and non-ASCII
  names are kept on the Python fallback path with `RXT011`.
- `SECURITY.md` documents the threat model and protections; CI runs a
  `check-wheel-contents` packaging gate.
- The supported-type capability matrix (scalar/list/dict/set item/key types)
  is defined once in `rextio.capabilities` and shared by the analyzer and the
  Rust backend; a consistency test asserts every registered type has a Rust
  mapping.
- Generated sequence indexing preserves Python semantics: a negative index
  counts from the end (`xs[-1]`), and an out-of-range index raises
  `IndexError` rather than triggering an unchecked Rust panic.
- Generated integer `+`/`-`/`*`/`%`, unary negation, and the `abs`/`sum`
  builtins use checked arithmetic: an i64 overflow raises `OverflowError`
  (PyO3) / returns a `RextioError` (Rust-importable crate) instead of silently
  wrapping or panicking, and a modulo by zero raises `ZeroDivisionError`.
  Integer `%` follows Python's floored semantics (the result takes the
  divisor's sign, e.g. `-7 % 3 == 2`) rather than Rust's truncated remainder.
  These are catchable `Exception`s (unlike the uncatchable PyO3
  `PanicException` a raw overflow panic produces), and the guarantee travels
  with the generated code, so it holds even when the Rust-importable crate is
  consumed as a dependency. Release builds also keep `overflow-checks = true`
  as a safety-net backstop for any arithmetic outside the checked path; it is
  not part of the catchable-exception contract.
- Generated float division and modulo preserve Python semantics: `x / 0.0`
  and `x % 0.0` raise `ZeroDivisionError` (instead of Rust's silent
  `inf`/`NaN`), and float `%` is floored (the result takes the divisor's
  sign); a remainder of exactly zero takes the divisor's sign
  (`copysign(0.0, b)`), matching CPython.
- `math.floor`/`ceil`/`trunc` convert through a guarded float-to-int helper: a
  value outside i64 range raises `OverflowError` and `NaN` raises
  `ValueError`, never silently saturating to `i64::MIN`/`MAX`.
- The Python runtime-semantics shim (`RXT080`) is strictly opt-in: only
  functions explicitly marked `@rextio.native` are promoted to the shim.
  Auto-discovered (undecorated) functions are accepted only within the
  direct-Rust subset, and an undecorated function that depends on a
  runtime-shim native is reported with `RXT074` and left on the Python
  fallback path.
- The native subset checker keeps patterns it cannot lower faithfully off the
  direct-native path (rejected to the Python fallback, or routed to the
  `RXT080` runtime shim for marked functions) — an accepted function is either
  CPython-equivalent or rejected, never silently mis-compiled. Among the
  rejected patterns: non-`bool` `if`/`while`/comprehension conditions;
  multiple assignment (`a = b = ...`); integer literals outside the `i64`
  range; ordering comparisons on `dict`/`set` operands (`==`/`!=` stay
  native); `len()` of a fixed tuple; value-position `range(...)`;
  `str`/`bytes` indexing; a value-position read of a name bound nowhere in
  the function (a module global, a closure, or a name leaked from a nested
  block); and a call to a name shadowed by a local binding or a module-level
  assignment (`len = 5` then `len(xs)`). `len(str)` counts Unicode code
  points (`.chars().count()`) rather than UTF-8 bytes, and a bare `return` in
  an `Optional[T]` function emits `None`.

### Notes

0.1.0 is intentionally narrow. It does not provide full Python
compatibility, bundled third-party package support, framework migration,
general-purpose Python JIT behavior, or full runtime boundary-cost optimization.
Scalar-helper embedding is experimental, opt-in, AOT, native-side only, and
limited to small scalar helper regions; there is no runtime JIT.
