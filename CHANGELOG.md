# Changelog

## Unreleased

### Device Provider API 1 foundation and bounded build wiring (tooling contract 2.26.0)

- Replace the behavior-neutral device-provider draft with a bounded,
  vendor-neutral API 1.0 contract: structured device value metadata, canonical
  device ids, expanded target capability facts, explicit provider/capability
  selection, fail-closed preflight, declarative build/resource inputs, and
  deterministic lock/report projections.
- Preserve existing CPU-only behavior when no provider is selected. An
  accelerator-bearing artifact profile now requires explicit resolution;
  installed-but-unselected providers are never inspected.
- Add advanced explicit `[target]` selection/options for `generate` and
  `build`. Core loads exactly one selected `rextio.device_providers` entry
  point, binds its module/attribute target and distribution name/version,
  redacts raw options to keys plus a SHA-256 binding, and completes preflight
  before generated-output mutation.
- Materialize only validated native-library names as a generated `build.rs`
  in this bounded step. Bind the selected plan into a generated lock, build
  and generate reports, plus artifact-evidence/SBOM/provenance inputs.
  Cargo features, package references, helpers, and runtime-check ids remain
  declared future inputs and fail closed if a provider contributes them.
- Keep support claims separate from discovery and preflight. E0 does not ship a
  Torch or TensorFlow CUDA lowering; selecting an accelerator provider without
  a matching typed domain `DeviceRequirement` fails closed.

### Plugin comparison expressions (plugin API 1.5; tooling contract 2.25.0)

- Add an explicitly version-gated `compare` claim kind for one non-chained
  `==`, `!=`, `<`, `<=`, `>`, or `>=` expression involving a plugin-owned
  operand. Providers below API 1.5 are never offered the new site.
- Preserve a claimed non-scalar comparison result type through subsequent
  plugin calls and carry the comparison's direct operands through analyzer,
  IR, and Rust lowering. Unclaimed/chained plugin comparisons remain on the
  fail-closed fallback path.
- Require every claimed comparison to return one registered, non-empty result
  type. Peek inference treats any multi-provider overlap as ambiguous even when
  providers report the same type; the authoritative claim path then reports
  the overlap.

## 0.1.5 — 2026-07-23

**Published release.** Package version `0.1.5` is tagged and published to PyPI
with plugin API **1.4**, tooling contract **2.24.0**, and readiness policy
**11**, superseding `0.1.4`. Release Train C ships the host source/artifact and
native-executable architecture plus the frozen, bounded Full-C6/C5.2 Alpha.
Those new surfaces remain Experimental/Alpha: this release does not claim
broad Full C6, general package AOT, general hermeticity, CUDA support, or heavy
host-lifecycle CI certification.

- Rename the public artifact distribution policy from its internal
  milestone-derived label to `strict-evidence`, and rename
  its serialized failure status to `strict-evidence-failed`. The old names are
  not accepted; those spellings were internal and were never released.
- Preserve CPython source-order semantics for eager function annotations in
  bounded module initialization, and fail closed on native-symbol collisions
  (including duplicate qualnames) within each artifact's actual emitted set.
  Defer external-source planner loading to remove the `analyzer.module_init` ↔
  `source.external_analysis` import-order cycle, covered by clean-interpreter tests.
- Make final Full C6 publication retries idempotent across an interruption after
  the atomic no-replace rename commit. An existing target succeeds only when it
  is still an owner-private mode-`0700` directory containing the exact closed
  bundle independently expected by the current verified request. Recovery
  safely recaptures every original payload and the trusted public key between
  repeated target descriptor/name-binding and byte validation passes;
  different, mutated, unsafe, or concurrently replaced targets remain
  fail-closed collisions and are never overwritten.

### Full C6 support closure and production sandbox receipts (tooling contract 2.24.0)

- Add `rextio policy bootstrap-support-lock --project-root . --output
  authority/rextio.toolchain-support.lock.json --format json` so owners can
  create or exactly reuse one canonical host support lock before a strict
  lifecycle. Its host-absolute-path-free result retains the project-relative
  config path and returns the exact
  `artifact_toolchain_support_lock` / `_sha256` config pair plus target,
  manifest/root roles, raw digest, and Merkle digest; it authorizes neither a
  build nor distribution.
- Require an existing owner-private mode-`0700` output parent and create or
  exactly reuse a single-link mode-`0600` canonical lock. Linked, aliased,
  changed, differently configured, or concurrently conflicting output fails
  closed.
- Bind the fixed platform support closure into the process-sealed plan,
  canonical lock bytes, raw SHA-256, and tree Merkle SHA-256. Linux execution
  runs Cargo through `bwrap`, a sealed seccomp filter, the support-locked
  isolated CPython launcher, and Landlock; macOS uses `sandbox-exec` with the
  exact Xcode, SDK, and sealed-system-volume anchor bindings.
- Add the closed sandbox-engine identifier plus path-free plan/profile digests
  to both invocation receipts, and the sealed seccomp digest on Linux.
  `sandbox_profile_sha256` is the engine-specific, path-tokenized
  semantic profile identity and must agree across both builds and equivalent
  lifecycle runs; the raw rendered profile may contain private per-run paths
  and is neither serialized nor signed. Propagate support-plan/raw-lock/Merkle
  identities into strict SBOM and SLSA materials, and reject any receipt or
  authority reconstruction that drops or changes those bindings.
- Remove inherited macOS executable-mapping allowances for mutable/data-volume
  roots by denying `file-map-executable` alongside read/write access under
  `/private/var`, `/private/etc`, `/Library`, `/dev`, `/cores`, and
  `/System/Volumes/Preboot`. A real macOS arm64 self-checking probe uses a
  pre-opened Apple regular-file fixture and requires both unsandboxed mapping
  and an explicit `read-execute` positive control before it accepts a hardened-
  profile denial of the same executable mapping; hosts unable to establish the
  unsandboxed control skip with an explicit reason. Sealed-system execution is
  checked separately.
  Only paths already bound by an explicit `read-execute` rule, or a bound
  read-write directory capability, regain executable mapping and process
  execution; ambient mutable paths remain blocked.
- Reserve every configured `imports.packages.*.source_archive` path during
  support-lock bootstrap. Before opening the output, NFC/case-folded path parts
  cannot form exact, ancestor, or descendant aliases with any source archive
  (including one that does not exist yet) or the other configured lifecycle
  artifacts.
- Perform three full support-tree verifications per strict `rextio build`
  invocation: once while collecting the configured host lock, once at
  native-executor entry, and once immediately before executor authority mint.
  The executor therefore performs exactly two full rewalks, and every
  owner-policy lifecycle stage repeats the sequence independently.
  External/production/internal and per-build boundaries perform no additional
  full walk; they revalidate the process seal, critical leaves, and exact
  plan/raw/Merkle digest identity.
- Record one local macOS arm64 observation of roughly **104,645** support
  members, **2.67 GB**, and about **45 seconds** per full verification. These
  are machine-specific measurements, not performance limits or guarantees.
- Keep the bounded Alpha threat model explicit: it does not defend against
  hostile same-UID concurrent replacement, kernel or operating-system
  compromise, or provide complete time, randomness, scheduling, or CPU
  virtualization. It is not a general hermetic-build claim.
- Preserve the frozen CPython 3.11/PyO3/Cargo scope on macOS arm64 and Linux
  x86_64 with exactly one depth-1 `py3-none-any` dependency and direct typed
  scalar leaves. Plugins, executables, rust-crate output, top-level AOT,
  embedding, Windows, general recursion, and broader external-source lowering
  remain excluded.
- Remove the 90-minute macOS arm64/Linux x86_64 Full C6 installed-wheel matrix
  from automatic CI. Keep fast policy/unit coverage in CI and preserve the real
  lifecycle as `python scripts/validate-full-c6-host.py`, with
  `--preflight-only` available for a non-building host/toolchain check. The
  command requires a clean Git worktree and index, exports only tracked `HEAD`
  files into a fresh temporary source tree so stale local build output cannot
  enter the wheel, and uses isolated build/install environments plus the
  existing real-Cargo E2E harness. Its result is evidence for that host and
  exact recorded commit, not CI certification.
- Publish tooling contract **2.24.0**, plugin API **1.4**, and readiness policy
  **11** with package **0.1.5**.

### C5.2 / Full C6 bounded Alpha coordinator and owner-policy handoff (tooling contracts 2.22.0-2.23.0)

- Connect one exact SourceLock-v2-admitted depth-1 `py3-none-any` dependency to
  project call sites. Only direct final-import calls with statically typed
  scalar positional arguments reach private Rust leaf functions; stale source,
  aliases, mutation, value escape, unsupported calls, or analysis drift fail
  closed.
- Preserve the original dependency as exact `Requires-Dist` metadata instead
  of vendoring it. Generated PyO3 code checks installed distribution identity,
  version, `RECORD` membership, located paths, and exact reached-module source
  bytes through descriptor-relative, no-follow reads. It never imports or
  introspects the external dependency module or callable; the signed source
  analysis already binds callable identity.
- Carry the SourceLock wheel's exact PEP 639 license payloads into the final
  wheel as `License-File` members below
  `external/<normalized-distribution>/<version>/`, with exact METADATA/RECORD,
  SourceLock-verification, subject, mapping, and byte bindings.
- Add one sealed, same-transaction `FullC6ExternalBuildContext` and require it
  at the orchestrator boundary. Reconstructed linkage, runtime guard, source
  wheel inventory, and fresh analysis must all agree before Cargo or packaging.
- Replace the initial digest/count-only bootstrap with canonical schema/domain
  v2. The public request embeds an exact technical template for the combined
  C6.14+C5.2 partition, transformation set, and exact project/Cargo plus
  external-wheel license observations, while remaining host-path-free,
  non-authorizing, and free of source/license payload bytes.
- Add a separate canonical owner-completion document. The owner must explicitly
  allow every applicable observed license row and accept the exact observed
  transformation set. `rextio policy finalize` combines the explicitly named
  bootstrap/completion files offline into the canonical v2 policy manifest; it
  does not sign or authorize the result.
- Bind the final manifest to the v2 bootstrap request, trusted public-key digest,
  exact observations, and fresh production recollection. Every bootstrap,
  signing-request, and publication `rextio build` run recollects the graph and
  executes two actual isolated offline builds; a prior report or serialized
  receipt cannot replace that work. `FullC6ProductionAuthority` is only a
  process-local evidence seal, never serialized publication authority.
- Keep the three-stage lifecycle: bootstrap; separately completed and pinned
  policy → canonical signing request; then externally detached-signed,
  create-if-absent atomic publication. Rextio neither invents owner decisions nor
  accepts, creates, or retains a private signing key.
- Seal the exact bounded project Python file/directory namespace through initial
  analysis, C5.2 reanalysis, and transformation replay. A custom
  `.rextioignore`, nonignored alias/special entry, namespace mutation, or replay
  scope loss fails closed. Failures before that authority exists are stderr-only
  and do not write through an untrusted project `.rextio` path.
- Freeze host admission to CPython 3.11 exactly on macOS arm64 or Linux x86_64,
  a non-editable, cache-free installed Rextio package whose complete `rextio/`
  tree matches wheel `RECORD`, and rustup-selected Cargo/rustc. The strict host
  requires a `pip --no-compile` installation, no `rextio/` `__pycache__`/`.pyc`
  `RECORD` row or physical package-tree entry, and a process started with
  `PYTHONDONTWRITEBYTECODE=1` (or equivalent `-B`). Require SHA-256-pinned
  `Cargo.lock` plus a pinned vendored tree and run both builds as
  `cargo build --release --locked --offline --frozen`.
- Treat that cache-free inventory as bounded build-evidence integrity, not a
  hostile-process secure-boot boundary: Rextio is already executing in the
  owner process and does not defend against a compromised OS or account.
- Treat the Cargo lock/vendor digest as owner-pinned input integrity only; this
  does not authenticate a registry, crate publisher, or upstream origin.
- Keep the profile to one external package and no plugins, executable,
  rust-crate, top-level AOT, embedding, Windows, recursion, or general package
  lowering.
- Advance only the unreleased tooling contract to **2.23.0**. Package **0.1.4**
  and plugin API **1.4** remain unchanged.

### Full C6 strict authority and publication primitives (tooling contract 2.21.0)

- Add immutable Full-C6 preauthorization/final evidence and a sealed
  distribution-authorization token that only the hard gate can mint.
- Execute two isolated, offline, frozen-input Cargo builds and require
  byte-identical wheel output, exact live toolchain/environment validation, and
  no source-tree mutation outside the single bounded lock-generation
  transition. Semantic receipts preserve caller-controlled environment values
  exactly while projecting executor-owned `HOME`, `CARGO_HOME`,
  `CARGO_TARGET_DIR`, and the project/build remap operands to stable
  `/rextio/project` and `/rextio/build` identities.
- Rebuild and cross-bind the standards SBOM/provenance, complete frozen policy,
  SourceLock v2 source wheel, build-input closure, Cargo source identities,
  runtime authorization, toolchain identity, and reproducibility receipts.
- Verify the detached Ed25519 authorization over the domain-separated message
  `REXTIO-FULL-C6-ED25519-V1\0 || canonical-request-bytes`, using one pinned raw
  32-byte public key and a closed seven-field canonical envelope containing the
  canonical Base64 form of one raw 64-byte signature. The envelope is bounded
  to 16 KiB. Rextio accepts no private signing key and never treats a preview
  lock or readiness record as a final signature.
- Publish a seven-file pinned-parent atomic bundle: wheel, CycloneDX, SLSA
  provenance, final evidence, detached-signature envelope, authorization, and
  `rextio.full-c6-manifest.json`. Existing targets,
  unsafe links/types, byte changes, races, or partial publication fail closed.
  Temporary host-output and private-quarantine cleanup completes before the
  final no-replace directory rename; that successful rename is the publication
  commit point.
- Certify the complete local macOS arm64 installed-wheel lifecycle at commit
  `f9eb5e6`: CPython 3.11.15, Cargo 1.93.1, all five real-E2E checks, all three
  stages with exactly two distinct Cargo PIDs each, final published/authorized
  state, fresh installation, external LICENSE/METADATA/RECORD bindings, runtime
  guard poison check, and no bytecode cache. The subsequent 256 MiB installed-
  input budget hardening is unit-tested; exact-HEAD and Linux x86_64 blocking
  CI remain pending.

### Fixed

- Normalize malformed or adversarial support-lock property failures at the
  external-execution and production boundaries into their fixed fail-closed
  Full-C6 errors instead of leaking lower-layer exception types.
- Require a cache-free Full-C6 host process and install. `sys.dont_write_bytecode`
  must already be true; wheel installation must omit compilation; RECORD and
  the complete physical `rextio/` namespace reject every `rextio/`
  `__pycache__`/`.pyc` row or entry, unrecorded package directory/member, alias,
  special entry, and between-walk addition.
  Enforce the existing 256 MiB cumulative installed-input budget twice: reject
  the aggregate sizes declared for `rextio/` `RECORD` members before the tree walk, then
  independently recheck aggregate actual `stat` sizes and bounded reads during
  the walk. This closes executable bytecode and oversized inputs outside the
  RECORD-backed evidence set without claiming hostile-process secure boot.
- Open the external installed-distribution root from `/` one directory component
  at a time with `openat`/`O_NOFOLLOW`, rather than following a linked root or
  ancestor. Open the final source with `O_NONBLOCK` as well as `O_NOFOLLOW`, then
  require a single-link regular file, so a FIFO or other special file fails
  quickly instead of blocking extension import.
- Resolve `importlib.import_module`, `globals`/`vars`, `sys.modules`,
  `__builtins__`, `__dict__`, and other loader/reflective capabilities through
  the complete project re-export graph. Direct, multi-hop, and package-init
  laundering now fail the strict external-linkage gate.
- Canonicalize only executor-owned per-run environment paths in lifecycle
  receipts after validating the exact absolute values supplied to Cargo. This
  keeps bootstrap, signing-request, and publication authorization requests
  stable without weakening caller-controlled environment binding.
- Permit unrelated ambient directory size/time churn only for absolute
  ancestors above the generated root while keeping their device/inode/mode and
  every generated-root/descendant identity exact. The separate bounded C6.9
  refresh may still admit only the generated root's expected size/time delta.
- Recheck the final loaded-image snapshot after symbol-provider identity probes
  and on every native-runtime authority validation. A late loader side effect
  taints the process and cannot mint or retain Full-C6 runtime authority.
- Accept the concrete platform `Path` type in strict finalization and project
  every strict analysis report path to a canonical project-relative value;
  residual private roots, unexpected containers, or unsafe projection fail
  through the fixed `RXT060` boundary.
- Preserve portable ordinary wheel behavior on POSIX and Windows while keeping
  the strict Full-C6 external-source collector descriptor-pinned and no-follow.
- Reject Windows drive-relative Full-C6 config paths and cover ordinary
  symlink, hardlink, Nuitka-sibling, and FIFO wheel inputs independently from
  the strict profile.
- Bind pip-rewritten installed dependency `RECORD` bytes separately from the
  source-wheel archive's own `RECORD`, while requiring every shared source,
  METADATA, WHEEL, and license identity to agree exactly.
- Accept Cargo's exact historical `MIT/Apache-2.0` metadata spelling only at
  Full-C6 Cargo-license ingestion, where its policy observation is canonicalized
  to `MIT OR Apache-2.0`. The original `Cargo.toml` bytes and digest remain
  evidence-bound; whitespace, reversed operands, and every other slash form
  still fail closed.
- Raise the bounded output-wheel license-file count from 64 to **128** so the
  frozen real PyO3 graph's 108 exact files (project 1 + Cargo 106 + external 1)
  fit the declared profile. A 129th file still fails closed; path, ordering,
  alias, per-file, and 64 MiB aggregate-byte bounds are unchanged.
- Bind the strict Cargo host linker through the active target's exact
  executor-owned `CARGO_TARGET_*_LINKER` variable. Its value must be the already
  verified linker path, caller overrides and the inactive target variable are
  rejected, and the scrubbed `PATH` remains limited to Cargo rather than being
  broadened to ambient compiler tools.
- Stabilize the macOS Full-C6 Mach-O self identity as the exact
  `@rpath/lib_rextio_native.dylib` while retaining the linker's default,
  content-derived deterministic `LC_UUID` required for dyld loadability; Linux
  linker flags are unchanged. Runtime inventory accepts that value only as the
  independently verified first self-ID row and rejects unverified or misplaced
  lookalikes. A dedicated real two-build experiment produced byte-identical
  unsigned wheels, UUIDs, ad-hoc signatures, and `RECORD`, contained no
  quarantine path bytes, and loaded the native extension. That narrower
  experiment alone was not a complete lifecycle claim; the later macOS arm64
  local real-E2E above certifies the full three-stage path through `f9eb5e6`.
- Admit exactly `/usr/lib/system/libcommonCrypto.dylib` as an additional
  macOS dyld shared-cache singleton provider for the direct
  `/usr/lib/libSystem.B.dylib` dependency. This is a bounded one-hop relation,
  not a broad `/usr/lib/system/*` allowance: the provider must be observed in
  the final platform-image snapshot, scoped and global lookup must resolve the
  same address, and `dladdr` must identify that exact provider. Unobserved,
  differently addressed, or otherwise named descendants fail closed; the
  existing OS-build and native-runtime authority bindings remain unchanged.

### C6.15 scoped artifact-class policy verification

- Add optional `artifact_evidence.artifact_class_policy_verification` schema 1
  for `host-extension-wheel-cpython-v1`. The strict project-root
  `rextio.artifact-policy.lock.json` binds the canonical SHA-256 and partition
  digest of one exact C6.14 inventory plus exactly thirteen ordered nested
  coverage rows.
- Require a closed, deterministic disposition pair for every class. Existing
  C6.10-C6.13 receipt-bound license or transformation states remain
  `prerequisite-receipt-bound` and cannot be weakened; unobserved,
  logical-system-leaf, not-applicable, and owner-declared-unverified cases use
  fixed tokens rather than free-form policy text.
- Reuse the bounded descriptor-pinned, no-follow, single-link strict JSON
  reader; reject duplicate keys, non-finite/deep/oversized JSON, boolean-as-
  integer confusion, missing/extra/reordered rows, stale digests, path aliases,
  and any disposition/state mismatch. Final collection recollects C6.10-C6.13,
  re-derives C6.14, and rereads the lock, requiring full equality without
  adopting changed bytes.
- Add the exact lock once as provenance material outside C6.14, avoiding a
  cyclic digest. Count or sidecar pressure omits C6.15 before C6.14; any C6.15
  failure leaves ordinary build success and the independent C6.3 gate
  unchanged.
- Advance readiness to policy version 11 with the fourteenth observation
  `scoped-artifact-class-policy-declaration-bound` and fixed
  `scoped-artifact-class-policy-declaration-unavailable` blocker. Attestor
  identity, SPDX, files/notices, obligations, compatibility, ownership/rights,
  legal approval, technical provenance, global completion, signatures, and
  distribution authority remain false. Advance only the unreleased tooling
  contract to **2.20.0**; package **0.1.4** and plugin API **1.4** are unchanged.

### C6.14 artifact-policy coverage inventory

- Add optional `artifact_evidence.artifact_policy_coverage_inventory` schema 1
  for the existing `host-extension-wheel-cpython-v1` evidence scope. Thirteen
  fixed, disjoint classes summarize only already-observed inputs, Cargo
  components, native-runtime nodes, and wheel outputs with an observed count
  and domain-qualified canonical identity-set SHA-256; evidence sidecars and
  the inventory itself are excluded.
- Keep identity, license-policy, and transformation-provenance semantics
  orthogonal. Exact file bytes, declared Cargo checksums, and logical-only
  identities are distinguished; only the exact C6.11/C6.12 owner receipts and
  C6.10 replay/C6.13 analysis-input receipts are referenced. No license,
  transformation, ownership, legal approval, or distribution authority is
  inferred for any other class.
- Deeply reconstruct and cross-bind the complete C6.9-C6.13 prerequisite chain,
  reject path aliases and overlapping wheel classes, and derive the inventory
  only after final runtime/lock/replay recollection. Malformed or changed
  prerequisites omit C6.14 without changing an ordinary build or the C6.3
  required-evidence result.
- Add the compact inventory to unsigned provenance metadata only, with no new
  material. At the provenance ceiling C6.14 is omitted first, then the existing
  C6.13 through C6.6 order applies. Advance readiness to policy version 10 with
  `artifact-policy-coverage-bound` and the dedicated
  `artifact-policy-coverage-unavailable` blocker. All ten global readiness
  checks remain blocked and completeness, signing, and distribution authority
  remain false. Advance only the unreleased tooling contract to **2.19.0**;
  package **0.1.4** and plugin API **1.4** are unchanged.

### C6.12 scoped project-source license-policy verification

- Add optional immutable
  `artifact_evidence.project_source_license_policy_verification` schema 1 for
  the fixed `project-functions-pyo3-plugin-free-source-license-v1` scope. It is
  collected only for a present valid C6.10 receipt and binds that receipt's
  canonical digest, exact project-source `EvidenceFileRef` set and input-set
  digest, and exact generated Rust `src/lib.rs` reference.
- Add the strict project-root `rextio.source-license.lock.json` schema 1
  (`kind: rextio.project-source-license-policy-lock`, policy
  `project-owner-exact-source-license-declaration-v1`). The closed document
  repeats the C6.10/source/output bindings, declares separate nonblank licenses
  for `project_sources` and `generated_rust`, and carries the fixed owner
  relationship, `allow` decision, local-build/package/redistribution scopes,
  and `REXTIO_PROJECT_SOURCE_LICENSE_POLICY_ACK_V1` acknowledgement.
- Use the bounded descriptor-relative, no-follow, single-link strict JSON
  reader shared with C6.11. Immediately before evidence return, rerun the C6.10
  collector with the same plan, snapshot, inventory, and embedding setting and
  require full receipt equality; only then recollect C6.12 and require full
  equality. A source, generated `src/lib.rs`, or lock change removes only
  C6.12 and rebuilds provenance without its material.
- Serialize the exact receipt in evidence and unsigned provenance and add the
  source-license lock as a separate resolved provenance material, never as a
  C6.2 input or CycloneDX component. Material-count and provenance ceilings
  omit in deterministic order C6.12, C6.11, C6.10, C6.9, C6.8, C6.7, then
  C6.6.
- Advance readiness to policy version 8 with the eleventh observation
  `scoped-project-source-license-policy-verified` and fixed
  `scoped-project-source-license-policy-verification-unavailable` blocker.
  This is an owner declaration, not proof of attestor identity, SPDX validity,
  license/NOTICE files, obligations, compatibility, source ownership,
  generated-output or derivative-work rights, legal approval, signing, global
  license policy, or distribution authority. All existing readiness blockers,
  `complete: false`, `signed: false`, and `distribution_authorized: false`
  remain unchanged. Advance only the unreleased tooling contract to **2.17.0**;
  package **0.1.4** and plugin API **1.4** remain unchanged.

### C6.13 scoped analysis-input verification

- Add an optional bounded receipt for the exact C6.10 source set's sibling
  `.pyi` observations. Every source records its sibling as exactly present or
  absent; present stubs bind logical path, byte SHA-256, size, and the
  deterministic supported-signature projection/version to the exact C6.10
  replay and source set.
- Present stubs are `project-python-stub` in-toto materials. Absent records are
  metadata observations only; raw bytes, source text, absolute roots, and
  exception text are never serialized. Secure immutable snapshots are
  evidence-eligible; compatibility snapshots on Windows or platforms without
  the required secure-open behavior remain analyzer-compatible but are
  evidence-ineligible.
- Advance readiness to policy version 9 with twelve observations and ten
  readiness checks. Missing C6.13 makes only
  `scoped-analysis-inputs-verified` unavailable with its dedicated blocker;
  malformed or forged present receipts fail the readiness assessment closed.
  `complete_for_scope` covers only the C6.10 sibling-stub scope; global
  build-input closure, reproducibility, signing, policy satisfaction, and
  distribution authorization remain false or blocked. Advance only the
  unreleased tooling contract to **2.18.0**; package **0.1.4** and plugin API
  **1.4** remain unchanged.

### C6.11 scoped Cargo component-license policy verification

- Add optional immutable
  `artifact_evidence.component_license_policy_verification` schema 1 for the
  narrow `reachable-registry-cargo-license-metadata-v1` scope. It binds the
  canonical full C6.7 inventory digest, exact sorted registry `bom_ref` set,
  exact bytes of project-root `rextio.cargo-license.lock.json`, and a canonical
  semantic snapshot of that strict JSON document. The generated path root is
  excluded from the allow rows but remains bound through the full inventory
  digest.
- Require every reachable registry component to have a nonblank raw Cargo
  metadata license value that is neither an exact nor compound unknown sentinel.
  The owner lock must reproduce every registry record verbatim and in order,
  carry `decision: allow`, the exact local-build/package/redistribution scopes,
  the fixed acknowledgement, and a closed human-owner or organization-owner
  relationship. This is metadata policy only: no SPDX parsing, normalization,
  license-file/NOTICE review, obligation or compatibility analysis, legal
  approval, authenticated attestor identity, signature, or distribution
  authorization is claimed.
- Read the fixed lock through bounded `openat`/`O_NOFOLLOW` traversal that pins
  and revalidates every absolute project-root ancestor, with regular-file,
  single-link, inode/device/time/size, UTF-8, duplicate-key, nonfinite-number,
  and JSON-depth checks. Recollect immediately before final evidence
  construction and require exact receipt equality; a missing or changed lock
  drops only C6.11 and rebuilds provenance without its material.
- Record the exact receipt in unsigned provenance and add its lock reference as
  a separate resolved material only while C6.11 is present. It is not added to
  C6.2 inputs or the SBOM. The additive ceiling now omits C6.11, C6.10, C6.9,
  C6.8, C6.7, then C6.6; material-count exhaustion caused only by the lock also
  omits C6.11 without changing the ordinary build or C6.3 gate.
- Advance readiness to policy version 7 with the tenth observation
  `scoped-component-license-policy-verified` and fixed
  `scoped-component-license-policy-verification-unavailable` blocker. The
  evidence-model binding independently reconstructs the canonical policy
  snapshot and rejects missing or compound unknown registry licenses. The
  existing global `component-license-policy-complete` check remains blocked;
  `complete`, `signed`, and `distribution_authorized` remain false. Advance
  only the unreleased tooling contract to **2.16.0**; package **0.1.4** and
  plugin API **1.4** remain unchanged.

### C6.10 scoped source-transformation replay verification

- Add optional immutable `artifact_evidence.source_transformation_verification`
  schema 1 for the narrow `project-functions-pyo3-plugin-free-v1` scope. It
  binds the canonical C6.6 inventory digest, exact project-source input set,
  canonical ModuleIR digest, complete accepted-function qualname set, and the
  captured plus independently regenerated `src/lib.rs` SHA-256/size.
- Reopen every project-owned source through bounded component-by-component
  `O_NOFOLLOW` traversal, reject symlink/hardlink/path/identity changes, parse
  the AST again, and rederive module qualname, UTF-8 byte range, and semantic
  fingerprint. Reanalyze the project with plugins, embedding, native top-level,
  runtime shims, and fallback boundary calls excluded; relower the entire
  accepted native closure and require byte-identical full Rust regeneration.
- Keep the collector total and noninterfering. Unsupported scope, mutation,
  replay mismatch, or resource-limit failure omits only C6.10; C6.6 and the
  independent C6.3 gate retain their outcomes. At the provenance ceiling omit
  C6.10 first, then C6.9, C6.8, C6.7, and C6.6.
- Advance readiness policy to version 6 with
  `scoped-source-transformation-verified` and the fixed
  `scoped-source-transformation-verification-unavailable` blocker. The receipt
  is complete only for its narrow scope; global transformation provenance,
  license policy, signatures, and distribution authorization remain blocked.
  Advance the unreleased tooling contract to **2.15.0** while keeping package
  **0.1.4** and plugin API **1.4** unchanged.

### C6.9 bounded transitive native-runtime graph observation

- Add immutable `artifact_evidence.native_runtime_transitive_closure` schema 1.
  It is rooted in the exact C6.4 subject and C6.8 direct records, serializes
  canonical packaged-content-bound nodes, deterministic name-bound/byte-unbound
  system leaves, and dependency edges, preserves cycles, and
  remains explicitly `complete: false`,
  `transitive_closure_complete: false`, and observation-only.
- Recursively inspect only exact packaged Mach-O/ELF wheel members reached by
  the existing loader-path/self-rpath or ORIGIN RPATH/RUNPATH semantics. Rebind
  every packaged node to one canonical wheel member/SHA-256/size, inspect an
  immutable private same-byte snapshot, validate object format/architecture
  (and `MH_DYLIB` for non-root Mach-O nodes), and revalidate final file receipts.
  System dependencies remain deterministic name-bound, byte-unbound terminal
  leaves; ELF leaves are rechecked against the target-triple C6.4 allowlist.
- Apply both the C6.8 path parser and C6.4 strict parser to every recursive ELF
  inspection and require identical dependency coverage, so malformed,
  unexpected, or partially parsed dynamic rows fail closed.
- Make traversal deterministic and cycle-safe with fixed node, edge, depth,
  per-dependency candidate, aggregate candidate, inspector invocation, total
  inspector-output, cooperative total-deadline, and serialized-size ceilings. Reject missing
  or multiple candidate paths, malformed inspectors, byte mutation, symlinks,
  hardlink/inode aliases, case-fold/Unicode-normalization aliases, unsupported loader forms, and
  Linux system-SONAME shadowing. Never consult ambient loader variables/cache,
  `ldd`, `ldconfig`, `dlopen`, or actual loader selection.
- Build exact and normalization-aware case-folded wheel member/basename indexes once per attempt and
  charge indexing, candidate loops, and every final receipt I/O to the single
  total deadline; synchronous filesystem reads are checked before and after but
  are not preempted mid-call. Keep the generated root's leading-underscore binary basename
  while enforcing the closed dependency basename grammar on nodes and edges.
- Keep C6.9 optional and noninterfering. A C6.9-only collection/final-receipt
  failure retains C6.8; a C6.8 failure omits both dependent observations. At
  the 2.14.0 provenance ceiling omit C6.9, then C6.8, C6.7, and C6.6; the
  cumulative 2.15.0 producer added C6.10 before that sequence, and 2.16.0 now
  omits C6.11 before C6.10. The
  independent C6.3 required-evidence gate is unchanged.
- Read-only refresh exact C6.8 packaged receipts after every C6.9 attempt. It
  requires complete prior receipt coverage, preserves exact file and non-root
  directory identity, and permits only the generated root's size/ctime/mtime
  delta caused by snapshot create/remove. Refresh failure still omits C6.8 and
  dependent C6.9. Private snapshot unlink/rmdir/absence-check failures now fail
  closed while preserving any already-active inspection exception.
- Advance readiness policy to version 5 with
  `bounded-static-native-runtime-graph-bound` and the fixed
  `bounded-static-native-runtime-graph-unavailable` blocker. Keep
  `native-runtime-transitive-closure-complete` blocked. Advance the tooling
  contract to **2.14.0** while keeping package **0.1.4**, plugin API **1.4**,
  signatures, completeness, and distribution authority unchanged.

### C6.8 one-hop native runtime path-resolution observation

- Add immutable `artifact_evidence.native_runtime_path_resolution` schema 1,
  exactly bound to the C6.4 native subject and every direct dependency in
  canonical `dependency_bom_ref` order. Records distinguish only
  `wheel-member | system-logical | unresolved` and the closed Mach-O/ELF
  mechanisms; successful evidence accepts the exact format/origin truth table
  and does not treat `unresolved` as a completed path observation.
- Resolve Mach-O packaged candidates only through contained `@loader_path` or
  `@rpath` with self `@loader_path`-anchored run paths. Resolve Linux packaged
  SONAMEs only through bounded `$ORIGIN`/`${ORIGIN}` RUNPATH or RPATH segments.
  Reject traversal, absolute/private/executable/inherited paths, unsupported
  variables and alternate load commands/tags, conflicting path tags,
  ambiguity, missing candidates, symlinks, and hash/size mismatch. Use fixed
  inspectors and pinned `O_NOFOLLOW` file receipts; never execute or load a
  candidate and never consult ambient loader state.
- Treat trusted macOS system paths and the existing Linux system-name allowlist
  as logical leaves without claiming their bytes. Keep Linux C6.4's historical
  `unresolved` origin serialization for those names; C6.8 adds the separate
  `system-logical` observation.
- Keep collection optional and noninterfering. Missing or unsafe C6.8 data
  omits only this field, adds the dedicated
  `native-runtime-path-resolution-inventory-unavailable` readiness blocker,
  and leaves ordinary builds plus C6.3 unchanged. Malformed present data fails
  readiness reconstruction closed. In the cumulative Train C producer the
  provenance ceiling omits C6.9 first, then C6.8, C6.7, and C6.6.
- Advance the always-blocked assessment to policy version 4 with
  `direct-native-path-resolution-bound`, and the unreleased tooling contract to
  **2.13.0**. Keep package **0.1.4**, plugin API **1.4**, all completeness,
  signature, and authorization fields false. Actual loader selection,
  complete transitive closure beyond C6.9's bounded graph, system-library bytes, `dlopen`, Windows PE, WASM,
  runtime-bearing plugins, complete license/legal policy, and signatures remain
  deferred.

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
  closed as well. In this preview path, packaging, executable/crate output, and
  redistribution remain unavailable; only the separate strict Full-C6/C5.2
  profile described above opens the bounded host-extension path.
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
  its provenance guard rejects writable canonical library leaves as well as
  writable directory ancestry. Ordinary e2e CI runs host `cargo test` on
  ubuntu/macOS and a loose Linux validate plus aarch64 compile-only `cargo
  check`; a separate GPU-free Windows x64 lane compiles/tests the MSVC probe
  and exercises the PowerShell wrapper and JSON non-claim contract. All
  platform paths share the
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
