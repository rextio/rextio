# Rextio documentation

An index of the project's documentation. See the top-level
[README](../README.md) for the feature overview and quick start.

## Guides

- [Feature stability](stability.md) — the Stable / Experimental / Planned tier table
  for every feature in the 0.1.x line.
- [Versioning policy](versioning.md) — SemVer with the pre-1.0 caveats and the
  definition of the public contract.
- [Unsupported features](unsupported-features.md) — the boundaries of the 0.1.x
  supported subset (published package: **0.1.8** / plugin API 1.7).
- [Host source-AOT and native executables](source-aot-and-executables.md) —
  **0.1.5 Experimental Release Train C** source graph, `ModuleInitIR`, artifact
  profile,
  explicit executable fallback, narrow initializer-before-main boundary, and
  the external-source preview plus the frozen strict artifact-contract
  technical template,
  owner-completion/finalization, cache-free host, public support-lock
  bootstrap, path-tokenized semantic production-sandbox receipts, mutable-host
  executable-map denial with explicit capability-only regrant,
  source-archive/output alias closure, domain-separated signing, and seven-file
  atomic-publication Alpha. The cache-free gate protects evidence
  integrity in an owner-controlled process; it rejects both declared and actual
  installed-tree aggregates above 256 MiB and is not hostile secure boot.

## Specs

- [Machine-readable tooling contract](specs/tooling-contract.md) — draft
  (current published producer `contract_version` `3.0.0` on core 0.1.8;
  core 0.1.7 emitted `2.28.0`; core 0.1.6
  emitted `2.27.0`; core 0.1.5
  emitted `2.24.0`; core 0.1.4
  emitted `2.2.0`; core 0.1.3
  emitted `2.1.0`; core 0.1.2 emitted `2.0.0`; `1.0.0` was PyPI 0.1.1): route
  taxonomy, `check --json`
  extensions, the `capabilities --json` manifest, and the plugin
  self-description protocol consumed by agent skills, LSP, and editor tooling.
  **Strict publish order for the 0.1.2 line:** rextio-lsp 0.1.1 → core 0.1.2 →
  rextio-numpy 0.1.1 (not simultaneous). Core **0.1.3** (published 2026-07-17)
  advances the contract to `2.1.0` (additive shape; same major) and ships
  plugin API 1.3. Release Train B then completed consumer first — rextio-lsp
  0.1.2 → core 0.1.4 — and advances the contract to `2.2.0`.
  Core 0.1.5 publishes contract `2.24.0`, incorporating unpublished/internal
  contract steps for host source/artifact/executable planning, standalone
  plugin capability, sanitized external-source planning and authorization,
  bounded host-extension evidence, required-evidence gating, native-runtime
  inventory, source and license observations, scoped verification, and the
  frozen strict artifact-contract authority/executor/signing/publication
  workflow. It includes the exact technical-template and owner-completion
  handoff, public support-lock bootstrap, path-free sandbox/support receipts,
  mutable-volume executable-map denial with explicit bound-capability regrant,
  and exact/ancestor/descendant protection between its output and every
  configured source archive. It also
  defines the strict lifecycle report, authorization-request, detached-signature,
  publication-manifest, and policy-finalizer JSON shapes;
  published 0.1.5 is the 2.24.0 producer with plugin API 1.4 and readiness
  policy 11.

  Core 0.1.6 publishes contract `2.27.0`: the unpublished/internal `2.25.0`
  comparison/result-only-resident shape, the `2.26.0` selected Device Provider
  API 1 planning/preflight/build shape, and the final `2.27.0` static
  device-domain lowering authorization. It publishes plugin API 1.6 and retains
  readiness policy 11. These contracts do not themselves claim CUDA framework
  support or certified accelerator execution.

  Core 0.1.7 publishes contract `2.28.0` and plugin API **1.7**: optional
  function-scope RAII guards for used plugins on accepted generated native
  functions. Pre-1.7 providers keep load and generated-output behavior.

  Core 0.1.8 publishes contract `3.0.0`: milestone-derived artifact report,
  lifecycle, persisted-file, and signing names become semantic
  `artifact-*` identities. Exact 0.1.7 persisted roots remain legacy
  read/verify-only; mixed or newly emitted legacy dialects fail closed.

Train C shipped in core 0.1.5 as Experimental/Alpha. Its evidence and local
artifact-publication authority remain bounded and do not imply general package
AOT, general hermeticity, CUDA support, or heavy host-lifecycle CI
certification. The complete macOS arm64 local installed-wheel lifecycle
through `f9eb5e6` is
historical evidence. The subsequent installed-input and 2.24.0 support-lock /
sandbox work is unit-tested; evidence for the current `HEAD` on macOS arm64 and
Linux x86_64 now requires
`python scripts/validate-artifact-contract-host.py` on the target host and is
not CI-certified. One local
macOS support closure measured roughly 104,645 members / 2.67 GB and about
45 seconds per full verification; those figures are observations, not
guarantees.

- [Plugin lowering](specs/plugin-lowering.md) — draft (0.1.1+; plugin API 1.1
  on PyPI 0.1.1, **1.2** additive on published 0.1.2, and **1.3** on published
  0.1.3 and retained in 0.1.4, **1.4** published in core 0.1.5, **1.6**
  published in core 0.1.6, and **1.7** published in core 0.1.7): the
  claim/lower hook that lets plugins translate
  covered constructs to Rust — plugin annotation vocabulary, expression-level
  codegen contract, boundary ABI, pinned crate injection with consent and report
  exposure, structured `ClaimExpr` / leaves-mode fusion surface, and the plugin
  certification kit.
- [Device Provider API 1](specs/device-provider.md) — bounded Experimental
  provider selection, entry-point discovery, preflight, lock/report, and
  native-library build wiring, separated from plugin-owned domain lowering.
  Unmaterialized contribution classes fail closed and every preflight remains
  non-certifying with `support_claim: false`.

## Testing guides

- [CUDA Driver API inventory validation](testing/cuda-driver-validation.md) —
  repository-only Windows+Linux bounded Driver API inventory instructions; the
  probe is not installed by the PyPI package. Every report carries
  `support_claim: false`; this is not CUDA execution support.

## Project

- [Contributing](../CONTRIBUTING.md) — development setup, quality gates, conventions.
- [Code of Conduct](../CODE_OF_CONDUCT.md).
- [Security model](../SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Changelog](../CHANGELOG.md).
