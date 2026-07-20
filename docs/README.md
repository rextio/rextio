# Rextio documentation

An index of the project's documentation. See the top-level
[README](../README.md) for the feature overview and quick start.

## Guides

- [Feature stability](stability.md) — the Stable / Experimental / Planned tier table
  for every feature in the 0.1.x line.
- [Versioning policy](versioning.md) — SemVer with the pre-1.0 caveats and the
  definition of the public contract.
- [Unsupported features](unsupported-features.md) — the boundaries of the 0.1.x
  supported subset (published package: **0.1.4** / plugin API 1.3).
- [Host source-AOT and native executables](source-aot-and-executables.md) —
  **unreleased Release Train C** source graph, `ModuleInitIR`, artifact profile,
  explicit executable fallback, narrow initializer-before-main boundary, and
  the C5.1 external-distribution inventory/build gate.

## Specs

- [Machine-readable tooling contract](specs/tooling-contract.md) — draft
  (current published producer `contract_version` `2.2.0` on core 0.1.4; core 0.1.3
  emitted `2.1.0`; core 0.1.2 emitted `2.0.0`; `1.0.0` was PyPI 0.1.1): route
  taxonomy, `check --json`
  extensions, the `capabilities --json` manifest, and the plugin
  self-description protocol consumed by agent skills, LSP, and editor tooling.
  **Strict publish order for the 0.1.2 line:** rextio-lsp 0.1.1 → core 0.1.2 →
  rextio-numpy 0.1.1 (not simultaneous). Core **0.1.3** (published 2026-07-17)
  advances the contract to `2.1.0` (additive shape; same major) and ships
  plugin API 1.3. Release Train B then completed consumer first — rextio-lsp
  0.1.2 → core 0.1.4 — and advances the contract to `2.2.0`.
  The **unreleased** Train C branch advances additively through `2.3.0` host
  source/artifact/executable planning and `2.4.0` standalone plugin capability
  to `2.5.0` sanitized external-source preview evidence, `2.6.0` C6.1
  authorization-contract evidence, `2.7.0` C6.2 host-extension wheel evidence,
  `2.8.0` C6.3 required-evidence gate, `2.9.0` C6.4 sanitized direct native
  runtime linkage inventory for macOS/Linux, `2.10.0` C6.5 always-blocked
  distribution-authorization readiness, `2.11.0` C6.6 bounded
  source-transformation observation, `2.12.0` C6.7 component-license
  observation, `2.13.0` C6.8 one-hop native path-resolution observation, and
  `2.14.0` C6.9 bounded static native-runtime graph observation, and current
  `2.15.0` C6.10 scoped source-transformation replay verification;
  published 0.1.4
  remains the 2.2.0 producer.
- [Plugin lowering](specs/plugin-lowering.md) — draft (0.1.1+; plugin API 1.1
  on PyPI 0.1.1, **1.2** additive on published 0.1.2, and **1.3** on published
  0.1.3 and retained in 0.1.4): the claim/lower hook that lets plugins translate
  covered constructs to Rust — plugin annotation vocabulary, expression-level
  codegen contract, boundary ABI, pinned crate injection with consent and report
  exposure, structured `ClaimExpr` / leaves-mode fusion surface, and the plugin
  certification kit.
- [Device-provider API draft](specs/device-provider.md) — non-operational Train
  C separation between domain lowering and future hardware/runtime providers;
  there is no discovery, build/link hook, or support claim.

## Testing guides

- [CUDA Driver API inventory validation](testing/cuda-driver-validation.md) —
  Windows+Linux bounded Driver API inventory instructions. Every report carries
  `support_claim: false`; this is not CUDA execution support.

## Project

- [Contributing](../CONTRIBUTING.md) — development setup, quality gates, conventions.
- [Code of Conduct](../CODE_OF_CONDUCT.md).
- [Security model](../SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Changelog](../CHANGELOG.md).
