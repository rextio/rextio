# Rextio documentation

An index of the project's documentation. See the top-level
[README](../README.md) for the feature overview and quick start.

## Guides

- [Feature stability](stability.md) — the Stable / Experimental / Planned tier table
  for every feature in the 0.1.x line.
- [Versioning policy](versioning.md) — SemVer with the pre-1.0 caveats and the
  definition of the public contract.
- [Unsupported features](unsupported-features.md) — the boundaries of the 0.1.x
  supported subset (published package: **0.1.5** / plugin API 1.4).
- [Host source-AOT and native executables](source-aot-and-executables.md) —
  **0.1.5 Experimental Release Train C** source graph, `ModuleInitIR`, artifact
  profile,
  explicit executable fallback, narrow initializer-before-main boundary, and
  the C5.1 preview plus the frozen Full-C6/C5.2 public technical-template,
  owner-completion/finalization, cache-free host, public support-lock
  bootstrap, path-tokenized semantic production-sandbox receipts, mutable-host
  executable-map denial with explicit capability-only regrant,
  source-archive/output alias closure, domain-separated signing, and seven-file
  atomic-publication Alpha. The cache-free gate protects evidence
  integrity in an owner-controlled process; it rejects both declared and actual
  installed-tree aggregates above 256 MiB and is not hostile secure boot.

## Specs

- [Machine-readable tooling contract](specs/tooling-contract.md) — draft
  (current published producer `contract_version` `2.24.0` on core 0.1.5; core 0.1.4
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
  intermediate contract `2.3.0` host source/artifact/executable planning and
  `2.4.0` standalone plugin capability
  to `2.5.0` sanitized external-source preview evidence, `2.6.0` C6.1
  authorization-contract evidence, `2.7.0` C6.2 host-extension wheel evidence,
  `2.8.0` C6.3 required-evidence gate, `2.9.0` C6.4 sanitized direct native
  runtime linkage inventory for macOS/Linux, `2.10.0` C6.5 always-blocked
  distribution-authorization readiness, `2.11.0` C6.6 bounded
  source-transformation observation, `2.12.0` C6.7 component-license
  observation, `2.13.0` C6.8 one-hop native path-resolution observation, and
  `2.14.0` C6.9 bounded static native-runtime graph observation,
  `2.15.0` C6.10 scoped source-transformation replay verification,
  `2.16.0` C6.11 scoped Cargo component-license policy verification,
  `2.17.0` C6.12 scoped project-source license-policy verification,
  `2.18.0` C6.13 scoped analysis-input verification, `2.19.0` C6.14 compact
  artifact-policy coverage inventory, `2.20.0` C6.15 scoped artifact-class
  policy verification, `2.21.0` strict Full-C6 authority/executor/signing/
  atomic-publication primitives, `2.22.0` bounded C5.2 linkage and initial CLI
  coordination, historical `2.23.0` exact technical-template/bootstrap v2 plus
  explicit owner completion and `rextio policy finalize` handoff, and current
  `2.24.0` public support-lock bootstrap plus path-free semantic
  sandbox/support receipt surfaces, mutable-volume executable-map denial with
  explicit bound-capability regrant, and exact/ancestor/descendant protection
  between its output and every configured source archive. It also
  defines the strict lifecycle report, authorization-request, detached-signature,
  publication-manifest, and policy-finalizer JSON shapes;
  published 0.1.5 is the 2.24.0 producer with plugin API 1.4 and readiness
  policy 11.

Train C shipped in core 0.1.5 as Experimental/Alpha. Its evidence and local
artifact-publication authority remain bounded and do not imply broad Full C6,
general package AOT, general hermeticity, CUDA support, or heavy host-lifecycle
CI certification. The complete macOS arm64 local installed-wheel lifecycle
through `f9eb5e6` is
historical evidence. The subsequent installed-input and 2.24.0 support-lock /
sandbox work is unit-tested; evidence for the current `HEAD` on macOS arm64 and
Linux x86_64 now requires `python scripts/validate-full-c6-host.py` on the target
host and is not CI-certified. One local
macOS support closure measured roughly 104,645 members / 2.67 GB and about
45 seconds per full verification; those figures are observations, not
guarantees.

- [Plugin lowering](specs/plugin-lowering.md) — draft (0.1.1+; plugin API 1.1
  on PyPI 0.1.1, **1.2** additive on published 0.1.2, and **1.3** on published
  0.1.3 and retained in 0.1.4, with **1.4** published in core 0.1.5): the
  claim/lower hook that lets plugins translate
  covered constructs to Rust — plugin annotation vocabulary, expression-level
  codegen contract, boundary ABI, pinned crate injection with consent and report
  exposure, structured `ClaimExpr` / leaves-mode fusion surface, and the plugin
  certification kit.
- [Device-provider API draft](specs/device-provider.md) — non-operational Train
  C separation between domain lowering and future hardware/runtime providers;
  there is no discovery, build/link hook, or support claim.

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
