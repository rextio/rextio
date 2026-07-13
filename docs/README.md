# Rextio documentation

An index of the project's documentation. See the top-level
[README](../README.md) for the feature overview and quick start.

## Guides

- [Feature stability](stability.md) — the Stable / Experimental / Planned tier table
  for every feature in the 0.1.x line.
- [Versioning policy](versioning.md) — SemVer with the pre-1.0 caveats and the
  definition of the public contract.
- [Unsupported features](unsupported-features.md) — the boundaries of the 0.1.0
  supported subset.

## Specs

- [Machine-readable tooling contract](specs/tooling-contract.md) — draft
  (producer `contract_version` `2.0.0` on the 0.1.2 line; `1.0.0` was PyPI
  0.1.1): route taxonomy, `check --json` extensions, the
  `capabilities --json` manifest, and the plugin self-description protocol
  consumed by agent skills, LSP, and editor tooling. Dual-map rextio-lsp
  0.1.1 must deploy before or with core 0.1.2.
- [Plugin lowering](specs/plugin-lowering.md) — draft (0.1.1+; plugin API 1.1
  on PyPI 0.1.1, **1.2** additive on the 0.1.2 line): the claim/lower hook
  that lets plugins translate covered constructs to Rust — plugin annotation
  vocabulary, expression-level codegen contract, boundary ABI, pinned crate
  injection with consent and report exposure, structured `ClaimExpr` /
  leaves-mode fusion surface, and the plugin certification kit.

## Project

- [Contributing](../CONTRIBUTING.md) — development setup, quality gates, conventions.
- [Code of Conduct](../CODE_OF_CONDUCT.md).
- [Security model](../SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Changelog](../CHANGELOG.md).
