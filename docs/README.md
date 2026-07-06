# Rextio documentation

An index of the project's documentation. See the top-level
[README](../README.md) for the feature overview and quick start.

## Guides

- [Feature stability](stability.md) — the Stable / Experimental / Planned tier table
  for every feature in 0.1.0.
- [Versioning policy](versioning.md) — SemVer with the pre-1.0 caveats and the
  definition of the public contract.
- [Unsupported features](unsupported-features.md) — the boundaries of the 0.1.0
  supported subset.

## Specs

- [Machine-readable tooling contract](specs/tooling-contract.md) — draft (0.1.1):
  route taxonomy, `check --json` extensions, the `capabilities --json` manifest,
  and the plugin self-description protocol consumed by agent skills, LSP, and
  editor tooling.
- [Plugin lowering](specs/plugin-lowering.md) — draft (0.1.1, plugin API 1.1):
  the claim/lower hook that lets plugins translate covered constructs to Rust —
  plugin annotation vocabulary, expression-level codegen contract, boundary ABI,
  pinned crate injection with consent and report exposure, and the plugin
  certification kit.

## Project

- [Contributing](../CONTRIBUTING.md) — development setup, quality gates, conventions.
- [Code of Conduct](../CODE_OF_CONDUCT.md).
- [Security model](../SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Changelog](../CHANGELOG.md).
