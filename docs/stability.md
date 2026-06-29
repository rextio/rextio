# Feature stability

Rextio is **0.1.0 alpha**. This page is the source of truth for which features are
covered by the [versioning policy](versioning.md)'s stability promises and which are
experimental (correct-but-incomplete, and free to change).

Tiers:

- **Stable** — part of the public contract, governed by the
  [versioning policy](versioning.md): a breaking change to a Stable feature may still
  land in a `0.MINOR` release (this is `0.x`), but it is deprecation-warned where
  possible and always called out in the [changelog](../CHANGELOG.md).
- **Experimental** — usable but incomplete; behavior, flags, and output may change in
  any release with no deprecation period. Most are off by default and opt-in.
- **Planned** — recognized by config/validation but not implemented; using it is
  rejected with a clear diagnostic, not silently mis-built.

## Core

| Feature | Tier | Notes |
| --- | --- | --- |
| Direct-Rust codegen for the typed subset (PyO3) | Stable | Scalars, lists, simple control flow, indexing, native↔native calls. Anything outside the subset is rejected (`RXTxxx`) or kept on fallback. |
| CPython fallback packaging + generated wrappers | Stable | Preserves Python semantics for everything not lowered to native. |
| `@rextio.native` / `@rextio.exempt` decorators | Stable | Public API. See [versioning](versioning.md). |
| `rextio.toml` configuration schema | Stable | Keys are part of the contract. |
| Diagnostics (`RXTxxx` codes + messages) | Stable | Deterministic and tested; treated as a contract. |
| Native build orchestration (maturin / Cargo) | Stable | `cargo` is the default `[rust] build_tool` (always available). Set `--rust-build-tool=maturin` (or `[rust] build_tool = "maturin"`, requires the optional `rextio[build]` dependency) to build wheels with maturin; if maturin is selected but not installed Rextio automatically falls back to Cargo. |
| Import policy — `fallback` | Stable | Treats an external package as fallback-only at the boundary. |
| Import policy — `analyze` / `try-native` / `plugin` | Experimental | Accepted as configuration, but in 0.1.0 alpha these are largely planning metadata; concrete third-party native lowering is not yet implemented. |

## CLI

| Command | Tier | Notes |
| --- | --- | --- |
| `rextio init` / `check` / `build` / `generate` / `clean` | Stable | Documented flags are part of the contract. |
| `rextio bench` | Stable | Prints a structured native-vs-fallback comparison; timings are not asserted. |
| `--format json` / `--verbose` / `--quiet` | Stable | Result on stdout, diagnostics on stderr. |

## Experimental

| Feature | Tier | How to reach it |
| --- | --- | --- |
| Cranelift scalar JIT | Experimental | `--jit` / `[jit] enabled`. Numeric scalar helpers only; overflow-prone integer arithmetic and float division are excluded (they stay on the checked native path so overflow/divide-by-zero still raise). |
| Runtime-semantics shim (`RXT080`) | Experimental | Auto-applied to explicitly `@rextio.native` dynamic/async functions; emits a generic shim that calls back into Python. |
| Native top-level module initialization | Experimental | `[policy] native_top_level`. Lowers a restricted subset of module-level code. |
| Nuitka fallback / executable backend | Experimental | `--fallback=nuitka`, `--executable-backend=nuitka`. Requires Nuitka; surfaced by the build preflight when missing. The real-Nuitka end-to-end path runs only on the scheduled/manual CI job (not on every PR), so regressions there may surface later than for the Cargo path. |
| Rust-importable crate artifact | Experimental | `--rust-importable` / `--rust-crate-name`. Exposes accepted direct-Rust functions as a Cargo path dependency. |
| Plugins | Experimental (metadata-only) | Entry-point plugins declare target compatibility and the external packages they cover; they do **not** inject codegen rules. |

## Planned (not implemented)

| Feature | Tier | Notes |
| --- | --- | --- |
| `mojo` target language | Planned | Configurable (`native_backend = "mojo"`) but no codegen backend yet — rejected with `RXT050`. |
| `julia` target language | Planned | Same as above. |

If a feature you depend on is **Experimental**, pin your Rextio version and watch the
changelog; if it is **Planned**, expect a diagnostic rather than a build.
