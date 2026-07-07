# Feature stability

Rextio **0.1.0** is an alpha-stage release. This page is the source of truth for which features are
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
| Scalar boundary calls (`RXT075`/`RXT076`) | Stable | A marked native may call a scalar-signature fallback function in-process; loop-positioned calls (including comprehension bodies) are rejected; crossings count toward the threshold. Scalars cross by value (argument identity `is` is not preserved; `None`/`bool` singletons are), and a callee exception's traceback includes the runtime hook's frames - exception type and message stay CPython-exact. |
| `@rextio.native` / `@rextio.exempt` decorators | Stable | Public API. See [versioning](versioning.md). |
| `rextio.toml` configuration schema | Stable | Keys are part of the contract. |
| `[toolchain]` selection + version pins | Experimental | New in 0.1.0: tool paths, rustup channel, CPython targeting, strict verification pins. Semantics may be refined before the first non-alpha release. |
| Diagnostics (`RXTxxx` codes + messages) | Stable | Deterministic and tested; treated as a contract. |
| Native build orchestration (maturin / Cargo) | Stable | `cargo` is the default `[rust] build_tool` (the builder needs no extra Python dependency; Cargo itself must be on PATH or configured via `[toolchain]`). Set `--rust-build-tool=maturin` (or `[rust] build_tool = "maturin"`, requires the optional `rextio[build]` dependency) to build wheels with maturin; if maturin is selected but not installed Rextio automatically falls back to Cargo. If the native build fails, packaging still produces a fallback-only pure-Python (`py3-none-any`) wheel that works through the Python fallback. |
| Import policy — `fallback` | Stable | Treats an external package as fallback-only at the boundary. |
| Import policy — `analyze` / `try-native` | Experimental | Accepted as configuration, but largely planning metadata; concrete core-driven native lowering of external calls is not yet implemented. |
| Import policy — `plugin` | Experimental | A package covered by an installed plugin is routed through it. As of 0.1.1 an API 1.1 plugin can concretely lower covered constructs via the claim/lower hooks (see the [plugin lowering spec](specs/plugin-lowering.md)); the analyzer still decides which sites are offered and remains the acceptance authority. |

## CLI

| Command | Tier | Notes |
| --- | --- | --- |
| `rextio init` / `check` / `build` / `generate` / `clean` | Stable | Documented flags are part of the contract. |
| `rextio bench` | Stable | Prints a structured native-vs-fallback comparison; timings are not asserted. |
| `--format json` / `--verbose` / `--quiet` | Stable | Result on stdout, diagnostics on stderr. |

## Experimental

| Feature | Tier | How to reach it |
| --- | --- | --- |
| Scalar-helper embedding | Experimental | `--embed-helpers` / `[embedding] enabled`. Unmarked numeric scalar helpers (single arithmetic return expression) are embedded as internal native functions through the normal checked lowering, so overflow/divide-by-zero raise like any native code. Embedded helpers lower through the checked AOT path; there is no runtime JIT compilation. |
| Numba external accelerator | Experimental (external) | `numba.jit`/`njit`/`vectorize`/`guvectorize` decorators keep a function on the Python fallback cleanly and are labeled in reports. Semantics are Numba's contract (e.g. nopython int overflow wraps), not Rextio's native contract. `--fallback=nuitka` coexists automatically (accelerated modules are kept as plain Python); Nuitka executables and the `nuitka` hybrid runtime fail early with guidance. |
| Native `try`/`except`/`finally` (built-in exceptions) | Experimental | A restricted subset compiles to native Rust: `except` handlers for built-in exceptions only (`ValueError`, `KeyError`, `IndexError`, `ZeroDivisionError`, `TypeError`, `OverflowError`, `ArithmeticError`, `RuntimeError`, `Exception`), no `try ... else`, no `as` binding, no `return` and no `break`/`continue` targeting a loop outside the block, and no non-comprehension variable first-assigned inside a block. Anything outside the subset falls back (RXT080 shim when explicitly `@rextio.native`, otherwise Python fallback). Known limitation: if the `finally` body itself raises, the original pending exception is dropped without `__context__` chaining (CPython preserves it as the new exception's context) — an accepted divergence (see [unsupported features](unsupported-features.md)); direct-native functions containing a `finally` block carry an `RXT090` note. |
| Runtime-semantics shim (`RXT080`) | Experimental | Auto-applied to explicitly `@rextio.native` dynamic/async functions; emits a generic shim that calls back into Python. |
| Native top-level module initialization | Experimental | `[policy] native_top_level`. Lowers a restricted subset of module-level code. |
| Nuitka fallback / executable backend | Experimental | `--fallback=nuitka`, `--executable-backend=nuitka`. Requires Nuitka; surfaced by the build preflight when missing. The real-Nuitka end-to-end path runs only on the scheduled/manual CI job (not on every PR), so regressions there may surface later than for the Cargo path. |
| Build incrementality | N/A (clean rebuild) | `rextio build`/`generate` fully re-analyze, re-lower, and re-render on every invocation and reset `.rextio/build`/`.rextio/generated` first; there is no mtime- or fingerprint-based incremental caching in 0.1.1. A no-op rebuild does the full work. Reports (`build.json`/`generate.json`/`check.json`) are reset each run so only the current command's reports remain. |
| Hybrid runtime `__file__` | Experimental (limitation) | The subprocess-hybrid executable backend copies the project's Python source into `<binary>.runtime/`, so a delegated fallback function's `__file__` points at the copied tree, not the original source. Code that resolves data files relative to `__file__` (e.g. `Path(__file__).parent / "data"`) will not find them there; keep such data-dependent functions native, or use the source hybrid runtime against the original tree. |
| Rust-importable crate artifact | Experimental | `--rust-importable` / `--rust-crate-name`. Exposes accepted direct-Rust functions as a Cargo path dependency. |
| Plugins | Experimental | Entry-point plugins declare target compatibility and the external packages they cover. Protocol v2 (see [the tooling contract](specs/tooling-contract.md)) lets a plugin additionally *self-describe* declarative rule records via `describe()`/`covers()` — surfaced in `rextio capabilities` with `RXTP-<PLUGIN>-NNN` diagnostic namespacing, and enabling the informational RXT091 plugin-lowerable hint on accelerator-decorated functions. A plugin API 1.1 plugin may also lower covered constructs through the claim/lower hooks ([plugin lowering spec](specs/plugin-lowering.md)); the analyzer decides which sites are offered and remains the acceptance authority. |
| Tooling-contract JSON fields | Experimental | `rextio check --format json` (and `.rextio/reports/check.json`) carries a top-level `contract_version` plus per-function `route`, `native_status`, and `rejection_codes`, as specified in [the tooling contract](specs/tooling-contract.md). Additive today; the shape may be refined until the contract is promoted to stable. |
| `rextio capabilities` command | Experimental | Prints the config-resolved capability manifest from [the tooling contract](specs/tooling-contract.md): the supported type matrix, the core rule records (constraint + diagnostic code + guidance per rule), a `config_fingerprint` for consumer caching, and the active plugins. Core rules only until plugin protocol v2 lands; introspection-only (no source analysis, no report files). |

## Planned (not implemented)

| Feature | Tier | Notes |
| --- | --- | --- |
| Additional native target languages | Planned | `native_backend` accepts only `rust` in 0.1.0; any other value is rejected at configuration load with a clear error. |

If a feature you depend on is **Experimental**, pin your Rextio version and watch the
changelog; if it is **Planned**, expect a diagnostic rather than a build.
