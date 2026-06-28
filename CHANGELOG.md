# Changelog

## 0.1.0 alpha

Initial public MVP for Rextio as a local hybrid build tool.

### Added

- CLI commands: `rextio init`, `rextio check`, `rextio build`, `rextio bench`, and `rextio clean`.
- Source-only generation command: `rextio generate`.
- Automatic native discovery for eligible typed module-level Python functions, with `@rextio.native` still supported and decorator-only mode available.
- `@rextio.exempt` decorator for functions that must remain Python fallback.
- Conservative 0.1.0 alpha subset checks for supported scalar/list types, simple control flow, indexing, and native-to-native calls.
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
- Runtime controls: `REXTIO_DISABLE_NATIVE=1` and `REXTIO_NATIVE_MODE`.
- Runtime boundary fallback threshold for repeated Python-to-native wrapper crossings.
- `--fallback-threshold` for embedding a generated-code default threshold in `rextio build` and `rextio generate`.
- Generated hybrid artifact wheel under `dist/`.
- Zipapp executable artifact generation with `rextio build --entrypoint=module:function`.
- Nuitka standalone/onefile executable artifact generation with `--executable-backend=nuitka`.
- Mirrored build and analysis settings across CLI parameters, environment variables, and `rextio.toml`.
- Target planning metadata for future Rust/Mojo/Julia backends and installed package plugins.
- Experimental opt-in native-side Cranelift JIT for narrow scalar helper
  regions represented in Rextio IR, with `--jit`, `REXTIO_JIT`, and `[jit]`
  configuration controls.
- Python runtime semantics native shim (`RXT080`) for compatibility coverage of
  object behavior, marked instance methods, exceptions, context managers,
  async functions, generators, and dynamic attribute access.
- Limited direct Rust lowering for expanded builtin and standard-library
  patterns including `math`, `all`/`any`, `sorted`/`reversed`, selected
  `str`/`bytes`/`list` methods, `statistics`, `time`/`datetime`,
  `hashlib.sha256`, `base64`, and `json`.
- Conservative Python/Rust ownership handling for direct Rust lowering:
  generated clones for reused owned values and fallback diagnostics for mutable
  collection alias mutation.
- Feature-oriented README and example documentation that explains generated
  artifacts, native/fallback behavior, executable outputs, and Rust-importable
  crate usage.
- Example projects for pure math, application-shell scoring, fallback safety, and boundary diagnostics.
- Focused end-to-end tests for build/import/runtime behavior, real Cargo builds, generated wheels, and Nuitka when installed.

### Changed

- Generated sequence indexing now preserves Python semantics: a negative index
  counts from the end (`xs[-1]`), and an out-of-range index raises `IndexError`
  instead of triggering an unchecked Rust panic.
- Generated native crates are compiled with `overflow-checks = true`, so i64
  integer overflow raises a Python exception (Python ints are arbitrary
  precision) instead of silently wrapping in release builds.
- Removed the unused `crates/rextio_runtime` helper crate; generated code inlines
  its bounds-checked access, so the crate was never wired into any build.
- The Python runtime-semantics shim (`RXT080`) is now strictly opt-in. Only
  functions explicitly marked `@rextio.native` are promoted to the shim.
  Auto-discovered (undecorated) functions are accepted only within the
  direct-Rust subset, and an undecorated function that depends on a runtime-shim
  native is now reported with `RXT074` and left on the Python fallback path.
  - Migration: if a previously auto-accepted dynamic function (or a caller of a
    runtime-shim native) regressed to Python fallback, add `@rextio.native` to
    opt back into the runtime-semantics shim.

### Notes

0.1.0 alpha is intentionally narrow. It does not provide full Python
compatibility, bundled third-party package support, framework migration,
general-purpose Python JIT behavior, or full runtime boundary-cost optimization.
The Cranelift path is experimental, opt-in, native-side only, and limited to
small scalar helper regions.
