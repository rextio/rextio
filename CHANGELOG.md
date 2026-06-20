# Changelog

## 0.1.0 - Public 1

Initial public MVP for Rextio as a local hybrid build tool.

### Added

- CLI commands: `rextio init`, `rextio check`, `rextio build`, `rextio bench`, and `rextio clean`.
- Source-only generation command: `rextio generate`.
- Explicit `@rextio.native` detection for typed module-level Python functions.
- Conservative Public 1 subset checks for supported scalar/list types, simple control flow, indexing, and native-to-native calls.
- Deterministic diagnostics for unsupported syntax, dynamic Python features, external calls, and unsafe boundaries.
- Static boundary policy:
  - reject native functions that call fallback-only functions;
  - reject native functions that depend on rejected native candidates;
  - warn when fallback Python loops call native functions repeatedly.
- Rextio IR lowering and deterministic Rust/PyO3 code generation for accepted native functions.
- Cargo and maturin build orchestration with Cargo fallback when maturin is unavailable.
- CPython fallback packaging and generated wrappers that preserve fallback behavior.
- Experimental Nuitka fallback packaging with clear unavailable-tool reporting.
- Runtime controls: `REXTIO_DISABLE_NATIVE=1` and `REXTIO_NATIVE_MODE`.
- Generated hybrid artifact wheel under `dist/`.
- Example projects for pure math, FastAPI scoring, fallback safety, and boundary diagnostics.
- Focused end-to-end tests for build/import/runtime behavior, real Cargo builds, generated wheels, and Nuitka when installed.

### Notes

Public 1 is intentionally narrow. It does not provide full Python compatibility,
NumPy/pandas support, framework migration, JIT behavior, or runtime boundary-cost
optimization.
