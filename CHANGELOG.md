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

- Generated `str` literals are now escaped into always-valid Rust (non-ASCII is
  emitted literally rather than as `\uXXXX`, which Rust rejects), fixing
  uncompilable output for string constants containing non-ASCII characters;
  escaping remains injection-safe. The same escaper is now the single funnel for
  every Python-string-to-Rust-literal path — plain `str` constants, the
  runtime-semantics shim's fallback module/attr names, logging format strings,
  and the unbound-local error message (which embeds a possibly non-ASCII variable
  name) — and lone surrogates, which a Python `str` can hold but Rust cannot
  represent, are rejected with a clear diagnostic instead of producing
  unencodable output.
- External build tools (`cargo`/`maturin`/`nuitka`) are invoked through a shared
  no-shell, bounded-timeout helper, so a hung toolchain fails the build with a
  clear message instead of blocking indefinitely.
- Added `SECURITY.md` (threat model + protections) and a `check-wheel-contents`
  packaging gate in CI.
- Internal refactor (no behavior change): the two largest modules were split into
  cohesive units guarded by the golden-snapshot and contract suites —
  `codegen/rust/generator.py` shed its formatting helpers (`rust_format`),
  checked-arithmetic emitter (`checked_arith`), shared error type (`errors`), and
  Cranelift JIT helpers (`jit_codegen`); `analyzer/unsupported_patterns.py` shed
  its stateless type/AST predicates (`type_predicates`).
- The supported-type capability matrix (scalar/list/dict/set item/key types) is
  now defined once in `rextio.capabilities` and shared by the analyzer and the
  Rust backend, replacing duplicated constants that could drift apart. No
  behavior change; a consistency test asserts every registered type has a Rust
  mapping.
- Generated sequence indexing now preserves Python semantics: a negative index
  counts from the end (`xs[-1]`), and an out-of-range index raises `IndexError`
  instead of triggering an unchecked Rust panic.
- Generated integer `+`/`-`/`*`/`%`, unary negation, and the `abs`/`sum`
  builtins now use checked arithmetic (`checked_add`/`checked_sub`/`checked_mul`/
  `checked_rem`/`checked_neg`/`checked_abs` and a checked `sum` fold): an i64
  overflow raises `OverflowError` (PyO3) / returns a `RextioError` (Rust-
  importable crate) instead of silently wrapping or panicking, and a modulo by
  zero raises `ZeroDivisionError`. Integer `%` also follows Python's floored
  semantics (the result takes the divisor's sign, e.g. `-7 % 3 == 2`) rather
  than Rust's truncated remainder. Python ints are arbitrary precision, so this
  preserves Python semantics, and these are catchable `Exception`s (unlike the
  uncatchable PyO3 `PanicException` a raw overflow panic produces). The
  guarantee travels with the generated code, so it holds even when the Rust-
  importable crate is consumed as a dependency (where a `[profile.release]`
  setting would be ignored). Release builds also keep `overflow-checks = true`
  as a safety-net backstop for any arithmetic not covered by the checked path;
  it is not part of the catchable-exception contract.
- Generated float division and modulo now preserve Python semantics: `x / 0.0`
  and `x % 0.0` raise `ZeroDivisionError` (instead of Rust's silent `inf`/`NaN`),
  and float `%` is floored (the result takes the divisor's sign, e.g.
  `-7.0 % 3.0 == 2.0`) rather than Rust's truncated `fmod`. When the remainder is
  exactly zero it takes the divisor's sign (`copysign(0.0, b)`), matching CPython.
- `math.floor`/`ceil`/`trunc` now convert through a guarded float-to-int helper:
  a value outside i64 range raises `OverflowError` and `NaN` raises `ValueError`,
  instead of silently saturating to `i64::MIN`/`MAX` via an `as i64` cast.
- The experimental Cranelift JIT no longer accepts integer helpers that contain
  overflow-prone arithmetic: the JIT path emits wrapping instructions and cannot
  raise `OverflowError`, so such helpers stay on the checked native path. Float
  scalar helpers remain JIT-eligible.
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
