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
- Configurable external build-tool timeout via `--build-timeout`,
  `REXTIO_BUILD_TIMEOUT`, and `[build] build_timeout_seconds` (CLI > env > toml >
  default, default 600s).
- Generated hybrid artifact wheel under `dist/`.
- Zipapp executable artifact generation with `rextio build --entrypoint=module:function`.
- Nuitka standalone/onefile executable artifact generation with `--executable-backend=nuitka`.
- Native Rust binary executable generation with `--executable-backend=rust`: a
  native executable whose `main` calls a direct-native `def main(argv: list[str])
  -> int` entrypoint, mirrors `sys.argv`, uses the returned `int` as the process
  exit code, and prints a returned error CPython-style (`TypeName: message`) to
  stderr. The crate-mode `RextioError` now carries the CPython exception type name
  so these binaries emit Python-style diagnostics.
- Subprocess hybrid for the Rust executable: a call the entrypoint makes to a
  project function that stays on the Python fallback is delegated to an external
  CPython process (a generated dispatcher + the project source shipped as
  `dist/<binary>.runtime/`, driven over a JSON stdio protocol) instead of being
  rejected, so hard-to-compile-to-Rust logic can be "left as Python." The
  delegated function runs real CPython (result is CPython-equivalent, exceptions
  forwarded CPython-style); wire types are scalars/`None`/`list` of those. A hybrid
  binary needs a Python interpreter at runtime; a fully-direct-native binary
  remains standalone. `--executable-python` (`[executable] python`,
  `REXTIO_EXECUTABLE_PYTHON`) pins the interpreter the binary launches (bare name,
  absolute path, or a path relative to `<binary>.runtime` to bundle one).
  `--hybrid-runtime=nuitka` (`[executable] hybrid_runtime`, `REXTIO_HYBRID_RUNTIME`)
  instead ships the delegated Python as a self-contained Nuitka-compiled dispatcher
  executable, so no separate Python install is needed at runtime (requires Nuitka
  at build time).
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
- Global CLI output options on every command: `--format text|json`, and mutually
  exclusive `-v/--verbose` and `-q/--quiet`. All commands now emit their result on
  stdout (text or JSON) while diagnostics and configuration errors go to stderr, so
  a `--format json` run produces clean machine-parseable stdout.
- Project documentation and governance: a `CONTRIBUTING.md` guide, GitHub issue forms
  and a pull-request template, a feature-stability table (`docs/stability.md`) and a
  versioning policy (`docs/versioning.md`) documenting the SemVer pre-1.0 stance and
  what is stable versus experimental.

### Changed

- `@rextio.native` now validates its `target` against the supported languages
  (rust/mojo/julia) and both `@rextio.native`/`@rextio.exempt` reject classes and
  non-callables, surfacing typos and misuse at decoration time instead of silently.
- Plugins are now explicitly metadata-only: the unused `RextioPlugin.rules` field
  (which never affected lowering) is removed; a legacy `rules` key from an older
  plugin is accepted and ignored so installed plugins keep loading.

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
  clear message instead of blocking indefinitely. On timeout the helper now
  terminates the whole process tree (POSIX process-group / Windows
  `CREATE_NEW_PROCESS_GROUP`), so child `rustc`/linker/`python` processes spawned
  by the tool are not left running.
- A native candidate's function name, parameters, and locals that collide with a
  Rust keyword (`fn`, `match`, `type`, …) are now carried as raw identifiers
  (`r#match`), so the function stays native instead of failing to compile. Only
  the keywords a raw identifier cannot express (`crate`/`self`/`Self`/`super`) and
  non-ASCII names are kept on the Python fallback path with `RXT011`. The
  function's own name is validated too, closing a gap where a root-package
  function named after a keyword emitted uncompilable Rust.
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
- Hardened the native subset checker so a batch of patterns that were accepted as
  direct-Rust but emitted wrong or uncompilable Rust are now kept off the
  direct-native path (rejected to the Python fallback, or routed to the `RXT080`
  runtime shim) — preserving the contract that an accepted function is either
  CPython-equivalent or rejected, never silently mis-compiled. Newly rejected:
  non-`bool` `if`/`while`/comprehension conditions; multiple assignment
  (`a = b = ...`); integer literals outside the `i64` range; ordering
  comparisons on `dict`/`set` operands (`==`/`!=` stay native); `len()` of a
  fixed tuple; value-position `range(...)`; `str`/`bytes` indexing; a
  value-position read of a name bound nowhere in the function (a module global, a
  closure, or a name leaked from a nested block); and a call to a name shadowed
  by a local binding or a module-level assignment (`len = 5` then `len(xs)`).
  Two cases are now lowered faithfully instead of rejected: `len(str)` counts
  Unicode code points (`.chars().count()`) rather than UTF-8 bytes, and a bare
  `return` in an `Optional[T]` function emits `Ok(None)` rather than `Ok(())`.

### Notes

0.1.0 alpha is intentionally narrow. It does not provide full Python
compatibility, bundled third-party package support, framework migration,
general-purpose Python JIT behavior, or full runtime boundary-cost optimization.
The Cranelift path is experimental, opt-in, native-side only, and limited to
small scalar helper regions.
