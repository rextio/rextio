# Changelog

## 0.1.0 alpha

Initial public MVP for Rextio as a local hybrid build tool.

### Text and formatting fidelity

- `print`/`logging` of `bool` and `float` are textually CPython-exact
  (`True`/`False`; shortest correctly-rounded float repr with CPython's
  positional/scientific thresholds, `nan`/`inf`/`-0.0` spellings, and signed
  two-digit exponents). Logging `%` conversions are validated per argument
  type (`%d`/`%i`: int and bool; `%f`: float only, fixed six decimals with
  the CPython `nan` spelling; count mismatches, unknown conversions, and
  dynamic format strings with arguments fall back), and `%r` renders CPython
  repr. Printable containers (list, fixed tuple, `Optional`, nested) compose
  CPython repr recursively in `print`/logging; `print` of a `set` or `dict`
  is rejected (native iteration order is not CPython's). `__rextio_repr_str`
  escapes quotes, backslash, `\n`/`\r`/`\t`, C0/C1 controls, and U+00A0
  exactly like CPython repr.
- Iterating a `set` in a native function is rejected to the Python fallback
  with a dedicated diagnostic (Rust hash-set iteration order is per-instance
  seeded and diverges from CPython's deterministic-within-process order).
  Building a set from an ordered iterable and order-independent set
  operations stay native.
- `RXT090` non-rejecting note marks direct-native functions relying on the
  statically attributable documented divergence (`bytes.decode()` raises
  `ValueError` where CPython raises `UnicodeDecodeError`); `rextio check`
  lists the notes. (The other documented divergence - repr of str values
  containing non-printables above U+00A0 - is value-dependent and cannot
  carry a per-function note.)
- `list.index` failure messages interpolate the needle repr exactly like
  CPython ("5 is not in list", "'x' is not in list", "[3] is not in list").

### Toolchain selection and version pins

- A `[toolchain]` configuration section (CLI flag > `REXTIO_*` variable >
  `rextio.toml` > PATH) selects the cargo, maturin, Nuitka, and CPython a
  build uses: paths accept a binary or a home directory, a configured path
  that does not resolve fails the build up front, and symlinks and `..`
  components are traversed exactly as at the shell. `rust_toolchain`
  forwards a rustup channel; `[toolchain] python` drives the PyO3 build
  target (`PYO3_PYTHON`), Nuitka's interpreter (`python -m nuitka`), and the
  hybrid binary's delegated-call runtime, and must be a CPython sharing the
  build interpreter's minor version.
- `*_version` pins verify (never install) tool versions: bare pins are
  prefix matches, `==` is exact, `>=` is a minimum. A pin is enforced under
  the environment the build runs the tool with, exactly when the build uses
  the tool - including the hybrid dispatcher and the maturin-to-cargo
  fallback - and an unresolvable or unprobeable pinned tool fails the build.

### Packaging and accelerator-scan behavior

- The wheel built from a Nuitka fallback tree excludes `.py` sources
  shadowed by their compiled extension module (import-loadable suffixes
  only, so a same-stem ctypes `.dylib`/`.dll` payload keeps its Python
  wrapper) and carries a platform tag rather than `py3-none-any`;
  accelerated modules keep their `.py`.
- The external-accelerator source scan walks the whole module tree (deferred
  imports in function bodies, nested functions, `except`/`finally` bodies,
  `from numba import *` submodules), keeps accelerator-resolving import
  bindings over scope-flattened collisions, and all three Nuitka build paths
  recognize project-local modules (a local `numba.py` shim neither skips nor
  blocks builds).
- A Nuitka standalone build whose `.dist` directory lacks the launcher
  binary is reported as failed rather than returning the directory as the
  artifact.

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
  exit code (converted to the platform's exit-status width, like CPython's
  `sys.exit`), and prints a returned error CPython-style (`TypeName: message`) to
  stderr. The crate-mode `RextioError` carries the CPython exception type name
  so these binaries emit Python-style diagnostics.
- Subprocess hybrid for the Rust executable: a call the entrypoint makes to a
  project function that stays on the Python fallback is delegated to an external
  CPython process (a generated dispatcher + the project source shipped as
  `dist/<binary>.runtime/`, driven over a JSON stdio protocol) instead of being
  rejected, so hard-to-compile-to-Rust logic can be "left as Python." The
  delegated function runs real CPython (result is CPython-equivalent, exceptions
  forwarded CPython-style). Delegated-call arguments and results must both be
  immutable scalars (`int`/`float`/`bool`/`str`/`None`) — a mutable container
  (`list`/`dict`/`set`) is not delegated in either direction because it crosses the
  wire by value, which severs the aliasing CPython preserves (a mutated argument or
  a mutated aliased return would diverge silently); non-finite floats are rejected
  rather than silently dropped. A delegated function's stdout/stderr is redirected
  to the binary's stderr so it cannot corrupt the wire protocol, the dispatcher
  survives a delegated `SystemExit`/`KeyboardInterrupt` or non-serializable result
  instead of dying, and it runs without `rextio` installed (a no-op decorator stub
  is supplied when absent). RXT080 runtime-shim functions are not delegated. A
  hybrid binary needs a Python interpreter at runtime; a fully-direct-native binary
  remains standalone. `--executable-python` (`[executable] python`,
  `REXTIO_EXECUTABLE_PYTHON`) pins the interpreter the binary launches (bare name,
  absolute path, or a path relative to `<binary>.runtime` to bundle one).
  `--hybrid-runtime=nuitka` (`[executable] hybrid_runtime`, `REXTIO_HYBRID_RUNTIME`)
  instead ships the delegated Python as a self-contained Nuitka-compiled dispatcher
  executable, so no separate Python install is needed at runtime (requires Nuitka
  at build time).
- Mirrored build and analysis settings across CLI parameters, environment variables, and `rextio.toml`.
- Target planning metadata for future Rust/Mojo/Julia backends and installed package plugins.
- Experimental opt-in scalar-helper embedding for narrow unmarked helpers
  represented in Rextio IR, with `--jit`, `REXTIO_JIT`, and `[jit] enabled`
  controls: an eligible helper compiles ahead of time as an internal native
  function through the normal checked lowering (int overflow raises
  OverflowError; float `/` raises ZeroDivisionError), and in the Rust
  executable backend it compiles into the binary instead of being delegated
  per call. There is no JIT: everything compiles ahead of time, and the built
  artifact contains no runtime compiler.
- Numba coexists with the Nuitka fallback backend (experimental): modules using a recognized
  external accelerator are automatically kept as plain Python (skipped from
  per-module Nuitka compilation, so the importable `.py` retains the bytecode
  the accelerator needs), and the build result lists them. The detection scan
  sees through the optional-dependency guard (`try: from numba import njit`),
  `from numba import *`, conditional top-level imports, and class-contained
  methods. Nuitka *executable* builds fail early with guidance when
  accelerated modules are present, and the `nuitka` hybrid-runtime dispatcher
  fails early when *any* project module uses an accelerator (the whole tree
  ships in the runtime and Nuitka follows imports into it), instead of
  producing a binary that fails at the first call.
- Numba (`numba.jit`/`njit`/`vectorize`/`guvectorize`) is recognized as an
  external accelerator (experimental) for Python fallback code: decorated
  functions stay on the fallback cleanly (no auto-discovery, no diagnostic
  noise), are labeled `external_accelerator: numba` in reports and
  `rextio check` output, and run under Numba's own semantics (documented,
  including the nopython int-overflow wrap divergence). Not compatible with
  Nuitka-compiled fallbacks.
- Python runtime semantics native shim (`RXT080`) for compatibility coverage of
  object behavior, marked instance methods, exceptions, context managers,
  async functions, generators, and dynamic attribute access.
- Limited direct Rust lowering for expanded builtin and standard-library
  patterns including `math`, `all`/`any`, `sorted`/`reversed`, selected
  `str`/`bytes`/`list` methods, `time`/`datetime`, `hashlib.sha256`, and
  `base64.b64encode`. (`statistics.mean`/`fmean`, `json.dumps`/`json.loads`,
  and `base64.b64decode` have no faithful native equivalent and stay on the
  fallback/runtime-shim path.)
- Conservative Python/Rust ownership handling for direct Rust lowering:
  generated clones for reused owned values and fallback diagnostics for mutable
  collection alias mutation.
- Feature-oriented README and example documentation that explains generated
  artifacts, native/fallback behavior, executable outputs, and Rust-importable
  crate usage.
- Example projects for pure math, application-shell scoring, fallback safety, and boundary diagnostics.
- Focused end-to-end tests for build/import/runtime behavior, real Cargo builds, generated wheels, and Nuitka when installed.
- Global CLI output options on every command: `--format text|json`, and mutually
  exclusive `-v/--verbose` and `-q/--quiet`. All commands emit their result on
  stdout (text or JSON) while diagnostics and configuration errors go to stderr, so
  a `--format json` run produces clean machine-parseable stdout.
- Project documentation and governance: a `CONTRIBUTING.md` guide, GitHub issue forms
  and a pull-request template, a feature-stability table (`docs/stability.md`) and a
  versioning policy (`docs/versioning.md`) documenting the SemVer pre-1.0 stance and
  what is stable versus experimental.

### Semantics and safety guarantees

- `@rextio.native` validates its `target` against the supported languages
  (rust/mojo/julia), and both `@rextio.native`/`@rextio.exempt` reject classes
  and non-callables at decoration time, surfacing typos and misuse immediately.
- Plugins are metadata-only; a legacy `rules` key in plugin metadata is
  accepted and ignored so such plugins still load.
- Generated `str` literals are escaped into always-valid Rust (non-ASCII is
  emitted literally; escaping is injection-safe) through a single escaper that
  funnels every Python-string-to-Rust-literal path — plain `str` constants,
  the runtime-semantics shim's fallback module/attr names, logging format
  strings, and error messages embedding variable names. Lone surrogates, which
  a Python `str` can hold but Rust cannot represent, are rejected with a clear
  diagnostic.
- External build tools (`cargo`/`maturin`/`nuitka`) are invoked through a
  shared no-shell, bounded-timeout helper: a hung toolchain fails the build
  with a clear message, and on timeout the whole process tree is terminated
  (POSIX process-group / Windows `CREATE_NEW_PROCESS_GROUP`) so child
  `rustc`/linker/`python` processes are not left running.
- A native candidate's function name, parameters, and locals that collide with
  a Rust keyword (`fn`, `match`, `type`, …) are carried as raw identifiers
  (`r#match`), so the function stays native. Only the keywords a raw
  identifier cannot express (`crate`/`self`/`Self`/`super`) and non-ASCII
  names are kept on the Python fallback path with `RXT011`.
- `SECURITY.md` documents the threat model and protections; CI runs a
  `check-wheel-contents` packaging gate.
- The supported-type capability matrix (scalar/list/dict/set item/key types)
  is defined once in `rextio.capabilities` and shared by the analyzer and the
  Rust backend; a consistency test asserts every registered type has a Rust
  mapping.
- Generated sequence indexing preserves Python semantics: a negative index
  counts from the end (`xs[-1]`), and an out-of-range index raises
  `IndexError` rather than triggering an unchecked Rust panic.
- Generated integer `+`/`-`/`*`/`%`, unary negation, and the `abs`/`sum`
  builtins use checked arithmetic: an i64 overflow raises `OverflowError`
  (PyO3) / returns a `RextioError` (Rust-importable crate) instead of silently
  wrapping or panicking, and a modulo by zero raises `ZeroDivisionError`.
  Integer `%` follows Python's floored semantics (the result takes the
  divisor's sign, e.g. `-7 % 3 == 2`) rather than Rust's truncated remainder.
  These are catchable `Exception`s (unlike the uncatchable PyO3
  `PanicException` a raw overflow panic produces), and the guarantee travels
  with the generated code, so it holds even when the Rust-importable crate is
  consumed as a dependency. Release builds also keep `overflow-checks = true`
  as a safety-net backstop for any arithmetic outside the checked path; it is
  not part of the catchable-exception contract.
- Generated float division and modulo preserve Python semantics: `x / 0.0`
  and `x % 0.0` raise `ZeroDivisionError` (instead of Rust's silent
  `inf`/`NaN`), and float `%` is floored (the result takes the divisor's
  sign); a remainder of exactly zero takes the divisor's sign
  (`copysign(0.0, b)`), matching CPython.
- `math.floor`/`ceil`/`trunc` convert through a guarded float-to-int helper: a
  value outside i64 range raises `OverflowError` and `NaN` raises
  `ValueError`, never silently saturating to `i64::MIN`/`MAX`.
- The Python runtime-semantics shim (`RXT080`) is strictly opt-in: only
  functions explicitly marked `@rextio.native` are promoted to the shim.
  Auto-discovered (undecorated) functions are accepted only within the
  direct-Rust subset, and an undecorated function that depends on a
  runtime-shim native is reported with `RXT074` and left on the Python
  fallback path.
- The native subset checker keeps patterns it cannot lower faithfully off the
  direct-native path (rejected to the Python fallback, or routed to the
  `RXT080` runtime shim for marked functions) — an accepted function is either
  CPython-equivalent or rejected, never silently mis-compiled. Among the
  rejected patterns: non-`bool` `if`/`while`/comprehension conditions;
  multiple assignment (`a = b = ...`); integer literals outside the `i64`
  range; ordering comparisons on `dict`/`set` operands (`==`/`!=` stay
  native); `len()` of a fixed tuple; value-position `range(...)`;
  `str`/`bytes` indexing; a value-position read of a name bound nowhere in
  the function (a module global, a closure, or a name leaked from a nested
  block); and a call to a name shadowed by a local binding or a module-level
  assignment (`len = 5` then `len(xs)`). `len(str)` counts Unicode code
  points (`.chars().count()`) rather than UTF-8 bytes, and a bare `return` in
  an `Optional[T]` function emits `None`.

### Notes

0.1.0 alpha is intentionally narrow. It does not provide full Python
compatibility, bundled third-party package support, framework migration,
general-purpose Python JIT behavior, or full runtime boundary-cost optimization.
Scalar-helper embedding is experimental, opt-in, AOT, native-side only, and
limited to small scalar helper regions; there is no runtime JIT.
