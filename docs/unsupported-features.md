# Unsupported Features in 0.1.0 alpha

Rextio 0.1.0 alpha is a focused hybrid build tool. It compiles eligible Python
functions with statically resolved types to Rust native modules and keeps the
rest of the project as Python fallback.

Unsupported native features are not bugs in the fallback path. When a native
candidate uses unsupported syntax, unsupported types, or unsafe boundaries,
Rextio rejects that function from native compilation and routes it through
fallback Python.

Read this document as the detailed boundary behind the main README. The happy
path is the direct Rust subset; the compatibility path is the Python runtime
semantics shim; everything else remains ordinary Python fallback.

| Path | Result |
| --- | --- |
| Direct Rust subset | Generated Rust/PyO3 code, expected speedup path. |
| Runtime semantics shim | Generated native wrapper that calls Python fallback to preserve behavior. |
| Python fallback | Original behavior stays in generated fallback modules and wrappers. |

## Supported Native Surface

0.1.0 alpha native candidates must be module-level functions whose argument and
return types are resolved from annotations, sibling `.pyi` stubs, or
conservative local context inference. Rextio discovers eligible candidates
automatically by default. Projects can set `[policy] native_marker = "decorator"`
to require `@rextio.native`.
Use `@rextio.exempt` to keep a function on Python fallback even when it has a
supported static signature.

Module top-level logic is fallback by default. When `[policy]
native_top_level = true` or `--native-top-level` is set, Rextio may convert a
narrow import-time subset to a native initializer: assignments, annotated
assignments, augmented assignments, supported expressions, and `if`/`while`
blocks that update variables assigned before the block. Assigned module
variables must share one supported value type so the initializer can return
`dict[str, T]`. Rextio still keeps a full original fallback module for
`REXTIO_DISABLE_NATIVE=1` and native import failures.

If a source function has no annotations and no `.pyi` signature, Rextio only
compiles it when constants, arithmetic, comparisons, `if` tests, loops,
indexing, comprehensions, and supported builtins make every argument and return
type unambiguous. Otherwise it stays on fallback.

Supported types:

- `int`
- `float`
- `bool`
- `str`
- `bytes`
- `None`
- `list[int]`
- `list[float]`
- `list[bool]`
- `list[str]`
- `list[list[T]]` where `T` is a supported scalar list item type
- fixed tuples such as `tuple[int, float]`
- fixed `dict[K, V]` where `K` is `int`, `bool`, or `str` and `V` is a
  supported fixed value type
- `set[int]`
- `set[float]`
- `set[bool]`
- `set[str]`
- `Optional[T]` and `T | None` for supported `T`

Supported syntax is intentionally small:

- typed arguments and return values
- local variable assignment
- local variable annotations with initializers, such as `total: float = 0.0`
- augmented assignment: `+=`, `-=`, `*=`, `/=`
- arithmetic with supported operators
- boolean operations
- comparisons with supported comparison operators, where `if`/`while`/
  comprehension conditions must evaluate to `bool` (`dict`/`set` operands
  support only `==` and `!=`, not ordering)
- `if` / `elif` / `else`
- `for x in xs`
- `for i in range(len(xs))`
- `for i in range(n)`
- `for i in range(start, stop)`
- `for i in range(start, stop, step)` when `step` is a positive int literal
- `for i, x in enumerate(xs)`
- `for x, y in zip(xs, ys)`
- `while`
- `break`
- `continue`
- `return`
- list literals for supported item types
- typed empty list literals such as `out: list[int] = []`
- `list.append(x)` for `list[int]`, `list[float]`, `list[bool]`, and
  `list[str]`
- fixed tuple literals and constant tuple indexing such as `pair[0]`
- limited dict literals, `d[key]` reads, and `d[key] = value` writes for
  supported fixed `dict[K, V]` types
- list comprehensions over supported `list`, `range`, `enumerate`, and `zip`
  iterables, including optional `if` clauses and multi-generator flattening
- nested list comprehensions that produce `list[list[T]]`
- limited dict comprehensions producing supported fixed `dict[K, V]` types
- limited set comprehensions producing `set[int]`, `set[float]`, `set[bool]`,
  or `set[str]`
- assignment expressions inside comprehensions; targets bind in the containing
  function scope and cannot rebind comprehension iteration variables
- `Optional[T]` / `T | None` annotations, `None` returns, and `is None` /
  `is not None` checks
- calls to accepted native functions
- `len(x)` for `list`, `set`, `dict`, `str`, and `bytes` (a `str` length counts
  Unicode code points, matching CPython, not UTF-8 bytes)
- `abs(x)` for `int` and `float`
- two-argument `min(x, y)` and `max(x, y)` for matching numeric types
- `sum(xs)` for `list[int]` and `list[float]`
- `math.sqrt`, `math.sin`, `math.cos`, and `math.floor`
- simple `list`, fixed `tuple`, and fixed `dict` indexing such as `xs[i]`
  (`str` and `bytes` indexing is not supported)

## Unsupported Native Syntax

Rextio rejects these inside direct-Rust native candidates with structured
diagnostics, usually `RXT010`, unless the construct is listed in the runtime
semantics shim section below:

- unsupported decorators on native candidates; `@rextio.native` and matching
  `@rextio.native(target="...")` markers are supported, while `@rextio.exempt`
  opts a function out of native candidacy instead
- lambdas and nested functions
- generator expressions
- assignment expressions outside comprehensions
- set literals
- general tuple and dict semantics outside the fixed tuple and limited fixed
  `dict[K, V]` subset
- general set semantics outside the limited `set[int|float|bool|str]`
  comprehension subset
- dataclasses
- empty list literals without a supported `list[...]` annotation
- empty dict literals without a supported fixed `dict[K, V]` annotation
- `enumerate` outside a supported loop or comprehension iterable
- `zip` outside a supported loop or comprehension iterable
- `range` outside a supported loop or comprehension iterable (a value-position
  `range(...)`, e.g. `return range(n)`, has no native representation)
- `enumerate` or `zip` over non-list expressions
- non-`bool` `if`, `elif`, `while`, and comprehension `if` conditions; native
  lowering requires the condition to be `bool`, so use an explicit comparison
  (`if len(xs) > 0:` rather than `if xs:`, `if x != 0:` rather than `if x:`)
- ordering comparisons (`<`, `<=`, `>`, `>=`) on `dict` or `set` operands; only
  `==` and `!=` are supported for those types
- `str` and `bytes` indexing such as `s[0]` (only `list`, fixed `tuple`, and
  fixed `dict` subscripting is lowered)
- `len()` of a fixed tuple (a Rust tuple has no length method; use the known
  arity directly)
- multiple assignment targets such as `a = b = value`
- integer literals outside the signed 64-bit range (`int` lowers to `i64`)
- a value-position read of a name bound nowhere in the function (a module
  global, a closure variable, or a name first bound inside a nested
  `if`/`for`/`while`/`try` block and read after it)
- calling a name that a local binding or a module-level assignment shadows
  (e.g. `len = 5` at module scope, then `len(xs)`)
- slices such as `xs[1:]`
- f-strings
- `pass`
- imports inside native functions
- `global` and `nonlocal`
- `match`
- assignment expressions outside comprehensions
- starred expressions
- arbitrary `*args` and `**kwargs`

Top-level native initialization is even narrower than native functions. Rextio
rejects native top-level conversion for top-level `for` loops, user/external
function calls, unsupported executable statements, and heterogeneous module
variable export types. These modules keep their top-level behavior on Python
fallback.
- keyword call arguments
- unsupported operators such as `**`, `//`, matrix multiply, bitwise operators,
  shifts, unary plus, and bitwise invert
- operations whose inferred operand types would not preserve Python semantics,
  such as `str + str`, `bool + bool`, mixed `int`/`float` arithmetic, and
  `int / int`
- identity and membership comparisons such as `is`, `is not`, `in`, and
  `not in`
- mutable collection alias mutation, such as assigning `ys = xs` and then
  mutating either alias with supported `append` or dict assignment. Direct Rust
  lowering may clone read-only owned values, but it must not silently replace
  Python reference aliasing semantics with Rust ownership semantics.

## Runtime Semantics Shim

Some Python features are not lowered into typed Rust statements, but can still
be exposed through a generated Rust/PyO3 native shim. The shim calls the
generated Python fallback implementation and therefore preserves Python runtime
semantics. Rextio reports `RXT080` for these functions.

Runtime-backed native functions currently cover:

- class/object behavior inside a marked native function
- regular instance methods marked with `@rextio.native`
- `try` / `except` / `finally` outside the restricted native subset (built-in
  exception handlers only — see `docs/stability.md`)
- `raise` and `assert`
- context managers
- `async` functions and `await`
- generators and `yield`
- dynamic attribute access such as `obj.attr`
- `getattr`, `setattr`, and `hasattr`

If a direct-Rust native function calls a runtime-backed native function, Rextio
promotes the caller to the runtime shim path and reports `RXT080`. This avoids
generating Rust code that would treat Python object values as typed Rust values.

This path is a compatibility mechanism. It is not expected to provide the same
speedup as direct Rust lowering. Automatic discovery for runtime-backed native
functions is conservative; broad object-runtime functions should be explicitly
marked with `@rextio.native`.

Runtime-backed native functions are not exported through the optional
Rust-importable crate artifact. `rextio build --rust-importable` includes only
functions that were directly lowered to typed Rust and leaves runtime shims as
Python-facing compatibility wrappers.

## Unsupported Dynamic Python Features

Dynamic Python features are rejected in native candidates, usually with
`RXT020`:

- `globals`
- `locals`
- `eval`
- `exec`
- `__import__`
- dynamic call targets that cannot be resolved statically

## Boundary Limits

Native compilation is allowed only when Rextio can prove the native function
does not depend on fallback-only Python code.

Native functions may call:

- accepted native functions
- supported builtins such as `len`, `range`, `abs`, `min`, `max`, and `sum`
- the supported builtin expansion: `all`, `any`, `sorted`, and `reversed`
- the supported `math` subset: trigonometric, logarithmic, rounding,
  finite/NaN checks, `math.pi`, and `math.e`
- limited side-effect and standard-library calls: `print(...)`,
  `logging.debug/info/warning/error(...)`, logger variables assigned from
  `logging.getLogger(...)`, `datetime.now()/utcnow().isoformat()` and
  `datetime.now().timestamp()`, `time.time()`, selected `str`/`bytes`/`list`
  methods, `hashlib.sha256(...).hexdigest()`, and `base64.b64encode(...)`

> **Kept on the Python fallback for fidelity (0.1.0 alpha):** some stdlib calls
> have no faithful native lowering and are rejected to fallback rather than
> silently mis-compiled: `json.dumps`/`json.loads` (serde is not
> CPython-`json`-compatible), `statistics.mean`/`statistics.fmean` (naive native
> summation diverges from CPython's exact/`math.fsum`), `base64.b64decode`
> (CPython discards non-alphabet characters the native decoder rejects),
> `str.strip` (Rust `trim()` and CPython whitespace sets differ on the C0
> separators), `set[float]`/`sorted(list[float])` (NaN identity/order), and
> `datetime.utcnow().timestamp()` (naive-UTC-as-local). See "Accepted Native
> Semantic Divergences" below for the handful of native lowerings that are kept
> with a small, documented textual difference.

When a direct-Rust native function calls a runtime-backed native function,
Rextio promotes the caller to the runtime shim path and emits `RXT080`.

Native functions must not call:

- fallback-only user functions (`RXT070`)
- exempt user functions (`RXT070`)
- rejected native candidates (`RXT072`)
- unsupported external packages or unresolved functions (`RXT030`)
- I/O, network, database, or ORM functions

External package handling is conservative by default. Project-local imports are
eligible for normal Rextio analysis, supported standard-library calls use
built-in lowering rules, and active plugins may claim specific external Python
packages through plugin metadata. External packages without an active plugin use
`[imports] default_external_policy = "fallback"` unless a package-specific
policy says otherwise.

`policy = "try-native"` is an explicit opt-in for future dependency lowering and
analysis reports. It does not mean Rextio silently translates arbitrary
third-party package source into Rust. If no safe direct lowering exists, calls to
that package keep the native candidate on CPython/Nuitka fallback and emit
`RXT030`. When such a call is inside a loop, the diagnostic suggests
function-level fallback, adding a plugin, or refactoring to a batch API.

Fallback Python code may call native functions. If fallback Python code calls a
native function inside a Python loop, Rextio emits `RXT073` because repeated
Python/Rust boundary crossings may erase speedup. The suggestion points users
toward native batch loops that 0.1.0 alpha can compile, including `for x in xs`,
`for i, x in enumerate(xs)`, and `for x, y in zip(xs, ys)`.

Generated wrappers count Python-to-native wrapper crossings per function. If the
count exceeds `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` (`1000` by default), later
calls use the generated CPython/Nuitka fallback path for that function. Use
`rextio generate --fallback-threshold=N` or
`rextio build --fallback-threshold=N`, set `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`,
or configure `[build] fallback_threshold = N` to embed the generated-code
default. The runtime environment variable overrides that embedded default. Set
the threshold to `0` or set `REXTIO_DISABLE_BOUNDARY_FALLBACK=1` to disable
this automatic fallback. `REXTIO_NATIVE_MODE=native` bypasses the threshold.

## Experimental Native-Side JIT Boundary

Rextio 0.1.0 alpha includes an opt-in native-side JIT for a very narrow scalar
helper subset. It is disabled by default and must be enabled with `[jit]
enabled = true`, `--jit`, or `REXTIO_JIT=true`.

The current JIT path is not a general Python JIT. It only covers internal
Rextio IR regions with scalar `int` or `float` arguments and return values, a
matching scalar signature, and a single arithmetic return expression. The
generated Rust module uses Cranelift only after the configured hot threshold.
Python code does not call a separate JIT API directly.

Code outside this subset remains on the normal direct Rust, Python runtime shim,
or CPython/Nuitka fallback path.

## Accepted Native Semantic Divergences

A small number of native lowerings are kept on the direct Rust path even though
they differ from CPython in a narrow, documented way. These are accepted trade-
offs for 0.1.0 alpha (the alternative being a Python fallback for a common
operation or replicating a large amount of CPython runtime formatting). All
other observed divergences are treated as bugs and either fixed or rejected to
fallback.

- **`print` / `logging` of a `float`.** A float is formatted with Rust's `{:?}`
  (Debug), which matches CPython's `float` repr for the common cases (`print(1.0)`
  writes `1.0`, and large/small magnitudes use scientific notation), but still
  differs on two narrow points: the NaN spelling (`NaN` vs CPython `nan`) and the
  exponent format (`1e16` / `1e-5` vs CPython `1e+16` / `1e-05`). Computed values
  are unaffected — only the textual stdout/log output can differ. int and str
  format identically.
- **`print` / `logging` of a `bool`.** Rust prints `true`/`false` where CPython
  prints `True`/`False`. Same class as the float case: only the textual output
  differs, and the boolean value itself is unaffected.
- **`bytes.decode()` on invalid UTF-8.** The native path raises `ValueError`
  where CPython raises `UnicodeDecodeError`. `UnicodeDecodeError` is a subclass
  of `ValueError`, so `except ValueError` still catches it; only code that
  catches `UnicodeDecodeError` specifically sees the difference. A faithful
  `UnicodeDecodeError` is feasible but DEFERRED for alpha — it would require
  threading the decode-position data through to the wrapper boundary (where the
  `py` token is available), since the inner native function has no `py` token.
  Valid UTF-8 decodes identically.

Operations whose divergence could not be bounded this narrowly are kept on the
Python fallback instead — for example `json.dumps`/`json.loads` (serde is not
CPython-`json`-compatible), `set[float]` / `sorted(list[float])` (NaN identity),
`statistics.mean`/`statistics.fmean` (naive native summation diverges from
CPython's exact/`math.fsum`), `base64.b64decode` (CPython silently discards
non-alphabet characters), `str.strip` (Rust `trim()` differs from CPython's
whitespace set on the C0 separators `\x1c`–`\x1f`), and
`datetime.utcnow().timestamp()` (CPython interprets the naive UTC wall-clock as
local time).

## Out of Scope for 0.1.0 alpha

0.1.0 alpha does not include:

- whole-project Python-to-Rust migration
- full Python compatibility
- bundled third-party package plugin rules
- framework conversion
- ORM conversion
- direct Rust compilation for the full Python async/generator object model
- monkey patching support
- runtime profiling-based optimization
- full runtime boundary-cost modeling
- automatic native region fusion
- automatic Rust translation of arbitrary third-party Python packages
- general-purpose Python JIT, LLVM JIT, or MLIR integration
- cloud build, SaaS dashboards, or GitHub app workflows
- Mojo or Julia native code generation
- concrete third-party plugin transformations

Nuitka fallback packaging is experimental in 0.1.0 alpha. If requested and not
available, Rextio reports a clear `RXT060` error and suggests CPython fallback.
If Nuitka is available, Rextio invokes it for generated fallback modules and
records the result in `.rextio/reports/build.json`.

Zipapp executable artifacts are supported through
`rextio build --entrypoint=module:function`. They still require a compatible
Python interpreter on the target machine. Native extension modules are not
loaded directly from inside the zipapp, so generated wrappers use Python fallback
when `_rextio_native` is unavailable. Python-free standalone binaries without
Nuitka remain out of scope for 0.1.0 alpha.

Rust-importable crate artifacts are supported with
`rextio build --rust-importable --rust-crate-name=name`. They are normal Cargo
library crates copied to `dist/name-rust-crate/` for path-dependency use from
Rust projects. This is not a whole-project Python-to-Rust migration; only
accepted direct-Rust functions are exported.

Nuitka executable artifacts are supported with
`--executable-backend=nuitka --nuitka-mode=standalone` or
`--executable-backend=nuitka --nuitka-mode=onefile`; the same values can be set
with `[executable] backend`, `[executable] nuitka_mode`, or matching
`REXTIO_EXECUTABLE_*` environment variables. This backend is available only when
Nuitka is installed and remains dependent on the local Nuitka toolchain. Rextio
does not guarantee cross-platform packaging of arbitrary third-party
dependencies in 0.1.0 alpha.

Native Rust binary artifacts are supported with `--executable-backend=rust` (or
`[executable] backend = "rust"`). Rextio generates a Cargo binary crate whose
`main` calls the entrypoint and builds a native executable in `dist/`. The
entrypoint must be an accepted direct-native function shaped `def main(argv:
list[str]) -> int`: `argv` mirrors `sys.argv` (the program path at index 0), the
returned `int` is the process exit code, and a returned error is printed
CPython-style (`TypeName: message`) to stderr with a non-zero exit. Requires
Cargo.

Rextio's Rust binary entrypoint accepts only command-line arguments that can be
represented as valid UTF-8 `str` values. If the OS supplies a non-Unicode
argument, the binary prints `ValueError: command-line argument is not valid
UTF-8` to stderr and exits with status 1. CPython on Unix can expose arbitrary
argv bytes through `surrogateescape`; Rextio does not model surrogate-containing
`str` values in the native Rust executable ABI for 0.1.0 alpha.

When the entrypoint (or its native call graph) calls a project function that
lives on the Python fallback — code outside the Rust subset that is "left as
Python", i.e. a function that is not a native candidate (RXT070) or is rejected
from the native subset (RXT072) — Rextio delegates that call to an **external
CPython subprocess** rather than rejecting it. The build ships a
`dist/<binary>.runtime/` directory (a generated dispatcher plus the project's
Python source); the binary launches `python3` (overridable with `REXTIO_PYTHON`)
once and forwards delegated calls over a JSON stdio protocol. The delegated
function runs real CPython, so its result is CPython-equivalent (not a silent
miscompile), and a raised Python exception is forwarded and printed CPython-style.

A delegated call's **argument and return** types must both be immutable scalars
(`int`/`float`/`bool`/`str`/`None`). A `list`/`dict`/`set` is *not* delegated in
either direction, because it crosses the wire by value (a JSON copy) and that
severs the aliasing CPython preserves: a callee's in-place mutation of a container
**argument**, or the native caller's mutation of a **returned** container that
aliased Python state, would silently diverge (the analyzer cannot prove a returned
container is a fresh, unaliased value). A non-finite float (`NaN`/`Infinity`) is
rejected in both directions rather than silently coerced to `null`/`None`. Any
unsupported type keeps the caller on the fallback (never a guess). A function on
the **RXT080 runtime shim** (the PyO3 runtime-semantics path) is not delegated: a
native entry that depends on one is rejected and not built, so delegation never
silently changes shim semantics. A delegated function's own stdout/stderr is
redirected to the binary's stderr so it cannot corrupt the wire protocol (which
owns stdout), and the long-lived dispatcher is hardened to survive any single
request — a delegated `SystemExit`/`KeyboardInterrupt`, an exception whose
`__str__` raises, and a non-serializable / non-finite / too-deep / too-large result
all become an error frame rather than killing it. The runtime does not require
`rextio` to be installed — the dispatcher supplies a minimal decorator stub when it
is absent.

Known limitation: a fallback callee annotated `-> None` is delegated for its side
effects (called as a bare statement); using its result in a value position (for
example `if callee() is None:`) is not supported and produces a clean build error
rather than a native binary.

This "hybrid" binary is not standalone — it needs a Python interpreter (and the
project's dependencies) at runtime, and each delegated call crosses a process
boundary. A binary whose entry graph is fully direct-native has no runtime
directory and no Python dependency. Embedding libpython (in-process) is out of
scope; delegation is process-external only.

Two options control the interpreter side:

- `--executable-python` (`[executable] python`, `REXTIO_EXECUTABLE_PYTHON`) sets
  the interpreter the binary launches — a bare name resolved on `PATH`, an
  absolute path, or a path relative to `<binary>.runtime` (to bundle a specific
  interpreter). `REXTIO_PYTHON` still overrides it at run time. Use this to keep
  the binary off the system's default `python3`.
- `--hybrid-runtime` (`[executable] hybrid_runtime`, `REXTIO_HYBRID_RUNTIME`;
  `source` or `nuitka`, default `source`) chooses how the Python is shipped.
  `nuitka` compiles the dispatcher into a self-contained onefile executable
  (`<binary>.runtime/dispatcher`, with the delegated fallback modules bundled),
  so the hybrid binary needs no separate Python install at runtime; the Rust
  binary launches that executable directly. It requires Nuitka at build time.

`native_backend = "mojo"` and `native_backend = "julia"` are accepted only as
target-planning values. They allow Rextio to record target version,
target-specific build options, and matching plugin metadata, but 0.1.0 alpha
does not generate Mojo or Julia source. Rextio plugins are ordinary Python
packages installed with tools such as `pip` or `uv`; they expose metadata
through the `rextio.plugins` entry point group. Projects opt into specific
plugin ids with `[plugins] enabled`, `--enable-plugin`, or
`REXTIO_PLUGINS_ENABLED`. Concrete plugin transformations remain separate
plugin work.

`@rextio.native(target="rust")` can pin an explicit native candidate to a target
language. Target names are normalized case-insensitively. A target-specific
marker applies only when the active target language matches it, whether that
target came from `--target-language` or `[build] native_backend`, so
`@rextio.native(target="mojo")` remains fallback in a Rust build until a Mojo
backend exists.
