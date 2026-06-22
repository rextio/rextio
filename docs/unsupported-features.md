# Unsupported Features in Public 1

Rextio Public 1 is a focused hybrid build tool. It compiles eligible Python
functions with statically resolved types to Rust native modules and keeps the
rest of the project as Python fallback.

Unsupported native features are not bugs in the fallback path. When a native
candidate uses unsupported syntax, unsupported types, or unsafe boundaries,
Rextio rejects that function from native compilation and routes it through
fallback Python.

## Supported Native Surface

Public 1 native candidates must be module-level functions whose argument and
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
- comparisons with supported comparison operators
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
- `len(x)`
- `abs(x)` for `int` and `float`
- two-argument `min(x, y)` and `max(x, y)` for matching numeric types
- `sum(xs)` for `list[int]` and `list[float]`
- `math.sqrt`, `math.sin`, `math.cos`, and `math.floor`
- simple indexing such as `xs[i]`

## Unsupported Native Syntax

Rextio rejects these inside native candidates with structured diagnostics,
usually `RXT010`:

- classes and instance methods
- unsupported decorators on native candidates; `@rextio.native` and matching
  `@rextio.native(target="...")` markers are supported, while `@rextio.exempt`
  opts a function out of native candidacy instead
- async functions and `await`
- generators and `yield`
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
- `enumerate` or `zip` over non-list expressions
- slices such as `xs[1:]`
- f-strings
- `pass`
- `try` / `except` / `finally`
- `raise` and `assert`
- context managers
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

## Unsupported Dynamic Python Features

Dynamic Python features are rejected in native candidates, usually with
`RXT020`:

- `getattr`
- `setattr`
- `hasattr`
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
- the supported `math` subset: `math.sqrt`, `math.sin`, `math.cos`, and
  `math.floor`

Native functions must not call:

- fallback-only user functions (`RXT070`)
- exempt user functions (`RXT070`)
- rejected native candidates (`RXT072`)
- unsupported external packages or unresolved functions (`RXT030`)
- I/O, network, database, or ORM functions

Fallback Python code may call native functions. If fallback Python code calls a
native function inside a Python loop, Rextio emits `RXT073` because repeated
Python/Rust boundary crossings may erase speedup. The suggestion points users
toward native batch loops that Public 1 can compile, including `for x in xs`,
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

## Out of Scope for Public 1

Public 1 does not include:

- whole-project Python-to-Rust migration
- full Python compatibility
- full NumPy or pandas support
- framework conversion such as FastAPI-to-Axum, Django conversion, or Flask
  conversion
- ORM conversion
- async Python compilation
- generator compilation
- monkey patching support
- runtime profiling-based optimization
- full runtime boundary-cost modeling
- automatic native region fusion
- JIT, Cranelift, LLVM, or MLIR integration
- cloud build, SaaS dashboards, or GitHub app workflows
- Mojo or Julia native code generation
- downloading mapper plugins from a mapper repository
- concrete third-party mapper rules such as NumPy-to-rust-numpy

Nuitka fallback packaging is experimental in Public 1. If requested and not
available, Rextio reports a clear `RXT060` error and suggests CPython fallback.
If Nuitka is available, Rextio invokes it for generated fallback modules and
records the result in `.rextio/reports/build.json`.

Zipapp executable artifacts are supported through
`rextio build --entrypoint=module:function`. They still require a compatible
Python interpreter on the target machine. Native extension modules are not
loaded directly from inside the zipapp, so generated wrappers use Python fallback
when `_rextio_native` is unavailable. Python-free standalone binaries without
Nuitka remain out of scope for Public 1.

Nuitka executable artifacts are supported with
`--executable-backend=nuitka --nuitka-mode=standalone` or
`--executable-backend=nuitka --nuitka-mode=onefile`; the same values can be set
with `[executable] backend`, `[executable] nuitka_mode`, or matching
`REXTIO_EXECUTABLE_*` environment variables. This backend is available only when
Nuitka is installed and remains dependent on the local Nuitka toolchain. Rextio
does not guarantee cross-platform packaging of arbitrary third-party
dependencies in Public 1.

`native_backend = "mojo"` and `native_backend = "julia"` are accepted only as
target-planning values. They allow Rextio to record target version,
target-specific build options, and matching local mapper metadata, but Public 1
does not generate Mojo or Julia source. Local mapper plugin folders may be
listed under `[mappers] paths`; each folder must contain `rextio-mapper.toml` or
`mapper.toml`. Mapper repository download and concrete mapper transformations
are reserved for later work.

`@rextio.native(target="rust")` can pin an explicit native candidate to a target
language. Target names are normalized case-insensitively. A target-specific
marker applies only when the active target language matches it, whether that
target came from `--target-language` or `[build] native_backend`, so
`@rextio.native(target="mojo")` remains fallback in a Rust build until a Mojo
backend exists.
