# Unsupported Features in Public 1

Rextio Public 1 is a focused hybrid build tool. It compiles eligible typed
Python functions to Rust native modules and keeps the rest of the project as
Python fallback.

Unsupported native features are not bugs in the fallback path. When a native
candidate uses unsupported syntax, unsupported types, or unsafe boundaries,
Rextio rejects that function from native compilation and routes it through
fallback Python.

## Supported Native Surface

Public 1 native candidates must be module-level typed functions. Rextio
discovers eligible candidates automatically by default. Projects can set
`[policy] native_marker = "decorator"` to require `@rextio.native`.
Use `@rextio.exempt` to keep a function on Python fallback even when it has a
supported typed signature.

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

Supported syntax is intentionally small:

- typed arguments and return values
- local variable assignment
- arithmetic with supported operators
- boolean operations
- comparisons with supported comparison operators
- `if` / `elif` / `else`
- `for x in xs`
- `for i in range(len(xs))`
- `while`
- `return`
- calls to accepted native functions
- `len(x)`
- simple indexing such as `xs[i]`

## Unsupported Native Syntax

Rextio rejects these inside native candidates with structured diagnostics,
usually `RXT010`:

- classes and instance methods
- unsupported decorators on native candidates; `@rextio.exempt` opts a function
  out of native candidacy instead
- async functions and `await`
- generators and `yield`
- lambdas and nested functions
- comprehensions
- container literals such as `[]`, `()`, `{}`, and set literals
- slices such as `xs[1:]`
- f-strings
- `break`, `continue`, and `pass`
- `try` / `except` / `finally`
- `raise` and `assert`
- context managers
- imports inside native functions
- `global` and `nonlocal`
- `match`
- assignment expressions
- starred expressions
- arbitrary `*args` and `**kwargs`
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
- supported builtins such as `len` and `range`

Native functions must not call:

- fallback-only user functions (`RXT070`)
- exempt user functions (`RXT070`)
- rejected native candidates (`RXT072`)
- unsupported external packages or unresolved functions (`RXT030`)
- I/O, network, database, or ORM functions

Fallback Python code may call native functions. If fallback Python code calls a
native function inside a Python loop, Rextio emits `RXT073` because repeated
Python/Rust boundary crossings may erase speedup.

Generated wrappers count Python-to-native wrapper crossings per function. If the
count exceeds `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` (`1000` by default), later
calls use the generated CPython/Nuitka fallback path for that function. Set the
threshold to `0` or set `REXTIO_DISABLE_BOUNDARY_FALLBACK=1` to disable this
automatic fallback. `REXTIO_NATIVE_MODE=native` bypasses the threshold.

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

Nuitka fallback packaging is experimental in Public 1. If requested and not
available, Rextio reports a clear `RXT060` error and suggests CPython fallback.
If Nuitka is available, Rextio invokes it for generated fallback modules and
records the result in `.rextio/reports/build.json`.
