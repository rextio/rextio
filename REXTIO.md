# Rextio Public 1 Notes

Rextio Public 1 proves a focused hybrid build workflow:

```text
Python source
  -> Rextio analyzer
  -> compatible subset checker
  -> boundary safety checker
  -> generated native artifact and Python fallback
```

Native compilation is an optimization. Fallback Python behavior must remain
available, including when `REXTIO_DISABLE_NATIVE=1` is set.

By default, Rextio discovers eligible module-level typed functions
automatically. Projects can set `[policy] native_marker = "decorator"` when
they want only explicitly marked `@rextio.native` functions to become native
candidates.

Use `@rextio.exempt` on functions that must stay on Python fallback. Exemptions
override automatic discovery and explicit native markers.

## Smoke Flow

```text
python -m pip install -e .
rextio init --project-root demo
rextio check demo
rextio generate demo --fallback=cpython
rextio build demo --fallback=cpython
rextio build demo --fallback=cpython --entrypoint=demo_app.cli:main
rextio bench demo_app.compute --project-root demo
rextio clean demo
```

Generated artifacts live under `.rextio/` and user source files are not
rewritten during build.

Use `rextio generate` when you want only generated source files. It writes Rust
and Python source under `.rextio/generated/` and skips Rust, Nuitka, wheel, and
build artifact compilation steps.

## Native Subset

Public 1 native candidates support module-level typed functions with scalar
types, `list[int|float|bool|str]`, `list[list[T]]`, fixed tuples, limited
fixed `dict[K, V]`, limited `set[int|float|bool|str]`, and `Optional[T]` /
`T | None`. The current Rust backend
handles assignment, typed local annotations with initializers, augmented
assignment, `if`, `while`, `for x in xs`, `range(n)`, `range(start, stop)`,
`range(start, stop, step)` with a positive int literal step,
`for i, x in enumerate(xs)`, `for x, y in zip(xs, ys)`, `break`, `continue`,
simple indexing, list literals, fixed tuple literals, limited dict read/write,
limited list/dict/set comprehensions, assignment expressions inside
comprehensions, and `list.append(...)` for supported list item types.

Supported builtin calls are limited to `len`, `abs`, two-argument `min`/`max`,
and `sum` over `list[int]` or `list[float]`. Supported `math` calls are
`math.sqrt`, `math.sin`, `math.cos`, and `math.floor`. Empty list literals must
use a supported local annotation such as `out: list[int] = []`. `enumerate` and
`zip` are supported only as batch loop or comprehension iterables over list
variables. Empty dict literals require a supported fixed `dict[K, V]`
annotation. Nested list comprehensions may produce `list[list[T]]`, dict
comprehensions may produce supported fixed `dict[K, V]`, and set
comprehensions may produce `set[int|float|bool|str]`. Class/object, exception,
context-manager, async, generator, and dynamic attribute semantics stay on
Python fallback. Dataclasses are not part of the Public 1 native subset.

## Configuration Sources

Build and analysis settings resolve in this order:

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

Every project behavior setting in `rextio.toml` has a matching command-line
flag and environment variable. Common examples:

```text
--fallback / REXTIO_FALLBACK_BACKEND / [build] fallback_backend
--fallback-threshold / REXTIO_BOUNDARY_FALLBACK_THRESHOLD / [build] fallback_threshold
--target-language / REXTIO_TARGET_LANGUAGE / [build] native_backend
--target-version / REXTIO_TARGET_VERSION / [target] version
--target-build-option / REXTIO_TARGET_BUILD_OPTIONS / [target.build_options]
--mapper-path / REXTIO_MAPPER_PATHS / [mappers] paths
--enable-mapper / REXTIO_MAPPERS_ENABLED / [mappers] enabled
--native-marker / REXTIO_NATIVE_MARKER / [policy] native_marker
--boundary-warnings / REXTIO_BOUNDARY_WARNINGS / [policy] boundary_warnings
--entrypoint / REXTIO_EXECUTABLE_ENTRYPOINT / [executable] entrypoint
--executable-backend / REXTIO_EXECUTABLE_BACKEND / [executable] backend
--nuitka-mode / REXTIO_NUITKA_MODE / [executable] nuitka_mode
```

Rust is the only implemented native target in Public 1. `mojo` and `julia` can
be selected as target languages so versioned mapper metadata can be modeled, but
native source generation reports a clear unsupported-backend failure until those
codegen backends are implemented. Mapper plugin download from a repository is
reserved for later; Public 1 only loads local mapper manifests.

## Release Verification

Run the regular test suite first:

```text
PYTHONPATH=src pytest
```

The suite includes an editable-install CLI smoke test. Cargo-specific tests are
skipped when Cargo is unavailable, and the Nuitka fallback E2E is skipped when
Nuitka is unavailable. To explicitly verify real local toolchains, run:

```text
PYTHONPATH=src pytest tests/e2e/test_pure_math_real_toolchain.py
PYTHONPATH=src pytest tests/e2e/test_nuitka_real_toolchain.py
cargo test --manifest-path crates/rextio_runtime/Cargo.toml
```

The editable-install smoke also installs the generated artifact wheel into a
fresh virtual environment and imports the generated package with
`REXTIO_DISABLE_NATIVE=1`, so release checks cover the packaged fallback path as
well as the build directory path.

`rextio build --entrypoint=module:function` generates a zipapp executable under
`dist/`. The artifact still needs a compatible Python interpreter. Native
extension modules are not loaded directly from inside the zipapp, so generated
wrappers preserve fallback behavior when `_rextio_native` is unavailable.

`rextio build --entrypoint=module:function --executable-backend=nuitka` invokes
Nuitka for executable packaging. Use `--nuitka-mode=standalone` for a `.dist`
application directory or `--nuitka-mode=onefile` for a single executable. Nuitka
must be installed for this backend.

## Boundary Safety

Native functions may call accepted native functions and supported builtins.
They may not call fallback-only functions, rejected native candidates, or
unresolved external package calls. Those cases produce deterministic diagnostics
such as `RXT070`, `RXT072`, and `RXT030`.

Fallback Python may call native functions. If it does so inside a Python loop,
Rextio emits `RXT073` with the suggestion to move the loop into a native batch
function. Supported batch loop shapes include `for x in xs`,
`for i, x in enumerate(xs)`, and `for x, y in zip(xs, ys)`.

Generated wrappers also keep a per-function runtime crossing count. After a
function's Python-to-native wrapper calls exceed
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD` (`1000` by default), later calls use the
generated Python fallback path for that function. `rextio generate` and
`rextio build` accept `--fallback-threshold=N`, and projects can set
`[build] fallback_threshold = N`, to embed the generated-code default. The
runtime environment variable overrides that embedded default. Set the threshold
to `0` or set `REXTIO_DISABLE_BOUNDARY_FALLBACK=1` to disable this automatic
fallback. `REXTIO_NATIVE_MODE=native` bypasses the threshold.
