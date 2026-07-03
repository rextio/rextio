# Rextio 0.1.0 alpha Notes

> **Security:** Rextio analyzes source, generates Rust, and runs external build
> tools — treat it like a compiler and only build trusted projects. See
> [`SECURITY.md`](./SECURITY.md) for the threat model and protections.

Rextio 0.1.0 alpha proves a focused hybrid build workflow:

```text
Python source
  -> Rextio analyzer
  -> compatible subset checker
  -> boundary safety checker
  -> generated native artifact and Python fallback
```

Native compilation is an optimization. Fallback Python behavior must remain
available, including when `REXTIO_DISABLE_NATIVE=1` is set.

At a product level, Rextio gives a Python project four practical outputs:

| Output | What it is for |
| --- | --- |
| Hybrid Python package | Keep normal Python imports while using Rust for accepted hot-path functions. |
| Source-only generation | Inspect generated Rust/PyO3 and Python wrapper code without compiling it. |
| Executable artifact | Package a configured Python entrypoint as zipapp, or through Nuitka when available. |
| Rust-importable crate | Expose accepted direct-Rust functions to Rust applications as a Cargo path dependency. |

The central rule is simple: if Rextio cannot prove that a function is safe for
direct Rust lowering, it must keep that behavior on the Python fallback path or
use an explicit Python runtime semantics shim.

By default, Rextio discovers eligible module-level functions automatically when
their static types can be resolved from annotations, sibling `.pyi` stubs, or
conservative local context inference. Projects can set
`[policy] native_marker = "decorator"` when they want only explicitly marked
`@rextio.native` functions to become native candidates.

Explicit native markers can also name the intended native target:
`@rextio.native(target="rust")`. Target names are normalized
case-insensitively, and a target-specific marker applies only when the active
`--target-language` / `[build] native_backend` matches it. 0.1.0 alpha can record
`rust`, `mojo`, and `julia` target selections for planning, but only Rust code
generation is implemented.

Use `@rextio.exempt` on functions that must stay on Python fallback. Exemptions
override automatic discovery and explicit native markers.

Module top-level logic remains Python fallback unless explicitly enabled with
`[policy] native_top_level = true` or `--native-top-level`. The supported
top-level subset is narrower than native functions: assignments, annotated
assignments, augmented assignments, supported expressions, and `if`/`while`
blocks that update already assigned module variables. Assigned module variables
must share one supported value type. Rextio keeps an original fallback module
and uses it whenever native is disabled or unavailable.

## Requirements

| Component | Version | Notes |
| --- | --- | --- |
| CPython | >= 3.11 (validated on 3.11-3.14) | The analyzer uses the build interpreter's `ast`; generated extensions pin PyO3 0.29, which supports up to CPython 3.14. Newer interpreters may work but are unvalidated. Wheels are tagged for the build interpreter's minor version. |
| Rust toolchain | MSRV 1.83 (tested on recent stable) | Generated crates use edition 2021 and PyO3 0.29. Install via [rustup](https://rustup.rs). |
| Nuitka (optional) | >= 2.0 | Only for the Nuitka fallback, Nuitka executables, and the hybrid runtime. The first two are rejected up front by the build preflight; the hybrid runtime is checked when delegated fallback calls actually require the Nuitka dispatcher. |
| Numba (optional, experimental) | matches your interpreter: >= 0.57 (3.11), >= 0.59 (3.12), >= 0.61 (3.13), >= 0.63 (3.14) | Rextio only recognizes Numba decorators; the package is a runtime dependency of the user project, not of Rextio. Floors follow [Numba's version support table](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information). |

## Feature Stability

0.1.0 alpha deliberately keeps a narrow, trustworthy core and gates broader
ambitions behind explicit opt-ins. Treat the surface in these tiers:

| Tier | Features | Notes |
| --- | --- | --- |
| **Stable (core)** | Typed-function discovery, supported-subset checks, Rust/PyO3 AOT codegen, Cargo/maturin build, CPython fallback packaging, boundary policy | The path the alpha is meant to be judged on. |
| **Experimental (opt-in)** | Scalar-helper embedding (`--jit`/`REXTIO_JIT`/`[jit] enabled`), Numba external accelerator recognition + Nuitka coexistence, Nuitka fallback and Nuitka executables, runtime-semantics shim (`RXT080`), Rust-importable crate | Behind flags/markers; behaviour and diagnostics may change before the first non-alpha release. |
| **Planned (not implemented)** | `mojo`/`julia` native targets, installed-package plugins beyond metadata | Target metadata can be recorded for planning, but only Rust codegen is implemented. |

Stability of diagnostic codes (`RXT…`) is tracked in
`src/rextio/analyzer/diagnostic_codes.py`.

## Smoke Flow

```text
python -m pip install -e .
rextio init --project-root demo
rextio check demo
rextio generate demo --fallback=cpython
rextio build demo --fallback=cpython
rextio build demo --fallback=cpython --jit
rextio build demo --fallback=cpython --rust-importable --rust-crate-name=demo_native
rextio build demo --fallback=cpython --entrypoint=demo_app.cli:main
rextio bench demo_app.compute --project-root demo
rextio clean demo
```

Generated artifacts live under `.rextio/` and user source files are not
rewritten during build.

Use `rextio check` first when deciding what will become Rust. It reports
accepted native functions, rejected functions, fallback-only functions, runtime
shim functions, and boundary warnings before any compiler is invoked.

Use `rextio generate` when you want only generated source files. It writes Rust
and Python source under `.rextio/generated/` and skips Rust, Nuitka, wheel, and
build artifact compilation steps. With `--rust-importable`, it also writes
`.rextio/generated/rust_crate/` for Rust consumers without compiling that crate.

## Native Subset

0.1.0 alpha native candidates support module-level functions with statically
resolved scalar types including `bytes`, `list[int|float|bool|str]`,
`list[list[T]]`, fixed tuples, limited
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
`sum` over `list[int]` or `list[float]`, `all`/`any` over `list[bool]`, and
`sorted`/`reversed` over supported fixed list item types. Supported `math` calls
include trigonometric, logarithmic, rounding, finite/NaN checks, and
`math.pi`/`math.e`. Common side-effect and standard-library lowering is limited
to `print(...)`, `logging.debug/info/warning/error(...)`, module logger
variables assigned from `logging.getLogger(...)`, `datetime`/`time` timestamp
calls, selected `str`/`bytes`/`list` methods, and constrained
`hashlib.sha256(...).hexdigest()` and `base64.b64encode` patterns.
`statistics.mean`/`fmean`, `json.dumps`/`json.loads`, and `base64.b64decode`
have no direct native lowering: explicitly marked functions using them ride
the RXT080 runtime shim and auto-discovered ones stay on the Python fallback. Empty list literals must
use a supported local annotation such as `out: list[int] = []`. `enumerate` and
`zip` are supported only as batch loop or comprehension iterables over list
variables. Empty dict literals require a supported fixed `dict[K, V]`
annotation. Nested list comprehensions may produce `list[list[T]]`, dict
comprehensions may produce supported fixed `dict[K, V]`, and set
comprehensions may produce `set[int|float|bool|str]`. Dataclasses are not part
of the direct Rust lowering subset.

Python/Rust ownership differences are handled conservatively. Codegen clones
owned Rust values when a read-only Python value is reused after assignment or
inside a container literal. Mutable aliasing of Python collections is not
directly lowered: if `ys = xs` or a container literal captures `xs`, and either
alias is later mutated through supported `append` or dict assignment, the
function is routed to Python fallback instead of silently changing alias
semantics.

When direct Rust lowering cannot safely preserve Python object semantics, Rextio
may generate a Python runtime semantics native shim. The shim is a Rust/PyO3
function that calls the generated Python fallback implementation. It supports
compatibility for class/object behavior, regular `@rextio.native` instance
methods, exception handling, context managers, `async`/`await`,
generators/`yield`, and dynamic attribute access. Rextio reports `RXT080` for
this path because it preserves semantics but should not be treated as a Rust
speedup path.

Source annotations are not the only type source. Rextio also reads sibling
`.pyi` files and performs conservative local context inference for simple
constants, arithmetic, comparisons, `if` tests, loops, indexing, comprehensions,
and supported builtins. Ambiguous or unresolved function signatures are routed
to Python fallback.

## Numeric Semantics

Generated native code preserves Python numeric semantics by raising a
**catchable** exception (an `Exception` subclass, not the uncatchable PyO3
`PanicException`) where a fixed-width `i64`/`f64` would otherwise diverge from
Python:

- Integer `+`, `-`, `*`, unary `-`, and `abs`/`sum` raise `OverflowError` when
  the mathematically-correct result leaves the `i64` range (Python `int` is
  arbitrary precision).
- Integer `%` is **floored** (the result takes the divisor's sign, e.g.
  `-7 % 3 == 2`) and raises `ZeroDivisionError` on a zero divisor.
- Float `/` and `%` raise `ZeroDivisionError` on a zero divisor (instead of
  Rust's silent `inf`/`NaN`); float `%` is floored, including CPython's
  signed-zero rule. Non-zero IEEE-754 results (including `inf`/`NaN`) pass
  through unchanged.
- `math.floor`/`ceil`/`trunc` return a Python `int`; a value outside the `i64`
  range raises `OverflowError` and `NaN` raises `ValueError`. **Alpha limitation:**
  these do not return an arbitrary-precision `int` for out-of-`i64` floats — they
  raise rather than silently saturating; full bignum conversion is a future item.

These guarantees travel with the generated code. In the **PyO3 extension**, the
errors are Python exceptions (`OverflowError`/`ZeroDivisionError`/`ValueError`).
In the **`--rust-importable` crate**, which is consumed by Rust code rather than
Python, the same conditions return a `RextioError` (a native Rust error type) so
a Rust caller can handle them idiomatically.

Operations that cannot preserve these semantics on `i64`/`f64` are rejected from
the native subset rather than generated with surprising behavior: integer `/`
(true division), `//`, `**`, bit operations (`<<`, `>>`, `&`, `|`, `^`, `~`), and
`int(float)` are not part of the direct-Rust subset.

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
--enable-plugin / REXTIO_PLUGINS_ENABLED / [plugins] enabled
--default-external-policy / REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY / [imports] default_external_policy
--package-import-policy / REXTIO_IMPORTS_PACKAGES / [imports.packages]
--jit / REXTIO_JIT / [jit] enabled
--rust-importable / REXTIO_RUST_IMPORTABLE / [rust] importable
--rust-crate-name / REXTIO_RUST_CRATE_NAME / [rust] crate_name
--native-marker / REXTIO_NATIVE_MARKER / [policy] native_marker
--boundary-warnings / REXTIO_BOUNDARY_WARNINGS / [policy] boundary_warnings
--native-top-level / REXTIO_NATIVE_TOP_LEVEL / [policy] native_top_level
--entrypoint / REXTIO_EXECUTABLE_ENTRYPOINT / [executable] entrypoint
--executable-backend / REXTIO_EXECUTABLE_BACKEND / [executable] backend
--nuitka-mode / REXTIO_NUITKA_MODE / [executable] nuitka_mode
--cargo / REXTIO_CARGO / [toolchain] cargo
--maturin / REXTIO_MATURIN / [toolchain] maturin
--nuitka / REXTIO_NUITKA / [toolchain] nuitka
--python / REXTIO_PYTHON / [toolchain] python
--rust-toolchain / REXTIO_RUST_TOOLCHAIN / [toolchain] rust_toolchain
--cargo-version / REXTIO_CARGO_VERSION / [toolchain] cargo_version
--maturin-version / REXTIO_MATURIN_VERSION / [toolchain] maturin_version
--nuitka-version / REXTIO_NUITKA_VERSION / [toolchain] nuitka_version
--python-version / REXTIO_PYTHON_VERSION / [toolchain] python_version
```

### Toolchain selection and version pins

`[toolchain]` selects which external tools a build uses and, optionally,
verifies their versions:

- `cargo`, `maturin`, `nuitka`, and `python` accept either the tool binary
  itself or a home directory containing it (`bin/` and `Scripts/` are
  searched). A configured path that does not resolve fails the build up front
  (RXT060) - it never silently falls back to PATH. Unset tools resolve from
  PATH as before.
- `python` selects the CPython the build targets end to end: the PyO3
  extension compiles against it (`PYO3_PYTHON`), Nuitka runs inside it
  (`python -m nuitka`) unless `nuitka` is set explicitly, and the hybrid rust
  binary launches it for delegated calls (explicit `[executable] python`
  still wins; `REXTIO_RUNTIME_PYTHON` overrides at run time). It must share
  the build interpreter's minor version - the analyzer semantics, wheel tag,
  and Nuitka output are all bound to one interpreter.
- `rust_toolchain` names a rustup channel (`stable`, `1.83`, ...); it is
  forwarded as `RUSTUP_TOOLCHAIN`, so a non-rustup cargo ignores it.
- `*_version` values are verification pins: `"1.85"` accepts any 1.85.x,
  `"==2.6.1"` is exact, `">=3.13"` is a minimum. Pins verify only - they
  never install or select a tool (point the matching path setting at the
  version you want). Unlike the best-effort floors, an explicit pin fails
  the build when the tool's version cannot be determined. Pins cannot relax
  hard floors (Nuitka >= 2.0 still applies).

Rust is the only implemented native target in 0.1.0 alpha. `mojo` and `julia` can
be selected as target languages so versioned plugin metadata can be modeled, but
native source generation reports a clear unsupported-backend failure until those
codegen backends are implemented. Rextio plugins are installed as ordinary
Python packages and expose metadata through the `rextio.plugins` entry point
group. Projects enable specific plugin ids with `[plugins] enabled` or
`--enable-plugin`.

Import handling is intentionally conservative. Project-local imports are
analyzed as normal Rextio code, supported standard-library calls use built-in
lowering, and active plugins may claim external package imports through their
metadata. External packages without an active plugin use
`[imports] default_external_policy = "fallback"` by default. A project can
declare package-specific policies:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

`try-native` is an explicit opt-in for future dependency lowering and analysis
reports. It does not authorize silent conversion of arbitrary third-party source;
if no safe direct lowering exists, Rextio keeps the native candidate on
CPython/Nuitka fallback and reports the boundary reason.

## Experimental Scalar-Helper Embedding (`[jit]`)

Embedding is an explicit opt-in in 0.1.0 alpha. Despite the `[jit]` key
name, this is NOT a JIT: everything compiles ahead of time and no JIT
compiler exists or runs inside the built artifact.

```toml
[jit]
enabled = true
```

The same control is available as `--jit` / `--no-jit` or `REXTIO_JIT`.

With embedding enabled, an unmarked typed scalar helper (single arithmetic
return expression) called from an accepted native function is compiled as an
internal native function - lowered through the normal checked path (overflow
raises OverflowError, float division by zero raises ZeroDivisionError) and not
exported as a PyO3 function. In the Rust executable backend the same helpers
compile into the binary instead of being delegated per call. There is no
runtime compilation, and embedding adds no crate dependencies to generated
Cargo projects. With embedding disabled, the same native-to-helper call is
rejected by the normal boundary rules and the caller stays on Python
fallback.

## Release Verification

Run the regular test suite first:

```text
PYTHONPATH=src pytest
```

The suite includes an editable-install CLI smoke test. Cargo-specific tests are
skipped when Cargo is unavailable, and the Nuitka fallback E2E is skipped when
Nuitka is unavailable. To explicitly verify real local toolchains, run:

```text
PYTHONPATH=src pytest -m needs_cargo tests/e2e
PYTHONPATH=src pytest -m needs_nuitka tests/e2e
```

The editable-install smoke also installs the generated artifact wheel into a
fresh virtual environment and imports the generated package with
`REXTIO_DISABLE_NATIVE=1`, so release checks cover the packaged fallback path as
well as the build directory path.

`rextio build --entrypoint=module:function` generates a zipapp executable under
`dist/`. The artifact still needs a compatible Python interpreter. Native
extension modules are not loaded directly from inside the zipapp, so generated
wrappers preserve fallback behavior when `_rextio_native` is unavailable.

`rextio build --rust-importable --rust-crate-name=name` generates a separate
Rust library crate, builds it with Cargo, and copies the source artifact to
`dist/name-rust-crate/`. Rust projects can consume that directory as a path
dependency. Exported functions use generated Rextio names such as
`package__module__function` and return `Result<T, RextioError>`. This artifact
contains only functions directly lowered to typed Rust; Python runtime semantics
shims remain Python-facing compatibility wrappers.

`rextio build --entrypoint=module:function --executable-backend=nuitka` invokes
Nuitka for executable packaging. Use `--nuitka-mode=standalone` for a `.dist`
application directory or `--nuitka-mode=onefile` for a single executable. Nuitka
must be installed for this backend.

## Boundary Safety

Native functions may call accepted native functions and supported builtins.
They may not call fallback-only functions, rejected native candidates, or
unresolved external package calls. Those cases produce deterministic diagnostics
such as `RXT070`, `RXT072`, and `RXT030`.

If a direct-Rust native function calls a runtime-semantics native function,
Rextio promotes the caller to the same runtime shim path and reports `RXT080`.
This avoids generating Rust code with incompatible Python object return values.

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
