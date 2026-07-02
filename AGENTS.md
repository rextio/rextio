# AGENTS.md

# Rextio 0.1.0 alpha Development Guide

This repository implements **Rextio 0.1.0 alpha**, the first alpha release of Rextio.

Rextio 0.1.0 alpha is a hybrid build tool for Python projects:

> Write typed Python. Compile eligible functions to Rust AOT native modules. Package the rest as safe CPython/Nuitka fallback.

The goal is not to replace Python, not to build a new programming language, and not to support all Python semantics. The goal is to provide a practical hybrid build workflow for existing Python projects:

```text
Python source
  -> Rextio analyzer
  -> Rextio-compatible subset checker
  -> boundary safety checker
  -> Rust AOT code generation for eligible functions
  -> CPython/Nuitka fallback packaging for the rest
  -> import-compatible hybrid artifact
```

---

## 1. Product Scope for 0.1.0 alpha

0.1.0 alpha must demonstrate all of the following:

1. A Python project can let Rextio discover eligible functions automatically when their types are statically resolved from annotations, `.pyi` stubs, or conservative local context inference, and can optionally mark functions with `@rextio.native` or target-specific `@rextio.native(target="rust")`.
2. A Python project can mark functions with `@rextio.exempt` to keep them on Python fallback.
3. Rextio can check whether those functions belong to the supported subset.
4. Rextio can reject unsafe native-to-fallback call boundaries.
5. Rextio can warn about likely excessive Python-to-Rust boundary crossings.
6. Rextio can use generated Python fallback after repeated Python-to-Rust wrapper crossings exceed a simple runtime threshold.
7. Rextio can generate Rust code for supported Python functions with statically resolved types.
8. Rextio can generate PyO3 bindings.
9. Rextio can build the generated Rust module with Cargo/maturin.
10. Rextio can optionally build accepted direct-Rust functions into a Rust
    library crate that Rust projects can import as a path dependency.
11. Rextio can preserve Python fallback behavior.
12. Rextio can package a hybrid output where native functions are used when available and fallback functions are used otherwise.
13. Rextio can optionally invoke Nuitka for fallback packaging.
14. Rextio can optionally generate a zipapp executable artifact for a configured Python entrypoint.
15. Rextio can optionally invoke Nuitka for standalone or onefile executable packaging.
16. Rextio can run simple benchmarks comparing Python fallback and Rust native execution.
17. Rextio can provide a clear demo project showing a normal Python app with a Rust-compiled hot path.
18. Rextio can optionally convert a narrow, supported subset of module top-level
    initialization logic to a Rust native initializer while preserving Python
    fallback import behavior.
19. Rextio can optionally embed narrow unmarked scalar helpers as internal
    native functions (experimental) when `[jit] enabled = true`, `--jit`, or
    `REXTIO_JIT=true` is set. Despite the `[jit]` key name this is AOT
    embedding only - the former runtime Cranelift JIT was removed and no JIT
    compiler runs inside the built artifact. Numba decorators are recognized as an
    external accelerator for fallback code (experimental in 0.1.0 alpha).

The 0.1.0 alpha release must feel like a usable hybrid compiler/build tool, not merely a static analyzer.

---

## 2. Non-Goals for 0.1.0 alpha

Do not implement these in 0.1.0 alpha unless explicitly requested:

* SaaS dashboard
* GitHub App
* Cloud build service
* Runtime profiling-based automatic fallback
* Full runtime boundary-cost model
* Runtime-weighted native/fallback optimization
* General-purpose Python JIT
* Runtime JIT compilation (the former Cranelift native-side hot path was removed; scalar-helper embedding is AOT)
* LLVM integration
* MLIR
* General-purpose executable packaging beyond zipapp, Nuitka, and the native
  Rust binary (`--executable-backend=rust`; its entrypoint is a direct-native
  `def main(argv: list[str]) -> int`, and a call it makes to a project fallback
  function is delegated to an external CPython subprocess rather than embedding
  libpython in-process)
* Third-party framework conversion
* ORM conversion
* Bundled third-party package plugin rules
* Async Python compilation
* Generator compilation
* Arbitrary Python object model support
* Monkey patching support
* Dynamic import support
* Runtime reflection support
* Automatic whole-project Rust migration
* LLM API integration
* Managed LLM service
* Background optimization agent

Rextio 0.1.0 alpha is a local CLI and build tool only.

---

## 3. Core Development Principles

### 3.1 Prefer a Narrow Working MVP

A small supported subset that works end-to-end is better than a large incomplete compiler.

Do not expand the Python subset unless:

1. The analyzer can validate it.
2. The IR can represent it.
3. The boundary checker can reason about it.
4. The Rust code generator can lower it.
5. The generated Rust compiles.
6. The fallback behavior remains correct.
7. Tests cover it.

### 3.2 Always Preserve Fallback Safety

Native compilation is an optimization, not a correctness requirement.

If a native module is missing, fails to load, or is disabled, the generated package must still be able to use the fallback Python implementation.

Required runtime switch:

```text
REXTIO_DISABLE_NATIVE=1
```

When this variable is set, the package must use fallback implementations.

### 3.3 Treat Boundary Crossings Conservatively

Crossing between Python fallback code and Rust native code can be expensive.

0.1.0 alpha must not implement a full cost model, but it must enforce conservative static safety rules and a simple runtime crossing threshold:

* Native functions must not call fallback-only functions.
* Native functions must not call unsupported external package functions.
* Native functions may call only accepted native functions and supported builtins/standard functions.
* Python fallback code may call native functions.
* Python fallback loops that repeatedly call native functions should produce warnings.
* Generated wrappers may initially cross into native code, but should use CPython/Nuitka fallback for that function after repeated wrapper crossings exceed `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`.

### 3.4 Do Not Modify User Source In-Place During Build

Build output must be generated under a build directory, not by rewriting user source files.

Preferred output layout:

```text
.rextio/
  build/
  generated/
  reports/
```

User source files should remain stable and human-maintained.

### 3.5 Generated Files Must Be Clearly Marked

Every generated file must contain a header like:

```text
# Generated by Rextio. Do not edit manually.
```

or for Rust:

```rust
// Generated by Rextio. Do not edit manually.
```

### 3.6 Python Is the Product Surface

The user-facing source language is Python.

Avoid exposing Rust concepts such as ownership, borrowing, lifetimes, unsafe, Send, Sync, or trait bounds to normal Rextio users in 0.1.0 alpha.

---

## 4. Recommended Repository Structure

Use this structure unless the existing repository already differs significantly.

```text
rextio/
├─ pyproject.toml
├─ README.md
├─ AGENTS.md
├─ REXTIO.md
├─ src/
│  └─ rextio/
│     ├─ __init__.py
│     ├─ cli/
│     │  ├─ __init__.py
│     │  ├─ main.py
│     │  ├─ init_cmd.py
│     │  ├─ check_cmd.py
│     │  ├─ build_cmd.py
│     │  ├─ bench_cmd.py
│     │  └─ clean_cmd.py
│     ├─ config/
│     │  ├─ __init__.py
│     │  ├─ schema.py
│     │  ├─ loader.py
│     │  └─ defaults.py
│     ├─ analyzer/
│     │  ├─ __init__.py
│     │  ├─ project_scanner.py
│     │  ├─ module_parser.py
│     │  ├─ native_marker.py
│     │  ├─ type_collector.py
│     │  ├─ dependency_graph.py
│     │  ├─ diagnostics.py
│     │  ├─ unsupported_patterns.py
│     │  └─ boundary.py
│     ├─ ir/
│     │  ├─ __init__.py
│     │  ├─ nodes.py
│     │  ├─ types.py
│     │  ├─ module.py
│     │  └─ lowering.py
│     ├─ codegen/
│     │  ├─ __init__.py
│     │  ├─ rust/
│     │  │  ├─ __init__.py
│     │  │  ├─ generator.py
│     │  │  ├─ pyo3.py
│     │  │  ├─ cargo.py
│     │  │  ├─ type_map.py
│     │  │  └─ templates/
│     │  └─ python_wrapper/
│     │     ├─ __init__.py
│     │     ├─ wrapper_gen.py
│     │     └─ import_rewriter.py
│     ├─ targets/
│     │  ├─ __init__.py
│     │  ├─ models.py
│     │  └─ plan.py
│     ├─ plugins/
│     │  ├─ __init__.py
│     │  ├─ models.py
│     │  └─ loader.py
│     ├─ partition/
│     │  ├─ __init__.py
│     │  ├─ classifier.py
│     │  ├─ native_plan.py
│     │  ├─ fallback_plan.py
│     │  └─ build_plan.py
│     ├─ build/
│     │  ├─ __init__.py
│     │  ├─ orchestrator.py
│     │  ├─ cargo_builder.py
│     │  ├─ maturin_builder.py
│     │  ├─ nuitka_builder.py
│     │  ├─ wheel_builder.py
│     │  ├─ artifact_layout.py
│     │  └─ env.py
│     ├─ fallback/
│     │  ├─ __init__.py
│     │  ├─ cpython.py
│     │  ├─ nuitka.py
│     │  ├─ module_copy.py
│     │  └─ fallback_marker.py
│     ├─ runtime/
│     │  ├─ __init__.py
│     │  ├─ dispatcher.py
│     │  ├─ native_loader.py
│     │  └─ flags.py
│     ├─ bench/
│     │  ├─ __init__.py
│     │  ├─ runner.py
│     │  ├─ compare.py
│     │  └─ report.py
│     └─ llm_specs/
│        ├─ __init__.py
│        ├─ generator.py
│        ├─ rules.yaml
│        └─ templates/
├─ examples/
│  ├─ pure_math/
│  ├─ app_shell/
│  └─ fallback_demo/
├─ tests/
│  ├─ analyzer/
│  ├─ ir/
│  ├─ codegen/
│  ├─ build/
│  ├─ runtime/
│  ├─ bench/
│  ├─ fixtures/
│  └─ e2e/
└─ docs/
```

---

## 5. Language Allocation

Use Python for most of 0.1.0 alpha implementation.

Use Rust only where Rust is directly required.

### 5.1 Python

Use Python for:

* CLI
* config loading
* project scanning
* Python AST parsing
* subset checking
* boundary checking
* IR construction
* initial Rust code generation
* build orchestration
* wrapper generation
* fallback packaging
* benchmark runner
* test harness

### 5.2 Rust

Use Rust for:

* generated native target code
* small PyO3 helper runtime
* common conversion helpers if needed

Do not prematurely move the analyzer, boundary checker, or code generator into Rust for 0.1.0 alpha.

0.1.0 alpha should prioritize fast iteration and end-to-end behavior.

---

## 6. 0.1.0 alpha CLI Commands

Implement these commands first:

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

### 6.1 `rextio init`

Creates:

```text
rextio.toml
REXTIO.md
.rextioignore
```

Default `rextio.toml`:

```toml
[build]
native_backend = "rust"
fallback_backend = "cpython"
fallback_threshold = 1000
build_timeout_seconds = 600

[rust]
binding = "pyo3"
build_tool = "cargo"
importable = false
crate_name = "rextio_generated_rust"

[fallback]
nuitka = "experimental"

[target]
# version = "stable"

[target.build_options]
# profile = "release"

[plugins]
enabled = []

[imports]
default_external_policy = "fallback"

[imports.packages]
# "some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
# "legacy_dynamic_pkg" = "fallback"
# "known_pkg" = { policy = "plugin", plugin = "known-rust" }

[jit]
enabled = false

[executable]
# entrypoint = "myapp.cli:main"
# name = "myapp"
backend = "zipapp"
nuitka_mode = "standalone"

[policy]
native_marker = "auto"
require_type_hints = true
allow_dynamic_features = false
boundary_warnings = true
native_top_level = false
```

### 6.2 `rextio check`

Checks the project and prints diagnostics.

It must detect:

* automatically discoverable statically typed native candidates
* `@rextio.native`
* `@rextio.exempt`
* missing or unresolved native signature types
* unsupported argument types
* unsupported return types
* unsupported syntax
* unsupported external package calls inside native functions
* dynamic Python features inside native functions
* native functions calling fallback-only functions
* native functions calling rejected native dependencies
* Python loops calling native functions repeatedly

Example output:

```text
Rextio check

Native candidates:
  ✓ myapp.scoring.compute_score
  ✓ myapp.math_ops.sum_squares

Rejected:
  ✗ myapp.users.get_user_score
    reason: external package call: external.package

  ✗ myapp.parser.parse_record
    reason: unsupported dynamic getattr

  ✗ myapp.pipeline.compute_batch
    reason: native function calls fallback-only function: helper

Boundary warnings:
  ⚠ myapp.pipeline.process_all
    reason: native function score_one is called inside a Python loop
    suggestion: move the loop into a native batch function
```

### 6.3 `rextio build`

Builds a hybrid artifact.

Minimum supported options:

```text
rextio build
rextio build --native-backend=rust
rextio build --target-language=rust
rextio build --target-version=stable
rextio build --target-build-option profile=release
rextio build --enable-plugin=python-basic-rust
rextio build --default-external-policy=fallback
rextio build --package-import-policy some_pure_python_pkg=try-native
rextio build --fallback=cpython
rextio build --fallback=nuitka
rextio build --fallback-threshold=1000
rextio build --jit
rextio build --no-jit
rextio build --rust-binding=pyo3
rextio build --rust-build-tool=maturin
rextio build --rust-importable
rextio build --rust-importable --rust-crate-name=my_native
rextio build --native-marker=auto
rextio build --native-top-level
rextio build --no-boundary-warnings
rextio build --entrypoint=myapp.cli:main
rextio build --entrypoint=myapp.cli:main --executable-name=myapp
rextio build --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Build and analysis settings should resolve with this precedence:

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

Supported environment variable mirrors:

```text
REXTIO_NATIVE_BACKEND
REXTIO_TARGET_LANGUAGE
REXTIO_TARGET_VERSION
REXTIO_TARGET_BUILD_OPTIONS
REXTIO_PLUGINS_ENABLED
REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY
REXTIO_IMPORTS_PACKAGES
REXTIO_JIT
REXTIO_FALLBACK_BACKEND
REXTIO_BOUNDARY_FALLBACK_THRESHOLD
REXTIO_BUILD_TIMEOUT
REXTIO_RUST_BINDING
REXTIO_RUST_BUILD_TOOL
REXTIO_RUST_IMPORTABLE
REXTIO_RUST_CRATE_NAME
REXTIO_NUITKA_FALLBACK
REXTIO_EXECUTABLE_ENTRYPOINT
REXTIO_EXECUTABLE_NAME
REXTIO_EXECUTABLE_BACKEND
REXTIO_NUITKA_MODE
REXTIO_NATIVE_MARKER
REXTIO_REQUIRE_TYPE_HINTS
REXTIO_ALLOW_DYNAMIC_FEATURES
REXTIO_BOUNDARY_WARNINGS
REXTIO_NATIVE_TOP_LEVEL
```

Command routing and output formatting flags such as project roots, bench
targets, `init --force`, and `check --json` are command-line concerns rather
than project configuration.

Rust is the only implemented native target in 0.1.0 alpha. `mojo` and `julia` may
be accepted as configurable target-language values so version-specific plugin
metadata can be represented, but code generation must fail clearly until those
backends are implemented. Rextio plugins must be ordinary Python packages
installed with tools such as `pip` or `uv`. Each plugin package exposes metadata
through the `rextio.plugins` entry point group, and projects opt into plugin ids
with `[plugins] enabled` or `--enable-plugin`.

Import handling must stay conservative in 0.1.0 alpha:

* Project-local imports are analyzed as normal Rextio code.
* Supported standard-library calls use built-in lowering rules.
* Active plugins may claim external Python packages through plugin metadata.
* External packages without an active plugin use
  `[imports] default_external_policy = "fallback"` by default.
* Package-specific `policy = "try-native"` is an explicit opt-in for future
  dependency lowering and analysis reporting only; do not silently translate
  arbitrary third-party package source into Rust.
* Package-specific `policy = "plugin"` requires the referenced plugin to be
  active for the build.

If a native candidate calls a fallback-policy external package, reject that
candidate from direct Rust lowering with `RXT030`. If the call is inside a loop,
the diagnostic should suggest function-level fallback, adding a plugin, or
refactoring to a batch API to avoid repeated Python/Rust boundary crossings.

Experimental scalar-helper embedding must stay opt-in:

* Default `[jit] enabled = false`.
* `--jit`, `REXTIO_JIT=true`, or `[jit] enabled = true` may enable it.
* `--no-jit` must override environment and `rextio.toml` settings.
* The embedding subset is limited to unmarked scalar `int`/`float` helpers
  that Rextio can represent as IR and that have a single arithmetic return
  expression.
* Embedded helpers are not exported as PyO3 functions. They are called only
  from generated native Rust code, and they lower through the normal checked
  path (overflow raises OverflowError; there is no runtime compilation - the
  former Cranelift hot path was removed after benchmarks showed it strictly
  slower than the AOT lowering).
* Generated Cargo projects must not contain Cranelift dependencies.
* If a helper falls outside the embedding subset, use normal boundary
  rejection or fallback behavior. Do not build a CPython-hosted JIT API;
  Numba is the external accelerator for fallback code (experimental).

Behavior:

* Generate Rust code for accepted native functions.
* Reject unsafe native-to-fallback call boundaries.
* Emit warnings for likely excessive Python-to-native call patterns.
* Optionally generate a Rust native module initializer for supported module
  top-level logic when `[policy] native_top_level = true` or
  `--native-top-level` is set.
* Generate PyO3 bindings.
* Generate Cargo project.
* Invoke maturin or Cargo as needed.
* Optionally generate and compile a Rust-importable library crate for accepted
  direct Rust functions.
* Optionally embed eligible unmarked scalar helpers as internal native
  functions when experimental embedding is enabled.
* Copy fallback Python modules.
* Generate import-compatible wrappers.
* Embed the default runtime boundary fallback threshold in generated wrappers.
* Produce a build artifact under `.rextio/build/`.
* Optionally produce a wheel under `dist/`.
* Optionally produce a zipapp executable artifact under `dist/` when `--entrypoint=module:function` is provided.
* Optionally invoke Nuitka to produce standalone or onefile executable artifacts.

Nuitka fallback is experimental in 0.1.0 alpha.

CPython fallback is stable and required.

Zipapp executable artifacts require a compatible Python interpreter on the
target machine. Native extension modules are not imported directly from inside
the zipapp, so generated wrappers must preserve fallback behavior when
`_rextio_native` is unavailable.

Nuitka executable artifacts require Nuitka to be installed. `--nuitka-mode=standalone`
should produce a `.dist` application directory, and `--nuitka-mode=onefile`
should produce a single executable. Do not claim cross-platform packaging of
arbitrary third-party dependencies in 0.1.0 alpha.

### 6.4 `rextio bench`

Benchmarks native vs fallback implementation.

Example:

```text
rextio bench myapp.scoring.compute_score
```

Output should compare:

* fallback Python execution time
* Rust native execution time
* speedup ratio

Example:

```text
compute_score(list[float], n=1_000_000)

Python fallback: 44.8 ms
Rust native:      6.1 ms
Speedup:          7.3x
```

`rextio bench` should not implement a full boundary-cost optimizer in 0.1.0 alpha. It may benchmark a specific function but should not automatically decide project-wide fallback policy based on runtime measurements.

### 6.5 `rextio clean`

Removes generated build artifacts.

Should remove:

```text
.rextio/build/
.rextio/generated/
.rextio/reports/
```

Do not delete user source files.

---

## 7. 0.1.0 alpha Python Subset

Only support a narrow typed subset.

### 7.1 Supported Types

Support:

```text
int
float
bool
str
bytes
None
list[int]
list[float]
list[bool]
list[str]
list[list[T]]
tuple[int, float]
dict[K, V] where K is int, bool, or str and V is a supported fixed value type
set[int]
set[bool]
set[str]
set[float] (no native lowering - NaN identity - fallback/shim only)
Optional[T]
T | None
```

Map to Rust:

```text
Python int         -> i64
Python float       -> f64
Python bool        -> bool
Python str         -> String
Python bytes       -> Vec<u8>
Python None        -> ()
Python list[int]   -> Vec<i64>
Python list[float] -> Vec<f64>
Python list[bool]  -> Vec<bool>
Python list[str]   -> Vec<String>
Python list[list[T]] -> Vec<Vec<T>>
Python tuple[...]   -> Rust fixed tuple
Python dict[K, V]   -> HashMap<K, V> for supported fixed K and V
Python set[int]     -> HashSet<i64>
Python set[float]   -> no native lowering (NaN identity); Python fallback or RXT080 shim
Python set[bool]    -> HashSet<bool>
Python set[str]     -> HashSet<String>
Python Optional[T]  -> Option<T>
Python T | None     -> Option<T>
```

### 7.2 Supported Syntax

Support inside native candidate functions:

* module-level function definitions
* typed arguments
* typed return values
* local variables
* assignment
* local variable annotations with initializers, such as `total: float = 0.0`
* augmented assignment: `+=`, `-=`, `*=`, `/=`
* arithmetic operations
* boolean operations
* comparisons (`dict`/`set` operands support only `==` and `!=`, not ordering)
* `if` / `elif` / `else` with a `bool` condition
* `for x in xs`
* `for i in range(len(xs))`
* `for i in range(n)`
* `for i in range(start, stop)`
* `for i in range(start, stop, step)` when `step` is a positive int literal
* `for i, x in enumerate(xs)`
* `for x, y in zip(xs, ys)`
* `while` with a `bool` condition
* `break`
* `continue`
* `return`
* list literals for supported list item types, including typed empty lists such
  as `out: list[int] = []`
* `list.append(x)` for `list[int]`, `list[float]`, `list[bool]`, and `list[str]`
* fixed tuple literals and constant indexing for supported scalar item types
* limited `dict[K, V]` literals, key reads, and `d[key] = value` writes for
  supported fixed key/value types
* list comprehensions over supported `list`, `range`, `enumerate`, and `zip`
  iterables, including optional `if` clauses and multi-generator flattening
* nested list comprehensions that produce `list[list[T]]`
* limited dict comprehensions producing supported fixed `dict[K, V]` types
* limited set comprehensions producing `set[int]`, `set[bool]`, or `set[str]`;
  the comprehension source must be a supported ordered iterable (list, range,
  enumerate, zip) - iterating a set or dict as the source is rejected (hash
  order diverges from CPython)
* assignment expressions inside comprehensions, with Python-style binding into
  the containing function scope and rejection when rebinding comprehension
  iteration variables
* `Optional[T]` / `T | None` annotations with `None` returns and `is None` /
  `is not None` checks
* calls to other accepted native functions
* `len(x)` for `list`, `set`, `dict`, `str`, and `bytes` (`str` counts Unicode
  code points, matching CPython, not UTF-8 bytes)
* limited `abs`, `min`, `max`, and `sum` builtins
* limited `all`, `any`, `sorted`, and `reversed` builtins
* limited `math` subset including trigonometric, logarithmic, rounding,
  finite/NaN checks, `math.pi`, and `math.e`
* limited `print(...)` lowering to Rust `println!`
* limited `logging.debug/info/warning/error(...)` lowering to Rust `log` macros
* limited module logger method calls when the logger variable is assigned from
  `logging.getLogger(...)`
* limited `datetime.datetime.now/utcnow().isoformat()` and timestamp lowering
  to Rust `chrono` formatting/time values
* limited `time.time()` lowering
* `statistics.mean`/`statistics.fmean` have NO direct native lowering
  (naive native summation diverges from CPython's exact/`math.fsum`
  behavior); marked functions using them ride the RXT080 shim and
  auto-discovered ones stay on the Python fallback
* limited `str`/`bytes`/`list` method lowering
* limited `hashlib.sha256(...).hexdigest()` and `base64.b64encode` lowering
  (`base64.b64decode` - CPython discards non-alphabet characters the native
  decoder rejects - and `json.dumps`/`json.loads` - serde is not
  CPython-`json`-compatible - never compile to direct Rust: marked functions
  ride the RXT080 runtime shim, auto-discovered ones stay on the fallback)
* simple `list`, fixed `tuple`, and fixed `dict` indexing such as `xs[i]`
  (`str` and `bytes` indexing is not supported)

Direct Rust lowering must treat Python/Rust ownership differences
conservatively. Generated Rust may clone owned values such as `String`,
`Vec<T>`, `HashMap<K, V>`, and `HashSet<T>` when a Python value is reused after
assignment or captured in a container literal. Do not silently change mutable
alias semantics: if a native candidate creates a mutable collection alias, such
as `ys = xs`, or captures a mutable collection inside a container literal and
then mutates either alias through supported `append`/dict assignment, reject
that candidate from direct Rust lowering and keep it on Python fallback.

When `[policy] native_top_level = true` or `--native-top-level` is set, Rextio
may also convert a narrower subset of module top-level executable statements.
Supported top-level native initialization is limited to assignment, annotated
assignment, augmented assignment, expressions supported by the native subset,
`if` and `while` blocks that update variables assigned before the block, and
homogeneous assigned module variables that can be returned as `dict[str, T]`
from the generated initializer. Imports, function definitions, class
definitions, and module docstrings remain in Python fallback. Rextio must keep a
full original fallback module and use it when native is disabled or unavailable.

### 7.3 Runtime Semantics Shim

Some Python semantics are not directly lowered into typed Rust statements, but
may be exposed through a generated Rust/PyO3 native shim that calls the
generated Python fallback implementation. This path must preserve Python
semantics and must emit `RXT080` so users understand it is a compatibility path,
not a Rust speedup path.

Runtime-backed native functions may cover:

* class/object behavior inside a marked native function
* regular instance methods marked with `@rextio.native`
* exception handling
* context managers
* `async` / `await`
* generators / `yield`
* dynamic attribute access such as `obj.attr`
* `getattr`, `setattr`, and `hasattr`

If a direct-Rust native function calls a runtime-backed native function, promote
the caller to the runtime shim path and emit `RXT080`. Do not generate direct
Rust code that treats Python object values as statically typed Rust values.
Automatic discovery for this path must remain conservative. Broad object-runtime
functions should require an explicit `@rextio.native` marker.

### 7.4 Unsupported Direct-Rust Syntax

Reject inside direct-Rust native candidate functions unless the runtime
semantics shim explicitly covers the construct:

* decorators other than `@rextio.native` or `@rextio.native(target="...")`
* lambdas
* closures
* nested functions
* generator expressions
* assignment expressions outside comprehensions
* set literals in 0.1.0 alpha
* general tuple, dict, or set semantics beyond the fixed tuple, limited fixed
  `dict[K, V]`, and limited `set[int|float|bool|str]` subsets
* dataclasses in 0.1.0 alpha
* `enumerate` outside a supported loop or comprehension iterable
* `zip` outside a supported loop or comprehension iterable
* `range` outside a supported loop or comprehension iterable (value-position
  `range(...)` such as `return range(n)`)
* non-`bool` `if`, `elif`, `while`, and comprehension `if` conditions; the
  condition must be `bool`, so use an explicit comparison (`if len(xs) > 0:`,
  `if x != 0:`) rather than relying on Python truthiness
* ordering comparisons (`<`, `<=`, `>`, `>=`) on `dict` or `set` operands; only
  `==` and `!=` are supported for those types
* `str` and `bytes` indexing such as `s[0]` (only `list`, fixed `tuple`, and
  fixed `dict` subscripting is lowered)
* `len()` of a fixed tuple
* multiple assignment targets such as `a = b = value`
* integer literals outside the signed 64-bit (`i64`) range
* a value-position read of a name bound nowhere in the function (a module
  global, a closure, or a name first bound inside a nested `if`/`for`/`while`/
  `try` block and read after it)
* calling a name shadowed by a local binding or a module-level assignment (such
  as `len = 5` at module scope, then `len(xs)`)
* dynamic import
* `globals`
* `locals`
* `eval`
* `exec`
* monkey patching
* arbitrary `*args`
* arbitrary `**kwargs`
* file I/O
* network I/O
* database calls
* ORM calls

Reject top-level native initialization when module-level executable statements
use unsupported syntax, user/external function calls, top-level `for` loops
whose iteration variables would leak into module scope, or assigned module
variables with heterogeneous export value types. Route the module top level to
Python fallback instead of silently changing import-time semantics.

When unsupported syntax is found, emit a diagnostic and route the function to fallback.

Do not silently generate incorrect Rust.

---

## 8. Native Discovery, Marker, and Exemptions

0.1.0 alpha defaults to automatic native candidate discovery for module-level typed
functions that fit the supported subset and pass boundary checks.

`@rextio.native` remains supported as an explicit marker:

```python
import rextio

@rextio.native
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += x * x
    return total
```

When multiple native target languages are configured in future releases, an
explicit marker can force a function to a specific target:

```python
import rextio

@rextio.native(target="rust")
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += x * x
    return total
```

The target name is normalized case-insensitively. 0.1.0 alpha accepts `rust`,
`mojo`, and `julia` as target-planning values, but only Rust code generation is
implemented. A target-specific marker applies only when the active
`[build] native_backend` / `--target-language` matches that marker. For example,
`@rextio.native(target="mojo")` is not a Rust native candidate when the active
target is Rust; it remains Python fallback for that build.

Projects that want decorator-only behavior can opt out of automatic discovery:

```toml
[policy]
native_marker = "decorator"
```

When `native_marker = "decorator"`, only functions marked with
`@rextio.native` or a matching `@rextio.native(target="...")` are native
candidates.

When `native_marker = "auto"` (the default), Rextio may treat unmarked
module-level functions as native candidates if they have supported static types
from annotations, sibling `.pyi` stubs, or conservative local context inference
and pass the same subset and boundary checks as marked functions.

`@rextio.exempt` always opts a function out of native compilation:

```python
import rextio

@rextio.exempt
def must_stay_python(x: float) -> float:
    return x + 1.0
```

Exemptions take precedence over automatic discovery and over `@rextio.native`.
An exempt function must never be emitted into generated Rust. If a native
candidate calls an exempt function, treat that callee as fallback-only and apply
the normal native-to-fallback boundary rejection.

Do not compile functions whose argument or return types remain unresolved, or
functions outside the supported 0.1.0 alpha subset. Automatic discovery must
remain conservative and deterministic.

---

## 9. Boundary Crossing Policy for 0.1.0 alpha

Rextio 0.1.0 alpha must include a conservative static boundary policy.

The goal is to prevent obviously unsafe native/fallback interactions while avoiding premature runtime cost modeling.

### 9.1 Required Boundary Rules

A native function may call only:

* other accepted native functions
* supported builtins
* supported standard-library functions

If a native function calls any of the following, reject that function from native compilation and route it to fallback:

* fallback-only user function
* rejected native candidate
* unsupported external package function
* dynamic callable
* ORM call
* I/O function
* unknown function that cannot be resolved statically

Python fallback code may call native functions.

If Python fallback code calls a native function inside a loop, allow it but emit a warning.

### 9.2 Native-to-Native Calls

Allowed:

```python
import rextio

@rextio.native
def square(x: float) -> float:
    return x * x

@rextio.native
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += square(x)
    return total
```

Both functions may be compiled if both pass subset and boundary checks.

### 9.3 Native-to-Fallback Calls

Reject:

```python
import rextio

def helper(x: float) -> float:
    return x * x

@rextio.native
def compute(x: float) -> float:
    return helper(x)
```

`compute` must be routed to fallback because it calls `helper`, which is not accepted as native.

Diagnostic:

```text
RXT070 Native function calls fallback-only function.
```

### 9.4 Rejected Native Dependency

Reject transitive dependency chains.

Example:

```python
import rextio

@rextio.native
def helper(x: float) -> float:
    return eval("x")

@rextio.native
def compute(x: float) -> float:
    return helper(x)
```

`helper` is rejected due to unsupported dynamic behavior. Therefore `compute` must also be rejected.

Diagnostic:

```text
RXT072 Native dependency rejected, so caller must fall back.
```

If `helper` is accepted through the Python runtime semantics shim instead,
`compute` must not be directly lowered to Rust. Promote `compute` to the same
runtime shim path and emit:

```text
RXT080 Native function uses Python runtime semantics shim.
```

### 9.5 Python Loop Calling Native Function

Warn but do not reject:

```python
def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(score_one(x))  # score_one is native
    return out
```

Diagnostic:

```text
RXT073 Native function call inside a Python loop may erase the speedup.
```

Suggestion:

```text
Move the loop into a native batch function. Supported batch loops include
for x in xs, for i, x in enumerate(xs), and for x, y in zip(xs, ys).
```

Do not reject native compilation at analysis time for this case. A native
function may be heavy enough to justify some boundary crossings. Generated
wrappers should use native initially, then switch that function to the generated
CPython/Nuitka fallback path after runtime wrapper crossings exceed
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD`.

### 9.6 Do Not Implement a Full Runtime Boundary Cost Model in 0.1.0 alpha

Do not implement:

* runtime profiling-based automatic fallback
* runtime-weighted native coverage
* boundary overhead measurement
* automatic native region fusion

These belong to Phase 2.5 or later. 0.1.0 alpha may include a simple per-function
wrapper crossing threshold that falls back after repeated Python-to-native calls.

### 9.7 Boundary Diagnostics

0.1.0 alpha should define at least:

```text
RXT070 Native function calls fallback-only function.
RXT072 Native dependency rejected, so caller must fall back.
RXT073 Native function call inside Python loop may erase speedup.
```

Boundary diagnostics must be deterministic and testable.

---

## 10. Analyzer Requirements

The analyzer must produce structured results, not only console text.

Implement internal data structures similar to:

```text
ProjectAnalysis
ModuleAnalysis
FunctionAnalysis
Diagnostic
NativeCandidate
FallbackCandidate
BoundaryDiagnostic
```

Each diagnostic should include:

```text
code
severity
message
file_path
line
column
function_name
suggestion
```

Diagnostic examples:

```text
RXT001 Missing type annotation
RXT002 Unsupported argument type
RXT003 Unsupported return type
RXT010 Unsupported syntax
RXT020 Dynamic Python feature
RXT030 External package call in native function
RXT040 Native dependency rejected
RXT050 Codegen failure
RXT060 Build failure
RXT070 Native function calls fallback-only function
RXT072 Native dependency rejected, so caller must fall back
RXT073 Native function call inside Python loop may erase speedup
RXT074 Undecorated function depends on a runtime-shim native; mark it @rextio.native to opt in
RXT080 Native function uses Python runtime semantics shim
RXT090 Native semantic divergence note (documented, non-rejecting warning)
```

Diagnostics must be deterministic and testable.

---

## 11. IR Requirements

Do not generate Rust directly from Python AST in scattered code.

Use a small Rextio IR layer.

Minimum IR nodes:

```text
ModuleIR
FunctionIR
ParamIR
BlockIR
AssignIR
ReturnIR
IfIR
ForIR
WhileIR
BinaryOpIR
UnaryOpIR
CompareIR
CallIR
NameIR
LiteralIR
IndexIR
```

Minimum type IR:

```text
RxtInt
RxtFloat
RxtBool
RxtStr
RxtNone
RxtList
```

The IR should be simple, explicit, and easy to snapshot test.

The boundary checker may use function dependency metadata before or after IR lowering, but boundary decisions must be reflected in the final build plan.

---

## 12. Rust Codegen Requirements

Generated Rust must be readable enough for debugging.

Do not over-optimize generated Rust in 0.1.0 alpha.

Generated Rust should follow this shape:

```rust
use pyo3::prelude::*;

#[pyfunction]
fn add(a: i64, b: i64) -> PyResult<i64> {
    Ok(a + b)
}

#[pymodule]
fn _rextio_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(add, m)?)?;
    Ok(())
}
```

For Rust/PyO3 version compatibility, keep generated PyO3 code centralized in `codegen/rust/pyo3.py`.

Do not duplicate PyO3 module boilerplate across multiple files.

Do not generate Rust code for a function rejected by boundary checks.

---

## 13. Build Artifact Layout

Preferred generated layout:

```text
.rextio/
  generated/
    rust/
      Cargo.toml
      pyproject.toml
      src/
        lib.rs
    rust_crate/
      Cargo.toml
      src/
        lib.rs
    python/
      myapp/
        scoring.py
        _fallback_scoring.py
  build/
    ...
  reports/
    check.json
    build.json
dist/
  <project>-0.1.0-<tag>.whl
  <rust-crate-name>-rust-crate/
  <executable-name>.pyz
  <executable-name>
  <executable-name>.dist/
```

Build output should not require users to understand this layout.

The CLI should hide this complexity.

---

## 14. Wrapper Requirements

Generated wrappers must preserve normal Python import paths where possible.

Example original source:

```text
src/myapp/scoring.py
```

Generated wrapper:

```python
# Generated by Rextio. Do not edit manually.

from rextio.runtime.flags import native_disabled
from rextio.runtime.native_loader import load_native_function
from ._fallback_scoring import compute_score as _fallback_compute_score

_native_compute_score = load_native_function(
    module_name="_rextio_native",
    function_name="compute_score",
)

def compute_score(values: list[float]) -> float:
    if native_disabled() or _native_compute_score is None:
        return _fallback_compute_score(values)
    return _native_compute_score(values)
```

Wrapper behavior:

1. Try native unless disabled.
2. Fall back to Python if native is unavailable.
3. Do not crash merely because native import fails.
4. Preserve the public function name.
5. Keep type annotations where feasible.

Wrappers should not attempt full runtime boundary-cost optimization in 0.1.0 alpha.
They may apply the simple per-function boundary crossing threshold described in
the boundary policy.

---

## 15. Fallback Requirements

### 15.1 CPython Fallback

CPython fallback is required and stable in 0.1.0 alpha.

Fallback behavior should copy or preserve original Python code for non-native execution.

### 15.2 Nuitka Fallback

Nuitka fallback is experimental in 0.1.0 alpha.

If Nuitka is unavailable, Rextio must report a clear error and suggest CPython fallback.

Do not make Nuitka mandatory for 0.1.0 alpha.

Example message:

```text
Nuitka fallback was requested, but Nuitka is not installed.
Install Nuitka or run: rextio build --fallback=cpython
```

---

## 16. Runtime Flags

Support at least:

```text
REXTIO_DISABLE_NATIVE=1
```

Support runtime boundary fallback controls:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
```

`rextio build --fallback-threshold=N` and
`rextio generate --fallback-threshold=N` should embed the generated-code default
threshold. `[build] fallback_threshold = N` should configure the same generated
default from `rextio.toml`. `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` overrides the
embedded default at runtime.

Optional:

```text
REXTIO_NATIVE_MODE=native
REXTIO_NATIVE_MODE=fallback
REXTIO_NATIVE_MODE=auto
```

`REXTIO_DEBUG_NATIVE=1` raises the full traceback (instead of warning and
falling back) when a built native module fails to load — useful for debugging an
ABI mismatch or a codegen/wrapper name mismatch.

Default mode:

```text
auto
```

In `auto` mode:

1. Use native if available.
2. Fall back to Python otherwise.
3. Fall back to Python for a function after repeated wrapper crossings exceed `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`.

In `native` mode, require generated native functions to be available and bypass
the runtime boundary fallback threshold.

Runtime flags must not override compile-time safety. A function rejected by subset or boundary checks must not be generated as native.

---

## 17. Example Projects Required for 0.1.0 alpha

Create and maintain these examples.

### 17.1 `examples/pure_math`

Shows simple Rust AOT compilation.

Must include:

* `sum_squares`
* `dot_simple`
* `count_positive`

### 17.2 `examples/app_shell`

Shows a realistic Python application shell with a Rust-native hot path.

The application shell remains Python fallback.

Only the scoring function is native.

Message:

```text
Application shell stays Python. compute_score becomes Rust native.
```

### 17.3 `examples/fallback_demo`

Shows fallback safety.

Must demonstrate:

```text
REXTIO_DISABLE_NATIVE=1
```

and native import failure fallback.

### 17.4 `examples/boundary_demo`

Shows boundary safety and warnings.

Must include:

1. A native function calling another accepted native function.
2. A native function rejected because it calls a fallback-only function.
3. A Python fallback loop calling a native function and producing a boundary warning.

---

## 18. Testing Requirements

0.1.0 alpha must include tests for:

### 18.1 Analyzer

* detects `@rextio.native`
* rejects missing or unresolved native signature types
* rejects unsupported syntax
* rejects dynamic features
* accepts supported functions

### 18.2 Boundary Checker

Test:

* native-to-native calls are allowed
* native-to-fallback calls are rejected
* native callers of rejected native dependencies are rejected
* native calls to unsupported package functions are rejected
* Python fallback loops calling native functions produce warnings
* Python fallback one-off calls to native functions are allowed

### 18.3 IR Lowering

* lowers simple arithmetic
* lowers loops
* lowers if statements
* lowers function calls to accepted native functions

### 18.4 Rust Codegen

Use snapshot-style tests for generated Rust.

Generated Rust must be deterministic.

Rejected functions must not appear in generated Rust.

### 18.5 Build

End-to-end build test:

1. fixture Python project
2. `rextio build --fallback=cpython`
3. generated Rust exists
4. native module builds
5. wrapper imports
6. fallback imports
7. native and fallback return the same result
8. functions rejected by boundary checks run through fallback

### 18.6 Runtime

Test:

* native available
* native unavailable
* native disabled by env var
* fallback result matches native result

### 18.7 Bench

Test that `rextio bench` runs and prints a structured comparison.

Do not require exact timing in tests.

---

## 19. Development Workflow for Codex

When implementing a task:

1. Inspect existing files first.
2. Make the smallest coherent change.
3. Preserve public APIs unless explicitly changing them.
4. Add or update tests.
5. Run relevant tests when possible.
6. Keep generated code deterministic.
7. Do not add broad dependencies without justification.
8. Do not silently widen the supported Python subset.
9. Prefer clear diagnostics over permissive behavior.
10. Do not rewrite user source files during build.
11. Do not implement out-of-scope features.
12. Do not bypass boundary checks to make codegen easier.
13. Do not generate native code for functions whose dependencies are rejected.
14. Emit warnings for suspicious boundary patterns rather than hiding them.

If something is ambiguous, prefer the narrower MVP behavior.

---

## 20. Coding Style

### 20.1 Python

Use:

* Python 3.11+
* type annotations
* dataclasses or Pydantic for internal schemas
* pathlib over raw string paths
* subprocess wrappers with explicit error handling
* deterministic output ordering

Prefer:

```python
from pathlib import Path
```

Avoid:

* global mutable state
* hidden filesystem side effects
* broad `except Exception` without diagnostic context
* changing current working directory without restoring it

### 20.2 Rust

Use stable Rust.

Generated Rust should be simple and readable.

Avoid in 0.1.0 alpha:

* unsafe
* custom macros
* complex lifetimes
* async Rust
* multithreading
* custom allocators

### 20.3 Errors

Errors should be actionable.

Bad:

```text
Build failed.
```

Good:

```text
RXT060 Build failed while compiling generated Rust module.
Cause: cargo was not found.
Suggestion: install Rust and Cargo, then rerun rextio build.
```

Boundary diagnostic example:

```text
RXT070 Native function calls fallback-only function.
Function: myapp.pipeline.compute
Called function: myapp.pipeline.helper
Suggestion: mark helper as @rextio.native if it belongs to the supported subset, or remove the call from the native function.
```

---

## 21. Dependency Policy

Keep dependencies minimal.

Acceptable Python dependencies:

* typer or click for CLI
* rich for console output
* tomli/tomllib for TOML loading
* pydantic only if useful for config/schema
* pytest for tests

Avoid unnecessary heavy dependencies in 0.1.0 alpha.

Do not require third-party application framework dependencies in Rextio itself.

Rust dependencies should be minimal:

* pyo3
* base64 for limited Python `base64` lowering
* chrono for limited `datetime` lowering
* log for limited Python `logging` lowering
* serde/serde_json only in the hybrid executable's binary crate (the
  delegated-call wire protocol); generated extension crates never depend on
  them and `json` lowering does not exist (fallback)
* sha2 for limited `hashlib.sha256` lowering
* optionally serde for helper structures later

Do not add LLVM, Cranelift, Tokio, Axum, or framework dependencies in 0.1.0
alpha. Generated Rust projects must not contain Cranelift dependencies (the
former runtime JIT hot path was removed; helper embedding is plain AOT).

---

## 22. 0.1.0 alpha Completion Criteria

0.1.0 alpha is complete only when all of these are true:

1. `pip install -e .` works.
2. `rextio init` creates config files.
3. `rextio check` detects native candidates and unsupported patterns.
4. `rextio check` rejects native-to-fallback calls.
5. `rextio check` warns about Python loops repeatedly calling native functions.
6. `rextio generate --fallback=cpython` writes source artifacts without compiling Rust, Nuitka, wheels, or executables.
7. `rextio build --fallback=cpython` builds a hybrid artifact.
8. `rextio build --fallback=nuitka` either works or reports a clear experimental/installation error.
9. Generated Rust compiles through Cargo/maturin.
10. Generated native functions can be imported from Python.
11. When requested, generated direct-Rust functions can also be compiled into a
    Rust library crate and imported from a Rust project.
12. Fallback works when native is disabled.
13. Functions rejected by boundary checks execute through fallback.
14. At least one example project demonstrates native speedup.
15. At least one example project demonstrates safe fallback.
16. At least one example project demonstrates boundary rejection/warning behavior.
17. E2E tests cover build/import/runtime behavior.
18. README explains 0.1.0 alpha scope honestly.
19. Unsupported features are clearly documented.

---

## 23. README Messaging

The README must not overclaim.

Do not say:

```text
Rextio converts Python projects to Rust.
```

Prefer:

```text
Rextio compiles eligible Python functions with statically resolved types to Rust native modules and packages the rest as safe Python fallback. Projects can opt out of automatic discovery and require `@rextio.native`.
```

Also mention:

```text
0.1.0 alpha includes conservative static boundary checks. It rejects native functions that call fallback-only code, warns when Python loops repeatedly call native functions, and uses generated fallback after repeated wrapper crossings exceed a simple runtime threshold.
```

Also mention that functions requiring Python object/runtime semantics may use a
Rust/PyO3 runtime shim with `RXT080`, and that this preserves compatibility
rather than promising Rust speedup.

Do not claim full Python compatibility.

Do not claim bundled third-party package support.

Do not claim framework migration.

Do not claim full runtime boundary-cost optimization.

Do not claim any runtime JIT. Scalar-helper embedding is opt-in, AOT,
native-side only, and limited to narrow scalar Rextio IR helper regions;
Numba is the external accelerator for fallback code (experimental).

---

## 24. Architecture Summary

0.1.0 alpha architecture:

```text
User Python project
  -> project scanner
  -> native marker detection
  -> subset checker
  -> dependency graph
  -> boundary safety checker
  -> Rextio IR
  -> partition plan
      -> Rust AOT codegen
      -> CPython/Nuitka fallback
  -> PyO3/maturin build
  -> wrapper generation
  -> hybrid artifact
```

Main invariant:

```text
Native acceleration must never remove the ability to run fallback Python code.
```

Boundary invariant:

```text
A generated native function must never depend on fallback-only Python code.
```

---

## 25. Implementation Order

Implement in this order:

1. CLI skeleton
2. config loader
3. project scanner
4. native candidate discovery and `@rextio.native` detector
5. subset checker for simple functions
6. diagnostics model
7. dependency graph for function calls
8. static boundary checker
9. IR for simple expressions/statements
10. Rust code generator for simple functions
11. PyO3 module generator
12. Cargo/maturin builder
13. CPython fallback copier
14. wrapper generator
15. build orchestrator
16. runtime native loader and disable flag
17. benchmark command
18. examples
19. boundary demo
20. e2e tests
21. Nuitka fallback experimental integration
22. docs and README polish

Do not start with Nuitka.

Do not start with SaaS.

Do not start with framework plugins.

Do not start with profiling or full runtime boundary-cost optimization.

---

## 26. Design Biases

When there is a trade-off:

* Choose correctness over performance.
* Choose explicit support over implicit magic.
* Choose fallback safety over aggressive native compilation.
* Choose clear diagnostics over silent behavior.
* Choose small subset over broad unsound subset.
* Choose deterministic generated output over clever codegen.
* Choose static boundary safety over premature runtime optimization.
* Choose local CLI usability over cloud-first architecture.

---

## 27. Future Phases, Not 0.1.0 alpha

The architecture may leave extension points for these, but do not implement them yet:

* package adapter registry
* third-party package plugin subsets
* profiling and optimization intelligence
* full runtime boundary-cost model
* runtime-weighted native coverage
* native region fusion suggestions
* GitHub PR integration
* SaaS dashboard
* cloud build
* framework conversion plugin
* framework-aware profiling
* general-purpose JIT metadata
* production JIT
* runtime JIT compilation of any kind (helper embedding is AOT)
* enterprise/on-prem platform

Keep 0.1.0 alpha focused.

---

## 28. Final Reminder for Codex

This project should first prove one thing:

> A normal Python project can be built into a hybrid artifact where selected statically typed Python functions run as Rust native code and everything else still works through safe Python fallback.

0.1.0 alpha must also prove one safety property:

> Native functions never depend on fallback-only Python functions, and suspicious Python/Rust boundary patterns are reported clearly.

Every implementation decision in 0.1.0 alpha should support those two demonstrations.
