# AGENTS.md

# Rextio Public 1 Development Guide

This repository implements **Rextio Public 1**, the first public MVP of Rextio.

Rextio Public 1 is a hybrid build tool for Python projects:

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

## 1. Product Scope for Public 1

Public 1 must demonstrate all of the following:

1. A Python project can let Rextio discover eligible typed functions automatically, and can optionally mark functions with `@rextio.native`.
2. A Python project can mark functions with `@rextio.exempt` to keep them on Python fallback.
3. Rextio can check whether those functions belong to the supported subset.
4. Rextio can reject unsafe native-to-fallback call boundaries.
5. Rextio can warn about likely excessive Python-to-Rust boundary crossings.
6. Rextio can use generated Python fallback after repeated Python-to-Rust wrapper crossings exceed a simple runtime threshold.
7. Rextio can generate Rust code for supported typed Python functions.
8. Rextio can generate PyO3 bindings.
9. Rextio can build the generated Rust module with Cargo/maturin.
10. Rextio can preserve Python fallback behavior.
11. Rextio can package a hybrid output where native functions are used when available and fallback functions are used otherwise.
12. Rextio can optionally invoke Nuitka for fallback packaging.
13. Rextio can optionally generate a zipapp executable artifact for a configured Python entrypoint.
14. Rextio can optionally invoke Nuitka for standalone or onefile executable packaging.
15. Rextio can run simple benchmarks comparing Python fallback and Rust native execution.
16. Rextio can provide a clear demo project showing a normal Python app with a Rust-compiled hot path.

The first public release must feel like a usable hybrid compiler/build tool, not merely a static analyzer.

---

## 2. Non-Goals for Public 1

Do not implement these in Public 1 unless explicitly requested:

* SaaS dashboard
* GitHub App
* Cloud build service
* Runtime profiling-based automatic fallback
* Full runtime boundary-cost model
* Runtime-weighted native/fallback optimization
* JIT
* Cranelift
* LLVM integration
* MLIR
* FastAPI-to-Axum conversion
* General-purpose executable packaging beyond zipapp and Nuitka
* Django conversion
* Flask conversion
* SQLAlchemy/Django ORM conversion
* Full NumPy support
* Full pandas support
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

Rextio Public 1 is a local CLI and build tool only.

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

Public 1 must not implement a full cost model, but it must enforce conservative static safety rules and a simple runtime crossing threshold:

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

Avoid exposing Rust concepts such as ownership, borrowing, lifetimes, unsafe, Send, Sync, or trait bounds to normal Rextio users in Public 1.

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
├─ crates/
│  └─ rextio_runtime/
│     ├─ Cargo.toml
│     └─ src/
│        ├─ lib.rs
│        ├─ errors.rs
│        └─ conversions.rs
├─ examples/
│  ├─ pure_math/
│  ├─ fastapi_scoring/
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

Use Python for most of Public 1 implementation.

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

Do not prematurely move the analyzer, boundary checker, or code generator into Rust for Public 1.

Public 1 should prioritize fast iteration and end-to-end behavior.

---

## 6. Public 1 CLI Commands

Implement these commands first:

```text
rextio init
rextio check
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

[rust]
binding = "pyo3"
build_tool = "maturin"

[fallback]
nuitka = "experimental"

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
```

### 6.2 `rextio check`

Checks the project and prints diagnostics.

It must detect:

* automatically discoverable typed native candidates
* `@rextio.native`
* `@rextio.exempt`
* missing type annotations
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
    reason: external package call: django.orm

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
rextio build --fallback=cpython
rextio build --fallback=nuitka
rextio build --fallback-threshold=1000
rextio build --rust-binding=pyo3
rextio build --rust-build-tool=maturin
rextio build --native-marker=auto
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
REXTIO_FALLBACK_BACKEND
REXTIO_BOUNDARY_FALLBACK_THRESHOLD
REXTIO_RUST_BINDING
REXTIO_RUST_BUILD_TOOL
REXTIO_NUITKA_FALLBACK
REXTIO_EXECUTABLE_ENTRYPOINT
REXTIO_EXECUTABLE_NAME
REXTIO_EXECUTABLE_BACKEND
REXTIO_NUITKA_MODE
REXTIO_NATIVE_MARKER
REXTIO_REQUIRE_TYPE_HINTS
REXTIO_ALLOW_DYNAMIC_FEATURES
REXTIO_BOUNDARY_WARNINGS
```

Command routing and output formatting flags such as project roots, bench
targets, `init --force`, and `check --json` are command-line concerns rather
than project configuration.

Behavior:

* Generate Rust code for accepted native functions.
* Reject unsafe native-to-fallback call boundaries.
* Emit warnings for likely excessive Python-to-native call patterns.
* Generate PyO3 bindings.
* Generate Cargo project.
* Invoke maturin or Cargo as needed.
* Copy fallback Python modules.
* Generate import-compatible wrappers.
* Embed the default runtime boundary fallback threshold in generated wrappers.
* Produce a build artifact under `.rextio/build/`.
* Optionally produce a wheel under `dist/`.
* Optionally produce a zipapp executable artifact under `dist/` when `--entrypoint=module:function` is provided.
* Optionally invoke Nuitka to produce standalone or onefile executable artifacts.

Nuitka fallback is experimental in Public 1.

CPython fallback is stable and required.

Zipapp executable artifacts require a compatible Python interpreter on the
target machine. Native extension modules are not imported directly from inside
the zipapp, so generated wrappers must preserve fallback behavior when
`_rextio_native` is unavailable.

Nuitka executable artifacts require Nuitka to be installed. `--nuitka-mode=standalone`
should produce a `.dist` application directory, and `--nuitka-mode=onefile`
should produce a single executable. Do not claim cross-platform packaging of
arbitrary third-party dependencies in Public 1.

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

`rextio bench` should not implement a full boundary-cost optimizer in Public 1. It may benchmark a specific function but should not automatically decide project-wide fallback policy based on runtime measurements.

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

## 7. Public 1 Python Subset

Only support a narrow typed subset.

### 7.1 Supported Types

Support:

```text
int
float
bool
str
None
list[int]
list[float]
list[bool]
list[str]
```

Map to Rust:

```text
Python int         -> i64
Python float       -> f64
Python bool        -> bool
Python str         -> String
Python None        -> ()
Python list[int]   -> Vec<i64>
Python list[float] -> Vec<f64>
Python list[bool]  -> Vec<bool>
Python list[str]   -> Vec<String>
```

### 7.2 Supported Syntax

Support inside native candidate functions:

* module-level function definitions
* typed arguments
* typed return values
* local variables
* assignment
* arithmetic operations
* boolean operations
* comparisons
* `if` / `elif` / `else`
* `for x in xs`
* `for i in range(len(xs))`
* `while`
* `return`
* calls to other accepted native functions
* `len(x)`
* simple indexing such as `xs[i]`

### 7.3 Unsupported Syntax

Reject inside native candidate functions:

* class definitions
* instance methods
* decorators other than `@rextio.native`
* async functions
* await
* generators
* yield
* lambdas
* closures
* nested functions
* comprehensions in Public 1
* dynamic import
* `getattr`
* `setattr`
* `hasattr`
* `globals`
* `locals`
* `eval`
* `exec`
* monkey patching
* arbitrary `*args`
* arbitrary `**kwargs`
* exception handling in native functions
* context managers
* file I/O
* network I/O
* database calls
* ORM calls

When unsupported syntax is found, emit a diagnostic and route the function to fallback.

Do not silently generate incorrect Rust.

---

## 8. Native Discovery, Marker, and Exemptions

Public 1 defaults to automatic native candidate discovery for module-level typed
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

Projects that want decorator-only behavior can opt out of automatic discovery:

```toml
[policy]
native_marker = "decorator"
```

When `native_marker = "decorator"`, only functions marked with `@rextio.native`
are native candidates.

When `native_marker = "auto"` (the default), Rextio may treat unmarked
module-level functions as native candidates if they have supported type
annotations and pass the same subset and boundary checks as marked functions.

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

Do not compile untyped functions or functions outside the supported Public 1
subset. Automatic discovery must remain conservative and deterministic.

---

## 9. Boundary Crossing Policy for Public 1

Rextio Public 1 must include a conservative static boundary policy.

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
    return getattr(x, "value")

@rextio.native
def compute(x: float) -> float:
    return helper(x)
```

`helper` is rejected due to unsupported dynamic behavior. Therefore `compute` must also be rejected.

Diagnostic:

```text
RXT072 Native dependency rejected, so caller must fall back.
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
RXT071 Possible excessive Python/Rust boundary crossing.
```

Suggestion:

```text
Move the loop into a native batch function.
```

Do not reject native compilation at analysis time for this case. A native
function may be heavy enough to justify some boundary crossings. Generated
wrappers should use native initially, then switch that function to the generated
CPython/Nuitka fallback path after runtime wrapper crossings exceed
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD`.

### 9.6 Do Not Implement a Full Runtime Boundary Cost Model in Public 1

Do not implement:

* runtime profiling-based automatic fallback
* runtime-weighted native coverage
* boundary overhead measurement
* automatic native region fusion

These belong to Phase 2.5 or later. Public 1 may include a simple per-function
wrapper crossing threshold that falls back after repeated Python-to-native calls.

### 9.7 Boundary Diagnostics

Public 1 should define at least:

```text
RXT070 Native function calls fallback-only function.
RXT071 Possible excessive Python/Rust boundary crossing.
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
RXT071 Possible excessive Python/Rust boundary crossing
RXT072 Native dependency rejected, so caller must fall back
RXT073 Native function call inside Python loop may erase speedup
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

Do not over-optimize generated Rust in Public 1.

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

Wrappers should not attempt full runtime boundary-cost optimization in Public 1.
They may apply the simple per-function boundary crossing threshold described in
the boundary policy.

---

## 15. Fallback Requirements

### 15.1 CPython Fallback

CPython fallback is required and stable in Public 1.

Fallback behavior should copy or preserve original Python code for non-native execution.

### 15.2 Nuitka Fallback

Nuitka fallback is experimental in Public 1.

If Nuitka is unavailable, Rextio must report a clear error and suggest CPython fallback.

Do not make Nuitka mandatory for Public 1.

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

## 17. Example Projects Required for Public 1

Create and maintain these examples.

### 17.1 `examples/pure_math`

Shows simple Rust AOT compilation.

Must include:

* `sum_squares`
* `dot_simple`
* `count_positive`

### 17.2 `examples/fastapi_scoring`

Shows a realistic Python web app shell with Rust-native hot path.

FastAPI itself remains Python fallback.

Only the scoring function is native.

Message:

```text
FastAPI stays Python. compute_score becomes Rust native.
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

Public 1 must include tests for:

### 18.1 Analyzer

* detects `@rextio.native`
* rejects missing type annotations
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

Avoid in Public 1:

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

Avoid unnecessary heavy dependencies in Public 1.

Do not require FastAPI as a dependency of Rextio itself. FastAPI may be used only in examples.

Rust dependencies should be minimal:

* pyo3
* optionally serde for helper structures later

Do not add Cranelift, LLVM, Tokio, Axum, or framework dependencies in Public 1.

---

## 22. Public 1 Completion Criteria

Public 1 is complete only when all of these are true:

1. `pip install -e .` works.
2. `rextio init` creates config files.
3. `rextio check` detects native candidates and unsupported patterns.
4. `rextio check` rejects native-to-fallback calls.
5. `rextio check` warns about Python loops repeatedly calling native functions.
6. `rextio build --fallback=cpython` builds a hybrid artifact.
7. `rextio build --fallback=nuitka` either works or reports a clear experimental/installation error.
8. Generated Rust compiles through Cargo/maturin.
9. Generated native functions can be imported from Python.
10. Fallback works when native is disabled.
11. Functions rejected by boundary checks execute through fallback.
12. At least one example project demonstrates native speedup.
13. At least one example project demonstrates safe fallback.
14. At least one example project demonstrates boundary rejection/warning behavior.
15. E2E tests cover build/import/runtime behavior.
16. README explains Public 1 scope honestly.
17. Unsupported features are clearly documented.

---

## 23. README Messaging

The README must not overclaim.

Do not say:

```text
Rextio converts Python projects to Rust.
```

Prefer:

```text
Rextio compiles eligible typed Python functions to Rust native modules and packages the rest as safe Python fallback. Projects can opt out of automatic discovery and require `@rextio.native`.
```

Also mention:

```text
Public 1 includes conservative static boundary checks. It rejects native functions that call fallback-only code, warns when Python loops repeatedly call native functions, and uses generated fallback after repeated wrapper crossings exceed a simple runtime threshold.
```

Do not claim full Python compatibility.

Do not claim full NumPy support.

Do not claim framework migration.

Do not claim full runtime boundary-cost optimization.

Do not claim production-ready JIT.

---

## 24. Architecture Summary

Public 1 architecture:

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

## 27. Future Phases, Not Public 1

The architecture may leave extension points for these, but do not implement them yet:

* package adapter registry
* NumPy subset
* profiling and optimization intelligence
* full runtime boundary-cost model
* runtime-weighted native coverage
* native region fusion suggestions
* GitHub PR integration
* SaaS dashboard
* cloud build
* FastAPI-to-Axum plugin
* framework-aware profiling
* JIT metadata
* Cranelift JIT
* enterprise/on-prem platform

Keep Public 1 focused.

---

## 28. Final Reminder for Codex

This project should first prove one thing:

> A normal Python project can be built into a hybrid artifact where selected typed Python functions run as Rust native code and everything else still works through safe Python fallback.

Public 1 must also prove one safety property:

> Native functions never depend on fallback-only Python functions, and suspicious Python/Rust boundary patterns are reported clearly.

Every implementation decision in Public 1 should support those two demonstrations.
