# Rextio

Rextio compiles explicitly marked, typed Python functions to Rust native modules
and packages the rest as safe Python fallback.

Public 1 is intentionally narrow. It is a local CLI and build-tool MVP for
projects that opt in with `@rextio.native`. It does not claim full Python
compatibility, full NumPy support, framework migration, JIT behavior, or
runtime boundary-cost optimization.

Public 1 includes conservative static boundary checks. It rejects native
functions that call fallback-only code and warns when Python loops repeatedly
call native functions.

## Current commands

```text
rextio init
rextio check
rextio build
rextio bench
rextio clean
```

The initial implementation focuses on project initialization, native marker
detection, subset diagnostics, static boundary diagnostics, runtime disable
flags, and deterministic check reports.

Typical local flow:

```text
python -m pip install -e .
rextio init --project-root path/to/project
rextio check path/to/project
rextio build path/to/project --fallback=cpython
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## Public 1 Scope

Public 1 supports a small typed Python subset for explicitly marked
module-level functions. Unsupported syntax, dynamic features, unsafe
native-to-fallback calls, and unresolved external calls are rejected from native
compilation and kept on Python fallback where possible.

See [Unsupported Features in Public 1](docs/unsupported-features.md) for the
supported subset, boundary limits, diagnostics, and non-goals.

## Build Prerequisites

Native builds require Rust and Cargo. Rextio can also use `maturin` when
configured with `[rust] build_tool = "maturin"`; if maturin is unavailable,
Rextio falls back to Cargo when possible.

Nuitka fallback packaging is experimental. If `--fallback=nuitka` is requested
without Nuitka installed, Rextio reports a clear `RXT060` error and suggests
`--fallback=cpython`. When Nuitka is installed, Rextio invokes it on generated
Python fallback modules while still keeping the CPython fallback files in the
build artifact.

`rextio build` uses `[build] fallback_backend` from `rextio.toml` when
`--fallback` is omitted. Passing `--fallback=cpython` or `--fallback=nuitka`
overrides the project setting for that run.

## Generated Artifacts

Rextio writes generated files under `.rextio/` and does not modify source files
in place.

```text
.rextio/
  build/
    python/
      rextio/
        runtime/
  generated/
    rust/
    python/
  reports/
    check.json
    build.json
    bench.json
dist/
  <project>-0.1.0-<tag>.whl
```

`rextio check` writes `.rextio/reports/check.json`. `rextio build` writes both
check and build reports. `rextio bench` writes `.rextio/reports/bench.json`
with a structured fallback/native timing comparison.

When `rextio build` succeeds, it also writes a generated hybrid artifact wheel
under `dist/`. Pure fallback wheels use `py3-none-any`; wheels that include the
generated native extension use the local CPython/platform tag. The test suite
installs this wheel into a fresh environment and verifies that packaged fallback
imports still work with `REXTIO_DISABLE_NATIVE=1`.

## Policy Configuration

Public 1 validates `rextio.toml` conservatively and rejects unknown sections,
unknown keys, unsupported backends, and policy values outside the Public 1
scope.

Boundary warnings are enabled by default. Projects that want strict safety
errors without Python-loop boundary warnings can set:

```toml
[policy]
boundary_warnings = false
```

## Fallback Safety

Generated wrappers use native functions when available and safe. They fall back
to Python when native import fails or when native execution is disabled:

```text
REXTIO_DISABLE_NATIVE=1
```

`REXTIO_NATIVE_MODE` can be set when a project needs explicit runtime behavior:

```text
REXTIO_NATIVE_MODE=auto      # default: use native when available, otherwise fallback
REXTIO_NATIVE_MODE=fallback  # force Python fallback
REXTIO_NATIVE_MODE=native    # require generated native functions to be available
```

Use `.rextioignore` to keep generated or irrelevant Python files out of Rextio
analysis.

## Boundary Diagnostics

Public 1 boundary checks are static and conservative:

- `RXT070`: a native function calls fallback-only Python code.
- `RXT072`: a native function depends on a rejected native function.
- `RXT073`: fallback Python calls a native function inside a loop.

`RXT070` and `RXT072` reject the native candidate. `RXT073` is a warning; the
function remains eligible because some native calls are still heavy enough to be
worth crossing the boundary.

## Examples

Public 1 includes focused local examples:

- `examples/pure_math`: simple typed math functions compiled as native hot paths.
- `examples/fastapi_scoring`: FastAPI stays Python. `compute_score` becomes Rust native.
- `examples/fallback_demo`: generated wrappers use Python fallback when native is missing or `REXTIO_DISABLE_NATIVE=1`.
- `examples/boundary_demo`: conservative boundary rejection and Python-loop boundary warnings.

Try:

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
