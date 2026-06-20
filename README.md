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
rextio check examples/boundary_demo
```
