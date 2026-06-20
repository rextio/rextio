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
