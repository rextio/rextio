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

## Smoke Flow

```text
python -m pip install -e .
rextio init --project-root demo
rextio check demo
rextio build demo --fallback=cpython
rextio bench demo_app.compute --project-root demo
rextio clean demo
```

Generated artifacts live under `.rextio/` and user source files are not
rewritten during build.

## Boundary Safety

Native functions may call accepted native functions and supported builtins.
They may not call fallback-only functions, rejected native candidates, or
unresolved external package calls. Those cases produce deterministic diagnostics
such as `RXT070`, `RXT072`, and `RXT030`.

Fallback Python may call native functions. If it does so inside a Python loop,
Rextio emits `RXT073` with the suggestion to move the loop into a native batch
function.
