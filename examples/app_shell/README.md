# App Shell Scoring Example

The application shell stays Python. `compute_score` becomes Rust native.

This example keeps integration code in Python fallback and marks only the typed
scoring hot path as native.

That is the intended Rextio model for application code: keep framework and I/O
logic in Python, and compile narrow typed hot paths when the analyzer can prove
they fit the direct Rust subset.

```text
rextio check examples/app_shell
rextio build examples/app_shell --fallback=cpython
```

The generated wrappers preserve the original import path for Python callers.
