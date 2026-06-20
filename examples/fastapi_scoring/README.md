# FastAPI Scoring Example

FastAPI stays Python. compute_score becomes Rust native.

This example keeps the web framework in Python fallback code and marks only the
typed scoring hot path as native.

```text
rextio check examples/fastapi_scoring
rextio build examples/fastapi_scoring --fallback=cpython
```

FastAPI is not a dependency of Rextio itself. Install FastAPI separately if you
want to run the web shell.
