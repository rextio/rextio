# App Shell Scoring Example

The application shell stays Python. `compute_score` becomes Rust native.

This example keeps integration code in Python fallback and marks only the typed
scoring hot path as native.

```text
rextio check path/to/app-shell-example
rextio build path/to/app-shell-example --fallback=cpython
```
