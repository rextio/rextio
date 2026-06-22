# Pure Math Example

This example is the shortest path for seeing what Rextio optimizes.

The source is normal typed Python math code. `rextio check` should identify
three direct-Rust native candidates, and `rextio build` should generate Rust,
Python wrappers, and a hybrid package without changing the source files.

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

`rextio bench` builds the hybrid artifact, runs the Python fallback and native
wrapper for the selected function, and prints a measured speedup ratio. The
exact number depends on the local machine and Rust toolchain, so use it as a
smoke demonstration rather than a fixed benchmark claim.

Native candidates:

- `pure_math.math_ops.sum_squares`
- `pure_math.math_ops.dot_simple`
- `pure_math.math_ops.count_positive`

Expected artifacts:

- `.rextio/generated/rust/` contains the generated Rust/PyO3 code.
- `.rextio/generated/python/` contains wrappers and fallback modules.
- `.rextio/build/python/` contains the import-compatible hybrid package tree.
