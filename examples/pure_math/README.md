# Pure Math Example

This example shows simple Rust AOT compilation for typed Python hot paths.

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
