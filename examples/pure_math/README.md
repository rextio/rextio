# Pure Math Example

This example shows simple Rust AOT compilation for typed Python hot paths.

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

Native candidates:

- `pure_math.math_ops.sum_squares`
- `pure_math.math_ops.dot_simple`
- `pure_math.math_ops.count_positive`
