# Boundary Demo

This example shows boundary safety and warnings.

It includes:

- accepted native-to-native calls
- a rejected native function calling `@rextio.exempt` fallback-only code
- a Python fallback loop repeatedly calling a native function

```text
rextio check examples/boundary_demo
```

Expected diagnostics include `RXT070` and `RXT073`.
