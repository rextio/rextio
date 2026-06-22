# Boundary Demo

This example shows where Rextio draws the line between native and fallback code.

The important behavior is not just whether Rust code can be generated. Rextio
also needs to reject native functions that would call fallback-only Python code
and warn when Python loops repeatedly cross into native wrappers.

It includes:

- accepted native-to-native calls
- a rejected native function calling `@rextio.exempt` fallback-only code
- a Python fallback loop repeatedly calling a native function

```text
rextio check examples/boundary_demo
```

Expected diagnostics include `RXT070` and `RXT073`.

Use this example when changing analyzer, boundary, or wrapper logic. It should
continue to make accepted, rejected, and warning cases easy to distinguish.
