# Fallback Demo

This example shows that native compilation is optional at runtime.

Rextio-generated wrappers try native first, but the package must still work
when native is disabled or missing. This is the behavior controlled by
`REXTIO_DISABLE_NATIVE=1`.

```text
rextio build examples/fallback_demo --fallback=cpython
PYTHONPATH=examples/fallback_demo/.rextio/build/python REXTIO_DISABLE_NATIVE=1 python -m fallback_demo.run_demo
```

When `REXTIO_DISABLE_NATIVE=1` is set, generated wrappers use the fallback
Python implementation.

Use this example when checking that a packaging change did not make Rust native
availability a correctness requirement.
