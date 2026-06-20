# Fallback Demo

This example shows fallback safety.

```text
rextio build examples/fallback_demo --fallback=cpython
PYTHONPATH=examples/fallback_demo/.rextio/generated/python REXTIO_DISABLE_NATIVE=1 python -m fallback_demo.run_demo
```

When `REXTIO_DISABLE_NATIVE=1` is set, generated wrappers use the fallback
Python implementation.
