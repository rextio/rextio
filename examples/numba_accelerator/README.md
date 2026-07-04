# Numba Accelerator Example

Shows Rextio and Numba working side by side in one project: a typed scalar
hot path becomes native Rust, while a NumPy array kernel stays on the Python
fallback and is JIT-compiled by Numba. Requires a Rust toolchain plus
`numba` and `numpy` installed in the project environment (Numba is a
dependency of YOUR project, not of Rextio).

```text
rextio check examples/numba_accelerator
rextio build examples/numba_accelerator --fallback=cpython
```

What to look for:

- `numba_accelerator.scalar_ops.polynomial_sum` is accepted as a direct-Rust
  native candidate.
- `numba_accelerator.array_ops.rolling_mean` carries the `@numba.njit`
  decorator, so `rextio check` labels it `external_accelerator: numba` and it
  is excluded from native discovery. It runs under Numba's semantics
  (nopython-mode integer arithmetic wraps on overflow) - that is the user's
  explicit opt-in, outside Rextio's native contract.

Compare performance:

```text
rextio bench numba_accelerator.scalar_ops.polynomial_sum --project-root examples/numba_accelerator
```

benchmarks the Rust-native path against the Python fallback, and the demo
script times both worlds in one run (from the example directory, with the
built artifact on `PYTHONPATH`):

```text
PYTHONPATH=examples/numba_accelerator/.rextio/build/python \
  python -m numba_accelerator.run_demo
```

Numbers depend on the machine; treat both as smoke demonstrations. As a rule
of thumb, prefer `@rextio.native` for typed scalar code and Numba for
NumPy/array kernels.
