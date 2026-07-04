# Nuitka + Numba Coexistence Example

Exercises all three engines in one build: a typed hot path becomes native
Rust, dynamic glue code is Nuitka-compiled on the fallback, and a
Numba-decorated NumPy kernel is automatically kept as plain Python source
(Numba JIT-compiles from bytecode, which a Nuitka-compiled module does not
expose). Requires a Rust toolchain, Nuitka, and `numba`/`numpy` in the
project environment.

```text
rextio check examples/nuitka_numba
rextio build examples/nuitka_numba --fallback=nuitka
```

What to look for:

- `nuitka_numba.hot_path.mix_series` is accepted as a direct-Rust
  native candidate.
- `nuitka_numba.jit_kernel.clipped_cumsum` is labeled
  `external_accelerator: numba` by `rextio check`, and the build output
  lists the module as kept plain (not Nuitka-compiled).
- `nuitka_numba.glue.summary` stays on the fallback and is Nuitka-compiled.
- In the built tree, `jit_kernel.py` remains a `.py` file while the other
  fallback modules gain compiled extension siblings.

Compare performance:

```text
rextio bench nuitka_numba.hot_path.mix_series --project-root examples/nuitka_numba
```

Numbers depend on the machine; treat them as smoke demonstrations. Note that
a Nuitka *executable* (`--executable-backend=nuitka`) cannot serve
Numba-accelerated functions and fails early with guidance - coexistence
applies to the wheel/fallback path shown here.
