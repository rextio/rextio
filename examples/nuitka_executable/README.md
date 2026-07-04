# Nuitka Executable Example

Builds the project into a Nuitka executable (experimental). The entrypoint,
name, backend, and mode are preconfigured in `rextio.toml` (`[executable]`),
so a plain build produces a single-file executable (onefile mode). Requires a Rust toolchain and Nuitka.

```text
rextio check examples/nuitka_executable
rextio build examples/nuitka_executable --fallback=cpython
./examples/nuitka_executable/dist/nuitka_demo 2000000
```

What to look for:

- `nuitka_executable.compute.triangle_mod` is accepted as a direct-Rust
  native candidate; the hybrid wheel still carries the native extension.
- The build writes a single `dist/nuitka_demo` file (onefile mode).
- A Nuitka executable cannot serve Numba-accelerated functions - such a
  build fails early with guidance rather than at the first call.

Compare performance:

```text
rextio bench nuitka_executable.compute.triangle_mod --project-root examples/nuitka_executable
```

benches the Rust-native path against the Python fallback. Timing the
executable itself (`time ./dist/nuitka_demo 2000000`) includes interpreter
startup; numbers depend on the machine.
