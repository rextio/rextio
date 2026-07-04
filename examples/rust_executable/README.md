# Native Rust Binary Example

Compiles the project into a standalone native binary whose `main` runs in
Rust - no Python interpreter is needed on the target machine, because the
whole call graph is direct-native. The entrypoint, name, and backend are
preconfigured in `rextio.toml` (`[executable]`). Requires Cargo.

```text
rextio check examples/rust_executable
rextio build examples/rust_executable --fallback=cpython
./examples/rust_executable/dist/primes
time ./examples/rust_executable/dist/primes extra extra
```

What to look for:

- `rust_executable.main.count_primes` and `rust_executable.main.main` are
  accepted as direct-Rust native candidates; the entrypoint must be an
  accepted `def main(argv: list[str]) -> int`.
- The build writes `dist/primes` with NO `dist/primes.runtime/` directory:
  nothing is delegated, so the binary is standalone. If `main` called a
  fallback-only project function, Rextio would ship that runtime directory
  and delegate the call to an external CPython subprocess (hybrid mode).
- `argv` mirrors `sys.argv`; the returned `int` is the process exit code.
  Each extra argument adds 50000 to the prime-counting limit (string
  parsing is outside the direct-native subset).

Compare performance: `time` the binary against the same algorithm on plain
CPython, or bench the kernel through the wheel path:

```text
rextio bench rust_executable.main.count_primes --project-root examples/rust_executable
```

Numbers depend on the machine; treat them as smoke demonstrations.
