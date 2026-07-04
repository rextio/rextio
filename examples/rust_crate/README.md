# Rust-Importable Crate Example

Builds, in addition to the hybrid wheel, a Cargo library crate that Rust
projects can import as a path dependency. `[rust] importable = true` and the
crate name are preconfigured in `rextio.toml`. Requires Cargo.

```text
rextio check examples/rust_crate
rextio build examples/rust_crate --fallback=cpython
```

What to look for:

- `rust_crate.metrics.mean_abs_delta` and `rust_crate.metrics.scaled_sum`
  are accepted as direct-Rust native candidates.
- The build writes `dist/rust_crate_demo-rust-crate/` (crate source) and
  compiles it to a `.rlib` to prove it builds as pure Rust.
- Only directly lowered functions are exported; fallback-only functions,
  runtime shims, and boundary-calling functions stay Python-facing.

Use the crate from a Rust project:

```toml
[dependencies]
rust_crate_demo = { path = "../dist/rust_crate_demo-rust-crate" }
```

```rust
fn main() -> Result<(), rust_crate_demo::RextioError> {
    let value = rust_crate_demo::rust_crate__metrics__scaled_sum(vec![1, 2, 3], 10)?;
    assert_eq!(value, 60);
    Ok(())
}
```

Compare performance from the Python side:

```text
rextio bench rust_crate.metrics.scaled_sum --project-root examples/rust_crate
```

Rust callers skip the Python boundary entirely; numbers depend on the
machine.
