# rextio_runtime

A small helper crate (`checked_index`, `len_to_i64`, `RextioRuntimeError`)
intended for reuse by generated Rextio Rust code.

> **Status (0.1.0 alpha): reserved, not yet wired.**
> Generated code currently inlines its own bounds-checked indexing, so this crate
> is **not** referenced by any generated `Cargo.toml` and is not on the build path.
> It is kept as the intended home for shared runtime helpers. Before the first
> non-alpha release this should either be wired into codegen (so generated crates
> depend on it as a path dependency) or removed in favour of the inlined helpers.
>
> Tracked in the project review notes as item **P2-3**.
