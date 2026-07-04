# Scalar-Helper Embedding Example

Contrasts the two ways a marked native function can call a tiny unmarked
scalar helper: per-call boundary dispatch (the default) versus compiling
the helper into the native artifact (experimental embedding). Requires a
Rust toolchain. The project uses `native_marker = "decorator"`, so the
unmarked helper stays on the Python fallback unless embedded.

Default build - the helper call is a scalar boundary call (`RXT075`):

```text
rextio check examples/embedding_helpers
rextio build examples/embedding_helpers --fallback=cpython
```

Embedding build - the helper compiles into the native artifact:

```text
rextio check examples/embedding_helpers --embed-helpers
rextio build examples/embedding_helpers --fallback=cpython --embed-helpers
```

What to look for:

- Without `--embed-helpers`, the `margin(...)` calls in `total_margin`
  are accepted as scalar boundary calls - `rextio check --format json`
  records the `RXT075` notes; each runtime call crosses into the
  interpreter and counts toward the boundary-fallback threshold, and
  monkeypatching `margin` is honored.
- With `--embed-helpers`, `rextio check` lists one embedding candidate
  and the `RXT075` notes disappear: `margin` is compiled ahead of time as an
  internal native function (no interpreter round-trip; runtime replacement
  of the helper is NOT visible to native callers).

Compare performance between the two builds:

```text
rextio bench embedding_helpers.pricing.total_margin --project-root examples/embedding_helpers
REXTIO_EMBED_HELPERS=true rextio bench embedding_helpers.pricing.total_margin --project-root examples/embedding_helpers
```

Numbers depend on the machine; the embedded build removes three
interpreter round-trips per call.
