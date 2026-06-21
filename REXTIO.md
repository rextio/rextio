# Rextio Public 1 Notes

Rextio Public 1 proves a focused hybrid build workflow:

```text
Python source
  -> Rextio analyzer
  -> compatible subset checker
  -> boundary safety checker
  -> generated native artifact and Python fallback
```

Native compilation is an optimization. Fallback Python behavior must remain
available, including when `REXTIO_DISABLE_NATIVE=1` is set.

By default, Rextio discovers eligible module-level typed functions
automatically. Projects can set `[policy] native_marker = "decorator"` when
they want only explicitly marked `@rextio.native` functions to become native
candidates.

Use `@rextio.exempt` on functions that must stay on Python fallback. Exemptions
override automatic discovery and explicit native markers.

## Smoke Flow

```text
python -m pip install -e .
rextio init --project-root demo
rextio check demo
rextio generate demo --fallback=cpython
rextio build demo --fallback=cpython
rextio bench demo_app.compute --project-root demo
rextio clean demo
```

Generated artifacts live under `.rextio/` and user source files are not
rewritten during build.

Use `rextio generate` when you want only generated source files. It writes Rust
and Python source under `.rextio/generated/` and skips Rust, Nuitka, wheel, and
build artifact compilation steps.

## Release Verification

Run the regular test suite first:

```text
PYTHONPATH=src pytest
```

The suite includes an editable-install CLI smoke test. Cargo-specific tests are
skipped when Cargo is unavailable, and the Nuitka fallback E2E is skipped when
Nuitka is unavailable. To explicitly verify real local toolchains, run:

```text
PYTHONPATH=src pytest tests/e2e/test_pure_math_real_toolchain.py
PYTHONPATH=src pytest tests/e2e/test_nuitka_real_toolchain.py
cargo test --manifest-path crates/rextio_runtime/Cargo.toml
```

The editable-install smoke also installs the generated artifact wheel into a
fresh virtual environment and imports the generated package with
`REXTIO_DISABLE_NATIVE=1`, so release checks cover the packaged fallback path as
well as the build directory path.

## Boundary Safety

Native functions may call accepted native functions and supported builtins.
They may not call fallback-only functions, rejected native candidates, or
unresolved external package calls. Those cases produce deterministic diagnostics
such as `RXT070`, `RXT072`, and `RXT030`.

Fallback Python may call native functions. If it does so inside a Python loop,
Rextio emits `RXT073` with the suggestion to move the loop into a native batch
function.
