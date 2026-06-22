# Rextio

Rextio 0.1.0 is an alpha-stage local build tool for Python projects.

It analyzes typed Python code, compiles eligible hot-path functions to Rust
native modules, and keeps unsupported or unsafe code on the Python fallback
path. The goal is to let Python projects adopt Rust acceleration selectively
without rewriting the whole project.

Rextio can:

- discover native candidates automatically or through `@rextio.native`
- keep selected functions on fallback with `@rextio.exempt`
- generate Rust/PyO3 code for accepted functions
- generate Python wrappers that preserve normal import paths
- fall back to Python when native code is unavailable or disabled
- build hybrid artifacts, zipapp executables, Nuitka executables, and optional
  Rust-importable crates

Rextio is not a Python replacement and does not attempt full Python semantics
or whole-project Rust migration. Native compilation is an optimization; Python
fallback behavior remains the correctness baseline.

Project repository: https://github.com/rextio/rextio
