# Rextio

Rextio **0.1.5** is an alpha-stage local build tool for Python projects,
published to PyPI on 2026-07-23 with plugin API **1.4**, tooling contract
**2.24.0**, and readiness policy **11**. It supersedes 0.1.4. Release Train C
ships experimental host source-AOT/executable planning and a bounded Full-C6 +
C5.2 Alpha; it does not claim broad Full C6, general package AOT, or CUDA
support.

```text
pip install rextio
```

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
- build hybrid artifacts, zipapp executables, Nuitka executables, standalone
  native Rust binaries, and optional Rust-importable crates
- select and version-pin the exact cargo, maturin, Nuitka, and CPython a
  build uses (`[toolchain]` in `rextio.toml`)

Rextio is not a Python replacement and does not attempt full Python semantics
or whole-project Rust migration. Native compilation is an optimization; Python
fallback behavior remains the correctness baseline.

Project repository: https://github.com/rextio/rextio

Author: Steve Si-young Song <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev)
