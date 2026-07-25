# Rextio

Rextio **0.1.6** is an alpha-stage local build tool for Python projects,
published to PyPI on 2026-07-26 with plugin API **1.6**, tooling contract
**2.27.0**, and readiness policy **11**. It supersedes 0.1.5. It retains the
experimental host source-AOT/executable and bounded Full-C6 + C5.2 Alpha from
Release Train C, and adds bounded plugin comparison expressions, Device
Provider API 1 selection/preflight/build wiring, and fail-closed static
device-domain lowering authorization. Core alone does not claim CUDA framework
support, certified accelerator execution, broad Full C6, or general package
AOT.

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
- explicitly select and preflight one compatible Device Provider for a
  statically authorized accelerator-bearing plugin domain

Rextio is not a Python replacement and does not attempt full Python semantics
or whole-project Rust migration. Native compilation is an optimization; Python
fallback behavior remains the correctness baseline.

Project repository: https://github.com/rextio/rextio

Author: Steve Si-young Song <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev)
