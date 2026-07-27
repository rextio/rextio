# Rextio

Rextio **0.1.8** is an alpha-stage local build tool for Python projects,
published to PyPI on 2026-07-27 with plugin API **1.7**, tooling contract
**3.0.0**. It supersedes 0.1.7 (2026-07-27; plugin API **1.7**, tooling
contract **2.28.0**), which superseded 0.1.6 (2026-07-26; plugin API **1.6**,
tooling contract **2.27.0**, readiness policy **11**). It retains the experimental host
source-AOT/executable and bounded strict artifact-contract Alpha from Release Train C,
bounded plugin comparison expressions, Device Provider API 1
selection/preflight/build wiring, and fail-closed static device-domain
lowering authorization from 0.1.6, and adds optional plugin function-scope
RAII guards (API 1.7), and replaces public artifact lifecycle identities with
semantic `artifact-*` names. Core alone does not claim CUDA framework support,
certified accelerator execution, general artifact authorization, or general
package AOT.

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
