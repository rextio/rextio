# Rextio

<p align="center">
  <img src="https://raw.githubusercontent.com/rextio/rextio/main/assets/readme/rextio-icon.png" width="112" alt="Rextio icon">
</p>

<p align="center">
  <strong>Compile eligible typed Python functions to Rust/PyO3 ahead of time.<br>Keep everything else on a safe Python fallback.</strong>
</p>

<p align="center">
  <a href="https://github.com/rextio/rextio/blob/main/README.md">English</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ko.md">한국어</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hans.md">简体中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hant.md">繁體中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/rextio/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/rextio"></a>
  <a href="https://pypi.org/project/rextio/"><img alt="Supported Python versions" src="https://img.shields.io/pypi/pyversions/rextio"></a>
  <a href="https://github.com/rextio/rextio/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Rextio is an **Alpha local build tool for Python developers** who want selected typed hot paths to run as native Rust without rewriting an application. Its conservative analyzer accepts only code it can lower with the documented semantics. Unsupported or ambiguous code stays on generated Python fallback wrappers; when native execution is disabled—or unavailable in the default `auto` mode—the same imports keep working through those wrappers.

```bash
python -m pip install rextio
rextio check .
```

That is the shortest useful first step: see which functions are accepted before building anything.

Core **0.1.8** was published on 2026-07-27 with plugin API **1.7** and tooling contract **3.0.0**. See the [changelog](CHANGELOG.md) for the release history.

> **Tooling migration:** contract 3.0 replaces milestone-derived artifact identities with semantic `artifact-*` names. Exact 0.1.7 identities remain legacy read/verification inputs only; 2.x-only consumers must degrade on major 3.

## Proof: measured CPU workloads

Three-run medians on **Mac16,11 / Apple M4 Pro**, **2026-07-26**, CPython **3.11.9**:

| Workload | Median source/native speedup |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas `Series.map` | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

These are **workload-specific observations**, not library-wide promises. Values near 1× mean parity, and some retained diagnostics are slower than Python. CUDA was not measured. The auditable [rextio-benchmark](https://github.com/rextio/rextio-benchmark) repository contains the exact revisions, source/fallback/native lanes, raw evidence, stability policy, diagnostics, and slower/parity cases.

## How it works

```text
typed Python
  → resolve types and check the supported subset
  → reject unsafe native/fallback call graphs
  → lower accepted functions to Rust + PyO3
  → generate import-compatible Python wrappers
  → build native artifacts while preserving fallback
```

The correctness baseline is Python. Rextio is not a Python replacement, a general Python-to-Rust converter, a JIT, or a whole-project migration tool.

## First build

Start with ordinary typed Python—decorators are optional in the default automatic mode:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # stays on Python fallback
```

```bash
rextio check .
rextio build . --fallback=cpython
```

Rextio can lower `sum_squares` and keep `format_result` on fallback. Callers keep normal Python imports:

```python
from myapp.math_ops import format_result, sum_squares

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

Force the built package onto fallback at any time:

```bash
REXTIO_NATIVE_MODE=fallback python -m myapp
```

Useful commands are `rextio init`, `rextio capabilities`, `rextio check`, `rextio generate`, `rextio build`, `rextio bench`, and `rextio clean`.

## Requirements

| Component | Supported boundary |
| --- | --- |
| CPython | `>=3.11`; validated on 3.11–3.14. Generated extensions pin PyO3 0.29, which supports through CPython 3.14. Newer interpreters are unvalidated, and wheels are tagged for the build interpreter's minor version. |
| Rust | MSRV 1.83; recent stable is tested. Generated crates use Rust 2021. Install with [rustup](https://rustup.rs). |
| Nuitka | Optional, `>=2.0`; required only for the selected Nuitka fallback, executable, or dispatcher path. Those paths are Experimental. |
| Numba | Optional and Experimental; interpreter-specific floors are 0.57 (3.11), 0.59 (3.12), 0.61 (3.13), and 0.63 (3.14). It remains your project's dependency. |

Tool locations and versions can be pinned through `[toolchain]`, environment variables, or CLI options; see [REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins).

## Selection and fallback safety

Automatic discovery is the default:

```toml
[policy]
native_marker = "auto"
```

Use `native_marker = "decorator"` to require `@rextio.native`, or use `@rextio.exempt` to keep a function on Python. Rust is the only implemented native target.

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

Safety rules that affect application design:

- Direct native functions may call only accepted native functions and supported builtins/standard-library operations.
- A call to fallback-only code rejects the native caller unless an explicitly marked caller qualifies for the immutable-scalar boundary path. Containers never cross that boundary, and boundary calls inside loops or comprehensions stay on fallback.
- Python loops that call native functions produce the static `RXT073` crossing warning. Eligible direct-native functions count wrapper and scalar-boundary entries toward the per-function runtime fallback threshold; plugin-routed functions are exempt.
- In `auto` mode, an unavailable native import or threshold demotion uses Python fallback, and analyzer-rejected functions remain on fallback. `fallback` mode explicitly disables native execution. `native` mode requires promoted native code and raises when its native import is unavailable. `REXTIO_DEBUG_NATIVE=1` turns native-load warnings into tracebacks for diagnosis.
- `native-shim`/`RXT080` calls the Python fallback through PyO3 to preserve dynamic Python semantics. It is a compatibility route, **not a Rust speedup**.
- Mutable collection aliasing stays on Python when Rust ownership would change behavior. A native candidate is never emitted merely because a translation seems likely.

Runtime controls:

```text
REXTIO_NATIVE_MODE=auto|fallback|native
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_DEBUG_NATIVE=1
```

## Supported direct-Rust shape

The deliberately narrow direct path covers supported combinations of:

- scalar `int`, `float`, `bool`, `str`, `bytes`, and `None`;
- lists (including nested lists), fixed tuples, fixed dictionaries with scalar keys, limited `set[int|bool|str]`, and `Optional[T]` / `T | None`;
- typed locals, arithmetic, comparisons, `if`, `while`, supported `for`/`range`/`enumerate`/`zip` forms, comprehensions, and accepted native helpers;
- limited builtins, `math`, string/bytes/list methods, logging/printing, `datetime`, `time`, `hashlib.sha256`, and `base64.b64encode`.

Important exclusions remain visible: `set[float]` and set iteration cannot preserve CPython's NaN identity/hash ordering; `statistics.mean/fmean`, `json.dumps/loads`, and `base64.b64decode` have no direct-native route; file/network/database/ORM work and dynamic object behavior stay on fallback or an explicitly marked compatibility shim. See [unsupported features](docs/unsupported-features.md) and [feature stability](docs/stability.md) for the complete, versioned boundary.

## Build outputs

| Request | Result and boundary |
| --- | --- |
| Default build | Import-compatible package tree and optional wheel with native code plus Python fallback. |
| `--entrypoint=…` | Zipapp; target still needs compatible Python, and native extensions are not imported from inside the zipapp. |
| `--executable-backend=nuitka` | Experimental standalone/onefile executable; requires Nuitka. Arbitrary cross-platform third-party packaging is not claimed. |
| `--executable-backend=rust` | Native Rust entrypoint. A closed graph can be standalone; `python-subprocess` delegates only bounded immutable-scalar calls and requires CPython, while `nuitka-sidecar` requires Nuitka. Runtime shims and container crossings are rejected. Prefer exit codes `0..255` for portable process status. |
| `--rust-importable` | Experimental Cargo path-dependency crate containing only direct-Rust functions. Fallback, shim, and scalar-boundary functions remain Python-facing. |

`rextio build` and `generate` perform clean re-analysis and regeneration; the 0.1.x line has no incremental build cache. The subprocess hybrid runtime copies source under `<binary>.runtime/`, so delegated code sees that copied `__file__`; code that locates data relative to the original file needs another path.

## Plugins, devices, and external source

Plugins are separate Python distributions enabled explicitly in project configuration. Packages without an active plugin stay conservative by default; `try-native` is an Experimental planning policy, not a promise of general dependency conversion.

Device Provider API 1 selection is also Experimental and explicit. Configuration alone does not make CPU-only Torch or TensorFlow routes CUDA-capable. Mixed or conflicting device domains, missing providers, unsupported GPU ordinals, and wrong capabilities fail closed. Provider preflight reports `support_claim: false`; Core does not claim certified CUDA execution.

The external pure-Python source inventory is a non-building preview for exactly one pinned, verified depth-1 `py3-none-any` distribution. It does not import the package, connect lexical candidates to project calls, lower, copy, redistribute, or authorize a build. Missing/invalid SourceLock evidence blocks; a verified lock alone still grants no build or distribution authority.

The separate `strict-evidence` **Alpha/Experimental** profile is frozen to CPython 3.11 host-extension builds on macOS arm64 or Linux x86_64, one SourceLock-authorized dependency, scalar leaf calls, owner-pinned offline inputs, two isolated builds, and an external Ed25519 signature. It excludes plugins, executables, Rust crates, embedding, native top-level initialization, Windows, broad package lowering, and general redistribution. Its sandbox/support locks protect evidence integrity inside an owner-controlled process; they are not secure boot, defense against a hostile same-UID process or compromised OS, general hermeticity, registry authentication, or cross-platform certification.

> **Legal boundary:** translating or redistributing dependency source can create license and derivative-work obligations, especially for GNU/copyleft terms. Rextio's inventory and SourceLock checks are not legal advice or legal approval.

Read [host source-AOT and native executables](docs/source-aot-and-executables.md), [Device Provider API 1](docs/specs/device-provider.md), and [the tooling contract](docs/specs/tooling-contract.md) before depending on these advanced surfaces.

## Numba and Nuitka

Recognized `@numba.*` decorators are an explicit opt-in to **Numba's** semantics on fallback, not Rextio's CPython-equivalent native contract. Do not combine them with `@rextio.native`. Wheel/zipapp and source-hybrid paths can work when Numba is installed; Nuitka executables and the Nuitka hybrid dispatcher reject accelerated functions early because compiled functions expose no bytecode and the accelerator is not bundled. Small functions may lose to boundary overhead under any accelerator.

## Examples and project information

```bash
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

Browse [`examples/`](examples/) for direct math, fallback and boundary behavior, wheels, zipapps, Nuitka, Numba, Rust executables/crates, and embedded helpers. Embedding is Experimental, off by default, AOT-only, scalar-only, and changes monkeypatch visibility for native callers; it is not a runtime JIT.

- [Security model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Versioning](docs/versioning.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) — MIT

Author: Steve Si-young Song · [@RextioDev](https://x.com/RextioDev)
