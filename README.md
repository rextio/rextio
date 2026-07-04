# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**Compiles eligible typed Python functions to Rust and keeps everything
else on the Python fallback.**

Rextio 0.1.0 is an alpha-stage local build tool for Python projects. It finds
typed Python functions that can be safely lowered to Rust, compiles them
ahead of time with PyO3, and keeps everything else running through generated
Python fallback code - same imports, same behavior.

```text
typed Python project
  -> analyze supported native candidates
  -> reject unsafe or unsupported functions
  -> generate Rust + PyO3 for accepted functions
  -> generate Python fallback wrappers for the rest
  -> build import-compatible artifacts
```

The contract is strict: a function is either compiled to native code with
CPython-equivalent semantics, or rejected with a diagnostic and left on the
Python fallback. When Rextio is unsure, it does not guess - it falls back.

Rextio is not a Python replacement and not a whole-project Rust migration tool.
Native compilation is an optimization. Python fallback behavior remains the
correctness baseline.

## Quick Start

Start with normal Python:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # not in the direct Rust subset
```

Build it (installed users; from a source checkout use
`python -m pip install -e .` instead):

```text
python -m pip install rextio
rextio check .
rextio build . --fallback=cpython
```

Rextio can compile `sum_squares` to Rust and keep `format_result` on Python
fallback. Import paths stay Python-facing:

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

The main commands:

| Command | What it does |
| --- | --- |
| `rextio init` | Creates `rextio.toml`, `REXTIO.md`, and `.rextioignore`. |
| `rextio check` | Analyzes native candidates and prints diagnostics. |
| `rextio generate` | Writes generated Rust and Python source without compiling. |
| `rextio build` | Generates, compiles, packages, and writes build reports. |
| `rextio bench` | Compares Python fallback and Rust native timing for one function. |
| `rextio clean` | Removes `.rextio/build`, `.rextio/generated`, and `.rextio/reports`. |

Common build variants:

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --embed-helpers
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

A typical end-to-end flow:

```text
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.math_ops.sum_squares --project-root path/to/project
rextio clean path/to/project
```

Use `rextio generate` when you want generated source only. It does not run
Cargo, maturin, Nuitka, wheel building, or executable packaging.

Use `rextio build` when you want the generated source plus compiled/packageable
artifacts.

## Requirements

| Component | Version | Notes |
| --- | --- | --- |
| CPython | >= 3.11 (validated on 3.11-3.14) | The analyzer uses the build interpreter's `ast`; generated extensions pin PyO3 0.29, which supports up to CPython 3.14. Newer interpreters may work but are unvalidated. Wheels are tagged for the build interpreter's minor version. |
| Rust toolchain | MSRV 1.83 (tested on recent stable) | Generated crates use edition 2021 and PyO3 0.29. Install via [rustup](https://rustup.rs). |
| Nuitka (optional) | >= 2.0 | Only for `--fallback=nuitka`, `--executable-backend=nuitka`, or `--hybrid-runtime=nuitka`. The first two are rejected up front by the build preflight; the hybrid runtime is checked when delegated fallback calls actually require the Nuitka dispatcher. |
| Numba (optional, experimental) | matches your interpreter: >= 0.57 (3.11), >= 0.59 (3.12), >= 0.61 (3.13), >= 0.63 (3.14) | Rextio only recognizes Numba decorators — the package itself is a runtime dependency of YOUR project, not of Rextio. Floors follow [Numba's version support table](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information). |

Tool locations and version pins are configurable: `[toolchain]` in
`rextio.toml` (or `REXTIO_*` variables / CLI flags) selects the cargo,
maturin, Nuitka, and CPython a build uses and can pin their versions.
See [REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins).

## Build Targets

Rextio can produce several artifacts from the same Python project:

| Output | Purpose |
| --- | --- |
| `.rextio/generated/rust/` | Generated Rust/PyO3 source for accepted native functions. |
| `.rextio/generated/python/` | Generated Python wrappers and fallback modules. |
| `.rextio/build/python/` | Import-compatible hybrid package tree. |
| `dist/*.whl` | Wheel containing fallback code and, when built, the native extension. |
| `dist/<name>.pyz` | Optional zipapp executable for a configured Python entrypoint. |
| `dist/<name>.dist/` or `dist/<name>` | Optional Nuitka standalone or onefile executable. |
| `dist/<name>` | Optional standalone native Rust binary (`--executable-backend=rust`), no Python runtime. |
| `dist/<crate>-rust-crate/` | Optional Rust library crate for Rust projects to import. |

The generated Python wrappers try native code first and fall back to Python when
native is disabled, unavailable, rejected by analysis, or past the configured
boundary threshold.

```text
REXTIO_NATIVE_MODE=fallback
```

Set `REXTIO_DEBUG_NATIVE=1` to raise the full traceback (instead of warning and
falling back) when a built native module fails to load — useful when debugging an
ABI mismatch or a wrapper/codegen name mismatch.

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

This writes `dist/myapp.pyz`. The target machine still needs a compatible
Python interpreter. Native extensions are not imported from inside the zipapp,
so wrappers preserve fallback behavior when `_rextio_native` is unavailable.

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka executable packaging is experimental and requires Nuitka to be installed.

Native Rust binary:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust
```

This compiles a native binary (`dist/<name>`) whose `main` runs in Rust. The
entrypoint must be an accepted direct-native `def main(argv: list[str]) -> int`:
`argv` mirrors `sys.argv` (the program path at index 0), the returned `int` is the
process exit code, and a raised error is printed CPython-style (`OverflowError:
...`) to stderr with a non-zero exit. Requires Cargo.

When the entrypoint calls a project function that stays on the Python fallback
(code outside the Rust subset), Rextio delegates that call to an external CPython
subprocess: the build ships a `dist/<name>.runtime/` directory (dispatcher +
project source) that the binary drives over stdio, so hard-to-compile logic can
be left as Python. Such a hybrid binary needs a Python interpreter at runtime; a
binary whose call graph is fully direct-native is standalone with no Python
dependency. Delegated-call arguments and results must both be immutable scalars
(`int`/`float`/`bool`/`str`/`None`); a `list`/`dict`/`set` is not delegated in
either direction (it crosses the wire by value, severing the aliasing CPython
preserves, so a mutated argument or a mutated aliased return would diverge
silently), and a non-finite float (`NaN`/`Infinity`) is rejected rather than
silently dropped. A delegated function's own stdout/stderr appears on the binary's stderr
(the binary's stdout carries the wire protocol). A function on the RXT080 runtime
shim is not delegated: an entry that depends on one is rejected, not built.

`--executable-python` pins the interpreter the binary launches (a name on `PATH`,
an absolute path, or a path relative to `<binary>.runtime` to bundle one);
`REXTIO_RUNTIME_PYTHON` overrides it at run time on the target machine.
`--hybrid-runtime=nuitka` instead compiles the delegated Python into a
self-contained dispatcher executable shipped in the runtime directory, so the
hybrid binary needs no separate Python install (requires Nuitka at build time).

When direct Rust functions are useful from a Rust application, build an
additional Cargo library crate:

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

Use the generated crate from Rust:

```toml
[dependencies]
my_native = { path = "../dist/my_native-rust-crate" }
```

```rust
fn main() -> Result<(), my_native::RextioError> {
    let value = my_native::myapp__math_ops__sum_squares(vec![1, 2, 3])?;
    assert_eq!(value, 14);
    Ok(())
}
```

Only functions directly lowered to typed Rust are exported through this crate.
Fallback-only functions, runtime semantics shims, and functions that make
scalar boundary calls (both need the interpreter) remain Python-facing paths.

## Configuration

Build and analysis settings resolve in this order:

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

Common settings:

| `rextio.toml` key | CLI parameter | Environment variable |
| --- | --- | --- |
| `[build] native_backend` | `--native-backend` / `--target-language` | `REXTIO_TARGET_LANGUAGE` / `REXTIO_NATIVE_BACKEND` |
| `[build] fallback_backend` | `--fallback` | `REXTIO_FALLBACK_BACKEND` |
| `[build] fallback_threshold` | `--fallback-threshold` | `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` |
| `[build] build_timeout_seconds` | `--build-timeout` | `REXTIO_BUILD_TIMEOUT` |
| `[rust] binding` | `--rust-binding` | `REXTIO_RUST_BINDING` |
| `[rust] build_tool` | `--rust-build-tool` | `REXTIO_RUST_BUILD_TOOL` |
| `[rust] importable` | `--rust-importable` / `--no-rust-importable` | `REXTIO_RUST_IMPORTABLE` |
| `[rust] crate_name` | `--rust-crate-name` | `REXTIO_RUST_CRATE_NAME` |
| `[fallback] nuitka` | `--nuitka-fallback` | `REXTIO_NUITKA_FALLBACK` |
| `[target] version` | `--target-version` | `REXTIO_TARGET_VERSION` |
| `[target.build_options]` | `--target-build-option KEY=VALUE` | `REXTIO_TARGET_BUILD_OPTIONS` |
| `[plugins] enabled` | `--enable-plugin` | `REXTIO_PLUGINS_ENABLED` |
| `[imports] default_external_policy` | `--default-external-policy` | `REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY` |
| `[imports.packages]` | `--package-import-policy PACKAGE=POLICY` | `REXTIO_IMPORTS_PACKAGES` |
| `[embedding] enabled` | `--embed-helpers` / `--no-embed-helpers` | `REXTIO_EMBED_HELPERS` |
| `[executable] entrypoint` | `--entrypoint` | `REXTIO_EXECUTABLE_ENTRYPOINT` |
| `[executable] name` | `--executable-name` | `REXTIO_EXECUTABLE_NAME` |
| `[executable] backend` | `--executable-backend` | `REXTIO_EXECUTABLE_BACKEND` |
| `[executable] nuitka_mode` | `--nuitka-mode` | `REXTIO_NUITKA_MODE` |
| `[executable] python` | `--executable-python` | `REXTIO_EXECUTABLE_PYTHON` |
| `[executable] hybrid_runtime` | `--hybrid-runtime` | `REXTIO_HYBRID_RUNTIME` |
| `[toolchain] cargo` | `--cargo` | `REXTIO_CARGO` |
| `[toolchain] maturin` | `--maturin` | `REXTIO_MATURIN` |
| `[toolchain] nuitka` | `--nuitka` | `REXTIO_NUITKA` |
| `[toolchain] python` | `--python` | `REXTIO_PYTHON` |
| `[toolchain] rust_toolchain` | `--rust-toolchain` | `REXTIO_RUST_TOOLCHAIN` |
| `[toolchain] *_version` pins | `--cargo-version` etc. | `REXTIO_CARGO_VERSION` etc. |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

Rust is the only implemented native target in 0.1.0 alpha.

Rextio plugins are ordinary Python packages installed with tools such as `pip`
or `uv`. A plugin package exposes metadata through the `rextio.plugins` entry
point group, including the Python package names it covers. A project enables
specific plugin ids with `[plugins] enabled` or `--enable-plugin`.

External Python packages without an active Rextio plugin are conservative by
default: Rextio does not silently translate third-party package source into Rust.
Calls to those packages keep the surrounding native candidate on fallback unless
you add a plugin or explicitly opt into experimental dependency analysis for a
known pure-Python package:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

The supported package policies are `fallback`, `analyze`, `try-native`, and
`plugin`. Concrete third-party plugin transformations and general dependency
lowering are not bundled in 0.1.0 alpha; `try-native` is an explicit planning
policy and still falls back when no safe direct lowering exists.

## Native Selection

By default, Rextio uses automatic native discovery:

```toml
[policy]
native_marker = "auto"
```

In this mode, Rextio may treat module-level functions as native candidates when
their types can be resolved and the function fits the supported direct Rust
subset.

You can require explicit markers instead:

```toml
[policy]
native_marker = "decorator"
```

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0
```

For future multi-target support, a marker can pin the intended target:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

Use `@rextio.exempt` when a function must stay on Python fallback:

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

Exempt functions are never emitted into generated Rust. If a native candidate
calls an exempt or fallback-only function, that candidate falls back too.

## Safety Model

Rextio keeps native compilation conservative:

- A direct Rust native function may call only accepted native functions,
  supported builtins, and supported standard-library functions.
- A native function calling fallback-only code is rejected - unless the
  caller is explicitly marked and the callee's signature is immutable scalars
  end to end (`int`/`float`/`bool`/`str`/`None`): that call becomes an
  in-process scalar boundary call (`RXT075`). The callee keeps running in the
  interpreter, so values and exceptions are CPython-exact and monkeypatching
  is honored; scalars cross by value, so argument identity (`is`) is not
  preserved (`None`/`bool` singletons are); containers never cross, and a
  boundary call inside a native loop - including comprehension bodies - keeps
  the caller on fallback (`RXT076`).
- Python fallback code may call native functions.
- Python loops that repeatedly call native functions produce boundary warnings.
- Generated wrappers can switch a function back to fallback after repeated
  boundary crossings - Python-to-native wrapper entries and native scalar
  boundary calls count toward the same per-function threshold.
- Python/Rust ownership differences are handled explicitly. Read-only reuse of
  owned values is lowered with Rust clones when needed, while mutable collection
  alias mutation stays on Python fallback.

Boundary fallback is controlled by:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## Supported Direct Rust Subset

Rextio 0.1.0 alpha supports a deliberately small subset. This is the code
that runs as native Rust.

Supported types include:

- `int`, `float`, `bool`, `str`, `bytes`, `None`
- `list[T]` for supported item types, including `list[list[T]]`
- fixed `tuple[...]`
- fixed `dict[K, V]` where keys are supported scalar key types
- limited `set[int]`, `set[bool]`, and `set[str]` (`set[float]` stays on the
  Python fallback: NaN-identity dedup has no faithful Rust lowering; native
  code also never *iterates* a set - hash order diverges from CPython)
- `Optional[T]` and `T | None`

Supported syntax includes:

- local assignment and typed local annotations
- arithmetic, boolean operations, comparisons, `if`, `while`
- `for x in xs`
- `range(...)`, `enumerate(xs)`, and `zip(xs, ys)` in supported loop or
  comprehension forms
- `break`, `continue`, `return`
- a restricted experimental `try`/`except`/`finally` subset (built-in
  exception handlers only; see [stability tiers](docs/stability.md))
- list/dict/set comprehensions in supported forms
- limited `list.append`, dict reads/writes, and indexing
- calls to accepted native helper functions

Supported builtin and standard-library lowering includes limited forms of:

- `len`, `abs`, `min`, `max`, `sum`, `all`, `any`, `sorted`, `reversed`
- selected `math` functions and constants
- selected `str`, `bytes`, and `list` methods
- `print`, `logging.debug/info/warning/error`
- `datetime`, `time`, `hashlib.sha256`, and `base64.b64encode`
  (`statistics.mean`/`fmean`, `json.dumps`/`json.loads`, and
  `base64.b64decode` have no faithful direct-native equivalent: explicitly
  marked functions using them ride the RXT080 runtime shim, auto-discovered
  ones stay on the Python fallback)

Unsupported or ambiguous code stays on fallback or is exposed through a Python
runtime semantics shim where supported. See
[Unsupported Features in 0.1.0 alpha](docs/unsupported-features.md) for the
detailed boundary.

## Writing Rextio-Friendly Python

Native promotion and boundary behavior follow directly from code shape. To
get the most out of Rextio:

- Annotate hot functions end to end - parameters and return type, using the
  supported scalar/list types. Unresolved types keep a function on fallback.
- Keep hot paths inside the supported subset and run `rextio check` early;
  every rejection names the construct that caused it.
- Move loops into native code: a Python loop that calls a native function
  crosses the boundary once per iteration (boundary warnings), while a
  native function that loops internally crosses once per call.
- Keep native call graphs native: native-to-native calls stay in Rust. A
  call to a fallback-only helper either rejects the caller or becomes a
  per-call scalar boundary call that counts toward the demotion threshold.
- Keep boundary calls out of loops and comprehension bodies (`RXT076`);
  hoist them, or mark the callee `@rextio.native` when it fits the subset.
- Pass immutable scalars across boundaries; containers never cross.
- Mark functions that must stay Python with `@rextio.exempt`, and split
  mixed functions so the typed hot core is its own function.
- Measure with `rextio bench`: very small functions can lose to call
  overhead, so batch enough work into each native call.

## Python Runtime Semantics Shim

Some Python features cannot be safely translated into typed Rust statements.
For explicitly marked native code, Rextio may generate a PyO3 shim that calls
the generated Python fallback implementation instead.

This compatibility path can preserve features such as class/object behavior,
instance methods, exceptions, context managers, `async`/`await`, generators, and
dynamic attribute access. It reports `RXT080`.

This path preserves behavior. It should not be treated as a Rust speedup path.

## Experimental Scalar-Helper Embedding

Rextio can optionally embed a very narrow set of unmarked scalar helpers as
internal native functions, compiled ahead of time like everything else.
This is off by default.

When enabled, an eligible unmarked helper (typed scalar arguments and return,
a single arithmetic return expression) is compiled into the generated native
artifact as an ordinary internal function - callable from native code, not
exported to Python. Embedded helpers lower through the normal checked path, so
integer overflow raises OverflowError and division by zero raises
ZeroDivisionError exactly like any native function. In the Rust executable
backend an embedded helper compiles into the binary instead of being delegated
per call to the CPython dispatcher.

```toml
[embedding]
enabled = true
```

Equivalent command-line and environment controls are:

```text
rextio build . --embed-helpers
REXTIO_EMBED_HELPERS=true rextio build .
```

## Using Numba on Fallback Code (experimental)

Numba support is EXPERIMENTAL in 0.1.0 alpha: recognition, reporting, and
the Nuitka-coexistence behavior may change before the first non-alpha
release. Rextio recognizes Numba decorators (`numba.jit`, `numba.njit`,
`numba.vectorize`, `numba.guvectorize`) as an external accelerator
(experimental)
for Python fallback code - the same externally-supported-tool pattern as the
Nuitka packaging backend. A decorated function stays on the Python fallback
cleanly (excluded from auto-discovery and helper embedding) and is labeled
`external_accelerator: numba` in reports; `rextio check` lists such functions.
Recognition resolves through the module's imports (attribute, from-import,
alias, and call forms; `numba.cuda.jit` included). Report labels in
`rextio check` cover straight-line imports only; the Nuitka build-time scan
is broader (star imports, optional-dependency guards, deferred imports
inside functions), so a module can be correctly kept plain by the build even
when its functions carry no label.

The contract boundary matters: an `@rextio.native` function has Rextio-verified,
CPython-exact semantics, while a `@numba.*` function runs under **Numba's**
semantics (for example, nopython-mode integer arithmetic wraps on overflow
instead of raising) - that trade is the user's explicit opt-in, outside
Rextio's native contract, exactly like `@rextio.exempt`. Combining
`@rextio.native` with a numba decorator is rejected loudly.

Compatibility: wheel and zipapp deployments work with numba installed as a
project dependency; the Rust executable's source-mode hybrid runtime works
(the dispatcher runs real CPython). The `--fallback=nuitka` backend
coexists automatically: modules using a recognized external accelerator are
kept as plain Python (the `.py` stays imported) while the rest of the tree is
Nuitka-compiled, and the build report lists them. The generated wheel ships a
Nuitka-compiled module as its extension only - the shadowed `.py` source is
excluded (dead weight that would also expose the source) - and carries a
platform-specific tag; accelerated modules keep their `.py`. A Nuitka *executable*
(`--executable-backend=nuitka`) and the `--hybrid-runtime=nuitka` dispatcher
cannot serve accelerated functions (compiled functions expose no bytecode and
the accelerator is not bundled) - those builds fail early with guidance
instead of dying at the first call. Prefer `@rextio.native` for typed scalar
code and Numba for NumPy/array kernels, and note that very small functions
lose to call-boundary costs under any accelerator.

Embedding adds no crate dependencies to generated Cargo projects. When
embedding is disabled, an eligible helper call still works through the
run-time scalar boundary call; embedding is the fast path that removes the
per-call interpreter round-trip. Unlike a boundary call, an embedded helper
is compiled ahead of time into the native artifact, so runtime replacement
of the helper (monkeypatching) is not visible to native callers.

## Examples

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

Example projects:

- `examples/pure_math`: direct Rust lowering for typed math hot paths.
- `examples/fallback_demo`: fallback behavior when native is disabled or missing.
- `examples/boundary_demo`: native-to-fallback boundary rejection and warnings.
- `examples/app_shell`: application shell stays Python while a scoring hot
  path can be native.

## Development And Verification

Run the test suite:

```text
python -m pytest
```

Real Cargo, Nuitka, and executable tests are skipped when the corresponding
toolchain is unavailable.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup and quality
gates.

## Roadmap

Plans, not promises - priorities can shift with alpha feedback:

1. Stabilization first: hardening the 0.1.0 alpha surface based on real
   usage before growing it.
2. An agentic-coding skill/plugin that teaches coding agents how to write
   Rextio-friendly Python.
3. A VS Code extension that shows, while you edit, whether the code on
   screen fits the supported native subset.
4. Rextio plugins - a plugin defines the rules for translating Python code
   that uses a specific package into Rust plus fallback code. We plan to
   build first-party plugins ourselves, starting with NumPy and continuing
   with widely used numeric and AI packages; once the plugin surface has
   stabilized, anyone will be able to build and publish Rextio plugins.
5. Longer term, additional native target backends beyond Rust are possible,
   but there is no concrete plan yet.

## Project Information

- [Feature stability](docs/stability.md) — what is stable vs. experimental in 0.1.0 alpha.
- [Versioning policy](docs/versioning.md) — SemVer with pre-1.0 caveats.
- [Unsupported features](docs/unsupported-features.md) — the 0.1.0 alpha subset boundaries.
- [Security model](SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Contributing](CONTRIBUTING.md) — setup, gates, and conventions.
- [Changelog](CHANGELOG.md).
