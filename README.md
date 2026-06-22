# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio 0.1.0 is an alpha-stage hybrid build tool. It compiles eligible
statically typed Python functions to Rust native modules and packages the rest
as safe Python fallback.

0.1.0 alpha is intentionally narrow. It is a local CLI and build-tool MVP for
projects that use statically typed Python hot paths. Rextio discovers eligible
functions by default when their types come from annotations, sibling `.pyi`
stubs, or conservative local context inference; projects can opt out and
require `@rextio.native` markers.
It does not claim full Python compatibility, bundled third-party package
coverage, framework migration, JIT behavior, or a full runtime boundary-cost
optimizer.

0.1.0 alpha includes conservative static boundary checks. It rejects native
functions that call fallback-only code, warns when Python loops repeatedly call
native functions, and generated wrappers switch that native function to fallback
after repeated Python/Rust crossings exceed a simple runtime threshold.

## Current commands

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

The initial implementation focuses on project initialization, native candidate
discovery, subset diagnostics, static boundary diagnostics, runtime disable
flags, and deterministic check reports.

Typical local flow:

```text
python -m pip install -e .
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython --entrypoint=myapp.cli:main
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## 0.1.0 alpha Scope

0.1.0 alpha supports a small statically typed Python subset for module-level
functions. Eligible functions are native candidates by default when Rextio can
resolve every argument and return type from source annotations, sibling `.pyi`
stubs, or conservative local context inference. Unsupported direct-Rust syntax,
unresolved types, unsafe native-to-fallback calls, and unresolved external calls
are rejected from direct Rust lowering and kept on Python fallback where
possible.

See [Unsupported Features in 0.1.0 alpha](docs/unsupported-features.md) for the
supported subset, boundary limits, diagnostics, and non-goals.

Current native candidates support scalar, `list[...]` including
`list[list[T]]`, fixed `tuple[...]`, limited fixed `dict[K, V]`,
limited `set[int|float|bool|str]`, and `Optional[T]` / `T | None` types. Supported
syntax includes arithmetic, comparisons, `if`, `while`, `for x in xs`,
`range(...)` loops, `for i, x in enumerate(xs)`, `for x, y in zip(xs, ys)`,
`break`, `continue`, augmented assignment, typed local annotations, simple
indexing, list literals, fixed tuple literals, limited dict read/write,
limited list/dict/set comprehensions, assignment expressions inside
comprehensions, and `list.append(...)` for supported list item types. Builtin support is
intentionally limited to `len`, `abs`, two-argument `min`/`max`, and
`sum(list[int|float])`. The supported `math` subset is `math.sqrt`, `math.sin`,
`math.cos`, and `math.floor`.

The expanded forms remain conservative: empty list literals need a supported
`list[...]` local annotation, and `range(start, stop, step)` currently requires
`step` to be a positive int literal. `enumerate` and `zip` are supported only as
batch loop or comprehension iterables over list variables. Dict support covers
fixed `dict[K, V]` forms where `K` is `int`, `bool`, or `str` and `V` is a
supported fixed value type. Set support is limited to `set[int]`, `set[float]`,
`set[bool]`, and `set[str]` comprehensions. Dataclasses are still outside direct
Rust lowering.

For Python semantics that cannot be safely lowered into the typed Rust subset,
Rextio can generate a Python runtime semantics native shim. This shim is a Rust
PyO3 function that calls the generated Python fallback implementation, so it can
preserve class/object behavior, regular instance methods marked with
`@rextio.native`, exception handling, context managers, `async`/`await`,
generators/`yield`, and dynamic attribute access such as `getattr` or
`obj.attr`. Rextio reports `RXT080` for this path. It is a compatibility path,
not a Rust speedup path. Automatic discovery for this path is conservative;
broad object-runtime code should be marked explicitly with `@rextio.native`.

Type inference is deliberately narrow. Rextio can infer simple scalar and
collection signatures from constants, arithmetic, comparisons, `if` tests,
loops, indexing, comprehensions, and supported builtins. A sibling `.pyi` file
with supported function signatures is preferred when source annotations are
missing. If a type remains ambiguous, the function stays on Python fallback.

Module top-level logic is Python fallback by default. Projects can opt into a
limited native initializer with `[policy] native_top_level = true` or
`--native-top-level`. This supports only a narrow import-time subset:
assignments, annotated assignments, augmented assignments, supported
expressions, and `if`/`while` blocks that update variables assigned before the
block. Assigned module variables must share one supported value type so the
Rust initializer can return `dict[str, T]`. Rextio keeps the original fallback
module and uses it when native is disabled or unavailable.

## Build Prerequisites

Native builds require Rust and Cargo. Rextio can also use `maturin` when
configured with `[rust] build_tool = "maturin"`; if maturin is unavailable,
Rextio falls back to Cargo when possible.

Nuitka fallback packaging is experimental. If `--fallback=nuitka` is requested
without Nuitka installed, Rextio reports a clear `RXT060` error and suggests
`--fallback=cpython`. When Nuitka is installed, Rextio invokes it on generated
Python fallback modules while still keeping the CPython fallback files in the
build artifact.

## Configuration Sources

Build and analysis settings use this precedence:

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

Command routing and output-shape arguments such as `project_root`, `bench`
targets, `init --force`, and `check --json` remain command-line only. Project
behavior settings can be configured from any of these sources:

| `rextio.toml` key | CLI parameter | Environment variable |
| --- | --- | --- |
| `[build] native_backend` | `--native-backend` / `--target-language` | `REXTIO_TARGET_LANGUAGE` / `REXTIO_NATIVE_BACKEND` |
| `[build] fallback_backend` | `--fallback` | `REXTIO_FALLBACK_BACKEND` |
| `[build] fallback_threshold` | `--fallback-threshold` | `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` |
| `[rust] binding` | `--rust-binding` | `REXTIO_RUST_BINDING` |
| `[rust] build_tool` | `--rust-build-tool` | `REXTIO_RUST_BUILD_TOOL` |
| `[fallback] nuitka` | `--nuitka-fallback` | `REXTIO_NUITKA_FALLBACK` |
| `[target] version` | `--target-version` | `REXTIO_TARGET_VERSION` |
| `[target.build_options]` | `--target-build-option KEY=VALUE` | `REXTIO_TARGET_BUILD_OPTIONS` |
| `[mappers] paths` | `--mapper-path` | `REXTIO_MAPPER_PATHS` |
| `[mappers] enabled` | `--enable-mapper` | `REXTIO_MAPPERS_ENABLED` |
| `[mappers] repository` | `--mapper-repository` | `REXTIO_MAPPER_REPOSITORY` |
| `[executable] entrypoint` | `--entrypoint` | `REXTIO_EXECUTABLE_ENTRYPOINT` |
| `[executable] name` | `--executable-name` | `REXTIO_EXECUTABLE_NAME` |
| `[executable] backend` | `--executable-backend` | `REXTIO_EXECUTABLE_BACKEND` |
| `[executable] nuitka_mode` | `--nuitka-mode` | `REXTIO_NUITKA_MODE` |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] require_type_hints` | `--require-type-hints` / `--no-require-type-hints` | `REXTIO_REQUIRE_TYPE_HINTS` |
| `[policy] allow_dynamic_features` | `--allow-dynamic-features` / `--no-allow-dynamic-features` | `REXTIO_ALLOW_DYNAMIC_FEATURES` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

0.1.0 alpha still validates values conservatively. Rust is the only implemented
native target today. `native_backend = "mojo"` and `native_backend = "julia"`
are accepted as planned target-language selections so versioned mapper and
build-option metadata can be configured, but source generation fails clearly
until those backends are implemented.

Mapper plugins can be loaded from local metadata folders or from a public Git
repository. Configure local folders with `[mappers] paths` and optional
`[mappers] enabled`; each folder must contain `rextio-mapper.toml` or
`mapper.toml`. Configure `[mappers] repository`, `--mapper-repository`, or
`REXTIO_MAPPER_REPOSITORY` with a public Git URL to clone mapper manifests into
`.rextio/mappers/repositories/` and discover mapper manifests recursively.

## Generated Artifacts

Rextio writes generated files under `.rextio/` and does not modify source files
in place.

```text
.rextio/
  build/
    python/
      rextio/
        runtime/
  generated/
    <target-language>/
    python/
  reports/
    check.json
    build.json
    bench.json
dist/
  <project>-0.1.0-<tag>.whl
  <executable-name>.pyz
  <executable-name>
  <executable-name>.dist/
```

`rextio check` writes `.rextio/reports/check.json`. `rextio build` writes both
check and build reports. `rextio bench` writes `.rextio/reports/bench.json`
with a structured fallback/native timing comparison.

`rextio generate` runs analysis and writes generated Rust/PyO3 and Python
wrapper/fallback source under `.rextio/generated/` without invoking Cargo,
maturin, or Nuitka and without creating `.rextio/build/` or `dist/`.

When `rextio build` succeeds, it also writes a generated hybrid artifact wheel
under `dist/`. Pure fallback wheels use `py3-none-any`; wheels that include the
generated native extension use the local CPython/platform tag. The test suite
installs this wheel into a fresh environment and verifies that packaged fallback
imports still work with `REXTIO_DISABLE_NATIVE=1`.

`rextio build --entrypoint=module:function` also generates a zipapp executable
artifact under `dist/`. Use `--executable-name=name` to control the output file
name; otherwise Rextio derives it from the entrypoint module. The result is a
Python zipapp (`.pyz`), so the target machine still needs a compatible Python
interpreter. Native extension modules cannot be imported directly from inside a
zipapp, so generated wrappers keep fallback safety and use Python fallback when
the native module is unavailable.

Nuitka executable artifacts are also available when Nuitka is installed:

```text
rextio build path/to/project \
  --entrypoint=myapp.cli:main \
  --executable-backend=nuitka \
  --nuitka-mode=standalone

rextio build path/to/project \
  --entrypoint=myapp.cli:main \
  --executable-backend=nuitka \
  --nuitka-mode=onefile
```

Standalone mode writes a Nuitka `.dist` application directory under `dist/`.
Onefile mode writes a single Nuitka executable under `dist/`. Nuitka executable
packaging is still toolchain-dependent; if Nuitka is unavailable, Rextio reports
a clear `RXT060` error and suggests the zipapp backend.

## Policy Configuration

0.1.0 alpha validates `rextio.toml` conservatively and rejects unknown sections,
unknown keys, unsupported backends, and policy values outside the 0.1.0 alpha
scope.

Boundary warnings are enabled by default. Projects that want strict safety
errors without Python-loop boundary warnings can set:

```toml
[policy]
boundary_warnings = false
```

Automatic native discovery is enabled by default:

```toml
[policy]
native_marker = "auto"
```

Projects that want only explicit native candidates can disable auto discovery:

```toml
[policy]
native_marker = "decorator"
```

In decorator-only mode, only functions marked with `@rextio.native` are native
candidates.

Explicit markers may also pin a function to a native target language:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

Target names are normalized case-insensitively. A target-specific marker applies
only when the active `--target-language` / `[build] native_backend` matches it;
for example, `@rextio.native(target="mojo")` is ignored by a Rust build and the
function stays on Python fallback. 0.1.0 alpha accepts `rust`, `mojo`, and `julia`
as target-planning values, but only Rust source generation is implemented.

Use `@rextio.exempt` to keep a function on Python fallback even when automatic
native discovery is enabled. Exempt functions are never emitted into generated
Rust; native candidates that call them are rejected by the normal
native-to-fallback boundary rule.

Top-level native initialization is separate from function discovery. Enable it
explicitly with:

```toml
[policy]
native_top_level = true
```

Unsupported top-level statements remain fallback-only. 0.1.0 alpha rejects
top-level native conversion for `for` loops, user/external function calls, and
heterogeneous module variable exports to avoid changing Python import
semantics.

## Fallback Safety

Generated wrappers use native functions when available and safe. They fall back
to Python when native import fails or when native execution is disabled:

```text
REXTIO_DISABLE_NATIVE=1
```

`REXTIO_NATIVE_MODE` can be set when a project needs explicit runtime behavior:

```text
REXTIO_NATIVE_MODE=auto      # default: use native when available, otherwise fallback
REXTIO_NATIVE_MODE=fallback  # force Python fallback
REXTIO_NATIVE_MODE=native    # require generated native functions to be available
```

Repeated Python-to-native wrapper calls are allowed at first. If a function's
wrapper is crossed more than `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` times, later
calls use the generated Python fallback for that function. The default threshold
is `1000`. `rextio generate --fallback-threshold=N`,
`rextio build --fallback-threshold=N`, `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`, and
`[build] fallback_threshold = N` can set the generated-code default for that
artifact. At runtime, `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` overrides the embedded
default. Set the threshold to `0` or set `REXTIO_DISABLE_BOUNDARY_FALLBACK=1` to
disable this automatic fallback. `REXTIO_NATIVE_MODE=native` bypasses this
threshold.

Use `.rextioignore` to keep generated or irrelevant Python files out of Rextio
analysis.

## Boundary Diagnostics

0.1.0 alpha boundary checks are static and conservative:

- `RXT070`: a native function calls fallback-only Python code.
- `RXT072`: a native function depends on a rejected native function.
- `RXT073`: fallback Python calls a native function inside a loop.
- `RXT080`: a native function uses the Python runtime semantics shim.

`RXT070` and `RXT072` reject the native candidate. `RXT073` is a warning; the
function remains eligible and may use native initially, but generated wrappers
fall back to the CPython/Nuitka fallback path after repeated runtime crossings
exceed the configured threshold. `RXT080` is a warning; the generated Rust
function preserves Python semantics by calling the generated fallback function.

## Examples

0.1.0 alpha includes focused local examples:

- `examples/pure_math`: simple typed math functions compiled as native hot paths.
- `examples/fallback_demo`: generated wrappers use Python fallback when native is missing or `REXTIO_DISABLE_NATIVE=1`.
- `examples/boundary_demo`: conservative boundary rejection through `@rextio.exempt` and Python-loop boundary warnings.

Try:

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
