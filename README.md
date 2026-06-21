# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio compiles eligible typed Python functions to Rust native modules and
packages the rest as safe Python fallback.

Public 1 is intentionally narrow. It is a local CLI and build-tool MVP for
projects that use typed Python hot paths. Rextio discovers eligible typed
functions by default; projects can opt out and require `@rextio.native` markers.
It does not claim full Python compatibility, full NumPy support, framework
migration, JIT behavior, or a full runtime boundary-cost optimizer.

Public 1 includes conservative static boundary checks. It rejects native
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

## Public 1 Scope

Public 1 supports a small typed Python subset for module-level functions.
Eligible typed functions are native candidates by default. Unsupported syntax,
dynamic features, unsafe native-to-fallback calls, and unresolved external calls
are rejected from native compilation and kept on Python fallback where possible.

See [Unsupported Features in Public 1](docs/unsupported-features.md) for the
supported subset, boundary limits, diagnostics, and non-goals.

Current native candidates support scalar, `list[...]` including
`list[list[T]]`, fixed `tuple[...]`, limited `dict[str, int|float|str]`,
limited `set[int|bool|str]`, and `Optional[T]` / `T | None` types. Supported
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
batch loop or comprehension iterables over list variables. Dict support is
limited to `dict[str, int]`, `dict[str, float]`, and `dict[str, str]`; set
support is limited to `set[int]`, `set[bool]`, and `set[str]` comprehensions.
Dataclasses are still outside Public 1 native compilation.

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

Public 1 still validates values conservatively. Rust is the only implemented
native target today. `native_backend = "mojo"` and `native_backend = "julia"`
are accepted as planned target-language selections so versioned mapper and
build-option metadata can be configured, but source generation fails clearly
until those backends are implemented.

Mapper plugins are local metadata folders today. Configure them with
`[mappers] paths` and optional `[mappers] enabled`; each folder must contain
`rextio-mapper.toml` or `mapper.toml`. Repository download is represented by
`[mappers] repository` for future work but is not implemented in Public 1.

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

Public 1 validates `rextio.toml` conservatively and rejects unknown sections,
unknown keys, unsupported backends, and policy values outside the Public 1
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

Use `@rextio.exempt` to keep a function on Python fallback even when automatic
native discovery is enabled. Exempt functions are never emitted into generated
Rust; native candidates that call them are rejected by the normal
native-to-fallback boundary rule.

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

Public 1 boundary checks are static and conservative:

- `RXT070`: a native function calls fallback-only Python code.
- `RXT072`: a native function depends on a rejected native function.
- `RXT073`: fallback Python calls a native function inside a loop.

`RXT070` and `RXT072` reject the native candidate. `RXT073` is a warning; the
function remains eligible and may use native initially, but generated wrappers
fall back to the CPython/Nuitka fallback path after repeated runtime crossings
exceed the configured threshold.

## Examples

Public 1 includes focused local examples:

- `examples/pure_math`: simple typed math functions compiled as native hot paths.
- `examples/fastapi_scoring`: FastAPI stays Python. `compute_score` becomes Rust native.
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
