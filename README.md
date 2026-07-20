# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**Compiles eligible typed Python functions to Rust and keeps everything
else on the Python fallback.**

Rextio **0.1.4** is an alpha-stage local build tool for Python projects,
published to PyPI on 2026-07-18 with plugin API **1.3** and tooling contract
**2.2.0**, superseding 0.1.3. It finds
typed Python functions that can be safely lowered to Rust, compiles them ahead
of time with PyO3, and keeps everything else running through generated Python
fallback code - same imports, same behavior.

**Unreleased branch note:** `main` remains at the released 0.1.4 commit while
Release Train C integrates on the next-version branch `0.1.5`; feature PRs
target `0.1.5` until the final release PR. Release Train C adds experimental host source/
artifact planning, a narrow initializer-before-main Rust executable slice, and
plugin API **1.4** fail-closed standalone artifact capability (rust-crate /
host-executable), plus a C5.1 external pure-Python source inventory/gate
preview, a C6.1 bounded prebuild authorization-contract preview, and a C6.2
bounded host-extension wheel SBOM/provenance preview (incomplete/unsigned; not
full C6), plus a C6.3 opt-in required-evidence gate for that exact preview
artifact set and a C6.4 sanitized, direct-only native runtime linkage inventory
for macOS Mach-O and Linux ELF extensions. C6.5 adds an always-blocked,
closed-vocabulary distribution-authorization readiness assessment that makes
selected current-scope hard-authorization gaps explicit without granting
authority. C6.6 adds a bounded observation-only inventory binding each accepted
project-owned native function to its project-relative source hash, reliable
range, semantic-AST hash, generated `src/lib.rs` input, closed generator/backend,
and sorted plugin ids. It does not complete source-transformation provenance.
C6.7 adds an exact, bounded observation-only inventory for every reachable
Cargo package (including the generated path root), preserving each nonblank
Cargo metadata license string verbatim as `declared-unvalidated` and recording
blank/null values as `missing`. It performs no SPDX validation or legal/policy
decision. C6.8 adds an exact, observation-only one-hop path record for every
direct native dependency: trusted system names remain logical leaves, while
contained Mach-O `@loader_path`/self-anchored `@rpath` and ELF `$ORIGIN`
RPATH/RUNPATH candidates must bind one exact regular non-symlink wheel member.
It does not claim actual loader selection or transitive closure. C6.9 builds on
that root with a deterministic, cycle-safe graph over recursively inspected
packaged Mach-O/ELF members and logical system leaves. Every packaged node is
rebound to exact wheel bytes and inspected through an immutable private
snapshot under closed node/edge/depth/candidate/inspector/output/size bounds.
The graph remains observation-only and explicitly incomplete: it does not use
ambient loader state, choose the actual loader result, hash system libraries,
or observe `dlopen`. This branch emits additive tooling contract **2.14.0** and plugin API **1.4**
while keeping package version
**0.1.4**; those changes are not yet a tagged or PyPI release. Published 0.1.4
remains the plugin API **1.3** / contract **2.2.0** producer. See
[Host source-AOT and native executables](docs/source-aot-and-executables.md) and
[plugin lowering](docs/specs/plugin-lowering.md) §10.

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
| `rextio check` | Analyzes native candidates and prints diagnostics (structured JSON via `--format json`). |
| `rextio capabilities` | Prints the machine-readable capability manifest: supported types, promotion rules with guidance, and active plugins (experimental). |
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
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust --executable-fallback=error
rextio build . --rust-importable --rust-crate-name=my_native
rextio build . --artifact-evidence-policy=required
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

`--artifact-evidence-policy=required` is deliberately narrower: it accepts
exactly one native host-extension + CPython wheel backed by an accepted native
region (a function and/or native top-level segment), with no executable or
Rust-importable crate, and exits with `RXT060` unless the artifact-evidence
status is `preview-ready`. C6.4 makes that preview include a bounded inventory
of only the extension's directly observed Mach-O (`otool -L`) or ELF
(`readelf -W -d`) link entries. The installed native binary must match the
exact wheel member by generated-Python relative name, SHA-256, and byte size
before the inventory is accepted. Binary-header and linkage inspection use one
private same-byte snapshot bound to both that wheel member and the installed
original; both original and snapshot identity/digest are revalidated. Inspector
children use reviewed absolute tool paths without a shell or inherited parent
environment, under only a minimal C locale. It records a normalized binary
architecture and only a closed set of expected system-runtime dependencies;
each accepted dependency has a sanitized `origin` and stable `bom_ref`. A
Mach-O first-row private Cargo self-ID is excluded only when the header is
`MH_DYLIB` and bounded `otool -D` reports that exact ID. An unexpected
dependency makes evidence unavailable. C6.8 may additionally bind each direct
dependency to one packaged wheel member or a system logical leaf. The packaged
path observation uses fixed `otool -l` / `readelf -W -d` inspection, only
contained loader/ORIGIN-anchored candidates, exact wheel hash/size binding, and
pinned non-symlink file receipts. It does not model actual loader-environment
selection, system library bytes, transitive dependencies, or `dlopen`. C6.9 may
then recursively inspect only those exact packaged members, preserving cycles
as canonical graph edges while inspecting each packaged node at most once.
Strict global and per-dependency bounds, exact wheel/hash/size rebinding,
case/hardlink alias rejection, Linux system-SONAME shadow checks, and final
receipt verification fail closed by omitting only C6.9. Its gate remains
`distribution_authorized: false`,
`complete: false`, and `signed: false`; it is not a release authorization or a
full supply-chain attestation. The default `best-effort` policy preserves the
C6.2 behavior where a fixed, sanitized evidence-unavailable reason does not fail
an ordinary build. Under `required`, the same unavailable evidence produces
`RXT060`; publication and rollback pin the output parent and verify exact
content receipts. Required wheels are built privately and exposed only with a
create-if-absent hard link; rollback quarantines a public candidate before
receipt verification. It therefore never claims or deletes an observed
concurrent-owner file. Publication mismatch makes evidence unavailable;
pre-existing or concurrently replaced content is restored or retained for
recovery, and a required rollback mismatch is reported as incomplete.
Windows, runtime-bearing plugins, signatures, transitive
closure, and runtime `dlopen` discovery remain outside this preview.

For that same in-scope wheel path, `build.json` also includes
`artifact_distribution_authorization`. This C6.5-C6.9 policy-version-5 record is derived from the
final `artifact_evidence` record after required-mode revalidation/transaction
handling. It always reports `status: "blocked"`,
`authority: "readiness-assessment-only"`, and false values for `complete`,
`signed`, and `distribution_authorized`. Preview-ready evidence with a valid
C6.6-C6.9 inventories satisfy only eight bounded observation checks after closed-model
reconstruction and exact source/generated `EvidenceFileRef` cross-binding; it
does not reopen artifacts, re-inspect output bytes, or independently re-derive
the recorded qualname, range, or semantic-AST hash from source, `BuildPlan`, or
the unsigned provenance. License
policy, runtime path/transitive closure, runtime dynamic loading, complete build
inputs, complete source-transformation provenance, builder identity, reproducibility,
signatures, and complete SBOM composition remain selected current-scope fixed
blockers. Unavailable evidence reports only `evidence-unavailable` plus its
existing sanitized reason. If a preview evidence model cannot pass the stricter
readiness validation, every check becomes `not-evaluated` and the only blocker
is `readiness-assessment-unavailable`; this cannot fail an otherwise successful
best-effort build or satisfied C6.3 required gate. No configuration flag can
turn this assessment into authorization.

The C6.6 `source_transformation_inventory` is deterministic and immutable. It
serializes SHA-256 identities, bounded logical paths/ranges, and closed ids only;
raw Python source, AST dumps, absolute paths, exception text, credentials, and
unbounded output are excluded. Accepted-function count, total plugin references,
unique plugin ids, and deterministic serialized inventory size have closed
bounds. If the inventory cannot be bound, or would make provenance exceed its
sidecar ceiling, evidence and
the independent C6.3 gate keep their prior outcome, while the new observation is
`unavailable` with the fixed
`source-transformation-inventory-unavailable` blocker. A malformed,
noncanonical, or source/generated-reference-binding-breaking inventory instead
uses the existing all-`not-evaluated`
`readiness-assessment-unavailable` shape. The separate
`source-transformation-provenance-complete` check remains blocked. A
structurally valid changed observation value is not independently detected by
this report-only evaluator and still cannot become signed, complete, or
distribution-authorizing.

The C6.7 `component_license_inventory` is likewise deterministic, immutable,
and observation-only. Its records exactly cover the reachable
`cargo_packages` set in canonical `bom_ref` order and bind only `bom_ref`,
name, version, package kind, the raw bounded metadata string or null, and
`declared-unvalidated | missing`. Nonblank values such as `UNKNOWN`,
`NOASSERTION`, compound expressions, and sentinel-looking text are not parsed,
normalized, approved, or denied. Whitespace-only values are missing; otherwise
leading and trailing whitespace is retained. NUL/control characters and
over-budget values fail closed. Missing inventory makes only
`component-license-inventory-bound` unavailable and adds the fixed
`component-license-inventory-unavailable` blocker. Malformed, reordered,
duplicated, stale, or non-exactly-bound records use the all-`not-evaluated`
readiness-unavailable shape. If provenance still exceeds its ceiling after the
newer C6.9 and C6.8 observations are omitted, C6.7 is omitted next so C6.6 and all earlier evidence/gate results are preserved whenever
possible. `component-license-policy-complete` remains blocked: this is not SPDX
validation, a license allow/deny lock, legal approval, or distribution authority.

The C6.8 `native_runtime_path_resolution` remains incomplete and
observation-only. Records are in direct-dependency `bom_ref` order and bind the
exact dependency name/origin plus one closed result/mechanism. Packaged records
also bind one unique canonical `WheelEntryRef` name, SHA-256, and size; missing,
ambiguous, symlinked, escaping, unsupported, or changed candidates omit only
C6.8. The readiness report then marks
`direct-native-path-resolution-bound` unavailable and adds
`native-runtime-path-resolution-inventory-unavailable`; the ordinary build and
C6.3 gate are unchanged. A present malformed or format-crossed record fails the
readiness reconstruction closed. C6.9 is omitted first, then C6.8, C6.7, and
C6.6 at the provenance ceiling. Actual loader precedence/environment, complete
transitive closure beyond the bounded C6.9 graph, system-library bytes, runtime `dlopen`, Windows PE, WASM,
runtime-bearing plugins, signatures, and distribution authorization remain out
of scope.

The C6.9 `native_runtime_transitive_closure` field is deliberately named for
the graph it observes, not a completeness claim. Its fixed fields keep
`complete: false`, `transitive_closure_complete: false`, and
`actual_loader_selection: false`. Missing, ambiguous, noncanonical, aliased,
tampered, unsupported, malformed, deadline-exhausted, or over-budget recursive
observations make only `bounded-static-native-runtime-graph-bound`
`unavailable` with the fixed
`bounded-static-native-runtime-graph-unavailable` blocker. C6.8 remains when a
C6.9-only check fails; a C6.8 failure necessarily removes both dependent
observations. The readiness check
`native-runtime-transitive-closure-complete` remains blocked.

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
| `dist/<name>` | Optional native Rust binary (`--executable-backend=rust`); `python-subprocess` needs CPython, while a closed graph or self-contained Nuitka sidecar needs no separate Python install. |
| `dist/<crate>-rust-crate/` | Optional Rust library crate for Rust projects to import. |

The generated Python wrappers try native code first and fall back to Python when
native is disabled, unavailable, rejected by analysis, or past the configured
boundary threshold.

Wrapper construction reserves no user-facing ``_rextio_*`` spelling. Internal
dispatch objects are created in an isolated initialization scope, so an
explicit ``__all__`` may faithfully export user functions or values whose names
look like generated helpers. Native top-level values are published only after
dispatch closures and native method replacements have been initialized.

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

The Rust executable's fallback policy is separate from wheel fallback and is
always explicit in its resolved artifact profile:

| Fallback | Behavior |
| --- | --- |
| `error` | Require a fully closed direct-native entry graph; fail before Cargo otherwise. |
| `python-subprocess` | Delegate supported immutable-scalar fallback calls to external CPython (default). |
| `nuitka-sidecar` | Compile the bounded fallback dispatcher as a Nuitka sidecar. |

Select it with `--executable-fallback`, `[executable] fallback`, or
`REXTIO_EXECUTABLE_FALLBACK`. The older `--hybrid-runtime=source|nuitka`
spelling remains a compatibility alias for
`python-subprocess|nuitka-sidecar`.

This compiles a native binary (`dist/<name>`) whose `main` runs in Rust. The
entrypoint must be an accepted direct-native `def main(argv: list[str]) -> int`:
`argv` mirrors `sys.argv` (the program path at index 0). The supported Python
`int` return is lowered as Rust `i64`; generated `main` casts that `i64` to
`i32` before `std::process::exit`, so values outside the `i32` range are
truncated to the low 32 bits. POSIX observers generally receive only the low 8
bits of the status, while Windows retains a 32-bit status representation.
Prefer `0..255` for portable exit codes. A raised error is printed
CPython-style (`OverflowError: ...`) to stderr with a non-zero exit. Requires
Cargo.

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

Delegated `SystemExit` (including `sys.exit(n)`) is a separate path from
direct-native `main`'s return code. The Python dispatcher forwards an int exit
as `{"exit": code}` (bool codes normalized to `0`/`1`); the Rust client honors
that frame only when the code is representable as a signed `i64`
(`serde_json::Value::as_i64`). Once consumed, the value is cast to `i32` before
`std::process::exit`, so platform process-status width still applies — prefer
`0..255` for portable codes, as with direct-native `main`. A Python `int`
outside signed `i64` still serializes as a JSON number on the wire, but the
client cannot consume it as an exit code: the exchange fails with a
malformed-response `RuntimeError` (printed CPython-style, non-zero exit) rather
than terminating with the intended status. Oversized delegated exit codes are
therefore not CPython-equivalent and must not be assumed to round-trip.

`--executable-python` pins the interpreter the binary launches (a name on `PATH`,
an absolute path, or a path relative to `<binary>.runtime` to bundle one);
`REXTIO_RUNTIME_PYTHON` overrides it at run time on the target machine.
`--hybrid-runtime=nuitka` instead compiles the delegated Python into a
self-contained dispatcher executable shipped in the runtime directory, so the
hybrid binary needs no separate Python install (requires Nuitka at build time).

Release Train C also connects one narrow top-level ordering slice to Rust
`main`. With `--native-top-level`, exactly one no-import source module may run
plain single-name assignments to `bool`/`int`/`float`/`str` literals before
argv handling and the entrypoint. Source hashes and statement indexes are
revalidated. The assigned values are discarded: they are not Rust globals,
are not published back to Python, and cannot be read by native functions.
Anything broader makes the executable unavailable before Cargo. This
unreleased slice is documented in
[Host source-AOT and native executables](docs/source-aot-and-executables.md).

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
| `[build] artifact_evidence_policy` | `--artifact-evidence-policy` | `REXTIO_ARTIFACT_EVIDENCE_POLICY` |
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
| `[executable] fallback` | `--executable-fallback` | `REXTIO_EXECUTABLE_FALLBACK` |
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

Rust is the only implemented native target in 0.1.4.

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

The unreleased C5.1 branch also has a deliberately non-building, config-only
preview for one exact installed pure-Python distribution:

```toml
[imports.packages.small_math_pkg]
policy = "try-native"
max_depth = 1
distribution = "small-math-pkg"
version = "1.0.0"
```

This full declaration may appear for exactly one imported package. Rextio does
not import or execute the package. It inventories direct depth-1 UTF-8 `.py`
files only after verifying the exact distribution name/version, one RFC822
WHEEL 1.0 record with a sole `py3-none-any` purelib tag, contained non-symlink paths, and RECORD
SHA-256/size values. `check` and `generate` emit a sanitized
`external_source_plan`; `generate` never copies that package source into the
fallback tree. Existing `try-native` entries without `distribution` and
`version` remain metadata-only.

This is inventory evidence, not source-to-Rust conversion. Candidate function
names are only lexical hints: they are not connected to project calls, lowered,
compiled, packaged, or redistributed. `rextio build` therefore stops with
`RXT060` before Python/Nuitka/Cargo or artifact work whenever the imported
declaration produces a plan, including an unavailable plan.

**C6.1 prebuild authorization-contract preview (not full C6):** run
`rextio check` and copy `source_files`, `metadata_files`,
`plan_snapshot_sha256`, and `license_material_sha256` into a project-owned
`rextio.external-source.lock.json` (see the tooling-contract copy rules).
The lock binds exact identity, path/SHA-256/**size**/**role** material
(sources + RECORD/METADATA/WHEEL + PEP 639 license files under
`dist-info/licenses/`), custom `source_inventory` (not full SPDX/CycloneDX),
provenance with exact ordered evidence and closed attestor relationships, and
a closed license attestation (`REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1`).
Null/unknown licenses never become preview-ready or verify. Missing/invalid
locks → `external-source-c6-blocked`. Verified locks still block with
`external-source-c5-not-implemented` and never open a build path.

**License warning:** translating or redistributing dependency source can create
derivative-work and redistribution obligations. Review the exact package
license, especially GNU/copyleft terms. Rextio's inventory and SourceLock gate
are not legal advice. The same warning is emitted on stderr and serialized in
the plan.

The supported package policies are `fallback`, `analyze`, `try-native`, and
`plugin`. Since 0.1.1 a plugin can also describe and *lower* covered
constructs (plugin API 1.1 — see
[the plugin lowering spec](docs/specs/plugin-lowering.md)); 0.1.2 adds
backward-compatible plugin API **1.2** with two distinct roles:
**static literal/ordered keyword metadata** enables literal-axis
claims/lowering, and **structured `ClaimExpr` trees plus leaves-mode
lowering** enable fusion. **0.1.3** ships additive plugin API **1.3**:
opaque resident values/native chaining plus static receiver,
callable-body/native-symbol, and declared-schema claim metadata, with
version-gated static `bool`/`str` named-keyword literals. API 1.1/1.2
providers keep their legacy shapes; API 1.3 remains Experimental. The
first-party [rextio-numpy](https://github.com/rextio/rextio-numpy) plugin is
installed separately (core has no reverse dependency on it). PyPI **0.1.1** is
the published API-1.2 consumer with literal-axis and fusion support and
requires core **>= 0.1.2,<0.2**.
**Strict related-package publish order for the 0.1.2 line (completed
2026-07-14):** rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1 (see
[the tooling contract](docs/specs/tooling-contract.md)). Core **0.1.3** is
published on 2026-07-17 with plugin API 1.3 and tooling contract **2.1.0**
(additive over the **2.0.0** shape emitted by core 0.1.2; dual-map `2.x`
consumers remain compatible).
Core **0.1.4** was published on 2026-07-18 after rextio-lsp 0.1.2, completing
Release Train B in strict consumer-first order. It retains plugin API 1.3 and
emits tooling contract **2.2.0**, adding isolated promotion assessments,
trusted marker intent, and reliable function/name ranges without changing
legacy route/status/rejection meanings.
General dependency lowering is not bundled; `try-native` is an explicit
planning policy and still falls back when no safe direct lowering exists.

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

Rextio 0.1.4 supports a deliberately small subset. This is the code
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
[Unsupported Features in 0.1.0](docs/unsupported-features.md) for the
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

The wrapper stores exact fallback callables in an isolated ordinal registry;
it does not add generated `_rextio_*` attributes to either the fallback module
or the public module. A source module may therefore export those spellings
without collision.

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

Embedding adds no crate dependencies to generated Cargo projects. When
embedding is disabled, an eligible helper call still works through the
run-time scalar boundary call; embedding is the fast path that removes the
per-call interpreter round-trip. Unlike a boundary call, an embedded helper
is compiled ahead of time into the native artifact, so runtime replacement
of the helper (monkeypatching) is not visible to native callers.

## Using Numba on Fallback Code (experimental)

Numba support is EXPERIMENTAL in 0.1.0: recognition, reporting, and
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

The first-party [rextio-numpy](https://github.com/rextio/rextio-numpy)
plugin translates covered NumPy into AOT-compiled native Rust. **Published
rextio-numpy 0.1.1** expands the initial 0.1.0 float64 1-D surface to the
certified F64/F32/I64 rank-1/rank-2 broadcasting subset, literal-axis
reductions, and 2–8-op elementwise fusion. It uses core plugin API 1.2
(**core >= 0.1.2**): literal-axis claims come from static keyword/literal
metadata, while fusion uses `ClaimExpr` + leaves-mode. Rank-2 `dot`/matmul
remains outside the covered surface and falls back. The required release
order — dual-map **rextio-lsp 0.1.1**, then **core 0.1.2**, then
**rextio-numpy 0.1.1** — completed on 2026-07-14. NumPy code therefore has
two routes: Rextio-plugin AOT compilation for the covered surface, or Numba
JIT inside the Python fallback. When both apply, an explicit `@numba.*`
decorator wins and the analyzer emits an informational RXT091 note; broader
guidance on choosing between the routes will firm up as the plugin surface
grows.

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
- `examples/wheel_package`: the default hybrid wheel, installed into a
  fresh environment and used through unchanged imports.
- `examples/nuitka_fallback`: hybrid wheel with a Nuitka-compiled fallback.
- `examples/numba_accelerator`: Rextio native and a Numba-JIT NumPy kernel
  side by side.
- `examples/nuitka_numba`: Rust native + Nuitka fallback + a Numba module
  kept as plain Python, in one build.
- `examples/zipapp_app`: single-file `.pyz` executable.
- `examples/nuitka_executable`: onefile Nuitka executable.
- `examples/rust_executable`: standalone native Rust binary.
- `examples/rust_crate`: Cargo library crate for Rust callers.
- `examples/embedding_helpers`: scalar boundary calls vs. embedded helpers.

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

1. Stabilization first: hardening the 0.1.0 surface based on real
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

- [Feature stability](docs/stability.md) — what is stable vs. experimental in 0.1.0.
- [Versioning policy](docs/versioning.md) — SemVer with pre-1.0 caveats.
- [Unsupported features](docs/unsupported-features.md) — the 0.1.0 subset boundaries.
- [Host source-AOT and native executables](docs/source-aot-and-executables.md) — unreleased Train C planning and initializer limits.
- [Device-provider API draft](docs/specs/device-provider.md) — non-operational hardware/runtime contract boundary.
- [CUDA Driver API inventory validation](docs/testing/cuda-driver-validation.md) — Windows+Linux bounded probe instructions; not a CUDA support claim.
- [Security model](SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Contributing](CONTRIBUTING.md) — setup, gates, and conventions.
- [Changelog](CHANGELOG.md).
- Author: Steve Si-young Song <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev).
