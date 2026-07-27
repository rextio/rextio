# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**Compiles eligible typed Python functions to Rust and keeps everything
else on the Python fallback.**

Rextio is an alpha-stage local build tool for Python projects. It finds
typed Python functions that can be safely lowered to Rust, compiles them ahead
of time with PyO3, and keeps everything else running through generated Python
fallback code - same imports, same behavior.

For release-by-release changes, see [CHANGELOG.md](CHANGELOG.md).

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

Start with normal typed Python:

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

Install and analyze/build (from a source checkout use
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

Native is an optimization, not a requirement. If the native module is missing,
disabled, or fails to load, the package still runs through Python fallback.
Force fallback at runtime with:

```text
REXTIO_NATIVE_MODE=fallback
```

Useful first-project commands: `rextio init`, `rextio check`,
`rextio generate` (write generated source without compiling), `rextio build`,
`rextio bench`, and `rextio clean`.

<!-- rextio-benchmark:start -->
## Verified CPU benchmark results

Three-run medians on **Mac16,11 / Apple M4 Pro**, **2026-07-26**, CPython **3.11.9**.

| Workload | 3-run median speedup |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas Series.map | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

Results are workload-specific. Values near 1× indicate parity, not a material speedup. CUDA was not measured.

**For full methodology, exact revision provenance, raw evidence, diagnostics, and detailed results, use the [rextio-benchmark](https://github.com/rextio/rextio-benchmark) repository.**
<!-- rextio-benchmark:end -->

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
0.1.5 Experimental slice is documented in
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
| `[build] artifact_distribution_policy` | — | — |
| `[build] artifact_source_lock_manifest` / `artifact_source_lock_signature` | — | — |
| `[build] artifact_policy_manifest` / `artifact_policy_manifest_sha256` | — | — |
| `[build] artifact_cargo_lock` / `artifact_cargo_lock_sha256` | — | — |
| `[build] artifact_cargo_vendor` / `artifact_cargo_vendor_sha256` | — | — |
| `[build] artifact_toolchain_support_lock` / `artifact_toolchain_support_lock_sha256` | — | — |
| `[build] artifact_trusted_public_key` / `artifact_trusted_public_key_sha256` | — | — |
| `[build] artifact_final_signature` / `artifact_signing_request_output` | — | — |
| `[build] artifact_repeat_builds` | — | — |
| `[rust] binding` | `--rust-binding` | `REXTIO_RUST_BINDING` |
| `[rust] build_tool` | `--rust-build-tool` | `REXTIO_RUST_BUILD_TOOL` |
| `[rust] importable` | `--rust-importable` / `--no-rust-importable` | `REXTIO_RUST_IMPORTABLE` |
| `[rust] crate_name` | `--rust-crate-name` | `REXTIO_RUST_CRATE_NAME` |
| `[fallback] nuitka` | `--nuitka-fallback` | `REXTIO_NUITKA_FALLBACK` |
| `[target] version` | `--target-version` | `REXTIO_TARGET_VERSION` |
| `[target.build_options]` | `--target-build-option KEY=VALUE` | `REXTIO_TARGET_BUILD_OPTIONS` |
| `[target] device_provider` / `device_capability` | — | `REXTIO_DEVICE_PROVIDER` / `REXTIO_DEVICE_CAPABILITY` |
| `[target.device_options]` | — | `REXTIO_DEVICE_OPTIONS` |
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

Rust is the only implemented native target in 0.1.8.

Device-provider selection is an advanced, experimental build integration. It
loads only the explicitly named `rextio.device_providers` entry point and
preflights it before generated-output mutation. An accelerator provider also
requires a matching typed `DeviceRequirement` emitted by a domain lowering;
configuration alone does not make current CPU-only Torch or TensorFlow routes
CUDA-capable. `[target.device_options]` is not a secret store: raw values are
passed to the selected provider, while Rextio reports only option keys and a
binding digest. `rextio capabilities` reports a configured provider/capability
identity without provider discovery, preflight, or option disclosure. See
[Device Provider API 1](docs/specs/device-provider.md).

Core 0.1.8 publishes plugin API **1.7** / tooling contract **3.0.0** semantic artifact-contract identities. Core 0.1.7 added plugin API **1.7** / tooling contract **2.28.0** function-scope guards. Core 0.1.6 added plugin API **1.6** / tooling contract **2.27.0** static
device-domain authorization. An accepted
accelerator plugin type contributes structured artifact requirements, and its
lowerer receives a minimal redacted authorization only after the explicitly
selected provider has matched and preflighted that exact profile. CPU-only and
fallback-only plugin types remain unchanged; mixed/conflicting domains,
non-zero GPU ordinals, missing providers, and wrong capabilities fail closed.
This Core contract does not itself add Torch or TensorFlow CUDA lowering.

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

The 0.1.5 Experimental external-source inventory has a deliberately non-building
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

In ordinary preview mode this is inventory evidence, not source-to-Rust
conversion. Candidate function
names are only lexical hints: they are not connected to project calls, lowered,
compiled, packaged, or redistributed. `rextio build` therefore stops with
`RXT060` before Python/Nuitka/Cargo or artifact work whenever the imported
declaration produces a plan, including an unavailable plan. The one exception
is the separately configured strict profile below; it does not reuse preview
JSON as build authority.

**SourceLock authorization (preview):** run `rextio check` and copy
`source_files`, `metadata_files`, `plan_snapshot_sha256`, and
`license_material_sha256` into a project-owned `rextio.external-source.lock.json`
(see the tooling-contract copy rules). The lock binds exact identity,
path/SHA-256/**size**/**role** material (sources + RECORD/METADATA/WHEEL + PEP
639 license files under `dist-info/licenses/`), custom `source_inventory` (not
full SPDX/CycloneDX), provenance with exact ordered evidence and closed
attestor relationships, and a closed license attestation
(`REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1`). Null/unknown licenses never become
preview-ready or verify. Missing or invalid locks remain blocked. In ordinary
preview mode, a verified lock alone does not authorize building or
distribution. Only the separate strict artifact-evidence profile may attempt
same-transaction build authority, subject to every later hard gate.

### Strict artifact-evidence profile (0.1.5 Experimental)

`artifact_distribution_policy = "strict-evidence"` selects a separate fail-closed
distribution profile. It is intended for bounded builds that need signed source
locks, owner-pinned Cargo lock/vendor inputs, owner policy finalization, offline
frozen Cargo builds, and atomic publication of a wheel with evidence sidecars.

User-level behavior and limits:

* Requires CPython **3.11** exactly on `aarch64-apple-darwin` or
  `x86_64-unknown-linux-gnu`, Cargo/PyO3 (`rust.importable = false`), CPython
  fallback, a non-editable Rextio wheel install, and no plugins, executable
  entrypoint, embedding, or native top-level initialization.
* Accepts exactly one SourceLock-authorized pure-Python distribution and only
  direct final-import calls whose positional arguments and return are statically
  supported scalars; reached leaf helpers lower as private Rust functions.
* Rextio accepts public verification material only. It does not invent owner
  decisions and never accepts, creates, or retains a private signing key.
* The lifecycle is owner-driven: bootstrap a technical policy template, complete
  and finalize owner policy offline (`rextio policy finalize`), produce a signing
  request, attach a detached signature envelope, then republish. Each lifecycle
  `rextio build` stage recollects inputs and performs two actual isolated,
  offline, frozen Cargo builds.
* The published bundle is create-if-absent and fails closed on path aliasing,
  unsafe files, platform/scope mismatch, stale analysis, unexpected dependencies,
  or concurrent replacement of the publication target (idempotent retry of an
  already-committed identical bundle is the sole success path for an existing
  target).

**Safety caveats:** cache-free install checks, support-lock verification, and
sandbox isolation protect evidence integrity for an already owner-controlled
process. They are not a secure-boot claim, do not defend against hostile
same-UID concurrent replacement or a compromised kernel/OS, and are not a
general hermetic-build or cross-platform CI guarantee. Cargo lock/vendor pins
establish owner-selected input integrity; they do not authenticate a registry,
publisher, or upstream origin.

**License warning:** translating or redistributing dependency source can create
derivative-work and redistribution obligations. Review the exact package
license, especially GNU/copyleft terms. Rextio's inventory and SourceLock gate
are not legal advice. The same warning is emitted on stderr and serialized in
the plan.

Configuration keys appear in the table above. For exact pin requirements,
lifecycle artifacts, sandbox behavior, signing envelopes, host validation, and
exclusion lists, see
[Host source-AOT and native executables](docs/source-aot-and-executables.md)
and [Feature stability](docs/stability.md).

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
version-gated static `bool`/`str` named-keyword literals. **0.1.5** ships
additive plugin API **1.4** for optional, fail-closed standalone artifact
capability. API 1.1/1.2/1.3 providers keep their legacy shapes; API 1.4 remains
Experimental. Core 0.1.6 additionally defines API **1.5**
comparison/result-only-resident support and API **1.6** structured static
device metadata plus Core-validated lowering authorization. API 1.1-1.5
providers remain compatible and never receive a non-`None` device
authorization. The
first-party [rextio-numpy](https://github.com/rextio/rextio-numpy) plugin is
installed separately (core has no reverse dependency on it). PyPI **0.1.2** is
the current published consumer. It uses plugin API **1.5** for bounded
comparison/result-only-resident masks and exact three-argument `numpy.where`,
while preserving the earlier literal-axis and fusion surfaces; it requires
core **>= 0.1.2,<0.2**.
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
Core **0.1.5** was published on 2026-07-23 with plugin API **1.4**, tooling
contract **2.24.0**, and readiness policy **11**. Its host source-AOT,
executable, and strict artifact-evidence surfaces remain Experimental/Alpha
under the bounded scope described above.
Core **0.1.6** was published on 2026-07-26 with plugin API **1.6**, tooling
contract **2.27.0**, and Device Provider API **1**. Core **0.1.7** was
published on 2026-07-27 with plugin API **1.7** and tooling contract
**2.28.0** (function-scope RAII guards). It retains the same
readiness policy and fail-closed Alpha boundaries. Core **0.1.8** was
published on 2026-07-27 with plugin API **1.7** and tooling contract
**3.0.0**, replacing public artifact lifecycle identities with semantic
`artifact-*` names while retaining exact 0.1.7 dialects for legacy
read/verification only.
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

Rextio 0.1.8 supports a deliberately small subset. This is the code
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

Rextio 0.1.5 ships the experimental host source-AOT, executable, and strict
artifact-evidence surfaces described above. Broader external-package promotion
remains deferred; the next platform milestone is bounded WASM work after the
host release gate is ready.

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
- [Host source-AOT and native executables](docs/source-aot-and-executables.md) — 0.1.5 Experimental host source planning, executables, and strict artifact-evidence profile.
- [Device-provider API draft](docs/specs/device-provider.md) — non-operational hardware/runtime contract boundary.
- [CUDA Driver API inventory validation](docs/testing/cuda-driver-validation.md) — repository-only Windows+Linux bounded probe instructions; not installed by the PyPI package and not a CUDA support claim.
- [Security model](SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Contributing](CONTRIBUTING.md) — setup, gates, and conventions.
- [Changelog](CHANGELOG.md).
- Author: Steve Si-young Song <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev).
