# Rextio

[한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**Compiles eligible typed Python functions to Rust and keeps everything
else on the Python fallback.**

Rextio **0.1.7** is an alpha-stage local build tool for Python projects,
published to PyPI on 2026-07-27 with plugin API **1.7**, tooling contract
**2.28.0**, superseding 0.1.6. It finds
typed Python functions that can be safely lowered to Rust, compiles them ahead
of time with PyO3, and keeps everything else running through generated Python
fallback code - same imports, same behavior.

**0.1.7:** optional plugin function-scope RAII guards (API 1.7 /
contract 2.28.0) for used plugins on accepted generated native functions.

**0.1.6 Release Train E foundation:** this published release adds bounded
plugin comparison expressions, Device Provider API 1 selection/preflight/build
wiring, and fail-closed static device-domain lowering authorization. An
accelerator-bearing plugin type contributes exact device/runtime requirements,
and an API-1.6 lowerer receives only a redacted authorization after one
explicitly selected provider has matched and preflighted that profile. Core
itself does not add Torch or TensorFlow CUDA lowering, certify accelerator
execution, or make a CUDA support claim.

**0.1.5 Release Train C:** this published release adds experimental host source/
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
or observe `dlopen`. C6.10 adds a separate narrow replay receipt for nonempty,
project-owned, plugin-free PyO3 function closures. It rereads source securely,
rederives AST identities and UTF-8 ranges, relowers the complete accepted set,
and requires byte-identical full `src/lib.rs` regeneration. C6.11 adds a
separate, narrower project-owner policy receipt for the exact raw
license metadata of every reachable Cargo registry component. It binds a fixed
project-root lock and the full C6.7 inventory, but does not authenticate the
owner, validate SPDX or license files, provide legal approval, or authorize
distribution. C6.12 adds an independent owner-declaration receipt only when a
valid C6.10 replay is present. The strict project-root
`rextio.source-license.lock.json` binds that exact C6.10 receipt, its complete
scoped project-source set, generated Rust `src/lib.rs`, and separate declared
licenses for the source and generated output. It does not verify identity,
SPDX, license/NOTICE files, obligations, compatibility, ownership,
derivative-work rights, legal approval, signing, global policy, or distribution
authority. C6.13 adds an optional, bounded analysis-input verification receipt
for every C6.10 source's sibling `.pyi`: present stubs bind logical path, byte
SHA-256, size, and deterministic supported-signature projection/version to the
exact replay and source set; absent records remain metadata only. Present stubs
are `project-python-stub` materials, while raw bytes, source text, absolute
roots, and exception text are never serialized. Secure immutable snapshots are
evidence-eligible; compatibility snapshots are analyzer-only and
evidence-ineligible. C6.14 adds a compact, thirteen-class policy-coverage
inventory over only the exact components already observed by C6.2-C6.13.
Identity strength, scoped license-owner receipts, and transformation/input
provenance are reported separately; all global coverage claims remain false.
C6.15 optionally binds `rextio.artifact-policy.lock.json` to the semantic
SHA-256 and exact ordered rows of that C6.14 partition. Its closed dispositions
cannot weaken an existing C6.10-C6.13 receipt; the lock is one provenance
material only, and every global policy/provenance/signing/authority claim stays
false. Contracts **2.21.0** through **2.24.0** add a separate strict, signed
Full-C6/C5.2 Alpha rather than promoting those preview records. It is frozen to
CPython + PyO3 + Cargo on macOS arm64 or Linux x86_64, exactly one depth-1
`py3-none-any` dependency, and direct typed scalar leaf calls. The original
dependency remains an exact `Requires-Dist` runtime dependency and generated
code verifies its installed identity/version/`RECORD` membership and exact
source bytes without importing or introspecting the external module or callable.
The Rextio host install must be non-editable and cache-free: install it with
`pip --no-compile`, run every strict lifecycle process with
`PYTHONDONTWRITEBYTECODE=1` (or `python -B`), and retain no `__pycache__` or
`.pyc` entry among the `rextio/` RECORD members or in the physical `rextio/`
tree. The package tree is limited to 256 MiB by both the pre-walk aggregate of
declared `rextio/` RECORD-member sizes and the independently checked actual
`stat`/read aggregate. This is an
evidence-integrity gate for an owner-controlled process, not hostile secure boot.
Contract 2.23.0 makes the non-authorizing bootstrap an exact public technical
template: combined C6.14+C5.2 rows, transformations, and internal/external
license observations. The owner supplies a separate explicit completion and
uses `rextio policy finalize` to create the canonical v2 manifest before the
signing-request and detached-signature publication stages. Rextio neither
invents owner decisions nor accepts, creates, or retains private signing keys.
Contract 2.24.0 adds a public, non-authorizing support-lock bootstrap and binds
the fixed host support closure plus the production sandbox to path-free
executor, SBOM, and SLSA receipts. Linux uses `bwrap`, sealed seccomp, an
isolated support-locked CPython launcher, Landlock, and Cargo; macOS uses
`sandbox-exec` with exact Xcode/SDK and sealed-system-volume anchors and removes
inherited executable mappings below mutable/data-volume roots. Only an explicitly
bound `read-execute` path or bound read-write directory capability regains
executable mapping/process execution; ambient paths remain denied. The receipt's
`sandbox_profile_sha256` is an engine-specific, path-tokenized semantic digest
that is equal across the two builds and equivalent lifecycle runs; the raw
rendered profile contains process-local paths and is neither public nor signed.
This is a bounded Alpha integrity contract, not general hermetic execution.
Plugins, executables, rust-crate output,
top-level AOT, embedding, Windows, recursive promotion, and general
external-source translation remain excluded. These surfaces ship in package
**0.1.5** with tooling contract **2.24.0**, plugin API **1.4**, and readiness
policy **11**. They remain Experimental/Alpha and do not claim broad Full C6,
general package AOT, general hermeticity, CUDA support, or heavy host-lifecycle
CI certification. See
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
| `rextio policy bootstrap-support-lock` | Creates or exactly reuses the canonical, non-authorizing Full-C6 host support lock and returns the two config values to pin (0.1.5 Experimental). |
| `rextio policy finalize` | Combines one exact Full-C6 bootstrap v2 and explicit owner completion into an unsigned, non-authorizing policy manifest v2 (0.1.5 Experimental). |
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
`artifact_distribution_authorization`. This C6.5-C6.15 policy-version-11 record is derived from the
final `artifact_evidence` record after required-mode revalidation/transaction
handling. It always reports `status: "blocked"`,
`authority: "readiness-assessment-only"`, and false values for `complete`,
`signed`, and `distribution_authorized`. Preview-ready evidence can satisfy
fourteen bounded observation checks after closed-model reconstruction and exact
cross-binding. The ninth check means the in-process C6.10 collector already
replayed one narrowly supported source/AST/IR/codegen closure; the later report
does not itself reopen source or generated artifacts. The tenth check means an
exact C6.11 owner lock was structurally bound to all registry-license metadata;
it is still not the blocked global license-policy check. The eleventh means a
separate C6.12 owner lock was bound to the exact C6.10 project-source set and
generated Rust output; it proves no ownership or output rights. The twelfth
check verifies the exact C6.10 sibling-stub set; present stubs become
`project-python-stub` materials and compatibility snapshots are not
evidence-eligible. The thirteenth binds C6.14's compact disjoint partition to
the exact surviving C6.9-C6.13 receipts without claiming global policy or
provenance completeness. The fourteenth binds C6.15's exact owner lock and
closed class dispositions to C6.14; it authenticates no owner and grants no
distribution authority. License
policy, runtime path/transitive closure, runtime dynamic loading, complete build
inputs, complete source-transformation provenance, builder identity, reproducibility,
signatures, and complete SBOM composition remain selected current-scope fixed
blockers. Unavailable evidence reports only `evidence-unavailable` plus its
existing sanitized reason. If a preview evidence model cannot pass the stricter
readiness validation, every check becomes `not-evaluated` and the only blocker
is `readiness-assessment-unavailable`; this cannot fail an otherwise successful
best-effort build or satisfied C6.3 required gate. No configuration flag can
turn this assessment into authorization. The strict Full-C6 Alpha described
below creates a separate, deeply typed authority chain; it never upgrades or
reinterprets this preview-readiness record.

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

The C6.10 `source_transformation_verification` is a sibling observation, not a
replacement for C6.6. Its scope is exactly
`project-functions-pyo3-plugin-free-v1`: project-owned module-level direct
native functions, CPython/PyO3 host-extension wheel, no plugins, embedding,
native top-level, runtime shim, delegated fallback, or Python boundary call.
It binds the canonical C6.6 inventory, exact project-source set, canonical
ModuleIR, complete accepted qualnames, and captured/regenerated Rust digest and
size. Any scope or replay mismatch omits only this receipt and reports
`scoped-source-transformation-verified: unavailable`; C6.6 and C6.3 remain
independent. `complete_for_scope: true` never changes
`global_provenance_complete: false`, the blocked
`source-transformation-provenance-complete` check, or distribution authority.

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
newer C6.15, C6.14, C6.13, C6.12, C6.11, C6.10, C6.9, and C6.8 observations are omitted, C6.7 is omitted next so C6.6 and all earlier evidence/gate results are preserved whenever
possible. `component-license-policy-complete` remains blocked: this is not SPDX
validation, a license allow/deny lock, legal approval, or distribution authority.

The C6.11 `component_license_policy_verification` is an optional scoped sibling
of that inventory. A fixed project-root `rextio.cargo-license.lock.json` must
repeat every registry record verbatim in canonical order, bind the full C6.7
digest, declare `allow` for the exact local-build/package/redistribution scopes,
use the fixed acknowledgement, and identify either a human owner or organization
owner. Rextio securely hashes the exact lock bytes, rejects links, races,
duplicate/nonfinite/deep JSON and missing or unknown registry-license sentinels,
then recollects the receipt before final evidence construction. The lock is a
provenance material only while the receipt survives; it is not a C6.2 input or
SBOM component. Missing, changed, or invalid policy data makes
`scoped-component-license-policy-verified` unavailable with the fixed
`scoped-component-license-policy-verification-unavailable` blocker without
changing the build or C6.3 gate. Claimed owner identity is not authenticated,
and license files, notices, obligations, compatibility, legal approval,
signatures, the global license policy, and distribution authority remain open.

The C6.8 `native_runtime_path_resolution` remains incomplete and
observation-only. Records are in direct-dependency `bom_ref` order and bind the
exact dependency name/origin plus one closed result/mechanism. Packaged records
also bind one unique canonical `WheelEntryRef` name, SHA-256, and size; missing,
ambiguous, symlinked, escaping, unsupported, or changed candidates omit only
C6.8. The readiness report then marks
`direct-native-path-resolution-bound` unavailable and adds
`native-runtime-path-resolution-inventory-unavailable`; the ordinary build and
C6.3 gate are unchanged. A present malformed or format-crossed record fails the
readiness reconstruction closed. C6.15 is omitted first, then C6.14, C6.13, C6.12, C6.11, C6.10, C6.9, C6.8,
C6.7, and C6.6 at the provenance ceiling. Actual loader precedence/environment, complete
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

Rust is the only implemented native target in 0.1.7.

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

Core 0.1.7 adds plugin API **1.7** / tooling contract **2.28.0** function-scope guards. Core 0.1.6 added plugin API **1.6** / tooling contract **2.27.0** static
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

The 0.1.5 Experimental C5.1 surface has a deliberately non-building preview for one
exact installed pure-Python distribution:

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
locks → `external-source-c6-blocked`. In the historical preview path, a
verified lock still reports `external-source-c5-not-implemented`; only the
strict signed profile below may attempt to create same-transaction C5.2 build
authority, subject to every later hard gate.

### Bounded Full C6 + C5.2 Alpha (0.1.5 Experimental)

`artifact_distribution_policy = "strict-evidence"` selects the separate
strict evidence distribution profile. It fails closed, and its configuration
is deliberately redundant and exact:

```toml
[build]
fallback_backend = "cpython"
artifact_evidence_policy = "required"
artifact_distribution_policy = "strict-evidence"
artifact_source_lock_manifest = "locks/rextio.source-lock.v2.json"
artifact_source_lock_signature = "locks/rextio.source-lock.v2.signature.json"
artifact_policy_manifest = "locks/rextio.full-c6-policy.json"
artifact_policy_manifest_sha256 = "<64 lowercase hex characters>"
artifact_cargo_lock = "locks/Cargo.lock"
artifact_cargo_lock_sha256 = "<64 lowercase hex characters>"
artifact_cargo_vendor = "vendor/cargo"
artifact_cargo_vendor_sha256 = "<64 lowercase hex characters>"
artifact_toolchain_support_lock = "authority/rextio.toolchain-support.lock.json"
artifact_toolchain_support_lock_sha256 = "<64 lowercase hex characters>"
artifact_trusted_public_key = "locks/owner.ed25519.pub"
artifact_trusted_public_key_sha256 = "<64 lowercase hex characters>"
artifact_signing_request_output = "state/rextio.full-c6-final-authorization-request.json"
artifact_repeat_builds = 2

[rust]
binding = "pyo3"
build_tool = "cargo"
importable = false

[imports]
default_external_policy = "fallback"

[imports.packages.small_math_pkg]
policy = "try-native"
max_depth = 1
distribution = "small-math-pkg"
version = "1.0.0"
source_archive = "locks/small_math_pkg-1.0.0-py3-none-any.whl"
source_archive_sha256 = "<64 lowercase hex characters>"
```

Before the first lifecycle build, create an owner-private output directory with
mode `0700`, then run the support-lock bootstrap from the same pinned host:

```text
rextio policy bootstrap-support-lock \
  --project-root . \
  --output authority/rextio.toolchain-support.lock.json \
  --format json
```

The output is host-absolute-path-free, retains only the project-relative config
path, and returns the exact two values to copy into `[build]`:
`artifact_toolchain_support_lock` and
`artifact_toolchain_support_lock_sha256`. The command creates a canonical
single-link regular file with mode `0600`, or exactly reuses an identical one;
the parent must already be owner-owned mode `0700`. The result also reports the
target, fixed manifest/root roles, raw lock SHA-256, and Merkle SHA-256, while
`authorizes_build` and `authorizes_distribution` remain false. Its output may
not be the same path as, an ancestor of, or a descendant of any configured
lifecycle artifact, including every
`imports.packages.*.source_archive` entry. This lexical NFC/case-folded check
runs before output creation even when the other path does not yet exist.

For the first lifecycle stage, configure the owner-policy path but omit
`artifact_policy_manifest_sha256`; the pinned value shown above is added only
after the owner completes and finalizes the bootstrap request. The profile
additionally requires no enabled plugin, no executable entrypoint, no embedding, and
`native_top_level = false`. Its hard host gate requires **CPython 3.11 exactly**
on `aarch64-apple-darwin` or `x86_64-unknown-linux-gnu`, a non-editable Rextio
wheel install whose complete, cache-free `rextio/` package matches its installed
`RECORD`, and rustup-selected Cargo/rustc satisfying the configured
CPython/Cargo/rust-toolchain pins. Install that wheel with
`python -m pip install --no-compile ...`; every
strict `rextio build` process must start with `PYTHONDONTWRITEBYTECODE=1` (or
`python -B`). Any `rextio/` RECORD row or physical package path containing
`__pycache__`/`.pyc`, or any unrecorded package directory/member, fails closed.
Before walking, the declared `rextio/` RECORD member-size aggregate must fit
the 256 MiB installed-input budget; actual member `stat` sizes and bounded reads are independently
aggregated against the same limit during the walk. This closes bytecode and
oversized inputs outside the evidence inventory but is not a secure-boot claim.
The bounded Alpha does not defend against hostile same-UID concurrent
replacement, a compromised kernel or operating system, or provide complete
time, randomness, scheduling, or CPU virtualization. Both
native builds use the exact pinned lock and vendor tree with
`cargo build --release --locked --offline --frozen`.

The separate support lock freezes the fixed host closure through a
process-sealed plan, canonical raw lock digest, and tree Merkle digest. Linux
x86_64 runs Cargo through `bwrap`, a sealed seccomp filter, the support-locked
isolated CPython launcher, and Landlock, with only the fixed GNU/Python/Rust
support closure mapped. macOS arm64 runs Cargo under `sandbox-exec`, bound to
the exact full Xcode developer root, SDK/toolchain resources, required sandbox
profiles, and captured sealed-system-volume platform anchor. The macOS base
profile also denies inherited `file-map-executable` access under
`/private/var`, `/private/etc`, `/Library`, `/dev`, `/cores`, and
`/System/Volumes/Preboot`; sealed-system executables remain admitted, and only
explicit bound `read-execute` paths or bound read-write directories regain
executable mapping/process execution.

Each strict `rextio build` invocation performs three full support-tree
verifications: host-input collection checks the configured lock once, then the
executor rewalks at entry and immediately before minting executor authority.
Every owner-policy lifecycle stage repeats that sequence independently.
External, production, internal, and per-build boundaries perform no additional
full walk; they revalidate the process seal, critical leaves, and exact
plan/raw/Merkle digest identity. Both invocation receipts carry the closed
sandbox-engine identifier, path-free plan/profile digests, and the Linux
seccomp digest. The profile field is the
path-tokenized, engine-specific semantic contract, must match for both builds
and equivalent lifecycle runs, and never exposes or signs the raw rendered
profile with its quarantine/PyO3 paths. Strict SBOM/SLSA materials bind the
support plan, raw lock, and Merkle identities.

One local macOS arm64 run observed roughly **104,645 members**, **2.67 GB**, and
about **45 seconds** for each full support verification. These are
machine-specific observations, not bounds, performance promises, or CI
guarantees. The real installed-wheel lifecycle is deliberately a manual host
validation rather than automatic CI certification. On a supported host with
CPython 3.11 and Cargo 1.93.1, run:

```bash
python scripts/validate-full-c6-host.py
```

Use `python scripts/validate-full-c6-host.py --preflight-only` to check the
target, Cargo, and required Xcode/sandbox-exec or bubblewrap setup without
building. The complete command requires a clean Git worktree and index, records
the exact `HEAD` commit, exports only that commit's tracked files into a fresh
temporary source tree, builds the wheel there, installs it non-editably into a
clean environment, and delegates to the existing Full C6 real-Cargo E2E harness
outside the checkout. Existing local `build/` and `dist/` contents are neither
used nor removed. A successful run is evidence for that exact host and recorded
commit; it is not a cross-platform CI guarantee or a general hermetic-build
claim.

The executor keeps `PATH`
scrubbed to the selected Cargo directory and binds the already verified linker
by absolute path through exactly the active target's
`CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER` or
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`. A caller override, missing or
different value, same-name shadow, or simultaneous inactive-target binding
fails closed. Cargo receives those exact live absolute paths. Only the semantic
invocation receipt maps executor-owned `HOME`, `CARGO_HOME`, and
`CARGO_TARGET_DIR` below `/rextio/build` and maps the project/build sides of its
two remap flags to `/rextio/project` and `/rextio/build`; caller-controlled
environment values remain byte-bound. On macOS only, executor-owned flags set
the exact Mach-O self ID
to `@rpath/lib_rextio_native.dylib` while retaining the linker's default,
content-derived deterministic `LC_UUID` required by dyld; Linux flags are
unchanged. Runtime inspection consumes that identity only when `otool -D`
independently verifies the exact first self-ID row. A dedicated real two-build
experiment produced byte-identical unsigned wheels with identical UUIDs,
ad-hoc signatures, and no quarantine-path bytes, and its native extension
loaded successfully. The later final local real-E2E at `f9eb5e6` certified the
complete three-stage installed-wheel lifecycle on macOS arm64 with CPython
3.11.15 and Cargo 1.93.1, including publication/authorization, fresh install,
runtime guard, and a cache-free tree. The subsequent installed-input byte-budget
  hardening is unit-tested. Evidence for the current `HEAD` on macOS arm64 and
  Linux x86_64 now requires the manual host-validation command above and is not
  CI-certified.
For the direct `/usr/lib/libSystem.B.dylib` dependency, the macOS dyld
shared-cache policy also recognizes exactly one additional singleton provider:
`/usr/lib/system/libcommonCrypto.dylib`. This is a bounded one-hop relation,
not permission for arbitrary `/usr/lib/system/*` descendants. The exact
provider must already be observed in the final platform-image snapshot, scoped
and global symbol lookup must agree on one address, and `dladdr` must map that
address to the same path. A missing provider, a different address/path, or any
other singleton fails closed without weakening the OS-build or sealed runtime
authority bindings. Provider probes must leave the snapshot unchanged; every
later native-runtime authority validation recollects it, and a late loaded image
taints the process instead of minting or retaining authority.
SourceLock v2 securely
reopens one exact source wheel, connects only direct final import calls whose
positional arguments and return are statically supported scalars, lowers only
the reached leaf helpers as private Rust functions, and forces a fresh project
analysis. Its installed and archive `RECORD` files are separate pinned
authorities because installers may rewrite `RECORD`; all shared source,
METADATA, WHEEL, and license identities still have to match. The output wheel
preserves `Requires-Dist: <distribution>==<version>` and embeds a runtime guard
for installed distribution identity/version, `RECORD` membership, located
paths, and exact reached-module bytes. It opens `/` and walks every absolute
distribution-root and source-member component descriptor-relatively with
`openat`/`O_NOFOLLOW`. The final source open also uses `O_NONBLOCK`, then
requires a single-link regular file, so symlinks, hard links, FIFOs/special
files, size/hash changes, and read-time replacement fail closed without a
blocking open. The
guard never imports or introspects the external dependency module or callable;
signed source analysis already binds the callable identity.

The final wheel also carries the exact external wheel's PEP 639 license payloads.
Each is declared as
`License-File: external/<normalized-distribution>/<version>/<relative-path>` and
stored below the output wheel's `.dist-info/licenses/` directory with exact
METADATA, `RECORD`, SourceLock-verification, mapping, and payload-byte bindings.
The complete output license set is capped at **128** files and 64 MiB total;
the frozen real PyO3 graph currently uses 108 (project 1 + Cargo 106 + external
1). A 129th file, noncanonical path/order, or alias still fails closed. This is
license-material inclusion, not source vendoring or an independent copy of the
dependency. Likewise, the pinned Cargo lock/vendor tree establishes
owner-selected input integrity; it does not authenticate a registry, publisher,
or upstream origin.

For compatibility with real locked Cargo trees, the strict license collector
recognizes exactly one historical Cargo metadata alias: an exact
`license = "MIT/Apache-2.0"` is observed canonically as
`MIT OR Apache-2.0`. Rextio still binds the untouched `Cargo.toml` bytes and
digest as evidence. Leading/trailing whitespace, reversed operands, and every
other slash expression remain unsupported and fail closed.

Strict analysis does not honor a project `.rextioignore`. It seals the exact
built-in-filtered, bounded Python file and directory namespace across initial
analysis, C5.2 reanalysis, and transformation replay, and rejects custom ignore
files, nonignored symlink/special entries, or namespace mutation. If this scope
cannot be established, `rextio build` reports a sanitized `RXT060` on stderr and
does not create project reports or follow an untrusted `.rextio` path.

The CLI lifecycle has exactly three stages:

1. With the owner-policy digest omitted, `rextio build` writes only canonical
   `rextio.full-c6-policy.bootstrap.json` schema/domain v2 as its lifecycle
   artifact (the normal strict `check.json` and `build.json` reports are also
   written). It embeds the exact
   non-authorizing technical policy template: the combined C6.14+C5.2 partition,
   every row and transformation, exact internal project/Cargo and external-wheel
   license observations, completion requirements, and aggregate digests. It
   contains no source/license payload bytes, private key, signature, legal
   approval, or distribution authority.
2. The owner writes a separate canonical completion that explicitly allows each
   license-applicable observed row and accepts the exact transformation set, then
   finalizes it offline:

   ```text
   rextio policy finalize \
     --bootstrap state/rextio.full-c6-policy.bootstrap.json \
     --completion locks/rextio.full-c6-policy.completion.json \
     --output locks/rextio.full-c6-policy.json
   ```

   The command creates or exactly reuses canonical owner-policy manifest v2; it
   does not sign or authorize it. After the owner pins that output SHA-256, the
   `signing-required` `rextio build` writes
   `rextio.full-c6-final-authorization-request.json` as its only lifecycle
   artifact, alongside the strict reports; this is still non-authorizing.
3. The owner signs the domain-separated message consisting of the ASCII prefix
   `REXTIO-FULL-C6-ED25519-V1` plus one NUL byte, followed by the exact canonical
   request-file bytes. The configured public-key file is exactly 32 raw Ed25519
   bytes. The raw 64-byte signature is encoded as canonical Base64 in the closed
   seven-field canonical detached envelope shown below; the envelope is bounded
   to 16 KiB. A PEM key, raw signature file, pretty-printed envelope, missing
   prefix, or signature over only the request bytes fails closed.
   Configure that envelope as `artifact_final_signature` and rerun. Only then
   may Rextio revalidate the complete chain and publish the create-if-absent
   atomic seven-file bundle under the retained project `dist`: wheel,
   CycloneDX, SLSA provenance, final evidence, detached-signature envelope,
   sealed authorization, and `rextio.full-c6-manifest.json`.
   All temporary host-output and private-quarantine cleanup finishes before the
   final no-replace directory rename; that successful rename is the publication
   commit point.

The detached envelope file is compact canonical UTF-8 JSON with sorted keys and
no trailing newline (placeholders below stand for lowercase SHA-256 and Base64):

```json
{"algorithm":"ed25519","domain":"rextio.full-c6-detached-signature.v1","kind":"full-c6-detached-signature","manifest_sha256":"<request-bytes-sha256>","public_key_sha256":"<raw-public-key-sha256>","schema_version":1,"signature":"<base64-raw-64-byte-signature>"}
```

The canonical authorization request is at most 64 KiB. Publication admits a
wheel, CycloneDX document, and SLSA document of at most 16 MiB each; final
evidence and authorization of at most 2 MiB each; and a detached envelope of at
most 16 KiB. The manifest is the seventh file and binds the six payload roles.
The state directory derived from `artifact_signing_request_output` must be
owner-owned mode `0700`; the CLI creates it that way when absent.

Each of the three `rextio build` lifecycle runs independently recollects the
current graph and performs exactly two actual isolated, offline, frozen Cargo
builds; it does not reuse an earlier build receipt. The resulting
`FullC6ProductionAuthority` is an immutable process-local evidence seal whose
public projection reports `executor_invocation_count: 2`; it cannot be copied,
serialized, or treated as signing/publication authority. Final manifest/policy
v2 lineage must match the freshly rederived bootstrap request and technical
template on the signing and publication runs.

Rextio does not invent owner decisions and never accepts, creates, or retains a
private signing key. Any input or staged-bundle byte change
detected before the final rename, path alias, unsafe file, platform/scope
mismatch, stale analysis, unexpected dependency, alternate publication
destination/name fails closed. An existing or concurrently created publication
target also fails closed unless it qualifies for the sole existing-target
success: an idempotent retry after a bundle was already committed. The target
must still be an owner-private mode-`0700` directory containing the exact
closed bundle expected by the current verified request. Every original bundle
source and the trusted public key must remain identical under safe recapture
between repeated descriptor/name-binding and member-byte validation passes. A
different, mutated, unsafe, or concurrently replaced target is
never accepted or overwritten. A later external mutation does not
retroactively invalidate the completed transaction receipt, but the changed
bytes no longer match that receipt or the publication manifest and must be
treated as invalid by any consumer.

This is a bounded **CLI Alpha**, not a general release workflow. `rextio build`
coordinates the frozen policy-bootstrap/signing/publication lifecycle but
never synthesizes owner policy or signing authority.
The strict profile excludes plugins, executable and
rust-crate artifacts, native top-level initialization, embedding, Windows,
non-CPython bindings, non-Cargo builders, multiple/recursive dependencies, and
non-leaf or dynamic external calls.

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
contract **2.24.0**, and readiness policy **11**. Its Train C surfaces remain
Experimental/Alpha under the bounded scope described above.
Core **0.1.6** was published on 2026-07-26 with plugin API **1.6**, tooling
contract **2.27.0**, and Device Provider API **1**. Core **0.1.7** was
published on 2026-07-27 with plugin API **1.7** and tooling contract
**2.28.0** (function-scope RAII guards). It retains the same
readiness policy and fail-closed Alpha boundaries.
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

Rextio 0.1.7 supports a deliberately small subset. This is the code
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

Rextio 0.1.5 ships the bounded Full-C6/C5.2 Alpha described above. Broader
external-package promotion remains deferred; the next
platform milestone is bounded WASM work after the host release gate is ready.

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
- [Host source-AOT and native executables](docs/source-aot-and-executables.md) — 0.1.5 Experimental Train C planning and initializer limits.
- [Device-provider API draft](docs/specs/device-provider.md) — non-operational hardware/runtime contract boundary.
- [CUDA Driver API inventory validation](docs/testing/cuda-driver-validation.md) — repository-only Windows+Linux bounded probe instructions; not installed by the PyPI package and not a CUDA support claim.
- [Security model](SECURITY.md) — trust boundary and how to report vulnerabilities.
- [Contributing](CONTRIBUTING.md) — setup, gates, and conventions.
- [Changelog](CHANGELOG.md).
- Author: Steve Si-young Song <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev).
