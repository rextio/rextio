# Host source-AOT and native executables

Status: **Unreleased Release Train C**, experimental. The latest published
Rextio release remains **0.1.4** with tooling contract **2.2.0**. The Train C
branch emits the additive, unreleased tooling contract **2.3.0**; none of the
surfaces on this page should be treated as already available from PyPI.

Train C introduces a fail-closed planning layer for host source, output
artifacts, and native executable entry graphs. It also connects one deliberately
small module-initialization slice to a generated Rust executable. This is an
architecture increment, not whole-module or whole-project Python-to-Rust
conversion.

## Planning contracts

The new records are immutable and serialize deterministically:

| Record | Purpose |
| --- | --- |
| `SourceModule` | Identifies one source snapshot by module name, project-relative path, SHA-256, origin/provenance, and source-ordered import records. |
| `SourceModuleGraph` | Records local import edges, external import references, strongly connected components, and cycles without importing project modules. |
| `ModuleInitIR` | Describes exact source-order module-initialization segments, bindings, exports, deletions, and fallback barriers. It is descriptive by default. |
| `HostSourcePlan` | Couples one source graph to the corresponding `ModuleInitIR` snapshots. A module-set, path, hash, or availability mismatch makes the whole plan unavailable. |
| `ArtifactProfile` | Resolves one requested output kind, target triple, packaging backend, fallback, ABI/runtime/device requirements, and provenance. |
| `NativeClosureReport` | Records the Rust executable entry graph, fallback edges, blockers, resolved profile, and any explicitly authorized `module_initializers`. |

Paths and provenance source references in these records must be
project-relative. Source and module-initialization records carry SHA-256
identities so a changed file cannot reuse stale planning authority.

`HostSourcePlan` always serializes `execution_authority: "descriptive-only"`.
The plan explains source order; it does not by itself authorize code generation
or execution. The separate executable closure gate selects the only initializer
slice that may run.

## Artifact profile authority

`rextio capabilities` declares the available artifact vocabulary without
probing the host or pretending that every artifact was requested. Resolved
profiles appear only during `generate` or `build`, after source analysis.

The canonical authority is `BuildPlan.artifact_profiles`; `generate.json` and
`build.json` also mirror the same array at the top level for consumers. Train C
defines three initial artifact kinds:

- `host-extension`
- `host-executable`
- `rust-crate`

A profile is created only for an output the command actually needs. In
particular, a fallback-only generate/build does not resolve or advertise a host
target triple. If a requested native output has no supported host triple,
Rextio writes a structured `RXT060` failure instead of fabricating a profile. A
host executable profile must always carry one explicit fallback strategy.

## Explicit native-executable fallback

Configure the Rust executable entry graph independently of wheel fallback:

```toml
[executable]
backend = "rust"
fallback = "python-subprocess"
```

or on the command line:

```text
rextio build . \
  --entrypoint=myapp.cli:main \
  --executable-backend=rust \
  --executable-fallback=python-subprocess
```

The fallback enum is closed:

| Value | Entry-graph behavior |
| --- | --- |
| `error` | Requires a fully closed direct-native graph. Any reachable fallback edge fails before external build work. |
| `python-subprocess` | Allows supported immutable-scalar fallback calls through the external CPython dispatcher. This is the default. |
| `nuitka-sidecar` | Allows the same bounded fallback edge shape through a Nuitka-built sidecar. Nuitka is required at build time. |

`--hybrid-runtime=source|nuitka` and `[executable] hybrid_runtime` remain
compatibility aliases for `python-subprocess|nuitka-sidecar`. New configuration
and tooling should use the canonical fallback names.

An unavailable closure is different from an open closure. Source-plan,
initializer, or unsupported-call blockers make the closure **unavailable** and
fail before Cargo under every fallback strategy. An otherwise valid closure
with reachable scalar fallback edges is **open** and is accepted only by the
two external-fallback strategies above.

## Initial initializer-before-main slice

The existing Python-facing/PyO3 `native_top_level` feature supports a broader
experimental subset and publishes a returned update mapping into generated
Python wrappers. Train C's Rust-executable path is intentionally separate and
much narrower.

When `[policy] native_top_level = true` (or `--native-top-level`) and a Rust
executable is requested, the first executable slice accepts only all of the
following:

- exactly one analyzed project source module;
- the initializer and direct-native entrypoint in that same module;
- no module-load project, standard-library, or external imports;
- no source-graph cycle, fallback barrier, conditional binding, deletion, or
  unknown namespace effect;
- an available `ModuleInitIR` whose module name, relative path, SHA-256, and
  exact statement indexes still match the source bytes;
- plain, single-name assignments whose value is an exact scalar literal:
  `bool`, `int`, `float`, or `str`.

For example, this shape may enter the experimental ordering slice:

```python
mode = "batch"
attempts = 3

def main(argv: list[str]) -> int:
    return 0
```

Annotated assignment, augmented assignment, expression-valued assignment,
calls, control flow, imports, multiple targets, and every non-scalar literal
are rejected from this executable slice even when the broader Python-wrapper
top-level feature could represent them. `AnnAssign` is excluded because
module annotation evaluation and `__annotations__` publication are not yet
modeled.

The generated initializer is a direct-native `() -> None` function. Rust
`main` calls authorized initializers in planned order before it reads `argv`
and before it invokes the entrypoint. An initializer error is printed in the
normal `TypeName: message` form and exits with status 1.

Most importantly, initializer values are currently locals whose results are
discarded. They are **not published as Rust globals**, are not exported to
Python, and cannot be read by the native entrypoint or any accepted native
function. A detected read blocks the executable before Cargo. The slice proves
snapshot validation and initializer-before-main ordering; it does not yet
model Python module global state.

## Tooling-contract 2.3 reports

The unreleased additive contract exposes:

- top-level `host_source_plan` in `rextio check --format json` and
  `.rextio/reports/check.json`;
- `plan.host_source_plan` and resolved `plan.artifact_profiles` in
  `generate.json` / `build.json`, with `artifact_profiles` mirrored at the
  report top level;
- `executable_build.closure.module_initializers` for a requested Rust
  executable;
- declarative `artifact_contract` and `device_provider_contract` objects in
  `rextio capabilities --format json`.

See the [machine-readable tooling contract](specs/tooling-contract.md) for the
exact additive shape. Contract-major 2 consumers must ignore unknown fields;
Train C does not change diagnostic positions, route, native-status, rejection,
or promotion-assessment semantics.

## Device-provider boundary and CUDA Driver API inventory

Train C also adds draft records that keep domain lowering plugins separate from
future hardware/runtime providers. There is no discovery, provider selection,
build/link hook, runtime dispatch, or CUDA provider in this train. See the
[device-provider API draft](specs/device-provider.md).

The no-dependency Rust probe inventories a bounded set of NVIDIA Driver API
symbols and device facts on Windows x64 and Linux x86_64/aarch64. It never
creates a context, manages memory, launches a kernel, or links generated code.
Every result has `support_claim: false`, including a report that successfully
enumerates a GPU. See
[CUDA Driver API inventory validation](testing/cuda-driver-validation.md).

## Deferred work

Train C does not yet provide:

- multiple-module initializer execution or Python import-order emulation;
- Rust-global publication or native reads of initialized module values;
- arbitrary top-level statements, calls, annotations, or side effects in a
  Rust executable;
- recursive source-native promotion of installed pure-Python packages;
- license-lock, SBOM, and provenance gates for vendored dependency source;
- device-provider discovery, privileged build/link contributions, CUDA
  execution, or CUDA certification;
- WASM artifact profiles or packaging.

Those require separate, reviewable authority and compatibility gates. An
unsupported case must remain ordinary Python fallback where that preserves
semantics, or fail before external build work when a native executable cannot
preserve the requested module/entry graph.
