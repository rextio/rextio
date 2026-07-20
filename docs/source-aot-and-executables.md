# Host source-AOT and native executables

Status: **Unreleased Release Train C**, experimental. The latest published
Rextio release remains **0.1.4** with tooling contract **2.2.0**. The Train C
branch emits the additive, unreleased tooling contract **2.19.0**; none of the
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

## C5.1 external distribution inventory — preview only

Train C can inventory one exact, imported pure-Python distribution at depth 1
when `rextio.toml` contains all four authority-sensitive fields:

```toml
[imports.packages.small_math_pkg]
policy = "try-native"
max_depth = 1
distribution = "small-math-pkg"
version = "1.0.0"
```

The resolver uses `importlib.metadata` and reads installed metadata/source bytes
without importing or executing package code. It requires exact name/version,
one well-formed WHEEL 1.0 record with a sole purelib `py3-none-any` tag, safe unique RECORD paths, matching SHA-256 and
size for metadata and selected source, containment under the installed root,
and no symlink in a selected path. It examines only direct UTF-8 `.py` modules
under the configured package; a selected module containing an import is
unavailable. Only one full declaration is accepted, and it cannot be activated
solely through a CLI/environment package-policy override.

The resulting `external_source_plan` is sanitized and carries
`execution_authority: "preview-only"`, `distributable: false`, and
`c6_gate: "required"` until C6.1 SourceLock verification succeeds. Its module paths are
stable distribution-relative references, never installation paths. Candidate
function names are lexical hints for fully scalar-annotated top-level functions;
C5.1 does not inspect body lowerability, connect project calls, generate Rust,
or copy external source into fallback output.

## C6.1 SourceLock authorization contract — bounded preview only

**Not full C6.** C6.1 verifies a project-owned
`rextio.external-source.lock.json` against exactly one available C5.1 plan.
Author the lock from `rextio check` output (`plan_snapshot`,
`plan_snapshot_sha256`, `source_files`, `metadata_files`). The lock must bind:

- exact package / distribution / version identity;
- verified path + SHA-256 + **byte size** for every source module and for
  RECORD, METADATA, WHEEL, and every METADATA `License-File` resolved under
  `<dist-info>/licenses/<value>` (PEP 639 / Metadata ≥ 2.4; no backslash
  normalization; no simultaneous License-Expression + License);
- domain-separated canonical `plan_snapshot_sha256` and shared
  `license_material_sha256` (both published in check JSON for lock authoring);
- custom `source_inventory` (`rextio-source-inventory-v1` — not a full
  SPDX/CycloneDX SBOM) with exact path/hash/size/**role** binding;
- provenance with `subject_snapshot_sha256`, installed-wheel metadata material,
  producer/attestor relationship (`organization-owner`→organization; other
  closed relationships require human), and exact ordered evidence
  (`installed-distribution-record`, `project-vcs-review`); project/VCS review
  is the trust boundary (no signature in this preview);
- closed license attestation: `reviewed_license` matching observed license,
  `reviewed_license_material_sha256`, `decision: "allow"`, exact
  `action_scopes`, and exact constant
  `acknowledgement: "REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1"`.
  Null/unknown/sentinel observed licenses never become preview-ready or verify.

Verification is fail-closed and offline: safe single-descriptor lock I/O,
duplicate JSON keys, NaN/Infinity, deep nesting, symlinks/FIFOs, stale
hashes/sizes, incomplete sections, and unavailable plans all reject. Rextio
validates structure and binding only; it does not auto-approve licenses or
give legal advice.

Any available or unavailable plan still blocks `rextio build` before configured
CPython/Nuitka/Cargo probes and artifact work. Missing/invalid authorization
uses status `external-source-c6-blocked`. A **verified** SourceLock uses the
distinct status `external-source-c5-not-implemented` because remaining C5.2
call-site linkage, body lowerability, Rust codegen, and packaging are not
implemented.

The plan and CLI include a strong warning: dependency source translation or
redistribution can create derivative-work obligations, GNU/copyleft terms need
particular care, and this inventory/authorization gate is not legal advice.

## C6.2-C6.13 host-extension evidence/readiness — bounded and blocked

For one ordinary native host-extension + CPython wheel, C6.2 emits incomplete
CycloneDX 1.6 and unsigned in-toto/SLSA provenance sidecars. C6.3 can make that
preview mandatory with `[build] artifact_evidence_policy = "required"`. C6.4
adds one sanitized inventory of the generated extension's **directly observed**
dynamic link entries:

- macOS Mach-O is inspected with bounded `otool -L` and, only for self-ID
  validation, bounded `otool -D`;
- Linux ELF is inspected with bounded `readelf -W -d`;
- every inspector child uses a reviewed absolute system-tool path, no shell,
  no inherited parent environment, and only a minimal C locale;
- the contained installed extension is accepted only when its generated-Python
  relative identity, SHA-256, and byte size match exactly one wheel member;
- header and inspector reads use one private same-byte snapshot bound to both
  the installed original and wheel member, followed by original/snapshot
  identity and digest revalidation;
- the binary-header architecture is normalized and checked against the profile;
- dependencies are admitted as closed system names or bounded packaged-candidate
  forms and
  serialize only a bounded name, `origin` (`system | unresolved | wheel-candidate`), and stable
  path-free `bom_ref`;
- the binary and wheel are revalidated before the preview becomes
  `preview-ready`; and
- reports and sidecars contain only bounded logical names and fixed sanitized
  failure reasons, never inspector paths, raw output, absolute private paths,
  source bytes, credentials, or environment secrets.

The C6.4 inventory records only the extension-to-direct-dependency observations.
By itself it does not resolve install/search paths, follow transitive dependencies,
observe runtime `dlopen`, or turn dependency names into verified build inputs.
Ambiguous or unsafe linkage, a missing/failing/timed-out inspector, excessive
output, an unsupported platform, architecture/format mismatch, an unexpected
dependency, and native-to-wheel identity/hash/size mismatch make evidence
`unavailable`. Mach-O admits `/usr/lib` and `/System/Library` system roots plus
bounded `@loader_path`/`@rpath` candidate forms; ELF admits non-system safe
`NEEDED` names only when an explicit bounded ORIGIN search path makes them a
wheel candidate. C6.8 must resolve every such candidate exactly or omit its
own observation.

The first `otool -L` row is not generically discarded as a self-reference. It
may be excluded only for a private Cargo self-ID when the snapshot header is
`MH_DYLIB` and the exact same ID is independently returned by bounded
`otool -D`. Without both facts, the row stays in the dependency set and must
pass the ordinary closed allowlist.

In the default `best-effort` mode, that unavailability does not change ordinary
build success. In `required` mode, it produces `RXT060` and the existing output
transaction rolls back this run's exact wheel and sidecars while preserving
pre-existing and unrelated files. Publication and rollback operate through a
pinned output-parent identity and exact content receipts. The required wheel is
built in a private transaction directory and linked into the public path only
if that path is absent; it is never claimed merely because it was observed.
Rollback atomically quarantines a candidate before receipt verification and
deletes only an exact owned match. A mismatch restores or retains pre-existing
or concurrently replaced content, fails publication closed, and reports
required rollback as incomplete rather than successful cleanup. Even a
successful inventory keeps
`composition: incomplete`, `signed: false`, and
`distribution_authorized: false`.

C6.5 serializes a separate `artifact_distribution_authorization` readiness
assessment for this same evidence path. C6.12 advances that assessment to
policy version 8 and revalidates eleven bounded observations; C6.13 advances
it to policy version 9 and adds the twelfth observation, both through
closed-model reconstruction and exact evidence cross-binding before marking
them satisfied.
The ninth observation reflects an earlier in-process C6.10 source/AST/IR/codegen
replay; the later report does not itself reopen artifacts, re-inspect bytes, or
repeat that replay. The tenth reflects C6.11's exact scoped Cargo owner-lock
binding. The eleventh reflects C6.12's separate owner declarations for the
exact C6.10 project-source set and generated Rust output. Neither scoped
observation is a completed global license policy. The
assessment remains unconditionally `blocked`, incomplete, unsigned, and
non-authorizing. Its closed blockers name selected current-scope missing license
policy, resolved/transitive runtime closure, dynamic-loading observation,
complete build-input closure, source-transformation provenance, builder
identity, reproducibility, signature, and complete SBOM composition. Unavailable
evidence produces only `evidence-unavailable` plus the existing fixed reason.
A structurally invalid preview produces only
`readiness-assessment-unavailable` with every check `not-evaluated`; C6.5
through C6.13 change neither best-effort build success nor the C6.3 required preview
gate.

C6.6 also places a deterministic observation-only
`source_transformation_inventory` under `artifact_evidence` and in the unsigned
provenance metadata. Each accepted project-owned native function binds one
project `SourceModule` path/SHA-256, module and qualname, reliable half-open
source range, SHA-256 of the analyzer's attribute-free semantic AST identity,
the exact generated Rust `src/lib.rs` evidence input path/hash/size, the closed
Rust/PyO3 generator/backend id, and sorted unique plugin ids. It never serializes
source bytes, the AST dump itself, absolute paths, exception text, credentials,
or unbounded output. The collector first requires exact ordered value-level
coverage between `NativePlan.accepted_functions` and the analyzer accepted list
used by code generation. Records, scanned plugin references, unique plugin ids,
and deterministic inventory characters are independently capped.

Missing, unsupported, over-budget, or sidecar-ceiling-exceeding inventory does
not change wheel evidence publication or the independent C6.3 gate. Provenance
is rebuilt with only that observation omitted when necessary, and the new
observation becomes `unavailable` with the
fixed `source-transformation-inventory-unavailable` blocker. Low-level malformed
or noncanonical inventory, or one whose exact source/generated evidence binding
is broken, remains the all-`not-evaluated`
`readiness-assessment-unavailable` shape. In both cases the overall assessment
stays blocked, and even a valid inventory leaves
`source-transformation-provenance-complete` blocked. A structurally valid
changed qualname/range/semantic hash is not independently re-derived by the
readiness evaluator and remains only an unsigned observation. Top-level initialization,
external packages, runtime-bearing plugins, executables, Rust crates, Nuitka,
WASM, and Windows are not covered by this inventory.

C6.7 adds `component_license_inventory` to the same evidence and unsigned
provenance. It exactly covers every reachable Cargo package, including the path
root, in canonical `bom_ref` order. Each record carries only package identity,
kind, and the raw bounded Cargo metadata license string (`declared-unvalidated`)
or null (`missing`). Whitespace-only values are missing; every other value is
preserved verbatim within fixed bounds. Control characters are rejected. No
SPDX parsing, normalization, compatibility/obligation analysis, license-file
reading, legal approval, owner policy, SourceLock change, or distribution
authorization is implied.

Missing C6.7 inventory makes only `component-license-inventory-bound`
unavailable with `component-license-inventory-unavailable`. Malformed,
noncanonical, stale, extra, omitted, or otherwise non-exact Cargo bindings use
the existing all-`not-evaluated` readiness-unavailable shape. Provenance records
whether the observation is present. Under current C6.13, a crossed sidecar
ceiling omits C6.13 first, then C6.12, C6.11, C6.10, C6.9, C6.8, and C6.7,
preserving C6.6 and earlier evidence/gate results whenever possible. The separate
`component-license-policy-complete` check remains blocked.

C6.8 adds `native_runtime_path_resolution` for exact one-hop static packaged
candidates. Its canonical subject wheel member and SHA-256 exactly bind the
C6.4 native runtime subject. Every C6.4 direct dependency appears exactly once
in canonical `dependency_bom_ref` order. macOS system install names become logical leaves;
contained `@loader_path` and `@rpath` names are accepted only when the usable
run paths are self `@loader_path` anchored. Linux allowlisted names become
logical leaves while other safe SONAMEs require a bounded `$ORIGIN` or
`${ORIGIN}` RUNPATH/RPATH candidate. Packaged results bind one unique regular,
non-symlink wheel member by logical name, SHA-256, and size through pinned
`O_NOFOLLOW` receipts. Fixed `otool -l` / `readelf -W -d` inspectors are never
used to execute or load the artifact, and ambient loader environment, cache,
`ldd`, `dlopen`, and `ldconfig` are never consulted.

Unsafe, unsupported, missing, ambiguous, changed, or over-bound candidates omit
C6.8 and its dependent C6.9 graph; the corresponding observation is unavailable with
`native-runtime-path-resolution-inventory-unavailable`. A malformed present
model fails the full readiness reconstruction closed. At the provenance
ceiling C6.14 is omitted first, then C6.13, C6.12, C6.11, C6.10, C6.9, C6.8, C6.7, and
C6.6. A satisfied C6.8 check is
still not `native-runtime-resolution-complete`: actual loader precedence and
environment, complete transitive closure, system-library bytes, runtime
`dlopen`, and signatures remain unverified.

C6.9 adds `native_runtime_transitive_closure`, a deterministic static graph
rooted in the exact C6.8 records. Only reached wheel members are eligible for
recursion. Each packaged node must match one canonical C6.4 wheel-inventory
member by path, SHA-256, and size, must be a regular unaliased file, and is
inspected from an immutable private snapshot with the target object
format/architecture (`MH_DYLIB` for non-root Mach-O). System dependencies are
logical terminal nodes with no system-byte hash. Cycles remain ordinary edges;
each packaged node is inspected at most once.

The collector has independent limits for nodes, edges, graph depth, candidate
paths per dependency, aggregate candidate attempts, inspector invocations,
aggregate inspector output, a cooperative total deadline, and serialized
characters. The deadline is checked around synchronous filesystem reads and
strictly prevents accepting late evidence, but it does not preempt an in-flight
filesystem call.
It requires exactly one canonical packaged candidate path, rejects
case-fold/Unicode-normalization and device/inode aliases, and rejects a Linux
allowlisted SONAME when a filesystem entry (including a dangling symlink) or
wheel member could shadow it. Missing, ambiguous, noncanonical, malformed,
unsupported, tampered, aliased, or exhausted observations omit only C6.9 and
leave C6.8 intact. Policy version 5 reports
`bounded-static-native-runtime-graph-bound`; absence adds
`bounded-static-native-runtime-graph-unavailable`. The graph always carries
`complete: false`, `transitive_closure_complete: false`, and
`actual_loader_selection: false`, so
`native-runtime-transitive-closure-complete` remains blocked.

After recursive snapshot cleanup, C6.8 receipt refresh requires exact prior
coverage and preserves file plus ancestor/descendant stamps. Only the generated
root directory's size/ctime/mtime may differ; its device, inode, and mode remain
fixed. Snapshot unlink/rmdir or final-absence failures make the observation
unavailable and never replace an already-active inspection exception.

Windows PE, runtime-bearing plugins,
signatures, host executables, Rust-importable crates, Nuitka, WASM, complete
dependency transitive closure, actual loader selection, system-library bytes, and `dlopen`
discovery remain out of scope.

C6.10 adds the sibling `source_transformation_verification` observation for
one deliberately narrow replay scope:
`project-functions-pyo3-plugin-free-v1`. The accepted closure must be nonempty
and consist entirely of project-owned module-level direct-native functions for
one CPython/PyO3 host-extension wheel. Plugins, embedding, native top-level
segments, runtime-semantics shims, delegated fallback, Python boundary calls,
external source, executable/crate profiles, and every other lowering surface
are excluded. An unsupported or inconsistent plan simply omits C6.10 without
changing the ordinary build, C6.3 gate, C6.6 inventory, or publication result.

For an in-scope plan, the collector securely reopens the exact project-source
input set with component-by-component `O_NOFOLLOW` traversal. It rejects
symlinked roots/components, hardlinked source/generated files, path escape,
file or directory identity/stamp drift, nonregular files, and oversized input.
It reparses UTF-8 source without importing it, rederives module-level
qualnames, half-open UTF-8 ranges, and semantic AST identities, and requires
exact agreement with the accepted analysis and every C6.6 record. It then
reanalyzes the whole project with plugins/embedding disabled, requires the same
complete accepted-function closure, lowers the resulting canonical `ModuleIR`,
regenerates the full `src/lib.rs`, and compares exact bytes, SHA-256, and size
with the captured generated-Rust input. Source and output receipts are checked
again after replay.

The immutable receipt binds the canonical C6.6-inventory digest, exact
project-source input-set digest and entries, canonical ModuleIR digest, sorted
accepted qualnames, the captured `src/lib.rs` reference, the regenerated Rust
digest/size, and the fixed generator backend. The same model is included in
unsigned provenance, with explicit observation-presence metadata. A replay or
scope mismatch makes only `scoped-source-transformation-verified` unavailable
and adds `scoped-source-transformation-verification-unavailable`; a malformed
present model still collapses the readiness report to the closed
all-`not-evaluated` shape. At the sidecar ceiling C6.14 is omitted first;
C6.13, C6.12, and C6.11 follow, then C6.10, C6.9, C6.8, C6.7, and C6.6.

`complete_for_scope: true` is intentionally paired with `complete: false` and
`global_provenance_complete: false`. C6.10 therefore does not satisfy
`source-transformation-provenance-complete`, sign an attestation, or authorize
distribution.

C6.11 adds the optional sibling
`component_license_policy_verification` for the narrow
`reachable-registry-cargo-license-metadata-v1` scope. Its project-root
`rextio.cargo-license.lock.json` must reproduce every C6.7 registry record
verbatim and in canonical order, bind the canonical digest of the full C6.7
inventory (including the generated path root), and carry a fixed `allow`
decision for `local-build`, `package`, and `redistribution`. The attestor shape
is closed to a human/human-owner or organization/organization-owner pair and a
fixed acknowledgement.

The lock reader uses bounded no-follow directory-relative access, accepts only
one regular single-link file, and rejects identity/stamp/size changes,
non-UTF-8, malformed or deeply nested JSON, duplicate keys, nonfinite numbers,
unknown/missing registry-license sentinels, and any stale, missing, reordered,
extra, or normalized registry row. It hashes both the exact lock bytes and a
canonical semantic snapshot. Immediately before final evidence construction it
recollects and compares the entire immutable receipt; absence or any change
removes only C6.11 and rebuilds provenance.

While present, the receipt is serialized in evidence and unsigned provenance,
and its exact lock reference is one separate provenance material. The lock is
not added to the C6.2 input snapshot or CycloneDX SBOM. It is omitted after
C6.13/C6.12 but before C6.10 for material-count or sidecar-ceiling pressure. Missing
C6.7 makes both the inventory and dependent C6.11 observation unavailable;
malformed present receipt data fails the total readiness reconstruction
closed. The scoped
observation does not authenticate the attestor, parse or normalize SPDX,
inspect license/NOTICE files, evaluate obligations or compatibility, provide
legal approval, sign evidence, satisfy `component-license-policy-complete`, or
authorize distribution.

C6.12 adds the optional sibling
`project_source_license_policy_verification` for the fixed
`project-functions-pyo3-plugin-free-source-license-v1` scope. It exists only
when the exact C6.10 replay receipt is present. The project-root
`rextio.source-license.lock.json` must bind the canonical digest of that full
C6.10 receipt, its exact source-input-set digest and ordered
`project-python-source` references, and its exact generated `src/lib.rs`
reference. It separately declares one bounded, trimmed, non-unknown license
string for the project sources and generated Rust output. Those strings are
owner declarations, not parsed or validated SPDX expressions.

The lock uses schema string `"1"`, kind
`rextio.project-source-license-policy-lock`, policy
`project-owner-exact-source-license-declaration-v1`, a fixed `allow` decision
for `local-build`, `package`, and `redistribution`, and acknowledgement
`REXTIO_PROJECT_SOURCE_LICENSE_POLICY_ACK_V1`. The attestor shape is closed to
a human/human-owner or organization/organization-owner pair. The strict
bounded no-follow reader shared with C6.11 rejects links, races, unsafe file
types, duplicate keys, nonfinite values, excessive depth, invalid UTF-8,
unknown/extra fields, and every stale or nonexact source/output binding. The
receipt separately hashes the exact lock bytes and its canonical semantic
snapshot.

While present, the receipt is serialized in evidence and unsigned provenance,
and its exact lock reference is one separate provenance material. It is not a
C6.2 declared input or CycloneDX SBOM component. Material-count or sidecar
pressure omits C6.13 first, then C6.12, and rebuilds provenance without the
omitted observation. Immediately
before final evidence return, the producer reruns C6.10 with the same plan,
input snapshot, transformation inventory, and embedding setting; it requires
full receipt equality and only then fully recollects C6.12. Any source,
generated-Rust, replay, or lock mismatch omits only C6.12 rather than adopting
changed evidence.

Policy version 8 adds the eleventh observation
`scoped-project-source-license-policy-verified`. Absence uses only its
dedicated `scoped-project-source-license-policy-verification-unavailable`
blocker in addition to the unchanged readiness blockers. A malformed or forged
present receipt fails the total readiness reconstruction closed: every check
is `not-evaluated` and the only blocker is
`readiness-assessment-unavailable`.

C6.12 does not prove attestor identity, SPDX validity, license or NOTICE file
presence, obligations, compatibility, source ownership, generated-output or
derivative-work rights, legal approval, signing, global license-policy
completion, or distribution authority. Existing readiness blockers remain;
`complete`, `signed`, and `distribution_authorized` remain false. C6.12 is a
bounded owner-declaration receipt, not Full C6.

### C6.13 scoped analysis-input verification

C6.13 adds the optional `analysis_input_verification` receipt for the exact
C6.10 replay/source set. It records every C6.10 source's sibling `.pyi` as
exactly `present` or `absent`. A present stub binds its project-relative
logical path, byte SHA-256, size, and deterministic supported-signature
projection/version; it is emitted as an in-toto `project-python-stub` material.
Absent records remain metadata observations and create no material. Raw stub
bytes, source text, absolute roots, and exception text are never serialized.

Secure immutable byte snapshots are evidence-eligible. Windows and platforms
without the required secure-open behavior may use compatibility snapshots for
conservative analysis, but those snapshots are explicitly evidence-ineligible.
`complete_for_scope: true` covers only the C6.10 sibling-stub scope; global
build-input closure, reproducibility, signing, policy satisfaction, and
distribution authorization remain false or blocked.

Readiness policy v9 has twelve observations and ten readiness checks. Missing
C6.13 makes only `scoped-analysis-inputs-verified` unavailable and adds
`scoped-analysis-input-verification-unavailable`; malformed or forged present
receipts fail the readiness assessment closed. Deterministic omission order is
C6.14, C6.13, C6.12, C6.11, C6.10, C6.9, C6.8, C6.7, C6.6. Removing C6.10 also removes
dependent C6.12 and C6.13.

### C6.14 artifact-policy coverage inventory

C6.14 adds `artifact_policy_coverage_inventory` only when the complete bounded
C6.9-C6.13 prerequisite chain survives final recollection. Thirteen fixed,
disjoint rows classify the observed project source/stub inputs, generated
Python/Rust/Cargo inputs, Cargo registry/path-root components, packaged and
logical-system runtime nodes, policy locks, wheel subject, and remaining wheel
entries. Every row contains only an `observed_count` and a class-qualified
canonical identity-set SHA-256; raw component identities are not serialized.

Identity strength (`byte-bound`, declared Cargo checksum, or logical-only),
owner-receipt license coverage, and replay/input provenance are separate closed
dimensions. Only exact C6.11/C6.12 and C6.10/C6.13 receipt kind/digests may be
referenced. This does not infer a license or transformation for other rows, and
`scope_complete`, both global policy/provenance claims, `complete`, `signed`,
and `distribution_authorized` are always false.

Readiness policy v10 adds `artifact-policy-coverage-bound` and the fixed
`artifact-policy-coverage-unavailable` blocker. A malformed present inventory
makes every check `not-evaluated`; absence remains an additive unavailable
observation. C6.14 is unsigned provenance metadata, never a material, and is
the first omission at the sidecar ceiling.

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

## Tooling-contract 2.6 reports

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
- sanitized top-level `external_source_plan` evidence in check/generate and
  blocked-build reports, including nested `authorization` status only (no
  top-level authorization mirror).

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

Train C through **2.19.0** does not yet provide:

- multiple-module initializer execution or Python import-order emulation;
- Rust-global publication or native reads of initialized module values;
- arbitrary top-level statements, calls, annotations, or side effects in a
  Rust executable;
- C5.2 project-call linkage, body lowerability, Rust lowering, packaging, or
  recursive source-native promotion of installed pure-Python packages;
- full/signed external-source authorization beyond the C6.1 prebuild lock
  contract (cryptographic signatures);
- complete standards SPDX/CycloneDX SBOM coverage (C6.2-C6.13 emit only a bounded
  incomplete CycloneDX 1.6 preview for ordinary host-extension wheels, plus
  unsigned in-toto/SLSA provenance and a macOS/Linux direct-linkage observation;
  not complete or actual-loader path resolution, complete transitive closure, `dlopen`
  discovery, or support for
  Windows PE, runtime-bearing plugins, host-executable, rust-crate, Nuitka
  sidecars, WASM, or external-package source-native builds);
- signed, reproducible, hermetic, or complete artifact provenance for
  packaged/redistributed hybrid outputs;
- device-provider discovery, privileged build/link contributions, CUDA
  execution, or CUDA certification;
- WASM artifact profiles or packaging.

**Residual local trust risk (C6.1):** the SourceLock open path hardens against
symlink/FIFO races with no-follow/nonblocking flags and fstat identity checks,
but a full installed-site-packages descriptor-relative TOCTOU redesign is out
of scope for this bounded pass.

Those require separate, reviewable authority and compatibility gates. An
unsupported case must remain ordinary Python fallback where that preserves
semantics, or fail before external build work when a native executable cannot
preserve the requested module/entry graph.
