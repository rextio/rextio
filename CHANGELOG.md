# Changelog

## Unreleased — Release Train C

**Experimental branch work; not tagged or published to PyPI.** The latest
published package remains Rextio **0.1.4** with plugin API **1.3** and tooling
contract **2.2.0**. This branch retains plugin API 1.3 and emits the additive,
unreleased tooling contract **2.3.0**.

### Host source and artifact planning

- Add immutable `ArtifactProfile`, `SourceModule`/`SourceModuleGraph`, and
  source-ordered `ModuleInitIR` records with deterministic serialization,
  project-relative provenance, source hashes, and fail-closed coherence checks.
- Add a descriptive-only `host_source_plan` to check and build-plan reports.
  A missing source, unavailable initializer, or module/path/hash mismatch makes
  the plan unavailable instead of approximating Python import order.
- Resolve artifact profiles only for outputs actually requested during
  generate/build. `BuildPlan.artifact_profiles` is authoritative; fallback-only
  work does not probe or advertise a host target triple.

### Native executable architecture

- Make the Rust executable fallback strategy explicit and closed:
  `error | python-subprocess | nuitka-sidecar`. Preserve
  `hybrid_runtime = source | nuitka` as a compatibility alias.
- Extend executable closure reports with ordered `module_initializers` and fail
  before external build work when source/initializer authority is unavailable.
- Connect a deliberately narrow initializer-before-main vertical slice:
  exactly one source module, no load-time imports/cycles, same-module
  direct-native entrypoint, and plain single-name assignments to exact scalar
  literals (`bool`, `int`, `float`, `str`). Revalidate the source hash, plan,
  and statement indexes before lowering; run the `() -> None` initializer before
  argv handling and the entrypoint.
- Do not publish initializer values as Rust globals or Python module values.
  Native reads of those values remain blocked; broader top-level semantics are
  deferred.

### Tooling contract 2.3.0 and device groundwork

- Add `host_source_plan`, resolved `artifact_profiles`, closure
  `module_initializers`, and capabilities `artifact_contract` fields without
  changing contract-2 position, route, native-status, rejection, or promotion
  semantics.
- Add a non-operational `device_provider_contract` marker and immutable draft
  `manifest()` / `preflight()` records. There is no provider discovery,
  selection, build/link hook, or runtime dispatch; every preflight result has
  `support_claim: false`.
- Add a no-dependency Windows x64 CUDA Driver API inventory probe and PowerShell
  validation workflow. The probe resolves `nvcuda.dll` from System32 only and
  uses just a six-symbol inventory surface, never creates a context or launches
  a kernel, and always reports `support_claim: false`; it is not CUDA support or
  certification.
- Document the released-versus-unreleased boundary, explicit executable
  fallback, source initializer limitations, device-provider draft, and Windows
  validation procedure.

## 0.1.4 — 2026-07-18

**Published release.** Package version `0.1.4` is tagged and published to PyPI
on 2026-07-18, superseding **0.1.3** (2026-07-17). `pip install rextio`
installs 0.1.4. Plugin API stays at **1.3** and the tooling contract advances
to **2.2.0**.

Release Train B completed in strict consumer-first order: **rextio-lsp 0.1.2**
was published before **core 0.1.4**.

### Tooling contract 2.2.0

- Add per-function `marker_kind`, isolated `promotion_assessment` evidence,
  and reliable half-open `source_range` / `name_range` records using 1-based
  lines and 0-based UTF-8 byte columns.
- Preserve failed automatic-promotion probe diagnostics and actionable
  suggestions without adding them to legacy function/project diagnostics,
  build errors, or CLI failure state.
- Serialize explicit exemptions and report unmarked module async functions
  plus direct methods of top-level classes as intentional skipped assessments.
- Keep the legacy meanings of `route`, `native_status`, and
  `rejection_codes` unchanged; expected automatic fallback remains
  `fallback-python` / `not-candidate` with no rejection codes.

## 0.1.3 — 2026-07-17

**Published release.** Package version `0.1.3` is tagged and published to PyPI
on 2026-07-17, superseding **0.1.2** (2026-07-14). Install this historical
release with `pip install rextio==0.1.3`.

Tooling contract advances to **2.1.0** (same major as the **2.0.0** shape
emitted by core 0.1.2; additive producer fields only — dual-map `2.x`
consumers that tolerate unknown keys remain compatible). Plugin API is **1.3**
(additive over 1.1/1.2; API 1.1/1.2 providers keep loading with their legacy
shapes). Plugin API 1.3 remains Experimental.

### Tooling contract 2.1.0 (protocol)

- **Additive producer shape** (minor bump; position semantics unchanged from
  `2.0.0`): `rextio check --format json` / `.rextio/reports/check.json` always
  serializes `modules[].logger_group_targets`, and conditionally serializes
  `plugin_claims[].receiver` and `plugin_claims[].callables` when plugin API
  1.3 method/callable metadata is present. `rextio capabilities` continues to
  embed the same top-level `contract_version`. See
  [docs/specs/tooling-contract.md](docs/specs/tooling-contract.md).

### Analyzer / identity

- Close the class-body ``global`` + assignment-expression rebinding gap in the
  project-wide final-binding authority: a walrus under class-body ``global``
  (assignment RHS, bare expression statement, control-flow conditions, or
  nested function/class/lambda headers evaluated while the class body runs)
  rebinds the module global and invalidates a prior ``FUNCTION`` final binding.
  Nested function/lambda/class *bodies* remain other scopes and do not create
  false module writes; class-body comprehensions with walruses are SyntaxError
  and are skipped safely.

### Plugin API 1.3

- Add plugin-owned opaque resident values and immutable-borrow native chaining,
  with RXT092 fail-closed boundaries when ownership or Python materialization
  cannot be proved.
- Add type-level Rust module support (`PluginType.uses`/`helpers`) so a
  signature-only accepted function (a plugin-typed parameter/return with zero
  claims) emits the `use`/helper items that define its rendered boundary
  conversion or named native type, instead of calling into undefined plugin
  functions/types. Support is collected only from the plugin types that appear
  directly in an accepted function's signature, threaded through
  `RxtPluginType` and the build/type-map path, and merged into the existing
  module collectors: `plugin_uses` is a set deduplicated and sorted at
  emission, while `plugin_helpers` is deduplicated by exact text in first-seen
  insertion order — including against identical `LoweredExpr` support. Empty support
  keeps the exact legacy 1.1/1.2 serialized bytes; non-empty support serializes
  deterministically (so report/cache identity moves) and requires
  `api_version >= 1.3` (rejected for lower-versioned providers).
- Add frozen receiver, structured callable-body/native-symbol, and ordered
  annotation-derived schema metadata for method-oriented plugins. API 1.1/1.2
  providers retain their exact legacy offer and serialization shapes.
- Extend named-keyword `ClaimLiteral` metadata with static `bool` and `str`
  values for API 1.3 providers only. Mixed-version registries project those
  sites exclusively to 1.3 providers; dynamic keyword values, `**kwargs`,
  floats, bytes, and non-int tuples remain fail-closed. A derived literal-kind
  discriminator keeps bool and int cache/equality keys distinct despite
  Python's `True == 1`, while legacy none/int/int-tuple serialization is
  unchanged.
- Thread one project-wide source-order binding/effect/mutation authority through
  analysis, callable metadata, claims, IR, and wrapper planning. Native markers,
  imported/static targets, re-exports, methods, and callable UDFs are accepted
  only when their exact executable identities remain proven.

### Correctness hardening

- Fail closed on source-visible module/class/stdlib/builtin mutation, aliases and
  control-flow joins, executed local mutators, consumed generators, implicit
  protocol hooks, decorator replacement, class construction hooks, descriptors,
  and post-class member replacement/deletion.
- Track exact tuple/list destructuring aliases and package-resolved relative
  re-exports while rejecting starred, mismatched, dynamic, cyclic, or mutated
  paths. Logger receiver/method aliases, `builtins.__build_class__` mutation,
  and module-load operator/attribute/subscript/f-string/comprehension protocol
  effects now also prevent unsafe direct-native promotion.
- Preserve API 1.3 `Frame[Schema]`-style metadata without weakening the new
  protocol-effect gate: only an exact, unmutated annotation target from the
  active validated plugin type vocabulary is trusted in annotation context,
  and that trust set is carried through shared binding, IR, and wrapper source
  revalidation. Shadowed, rebound, mutated, unregistered, or arbitrary
  subscriptions remain fail-closed.
- Revalidate semantic AST fingerprints before lowering or wrapper generation so
  an edit after analysis cannot reuse stale types or plugin claims. Generated
  method wrappers also verify the fallback owner/function identity before
  installation and fail loudly on mismatch.
- Dynamic monkeypatching performed externally after wrapper import remains
  outside this static proof boundary; source-visible mutations are rejected or
  routed through Python fallback.
- Close the follow-up 11 module-execution gaps: loop alias/effect replay now
  reaches a sound fixed point (with conservative widening), logger identity is
  process-global and keyed by exact names, implicit ``__builtins__`` mutations
  enter the builtin authority, and exact imported project mutators are replayed
  with defining-module imports plus positional/keyword/default binding. Unknown
  imported callables, recursive summary cycles, dynamic defaults, and complex
  argument expansion fail closed.
- Close the follow-up 12 execution gaps: project-call replay now selects
  source-order global bindings at circular-import suspension edges and final
  bindings for ordinary calls; narrow exact return summaries preserve root,
  scalar, conditional, default, and logger-factory identities. Generalized
  expression roots cover direct/conditional/container/walrus logger factories
  and module-dict ``__builtins__`` forms, while unknown external callees that
  receive project roots (including container-nested roots), unknown identities,
  or globals fail closed. Source constructors and protocol-dispatching builtins
  are no longer assumed pure without a closed proof; function-local ``vars()``
  remains local rather than being mistaken for module globals.
- Construct fallback/native bindings, factories, function wrappers, and method
  wrappers in one isolated bootstrap scope with ordinal local slots. Terminal
  publication preserves callable user exports of any ``_rextio_*`` spelling;
  native top-level updates cannot overwrite runtime captures before method and
  closure initialization. Correct stale release-candidate wording for the
  published core 0.1.2 and rextio-numpy 0.1.1 releases.
- Close the follow-up 13 identity/effect gaps: builtin and
  ``logging.getLogger`` purity now consult a project-wide fixed-point mutation
  authority; post-definition constructor changes, source-class protocol hooks,
  executed ``nonlocal`` cells, opaque module-scope exposure (including nested
  containers and deferred generators), and structurally unknown callable
  returns widen rather than inventing identities. RXT080 originals live in an
  isolated runtime ordinal registry instead of synthetic fallback/public module
  attributes. Native top-level results are filtered against exact final
  bindings and published only at the terminal wrapper step, so assignment vs
  function/class name collisions follow Python source order.
- Close the follow-up 14 mutation-summary gaps: bounded container summaries
  retain project exposure without flattening roots into invented subscript
  paths, while unsupported or externally mutated shapes widen. Bare
  `id`/`len`/`range`
  aliases preserve their builtin-slot identity across chained and destructured
  assignments, so monkeypatching revokes purity. Opaque calls now recursively
  account for project roots yielded by list/set/dict comprehensions and
  generator expressions; unknown comprehension inputs fail closed while
  closed scalar comprehensions remain clean.
- Close the follow-up 15 mutable-container alias gap: dict/list/set summaries
  now discard exact shape at the first alias, parameter, shared binding, or
  callable return while retaining every exposed project root. Stores, deletes,
  and modeled mutating methods through any resulting alias invalidate all such
  roots (including newly inserted values); nested tuples containing mutable
  members follow the same rule, while immutable tuple/scalar summaries and
  fresh literal direct selection remain precise.

## 0.1.2 — 2026-07-14

**Published release.** Package version `0.1.2` is tagged and published to PyPI
on 2026-07-14, superseding **0.1.1** (2026-07-12). Install this historical
release with `pip install rextio==0.1.2`.

**Release-order gate (tooling contract 2.0; strict sequence):** publish
related packages in this order only — **rextio-lsp 0.1.1** (dual-map contract
majors `{1, 2}`) **first**, then **core 0.1.2**, then **rextio-numpy 0.1.1**
(plugin API 1.2 consumer). Do not ship LSP simultaneously with or after core,
and do not ship rextio-numpy 0.1.1 before core. Core **must not** publish alone
first: a contract-`2.0.0` producer against major-1-only LSP mis-pairs RXT000
columns. See `docs/specs/tooling-contract.md`. Core has no runtime dependency
on `rextio-lsp` or `rextio-numpy`.

### Tooling contract 2.0.0 (protocol)

- **Breaking protocol change:** `contract_version` advances to `2.0.0`.
  `RXT000` (syntax-error) diagnostic `column` is now a **0-based UTF-8 byte
  offset** into the line, matching every other diagnostic and `ast.col_offset`.
  Contract `1.x` (PyPI 0.1.1) left `RXT000.column` as CPython's 1-based Unicode
  code-point `SyntaxError.offset`.
- Major (not minor) so consumers that gate only on major 1 refuse the
  unsupported path instead of silently mis-mapping RXT000. See
  `docs/specs/tooling-contract.md` (positions, compatibility, release
  ordering).

### Plugin API 1.2 (backward-compatible)

- Additive plugin API **1.2** on the same major as 1.1 (API 1.1 plugins keep
  loading). Core advertises `PLUGIN_API_VERSION = "1.2"`.
- **Static literal / ordered keyword metadata** on claim sites
  (`operand_literals`, ordered `keywords`) for version-gated offers to API
  ≥ 1.2 providers. This surface **enables literal-axis claims and lowering**
  (for example `axis=0` keyword literals).
- **Structured `ClaimExpr` trees** so plugins can reason about nested covered
  expressions without seeing core IR.
- **Leaves-mode lowering** (`operand_mode` `direct` | `leaves` with
  `leaf_operands` on `LoweringContext`) **enables fusion-aware** expression
  emission (one helper over non-literal leaves of a multi-op tree). Leaves
  mode is the fusion path; it is **not** the literal-axis path.
- Together these Wave 2 surfaces are used by rextio-numpy **0.1.1**, published
  later on 2026-07-14 after LSP 0.1.1 and core 0.1.2 in the required order.
  API 1.1 providers retain legacy keyword-not-offered semantics and never
  receive leaves-mode data. See `docs/specs/plugin-lowering.md`.

### Diagnostics and CLI

- User-visible release-version strings now derive from
  `rextio.__about__.__version__` instead of a hardcoded `0.1.0` /
  `0.1.0-alpha`. This fixes stale version text in RXT diagnostic suggestions and
  messages, `rextio` CLI `--help` output, config-validation errors, target-spec
  warnings, and the `rextio init` `REXTIO.md` template, so they track the
  installed version. Wording of version-agnostic messages was reworded to the
  "native subset" where no version belongs.

### Documentation

- Hybrid Rust executable (subprocess delegate): document that a delegated
  `SystemExit` / `sys.exit(n)` int code is honored only when representable as
  a signed `i64` (Rust client `serde_json::Value::as_i64`). After consume the
  value is cast to `i32` and OS process-status width applies — prefer portable
  `0..255`. Python ints outside signed `i64` still serialize on the wire but
  are not faithfully modeled as process exits: the client surfaces a
  malformed-response `RuntimeError` rather than terminating with the intended
  status (not CPython-equivalent for oversized codes). This is distinct from
  direct-native `main` return semantics (compile-time `int`→`i64` lowering,
  then the same `i64`→`i32` / platform truncation). See README and
  `docs/unsupported-features.md`.

## 0.1.1 — 2026-07-12

Contract-and-plugins release: the machine-readable tooling contract for
external tooling (agent skills, LSP servers, editor extensions) and the
plugin protocol that lets plugins describe AND lower covered constructs.
All new surfaces are Experimental (see docs/stability.md); no analyzer or
codegen behavior changed for plugin-free projects.

### Machine-readable tooling contract

- `rextio check --format json` (and `.rextio/reports/check.json`) carries a
  top-level `contract_version` plus per-function `route` (`native-direct`,
  `native-shim`, `native-plugin:<id>`, `fallback-accelerated:<tool>`,
  `fallback-python`), `native_status` (`accepted`/`rejected`/`not-candidate`),
  and `rejection_codes`. Additive: no existing key changed.
- New `rextio capabilities [project_root] --format json`: the config-resolved
  capability manifest — the supported type matrix, structured L2 rule records
  (constraint + diagnostic code + remediation guidance per rule, core and
  active plugins merged), a `config_fingerprint` for consumer caching, and the
  active plugin list. Introspection-only: no source analysis, no report files.
- Specs: `docs/specs/tooling-contract.md` and `docs/specs/plugin-lowering.md`.

### Plugin protocol v2 and lowering (plugin API 1.1)

- Entry-point plugins can now self-describe declarative rule records via
  `describe()`/`covers()` (`rextio.plugins.api`), with `RXTP-<PLUGIN>-NNN`
  diagnostic namespacing validated at load. Metadata-only plugins keep
  loading unchanged.
- Plugin API 1.1 adds the lowering members (`type_vocabulary`, `claim`,
  `lower`, `crate_dependencies` — all-or-nothing): a plugin registers an
  annotation vocabulary the analyzer resolves through the module import map,
  claims covered call/binop sites at analysis time (deterministic by
  contract; claims are matched to IR nodes on the full kind+span signature),
  and emits expression-level Rust through `lower(site, LoweringContext)` at
  codegen time. Claimed functions route as `native-plugin:<id>`; plugin
  claim rejections surface at the boundary pass with the plugin's own
  diagnostics; plugin codegen failures demote to the Python fallback exactly
  like core codegen failures.
- Plugin-typed PyO3 boundaries: plugin types declare their parameter/return
  conversions (read-only borrows in, owned returns out); plugin types never
  cross scalar boundary calls or executable delegation, and plugin-lowered
  functions are excluded from the Rust-importable crate.
- Pinned crate injection: a lowering plugin declares exact-pinned crate
  dependencies; they are appended to the generated Cargo.toml only when a
  plugin-lowered function exists, listed in `build.json`
  (`plugin_crate_dependencies`) and the text report, and cross-plugin pin
  conflicts fail loudly up front.
- New diagnostics: `RXT091` (informational: an accelerator-decorated function
  may be plugin-lowerable if the decorator is removed — the decorator is
  respected; precedence is explicit decorator > plugin > fallback) and the
  plugin-owned `RXTP-*` code space.

### Plugin certification kit

- `rextio.plugins.testing`: builds a fixture project once, then runs each
  input through the generated wrapper on both legs
  (`REXTIO_NATIVE_MODE=native`/`fallback`) with deep-copied arguments,
  comparing results (NaN-aware, type-strict; custom comparators for richer
  types) and exceptions (type + message). Rule records gain an optional
  `verified` field for certification status.
- First consumer: the rextio-numpy plugin's initial float64 1-D surface
  (element-wise arithmetic, `numpy.dot`, whole-array `sum`/`mean`) is
  certified with this kit against CPython NumPy under real cargo builds.

### Correctness and robustness hardening

Semantics- and safety-focused fixes to the analyzer, the generated wrapper,
the plugin pipeline, and the hybrid-executable delegate, verified end-to-end
(generate → import → call, and against real cargo builds). None change behavior
for a plugin-free project whose native candidates already compiled cleanly;
they tighten the reject-to-fallback boundary so more edge cases stay on the
CPython-equivalent fallback instead of being mis-accelerated.

- `@rextio.native` on a **method** is now accepted only for a plain instance
  method defined directly in a top-level class body whose name is never
  rebound. Every other shape is rejected with `RXT010` and left on the Python
  fallback with its original behavior intact: any non-native decorator
  (`@staticmethod`/`@classmethod`/`@property`/`functools.cached_property`,
  aliased or not); an implicit-descriptor dunder (`__new__`/`__init_subclass__`/
  `__class_getitem__`); any class-body rebinding of the method name after its
  definition — plain/annotated/augmented/walrus/tuple-unpack assignment, a
  `for`/`with`/`except`-as target, a `match` capture, `import ... as`, `del`, a
  later `def`/`class`/`type` of the same name, or a walrus in a def/class
  header, including any of these nested inside class-body control flow; a method
  in a nested (inner) class; a method defined inside class-body control flow;
  and a method whose name is declared `global`/`nonlocal`. Previously several of
  these were silently accepted and the generated wrapper could strip a
  descriptor, change the calling convention, bind the wrong scope, or fail at
  import.
- Generated Python wrapper fidelity: annotations stay as PEP 563 strings (no
  eager evaluation that could `NameError` on private or `__all__`-excluded
  names); `__defaults__`/`__kwdefaults__`, `__doc__`, and `__all__` are mirrored
  from the fallback at runtime (including an `__all__` defined by control flow or
  import); the positional-only `/` marker is preserved; and runtime helpers are
  aliased under a `_rextio_` prefix so they cannot be clobbered or leak through
  `from module import *`.
- Plugin lowering and routing: claim validation (result type required and
  known, advertised rule ids, `RXTP-*` rejection codes namespaced and declared),
  expression typing over plugin types, deterministic claim-to-IR matching,
  same-site multi-plugin claim rejection, crate-pin format validation with a
  core-crate-name collision guard, and deterministic merging of duplicate
  cross-plugin pins. A claim-only plugin function (one that claims a core-typed
  call site without plugin-typed parameters/returns) is now exempt from the
  boundary-fallback threshold like a plugin-typed one, so it never flips to the
  fallback leg mid-run and changes an observable per-leg divergence.
- Hybrid-executable subprocess delegate: a protocol-version handshake and
  dead-bridge re-spawn, and a delegated `sys.exit()`/`KeyboardInterrupt` is
  forwarded as a distinct `{"exit": code}` frame that the Rust executable
  honors when the int code is representable as signed `i64` (bool codes
  normalized to `0`/`1`; then cast to `i32` / platform status width — prefer
  `0..255`) instead of always exiting `1`. Python ints outside signed `i64`
  are not CPython-equivalent on this path (see 0.1.2 documentation).
- Certification kit: dual-leg equivalence uses deep-copied arguments and sets
  the native/fallback env before import; strided (non-contiguous) arrays are
  certified for real rather than being silently flattened.

## 0.1.0 — 2026-07-04

Initial public release (alpha stage) of Rextio as a local hybrid build tool.

### Text and formatting fidelity

- `print`/`logging` of `bool` and `float` are textually CPython-exact
  (`True`/`False`; shortest correctly-rounded float repr with CPython's
  positional/scientific thresholds, `nan`/`inf`/`-0.0` spellings, and signed
  two-digit exponents). Logging `%` conversions are validated per argument
  type (`%d`/`%i`: int and bool; `%f`: float only, fixed six decimals with
  the CPython `nan` spelling; count mismatches, unknown conversions, and
  dynamic format strings with arguments fall back), and `%r` renders CPython
  repr. Printable containers (list, fixed tuple, `Optional`, nested) compose
  CPython repr recursively in `print`/logging; `print` of a `set` or `dict`
  is rejected (native iteration order is not CPython's). `__rextio_repr_str`
  escapes quotes, backslash, `\n`/`\r`/`\t`, C0/C1 controls, and U+00A0
  exactly like CPython repr.
- Iterating a `set` in a native function is rejected to the Python fallback
  with a dedicated diagnostic (Rust hash-set iteration order is per-instance
  seeded and diverges from CPython's deterministic-within-process order).
  Building a set from an ordered iterable and order-independent set
  operations stay native.
- `RXT090` non-rejecting note marks direct-native functions relying on the
  statically attributable documented divergence (`bytes.decode()` raises
  `ValueError` where CPython raises `UnicodeDecodeError`); `rextio check`
  lists the notes. (The other documented divergence - repr of str values
  containing non-printables above U+00A0 - is value-dependent and cannot
  carry a per-function note.)
- `list.index` failure messages interpolate the needle repr exactly like
  CPython ("5 is not in list", "'x' is not in list", "[3] is not in list").

### Scalar boundary calls

- An explicitly marked native function may call a fallback-only project
  function whose signature is immutable scalars end to end: the call is an
  in-process boundary call (`RXT075`, informational) executed by the host
  interpreter, so values and exceptions are CPython-exact and runtime
  replacement of the callee (monkeypatching) is honored by the native path.
  Scalars cross by value: argument identity (`is`) is not preserved
  (`None`/`bool` singletons are). Containers never cross; a boundary call
  inside a native loop - including comprehension bodies and while-loop
  tests - keeps the caller on the Python fallback (`RXT076`), while a call
  in a for-loop iterable (evaluated once) stays an accepted `RXT075`;
  auto-discovered candidates are
  excluded (marker-only). Every crossing counts against the caller's
  boundary-fallback threshold (one native call performing `k` boundary calls
  adds `k + 1` crossings), so a chattering native demotes itself to the
  Python fallback at run time. The importable Rust crate does not export
  boundary-calling functions or their transitive native callers (they need
  the interpreter), and the rust-executable delegate mode is unchanged.

### Toolchain selection and version pins

- A `[toolchain]` configuration section (CLI flag > `REXTIO_*` variable >
  `rextio.toml` > PATH) selects the cargo, maturin, Nuitka, and CPython a
  build uses: paths accept a binary or a home directory, a configured path
  that does not resolve fails the build up front, and symlinks and `..`
  components are traversed exactly as at the shell. `rust_toolchain`
  forwards a rustup channel; `[toolchain] python` drives the PyO3 build
  target (`PYO3_PYTHON`), Nuitka's interpreter (`python -m nuitka`), and the
  hybrid binary's delegated-call runtime, and must be a CPython sharing the
  build interpreter's minor version. For PyO3 specifically, when
  `[toolchain] python` is unset the target defaults to the running build
  interpreter (not PATH `python3`); an explicitly exported `PYO3_PYTHON` is
  respected as an override.
- `*_version` pins verify (never install) tool versions: bare pins are
  prefix matches, `==` is exact, `>=` is a minimum. A pin is enforced under
  the environment the build runs the tool with, exactly when the build uses
  the tool - including the hybrid dispatcher and the maturin-to-cargo
  fallback - and an unresolvable or unprobeable pinned tool fails the build.

### Packaging and accelerator-scan behavior

- The wheel built from a Nuitka fallback tree excludes `.py` sources
  shadowed by their compiled extension module (import-loadable suffixes
  only, so a same-stem ctypes `.dylib`/`.dll` payload keeps its Python
  wrapper) and carries a platform tag rather than `py3-none-any`;
  accelerated modules keep their `.py`.
- The external-accelerator source scan walks the whole module tree (deferred
  imports in function bodies, nested functions, `except`/`finally` bodies,
  `from numba import *` submodules), keeps accelerator-resolving import
  bindings over scope-flattened collisions, and all three Nuitka build paths
  recognize project-local modules (a local `numba.py` shim neither skips nor
  blocks builds).
- A Nuitka standalone build whose `.dist` directory lacks the launcher
  binary is reported as failed rather than returning the directory as the
  artifact.

### Added

- CLI commands: `rextio init`, `rextio check`, `rextio build`, `rextio bench`, and `rextio clean`.
- Source-only generation command: `rextio generate`.
- Automatic native discovery for eligible typed module-level Python functions, with `@rextio.native` still supported and decorator-only mode available.
- `@rextio.exempt` decorator for functions that must remain Python fallback.
- Conservative 0.1.0 subset checks for supported scalar/list types, simple control flow, indexing, and native-to-native calls.
- Experimental restricted native `try`/`except`/`finally` subset (built-in exception handlers only; a `finally` block carries an `RXT090` note for the documented `__context__` divergence).
- Deterministic diagnostics for unsupported syntax, dynamic Python features, external calls, and unsafe boundaries.
- Static boundary policy:
  - reject native functions that call fallback-only functions;
  - reject native functions that depend on rejected native candidates;
  - warn when fallback Python loops call native functions repeatedly.
- Rextio IR lowering and deterministic Rust/PyO3 code generation for accepted native functions.
- Cargo and maturin build orchestration with Cargo fallback when maturin is unavailable.
- Optional Rust-importable crate artifact generation with `--rust-importable`
  and `--rust-crate-name`, allowing Rust projects to consume accepted
  direct-Rust functions as a path dependency.
- CPython fallback packaging and generated wrappers that preserve fallback behavior.
- Experimental Nuitka fallback packaging with clear unavailable-tool reporting.
- Runtime control: `REXTIO_NATIVE_MODE=auto|native|fallback` (one switch for disable/require/default).
- Runtime boundary fallback threshold for repeated Python-to-native wrapper crossings.
- `--fallback-threshold` for embedding a generated-code default threshold in `rextio build` and `rextio generate`.
- Configurable external build-tool timeout via `--build-timeout`,
  `REXTIO_BUILD_TIMEOUT`, and `[build] build_timeout_seconds` (CLI > env > toml >
  default, default 600s).
- Generated hybrid artifact wheel under `dist/`.
- Zipapp executable artifact generation with `rextio build --entrypoint=module:function`.
- Nuitka standalone/onefile executable artifact generation with `--executable-backend=nuitka`.
- Native Rust binary executable generation with `--executable-backend=rust`: a
  native executable whose `main` calls a direct-native `def main(argv: list[str])
  -> int` entrypoint, mirrors `sys.argv`, uses the returned `int` as the process
  exit code (converted to the platform's exit-status width, like CPython's
  `sys.exit`), and prints a returned error CPython-style (`TypeName: message`) to
  stderr. The crate-mode `RextioError` carries the CPython exception type name
  so these binaries emit Python-style diagnostics.
- Subprocess hybrid for the Rust executable: a call the entrypoint makes to a
  project function that stays on the Python fallback is delegated to an external
  CPython process (a generated dispatcher + the project source shipped as
  `dist/<binary>.runtime/`, driven over a JSON stdio protocol) instead of being
  rejected, so hard-to-compile-to-Rust logic can be "left as Python." The
  delegated function runs real CPython (result is CPython-equivalent, exceptions
  forwarded CPython-style). Delegated-call arguments and results must both be
  immutable scalars (`int`/`float`/`bool`/`str`/`None`) — a mutable container
  (`list`/`dict`/`set`) is not delegated in either direction because it crosses the
  wire by value, which severs the aliasing CPython preserves (a mutated argument or
  a mutated aliased return would diverge silently); non-finite floats are rejected
  rather than silently dropped. A delegated function's stdout/stderr is redirected
  to the binary's stderr so it cannot corrupt the wire protocol, the dispatcher
  survives a delegated `SystemExit`/`KeyboardInterrupt` or non-serializable result
  instead of dying, and it runs without `rextio` installed (a no-op decorator stub
  is supplied when absent). RXT080 runtime-shim functions are not delegated. A
  hybrid binary needs a Python interpreter at runtime; a fully-direct-native binary
  remains standalone. `--executable-python` (`[executable] python`,
  `REXTIO_EXECUTABLE_PYTHON`) pins the interpreter the binary launches (bare name,
  absolute path, or a path relative to `<binary>.runtime` to bundle one).
  `--hybrid-runtime=nuitka` (`[executable] hybrid_runtime`, `REXTIO_HYBRID_RUNTIME`)
  instead ships the delegated Python as a self-contained Nuitka-compiled dispatcher
  executable, so no separate Python install is needed at runtime (requires Nuitka
  at build time).
- Mirrored build and analysis settings across CLI parameters, environment variables, and `rextio.toml`.
- Target planning metadata for future native backends and installed package plugins.
- Experimental opt-in scalar-helper embedding for narrow unmarked helpers
  represented in Rextio IR, with `--embed-helpers`, `REXTIO_EMBED_HELPERS`, and `[embedding] enabled`
  controls (`rextio bench` accepts the same flag pair, so both embedding
  modes can be benchmarked): an eligible helper compiles ahead of time as an internal native
  function through the normal checked lowering (int overflow raises
  OverflowError; float `/` raises ZeroDivisionError), and in the Rust
  executable backend it compiles into the binary instead of being delegated
  per call. There is no JIT: everything compiles ahead of time, and the built
  artifact contains no runtime compiler.
- Numba coexists with the Nuitka fallback backend (experimental): modules using a recognized
  external accelerator are automatically kept as plain Python (skipped from
  per-module Nuitka compilation, so the importable `.py` retains the bytecode
  the accelerator needs), and the build result lists them. The detection scan
  sees through the optional-dependency guard (`try: from numba import njit`),
  `from numba import *`, conditional top-level imports, and class-contained
  methods. Nuitka *executable* builds fail early with guidance when
  accelerated modules are present, and the `nuitka` hybrid-runtime dispatcher
  fails early when *any* project module uses an accelerator (the whole tree
  ships in the runtime and Nuitka follows imports into it), instead of
  producing a binary that fails at the first call.
- Numba (`numba.jit`/`njit`/`vectorize`/`guvectorize`) is recognized as an
  external accelerator (experimental) for Python fallback code: decorated
  functions stay on the fallback cleanly (no auto-discovery, no diagnostic
  noise), are labeled `external_accelerator: numba` in reports and
  `rextio check` output, and run under Numba's own semantics (documented,
  including the nopython int-overflow wrap divergence). Not compatible with
  Nuitka-compiled fallbacks.
- Python runtime semantics native shim (`RXT080`) for compatibility coverage of
  object behavior, marked instance methods, exceptions, context managers,
  async functions, generators, and dynamic attribute access.
- Limited direct Rust lowering for expanded builtin and standard-library
  patterns including `math`, `all`/`any`, `sorted`/`reversed`, selected
  `str`/`bytes`/`list` methods, `time`/`datetime`, `hashlib.sha256`, and
  `base64.b64encode`. (`statistics.mean`/`fmean`, `json.dumps`/`json.loads`,
  and `base64.b64decode` have no faithful native equivalent and stay on the
  fallback/runtime-shim path.)
- Conservative Python/Rust ownership handling for direct Rust lowering:
  generated clones for reused owned values and fallback diagnostics for mutable
  collection alias mutation.
- Feature-oriented README and example documentation that explains generated
  artifacts, native/fallback behavior, executable outputs, and Rust-importable
  crate usage.
- Example projects for pure math, application-shell scoring, fallback safety, and boundary diagnostics.
- Focused end-to-end tests for build/import/runtime behavior, real Cargo builds, generated wheels, and Nuitka when installed.
- Global CLI output options on every command: `--format text|json`, and mutually
  exclusive `-v/--verbose` and `-q/--quiet`. All commands emit their result on
  stdout (text or JSON) while diagnostics and configuration errors go to stderr, so
  a `--format json` run produces clean machine-parseable stdout.
- Project documentation and governance: a `CONTRIBUTING.md` guide, GitHub issue forms
  and a pull-request template, a feature-stability table (`docs/stability.md`) and a
  versioning policy (`docs/versioning.md`) documenting the SemVer pre-1.0 stance and
  what is stable versus experimental.

### Semantics and safety guarantees

- `@rextio.native` validates its `target` against the recognized target
  languages, and both `@rextio.native`/`@rextio.exempt` reject classes
  and non-callables at decoration time, surfacing typos and misuse immediately.
- Plugins are metadata-only; a legacy `rules` key in plugin metadata is
  accepted and ignored so such plugins still load.
- Generated `str` literals are escaped into always-valid Rust (non-ASCII is
  emitted literally; escaping is injection-safe) through a single escaper that
  funnels every Python-string-to-Rust-literal path — plain `str` constants,
  the runtime-semantics shim's fallback module/attr names, logging format
  strings, and error messages embedding variable names. Lone surrogates, which
  a Python `str` can hold but Rust cannot represent, are rejected with a clear
  diagnostic.
- External build tools (`cargo`/`maturin`/`nuitka`) are invoked through a
  shared no-shell, bounded-timeout helper: a hung toolchain fails the build
  with a clear message, and on timeout the whole process tree is terminated
  (POSIX process-group / Windows `CREATE_NEW_PROCESS_GROUP`) so child
  `rustc`/linker/`python` processes are not left running.
- A native candidate's function name, parameters, and locals that collide with
  a Rust keyword (`fn`, `match`, `type`, …) are carried as raw identifiers
  (`r#match`), so the function stays native. Only the keywords a raw
  identifier cannot express (`crate`/`self`/`Self`/`super`) and non-ASCII
  names are kept on the Python fallback path with `RXT011`.
- `SECURITY.md` documents the threat model and protections; CI runs a
  `check-wheel-contents` packaging gate.
- The supported-type capability matrix (scalar/list/dict/set item/key types)
  is defined once in `rextio.capabilities` and shared by the analyzer and the
  Rust backend; a consistency test asserts every registered type has a Rust
  mapping.
- Generated sequence indexing preserves Python semantics: a negative index
  counts from the end (`xs[-1]`), and an out-of-range index raises
  `IndexError` rather than triggering an unchecked Rust panic.
- Generated integer `+`/`-`/`*`/`%`, unary negation, and the `abs`/`sum`
  builtins use checked arithmetic: an i64 overflow raises `OverflowError`
  (PyO3) / returns a `RextioError` (Rust-importable crate) instead of silently
  wrapping or panicking, and a modulo by zero raises `ZeroDivisionError`.
  Integer `%` follows Python's floored semantics (the result takes the
  divisor's sign, e.g. `-7 % 3 == 2`) rather than Rust's truncated remainder.
  These are catchable `Exception`s (unlike the uncatchable PyO3
  `PanicException` a raw overflow panic produces), and the guarantee travels
  with the generated code, so it holds even when the Rust-importable crate is
  consumed as a dependency. Release builds also keep `overflow-checks = true`
  as a safety-net backstop for any arithmetic outside the checked path; it is
  not part of the catchable-exception contract.
- Generated float division and modulo preserve Python semantics: `x / 0.0`
  and `x % 0.0` raise `ZeroDivisionError` (instead of Rust's silent
  `inf`/`NaN`), and float `%` is floored (the result takes the divisor's
  sign); a remainder of exactly zero takes the divisor's sign
  (`copysign(0.0, b)`), matching CPython.
- `math.floor`/`ceil`/`trunc` convert through a guarded float-to-int helper: a
  value outside i64 range raises `OverflowError` and `NaN` raises
  `ValueError`, never silently saturating to `i64::MIN`/`MAX`.
- The Python runtime-semantics shim (`RXT080`) is strictly opt-in: only
  functions explicitly marked `@rextio.native` are promoted to the shim.
  Auto-discovered (undecorated) functions are accepted only within the
  direct-Rust subset, and an undecorated function that depends on a
  runtime-shim native is reported with `RXT074` and left on the Python
  fallback path.
- The native subset checker keeps patterns it cannot lower faithfully off the
  direct-native path (rejected to the Python fallback, or routed to the
  `RXT080` runtime shim for marked functions) — an accepted function is either
  CPython-equivalent or rejected, never silently mis-compiled. Among the
  rejected patterns: non-`bool` `if`/`while`/comprehension conditions;
  multiple assignment (`a = b = ...`); integer literals outside the `i64`
  range; ordering comparisons on `dict`/`set` operands (`==`/`!=` stay
  native); `len()` of a fixed tuple; value-position `range(...)`;
  `str`/`bytes` indexing; a value-position read of a name bound nowhere in
  the function (a module global, a closure, or a name leaked from a nested
  block); and a call to a name shadowed by a local binding or a module-level
  assignment (`len = 5` then `len(xs)`). `len(str)` counts Unicode code
  points (`.chars().count()`) rather than UTF-8 bytes, and a bare `return` in
  an `Optional[T]` function emits `None`.

### Notes

0.1.0 is intentionally narrow. It does not provide full Python
compatibility, bundled third-party package support, framework migration,
general-purpose Python JIT behavior, or full runtime boundary-cost optimization.
Scalar-helper embedding is experimental, opt-in, AOT, native-side only, and
limited to small scalar helper regions; there is no runtime JIT.
