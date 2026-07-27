# Spec: Plugin Lowering (claim/lower Hook)

Status: **draft** (targets 0.1.1+, experimental tier; plugin API 1.0 → 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6 → 1.7)
Builds on: [tooling-contract.md](tooling-contract.md) (protocol v2: `describe()`/`covers()`)
First consumer: rextio-numpy

**Release framing:** core **0.1.8** is under development with plugin API
**1.7** and tooling contract **3.0.0**; the contract-major bump renames
artifact lifecycle surfaces and does not widen the plugin API. Published core
**0.1.7** implements plugin API **1.7** and tooling contract **2.28.0**.
Published core **0.1.6** ships plugin API **1.6**,
tooling contract **2.27.0**, and readiness policy **11**. Core 0.1.5 shipped plugin API
1.4 and tooling contract 2.24.0. The standalone artifact
capability shape below first appeared in unpublished/internal intermediate
tooling contract **2.4.0**. Core 0.1.5's published producer was **2.24.0**
because its unrelated external-source inventory and authorization, bounded
host-extension evidence, required-evidence gate, native-runtime inventory,
always-blocked readiness assessment, transformation and license observations,
path/graph observations, scoped replay and owner-policy receipts, analysis
inputs, and the strict artifact-contract Alpha all extend the tooling report.
The 0.1.5 plugin API remained **1.4**; those artifact surfaces do not add
runtime-bearing plugin support. They remain Experimental/Alpha and do not
claim general package AOT.

Contracts 2.21.0-2.24.0 do not widen this plugin API. Their strict source-native path is
a separate core-owned linkage contract for exactly one SourceLock-authorized,
digest-pinned depth-1 `py3-none-any` dependency and direct typed scalar leaf
calls. It emits private
external Rust functions while retaining the Python dependency through exact
`Requires-Dist` and a runtime identity/source-byte guard that never imports or
introspects the external module or callable. Contract 2.23.0's public technical
template, explicit owner completion, and offline policy finalizer are likewise
core-owned and do not invoke plugin hooks. Contract 2.24.0's public support-lock
bootstrap and sandbox/support receipts are also core-owned and do not invoke
plugin discovery, lowering, or standalone capability hooks. Its bootstrap
reserves every configured `imports.packages.*.source_archive` against exact,
ancestor, or descendant aliasing with the support-lock output, and its public
sandbox receipt binds an engine-specific, path-tokenized semantic profile—not
the raw rendered profile or its private paths. The sandbox regrants executable
mapping only to core-bound read-execute paths/read-write directories, never by
plugin claim. The frozen strict artifact profile
requires `[plugins] enabled = []` and excludes plugin, executable, rust-crate,
native-top-level, embedding, and Windows artifacts; no plugin claim or
`artifact_capability()` result can opt into that profile.

Core 0.1.7 implements plugin API **1.7** and tooling contract **2.28.0**.
API 1.7 adds optional function-scope RAII guards (§11). Core 0.1.6 implements
plugin API **1.6** and tooling contract **2.27.0**.
API 1.5 was introduced by contract 2.25.0 with one
explicitly version-gated
``ClaimSite(kind="compare")`` surface for a non-chained comparison from the
closed token set ``== != < <= > >=``. Core offers it only when at least one
operand is owned by an API-1.5 plugin, preserves the claimed result type
(including a non-scalar plugin type) through later claimed calls, and carries
the exact direct operands through IR to ``lower()``. Providers below 1.5 are
never offered these sites; chained comparisons, identity/membership operators,
and unclaimed plugin comparisons remain fail-closed. A claimed comparison must
state a non-empty result type registered either as a Core type or plugin type;
`result_type=None` is an invalid claim. Peek inference never chooses between
multiple claiming providers, even if they report the same result type; the
authoritative recording pass reports that overlap.

API 1.5 also permits a **result-only resident type** to declare
`annotations=()`. It remains registered by stable key for claim results,
subsequent claim operands, IR, and codegen, but contributes no annotation-map
entry and therefore cannot be forged in a Python signature. Returning one
directly or inferring it into a parameter/return signature is an RXT092
native-boundary escape; auto-mode retains that blocker in its promotion
assessment. This exception is valid only when `conversion is None` and the
provider advertises API 1.5 or newer. Materialized types and API 1.1-1.4
resident types still require at least one non-empty dotted annotation spelling.

API 1.6 adds optional structured `PluginType.device_value_metadata`. Core reads
it only for plugin type keys used by accepted native signatures and claims,
derives deterministic artifact device/runtime requirements, and rejects mixed
CPU/accelerator, conflicting accelerator domains, and non-zero accelerator
ordinals before codegen. CPU-only and fallback-only types do not change an
artifact profile. A selected provider must resolve and preflight the exact
profile before codegen. Only then does Core pass a redacted immutable
`LoweringContext.device_authorization` to API-1.6 providers; older providers
always observe `None`. An accelerator claim without a matching authorization
fails closed. Authorization matching covers the canonical device/backend,
domain runtime/reuse, features, optional layout projection, and memory spaces.
Static dtype/rank/layout/runtime/reuse facts belong to the plugin type; target
architecture remains an explicit build/provider-selection fact and is not
rechecked as type metadata.

## Purpose

Protocol v2 lets a plugin *describe* rules; this spec lets a plugin *lower*
code: translate covered constructs (e.g. NumPy calls) in accepted native
candidates into Rust, inside core's existing analyze → partition → codegen →
build pipeline. The core contract is unchanged — a construct is lowered with
CPython-equivalent semantics (documented divergences only) or the candidate
stays on the Python fallback. The analyzer remains the authority; plugins
extend what it can accept.

All decisions below were fixed on 2026-07-06 (owner); the record lives in the
project wiki (`decisions-plugin-lowering-2026-07-06`).

## 1. Type system extension: plugin annotation vocabulary

Core's analyzer only resolves types in `rextio.capabilities`. A lowering
plugin registers additional **plugin types** the analyzer can resolve from
annotations:

```python
@dataclass(frozen=True)
class PluginType:
    key: str                      # stable id, e.g. "rextio-numpy/f64-1d"
    annotations: tuple[str, ...]  # dotted spellings that resolve to this type,
                                  # e.g. ("rextio_numpy.types.F64Arr1",)
    rust_type: str                # e.g. "ndarray::Array1<f64>"
    conversion: BoundaryConversion | None = None  # see §4 (None → resident, §4a)
    uses: tuple[str, ...] = ()    # plugin API 1.3: `use` lines this type OWNS
    helpers: tuple[str, ...] = () # plugin API 1.3: module-level items this type
                                  # OWNS (fn/struct/const), deduplicated by text
    device_value_metadata: DeviceValueMetadata | None = None  # plugin API 1.6
```

- **Type-level module support (`uses`/`helpers`, plugin API 1.3).** A
  `PluginType` may declare the exact-text `use` lines and module-level items
  (fn / struct / const) that DEFINE the symbols its `rust_type` or
  `conversion` references. Type-level ownership is required because (a) a
  **resident** type has `conversion=None` yet may still use a plugin-owned
  named Rust type, and (b) a **signature-only accepted function** — one with a
  plugin-typed parameter/return and **zero claims** — renders the type's
  boundary conversion / named native type without ever running `lower()`, so
  its support could not otherwise reach the module. Core collects this support
  from the plugin types that appear **directly** in each accepted function's
  parameters/return and merges it into the same module collectors as
  `LoweredExpr` support (§3): `uses` are deduplicated in a set and **sorted at
  emission**, while `helpers` are deduplicated by exact text in **first-seen
  insertion order**. Deduplication is by exact text — including when the
  identical helper also arrives from a claim. An **unused** registered type emits nothing. Empty support is
  omitted from `PluginType.to_dict()` (a 1.1/1.2 type keeps its exact legacy
  serialized bytes); non-empty support serializes deterministically so
  report/cache identity moves when it changes. Declaring non-empty support
  requires `api_version >= 1.3` (the loader rejects it below 1.3).

- The **primary mechanism is an explicit annotation vocabulary** the plugin
  ships (e.g. `rextio_numpy.types.F64Arr1` / `F64Arr2` — at Python runtime
  these are ordinary aliases of `numpy.ndarray`/`NDArray`, so fallback code
  runs unchanged). Bare `np.ndarray` (no dtype) and `NDArray[np.float64]`
  (no rank) stay unresolved → the function is not a candidate, as today.
- Usage-based dtype/rank **inference is deferred** to a later slice; the spec
  reserves it, the vocabulary is forward-compatible with it.
- A parameter/return annotated with a plugin type makes the function a
  candidate only when the owning plugin is active; otherwise it stays
  fallback (`not-candidate`), never an error.
- Plugin types participate in core's ownership rules; mutation of aliased
  values keeps functions on fallback exactly like core containers.

New protocol member (optional, like all v1.1 members):

```python
def type_vocabulary(self) -> tuple[PluginType, ...]: ...
```

## 2. Two-phase API: claim (analysis) + lower (codegen)

Lowering decisions must be visible in `rextio check` — so the decision runs
at analysis time, separately from emission:

```python
def claim(self, site: ClaimSite, config: RextioConfig) -> ClaimResult: ...
def lower(self, claimed: ClaimSite, ctx: LoweringContext) -> LoweredExpr: ...
# at lower() time the site carries the claim's own rule_id and result_type
```

- `ClaimSite`: one candidate construct — a call, binary operation, or API-1.5
  non-chained comparison
  (`+ - * / % @` — matmul is offered to plugins BEFORE core's arithmetic
  allow-set rejects it, so a plugin may claim `@`; comparison tokens are
  `== != < <= > >=`). One candidate construct
  whose operand/argument types include a plugin type or a covered symbol
  (`covers()` decides which sites are offered to which plugin). Carries the
  resolved operand types and the dotted call target. The source-location
  fields exist on the dataclass but are ZEROED (`file_path=""`, `line=0`,
  `column=0`) for `claim()`/`lower()` calls — the determinism contract lets
  core cache verdicts per site signature, so plugins must not key behavior
  on location. Locations are re-attached by core when reporting.

  **Plugin API 1.2 additive fields** (all optional/defaulted; 1.1 providers
  remain source- and behavior-compatible):

  * `operand_literals: tuple[ClaimLiteral, ...]` — per-positional static
    literal metadata aligned with `operand_types`. A `ClaimLiteral` is
    either non-literal (`is_literal=False`) or a supported static shape
    extracted without executing user code: signed `int` (not `bool`),
    literal `None`, or a tuple of signed ints (NumPy `axis=` work).
    **Literal `None` is distinct from non-literal / absent.**
  * `keywords: tuple[KeywordArg, ...]` — ordered keyword arguments on call
    sites (`name`, optional resolved `arg_type`, and `literal`). A missing
    keyword is simply absent from the tuple; that is distinct from a
    present keyword whose value is literal `None`. Calls with dynamic
    `**kwargs` / unnamed keywords are **not offered** (fail closed to the
    pre-1.2 keyword rejection path). Named keywords with non-literal
    (runtime) values are also **never offered** — current `CallIR`/
    `LoweringContext` cannot represent runtime keyword operands (reserved
    for a future API). API 1.3 additively permits static `bool` and `str`
    constants in **named keyword** `ClaimLiteral` metadata; positional
    `operand_literals` retain the exact 1.2 shape. Floats, bytes, tuple-of-bool,
    tuple-of-string, and every other constant shape remain non-literal.
  * `expression: ClaimExpr | None` — a frozen structured tree of nested
    eligible call/binop nodes, literals, and leaves. Core builds it only
    when the nested structure is representable safely; otherwise the site
    stays flat (fail closed). Leaves carry a `leaf_index` into
    `LoweringContext.leaf_operands` at lower time, and a `leaf_kind` of
    `"name"` (simple `ast.Name`) or `"opaque"` (subscript / other
    non-literal leaf). Fusion providers can accept only `"name"` leaves
    and reject unsafe trees. Numeric `ClaimLiteral` nodes use
    `kind="literal"`, not leaf kinds.

  Claim-cache keys include these fields so sites that differ only in
  keywords, literals, or tree shape never share a verdict. Literal identity
  includes a derived `value_kind`, so Python's `True == 1` rule cannot make a
  bool-keyword site collide with an integer-keyword site. Serialization uses
  `value_kind="bool"` / `"str"` for the 1.3 additions and keeps the exact
  existing `none` / `int` / `int_tuple` forms.
  `ClaimSite.to_dict()` omits empty/absent 1.2 keys so a site built with
  only legacy fields keeps the exact pre-1.2 dict shape.

  **API version gate:** all 1.2 analyzer behavior (keyword offers, claim
  metadata, expression trees, `operand_mode="leaves"`) is restricted to
  providers with `api_version >= 1.2`. API 1.1 providers retain legacy
  semantics: calls with any keyword are never offered; claim/lower sites
  they see have empty 1.2 metadata; codegen never computes `leaf_operands`
  for their claims.

  **Keyword-call policy (fail closed):**

  * `**kwargs` / unnamed keywords are never offered.
  * Named keywords with non-literal (runtime) values are never offered —
    current `CallIR`/`LoweringContext` cannot represent runtime keyword
    operands. Runtime keyword operands are reserved for a future API.
  * Named keywords with supported static literals (`None`, signed int,
    int tuples) are offered only to API ≥ 1.2 providers.
  * Named keywords with static `bool` or `str` values are offered only to API
    ≥ 1.3 providers. In a mixed 1.2/1.3 registry, only the 1.3 providers see
    that call site. Dynamic values, `**kwargs`, floats, bytes, and other
    constants stay unoffered/fail-closed.
  * Positional arguments are inferred before ordered keyword values
    (Python evaluation order).
  * `Claimed` **or** `Rejected` plugin-managed keyword calls suppress
    generic RXT010 (matched by kind + full start/end span). `NotCovered`
    / unoffered keyword calls keep pre-1.2 RXT010/fallback. A plugin
    `Rejected` on a keyword call is deferred and delivered — it must not
    become a silent not-candidate.

  **Expression trees:** root call trees and nested binop / name / literal
  trees only. Nested `ast.Call` nodes are always opaque atomic leaves
  (never expanded). An expression containing opaque/unsafe leaves is not
  eligible for `operand_mode="leaves"`.

  **`Claimed.operand_mode`:** closed set `direct` | `leaves` (default
  `direct`). Only API ≥ 1.2 may return `leaves`; `leaves` requires a
  leaves-safe expression (name leaves / literals / binops only). Invalid
  leaves claims fail closed with `PluginError`.
- `ClaimResult` is one of:
  - `Claimed(rule_id, result_type)` — the plugin will lower this site;
    `rule_id` must be one of the plugin's rule records (enforced: a claim
    with an unadvertised rule id from a describing plugin fails the
    analysis with a PluginError). `result_type` is **required** for
    expression claims: a core type name or a registered plugin type key.
    `None` is **rejected** with `PluginError` (the enclosing expression
    would otherwise stay untyped and the analyzer would report accepted
    for a function it never finished typing). The type must be known —
    core validates it against the core type matrix and the plugin's
    registered type keys. *(Amended during implementation: without a
    required `result_type`, claimed sites were untyped.)*
  - `NotCovered()` — not this plugin's business; core continues as if the
    plugin did not exist (usually → candidate rejection via core rules).
  - `Rejected(diagnostic)` — covered but not lowerable; the RXTP diagnostic
    (with guidance) attaches to the function, which falls back. *(Amended
    during implementation: the rejection is recorded at claim time but
    attached by the boundary pass, mirroring RXT030 — a parse-time error
    would divert explicitly marked functions onto the RXT080 shim and
    silently drop auto candidates, hiding the plugin's guidance.)*
- **Determinism contract (normative):** for identical inputs (site, resolved
  types, config), `claim` MUST return the same result every time it is
  called. Core MAY call `claim` once and cache, or call it in both phases;
  a plugin MUST NOT base the decision on ambient state. `lower` is called
  exactly once per **effective / non-subsumed** claimed site, only for
  functions that stayed accepted. Analysis may still record descendant
  claims under a multi-op tree; when an ancestor claims with
  `operand_mode="leaves"`, those descendant claims are **subsumed** and
  intentionally not lowered (no nested `lower()`, fresh names, helpers, or
  uses from the descendants).
- A function containing a `Rejected` or unclaimable plugin-type site is
  rejected/falls back as a whole (core's usual bottom-up propagation,
  RXT072 unchanged).

## 3. Codegen contract: restricted expression-level output

Plugins emit **expressions, not structure**. Core owns statements, control
flow, temporaries, error propagation, and rendering consistency.

```python
@dataclass(frozen=True)
class LoweredExpr:
    rust: str                        # one Rust expression, no trailing ';'
    uses: tuple[str, ...] = ()       # required `use` lines, deduplicated by core
    helpers: tuple[str, ...] = ()    # module-level helper items (fn/const),
                                     # deduplicated by exact text
```

- `ctx` (`LoweringContext`) is a small, closed surface. It exposes only:

  * `operands: tuple[str, ...]` — rendered Rust sub-expressions for the
    site's direct child operands/arguments (already lowered by core or by
    prior plugin claims), in positional order. Empty under
    `operand_mode="leaves"`.
  * `target_language: str` — the active codegen language id (`"rust"` in
    0.1.x). This is a language id string, **not** an active `TargetSpec`
    object and not a build/profile options bag.
  * `fresh_name: Callable[[str], str]` — allocates a fresh temporary
    identifier in the enclosing function's namespace from a given prefix.
  * `leaf_operands: tuple[str, ...]` (plugin API 1.2; default `()`) —
    rendered non-literal leaves of `ClaimSite.expression` when
    `operand_mode="leaves"`. Empty under `direct`, or when the tree has no
    non-literal leaves.
  * `backend: str = "pyo3"` (plugin API 1.4; closed set
    `{pyo3, standalone-rust}`) — distinguishes host-extension PyO3 emission
    from boundary-free standalone Rust. Old construction remains valid.
  * `artifact_profile: ArtifactProfile | None = None` (plugin API 1.4) —
    the exact resolved profile used for authorization on standalone lowers;
    required when `backend == "standalone-rust"`.

  `LoweringContext` does **not** expose core error-raising helpers, IR
  nodes, or a `TargetSpec`. A plugin-typed operand is handed to the plugin
  as a **bare identifier** (no `.clone()`): the plugin OWNS the
  borrow-vs-consume decision and must add `&` where it borrows. Because
  the same operand can appear more than once at a site (e.g. `a + a`), a
  `lower()` snippet MUST NOT consume (move) an operand — borrow it. A
  consuming snippet on a repeated operand is a `use of moved value` error
  at `cargo build`, so the failure is loud, not silent.

  **Plugin API 1.2 operand modes (never eagerly render both):**

  * `operand_mode="direct"` (default) — only classic direct child operands
    in `ctx.operands`; `ctx.leaf_operands` is always empty. Nested claimed
    children may lower independently (1.1 nesting unchanged).
  * `operand_mode="leaves"` — only non-literal leaves from
    `ClaimSite.expression`, ordered by LTR DFS `leaf_index` **encounter
    sequence** into `ctx.leaf_operands`. The encounter sequence must be
    exactly `0..n-1` (swaps, duplicates, and gaps fail closed). A valid
    all-literal leaves-safe tree yields `ctx.leaf_operands=()` (success,
    not failure). `ctx.operands` is always empty. Nested plugin `lower()`
    is not invoked for intermediate structure (subsumed descendant claims
    stay on the analysis record but are not codegen'd). Fusion-aware
    providers claim an outer multi-op expression (e.g. `a*b + c*d - e`)
    and emit **one** helper from those leaves. Alignment failure fails
    codegen rather than silently nesting. Unknown `operand_mode` values
    fail closed with a codegen error (never coerced to `direct`).
  * **Codegen API-version defense:** even if IR carries 1.2 fields, a
    provider with `api_version < 1.2` always receives a legacy `ClaimSite`
    (empty 1.2 metadata), never gets `leaf_operands`, and cannot lower
    leaves-mode IR.
- Plugin authors emit only through `LoweredExpr` fields: `rust` (one
  expression, no trailing `;`), `uses` (deduplicated `use` lines), and
  `helpers` (module-level items, deduplicated by exact text). Core owns
  statements, control flow, temporary binding of the expression result,
  and how the surrounding function propagates errors.
- **Backend contract (0.1.2):** plugin lowering is **PyO3-extension-only**.
  Codegen runs `lower()` only for the PyO3 extension module; plugin-lowered
  functions are excluded from the pure-Rust importable crate (no
  `RextioError` plugin-lowering path exists today). Fallible plugin output
  must therefore be compatible with the ambient **`PyResult<_>`** and PyO3
  exception types (for example a helper that returns `PyResult<_>`, or an
  expression that uses `?` / `map_err` into a PyO3 error). Core does
  **not** pass error-raising helper callables through `ctx`; plugins write
  the Rust text they need into `rust` / `helpers` / `uses`.
- Exposing core IR to plugins is **deferred**; nothing in this contract
  assumes plugins can see or produce IR nodes.
- **Helper namespacing.** `helpers` items land at module level in one shared
  generated file, deduplicated by exact text. Two plugins emitting a helper
  with the same name but different text collide loudly at `cargo build`
  (duplicate definition) — deliberate: a silent merge would pick one plugin's
  semantics for both. To stay collision-free, prefix helper names with your
  plugin id, e.g. `fn __rextio_numpy_dot_f64(...)`.
- **Debugging plugin-emitted Rust.** The generated crate is kept on disk
  under the project's `.rextio/build/` tree; when a plugin's emission
  misbehaves, read the generated `src/lib.rs` there and run `cargo build`
  directly in that directory for full rustc diagnostics. `rextio build`
  surfaces codegen/build failures with the owning plugin id (see section 7);
  the emitted expression appears verbatim in the generated function body, so
  rustc's spans point into your `LoweredExpr.rust`/`helpers` text.

## 4. Boundary ABI: read-only in, owned out, no aliasing

How plugin types cross the Python↔Rust boundary of a generated PyO3
function:

```python
@dataclass(frozen=True)
class BoundaryConversion:
    param_rust: str    # PyO3 parameter type, e.g. "numpy::PyReadonlyArray1<'py, f64>"
    param_expr: str    # expression producing the owned/borrowed native value,
                       # e.g. "{param}.as_array()"
    return_rust: str   # PyO3 return type, e.g. "pyo3::Bound<'py, numpy::PyArray1<f64>>"
    return_expr: str   # expression converting the native result for Python,
                       # e.g. "numpy::ToPyArray::to_pyarray(&{value}, py)"
```

`param_expr` and `return_expr` are `str.format` templates (placeholders
`{param}` / `{value}`), so any literal `{`/`}` in the Rust text — closures,
struct literals, blocks — must be doubled (`{{` and `}}`) or formatting
raises `KeyError`/`ValueError` at codegen.

Normative rules for the initial surface:

- Arguments cross the boundary as **read-only PyO3 views**; generated code
  never mutates the caller's array in place. The plugin's ``param_expr``
  decides what the function body actually operates on — in the initial
  surface it is an **owned copy** (``as_array().to_owned()``), NOT a borrow:
  every plugin-typed argument pays an O(n) materialization per call,
  including arguments the body never reads. Plugin authors designing around
  a "borrow" mental model will silently inherit that copy cost.
  (For numpy: float64 1-D only; statically known mismatches are rejected at
  analysis. **Non-contiguous (strided) arrays are accepted**: the read-only
  view honors strides and the conversion materializes a contiguous owned
  copy — certified behavior since round 4. A runtime value that violates the
  declared plugin type — wrong dtype, wrong rank — raises the PyO3
  conversion error in native mode; it does NOT fall back per call. Treat it
  as a runtime type-contract violation, like passing a str to an int-typed
  native function. A per-call conversion-failure fallback may be added
  later.)
- Returns transfer ownership of **newly allocated** values.
- Plugin types NEVER cross the internal scalar boundary-call path (RXT075)
  and are never delegated by the Rust-executable dispatcher — the existing
  "containers never cross" rule extends to plugin types verbatim.

## 4a. Resident types and native-to-native chaining (plugin API 1.3)

A **resident** plugin type is a `PluginType` whose `conversion is None`
(`PluginType.is_resident`). It is an *opaque, native-only* Rust value: it has
**no Python boundary conversion** and therefore **never crosses an exported
PyO3 parameter or return**. It exists only inside generated native code and
enables **safe native-to-native chaining** — a value produced by one claim can
be stored in a local, handed to an accepted native helper, and consumed by
another claim, with no Python round-trip. Existing materialized types (with a
`BoundaryConversion`) are unchanged and remain source/behavior compatible.

Normative rules for the 1.3 resident-type contract (static claim metadata
in §9 completes the same surface):

- **Declaration.** A resident type sets `conversion=None`. A plugin declaring a
  resident type MUST advertise `api_version >= 1.3`; the loader rejects a
  resident type from a lower-versioned provider (`PluginError`). `rust_type` is
  the value's exact native representation (e.g. `petgraph::Graph<...>`), used
  verbatim in native signatures. The IR carries it as
  `RxtPluginType(resident=True)`; `RxtPluginType.resident=False` is the
  materialized form. API 1.5 adds the narrower result-only form:
  `annotations=()` is accepted only for a resident type from a provider
  advertising API 1.5 or newer. It remains available by key to claim chaining
  but is absent from source-annotation maps. A direct return or inferred
  parameter/return signature is rejected as RXT092; it must be consumed by a
  later claim inside the same native body. Every materialized type and every
  pre-1.5 resident type must declare an annotation spelling.

- **Production / storage / consumption.** A resident value is produced by a
  claimed plugin expression whose `Claimed.result_type` is the resident type
  key, stored in an ordinary local (the analyzer types the local with the exact
  key), passed as a positional argument to another claimed plugin expression,
  or passed to an **accepted native helper** call. It is handed to plugin
  `lower()` as a bare identifier (the plugin owns borrow-vs-consume, as for
  materialized operands); native-to-native calls pass the value **by shared
  reference** — a resident parameter lowers to `&T` and an argument is borrowed
  (`&value`), never moved and never cloned (a resident type need not be
  `Clone`). Because the argument is only borrowed, the caller keeps ownership
  and MAY reuse the value, pass it to another helper, or pass it twice in the
  same call; a `g = new(...); g2 = helper(g, ...)` chain that then consumes both
  `g` and `g2` is well-formed native code, not a use-after-move.

- **Native-to-native signature compatibility.** The boundary pass understands
  registered plugin type keys and exact Rust representations. A native call
  into a helper whose parameters/return are resident is permitted; the
  positional-arity, keyword-only, scalar, and container checks are preserved,
  and a resident parameter requires the caller's argument to carry the **exact
  same** registered type key (any core value, different plugin type, or
  undetermined type keeps the caller on the Python fallback, RXT010).

- **Fail-closed escape rules (RXT092 where it is the appropriate existing
  diagnostic).** A resident value MUST NOT escape through:
  * an **exported PyO3 parameter/return** — a resident-signature function is
    compiled as an internal, non-`#[pyfunction]` native-only helper and gets no
    Python-dispatch wrapper; an **explicitly `@rextio.native`-marked**
    resident-signature function (a request for a Python-callable native export
    a resident boundary cannot honor) is rejected with **RXT092**;
  * a **materialized** plugin-typed callee — native calls into a function whose
    signature carries a materialized plugin type stay **RXT092** (Python-facing
    entry points), unchanged;
  * a **fallback / delegate / scalar-boundary / runtime-shim** edge — those
    paths admit only immutable delegatable scalars, so a resident value is
    never eligible (fail closed);
  * an **unsupported container** — a resident type nested in a
    list/dict/set/tuple annotation does not resolve as a core type, so the
    function is simply not a candidate (fail closed).

- **Ownership.** The ownership contract is **immutable shared borrow**: a
  resident value crosses a native-to-native call as `&T`, so ownership stays
  with the producer and reuse is well-defined (the caller may consume the value
  again or pass it to further helpers). No raw pointers, unchecked lifetime
  extension, `unsafe`, global caches, silent clones, or Python-object leakage
  are introduced to make chaining pass. Patterns the borrow contract cannot
  honor without a second owner are rejected **before codegen** and stay on the
  Python fallback — never allowed to surface as a compiler error:
  * returning a resident **parameter** (or an alias of one) by value, which the
    fallback would return by identity while the native leg would need an owned
    copy — rejected by the plugin alias-escape check;
  * aliasing a resident value into another binding (`g2 = g`), which would need
    a `.clone()` (a resident type need not be `Clone`) or a move that invalidates
    the original — rejected during signature inference.

  A compiler error is a bug in this contract, not the contract itself.

- **Routes / crates.** A resident-signature or resident-claiming function keeps
  the `native-plugin:<id>` route and the `native_status=accepted` /
  boundary-fallback-exemption posture of §7. Crate injection, generated
  imports, and helpers stay deterministic and deduplicated (§3, §5).

## 5. Crate dependency injection: pinned, consented, reported

```python
@dataclass(frozen=True)
class CrateDependency:
    name: str          # "ndarray"
    version: str       # exact pin REQUIRED, e.g. "=0.16.1"
    features: tuple[str, ...] = ()
```

New optional protocol member: `def crate_dependencies(self) -> tuple[CrateDependency, ...]`.

Normative rules (all REQUIRED by this spec):

- **Version pins are mandatory.** A dependency without an exact `=X.Y.Z` pin
  fails plugin load (PluginError). A Cargo lockfile is NOT required. Two
  plugins may pin the same crate at the same version; core merges them into
  one manifest entry with the union of their feature sets.
- **User consent:** plugin-injected crates are compiled only for plugins the
  user explicitly enabled (`[plugins] enabled` / `--enable-plugin`) — and the
  first build after a plugin's dependency set changes surfaces the injected
  crates in the build output (not silently).
- **Report exposure:** `build.json` (and the build text report) lists every
  plugin-injected dependency as `{plugin_id, name, version, features}`.
- Conflicts (two plugins pinning the same crate to different versions, or a
  plugin colliding with a core-generated dependency) fail the build up front
  with a configuration-style error (RXT060 posture). The core-generated
  manifests reserve these crate names, which plugins may not declare:
  ``base64``, ``chrono``, ``log``, ``pyo3``, ``sha2``, ``serde``,
  ``serde_json`` (the loader enforces the list — ``CORE_CRATE_NAMES``).
  ``serde``/``serde_json`` are not in the extension crate's manifest today;
  they are reserved because the hybrid executable's core-generated binary
  crate declares them for the delegated-call wire protocol.

## 6. Verification: the plugin certification kit

Core ships a reusable equivalence harness (`rextio.plugins.testing`,
name provisional): given a project fixture and a set of inputs strategies,
it builds twice (native on / `REXTIO_NATIVE_MODE=fallback`) and asserts
result equivalence with hypothesis — the same posture as core's own
`tests/e2e` property tests.

- A lowering rule record SHOULD reference its certification status; rule
  records gain an optional `verified: bool` field (L2-compatible, additive).
  When a rule's documented divergence makes bit-exact comparison impossible
  (e.g. summation order), certification MAY use a tolerance-based comparator,
  and the rule's `constraint` MUST state that tolerance — `verified` then
  means "certified within the stated tolerance", not bit-equivalence.
- Divergences must be documented per rule in `constraint` (the float
  summation-order divergence in RXTP-NUMPY-002/003 is the model) and follow
  the RXT090 posture: statically attributable ones may carry a per-function
  note.
- First-party plugins MUST run the kit in CI; third-party plugins are
  strongly recommended to (the manifest's `verified` field is their signal).

## 7. Routes, policies, and failure flow

- A function with ≥1 plugin-claimed site OR a plugin-typed parameter/return
  gets route `native-plugin:<id>` (even if other sites lowered through core
  rules) — a signature-only plugin function still needs the plugin's boundary
  conversions and crates. `native_status` stays `accepted`. A signature-only
  accepted function (plugin-typed parameter/return, **zero claims**) never runs
  `lower()`, so the `use`/helper items that DEFINE its rendered conversion /
  named native type come from the signature plugin types' **type-level module
  support** (`PluginType.uses`/`helpers`, §1), collected from the types that
  appear directly in the signature and deduplicated against any `LoweredExpr`
  support before the module prelude is rendered. Native-to-native
  calls INTO a **materialized** plugin-typed function are rejected (RXT092):
  materialized plugin-typed functions are Python-facing entry points. A
  **resident**-only function (plugin API 1.3, §4a) is exempt — it is an
  internal native-only helper, so native-to-native calls into it are permitted
  under the extended signature-compatibility check.
  Every `native-plugin` function (by claims OR type keys) is **exempt from the
  boundary-fallback threshold**: it never flips to the Python fallback leg
  mid-run, because the native and fallback legs may have documented per-leg
  divergences (e.g. a native builtin `float` vs NumPy's `float64`) and switching
  mid-run would silently change observable behavior.
- Overlapping claims: if two active plugins both return `Claimed` for one
  site, core fails loudly (PluginError naming both plugins). Priority
  systems are deferred.
- Plugin codegen or crate compilation failure demotes exactly like core
  failures (RXT050/RXT060 posture): the candidate falls back; the build
  reports the cause. Generated wrappers keep their warn-and-fallback runtime
  behavior, so a broken native module never breaks the program.
- `[imports.packages] "<pkg>" = {policy="plugin", plugin="<id>"}` now has
  teeth: it routes covered sites to that plugin's claim path. The RXT091
  hint on accelerator-decorated functions is unchanged (decorator still
  wins: explicit decorator > plugin > fallback).

## 8. Versioning and rollout (released 1.2 / 1.3 / 1.4)

- `PLUGIN_API_VERSION` bumps **1.0 → 1.1** for the lowering members; all new
  members are optional, so 1.0 describe-only plugins keep loading (major
  must still match). A plugin that implements `lower` without `claim` (or
  vice versa) fails load.
- **Plugin API 1.2** (additive, same major): extends `ClaimSite` with
  `operand_literals` / `keywords` / `expression` and `LoweringContext` with
  `leaf_operands`. Defaults keep 1.1 providers source- and
  behavior-compatible. Plugins may still declare `api_version = "1.1"`.
- **Plugin API 1.3** (additive, same major; published with core **0.1.3** on
  2026-07-17): adds **resident** types (`PluginType.conversion` is now
  optional; `conversion=None` marks an opaque, native-only value), safe
  native-to-native chaining (§4a), orthogonal static receiver/callable-body/
  schema metadata (§9), and bool/string static named keyword literals.
  Defaults and per-provider projection keep 1.1/1.2 providers source- and
  behavior-compatible; a resident type and every 1.3 metadata addition
  require `api_version >= 1.3`. Core 0.1.3 and 0.1.4 advertised
  `PLUGIN_API_VERSION = "1.3"`. API 1.3 remains Experimental.
- **Plugin API 1.4** (additive, same major; published with core **0.1.5** on
  2026-07-23): adds the optional fail-closed standalone artifact capability for
  exact `rust-crate` / `host-executable` profiles. Core advertises
  `PLUGIN_API_VERSION = "1.4"`; older 1.x providers keep their projected legacy
  shapes. API 1.4 remains Experimental.
- **Plugin API 1.5** (additive, same major; published as part of core **0.1.6**
  on 2026-07-26): adds non-chained
  comparison claims and result-only resident vocabulary entries. A result-only
  entry uses `conversion=None` and `annotations=()`: it is registered only by
  stable key and can flow from one claim into another, but source annotations
  cannot name it. Codegen rechecks that every `compare` claim still has an
  API-1.5 provider, guarding against stale IR/provider-version drift.
- **Plugin API 1.7** (additive, same major; published with core **0.1.7** on
  2026-07-27): optional `function_scope_guard(ctx)` for used plugins; Core-owned
  let-bound RAII guards; capabilities presence `function_scope_guard_declared`.
- **Plugin API 1.6** (additive, same major; published with core **0.1.6** on
  2026-07-26): adds optional
  structured static device-value metadata to `PluginType` and a defaulted
  `LoweringContext.device_authorization`. Used accepted accelerator types
  determine exact artifact device/runtime requirements. Provider resolution
  and preflight must succeed before an API-1.6 lowerer receives the minimal
  authorization; no selection, a wrong backend/capability, a conflicting
  domain, or an unauthorized claim fails closed. API 1.1-1.5 providers never
  receive a non-`None` authorization.
- Everything in the 1.1 surface ships in the **0.1.1 line** as Experimental.
  The 1.2 claim metadata / fusion tree surface ships on the **0.1.2** core
  line without a package major bump (Wave 2 core gate; Wave 3 package
  release is separate). The 1.3 resident/chaining/metadata surface ships on
  the **0.1.3** core line without a package major bump. The 1.4 standalone
  artifact-capability surface ships on the **0.1.5** core line. The 1.5
  comparison/result-only-resident surface and 1.6 device-domain authorization
  surface ship together on the **0.1.6** core line.
- **Related-package publish order** for the 1.2 consumer surface (strict, not
  simultaneous): **rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1**. The
  published rextio-numpy 0.1.1 (literal-axis / fusion / leaves-mode) requires
  core plugin API 1.2. That order completed on 2026-07-14. Core **0.1.3**
  (plugin API 1.3; tooling contract **2.1.0**, additive over core 0.1.2's
  contract **2.0.0**) published on 2026-07-17. See
  [tooling-contract.md](tooling-contract.md) §Compatibility and release
  ordering.
- Implementation slices, in order:
  1. Plugin API additions (`PluginType`, `ClaimSite`/`ClaimResult`,
     `LoweredExpr`, `BoundaryConversion`, `CrateDependency`) + loader
     validation + API version 1.1.
  2. Analyzer integration: plugin type resolution + claim pass + route
     `native-plugin:<id>` + report fields.
  3. Codegen/build integration: lower() emission, crate injection with
     consent/report rules, failure demotion.
  4. Certification kit + the agreed vertical slice in rextio-numpy:
     `numpy.dot(a, b)` on float64 1-D end to end (claim → lower → ndarray/
     rust-numpy injection → cargo build → hypothesis equivalence).
  5. **Wave 2 (1.2):** claim-site literal/keyword metadata, structured
     `ClaimExpr` trees, fusion `leaf_operands` at lower, additive docs/tests.

## 9. Static claim metadata surfaces (plugin API 1.3)

Plugin API 1.3 defines three orthogonal, deterministic, **static** metadata
surfaces carried on the claim site. Every record is frozen,
hashable/cache-safe, order-preserving, and JSON-serializable through
`to_dict()`. None ever carries raw source text, mutable AST nodes,
closures/globals, or a value produced by executing user code — they are derived
only from resolved types and a documented static grammar. All are additive,
defaulted `ClaimSite` / `PluginClaim` fields (and one `LoweringContext` field),
so 1.1/1.2 providers keep the exact pre-1.3 serialization shape and never
observe the new metadata (stripped by `_site_for_provider` below api 1.3).
Claim-cache keys include `receiver` and `callables`, so sites that differ only
in the 1.3 metadata never share a verdict.

### 9.1 Method receiver metadata — `ClaimSite.receiver: ReceiverMeta | None`

A method claim site (`obj.method(...)`) distinguishes the receiver *value* from
the ordinary positional arguments. The positional args stay in `operand_types`;
the receiver never appears there. `ReceiverMeta` carries:

- `arg_type: str | None` — the receiver's resolved type (plugin type key or
  core type name; `None` when unresolved).
- `schema: SchemaMeta | None` — the receiver type's declared schema (§9.3) when
  one is registered; `None` otherwise.
- `expr_kind: str` — the receiver expression shape, one of
  `name | attribute | subscript | call | opaque`.
- `is_safe: bool` — whether the receiver is a side-effect-free reference. Only
  a plain local `name` is intrinsically safe: an `attribute` access can fire a
  descriptor `__get__` or `__getattr__`, a `subscript` invokes `__getitem__`,
  and `call`/`opaque` evaluate user code, so every non-name receiver is unsafe.
  Core **always** evaluates the receiver exactly once in Python order
  regardless; `is_safe` only tells a provider whether the rendered receiver
  text (`LoweringContext.receiver`) is a bare reference or a bound single-use
  temporary.

A method call is detected when `node.func` is an attribute access whose base
resolves to a value type; the method name is the last segment of `target`. A
module-qualified call (`numpy.dot(...)`: the base `numpy` has no value type) has
no receiver. A plugin-typed receiver makes the site that plugin's business even
when no positional arg carries the type. At lower time,
`LoweringContext.receiver` is the receiver rendered once in Python evaluation
order.

### 9.2 Callable metadata — `ClaimSite.callables: tuple[CallableMeta, ...]`

For a callable argument that resolves to a project function, `CallableMeta`
exposes only immutable structured facts:

- `arg_index: int` — the callable argument's positional index at the site.
- `qualname: str` — the resolved project-function qualname.
- `params: tuple[CallableParam, ...]` — ordered typed signature.
- `return_type: str | None` — resolved return type.
- `accepts_native: bool` — the function is a proven accepted scalar native
  function (a direct native-callable UDF).
- `runtime_semantics: bool` — it carries the RXT080 runtime-shim semantics.
- `native_symbol: str | None` — the codegen-resolved native Rust symbol when
  one exists (filled at lower time; `None` at claim time).
- `body: CallableBody` — a closed body representation, or an explicit
  unavailability.

`CallableBody` is either `available=True` with a closed `CallableBodyExpr`
tree, or `available=False` with an `unavailable_reason` (and no expression).
The **closed body grammar** (`CallableBodyExpr`) covers only the safe
scalar/simple-row UDF subset: parameter reads (`param`), supported scalar
literals (`literal` / `ScalarLiteral`, int/float/bool/str/None only),
schema-bound field/subscript reads (`field` / `subscript`), unary/binary/
boolean/comparison operations (`unary`/`binop`/`boolop`/`compare`), the
conditional expression (`cond`), and already-supported pure scalar calls
(`call`). Everything else — statements, mutation, loops, comprehensions,
attribute side effects, globals, closures, dynamic-valued defaults, varargs,
kwargs, async/generator/yield — is **unavailable** (a body with
`available=False`), and a claim that needs a body MUST fail closed on an
unavailable body rather than guess. Internal AST objects are never exposed;
the closed record is the only representation.

### 9.3 Declared schema metadata — `SchemaMeta` / `SchemaField`

An immutable, ordered schema identity (`identity`) and fields (`name` plus a
resolved scalar/plugin `field_type`), derived only from the documented static
annotation grammar by `build_declared_schema(identity, class_node,
resolve_type)`. The grammar: a schema class body contains ONLY simple field
annotations `name: <type>` (an optional leading string docstring and bare
`pass` are permitted); each annotation must resolve, through the caller's
`resolve_type`, to a core scalar type name or a registered plugin type key.
Pandas runtime objects are never inferred and the annotation is never executed.
The builder fails closed with `SchemaGrammarError` (the analysis-time caller
treats that as "no schema") on: unsupported metadata (any non-annotation
statement, methods, nested classes, assignments), a field default/value,
a non-`Name` target, a dynamic annotation expression (one containing a call),
an unresolved type, or a duplicate field name. `SchemaMeta` re-checks duplicate
names as a construction-time invariant.

**Association spelling (exact source form).** A declared schema is associated
with a receiver/parameter through a **schema-parameterized plugin annotation**:
the plugin's base type annotation subscripted by a schema class. A schema is a
plain project class whose body is only field annotations, and the parameter is
annotated with `Base[Schema]`:

```python
class Row:                      # the schema: only `name: <type>` fields
    price: float
    qty: int

def kernel(df: Frame[Row]) -> float:   # Frame[Row] associates Row with df
    return df.apply(udf)
```

`Frame[Row]` resolves to the **same** plugin type key as bare `Frame` — the
`[Row]` subscript only carries the schema association and never changes type
resolution (`resolve_annotation` strips the subscript; every existing
signature/return/local type path is preserved). During project analysis the
schema class is discovered (project-wide, order-independent), built statically
by the grammar above, and associated with the annotated parameter in
`FunctionAnalysis.declared_schemas`. It then propagates to the method receiver's
`ReceiverMeta.schema` and, for a row UDF (an unannotated first callable
parameter), binds that parameter so `row["col"]` / `row.col` reads in the
callable body resolve to typed `subscript` / `field` nodes. A malformed,
dynamic, unresolved, or duplicate schema fails closed to **no association** (a
well-formed schemaless receiver), never a wrong schema. rextio-pandas consumes
`ReceiverMeta.schema` and the row-param field/subscript body nodes directly.

When annotations are evaluated at module load (no postponed-annotations
future), subscription normally invokes an arbitrary protocol hook. Core exempts
only a subscript whose base resolves at that exact source position to an
annotation target in the active, validated plugin type vocabulary and whose
target has no source-visible mutation or same-spelling project module. The
trusted target set travels with the shared `ModuleBindings` authority into
IR/wrapper source revalidation. A local same-spelling class, a project-owned
module shadowing the plugin package, a rebound/import-ambiguous alias, a mutated
plugin target, an unregistered `Evil[T]`, nested unsupported subscription, or
an effectful slice remains fail-closed. `from __future__ import annotations`
follows Python's normal postponed-evaluation rule and executes no subscription
at module load.

### 9.4 Integration contract for method claim sites

From one method claim site a 1.3 provider can determine: the receiver Rust
operand (`LoweringContext.receiver`), type, and schema (`ClaimSite.receiver`);
the ordered call args (`operand_types` / `operand_literals`) and literal
keywords (`keywords`, including API 1.3 static bool/string values); whether the
UDF is a proven accepted scalar native function
(`CallableMeta.accepts_native`) or has a supported closed row-UDF body
(`CallableMeta.body.available`); its native symbol/body
(`CallableMeta.native_symbol` / `body`); and the exact output scalar type
(`Claimed.result_type`, echoed on the claim). Receiver/callable evaluation
order and single evaluation match Python.

**Analysis wiring.** A callable argument that is a bare name/dotted reference
statically resolving (through the caller's imports/aliases) to an indexed
project function is offered as a `CallableMeta`; core recognizes it at a
plugin-covered site and does **not** reject the enclosing function for reading
an unbound value (the callable never becomes a Rust local). `accepts_native` is
a static determination over the documented scalar subset: every parameter and
the return resolve to a core scalar, the body is representable in the closed
grammar, and it carries no runtime-shim semantics — a row UDF (schema-bound
first parameter) is `body.available` but not `accepts_native`. `runtime_semantics`
is set (and the body left unavailable) when the resolved function calls a
CPython runtime-fidelity target.

**Codegen wiring.** `PluginClaimIR` carries the receiver/callable metadata and
`CallIR.receiver` carries the lowered receiver sub-expression (never a positional
argument). At lower time core: (1) fills `CallableMeta.native_symbol` for a
callable that is `accepts_native` **and** whose qualname names an actually-
generated accepted native helper in the module — every other callable keeps
`native_symbol=None`, so the plugin uses the closed body or fails closed; and
(2) evaluates the receiver **exactly once, before the operands** — a safe
receiver (a plain local name) is passed through as a bare reference, and any
non-safe receiver is bound to a fresh single-use temporary
(`let __rextio_recv = …;`) whose name is handed to the provider as
`LoweringContext.receiver`, so a descriptor/`__getattr__`/`__getitem__`/call in
the receiver runs once. This preserves the resident-borrow semantics (§4a): a
resident receiver is borrowed by the provider, never moved or cloned.

### 9.5 Executable identity and source-order safety

All 1.3 metadata and generated code consume one project-wide source-order
authority. Raw spelling is never proof that `@native`, `@exempt`, a callable
argument, imported target, class, or method still names the object analyzed.
Final bindings, every re-export/alias hop, qualified parent and descendant
mutations, module-load effects, and the exact definition origin must agree.
Unknown execution or ownership routes fail closed to a rejection, runtime shim,
or Python fallback.

Class methods are limited to stable plain classes. Class decorators, custom
bases/metaclasses, arbitrary descriptor-bearing namespace values, class-body or
post-class member replacement/deletion, and construction hooks are not eligible.
IR and wrapper generation re-read the source and require the analyzed function's
semantic AST fingerprint; generated method installation additionally verifies
the runtime fallback owner and function identity before replacement. A mismatch
is a build/import error, never permission to install stale native code.

The proof covers mutations visible in the analyzed project during module
execution, including executed local callables, consumed generators, implicit
protocol hooks (including module-load operators, subscripts, attributes,
formatted strings, and comprehensions), stdlib/builtin targets (including
`builtins.__build_class__`), logger receivers/aliases, marker internals, and
package-resolved relative re-exports. Exact tuple/list destructuring aliases are
tracked; starred, mismatched, or dynamic unpacking fails closed. Mutation
performed externally after wrapper import remains a documented dynamic
limitation and is outside the static contract.

Exact project callables are replayed with the globals visible at the relevant
source-order execution point. Calls made while a circular import has suspended
the defining module use that cycle-edge environment; ordinary calls use the
final environment. A deliberately narrow return summary carries exact project
roots, immutable scalars, conditional unions, bound defaults, and logger
factory identities into subsequent assignment or mutation expressions.
Unknown/dynamic return identities and external calls exposed to project roots
or a module globals dictionary poison the affected mutation authority, including
roots nested in literal containers or deferred generator yields. Container
return aliases are never flattened into fabricated subscript paths: without a
closed structural summary they widen at their rooted owner. Source constructors
and builtins that can dispatch Python protocol hooks require a closed effect
proof; post-definition constructor replacement revokes that proof, and an
instance with source protocol hooks becomes unknown on its first later use.
Executed callables containing ``nonlocal`` also widen because closure cells are
not modeled. Builtin and ``logging.getLogger`` fast paths consult a monotone
project-wide mutation fixed point, so scan order cannot preserve stale purity.
Zero-argument ``vars()`` is module authority only at module scope and remains a
local namespace inside an executed function.

Generated Python dispatch state has no reserved user-name namespace. Native and
fallback bindings, factories, wrappers, and method-installation helpers are
created in an isolated bootstrap scope under ordinal local slots. The source
namespace (including explicit ``__all__`` entries with any ``_rextio_*``
spelling) and native top-level updates are published only after closures and
methods are ready; accepted top-level dispatch functions are installed last.
RXT080 originals are captured as an ordinal mapping in a separate runtime
registry, never as generated attributes on the fallback or public module.
Native top-level update keys are reconciled with the exact final source binding
before terminal publication, so a later function/class defeats an earlier
assignment and a later accepted assignment defeats the earlier definition.

## 10. Standalone artifact capability (plugin API 1.4)

Host-extension builds (PyO3 wheels) keep using the 1.1–1.3 lowering members and
boundary conversion. Boundary-free standalone artifacts — **`rust-crate`** and
**`host-executable`** — never infer plugin support from those surfaces.

The strict artifact-contract Alpha is not a standalone-plugin profile. It accepts
only a plugin-free, core-owned PyO3 host-extension path and does not call this
section's hook. Its installed-host input must be cache-free and bounded: no
`__pycache__`/`.pyc` among the `rextio/` RECORD members or physical package
tree, no unrecorded package-tree member, and no more than 256 MiB by both the
pre-walk `rextio/` RECORD declared-size aggregate and the independently
checked actual `stat`/read aggregate. This is an evidence-integrity contract
for an owner-controlled process, not hostile-process secure boot. The
domain-separated detached-signature and seven-file atomic-publication
contracts likewise do not widen plugin API 1.4 or make an
`artifact_capability()` declaration authoritative. The plugin-free macOS arm64
installed-wheel lifecycle is certified by the final local real-E2E at
`f9eb5e6`; the subsequent byte-budget hardening is unit-tested, and
evidence for the current `HEAD` on macOS arm64 plus Linux x86_64 for the 2.24.0
support-lock/sandbox changes requires manual host validation and is not
CI-certified. This result
does not certify or widen any plugin-bearing strict artifact profile.

### 10.1 Explicit hook (separate extension Protocol)

```python
class RextioArtifactCapabilityPlugin(Protocol):
    def artifact_capability(
        self, profile: ArtifactProfile
    ) -> PluginArtifactCapability | None: ...
```

- Optional. Presence requires `api_version >= 1.4` **and** a lowering provider
  (loader fail-closed). Describe-only providers may not declare the hook.
- Defined on a **separate** Protocol from `RextioLoweringPlugin` so inheriting
  the legacy lowering Protocol does not create a callable stub. Core detects a
  concrete (non-Protocol) implementation only.
- Absence is valid and means **standalone unsupported** for every profile.
- **Not** part of the all-or-none set
  (`type_vocabulary` / `claim` / `lower` / `crate_dependencies`).
- Core never infers standalone support from `PluginType.conversion`, resident
  status, host-extension `uses`/`helpers`, or `crate_dependencies()`.

### 10.2 Capability records

```python
@dataclass(frozen=True)
class PluginArtifactTypeSupport:
    type_key: str                 # exact namespaced key, e.g. "rextio-numpy/f64-1d"
    uses: tuple[str, ...] = ()    # profile-specific `use` lines
    helpers: tuple[str, ...] = () # profile-specific module items

@dataclass(frozen=True)
class PluginArtifactCapability:
    rule_ids: tuple[str, ...] = ()
    types: tuple[PluginArtifactTypeSupport, ...] = ()
    crate_dependencies: tuple[CrateDependency, ...] = ()
```

Core validates namespace ownership (`<plugin_id>/…`), membership against the
plugin's actual `describe()` rule records and `type_vocabulary()` keys (stale
but correctly namespaced values fail closed), duplicate rule/type keys,
malformed return values, reserved core crate names, and conflicting pins.
Duplicate uses/helpers/deps are canonicalized deterministically. Hook
exceptions and invalid declarations raise `PluginError` (CLI surfaces as
stable `RXT060`; programmatic paths remain fail-closed). Records serialize
deterministically (sorted rule ids, type keys, crate deps).

### 10.3 Resolution and coverage

Capability is resolved **exactly once per exact** resolved `ArtifactProfile`
per generate/build command (`rextio.plugins.capabilities`). The immutable
`StandalonePluginContext` is reused for closure, codegen, dependency
selection, and JSON serialization — reports never re-call the hook.

A function is standalone-capable only when **every** plugin claim rule id and
**every** plugin type key it uses is covered: signature `plugin_type_keys`
**plus** claim `operand_types`, `result_type`, and receiver type when present.
Missing or partial coverage excludes the function (planning and codegen
defense-in-depth). Rejected/fallback functions never appear in
`capable_functions`. Standalone reports include deterministic per-function
decisions (`qualname`, `supported`, used/missing rule ids and type keys,
`denial_reason`). Existing `route` / `native_status` and legacy
`PluginType.to_dict()` byte shapes are unchanged.

### 10.4 Codegen and cargo

`LoweringContext` gains defaulted API 1.4 fields (host-extension construction
unchanged):

* `backend: str = "pyo3"` — closed set `{pyo3, standalone-rust}`
* `artifact_profile: ArtifactProfile | None = None` — exact resolved profile
  for standalone lowers; required when `backend == "standalone-rust"`

In standalone Rust mode, capable plugin-lowered functions render with **native
Rust types only** (no PyO3 boundary conversion). Only profile-declared uses/
helpers may be emitted; a second codegen assertion rejects undeclared support
from `lower()`. Profile-specific exact crate dependencies are collected only
from functions **actually emitted after transitive exclusion** (a capable
plugin function that calls an unsupported plugin function is excluded and must
not inject deps when an independent core function remains). Unsupported
reachable plugin functions are pre-Cargo closure blockers for native-only
executables; unreachable ones do not block. Rust executable CLI preflight uses
the same capability-aware closure / precomputed context so a valid plugin
executable is not misclassified as unavailable.

### 10.5 Introspection vs generate/build

- `rextio capabilities` reports additive `artifact_capability_declared`
  presence only. It must **not** probe the host or execute profile hooks.
- `generate` / `build` JSON may include resolved
  `standalone_plugin_capabilities` allow/deny details (including
  `function_decisions`) for requested profiles, serialized from the
  already-resolved context.
- `lowering_provided` semantics are unchanged.

### 10.6 Deferred positive host-executable vertical slice

The contract, resolver, closure blockers, and codegen path are shared with
host-executable profiles. A full positive end-to-end host-executable
integration (entrypoint + plugin-capable call graph + cargo binary) may still
be expanded beyond the rust-crate positive vertical slice; until then,
unsupported or undeclared plugin reachability remains fail-closed pre-Cargo.

## 11. Function-scope RAII guards (plugin API 1.7)

Optional, independent of the all-or-none lowering members
(`type_vocabulary` / `claim` / `lower` / `crate_dependencies`), but still
requires a lowering-capable provider.

```python
@dataclass(frozen=True)
class PluginFunctionScopeContext:
    function_qualname: str
    used_rule_ids: tuple[str, ...]     # unique sorted; this plugin only
    used_type_keys: tuple[str, ...]    # unique sorted; this plugin only
    backend: str                       # "pyo3" | "standalone-rust"
    artifact_profile: ArtifactProfile | None = None  # standalone only
    has_python_boundary_calls: bool = False  # exact RXT075 FunctionIR fact

@dataclass(frozen=True)
class PluginFunctionScopeGuard:
    rust: str                          # zero-argument path call (see grammar)
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()

class RextioFunctionScopeGuardPlugin(Protocol):
    def function_scope_guard(
        self, ctx: PluginFunctionScopeContext
    ) -> PluginFunctionScopeGuard | None: ...

# Additive field on the per-claim context handed to this provider's lower():
LoweringContext.function_scope_guard_active: bool = False
```

**Exact ``rust`` grammar (fail-closed):**

```text
PATH_CALL ::= IDENT ( "::" IDENT )* "()"
IDENT     ::= [A-Za-z_][A-Za-z0-9_]*
```

Accepted: `tch::no_grad_guard()`, `AlphaGuard::enter()`, `enter()`.
Rejected: arguments (`Guard::enter(x)`), macros (`panic!()`), blocks,
operators, method chains (`.`), `?`, statements, bare identifiers, and any
parameter-dependent form.

- Presence requires `api_version >= 1.7` and a lowering provider (loader
  fail-closed). Protocol stubs do not count as concrete declarations.
- Core calls the hook only for plugins **used** by an accepted generated
  native function (owned claim rule ids and/or directly used namespaced type
  keys, including claims nested under dict items, comprehension generators,
  and try handlers). Unused installed plugins are excluded. Usage facts are
  unique and sorted.
- `has_python_boundary_calls` is the exact deterministic projection of
  `FunctionIR.has_boundary_calls`: it means the function performs an
  in-process scalar call to Python fallback code (RXT075). A provider must
  return `None` for that function. Core rejects any non-`None` whole-function
  guard fail-closed so guard state cannot span the Python callback or
  re-entrant work it performs.
- Core owns collision-free ordinal bindings
  (`__rextio_plugin_scope_guard_{ordinal}` in sorted plugin-id order), so
  ids that sanitize identically never share a name. Allocation also skips
  normalized parameter names, function-scope assigned names (including named
  expressions and handler bodies), and existing Core temporaries.
- For a PyO3 function with materialized plugin parameters, plugin-owned
  `param_expr` input conversion runs **before** guards are let-bound. Guards
  then span the native body. At each normal materialized plugin return, Core
  evaluates the native result exactly once into a collision-free temporary,
  explicitly drops active guards in reverse declaration order, and only then
  evaluates the plugin-owned `return_expr` output conversion. Thus plugin-owned
  PyO3 conversion code always executes outside guard state. Native-body early
  returns and error propagation continue to unwind guards through Rust RAII.
- At most one path-call expression per used plugin per function. Invalid
  grammar, empty/multiline support, hook exceptions, and wrong return types
  fail closed as `RustCodegenError`.
- PyO3 always supports the hook. Standalone rust-crate / host-executable only
  when the same plugin/function already passes `artifact_capability`/profile
  authorization; undeclared uses/helpers fail closed without widening
  eligibility.
- For each claimed expression, Core sets the default-compatible
  `LoweringContext.function_scope_guard_active` independently for that claim's
  provider. It is true only when the provider's hook returned a guard that
  Core accepted and emitted for this function. Plugins that use the bit to
  omit per-operation guards must emit distinctly named guarded and guardless
  helper variants when both modes can coexist in one generated module.
- `rextio capabilities` / plugin serialization report
  `function_scope_guard_declared: true` only when a concrete hook is present;
  the key is **omitted** when false so pre-1.7 / no-hook shapes stay unchanged.

## Non-goals

- No core-IR exposure to plugins; no statement/control-flow emission.
- No in-place mutation of plugin-typed arguments; no view aliasing.
- No plugin participation in the scalar boundary-call path or executable
  delegation without an explicit API 1.4 standalone capability.
- No claim priority/ordering between plugins (overlap is an error).
- No usage-based dtype/rank inference yet (annotation vocabulary only).
- No inference of standalone support from host-extension plugin surfaces.
