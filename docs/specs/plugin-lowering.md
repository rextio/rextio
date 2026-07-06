# Spec: Plugin Lowering (claim/lower Hook)

Status: **draft** (targets 0.1.1, experimental tier; plugin API 1.0 → 1.1)
Builds on: [tooling-contract.md](tooling-contract.md) (protocol v2: `describe()`/`covers()`)
First consumer: rextio-numpy

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
    conversion: BoundaryConversion  # see §4
```

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
def lower(self, claimed: ClaimedSite, ctx: LoweringContext) -> LoweredExpr: ...
```

- `ClaimSite`: one candidate construct — a call or binary operation whose
  operand/argument types include a plugin type or a covered symbol
  (`covers()` decides which sites are offered to which plugin). Carries the
  resolved operand types, the dotted call target, and the source location.
- `ClaimResult` is one of:
  - `Claimed(rule_id)` — the plugin will lower this site; `rule_id` must be
    one of the plugin's rule records.
  - `NotCovered()` — not this plugin's business; core continues as if the
    plugin did not exist (usually → candidate rejection via core rules).
  - `Rejected(diagnostic)` — covered but not lowerable; the RXTP diagnostic
    (with guidance) attaches to the function, which falls back.
- **Determinism contract (normative):** for identical inputs (site, resolved
  types, config), `claim` MUST return the same result every time it is
  called. Core MAY call `claim` once and cache, or call it in both phases;
  a plugin MUST NOT base the decision on ambient state. `lower` is called
  exactly once per claimed site, only for functions that stayed accepted.
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

- `ctx` (`LoweringContext`) provides the rendered Rust sub-expressions for
  the site's operands (already lowered by core or by prior plugin claims),
  the target function's identifier namespace (for fresh temporaries via
  `ctx.fresh_name()`), and the active `TargetSpec`.
- The emitted expression must follow core's error posture: fallible
  operations return `Result<_, RextioError>`-compatible expressions using
  the same error-raising helpers core codegen uses (exposed through `ctx`),
  so a shape mismatch raises the CPython-comparable exception type.
- Exposing core IR to plugins is **deferred**; nothing in this contract
  assumes plugins can see or produce IR nodes.

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

Normative rules for the initial surface:

- Arguments are **read-only borrows**; generated code never mutates an
  argument array in place. (For numpy: C-contiguous float64 only; a
  non-contiguous or wrong-dtype array raises the wrapper's normal
  warn-and-fallback path at runtime and is rejected at analysis when
  statically known.)
- Returns transfer ownership of **newly allocated** values.
- Plugin types NEVER cross the internal scalar boundary-call path (RXT075)
  and are never delegated by the Rust-executable dispatcher — the existing
  "containers never cross" rule extends to plugin types verbatim.

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
  fails plugin load (PluginError). A Cargo lockfile is NOT required.
- **User consent:** plugin-injected crates are compiled only for plugins the
  user explicitly enabled (`[plugins] enabled` / `--enable-plugin`) — and the
  first build after a plugin's dependency set changes surfaces the injected
  crates in the build output (not silently).
- **Report exposure:** `build.json` (and the build text report) lists every
  plugin-injected dependency as `{plugin_id, name, version, features}`.
- Conflicts (two plugins pinning the same crate to different versions, or a
  plugin colliding with a core-generated dependency) fail the build up front
  with a configuration-style error (RXT060 posture).

## 6. Verification: the plugin certification kit

Core ships a reusable equivalence harness (`rextio.plugins.testing`,
name provisional): given a project fixture and a set of inputs strategies,
it builds twice (native on / `REXTIO_NATIVE_MODE=fallback`) and asserts
result equivalence with hypothesis — the same posture as core's own
`tests/e2e` property tests.

- A lowering rule record SHOULD reference its certification status; rule
  records gain an optional `verified: bool` field (L2-compatible, additive).
- Divergences must be documented per rule in `constraint` (the float
  summation-order divergence in RXTP-NUMPY-002/003 is the model) and follow
  the RXT090 posture: statically attributable ones may carry a per-function
  note.
- First-party plugins MUST run the kit in CI; third-party plugins are
  strongly recommended to (the manifest's `verified` field is their signal).

## 7. Routes, policies, and failure flow

- A function with ≥1 plugin-lowered site gets route `native-plugin:<id>`
  (even if other sites lowered through core rules). `native_status` stays
  `accepted`.
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

## 8. Versioning and rollout (0.1.1)

- `PLUGIN_API_VERSION` bumps **1.0 → 1.1**; all new members are optional, so
  1.0 describe-only plugins keep loading (major must still match). A plugin
  that implements `lower` without `claim` (or vice versa) fails load.
- Everything in this spec ships in the **0.1.1 line** (owner decision) as
  Experimental, alongside the existing contract surfaces.
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

## Non-goals

- No core-IR exposure to plugins; no statement/control-flow emission.
- No in-place mutation of plugin-typed arguments; no view aliasing.
- No plugin participation in the scalar boundary-call path or executable
  delegation.
- No claim priority/ordering between plugins (overlap is an error).
- No usage-based dtype/rank inference yet (annotation vocabulary only).
