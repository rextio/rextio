"""End-to-end analyzer coverage for plugin API 1.3 callable + schema surfaces (WP-4).

Unlike the direct-dataclass tests, these run the whole ``analyze_project`` claim
pass and assert that ``ClaimSite.callables`` and ``ReceiverMeta.schema`` are
populated from real project sources — including a callable resolved across
modules and a row UDF whose ``row["col"]`` reads bind to the receiver's declared
schema.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    NotCovered,
    PluginType,
)
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)

FRAME = PluginType(
    key="rextio-frame/frame",
    annotations=("rextio_frame.types.Frame",),
    rust_type="FrameData",
    conversion=BoundaryConversion(
        param_rust="PyRef<'py, PyFrame>",
        param_expr="{param}.borrow().clone_data()",
        return_rust="pyo3::Bound<'py, PyFrame>",
        return_expr="PyFrame::new(py, {value})",
    ),
)


class FrameProvider:
    """A 1.3 provider that claims ``frame.apply(udf)`` / ``frame.total()`` sites."""

    plugin_id = "rextio-frame"
    api_version = "1.3"

    def __init__(self) -> None:
        self.sites: list[ClaimSite] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind != "call" or site.receiver is None:
            return NotCovered()
        if site.receiver.arg_type != FRAME.key:
            return NotCovered()
        self.sites.append(site)
        method = site.target.rpartition(".")[2]
        if method == "apply":
            # Fail closed unless the sole callable resolves to a supported body.
            if not site.callables or not site.callables[0].body.available:
                return NotCovered()
            return Claimed(rule_id="rextio-frame/apply", result_type="float")
        if method == "total":
            return Claimed(rule_id="rextio-frame/total", result_type="int")
        return NotCovered()


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id="rextio-frame",
        name="rextio-frame",
        packages=("rextio_frame",),
        rules_provided=True,
        api_version=str(getattr(provider, "api_version")),
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=("rextio-frame",),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id="rextio-frame", plugin_type=FRAME),),
        providers=(PluginProviderBinding(plugin_id="rextio-frame", provider=provider),),
    )


def function_named(analysis: ProjectAnalysis, qualname: str) -> FunctionAnalysis:
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


def analyze(root: Path, provider: object) -> ProjectAnalysis:
    return analyze_project(
        root, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )


def _write(root: Path, rel: str, contents: str) -> None:
    path = root / "src" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


SCHEMA_MODULE = """
class Row:
    price: float
    qty: int
    rate: float
"""

UDF_MODULE = """
def total(row) -> float:
    return row["price"] * row["rate"]


def scaled(x: float) -> float:
    return x * 2.0
"""

KERNEL_MODULE = """
from rextio_frame.types import Frame

from myapp.schema import Row
from myapp.udfs import scaled, total


def apply_row(df: Frame[Row]) -> float:
    return df.apply(total)


def apply_scalar(df: Frame[Row]) -> float:
    return df.apply(scaled)
"""


def _setup(root: Path) -> None:
    _write(root, "myapp/schema.py", SCHEMA_MODULE)
    _write(root, "myapp/udfs.py", UDF_MODULE)
    _write(root, "myapp/kernels.py", KERNEL_MODULE)


def test_receiver_schema_is_populated_from_annotation(tmp_path: Path) -> None:
    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    kernel = function_named(analysis, "myapp.kernels.apply_row")
    claim = kernel.plugin_claims[0]
    assert claim.receiver is not None
    assert claim.receiver.schema is not None  # the whole point: non-None schema
    assert claim.receiver.schema.identity == "myapp.schema.Row"
    assert [(f.name, f.field_type) for f in claim.receiver.schema.fields] == [
        ("price", "float"),
        ("qty", "int"),
        ("rate", "float"),
    ]


def test_active_plugin_annotation_subscription_keeps_exact_bindings(
    tmp_path: Path,
) -> None:
    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    bindings = analysis.project_bindings.for_module("myapp.kernels")

    assert bindings.trusted_annotation_targets == {"rextio_frame.types.Frame"}
    assert bindings.last_unknown_star_order is None
    assert bindings.lookup("Frame").kind.value == "import"
    assert bindings.lookup("apply_row").kind.value == "function"


def test_shadowed_plugin_annotation_spelling_remains_effectful(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "myapp/kernels.py",
        """
import rextio
from rextio_frame.types import Frame

class Row:
    value: int

class Evil:
    @classmethod
    def __class_getitem__(cls, item):
        globals()["good"] = lambda x: x + 200
        return cls

Frame = Evil

@rextio.native
def good(x: int) -> int:
    return x + 100

def trigger(value: Frame[Row]):
    pass

@rextio.native
def caller(x: int) -> int:
    return good(x)
""",
    )
    analysis = analyze(tmp_path, FrameProvider())

    assert function_named(analysis, "myapp.kernels.good").accepted is False
    assert function_named(analysis, "myapp.kernels.caller").route != "native-direct"


def test_project_module_shadowing_plugin_annotation_target_remains_effectful(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "rextio_frame/__init__.py", "")
    _write(
        tmp_path,
        "rextio_frame/types.py",
        """
class Frame:
    @classmethod
    def __class_getitem__(cls, item):
        import myapp.kernels as kernels
        kernels.good = lambda x: x + 200
        return cls
""",
    )
    _write(
        tmp_path,
        "myapp/kernels.py",
        """
import rextio
from rextio_frame.types import Frame

class Row:
    value: int

@rextio.native
def good(x: int) -> int:
    return x + 100

def trigger(value: Frame[Row]):
    pass

@rextio.native
def caller(x: int) -> int:
    return good(x)
""",
    )
    analysis = analyze(tmp_path, FrameProvider())

    assert "rextio_frame.types" in analysis.project_bindings.by_module
    assert function_named(analysis, "myapp.kernels.good").accepted is False
    assert function_named(analysis, "myapp.kernels.caller").route != "native-direct"


def test_mutated_registered_plugin_annotation_target_remains_effectful(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "myapp/kernels.py",
        """
import rextio
import rextio_frame.types as frame_types

class Row:
    value: int

class Evil:
    @classmethod
    def __class_getitem__(cls, item):
        globals()["good"] = lambda x: x + 200
        return cls

@rextio.native
def good(x: int) -> int:
    return x + 100

frame_types.Frame = Evil

def trigger(value: frame_types.Frame[Row]):
    pass

@rextio.native
def caller(x: int) -> int:
    return good(x)
""",
    )
    analysis = analyze(tmp_path, FrameProvider())

    assert analysis.project_mutations.target_is_mutated("rextio_frame.types.Frame")
    assert function_named(analysis, "myapp.kernels.good").accepted is False
    assert function_named(analysis, "myapp.kernels.caller").route != "native-direct"


def test_row_udf_callable_body_binds_receiver_schema(tmp_path: Path) -> None:
    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    claim = function_named(analysis, "myapp.kernels.apply_row").plugin_claims[0]
    assert len(claim.callables) == 1
    meta = claim.callables[0]
    # Cross-module: the callable resolved from myapp.kernels to myapp.udfs.total.
    assert meta.qualname == "myapp.udfs.total"
    assert meta.arg_index == 0
    # A row UDF is representable but NOT a scalar native function.
    assert meta.body.available is True
    assert meta.accepts_native is False
    # row["price"] * row["rate"] -> binop(subscript(price), subscript(rate)).
    # Both fields are float: the closed body mirrors core's same-type numeric
    # subset, so a mixed float*int arithmetic body is instead rejected (see
    # test_mixed_type_row_udf_body_is_unavailable).
    expr = meta.body.expression
    assert expr is not None and expr.kind == "binop" and expr.op == "*"
    left, right = expr.children
    assert left.kind == "subscript" and left.name == "price" and left.result_type == "float"
    assert right.kind == "subscript" and right.name == "rate" and right.result_type == "float"


def test_scalar_udf_callable_is_accepts_native(tmp_path: Path) -> None:
    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    claim = function_named(analysis, "myapp.kernels.apply_scalar").plugin_claims[0]
    meta = claim.callables[0]
    assert meta.qualname == "myapp.udfs.scaled"
    assert meta.params == meta.params  # sanity
    assert [(p.name, p.param_type) for p in meta.params] == [("x", "float")]
    assert meta.return_type == "float"
    assert meta.accepts_native is True
    assert meta.body.available is True


BAD_SCHEMA_KERNEL = """
from rextio_frame.types import Frame

from myapp.badschema import Bad


def kern(df: Frame[Bad]) -> int:
    return df.total()
"""


def test_malformed_schema_fails_closed_to_no_association(tmp_path: Path) -> None:
    # A schema class violating the grammar (a method) yields NO association: the
    # receiver stays a well-formed schemaless Frame rather than a wrong schema.
    _write(
        tmp_path, "myapp/badschema.py", "class Bad:\n    x: int\n    def m(self):\n        pass\n"
    )
    _write(tmp_path, "myapp/kernels.py", BAD_SCHEMA_KERNEL)
    analysis = analyze(tmp_path, FrameProvider())
    kernel = function_named(analysis, "myapp.kernels.kern")
    assert kernel.accepted is True
    claim = kernel.plugin_claims[0]
    assert claim.receiver is not None
    assert claim.receiver.arg_type == FRAME.key
    assert claim.receiver.schema is None  # fail closed, not a wrong schema


UNSUPPORTED_UDF_MODULE = """
def looping(row) -> float:
    total = 0.0
    for v in row:
        total = total + v
    return total
"""

UNSUPPORTED_KERNEL = """
from rextio_frame.types import Frame

from myapp.schema import Row
from myapp.badudfs import looping


def kern(df: Frame[Row]) -> float:
    return df.apply(looping)
"""


def test_unsupported_udf_body_is_unavailable_and_site_unclaimed(tmp_path: Path) -> None:
    # A UDF with a loop is outside the closed grammar: its body is unavailable,
    # and the provider (which fails closed on an unavailable body) does not claim.
    _write(tmp_path, "myapp/schema.py", SCHEMA_MODULE)
    _write(tmp_path, "myapp/badudfs.py", UNSUPPORTED_UDF_MODULE)
    _write(tmp_path, "myapp/kernels.py", UNSUPPORTED_KERNEL)
    provider = FrameProvider()
    analysis = analyze(tmp_path, provider)
    kernel = function_named(analysis, "myapp.kernels.kern")
    # The site was offered with an explicitly unavailable-body callable; the
    # provider declined, so the function is not on the native-plugin route.
    offered = [s for s in provider.sites if s.target.endswith(".apply")]
    assert offered and offered[0].callables[0].body.available is False
    assert offered[0].callables[0].body.unavailable_reason is not None
    assert kernel.route == "fallback-python"


def test_finalized_analysis_retains_declared_schema_and_locals(tmp_path: Path) -> None:
    # WP-4 follow-up 4, section 8: an accepted analysis must keep the probe's
    # declared schemas and local-binding scope, not drop them silently.
    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    kern = function_named(analysis, "myapp.kernels.apply_row")
    assert kern.route == "native-plugin:rextio-frame"
    assert "df" in kern.declared_schemas
    assert kern.declared_schemas["df"].identity == "myapp.schema.Row"
    assert "df" in kern.local_binding_names


def test_callables_survive_to_dict_json_roundtrip(tmp_path: Path) -> None:
    import json

    _setup(tmp_path)
    analysis = analyze(tmp_path, FrameProvider())
    claim = function_named(analysis, "myapp.kernels.apply_row").plugin_claims[0]
    data = claim.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["callables"][0]["qualname"] == "myapp.udfs.total"


# --- CallableMeta vs. real FunctionAnalysis consistency (WP-4 review) -----
#
# ``accepts_native`` must never be a structural false positive: whenever it is
# True the resolved UDF is genuinely an accepted, non-runtime-shim scalar native
# function; and ``runtime_semantics`` reflects the documented actual shim subset.
# These run the whole analyzer so the CallableMeta offered to the provider is
# compared against the SAME project's real FunctionAnalysis for that UDF.


def _offered_apply_callable(root: Path, provider: FrameProvider) -> ClaimSite:
    analyze(root, provider)
    offered = [s for s in provider.sites if s.target.endswith(".apply")]
    assert offered, "the df.apply(udf) site was never offered"
    return offered[0]


APPLY_KERNEL = """
from rextio_frame.types import Frame

from myapp.udfs import udf


def kern(df: Frame) -> float:
    return df.apply(udf)
"""


def _analyze_udf(tmp_path: Path, udf_src: str) -> tuple[object, FunctionAnalysis]:
    _write(tmp_path, "myapp/udfs.py", udf_src)
    _write(tmp_path, "myapp/kernels.py", APPLY_KERNEL)
    provider = FrameProvider()
    site = _offered_apply_callable(tmp_path, provider)
    meta = site.callables[0]
    # Re-run to fetch the real UDF FunctionAnalysis from the same sources.
    analysis = analyze(tmp_path, FrameProvider())
    real = function_named(analysis, "myapp.udfs.udf")
    return meta, real


def _assert_no_false_positive(meta: object, real: FunctionAnalysis) -> None:
    # If the metadata claims native-acceptance, the real analysis must agree it
    # is an accepted, non-shim scalar native function.
    if meta.accepts_native:  # type: ignore[attr-defined]
        assert real.accepted is True
        assert real.native_runtime_semantics is False


def test_mismatched_return_is_not_accepts_native(tmp_path: Path) -> None:
    meta, real = _analyze_udf(tmp_path, "def udf(x: float) -> int:\n    return x * 2.0\n")
    assert real.accepted is False  # core rejects the return-type mismatch
    assert meta.accepts_native is False
    _assert_no_false_positive(meta, real)


def test_numeric_boolop_is_not_accepts_native(tmp_path: Path) -> None:
    meta, real = _analyze_udf(tmp_path, "def udf(a: int, b: int) -> bool:\n    return a and b\n")
    # Core does not accept a numeric ``and`` (it returns an operand, not a bool),
    # and the closed body fails closed on non-boolean operands — consistent.
    assert real.accepted is False
    assert meta.body.available is False
    assert meta.accepts_native is False


def test_unsupported_call_is_not_accepts_native(tmp_path: Path) -> None:
    # math.fabs is not a core-lowered native call, so an accepts_native here would
    # be a structural false positive.
    meta, real = _analyze_udf(
        tmp_path, "import math\ndef udf(x: float) -> float:\n    return math.fabs(x)\n"
    )
    assert real.accepted is False
    assert meta.body.available is False
    assert meta.accepts_native is False


def test_project_local_math_module_is_not_callable_stdlib_metadata(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "math.py", "def sin(x):\n    return x + 100.0\n")
    meta, real = _analyze_udf(
        tmp_path,
        "import math\ndef udf(x: float) -> float:\n    return math.sin(x)\n",
    )
    assert real.route != "native-direct"
    assert meta.body.available is False
    assert meta.accepts_native is False


def test_genuine_stdlib_math_module_stays_callable_native_metadata(
    tmp_path: Path,
) -> None:
    meta, real = _analyze_udf(
        tmp_path,
        "import math\ndef udf(x: float) -> float:\n    return math.sin(x)\n",
    )
    assert real.route == "native-direct"
    assert meta.body.available is True
    assert meta.accepts_native is True


def test_unsupported_decorator_is_not_accepts_native(tmp_path: Path) -> None:
    meta, real = _analyze_udf(
        tmp_path,
        "import functools\n@functools.cache\ndef udf(x: float) -> float:\n    return x * 2.0\n",
    )
    assert real.accepted is False
    assert meta.body.available is False
    assert meta.accepts_native is False


def test_runtime_shim_reflects_semantics_and_is_not_native(tmp_path: Path) -> None:
    meta, real = _analyze_udf(
        tmp_path,
        "import rextio\nimport statistics\n@rextio.native\n"
        "def udf(xs: list[float]) -> float:\n    return statistics.mean(xs)\n",
    )
    # The real UDF rides the RXT080 runtime shim; the metadata reflects that
    # actual shim subset instead of a misleading False, and is not native.
    assert real.native_runtime_semantics is True
    assert meta.runtime_semantics is True
    assert meta.accepts_native is False


def test_decorated_native_scalar_is_accepts_native(tmp_path: Path) -> None:
    # The @rextio.native marker must NOT disqualify a proven scalar UDF: the real
    # analysis accepts it as a direct native function and so does the metadata.
    meta, real = _analyze_udf(
        tmp_path,
        "import rextio\n@rextio.native\ndef udf(x: float) -> float:\n    return x * 2.0\n",
    )
    assert real.accepted is True
    assert real.native_runtime_semantics is False
    assert meta.accepts_native is True
    assert meta.runtime_semantics is False
    assert meta.body.available is True


@pytest.mark.parametrize(
    "source",
    [
        (
            "def native(fn):\n    return lambda x: x + 200.0\n\n"
            "@native\ndef udf(x: float) -> float:\n    return x * 2.0\n"
        ),
        (
            "import rextio\n"
            "rextio.native = lambda fn: (lambda x: x + 200.0)\n\n"
            "@rextio.native\ndef udf(x: float) -> float:\n    return x * 2.0\n"
        ),
    ],
)
def test_unproven_native_marker_is_not_advertised_as_callable_native(
    tmp_path: Path, source: str
) -> None:
    meta, real = _analyze_udf(tmp_path, source)
    assert real.accepted is False
    assert real.is_native_candidate is False
    assert meta.accepts_native is False


# --- keyword-callable route (WP-4 review) --------------------------------
#
# A project-function reference passed as a KEYWORD (``df.apply(func=udf)``) is
# claimable compile-time callable metadata, not a runtime keyword operand — the
# claim must fire, the callable must name its keyword, and it must NOT appear on
# the site's runtime ``keywords`` surface.

KEYWORD_KERNEL = """
from rextio_frame.types import Frame

from myapp.udfs import scaled


def kern(df: Frame) -> float:
    return df.apply(func=scaled)
"""


def test_keyword_callable_is_claimed_and_named(tmp_path: Path) -> None:
    import json

    _write(tmp_path, "myapp/udfs.py", UDF_MODULE)
    _write(tmp_path, "myapp/kernels.py", KEYWORD_KERNEL)
    analysis = analyze(tmp_path, FrameProvider())
    kern = function_named(analysis, "myapp.kernels.kern")
    assert kern.route == "native-plugin:rextio-frame"
    claim = kern.plugin_claims[0]
    # The keyword callable is carried as CallableMeta, NOT as a runtime keyword.
    assert claim.keywords == ()
    assert len(claim.callables) == 1
    meta = claim.callables[0]
    assert meta.qualname == "myapp.udfs.scaled"
    assert meta.keyword == "func"
    assert meta.accepts_native is True
    # Serialization: the keyword survives a JSON round-trip (cache/tooling shape).
    data = claim.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["callables"][0]["keyword"] == "func"


def test_keyword_callable_claim_is_cached_and_deterministic(tmp_path: Path) -> None:
    # The determinism contract: re-analyzing the identical source produces an
    # identical claim (same callable, same keyword) — the cache key includes the
    # keyword-bearing CallableMeta.
    _write(tmp_path, "myapp/udfs.py", UDF_MODULE)
    _write(tmp_path, "myapp/kernels.py", KEYWORD_KERNEL)
    first = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    second = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    assert first.plugin_claims[0].callables == second.plugin_claims[0].callables
    assert first.plugin_claims[0].callables[0].keyword == "func"


def test_non_callable_nonliteral_keyword_still_fails_closed(tmp_path: Path) -> None:
    # A non-literal keyword that is NOT a project-function reference has no
    # CallIR representation, so the site is not claimed (fail closed) — the
    # keyword route admits ONLY statically-resolved project callables.
    _write(tmp_path, "myapp/udfs.py", UDF_MODULE)
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\n\n\n"
        "def kern(df: Frame, other: float) -> float:\n    return df.apply(func=other)\n",
    )
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    assert kern.route == "fallback-python"
    assert not kern.plugin_claims


# --- scope/site-aware callable resolution (director follow-up 2, item 1) ----
#
# Project-callable detection must resolve the actual binding at the call site,
# not just the AST spelling/import map: a callable-argument name shadowed by a
# parameter/local/loop/comprehension target, read before a local assignment, or
# reassigned at module scope must NOT native-lower a different function than
# Python calls. Each of these must yield NO callable metadata (fail closed),
# while a plain unshadowed same-module or imported function still resolves.

GOOD_UDF_MODULE = """
def good(x: int) -> int:
    return x
"""


def _apply_site(root: Path) -> ClaimSite:
    provider = FrameProvider()
    analyze(root, provider)
    offered = [s for s in provider.sites if s.target.endswith(".apply")]
    assert offered, "the df.apply(...) site was never offered"
    return offered[0]


_SHADOW_KERNELS = {
    "parameter": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame, good: int) -> float:\n    return df.apply(good)\n"
    ),
    "local_assignment": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame) -> float:\n    good = 7\n    return df.apply(good)\n"
    ),
    "loop_target": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame, items: list[int]) -> float:\n"
        "    for good in items:\n        pass\n    return df.apply(good)\n"
    ),
    "read_before_local_assign": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame) -> float:\n    y = df.apply(good)\n    good = 7\n    return y\n"
    ),
    "imported_alias_shadowed_by_param": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame, good: int) -> float:\n    return df.apply(good)\n"
    ),
    "imported_alias_overwritten_at_module_scope": (
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n"
        "good = 7\n\n\n"
        "def run(df: Frame) -> float:\n    return df.apply(good)\n"
    ),
}


@pytest.mark.parametrize("case", sorted(_SHADOW_KERNELS))
def test_shadowed_callable_yields_no_metadata(tmp_path: Path, case: str) -> None:
    _write(tmp_path, "myapp/udfs.py", GOOD_UDF_MODULE)
    _write(tmp_path, "myapp/kernels.py", _SHADOW_KERNELS[case])
    site = _apply_site(tmp_path)
    # No callable metadata is offered for a shadowed/reassigned reference.
    assert site.callables == (), case
    # And the site is not claimed as a native-plugin callable route.
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.run")
    assert kern.route == "fallback-python", case


# A comprehension `for` target is scoped to the comprehension (Python 3), so a
# same-name reference AFTER the comprehension is NOT shadowed and still resolves,
# while a reference INSIDE the comprehension's active scope IS shadowed. (WP-4
# director follow-up 4, section 3.)
_COMPREHENSION_RESOLVES = {
    "list_comp_after": "    xs = [good for good in items]\n    return df.apply(good)\n",
    "set_comp_after": "    xs = {good for good in items}\n    return df.apply(good)\n",
    "dict_comp_after": "    xs = {good: good for good in items}\n    return df.apply(good)\n",
    "genexpr_after": "    xs = list(good for good in items)\n    return df.apply(good)\n",
    "nested_generators_after": (
        "    xs = [a + b for a in items for b in items]\n    return df.apply(good)\n"
    ),
}


@pytest.mark.parametrize("case", sorted(_COMPREHENSION_RESOLVES))
def test_comprehension_target_does_not_leak_shadow(tmp_path: Path, case: str) -> None:
    _write(tmp_path, "myapp/udfs.py", GOOD_UDF_MODULE)
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame, items: list[int]) -> float:\n" + _COMPREHENSION_RESOLVES[case],
    )
    site = _apply_site(tmp_path)
    # The trailing `df.apply(good)` references the imported module function, not the
    # comprehension's `good` target, so it resolves to a callable.
    assert len(site.callables) == 1, case
    assert site.callables[0].qualname == "myapp.udfs.good", case


def test_reference_inside_comprehension_is_shadowed(tmp_path: Path) -> None:
    # `df.apply(good)` INSIDE the comprehension element is in the comprehension's
    # active scope, where `good` is the iteration target — so it must fail closed.
    _write(tmp_path, "myapp/udfs.py", GOOD_UDF_MODULE)
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.udfs import good\n\n\n"
        "def run(df: Frame, items: list[int]) -> float:\n"
        "    xs = [df.apply(good) for good in items]\n    return xs[0]\n",
    )
    site = _apply_site(tmp_path)
    assert site.callables == ()
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.run")
    assert kern.route == "fallback-python"


def test_unshadowed_same_module_function_still_resolves(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\n\n\n"
        "def scaled(x: float) -> float:\n    return x * 2.0\n\n\n"
        "def run(df: Frame) -> float:\n    return df.apply(scaled)\n",
    )
    site = _apply_site(tmp_path)
    assert len(site.callables) == 1
    assert site.callables[0].qualname == "myapp.kernels.scaled"
    assert site.callables[0].accepts_native is True


def test_unshadowed_imported_function_still_resolves(tmp_path: Path) -> None:
    _write(tmp_path, "myapp/udfs.py", "def scaled(x: float) -> float:\n    return x * 2.0\n")
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.udfs import scaled\n\n\n"
        "def run(df: Frame) -> float:\n    return df.apply(scaled)\n",
    )
    site = _apply_site(tmp_path)
    assert len(site.callables) == 1
    assert site.callables[0].qualname == "myapp.udfs.scaled"


# --- final-binding-aware schema resolution (item 2) -------------------------


def test_module_reassigned_schema_class_yields_no_schema(tmp_path: Path) -> None:
    # ``Row = int`` after ``class Row`` makes the class node stale: the receiver
    # must not associate the reassigned class's schema (fail closed).
    _write(
        tmp_path,
        "myapp/schema.py",
        "class Row:\n    price: float\n\n\nRow = int\n",
    )
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.schema import Row\n\n\n"
        "def kern(df: Frame[Row]) -> int:\n    return df.total()\n",
    )
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    claim = kern.plugin_claims[0]
    assert claim.receiver is not None
    assert claim.receiver.schema is None  # fail closed, not the stale class schema


def test_schema_reassigned_in_defining_module_yields_no_schema(tmp_path: Path) -> None:
    # The schema class is defined and reassigned in module A, then imported by
    # module B: the DEFINING module's reassignment must fail closed too.
    _write(tmp_path, "myapp/schema.py", "class Row:\n    price: float\n\n\nRow = int\n")
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.schema import Row\n\n\n"
        "def kern(df: Frame[Row]) -> int:\n    return df.total()\n",
    )
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    assert kern.plugin_claims[0].receiver.schema is None


# --- direct schema annotation shape (item 8) --------------------------------


def test_nested_schema_subscript_yields_no_schema(tmp_path: Path) -> None:
    # ``Frame[Row][Other]`` is a nested subscript; its base is not the direct
    # registered plugin spelling, so no schema is associated (never ``Other``).
    _write(
        tmp_path,
        "myapp/schema.py",
        "class Row:\n    price: float\n\n\nclass Other:\n    qty: int\n",
    )
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from __future__ import annotations\n"
        "from rextio_frame.types import Frame\nfrom myapp.schema import Other, Row\n\n\n"
        "def kern(df: Frame[Row][Other]) -> int:\n    return df.total()\n",
    )
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    claim = kern.plugin_claims[0]
    assert claim.receiver is not None
    assert claim.receiver.schema is None


def test_direct_schema_subscript_associates_schema(tmp_path: Path) -> None:
    # The direct ``Frame[Row]`` form still associates Row (the positive control).
    _write(tmp_path, "myapp/schema.py", "class Row:\n    price: float\n")
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.schema import Row\n\n\n"
        "def kern(df: Frame[Row]) -> int:\n    return df.total()\n",
    )
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    assert kern.plugin_claims[0].receiver.schema is not None
    assert kern.plugin_claims[0].receiver.schema.identity == "myapp.schema.Row"


# --- literal fail-closed + i64 bounds (item 4) ------------------------------


def test_overflow_float_literal_body_is_unavailable_not_error(tmp_path: Path) -> None:
    # ``1e400`` parses to inf; extraction must yield an unavailable body, never a
    # raised ValueError that aborts project analysis. (Core itself lowers a
    # non-finite float literal, so it accepts the UDF — the metadata is
    # deliberately narrower because inf/NaN have no JSON-safe/cache-stable literal,
    # which is a fail-closed narrowing, not a false positive.)
    meta, real = _analyze_udf(tmp_path, "def udf(x: float) -> float:\n    return 1e400\n")
    assert meta.body.available is False
    assert meta.accepts_native is False
    # Analysis completed without the extractor's ValueError aborting it.
    assert real is not None


def test_int_literal_above_i64_max_is_unavailable(tmp_path: Path) -> None:
    meta, real = _analyze_udf(tmp_path, "def udf(x: int) -> int:\n    return 9223372036854775808\n")
    assert meta.body.available is False
    assert meta.accepts_native is False
    assert real.accepted is False


def test_i64_min_literal_is_available(tmp_path: Path) -> None:
    # ``-9223372036854775808`` (i64::MIN) is parsed as unary minus over 2**63 and
    # must stay available/accepted, exactly as core types this constant form.
    meta, real = _analyze_udf(
        tmp_path, "def udf(x: int) -> int:\n    return -9223372036854775808\n"
    )
    assert meta.body.available is True
    assert meta.accepts_native is True
    assert real.accepted is True


def test_i64_max_literal_is_available(tmp_path: Path) -> None:
    meta, real = _analyze_udf(tmp_path, "def udf(x: int) -> int:\n    return 9223372036854775807\n")
    assert meta.accepts_native is True
    assert real.accepted is True


def test_below_i64_min_literal_is_unavailable(tmp_path: Path) -> None:
    meta, real = _analyze_udf(
        tmp_path, "def udf(x: int) -> int:\n    return -9223372036854775809\n"
    )
    assert meta.body.available is False
    assert meta.accepts_native is False
    assert real.accepted is False


# --- accepts_native implies a real generatable helper (item 5) --------------


def test_unrepresentable_param_identifier_is_not_accepts_native(tmp_path: Path) -> None:
    # ``crate`` is a Rust keyword a raw identifier cannot carry: core rejects the
    # helper (RXT011), so metadata must NOT claim accepts_native (else the caller
    # is claimed and fails later with RXT050, no native symbol).
    meta, real = _analyze_udf(tmp_path, "def udf(crate: float) -> float:\n    return crate * 2.0\n")
    assert meta.accepts_native is False
    assert real.accepted is False


def test_ordinary_valid_helper_is_accepts_native(tmp_path: Path) -> None:
    # The positive control: a representable-identifier scalar helper stays native.
    meta, real = _analyze_udf(tmp_path, "def udf(value: float) -> float:\n    return value * 2.0\n")
    assert meta.accepts_native is True
    assert real.accepted is True


# --- exact callable expression typing matrix (item 3) -----------------------
#
# CallableMeta availability/accepts_native must agree with the REAL
# FunctionAnalysis acceptance for every admitted/rejected operator class — the
# closed body grammar is never broader than core's native analyzer contract.

_OPERATOR_MATRIX = {
    # admitted (core accepts, metadata is accepts_native)
    "add_same_float": ("def udf(a: float, b: float) -> float:\n    return a + b\n", True),
    "sub_same_int": ("def udf(a: int, b: int) -> int:\n    return a - b\n", True),
    "mul_same_int": ("def udf(a: int, b: int) -> int:\n    return a * b\n", True),
    "mod_same_float": ("def udf(a: float, b: float) -> float:\n    return a % b\n", True),
    "truediv_float": ("def udf(a: float, b: float) -> float:\n    return a / b\n", True),
    "unary_minus": ("def udf(x: int) -> int:\n    return -x\n", True),
    "not_bool": ("def udf(x: bool) -> bool:\n    return not x\n", True),
    "compare_same_int": ("def udf(a: int, b: int) -> bool:\n    return a < b\n", True),
    # rejected (core rejects, metadata is not accepts_native)
    "floordiv": ("def udf(a: int, b: int) -> int:\n    return a // b\n", False),
    "truediv_int": ("def udf(a: int, b: int) -> float:\n    return a / b\n", False),
    "mixed_add": ("def udf(a: int, b: float) -> float:\n    return a + b\n", False),
    "str_concat": ("def udf(a: str, b: str) -> str:\n    return a + b\n", False),
    "bit_and": ("def udf(a: int, b: int) -> int:\n    return a & b\n", False),
    "bit_or": ("def udf(a: int, b: int) -> int:\n    return a | b\n", False),
    "lshift": ("def udf(a: int, b: int) -> int:\n    return a << b\n", False),
    "unary_plus": ("def udf(x: int) -> int:\n    return +x\n", False),
    "invert": ("def udf(x: int) -> int:\n    return ~x\n", False),
    "compare_mixed": ("def udf(a: int, b: str) -> bool:\n    return a < b\n", False),
    "identity_non_none": ("def udf(a: int, b: int) -> bool:\n    return a is b\n", False),
    "membership_scalar": ("def udf(a: int, b: int) -> bool:\n    return a in b\n", False),
}


@pytest.mark.parametrize("case", sorted(_OPERATOR_MATRIX))
def test_operator_matrix_metadata_matches_real_acceptance(tmp_path: Path, case: str) -> None:
    src, expected = _OPERATOR_MATRIX[case]
    meta, real = _analyze_udf(tmp_path, src)
    real_native = real.accepted and not real.native_runtime_semantics
    # Metadata acceptance mirrors the real analyzer's exactly.
    assert meta.accepts_native == real_native, (case, meta.accepts_native, real_native)
    # And matches the documented expectation for this operator class.
    assert meta.accepts_native is expected, case
    _assert_no_false_positive(meta, real)


# --- mixed-type row UDF body is unavailable (item 3, row-UDF path) -----------


def test_mixed_type_row_udf_body_is_unavailable(tmp_path: Path) -> None:
    # A row UDF mixing float*int is outside core's same-type numeric subset (it
    # would lower to uncompilable ``f64 * i64`` Rust), so its closed body is
    # unavailable and the provider — which fails closed on an unavailable body —
    # does not claim the apply site.
    _write(tmp_path, "myapp/schema.py", "class Row:\n    price: float\n    qty: int\n")
    _write(
        tmp_path,
        "myapp/udfs.py",
        'def total(row) -> float:\n    return row["price"] * row["qty"]\n',
    )
    _write(
        tmp_path,
        "myapp/kernels.py",
        "from rextio_frame.types import Frame\nfrom myapp.schema import Row\n"
        "from myapp.udfs import total\n\n\n"
        "def kern(df: Frame[Row]) -> float:\n    return df.apply(total)\n",
    )
    provider = FrameProvider()
    analyze(tmp_path, provider)
    offered = [s for s in provider.sites if s.target.endswith(".apply")]
    assert offered and offered[0].callables[0].body.available is False
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    assert kern.route == "fallback-python"


# --- legacy provider behavior compatibility (item 7) ------------------------
#
# Receiver-type-only matching is a plugin API 1.3 surface. A legacy 1.1/1.2
# provider must NEVER be newly offered a method site solely because its plugin
# type is the receiver — a site it was never offered before 1.3.


class _LegacyTotalProvider:
    """An API 1.2 provider that would claim any ``*.total`` call if offered."""

    plugin_id = "rextio-frame"
    api_version = "1.2"

    def __init__(self) -> None:
        self.sites: list[ClaimSite] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        self.sites.append(site)
        if site.kind == "call" and site.target.endswith(".total"):
            return Claimed(rule_id="rextio-frame/total", result_type="int")
        return NotCovered()


TOTAL_KERNEL = """
from rextio_frame.types import Frame


def kern(df: Frame) -> int:
    return df.total()
"""


def test_legacy_provider_not_offered_method_site_by_receiver_type(tmp_path: Path) -> None:
    _write(tmp_path, "myapp/kernels.py", TOTAL_KERNEL)
    provider = _LegacyTotalProvider()
    analysis = analyze(tmp_path, provider)
    # The legacy provider is never offered the ``df.total()`` site: its package
    # (rextio_frame) does not match the target (``df.total``) and the receiver
    # type is not offered to a < 1.3 provider.
    assert not [s for s in provider.sites if s.target.endswith(".total")]
    kern = function_named(analysis, "myapp.kernels.kern")
    assert kern.route == "fallback-python"
    assert not kern.plugin_claims


def test_api_13_control_is_offered_method_site_by_receiver_type(tmp_path: Path) -> None:
    # The identical site IS offered to (and claimed by) a >= 1.3 provider — the
    # receiver-type surface is preserved for 1.3, only gated off for legacy.
    _write(tmp_path, "myapp/kernels.py", TOTAL_KERNEL)
    provider = FrameProvider()
    analysis = analyze(tmp_path, provider)
    assert [s for s in provider.sites if s.target.endswith(".total")]
    kern = function_named(analysis, "myapp.kernels.kern")
    assert kern.route == "native-plugin:rextio-frame"


# --- module final-binding matrix (director follow-up 3) ---------------------
#
# Callable and schema resolution share ONE conservative, source-order module
# final-binding model: a name resolves to its indexed definition only when its
# FINAL module-level binder is the matching def/class/import; a later class /
# function / import / del / ordinary assignment invalidates the stale node (it
# must never be selected), a later matching definition restores it, and a
# conditional (branch-guarded) binder makes the name ambiguous unless a later
# unconditional binder overrides it. The final import target — not the stale
# local definition — is what an import-shadowed name resolves to.

# A sibling project module supplying an unshadowed function and schema class,
# so import-shadowed names resolve to a DISTINCT final target (proving the
# stale same-module node is never selected).
OTHER_MODULE = "def good(x: float) -> float:\n    return x * 3.0\n\n\nclass Row:\n    weight: int\n"


def _apply_kernel(setup: str, call_form: str) -> str:
    return (
        "from rextio_frame.types import Frame\n\n\n"
        + setup
        + "\n\ndef run(df: Frame) -> float:\n    return df.apply("
        + call_form
        + ")\n"
    )


# case -> (setup establishing ``good``'s final binding in the kernel module,
#          expected resolved qualname or None when it must fail closed)
_CALLABLE_FINAL_BINDING = {
    # function followed by class / import / del / ordinary assignment
    "function_then_class": (
        "def good(x: float) -> float:\n    return x\n\n\nclass good:\n    pass\n",
        None,
    ),
    "function_then_import": (
        "def good(x: float) -> float:\n    return x\n\n\nfrom myapp.other import good\n",
        "myapp.other.good",  # resolves the final import target, not the stale def
    ),
    "function_then_del": (
        "def good(x: float) -> float:\n    return x\n\n\ndel good\n",
        None,
    ),
    "function_then_assignment": (
        "def good(x: float) -> float:\n    return x\n\n\ngood = 7\n",
        None,
    ),
    # assignment / import followed by a final matching function (positive control)
    "assignment_then_function": (
        "good = 7\n\n\ndef good(x: float) -> float:\n    return x\n",
        "myapp.kernels.good",
    ),
    "import_then_function": (
        "from myapp.other import good\n\n\ndef good(x: float) -> float:\n    return x\n",
        "myapp.kernels.good",  # the final local def overrides the earlier import
    ),
    # imported project function left unshadowed (positive control)
    "imported_unshadowed": ("from myapp.other import good\n", "myapp.other.good"),
    # imported alias replaced by another project import (resolve the final target)
    "import_replaced_by_import": (
        "from myapp.udfs import good\n\n\nfrom myapp.other import good\n",
        "myapp.other.good",
    ),
    # duplicate definitions in source order (the last def wins)
    "duplicate_functions": (
        "def good(x: float) -> float:\n    return x + 1.0\n\n\n"
        "def good(x: float) -> float:\n    return x + 2.0\n",
        "myapp.kernels.good",
    ),
    # conditional bind after a definition (fail closed)
    "conditional_after_definition": (
        "import os\n\n\ndef good(x: float) -> float:\n    return x\n\n\nif os.environ:\n    good = 7\n",
        None,
    ),
    # conditional bind before a later unconditional definition (positive control)
    "conditional_before_definition": (
        "import os\n\n\nif os.environ:\n    good = 7\n\n\ndef good(x: float) -> float:\n    return x\n",
        "myapp.kernels.good",
    ),
}


@pytest.mark.parametrize("call_form", ["good", "func=good"])
@pytest.mark.parametrize("case", sorted(_CALLABLE_FINAL_BINDING))
def test_callable_final_binding_matrix(tmp_path: Path, case: str, call_form: str) -> None:
    # The matrix runs through BOTH a positional (``df.apply(good)``) and a
    # keyword (``df.apply(func=good)``) callable argument, so the cheap probe and
    # metadata builder apply the identical final-binding decision to each form.
    setup, expected = _CALLABLE_FINAL_BINDING[case]
    _write(tmp_path, "myapp/other.py", OTHER_MODULE)
    _write(tmp_path, "myapp/udfs.py", "def good(x: float) -> float:\n    return x + 5.0\n")
    _write(tmp_path, "myapp/kernels.py", _apply_kernel(setup, call_form))
    run = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.run")
    if expected is None:
        # The stale/ambiguous node is never selected: the site is not claimed
        # onto the native-plugin route (a shadowed keyword callable is not even
        # offered; a shadowed positional one is offered with no callable meta and
        # the provider declines). Either way the function stays on the fallback.
        assert run.route == "fallback-python", (case, call_form)
        assert not run.plugin_claims, (case, call_form)
    else:
        assert run.route == "native-plugin:rextio-frame", (case, call_form)
        callables = run.plugin_claims[0].callables
        assert len(callables) == 1, (case, call_form)
        assert callables[0].qualname == expected, (case, call_form)
        assert callables[0].keyword == ("func" if call_form.startswith("func=") else "")


def _total_kernel(setup: str) -> str:
    return (
        "from rextio_frame.types import Frame\n\n\n"
        + setup
        + "\n\ndef kern(df: Frame[Row]) -> int:\n    return df.total()\n"
    )


# case -> (setup establishing ``Row``'s final binding, expected schema identity
#          or None when the schema association must fail closed)
_SCHEMA_FINAL_BINDING = {
    # class followed by function / import / del / ordinary assignment
    "class_then_function": (
        "class Row:\n    price: float\n\n\ndef Row():\n    return None\n",
        None,
    ),
    "class_then_import": (
        "class Row:\n    price: float\n\n\nfrom myapp.other import Row\n",
        "myapp.other.Row",  # resolves the final import target, not the stale class
    ),
    "class_then_del": ("class Row:\n    price: float\n\n\ndel Row\n", None),
    "class_then_assignment": ("class Row:\n    price: float\n\n\nRow = int\n", None),
    # assignment / import followed by a final matching class (positive control)
    "assignment_then_class": ("Row = int\n\n\nclass Row:\n    price: float\n", "myapp.kernels.Row"),
    "import_then_class": (
        "from myapp.other import Row\n\n\nclass Row:\n    price: float\n",
        "myapp.kernels.Row",  # the final local class overrides the earlier import
    ),
    # imported project class left unshadowed (positive control)
    "imported_unshadowed": ("from myapp.other import Row\n", "myapp.other.Row"),
    # duplicate definitions in source order (the last class wins)
    "duplicate_classes": (
        "class Row:\n    price: float\n\n\nclass Row:\n    weight: int\n",
        "myapp.kernels.Row",
    ),
    # conditional bind after a definition (fail closed)
    "conditional_after_class": (
        "import os\n\n\nclass Row:\n    price: float\n\n\nif os.environ:\n    Row = int\n",
        None,
    ),
    # conditional bind before a later unconditional definition (positive control)
    "conditional_before_class": (
        "import os\n\n\nif os.environ:\n    Row = int\n\n\nclass Row:\n    price: float\n",
        "myapp.kernels.Row",
    ),
}


@pytest.mark.parametrize("case", sorted(_SCHEMA_FINAL_BINDING))
def test_schema_final_binding_matrix(tmp_path: Path, case: str) -> None:
    setup, expected = _SCHEMA_FINAL_BINDING[case]
    _write(tmp_path, "myapp/other.py", OTHER_MODULE)
    _write(tmp_path, "myapp/kernels.py", _total_kernel(setup))
    kern = function_named(analyze(tmp_path, FrameProvider()), "myapp.kernels.kern")
    # ``df.total()`` is claimed regardless of the schema outcome, so the receiver
    # (and its schema decision) is always observable.
    assert kern.plugin_claims, case
    receiver = kern.plugin_claims[0].receiver
    assert receiver is not None and receiver.arg_type == FRAME.key, case
    if expected is None:
        assert receiver.schema is None, case  # the stale class node is never selected
    else:
        assert receiver.schema is not None, case
        assert receiver.schema.identity == expected, case
        # The final target's fields — not the stale local ``price`` — are used
        # whenever the winning binder points elsewhere.
        if case in {"class_then_import", "imported_unshadowed", "duplicate_classes"}:
            fields = [(f.name, f.field_type) for f in receiver.schema.fields]
            assert fields == [("weight", "int")], case
