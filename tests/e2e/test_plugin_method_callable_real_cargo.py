"""End-to-end real-cargo proof of plugin API 1.3 method + callable lowering (WP-4).

A method claim site (``s.reduce(udf)`` on a resident ``Series``) is lowered with
real cargo: core evaluates the receiver once, threads it as
``LoweringContext.receiver``, and fills ``CallableMeta.native_symbol`` with the
Rust symbol of the actually-generated accepted scalar native UDF, which the
plugin calls per element. The compiled extension runs and matches the pure-Python
fallback — the ``Series.map`` shape WP-5 needs, proven native-callable.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    Claimed,
    ClaimSite,
    CoverageDecl,
    LoweredExpr,
    NotCovered,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.models import RextioPlugin

SERIES = PluginType(
    key="rextio-series/series",
    annotations=("rextio_series_types.Series",),
    rust_type="SeriesData",
    conversion=None,  # resident: opaque, native-only
)

# A self-contained resident Rust type (no external crates). ``reduce_scalar``
# takes the generated native UDF as a plain ``fn(f64) -> PyResult<f64>`` and
# applies it to each element — the native-callable UDF path.
STRUCT_HELPER = (
    "struct SeriesData { values: Vec<f64> }\n"
    "impl SeriesData {\n"
    "    fn new(values: &Vec<f64>) -> SeriesData { SeriesData { values: values.clone() } }\n"
    "    fn reduce_scalar<F: Fn(f64) -> pyo3::PyResult<f64>>(&self, f: F)"
    " -> pyo3::PyResult<f64> {\n"
    "        let mut acc = 0.0f64;\n"
    "        for &v in &self.values { acc += f(v)?; }\n"
    "        Ok(acc)\n"
    "    }\n"
    "}"
)


class FakeSeriesPlugin:
    plugin_id = "rextio-series"
    api_version = "1.3"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-series", name="Series to Rust (e2e fake)")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("rextio_series",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id="rextio-series/make",
                provider="rextio-series",
                scope=RuleScope(kind="call", pattern="rextio_series.make"),
                constraint="Builds a resident series from a float list.",
                outcome="native",
                diagnostic_code=None,
                guidance="Pass a list[float].",
                stability="experimental",
            ),
            RuleRecord(
                id="rextio-series/reduce",
                provider="rextio-series",
                scope=RuleScope(kind="call", pattern="series.reduce"),
                constraint="Applies a scalar UDF to each element and sums.",
                outcome="native",
                diagnostic_code=None,
                guidance="Pass a scalar float->float UDF.",
                stability="experimental",
            ),
        )

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (SERIES,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "rextio_series.make":
            return Claimed(rule_id="rextio-series/make", result_type=SERIES.key)
        # A method claim: the receiver is a resident Series, the sole argument a
        # project-function UDF. Fail closed unless the UDF is a proven scalar
        # native function (accepts_native) — WP-5's Series.map contract.
        if (
            site.kind == "call"
            and site.target.rpartition(".")[2] == "reduce"
            and site.receiver is not None
            and site.receiver.arg_type == SERIES.key
            and site.callables
            and site.callables[0].accepts_native
        ):
            return Claimed(rule_id="rextio-series/reduce", result_type="float")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx) -> LoweredExpr:
        if site.target == "rextio_series.make":
            return LoweredExpr(
                rust=f"SeriesData::new(&{ctx.operands[0]})", helpers=(STRUCT_HELPER,)
            )
        if site.target.rpartition(".")[2] == "reduce":
            symbol = site.callables[0].native_symbol
            assert symbol is not None, "native symbol must be filled at lower time"
            # ctx.receiver is the once-evaluated receiver; the UDF is the actual
            # generated native helper, called per element.
            return LoweredExpr(
                rust=f"{ctx.receiver}.reduce_scalar({symbol})?", helpers=(STRUCT_HELPER,)
            )
        raise AssertionError(f"unexpected lower target: {site.target}")

    def crate_dependencies(self):
        return ()


def _function_source(source: str, name: str) -> str:
    """Return the generated source of one Rust function (up to the next ``fn``)."""
    marker = f"fn {name}"
    index = source.find(marker)
    assert index != -1, f"function {name} not found in generated source"
    tail = source[index:]
    nxt = tail.find("\nfn ", 1)
    return tail if nxt == -1 else tail[:nxt]


class _FakeEntryPoint:
    name = "rextio-series"
    dist = None

    def load(self) -> object:
        return FakeSeriesPlugin()


def _write_project(tmp_path: Path) -> Path:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[plugins]
enabled = ["rextio-series"]
""",
        encoding="utf-8",
    )
    runtime = tmp_path / "runtime"
    pkg = runtime / "rextio_series"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        """
class Series:
    def __init__(self, values):
        self.values = [float(v) for v in values]

    def reduce(self, f):
        acc = 0.0
        for v in self.values:
            acc += f(v)
        return acc


def make(values):
    return Series(values)
""",
        encoding="utf-8",
    )
    (runtime / "rextio_series_types.py").write_text(
        "from rextio_series import Series\n", encoding="utf-8"
    )
    app = tmp_path / "src" / "series_app"
    app.mkdir(parents=True)
    (app / "__init__.py").write_text("", encoding="utf-8")
    return app


KERNEL_SOURCE = """
import rextio
import rextio_series
from rextio_series_types import Series


@rextio.native
def scaled(x: float) -> float:
    return x * 2.0 + 1.0


def run(values: list[float]) -> float:
    s = rextio_series.make(values)
    return s.reduce(scaled)


def run_chained(values: list[float]) -> float:
    # Direct-temporary receiver: the resident Series produced by ``make`` is the
    # unsafe (call-valued) receiver of ``.reduce`` with no intervening local, so
    # core must bind it to a single-use temporary and construct it exactly once.
    return rextio_series.make(values).reduce(scaled)
"""


def test_real_cargo_method_callable_route_builds_and_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rextio.plugins import loader as plugin_loader

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))

    app = _write_project(tmp_path)
    (app / "kernels.py").write_text(KERNEL_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path / "runtime"))

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"

    lib_rs = (tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    # The receiver was threaded (the resident local ``s``) and the UDF's actual
    # generated native symbol is called per element — not a placeholder.
    assert "reduce_scalar(series_app__kernels__scaled)" in lib_rs
    # The scalar UDF is an EXPLICITLY @rextio.native-decorated real native helper
    # reachable by its symbol — the decorated-UDF path is proven end to end.
    assert "fn series_app__kernels__scaled" in lib_rs

    # The direct-temporary chained receiver binds the unsafe (call-valued) Series
    # to a single-use temporary and constructs it exactly ONCE.
    chained = _function_source(lib_rs, "series_app__kernels__run_chained")
    assert chained.count("SeriesData::new(") == 1
    assert "__rextio_recv" in chained

    def _run(kernels: object) -> list[float]:
        return [
            kernels.run([1.0, 2.0, 3.0]),
            kernels.run([]),
            kernels.run([10.0]),
            kernels.run_chained([1.0, 2.0, 3.0]),
            kernels.run_chained([]),
            kernels.run_chained([10.0]),
        ]

    def _fresh() -> object:
        for module_name in (
            "_rextio_native",
            "series_app.kernels",
            "rextio_series",
            "rextio_series_types",
        ):
            sys.modules.pop(module_name, None)
        return importlib.import_module("series_app.kernels")

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    native_results = _run(_fresh())
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    fallback_results = _run(_fresh())

    # Native equals fallback (behavior compatible), and matches the hand result:
    # sum(2x+1) = 2*sum + n. [1,2,3] -> 2*6+3 = 15; [] -> 0; [10] -> 21. The
    # chained direct-temporary path (run_chained) computes the identical result.
    assert native_results == fallback_results
    assert native_results == [15.0, 0.0, 21.0, 15.0, 0.0, 21.0]

    for module_name in (
        "_rextio_native",
        "series_app.kernels",
        "rextio_series",
        "rextio_series_types",
    ):
        sys.modules.pop(module_name, None)
