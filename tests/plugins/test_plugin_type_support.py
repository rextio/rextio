"""Plugin API 1.3: type-level Rust module support (``uses``/``helpers``).

WP-6: a signature-only accepted function (a plugin-typed parameter/return with
zero claims) still needs the plugin type's boundary conversion / named struct
support. That support is declared on :class:`PluginType`, serialized so
provider/report/cache identity moves when it changes, rejected for providers
below plugin API 1.3, and threaded through :class:`RxtPluginType` and the
build/type-map path.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from rextio.build.orchestrator import _plugin_lowering_inputs
from rextio.config.schema import PluginConfig, RextioConfig
from rextio.ir.types import RxtPluginType
from rextio.plugins.api import BoundaryConversion, CoverageDecl, PluginType
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)
from rextio.targets.models import TargetSpec

SERIES_KEY = "rextio-pandas/series-f64"
RESULT_ONLY_KEY = "rextio-pandas/result-mask"
SERIES_USE = "use pandas_rs::series::SeriesF64;"
SERIES_STRUCT = "pub struct RxtSeriesF64 { data: Vec<f64> }"
SERIES_EXTRACT = "fn __rxtpd_extract_series_f64(v: RxtSeriesF64) -> RxtSeriesF64 { v }"

MATERIALIZED_CONVERSION = BoundaryConversion(
    param_rust="RxtSeriesF64",
    param_expr="__rxtpd_extract_series_f64({param})",
    return_rust="RxtSeriesF64",
    return_expr="{value}",
)


def test_empty_support_omitted_preserves_legacy_byte_shape() -> None:
    # A materialized 1.1/1.2 type with no module support keeps its EXACT legacy
    # serialized shape: no ``uses``/``helpers`` keys at all.
    materialized = PluginType(
        key=SERIES_KEY,
        annotations=("rextio_pandas.types.SeriesF64",),
        rust_type="RxtSeriesF64",
        conversion=MATERIALIZED_CONVERSION,
    )
    data = materialized.to_dict()
    assert "uses" not in data
    assert "helpers" not in data
    assert data == {
        "key": SERIES_KEY,
        "annotations": ["rextio_pandas.types.SeriesF64"],
        "rust_type": "RxtSeriesF64",
        "conversion": {
            "param_rust": "RxtSeriesF64",
            "param_expr": "__rxtpd_extract_series_f64({param})",
            "return_rust": "RxtSeriesF64",
            "return_expr": "{value}",
        },
    }


def test_non_empty_support_serialized_deterministically_and_moves_identity() -> None:
    plugin_type = PluginType(
        key=SERIES_KEY,
        annotations=("rextio_pandas.types.SeriesF64",),
        rust_type="RxtSeriesF64",
        conversion=MATERIALIZED_CONVERSION,
        uses=(SERIES_USE,),
        helpers=(SERIES_STRUCT, SERIES_EXTRACT),
    )
    data = plugin_type.to_dict()
    # Order-preserving list form (deterministic, JSON-serializable).
    assert data["uses"] == [SERIES_USE]
    assert data["helpers"] == [SERIES_STRUCT, SERIES_EXTRACT]
    # Support changes the serialized identity, so any report/cache fingerprint
    # keyed on ``to_dict()`` moves when the support text changes.
    without_support = PluginType(
        key=SERIES_KEY,
        annotations=("rextio_pandas.types.SeriesF64",),
        rust_type="RxtSeriesF64",
        conversion=MATERIALIZED_CONVERSION,
    )
    assert plugin_type.to_dict() != without_support.to_dict()


def test_resident_type_carries_support_without_a_conversion() -> None:
    # A resident type has ``conversion=None`` yet may still own a named Rust
    # struct through ``helpers`` (type-level ownership, not boundary-level).
    resident = PluginType(
        key="rextio-nx/graph",
        annotations=("rextio_nx.types.Graph",),
        rust_type="RxtNxGraph",
        conversion=None,
        helpers=(SERIES_STRUCT,),
    )
    data = resident.to_dict()
    assert data["resident"] is True
    assert data["conversion"] is None
    assert data["helpers"] == [SERIES_STRUCT]
    assert "uses" not in data


@pytest.mark.parametrize(
    "bad",
    [
        ["use x;"],  # a list, not a tuple
        "use x;",  # a bare string (iterable of chars) is not a tuple
        (1,),  # non-string element
        (b"x",),  # bytes, not str
        ("",),  # empty string
    ],
)
def test_malformed_uses_fails_loud(bad: object) -> None:
    with pytest.raises(ValueError, match="uses"):
        PluginType(
            key="rextio-x/t",
            annotations=("rextio_x.T",),
            rust_type="T",
            uses=bad,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "bad",
    [
        ["fn h(){}"],
        "fn h(){}",
        (1,),
        (b"x",),
        ("",),
    ],
)
def test_malformed_helpers_fails_loud(bad: object) -> None:
    with pytest.raises(ValueError, match="helpers"):
        PluginType(
            key="rextio-x/t",
            annotations=("rextio_x.T",),
            rust_type="T",
            helpers=bad,  # type: ignore[arg-type]
        )


def _support_provider(api_version: str) -> object:
    class SupportProvider:
        plugin_id = "rextio-pandas"

        def __init__(self) -> None:
            self.api_version = api_version

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("pandas",))

        def describe(self, config: RextioConfig) -> tuple[object, ...]:
            return ()

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (
                PluginType(
                    key=SERIES_KEY,
                    annotations=("rextio_pandas.types.SeriesF64",),
                    rust_type="RxtSeriesF64",
                    conversion=MATERIALIZED_CONVERSION,
                    uses=(SERIES_USE,),
                    helpers=(SERIES_STRUCT, SERIES_EXTRACT),
                ),
            )

        def claim(self, site: object, config: RextioConfig) -> object:
            raise AssertionError

        def lower(self, site: object, ctx: object) -> object:
            raise AssertionError

        def crate_dependencies(self) -> tuple[object, ...]:
            return ()

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-pandas", name="pandas")

    return SupportProvider()


def _single_type_provider(api_version: str, plugin_type: PluginType) -> object:
    class SingleTypeProvider:
        plugin_id = "rextio-pandas"

        def __init__(self) -> None:
            self.api_version = api_version

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("pandas",))

        def describe(self, config: RextioConfig) -> tuple[object, ...]:
            del config
            return ()

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (plugin_type,)

        def claim(self, site: object, config: RextioConfig) -> object:
            raise AssertionError

        def lower(self, site: object, ctx: object) -> object:
            raise AssertionError

        def crate_dependencies(self) -> tuple[object, ...]:
            return ()

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-pandas", name="pandas")

    return SingleTypeProvider()


def _entry_point(provider: object) -> object:
    class _EntryPoint:
        name = "rextio-pandas"
        dist = None

        def load(self) -> object:
            return provider

    return _EntryPoint()


def test_loader_rejects_type_support_below_api_13() -> None:
    with pytest.raises(PluginError, match="type-level support requires api_version >= 1.3"):
        load_plugin_registry(
            PluginConfig(enabled=("rextio-pandas",)),
            TargetSpec(language="rust"),
            entry_points=(_entry_point(_support_provider("1.2")),),
        )


def test_loader_accepts_type_support_at_api_13() -> None:
    registry = load_plugin_registry(
        PluginConfig(enabled=("rextio-pandas",)),
        TargetSpec(language="rust"),
        entry_points=(_entry_point(_support_provider("1.3")),),
    )
    [binding] = registry.types
    assert binding.plugin_type.uses == (SERIES_USE,)
    assert binding.plugin_type.helpers == (SERIES_STRUCT, SERIES_EXTRACT)


def test_api_15_loads_result_only_resident_type_without_source_spelling() -> None:
    result_only = PluginType(
        key=RESULT_ONLY_KEY,
        annotations=(),
        rust_type="RxtResultMask",
        conversion=None,
    )
    registry = load_plugin_registry(
        PluginConfig(enabled=("rextio-pandas",)),
        TargetSpec(language="rust"),
        entry_points=(
            _entry_point(_single_type_provider("1.5", result_only)),
        ),
    )

    [binding] = registry.types
    assert binding.plugin_type is result_only
    assert result_only.to_dict() == {
        "key": RESULT_ONLY_KEY,
        "annotations": [],
        "rust_type": "RxtResultMask",
        "resident": True,
        "conversion": None,
    }

    maps, _providers, by_key = _plugin_lowering_inputs(
        SimpleNamespace(plugins=registry)
    )
    assert maps is not None and by_key is not None
    assert by_key[RESULT_ONLY_KEY].resident is True
    assert maps.by_key[RESULT_ONLY_KEY] is by_key[RESULT_ONLY_KEY]
    assert maps.by_spelling == {}
    assert "" not in maps.by_spelling


@pytest.mark.parametrize(
    ("api_version", "conversion"),
    [
        ("1.4", None),
        ("1.5", MATERIALIZED_CONVERSION),
    ],
)
def test_empty_annotations_remain_invalid_before_15_or_when_materialized(
    api_version: str,
    conversion: BoundaryConversion | None,
) -> None:
    plugin_type = PluginType(
        key=RESULT_ONLY_KEY,
        annotations=(),
        rust_type="RxtResultMask",
        conversion=conversion,
    )

    with pytest.raises(PluginError, match="declares no annotation spellings"):
        load_plugin_registry(
            PluginConfig(enabled=("rextio-pandas",)),
            TargetSpec(language="rust"),
            entry_points=(
                _entry_point(_single_type_provider(api_version, plugin_type)),
            ),
        )


def test_rxt_plugin_type_empty_support_byte_shape_unchanged() -> None:
    rxt = RxtPluginType(key=SERIES_KEY, native_rust="RxtSeriesF64")
    assert rxt.to_dict() == {
        "kind": "plugin",
        "key": SERIES_KEY,
        "native_rust": "RxtSeriesF64",
    }


def test_rxt_plugin_type_serializes_non_empty_support() -> None:
    rxt = RxtPluginType(
        key=SERIES_KEY,
        native_rust="RxtSeriesF64",
        uses=(SERIES_USE,),
        helpers=(SERIES_STRUCT,),
    )
    data = rxt.to_dict()
    assert data["uses"] == [SERIES_USE]
    assert data["helpers"] == [SERIES_STRUCT]


def test_orchestrator_threads_support_into_rxt_plugin_type() -> None:
    materialized = PluginType(
        key=SERIES_KEY,
        annotations=("rextio_pandas.types.SeriesF64",),
        rust_type="RxtSeriesF64",
        conversion=MATERIALIZED_CONVERSION,
        uses=(SERIES_USE,),
        helpers=(SERIES_STRUCT, SERIES_EXTRACT),
    )
    resident = PluginType(
        key="rextio-nx/graph",
        annotations=("rextio_nx.types.Graph",),
        rust_type="RxtNxGraph",
        conversion=None,
        helpers=("pub struct RxtNxGraph { nodes: Vec<i64> }",),
    )
    registry = PluginRegistry(
        enabled=("rextio-pandas", "rextio-nx"),
        types=(
            PluginTypeBinding(plugin_id="rextio-pandas", plugin_type=materialized),
            PluginTypeBinding(plugin_id="rextio-nx", plugin_type=resident),
        ),
        providers=(PluginProviderBinding(plugin_id="rextio-pandas", provider=object()),),
    )
    maps, _providers, by_key = _plugin_lowering_inputs(SimpleNamespace(plugins=registry))
    assert by_key is not None and maps is not None
    assert by_key[SERIES_KEY].uses == (SERIES_USE,)
    assert by_key[SERIES_KEY].helpers == (SERIES_STRUCT, SERIES_EXTRACT)
    assert by_key["rextio-nx/graph"].resident is True
    assert by_key["rextio-nx/graph"].helpers == ("pub struct RxtNxGraph { nodes: Vec<i64> }",)
    # The by-spelling map shares the same instances, so signatures resolved
    # during lowering carry the support too.
    assert maps.by_spelling["rextio_pandas.types.SeriesF64"] is by_key[SERIES_KEY]
