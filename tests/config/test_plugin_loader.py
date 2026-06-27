from __future__ import annotations

from typing import Any

import pytest

from rextio.config.schema import PluginConfig
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import TargetSpec


class FakeEntryPoint:
    def __init__(self, name: str, payload: Any) -> None:
        self.name = name
        self._payload = payload

    def load(self) -> Any:
        return self._payload


def test_load_plugin_registry_activates_configured_installed_plugin() -> None:
    registry = load_plugin_registry(
        PluginConfig(enabled=("numpy-rust",)),
        TargetSpec(
            language="rust",
            version="stable",
            build_options={"binding": "pyo3"},
        ),
        entry_points=(
            FakeEntryPoint(
                "numpy-rust",
                lambda: {
                    "name": "Python NumPy to rust-numpy",
                    "source_language": "python",
                    "target_language": "rust",
                    "target_versions": ["stable"],
                    "target_build_options": {"binding": "pyo3"},
                    "rules": ["numpy.ndarray"],
                    "packages": ["numpy"],
                },
            ),
        ),
    )

    assert [plugin.id for plugin in registry.discovered] == ["numpy-rust"]
    assert [plugin.id for plugin in registry.active] == ["numpy-rust"]
    assert registry.active[0].entry_point == "rextio.plugins:numpy-rust"
    assert registry.active[0].packages == ("numpy",)


def test_load_plugin_registry_does_not_activate_unconfigured_installed_plugin() -> None:
    registry = load_plugin_registry(
        PluginConfig(),
        TargetSpec(language="rust"),
        entry_points=(
            FakeEntryPoint(
                "numpy-rust",
                {
                    "target_language": "rust",
                },
            ),
        ),
    )

    assert [plugin.id for plugin in registry.discovered] == ["numpy-rust"]
    assert registry.active == ()


def test_load_plugin_registry_accepts_rextio_plugin_object() -> None:
    registry = load_plugin_registry(
        PluginConfig(enabled=("rust-basic",)),
        TargetSpec(language="rust"),
        entry_points=(
            FakeEntryPoint(
                "rust-basic",
                RextioPlugin(
                    id="rust-basic",
                    name="Rust basic plugin",
                    target_language="rust",
                    rules=("python.basic",),
                ),
            ),
        ),
    )

    assert [plugin.id for plugin in registry.active] == ["rust-basic"]
    assert registry.active[0].rules == ("python.basic",)


def test_load_plugin_registry_filters_by_target_version() -> None:
    registry = load_plugin_registry(
        PluginConfig(enabled=("mojo-dev",)),
        TargetSpec(language="mojo", version="25.2"),
        entry_points=(
            FakeEntryPoint(
                "mojo-dev",
                {
                    "target_language": "mojo",
                    "target_versions": ["25.1"],
                },
            ),
        ),
    )

    assert [plugin.id for plugin in registry.discovered] == ["mojo-dev"]
    assert registry.active == ()


def test_load_plugin_registry_rejects_missing_enabled_plugin() -> None:
    with pytest.raises(PluginError, match=r"enabled plugin was not discovered"):
        load_plugin_registry(
            PluginConfig(enabled=("missing",)),
            TargetSpec(language="rust"),
            entry_points=(),
        )


def test_load_plugin_registry_rejects_duplicate_plugin_id() -> None:
    with pytest.raises(PluginError, match=r"duplicate plugin id: rust-basic"):
        load_plugin_registry(
            PluginConfig(enabled=("rust-basic",)),
            TargetSpec(language="rust"),
            entry_points=(
                FakeEntryPoint("rust-basic", {"target_language": "rust"}),
                FakeEntryPoint("rust-other", {"id": "rust-basic", "target_language": "rust"}),
            ),
        )
