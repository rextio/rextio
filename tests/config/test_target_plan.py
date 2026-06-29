from __future__ import annotations

from pathlib import Path

import pytest

from rextio.config.loader import load_config
from rextio.targets.plan import TargetPlanError, create_target_plan


def test_create_target_plan_rejects_import_policy_for_inactive_plugin(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[imports.packages]
"some_pkg" = { policy = "plugin", plugin = "some-plugin" }
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    with pytest.raises(TargetPlanError, match=r"plugin 'some-plugin'.*not active"):
        create_target_plan(tmp_path, config)


def test_inert_target_keys_warn() -> None:
    import warnings

    from rextio.config.schema import RextioConfig, TargetConfig
    from rextio.targets.plan import create_target_spec

    config = RextioConfig(target=TargetConfig(version="1.2", build_options={"opt": "x"}))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        create_target_spec(config)
    assert any(
        issubclass(w.category, RuntimeWarning) and "no effect" in str(w.message)
        for w in caught
    )
