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
