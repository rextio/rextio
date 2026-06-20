from __future__ import annotations

from pathlib import Path

import pytest

from rextio.config.loader import ConfigError, load_config


def test_load_config_rejects_unknown_top_level_section(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[future]
enabled = true
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"unsupported config section: \[future\]"):
        load_config(tmp_path)


def test_load_config_rejects_unknown_section_key(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
magic_backend = "llvm"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"unsupported config key: \[build\]\.magic_backend"):
        load_config(tmp_path)


def test_load_config_rejects_non_table_section(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text('build = "rust"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=r"config section \[build\] must be a table"):
        load_config(tmp_path)


def test_load_config_rejects_unsupported_public_1_policy(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
allow_dynamic_features = true
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"allow_dynamic_features"):
        load_config(tmp_path)

