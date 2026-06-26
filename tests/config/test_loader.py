from __future__ import annotations

from pathlib import Path

import pytest

from rextio.config.loader import ConfigError, load_config, override_config


def test_load_config_defaults_to_auto_native_discovery(tmp_path: Path) -> None:
    config = load_config(tmp_path)

    assert config.policy.native_marker == "auto"
    assert config.policy.native_top_level is False


def test_load_config_allows_decorator_only_native_discovery(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.policy.native_marker == "decorator"


def test_load_config_reads_build_and_executable_options(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "nuitka"
fallback_threshold = 12

[rust]
build_tool = "cargo"
importable = true
crate_name = "demo-rust"

[executable]
entrypoint = "demo.cli:main"
name = "demo-tool"
backend = "nuitka"
nuitka_mode = "onefile"
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.build.fallback_backend == "nuitka"
    assert config.build.fallback_threshold == 12
    assert config.rust.build_tool == "cargo"
    assert config.rust.importable is True
    assert config.rust.crate_name == "demo-rust"
    assert config.executable.entrypoint == "demo.cli:main"
    assert config.executable.name == "demo-tool"
    assert config.executable.backend == "nuitka"
    assert config.executable.nuitka_mode == "onefile"


def test_load_config_reads_target_and_plugin_options(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
native_backend = "mojo"

[target]
version = "25.1"

[target.build_options]
optimization = "speed"
abi = "cpython"

[plugins]
enabled = ["numpy-mojo"]
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.build.native_backend == "mojo"
    assert config.target.version == "25.1"
    assert config.target.build_options == {"optimization": "speed", "abi": "cpython"}
    assert config.plugins.enabled == ("numpy-mojo",)


def test_load_config_applies_environment_overrides(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[build]
fallback_backend = "cpython"
fallback_threshold = 12

[policy]
native_marker = "decorator"
boundary_warnings = true
""",
        encoding="utf-8",
    )

    config = load_config(
        tmp_path,
        environ={
            "REXTIO_FALLBACK_BACKEND": "nuitka",
            "REXTIO_BOUNDARY_FALLBACK_THRESHOLD": "5",
            "REXTIO_RUST_BUILD_TOOL": "cargo",
            "REXTIO_RUST_IMPORTABLE": "true",
            "REXTIO_RUST_CRATE_NAME": "demo_env_rust",
            "REXTIO_TARGET_LANGUAGE": "julia",
            "REXTIO_TARGET_VERSION": "1.11",
            "REXTIO_TARGET_BUILD_OPTIONS": "profile=release,threads=auto",
            "REXTIO_PLUGINS_ENABLED": "numpy-julia",
            "REXTIO_EXECUTABLE_ENTRYPOINT": "demo.cli:main",
            "REXTIO_EXECUTABLE_NAME": "demo-env",
            "REXTIO_EXECUTABLE_BACKEND": "nuitka",
            "REXTIO_NUITKA_MODE": "onefile",
            "REXTIO_NATIVE_MARKER": "auto",
            "REXTIO_BOUNDARY_WARNINGS": "false",
            "REXTIO_NATIVE_TOP_LEVEL": "true",
        },
    )

    assert config.build.fallback_backend == "nuitka"
    assert config.build.fallback_threshold == 5
    assert config.rust.build_tool == "cargo"
    assert config.rust.importable is True
    assert config.rust.crate_name == "demo_env_rust"
    assert config.build.native_backend == "julia"
    assert config.target.version == "1.11"
    assert config.target.build_options == {"profile": "release", "threads": "auto"}
    assert config.plugins.enabled == ("numpy-julia",)
    assert config.executable.entrypoint == "demo.cli:main"
    assert config.executable.name == "demo-env"
    assert config.executable.backend == "nuitka"
    assert config.executable.nuitka_mode == "onefile"
    assert config.policy.native_marker == "auto"
    assert not config.policy.boundary_warnings
    assert config.policy.native_top_level is True


def test_override_config_applies_cli_style_overrides(tmp_path: Path) -> None:
    config = override_config(
        load_config(
            tmp_path,
            environ={
                "REXTIO_FALLBACK_BACKEND": "nuitka",
                "REXTIO_BOUNDARY_FALLBACK_THRESHOLD": "5",
            },
        ),
        {
            ("build", "fallback_backend"): "cpython",
            ("build", "native_backend"): "mojo",
            ("build", "fallback_threshold"): 3,
            ("rust", "importable"): True,
            ("rust", "crate_name"): "demo_cli_rust",
            ("target", "version"): "25.1",
            ("target", "build_options"): {"profile": "debug"},
            ("plugins", "enabled"): ("numpy-mojo",),
            ("policy", "native_marker"): "decorator",
            ("policy", "native_top_level"): True,
        },
    )

    assert config.build.native_backend == "mojo"
    assert config.build.fallback_backend == "cpython"
    assert config.build.fallback_threshold == 3
    assert config.rust.importable is True
    assert config.rust.crate_name == "demo_cli_rust"
    assert config.target.version == "25.1"
    assert config.target.build_options == {"profile": "debug"}
    assert config.plugins.enabled == ("numpy-mojo",)
    assert config.policy.native_marker == "decorator"
    assert config.policy.native_top_level is True


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


def test_load_config_rejects_invalid_environment_integer(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"REXTIO_BOUNDARY_FALLBACK_THRESHOLD"):
        load_config(tmp_path, environ={"REXTIO_BOUNDARY_FALLBACK_THRESHOLD": "not-an-int"})


def test_load_config_rejects_invalid_environment_boolean(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"REXTIO_BOUNDARY_WARNINGS"):
        load_config(tmp_path, environ={"REXTIO_BOUNDARY_WARNINGS": "maybe"})


def test_load_config_rejects_invalid_rust_crate_name(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
crate_name = "123-invalid"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"crate_name"):
        load_config(tmp_path)


def test_load_config_rejects_invalid_environment_target_build_options(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"REXTIO_TARGET_BUILD_OPTIONS"):
        load_config(tmp_path, environ={"REXTIO_TARGET_BUILD_OPTIONS": "profile"})


def test_load_config_rejects_non_string_target_build_option(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[target.build_options]
profile = 1
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"target.*build_options"):
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


def test_load_config_rejects_unknown_native_marker_policy(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "always"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"native_marker"):
        load_config(tmp_path)
