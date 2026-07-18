from __future__ import annotations

from pathlib import Path

import pytest

from rextio.config.loader import ConfigError, load_config, override_config


def test_executable_fallback_defaults_to_python_subprocess(tmp_path: Path) -> None:
    config = load_config(tmp_path)

    assert config.executable.fallback == "python-subprocess"
    assert config.executable.hybrid_runtime == "source"


@pytest.mark.parametrize(
    ("legacy", "canonical"),
    [("source", "python-subprocess"), ("nuitka", "nuitka-sidecar")],
)
def test_legacy_hybrid_runtime_maps_to_canonical_fallback(
    tmp_path: Path, legacy: str, canonical: str
) -> None:
    (tmp_path / "rextio.toml").write_text(
        f'[executable]\nhybrid_runtime = "{legacy}"\n', encoding="utf-8"
    )

    config = load_config(tmp_path)

    assert config.executable.fallback == canonical
    assert config.executable.hybrid_runtime == legacy


def test_canonical_and_legacy_fallback_conflict_is_actionable(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        '[executable]\nfallback = "error"\nhybrid_runtime = "source"\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="fallback='error'.*hybrid_runtime='source'"):
        load_config(tmp_path)


def test_environment_canonical_fallback_overrides_legacy_toml(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        '[executable]\nhybrid_runtime = "source"\n', encoding="utf-8"
    )

    config = load_config(tmp_path, environ={"REXTIO_EXECUTABLE_FALLBACK": "nuitka-sidecar"})

    assert config.executable.fallback == "nuitka-sidecar"
    assert config.executable.hybrid_runtime == "nuitka"


def test_cli_style_legacy_override_beats_lower_canonical_setting(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text('[executable]\nfallback = "error"\n', encoding="utf-8")

    config = override_config(load_config(tmp_path), {("executable", "hybrid_runtime"): "source"})

    assert config.executable.fallback == "python-subprocess"


@pytest.mark.parametrize("key", ["fallback", "hybrid_runtime"])
def test_executable_fallback_inputs_reject_non_string_types(tmp_path: Path, key: str) -> None:
    (tmp_path / "rextio.toml").write_text(f"[executable]\n{key} = []\n", encoding="utf-8")

    with pytest.raises(ConfigError, match=rf"\[executable\]\.{key} must be a string"):
        load_config(tmp_path)


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
native_backend = "rust"

[target]
version = "25.1"

[target.build_options]
optimization = "speed"
abi = "cpython"

[plugins]
enabled = ["numpy-rust"]
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.build.native_backend == "rust"
    assert config.target.version == "25.1"
    assert config.target.build_options == {"optimization": "speed", "abi": "cpython"}
    assert config.plugins.enabled == ("numpy-rust",)


def test_load_config_rejects_unsupported_native_backend(tmp_path: Path) -> None:
    # rust is the only accepted native_backend in 0.1.0; nothing else is a
    # planning value anymore.
    (tmp_path / "rextio.toml").write_text(
        """
[build]
native_backend = "zig"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r'native_backend.*Use "rust"'):
        load_config(tmp_path)


def test_load_config_reads_import_policy_options(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[imports]
default_external_policy = "analyze"

[imports.packages]
"some_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.imports.default_external_policy == "analyze"
    assert config.imports.packages["some_pkg"].policy == "try-native"
    assert config.imports.packages["some_pkg"].max_depth == 1
    assert config.imports.packages["legacy_pkg"].policy == "fallback"
    assert config.imports.packages["known_pkg"].policy == "plugin"
    assert config.imports.packages["known_pkg"].plugin == "known-rust"


def test_load_config_reads_embedding_options(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[embedding]
enabled = true
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.embedding.enabled is True


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
            "REXTIO_TARGET_LANGUAGE": "rust",
            "REXTIO_TARGET_VERSION": "1.11",
            "REXTIO_TARGET_BUILD_OPTIONS": "profile=release,threads=auto",
            "REXTIO_PLUGINS_ENABLED": "numpy-env",
            "REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY": "try-native",
            "REXTIO_IMPORTS_PACKAGES": "safe_pkg=try-native,legacy_pkg=fallback",
            "REXTIO_EMBED_HELPERS": "true",
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
    assert config.build.native_backend == "rust"
    assert config.target.version == "1.11"
    assert config.target.build_options == {"profile": "release", "threads": "auto"}
    assert config.plugins.enabled == ("numpy-env",)
    assert config.imports.default_external_policy == "try-native"
    assert config.imports.packages["safe_pkg"].policy == "try-native"
    assert config.imports.packages["legacy_pkg"].policy == "fallback"
    assert config.embedding.enabled is True
    assert config.executable.entrypoint == "demo.cli:main"
    assert config.executable.name == "demo-env"
    assert config.executable.backend == "nuitka"
    assert config.executable.nuitka_mode == "onefile"
    assert config.policy.native_marker == "auto"
    assert not config.policy.boundary_warnings
    assert config.policy.native_top_level is True


def test_build_timeout_seconds_precedence(tmp_path: Path) -> None:
    from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS

    # Default.
    assert load_config(tmp_path).build.build_timeout_seconds == DEFAULT_BUILD_TIMEOUT_SECONDS

    # toml.
    (tmp_path / "rextio.toml").write_text(
        "[build]\nbuild_timeout_seconds = 120\n", encoding="utf-8"
    )
    assert load_config(tmp_path).build.build_timeout_seconds == 120

    # env beats toml.
    config = load_config(tmp_path, environ={"REXTIO_BUILD_TIMEOUT": "90"})
    assert config.build.build_timeout_seconds == 90.0

    # CLI override beats env/toml.
    overridden = override_config(config, {("build", "build_timeout_seconds"): 45.0})
    assert overridden.build.build_timeout_seconds == 45.0


def test_build_timeout_seconds_rejects_non_positive(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"REXTIO_BUILD_TIMEOUT"):
        load_config(tmp_path, environ={"REXTIO_BUILD_TIMEOUT": "0"})
    (tmp_path / "rextio.toml").write_text("[build]\nbuild_timeout_seconds = -5\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"build_timeout_seconds"):
        load_config(tmp_path)


def test_build_timeout_seconds_rejects_inf_and_nan(tmp_path: Path) -> None:
    # `float("inf")`/`float("nan")` parse fine but must be rejected: inf disables
    # the timeout, and nan slips past a bare `<= 0` check.
    for raw in ("inf", "nan"):
        with pytest.raises(ConfigError, match=r"REXTIO_BUILD_TIMEOUT"):
            load_config(tmp_path, environ={"REXTIO_BUILD_TIMEOUT": raw})
    (tmp_path / "rextio.toml").write_text(
        "[build]\nbuild_timeout_seconds = nan\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match=r"build_timeout_seconds"):
        load_config(tmp_path)


def test_build_timeout_seconds_rejects_absurdly_large_values(tmp_path: Path) -> None:
    # A finite but absurd timeout effectively disables the bound and overflows the
    # C-level select timeout; reject anything past the 7-day cap.
    from rextio.build.subprocess_utils import MAX_BUILD_TIMEOUT_SECONDS

    too_big = MAX_BUILD_TIMEOUT_SECONDS + 1
    with pytest.raises(ConfigError, match=r"REXTIO_BUILD_TIMEOUT"):
        load_config(tmp_path, environ={"REXTIO_BUILD_TIMEOUT": str(too_big)})
    (tmp_path / "rextio.toml").write_text(
        f"[build]\nbuild_timeout_seconds = {too_big}\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match=r"build_timeout_seconds"):
        load_config(tmp_path)
    # The cap itself is accepted.
    (tmp_path / "rextio.toml").write_text(
        f"[build]\nbuild_timeout_seconds = {MAX_BUILD_TIMEOUT_SECONDS}\n", encoding="utf-8"
    )
    assert load_config(tmp_path).build.build_timeout_seconds == MAX_BUILD_TIMEOUT_SECONDS


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
            ("build", "native_backend"): "rust",
            ("build", "fallback_threshold"): 3,
            ("rust", "importable"): True,
            ("rust", "crate_name"): "demo_cli_rust",
            ("target", "version"): "25.1",
            ("target", "build_options"): {"profile": "debug"},
            ("plugins", "enabled"): ("numpy-cli",),
            ("imports", "default_external_policy"): "analyze",
            ("imports", "packages"): {"safe_pkg": {"policy": "try-native", "max_depth": 1}},
            ("embedding", "enabled"): True,
            ("policy", "native_marker"): "decorator",
            ("policy", "native_top_level"): True,
        },
    )

    assert config.build.native_backend == "rust"
    assert config.build.fallback_backend == "cpython"
    assert config.build.fallback_threshold == 3
    assert config.rust.importable is True
    assert config.rust.crate_name == "demo_cli_rust"
    assert config.target.version == "25.1"
    assert config.target.build_options == {"profile": "debug"}
    assert config.plugins.enabled == ("numpy-cli",)
    assert config.imports.default_external_policy == "analyze"
    assert config.imports.packages["safe_pkg"].policy == "try-native"
    assert config.imports.packages["safe_pkg"].max_depth == 1
    assert config.embedding.enabled is True
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


def test_load_config_rejects_import_plugin_policy_without_plugin(tmp_path: Path) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[imports.packages]
"some_pkg" = { policy = "plugin" }
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"plugin is required"):
        load_config(tmp_path)


def test_load_config_rejects_unknown_embedding_keys(tmp_path: Path) -> None:
    # [embedding] accepts only `enabled`; an unknown key must be rejected rather
    # than silently ignored.
    (tmp_path / "rextio.toml").write_text(
        """
[embedding]
bogus_option = 25
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match=r"embedding"):
        load_config(tmp_path)


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


def test_load_config_ignores_unknown_environment_variables(tmp_path: Path) -> None:
    # An unrecognized REXTIO_* variable (including a typo) is silently
    # ignored, like any junk environment variable - only the names in
    # ENVIRONMENT_OVERRIDES are consulted.
    (tmp_path / "rextio.toml").write_text("", encoding="utf-8")

    config = load_config(
        tmp_path,
        environ={"REXTIO_TOTALLY_UNKNOWN": "1", "REXTIO_JTI": "true"},
    )

    assert config.embedding.enabled is False


def test_toolchain_section_loads_from_toml_env_and_overrides(tmp_path):
    (tmp_path / "rextio.toml").write_text(
        """
[toolchain]
cargo = "/opt/rust/bin/cargo"
python_version = ">=3.13"
""",
        encoding="utf-8",
    )
    config = load_config(tmp_path, environ={"REXTIO_NUITKA": "/opt/py/bin/nuitka"})
    assert config.toolchain.cargo == "/opt/rust/bin/cargo"
    assert config.toolchain.nuitka == "/opt/py/bin/nuitka"
    assert config.toolchain.python_version == ">=3.13"
    overridden = override_config(config, {("toolchain", "rust_toolchain"): "1.83"})
    assert overridden.toolchain.rust_toolchain == "1.83"
    assert overridden.toolchain.cargo == "/opt/rust/bin/cargo"


def test_toolchain_version_pin_syntax_is_validated(tmp_path):
    (tmp_path / "rextio.toml").write_text(
        """
[toolchain]
cargo_version = "one-point-two"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="version pin"):
        load_config(tmp_path)


def test_unknown_toolchain_key_is_rejected(tmp_path):
    (tmp_path / "rextio.toml").write_text(
        """
[toolchain]
rustc = "/somewhere"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="unsupported config key"):
        load_config(tmp_path)
