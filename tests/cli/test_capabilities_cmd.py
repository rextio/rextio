from __future__ import annotations

import json
from pathlib import Path

import pytest

from rextio.__about__ import __version__
from rextio.capabilities import SCALAR_TYPES, SET_ITEM_TYPES
from rextio.cli.main import main
from rextio.contract import TOOLING_CONTRACT_VERSION


def run_capabilities_json(tmp_path: Path, capsys, *extra: str) -> dict[str, object]:
    assert main(["capabilities", str(tmp_path), "--format", "json", *extra]) == 0
    return json.loads(capsys.readouterr().out)


def test_capabilities_json_shape(tmp_path: Path, capsys) -> None:
    manifest = run_capabilities_json(tmp_path, capsys)

    assert manifest["contract_version"] == TOOLING_CONTRACT_VERSION
    assert manifest["rextio_version"] == __version__
    assert manifest["project_root"] == str(tmp_path.resolve())
    assert manifest["target"] == {"language": "rust"}
    assert manifest["plugins"] == []
    assert manifest["artifact_contract"] == {
        "status": "experimental",
        "profile_resolution": "generate-build-only",
        "kinds": ["host-extension", "host-executable", "rust-crate"],
        "host_executable_fallbacks": [
            "error",
            "python-subprocess",
            "nuitka-sidecar",
        ],
    }
    assert manifest["device_provider_contract"] == {
        "status": "draft",
        "discovery": False,
        "provider_selected": False,
        "local_probe_performed": False,
    }

    type_capabilities = manifest["type_capabilities"]
    assert type_capabilities["scalar_types"] == sorted(SCALAR_TYPES)
    assert type_capabilities["set_item_types"] == sorted(SET_ITEM_TYPES)
    assert "float" not in type_capabilities["set_item_types"]

    rules = manifest["rules"]
    assert rules, "the core rule set must not be empty"
    for rule in rules:
        assert rule["provider"] == "core"
        assert rule["id"].startswith("core/")
        assert rule["guidance"].strip()
        assert rule["outcome"] in {"native", "fallback", "reject", "shim", "boundary"}


def test_capabilities_writes_no_report_file(tmp_path: Path, capsys) -> None:
    run_capabilities_json(tmp_path, capsys)
    assert not (tmp_path / ".rextio").exists()


def test_capabilities_fingerprint_is_deterministic(tmp_path: Path, capsys) -> None:
    first = run_capabilities_json(tmp_path, capsys)
    second = run_capabilities_json(tmp_path, capsys)
    assert first["config_fingerprint"] == second["config_fingerprint"]
    assert first == second


def test_capabilities_fingerprint_tracks_config_file(tmp_path: Path, capsys) -> None:
    default = run_capabilities_json(tmp_path, capsys)
    (tmp_path / "rextio.toml").write_text("[embedding]\nenabled = true\n", encoding="utf-8")
    changed = run_capabilities_json(tmp_path, capsys)
    assert default["config_fingerprint"] != changed["config_fingerprint"]


def test_capabilities_fingerprint_tracks_cli_overrides(tmp_path: Path, capsys) -> None:
    default = run_capabilities_json(tmp_path, capsys)
    overridden = run_capabilities_json(tmp_path, capsys, "--embed-helpers")
    assert default["config_fingerprint"] != overridden["config_fingerprint"]


def test_capabilities_text_output_summarizes_manifest(tmp_path: Path, capsys) -> None:
    assert main(["capabilities", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Rextio capabilities" in out
    assert f"contract version: {TOOLING_CONTRACT_VERSION}" in out
    assert "Rules:" in out
    assert "core/set-float-item-type" in out


def test_capabilities_rejects_invalid_config(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text("[build]\nnative_backend = 7\n", encoding="utf-8")
    assert main(["capabilities", str(tmp_path), "--format", "json"]) == 1
    err = capsys.readouterr().err
    assert "RXT060" in err


def test_capabilities_merges_v2_plugin_rules(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.plugins import loader as plugin_loader
    from rextio.plugins.api import CoverageDecl, RuleRecord, RuleScope
    from rextio.plugins.models import RextioPlugin

    class FakeV2Plugin:
        plugin_id = "rextio-numpy"
        api_version = "1.0"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-numpy", name="NumPy to Rust")

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("numpy",))

        def describe(self, config) -> tuple[RuleRecord, ...]:
            return (
                RuleRecord(
                    id="rextio-numpy/elementwise-float64",
                    provider="rextio-numpy",
                    scope=RuleScope(kind="call", pattern="numpy elementwise op"),
                    constraint="Only float64 elementwise operations lower.",
                    outcome="fallback",
                    diagnostic_code="RXTP-NUMPY-001",
                    guidance="Use float64 arrays.",
                ),
            )

    class FakeEntryPoint:
        name = "rextio-numpy"

        def load(self) -> object:
            return FakeV2Plugin()

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (FakeEntryPoint(),))

    manifest = run_capabilities_json(tmp_path, capsys, "--enable-plugin", "rextio-numpy")

    plugin_entries = manifest["plugins"]
    assert plugin_entries == [
        {
            "id": "rextio-numpy",
            "name": "NumPy to Rust",
            "version": None,  # FakeEntryPoint has no dist metadata
            "packages": ["numpy"],
            "rules_provided": True,
            "api_version": "1.0",
            "lowering_provided": False,
        }
    ]
    plugin_rules = [rule for rule in manifest["rules"] if rule["provider"] == "rextio-numpy"]
    assert [rule["id"] for rule in plugin_rules] == ["rextio-numpy/elementwise-float64"]
    assert plugin_rules[0]["diagnostic_code"] == "RXTP-NUMPY-001"
    core_rules = [rule for rule in manifest["rules"] if rule["provider"] == "core"]
    assert core_rules, "core rules must still be present alongside plugin rules"


def test_capabilities_rejects_nonexistent_project_root(tmp_path: Path, capsys) -> None:
    # Council round 4 (qwen): a typo'd path previously reported default
    # capabilities silently, which downstream tooling would cache as the
    # project's contract.
    missing = tmp_path / "no" / "such" / "project"
    assert main(["capabilities", str(missing)]) == 1
    err = capsys.readouterr().err
    assert "RXT060" in err
    assert "does not exist" in err


def test_capabilities_no_plugins_emits_core_only_manifest(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    # Council round 6 (kimi): resolving the plugin registry executes enabled
    # plugins' module-level code; --no-plugins is the side-effect-free
    # escape hatch for consumers who only need the core manifest.
    (tmp_path / "rextio.toml").write_text(
        '[plugins]\nenabled = ["rextio-numpy"]\n', encoding="utf-8"
    )
    from rextio.plugins import loader as plugin_loader

    def exploding_entry_points(_eps):
        raise AssertionError("--no-plugins must not touch plugin entry points")

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", exploding_entry_points)
    manifest = run_capabilities_json(tmp_path, capsys, "--no-plugins")
    assert manifest["plugins"] == []
    assert all(rule["provider"] == "core" for rule in manifest["rules"])
