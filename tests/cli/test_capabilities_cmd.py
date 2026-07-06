from __future__ import annotations

import json
from pathlib import Path

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
