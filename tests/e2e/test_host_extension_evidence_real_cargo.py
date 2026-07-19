"""E2E: ordinary host-extension+cpython wheel builds emit C6.2 evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_host_extension_wheel_emits_deterministic_evidence_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "e2e_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    captured = capsys.readouterr()
    assert exit_code == 0
    combined = f"{captured.out}\n{captured.err}"
    assert "artifact evidence: preview-ready" in combined

    report_path = tmp_path / ".rextio" / "reports" / "build.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["native_build"]["status"] == "built"
    assert report["wheel_build"]["status"] == "built"
    assert "artifact_evidence" in report
    evidence = report["artifact_evidence"]
    assert evidence["kind"] == "host-extension-wheel"
    assert evidence["status"] == "preview-ready"
    assert evidence["authority"] == "evidence-only"
    assert evidence["signature_status"] == "unsigned"
    assert evidence["composition"] == "incomplete"
    assert evidence["preview"] is True
    assert evidence["complete"] is False
    assert evidence["signed"] is False
    assert "not-external-source-authorization" in evidence["limitations"]

    wheel_path = Path(report["wheel_build"]["path"])
    assert wheel_path.is_file()
    wheel_digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    assert evidence["subject"]["sha256"] == wheel_digest
    assert evidence["subject"]["logical_path"].startswith("dist/")
    assert str(tmp_path) not in json.dumps(evidence)

    sbom_path = tmp_path / evidence["sbom"]["logical_path"]
    prov_path = tmp_path / evidence["provenance"]["logical_path"]
    assert sbom_path.is_file()
    assert prov_path.is_file()
    assert hashlib.sha256(sbom_path.read_bytes()).hexdigest() == evidence["sbom"]["sha256"]
    assert hashlib.sha256(prov_path.read_bytes()).hexdigest() == evidence["provenance"]["sha256"]

    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert sbom["compositions"][0]["aggregate"] == "incomplete"
    root_ref = sbom["metadata"]["component"]["bom-ref"]
    assert root_ref not in [c["bom-ref"] for c in sbom["components"]]
    assert "dependencies" in sbom
    assert "wheel_entries" in evidence
    assert str(tmp_path) not in sbom_path.read_text(encoding="utf-8")
    assert "/Users/" not in sbom_path.read_text(encoding="utf-8")

    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    assert prov["_type"] == "https://in-toto.io/Statement/v1"
    assert len(prov["subject"]) == 2
    assert "invocationId" not in prov["predicate"]["runDetails"].get("metadata", {})
    materials = prov["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert not any(str(item.get("uri", "")).endswith(".cdx.json") for item in materials)
    assert str(tmp_path) not in prov_path.read_text(encoding="utf-8")

    cargo_keys = [
        (item["name"], item["version"], item["kind"]) for item in evidence["cargo_packages"]
    ]
    assert cargo_keys == sorted(cargo_keys)
    assert any(item["name"] == "pyo3" for item in evidence["cargo_packages"])

    # Rebuild: deterministic subject/sidecar digests for identical inputs.
    shutil.rmtree(tmp_path / "dist", ignore_errors=True)
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    assert exit_code == 0
    report2 = json.loads(report_path.read_text(encoding="utf-8"))
    evidence2 = report2["artifact_evidence"]
    assert evidence2["status"] == "preview-ready"
    assert evidence2["subject"]["sha256"] == evidence["subject"]["sha256"]
    assert evidence2["sbom"]["sha256"] == evidence["sbom"]["sha256"]
    assert evidence2["provenance"]["sha256"] == evidence["provenance"]["sha256"]
