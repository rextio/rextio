"""E2E: ordinary host-extension+cpython wheel builds emit C6.2 evidence."""

from __future__ import annotations

import hashlib
import json
import sys
import shutil
import zipfile
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_host_extension_wheel_emits_deterministic_evidence_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if sys.platform == "darwin":
        inspector = Path("/usr/bin/otool")
        expected_format = "mach-o"
    elif sys.platform.startswith("linux"):
        inspector = Path("/usr/bin/readelf")
        expected_format = "elf"
    else:
        pytest.skip("real runtime linkage evidence is supported on macOS and Linux")
    assert inspector.is_file(), f"required blocking-CI inspector is missing: {inspector}"

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
    assert evidence["distribution_authorized"] is False
    assert "not-external-source-authorization" in evidence["limitations"]

    runtime = evidence["native_runtime_inventory"]
    target_arch = evidence["target_triple"].split("-", 1)[0]
    expected_architecture = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "x86_64": "x86_64",
        "i686": "x86",
    }.get(target_arch, target_arch)
    assert runtime["format"] == expected_format
    assert runtime["architecture"] == expected_architecture
    assert runtime["inspector"] == inspector.name
    assert runtime["scope"] == "direct-only"
    assert runtime["transitive_closure"] is False
    assert runtime["runtime_dlopen"] is False
    assert runtime["dependency_count"] == len(runtime["dependencies"])
    for dependency in runtime["dependencies"]:
        assert set(dependency) == {"name", "origin", "bom_ref"}
        assert dependency["origin"] in {"system", "unresolved"}
        assert dependency["bom_ref"].startswith("urn:rextio:native-dep:")
        assert "/" not in dependency["name"]
        assert "\\" not in dependency["name"]
        assert ".." not in dependency["name"]

    wheel_path = Path(report["wheel_build"]["path"])
    assert wheel_path.is_file()
    wheel_digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    assert evidence["subject"]["sha256"] == wheel_digest
    assert evidence["subject"]["logical_path"].startswith("dist/")
    assert str(tmp_path) not in json.dumps(evidence)

    installed_path = Path(report["native_build"]["installed_path"])
    installed_bytes = installed_path.read_bytes()
    installed_digest = hashlib.sha256(installed_bytes).hexdigest()
    assert runtime["subject_basename"] == installed_path.name
    assert runtime["subject_sha256"] == installed_digest
    assert runtime["subject_size"] == len(installed_bytes)
    with zipfile.ZipFile(wheel_path) as archive:
        wheel_member_bytes = archive.read(runtime["wheel_member"])
    assert wheel_member_bytes == installed_bytes
    assert runtime["wheel_member_sha256"] == installed_digest
    assert runtime["wheel_member_size"] == len(installed_bytes)

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
    native_component = next(
        component
        for component in sbom["components"]
        if component["name"] == runtime["wheel_member"]
    )
    native_edge = next(
        edge for edge in sbom["dependencies"] if edge["ref"] == native_component["bom-ref"]
    )
    assert set(native_edge["dependsOn"]) >= {
        dependency["bom_ref"] for dependency in runtime["dependencies"]
    }

    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    assert prov["_type"] == "https://in-toto.io/Statement/v1"
    assert len(prov["subject"]) == 2
    assert "invocationId" not in prov["predicate"]["runDetails"].get("metadata", {})
    materials = prov["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert not any(str(item.get("uri", "")).endswith(".cdx.json") for item in materials)
    assert str(tmp_path) not in prov_path.read_text(encoding="utf-8")
    internal = prov["predicate"]["buildDefinition"]["internalParameters"]
    assert internal["native_runtime_scope"] == "direct-only"
    assert internal["native_runtime_transitive_closure"] is False
    assert internal["native_runtime_dlopen"] is False
    assert internal["complete_claim"] is False
    assert internal["signed"] is False
    assert internal["distribution_authorized"] is False
    assert (
        prov["predicate"]["runDetails"]["metadata"][
            "rextio:observed_native_runtime"
        ]
        == runtime
    )

    serialized_evidence = json.dumps(evidence, sort_keys=True)
    serialized_sidecars = json.dumps({"sbom": sbom, "provenance": prov}, sort_keys=True)
    for serialized in (serialized_evidence, serialized_sidecars):
        assert str(tmp_path) not in serialized
        assert '"stdout"' not in serialized
        assert '"stderr"' not in serialized
        assert "speedup" not in serialized.lower()
        assert "performance" not in serialized.lower()

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
    assert evidence2["native_runtime_inventory"] == runtime
    assert evidence2["sbom"]["sha256"] == evidence["sbom"]["sha256"]
    assert evidence2["provenance"]["sha256"] == evidence["provenance"]["sha256"]
