from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import rextio.cli.build_cmd as build_cmd
import rextio.source.external as external_source
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.main import main
from rextio.config.loader import load_config


PACKAGE = "rextio_c5_poc_math"
DIST_NAME = "rextio-c5-poc-math"
VERSION = "1.0.0"
SOURCE = """
raise RuntimeError("external distribution source must not be imported or copied")

def affine(x: int, scale: int, bias: int) -> int:
    return x * scale + bias
""".lstrip()


def _record_row(root: Path, relative: str) -> str:
    data = (root / relative).read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return f"{relative},sha256={digest.rstrip('=')},{len(data)}"


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "rextio.toml").write_text(
        f"""
[imports.packages.{PACKAGE}]
policy = "try-native"
max_depth = 1
distribution = "{DIST_NAME}"
version = "{VERSION}"
""".lstrip(),
        encoding="utf-8",
    )
    (project / "app.py").write_text(
        f"""
import {PACKAGE} as poc

def calculate(x: int) -> int:
    return poc.affine(x, 2, 3)
""".lstrip(),
        encoding="utf-8",
    )
    return project


def _write_distribution(
    root: Path,
    *,
    name: str = DIST_NAME,
    version: str = VERSION,
    source: str = SOURCE,
    metadata_text: str | None = None,
    wheel: str = "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    include_record: bool = True,
) -> external_source.metadata.Distribution:
    root.mkdir()
    package = root / PACKAGE
    package.mkdir()
    (package / "__init__.py").write_text(source, encoding="utf-8")
    dist_info = root / f"{PACKAGE}-{version}.dist-info"
    dist_info.mkdir()
    if metadata_text is None:
        metadata_text = "\n".join(
            (
                "Metadata-Version: 2.4",
                f"Name: {name}",
                f"Version: {version}",
                "License-Expression: MIT",
                "",
            )
        )
    (dist_info / "METADATA").write_text(metadata_text, encoding="utf-8")
    (dist_info / "WHEEL").write_text(wheel, encoding="utf-8")
    if include_record:
        source_relative = f"{PACKAGE}/__init__.py"
        metadata_relative = f"{dist_info.name}/METADATA"
        wheel_relative = f"{dist_info.name}/WHEEL"
        (dist_info / "RECORD").write_text(
            "\n".join(
                (
                    _record_row(root, source_relative),
                    _record_row(root, metadata_relative),
                    _record_row(root, wheel_relative),
                    f"{dist_info.name}/RECORD,,",
                    "",
                )
            ),
            encoding="utf-8",
        )
    return external_source.metadata.Distribution.at(dist_info)


def _install_distribution(
    monkeypatch: pytest.MonkeyPatch,
    distribution: external_source.metadata.Distribution,
) -> None:
    def get_distribution(name: str) -> external_source.metadata.Distribution:
        assert name == DIST_NAME
        return distribution

    monkeypatch.setattr(external_source.metadata, "distribution", get_distribution)


def _analyze(project: Path):
    config = load_config(project, environ={})
    return analyze_project(project, imports_config=config.imports)


def test_analyze_project_creates_sanitized_external_source_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "preview-ready"
    assert analysis.external_source_plan.candidate_functions == (
        f"{PACKAGE}.affine",
    )
    payload = analysis.to_dict()["external_source_plan"]
    assert payload["execution_authority"] == "preview-only"
    assert payload["distributable"] is False
    assert payload["c6_gate"] == "required"
    assert payload["modules"][0]["path"] == (
        f"distributions/{DIST_NAME}/{PACKAGE}/__init__.py"
    )
    assert "GNU/copyleft" in payload["license_warning"]
    assert str(installed_root) not in json.dumps(payload)


def test_check_and_generate_serialize_preview_without_copying_distribution_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    assert main(["check", str(project)]) == 0
    assert "GNU/copyleft" in capsys.readouterr().err
    check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    assert check_payload["external_source_plan"]["status"] == "preview-ready"
    assert str(installed_root) not in json.dumps(check_payload)

    assert main(["generate", str(project), "--fallback=cpython"]) == 0
    assert "GNU/copyleft" in capsys.readouterr().err
    generate_payload = json.loads(
        (project / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    generated_check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    assert generate_payload["external_source_plan"]["status"] == "preview-ready"
    assert generated_check_payload["external_source_plan"]["status"] == "preview-ready"
    assert str(installed_root) not in json.dumps(generate_payload)
    assert str(installed_root) not in json.dumps(generated_check_payload)

    generated_python = project / ".rextio" / "generated" / "python"
    assert not (generated_python / PACKAGE).exists()
    assert not (generated_python / f"{PACKAGE}.py").exists()
    generated_text = "\n".join(
        path.read_text(encoding="utf-8") for path in generated_python.rglob("*.py")
    )
    assert "external distribution source must not be imported or copied" not in generated_text


def test_cli_build_reports_c6_gate_without_starting_artifact_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    def unexpected_artifact_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the C6 gate must run before toolchain or artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_artifact_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_artifact_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert "C6 SourceLock" in captured.err
    assert "GNU/copyleft" in captured.err
    assert report["status"] == "external-source-c6-blocked"
    assert report["error"]["code"] == "RXT060"
    assert report["external_source_plan"]["execution_authority"] == "preview-only"
    assert str(installed_root) not in json.dumps(report)
    assert not (project / ".rextio" / "generated").exists()
    assert not (project / ".rextio" / "build").exists()


def test_cli_build_unavailable_plan_still_precedes_toolchain_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        version="1.0.1",
    )
    _install_distribution(monkeypatch, distribution)

    def unexpected_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an unavailable plan must block before toolchain or artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c6-blocked"
    assert report["external_source_plan"]["status"] == "unavailable"
    assert "GNU/copyleft" in captured.err


def test_cli_external_plan_precedes_unrelated_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    (project / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    distribution = _write_distribution(tmp_path / "fake-site-packages")
    _install_distribution(monkeypatch, distribution)

    def unexpected_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the C6 plan gate must precede toolchain and artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c6-blocked"
    assert any(
        diagnostic["code"] == "RXT000"
        for diagnostic in report["analysis"]["diagnostics"]
    )
    assert "GNU/copyleft" in captured.err


@pytest.mark.parametrize(
    ("distribution_options", "reason"),
    (
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {"wheel": "Root-Is-Purelib: true\nTag: py3-none-any\n"},
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n"
                    "Wheel-Version: 1.0\n"
                    "Root-Is-Purelib: true\n"
                    "Tag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n\n"
                    "Root-Is-Purelib: true\nTag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n"
                    "Root-Is-Purelib: false\n"
                    "Root-Is-Purelib: true\n"
                    "Tag: cp313-cp313-macosx_14_0_arm64\n"
                    "Tag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        ({"include_record": False}, "no RECORD source inventory"),
        (
            {"name": "totally-other"},
            "name does not match the exact configured distribution",
        ),
        (
            {"source": "import os\n\ndef affine(x: int) -> int:\n    return x + 1\n"},
            "contains an unresolved import",
        ),
        ({"version": "1.0.1"}, "does not match the exact configured version"),
    ),
)
def test_analyze_project_fails_closed_for_untrusted_distribution_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    distribution_options: dict[str, Any],
    reason: str,
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        **distribution_options,
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert reason in (analysis.external_source_plan.reason or "")
    assert str(tmp_path / "fake-site-packages") not in json.dumps(analysis.to_dict())


def test_analyze_project_detects_record_sha256_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    (installed_root / PACKAGE / "__init__.py").write_text(
        SOURCE.replace("x * scale", "x + scale"),
        encoding="utf-8",
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD SHA-256 drift detected for source"
    )


def test_analyze_project_detects_record_size_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    lines = record.read_text(encoding="utf-8").splitlines()
    path, digest, size = lines[0].split(",")
    lines[0] = f"{path},{digest},{int(size) + 1}"
    record.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD size drift detected for source"
    )


@pytest.mark.parametrize(("filename", "label"), (("METADATA", "METADATA"), ("WHEEL", "WHEEL")))
def test_analyze_project_detects_dist_info_hash_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    label: str,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    target = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / filename
    with target.open("a", encoding="utf-8") as stream:
        stream.write("X-Rewritten: true\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        f"distribution RECORD SHA-256 drift detected for {label}"
    )


def test_analyze_project_rejects_duplicate_record_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    first_row = record.read_text(encoding="utf-8").splitlines()[0]
    with record.open("a", encoding="utf-8") as stream:
        stream.write(first_row + "\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains a duplicate path"
    )


@pytest.mark.parametrize(
    "metadata_text",
    (
        f"Name: {DIST_NAME}\nVersion: {VERSION}\n",
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\n"
            f"Name: other\nVersion: {VERSION}\n"
        ),
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\n"
            f"Version: {VERSION}\nVersion: 2.0.0\n"
        ),
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\nVersion: {VERSION}\n"
            "malformed header\n"
        ),
    ),
)
def test_analyze_project_rejects_ambiguous_distribution_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_text: str,
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        metadata_text=metadata_text,
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert "METADATA" in (analysis.external_source_plan.reason or "")


def test_analyze_project_rejects_unsafe_record_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8") as stream:
        stream.write("../outside.py,,\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains an unsafe path"
    )


def test_analyze_project_rejects_symlinked_package_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    package = installed_root / PACKAGE
    real_package = installed_root / "contained-real-package"
    package.rename(real_package)
    package.symlink_to(real_package, target_is_directory=True)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution source is a symlink or non-regular file"
    )


def test_analyze_project_rejects_shadow_dist_info_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    actual_dist_info = installed_root / f"{PACKAGE}-{VERSION}.dist-info"
    shadow_dist_info = installed_root / "shadow-1.0.0.dist-info"
    shadow_dist_info.mkdir()
    for name in ("METADATA", "WHEEL"):
        (shadow_dist_info / name).write_bytes((actual_dist_info / name).read_bytes())
    (shadow_dist_info / "RECORD").write_text("shadow-1.0.0.dist-info/RECORD,,\n")
    (actual_dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(installed_root, f"{PACKAGE}/__init__.py"),
                _record_row(installed_root, "shadow-1.0.0.dist-info/METADATA"),
                _record_row(installed_root, "shadow-1.0.0.dist-info/WHEEL"),
                "shadow-1.0.0.dist-info/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains a foreign dist-info root"
    )


@pytest.mark.parametrize(
    ("link_outside_root", "reason"),
    (
        (False, "distribution source is a symlink or non-regular file"),
        (True, "distribution source escapes its installed root"),
    ),
)
def test_analyze_project_fails_closed_for_distribution_source_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_outside_root: bool,
    reason: str,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    source_path = installed_root / PACKAGE / "__init__.py"
    source_path.unlink()
    target = (
        tmp_path / "outside.py"
        if link_outside_root
        else installed_root / "contained-but-linked.py"
    )
    target.write_text(SOURCE, encoding="utf-8")
    source_path.symlink_to(target)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == reason
    assert str(installed_root) not in json.dumps(analysis.to_dict())
