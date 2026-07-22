from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.needs_cargo,
    pytest.mark.skipif(
        sys.platform != "win32" or os.environ.get("REXTIO_WINDOWS_CUDA_PROBE") != "1",
        reason="requires Windows and explicit REXTIO_WINDOWS_CUDA_PROBE=1 opt-in",
    ),
]


def test_windows_cuda_probe_writes_a_truthful_non_support_report(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    script = repository_root / "scripts" / "validate-windows-cuda.ps1"
    output = tmp_path / "cuda-driver-probe.json"
    target = tmp_path / "cargo-target"
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    assert powershell is not None, "PowerShell is required for Windows CUDA validation"
    assert shutil.which("cargo") is not None, "the Rust MSVC cargo toolchain is required"

    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-OutputPath",
            str(output),
            "-TargetDirectory",
            str(target),
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1"
    assert report["probe"] == "rextio-cuda-driver-probe"
    assert report["support_claim"] is False
    assert report["target"]["os"] == "windows"
    assert report["target"]["arch"] == "x86_64"
    assert report["platform_supported"] is True
    assert report["status"] in {"probe-complete", "unavailable", "error"}
    assert isinstance(report["devices"], list)

    if report["status"] == "probe-complete":
        assert report["driver_loaded"] is True
        assert isinstance(report["driver_version"], int)
        assert report["device_count"] == len(report["devices"])
        assert report["device_count"] > 0
        for ordinal, device in enumerate(report["devices"]):
            assert device["ordinal"] == ordinal
            assert device["name"]
            assert device["sm"].startswith("sm_")
    else:
        assert isinstance(report["reason_code"], str)
