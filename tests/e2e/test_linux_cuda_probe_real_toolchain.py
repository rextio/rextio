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
        sys.platform != "linux" or os.environ.get("REXTIO_LINUX_CUDA_PROBE") != "1",
        reason="requires Linux and explicit REXTIO_LINUX_CUDA_PROBE=1 opt-in",
    ),
]


def test_linux_cuda_probe_writes_a_truthful_non_support_report(tmp_path: Path) -> None:
    """Opt-in Linux real-toolchain E2E.

    Loose mode (default): accepts no-GPU hosts with status in
    probe-complete|unavailable|error and platform_supported=true.
    Strict mode when REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1: requires probe-complete.

    Owner command for strict real-GPU evidence (not CUDA support):

        REXTIO_LINUX_CUDA_PROBE=1 REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1 \\
          python3 -m pytest tests/e2e/test_linux_cuda_probe_real_toolchain.py -q
    """
    repository_root = Path(__file__).resolve().parents[2]
    script = repository_root / "scripts" / "validate-linux-cuda.sh"
    output = tmp_path / "cuda-driver-probe.json"
    target = tmp_path / "cargo-target"
    assert script.is_file(), "Linux CUDA validation script is required"
    assert shutil.which("cargo") is not None, "cargo is required for Linux CUDA validation"
    assert shutil.which("python3") is not None, "python3 is required for schema checks"

    require_device = os.environ.get("REXTIO_LINUX_CUDA_REQUIRE_DEVICE") == "1"
    command = [
        "bash",
        str(script),
        "--output",
        str(output),
        "--target-dir",
        str(target),
    ]
    if require_device:
        command.append("--require-device")

    completed = subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env={
            **os.environ,
            **(
                {"REXTIO_LINUX_CUDA_REQUIRE_DEVICE": "1"}
                if require_device
                else {}
            ),
        },
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1"
    assert report["probe"] == "rextio-cuda-driver-probe"
    assert report["support_claim"] is False
    assert report["target"]["os"] == "linux"
    assert report["target"]["arch"] in {"x86_64", "aarch64"}
    assert report["platform_supported"] is True
    assert report["status"] in {"probe-complete", "unavailable", "error"}
    assert isinstance(report["devices"], list)

    if require_device:
        assert report["status"] == "probe-complete"

    if report["status"] == "probe-complete":
        assert report["driver_loaded"] is True
        assert isinstance(report["driver_version"], int)
        assert report["device_count"] == len(report["devices"])
        assert report["device_count"] > 0
        for ordinal, device in enumerate(report["devices"]):
            assert device["ordinal"] == ordinal
            assert device["name"]
            assert device["sm"].startswith("sm_")
            assert isinstance(device["compute_major"], int)
            assert isinstance(device["compute_minor"], int)
    else:
        assert isinstance(report["reason_code"], str)
        assert report["reason_code"]
        assert "/" not in report["reason_code"]
        assert "\\" not in report["reason_code"]
        assert "=" not in report["reason_code"]
