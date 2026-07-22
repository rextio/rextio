#!/usr/bin/env bash
# Linux validation wrapper for the CUDA Driver API inventory probe.
# Inventory only: never claims CUDA support; refuses support_claim != false.
#
# Loose mode (default): accepts probe-complete / unavailable / error on Linux
# x86_64/aarch64 (always platform_supported=true; never unsupported).
# Strict real-GPU mode: --require-device and/or REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1
# requires status=probe-complete (same probe-complete invariants as loose).
# That is host evidence only, not Rextio CUDA support or certification.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/validate-linux-cuda.sh --output PATH [--target-dir PATH] [--release] [--require-device]

Build tools/cuda-driver-probe, run it once, validate schema/support_claim,
and write the JSON report to PATH. Requires Linux x86_64 or aarch64 and cargo.

Modes:
  loose (default)     Accepts no-GPU hosts (e.g. LIBCUDA_SO_NOT_FOUND) with
                      status in probe-complete|unavailable|error.
  --require-device    Same probe-complete invariants as loose, but requires
                      status=probe-complete. Also enabled when
                      REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1.

Owner command for strict real-GPU validation on a trusted NVIDIA Linux host:

  REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1 ./scripts/validate-linux-cuda.sh \
    --output ./.rextio/reports/cuda-driver-probe.json \
    --require-device \
    --release

Or equivalently via the opt-in Python E2E:

  REXTIO_LINUX_CUDA_PROBE=1 REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1 \
    python3 -m pytest tests/e2e/test_linux_cuda_probe_real_toolchain.py -q
EOF
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "error: this validation wrapper runs only on Linux." >&2
  exit 1
fi

arch="$(uname -m)"
case "${arch}" in
  x86_64|aarch64) ;;
  *)
    echo "error: unsupported Linux architecture '${arch}' (need x86_64 or aarch64)." >&2
    exit 1
    ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo was not found. Install a Rust toolchain and rerun." >&2
  exit 1
fi

output_path=""
target_directory=""
release=0
require_device=0
if [[ "${REXTIO_LINUX_CUDA_REQUIRE_DEVICE:-}" == "1" ]]; then
  require_device=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    --target-dir)
      target_directory="${2:-}"
      shift 2
      ;;
    --release)
      release=1
      shift
      ;;
    --require-device)
      require_device=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${output_path}" ]]; then
  echo "error: --output PATH is required." >&2
  usage >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_dir}/.." && pwd)"
manifest_path="${repository_root}/tools/cuda-driver-probe/Cargo.toml"

if [[ ! -f "${manifest_path}" ]]; then
  echo "error: probe manifest not found" >&2
  exit 1
fi

if [[ -z "${target_directory}" ]]; then
  target_directory="$(mktemp -d "${TMPDIR:-/tmp}/rextio-cuda-driver-probe.XXXXXX")"
fi

profile_directory="debug"
cargo_args=(build --locked --manifest-path "${manifest_path}" --target-dir "${target_directory}")
if [[ "${release}" -eq 1 ]]; then
  cargo_args+=(--release)
  profile_directory="release"
fi

cargo "${cargo_args[@]}"

probe_path="${target_directory}/${profile_directory}/rextio-cuda-driver-probe"
if [[ ! -f "${probe_path}" ]]; then
  echo "error: compiled probe not found at expected target path" >&2
  exit 1
fi

json="$("${probe_path}")"
if [[ -z "${json}" ]]; then
  echo "error: probe emitted empty output." >&2
  exit 1
fi

# Write JSON to a temp file so shell metacharacters in device names cannot be
# expanded when validating (never print private paths beyond the report file).
report_tmp="$(mktemp "${TMPDIR:-/tmp}/rextio-cuda-probe-report.XXXXXX")"
trap 'rm -f "${report_tmp}"' EXIT
printf '%s\n' "${json}" > "${report_tmp}"

# Schema / non-support / optional strict-device checks. Never print private paths
# from the report payload into diagnostics beyond structured status codes.
REQUIRE_DEVICE="${require_device}" python3 - "${report_tmp}" <<'PY'
import json
import os
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
require_device = os.environ.get("REQUIRE_DEVICE") == "1"

if report.get("schema_version") != "1":
    raise SystemExit("error: unexpected schema_version")
if report.get("probe") != "rextio-cuda-driver-probe":
    raise SystemExit("error: unexpected probe name")
if report.get("support_claim") is not False:
    raise SystemExit("error: probe report must never make a CUDA support claim")
target = report.get("target") or {}
if target.get("os") != "linux":
    raise SystemExit("error: Linux validation wrapper expected a linux target report")
if target.get("arch") not in {"x86_64", "aarch64"}:
    raise SystemExit("error: unexpected linux arch in report")
# Supported Linux arches always report platform_supported=true and never emit
# unsupported (that status is for non-Linux / non-x86_64-aarch64 hosts).
if report.get("platform_supported") is not True:
    raise SystemExit("error: linux x86_64/aarch64 report must have platform_supported=true")
status = report.get("status")
if status not in {"probe-complete", "unavailable", "error"}:
    raise SystemExit("error: unexpected status (expected probe-complete|unavailable|error)")
devices = report.get("devices")
if not isinstance(devices, list):
    raise SystemExit("error: devices must be a list")

# Reason codes must never look like paths or environment dumps.
reason = report.get("reason_code")
if reason is not None:
    if not isinstance(reason, str) or not reason:
        raise SystemExit("error: invalid reason_code")
    if "/" in reason or "\\" in reason or "=" in reason:
        raise SystemExit("error: reason_code must not contain paths or env text")

def validate_probe_complete() -> None:
    if report.get("driver_loaded") is not True:
        raise SystemExit("error: probe-complete requires driver_loaded=true")
    if not isinstance(report.get("driver_version"), int):
        raise SystemExit("error: probe-complete requires integer driver_version")
    device_count = report.get("device_count")
    if not isinstance(device_count, int) or device_count <= 0:
        raise SystemExit("error: probe-complete requires device_count>0")
    if len(devices) != device_count:
        raise SystemExit("error: probe-complete requires matching device records")
    for ordinal, device in enumerate(devices):
        if not isinstance(device, dict):
            raise SystemExit("error: invalid device record")
        if device.get("ordinal") != ordinal:
            raise SystemExit("error: device ordinal mismatch")
        if not device.get("name"):
            raise SystemExit("error: device name missing")
        sm = device.get("sm")
        if not isinstance(sm, str) or not sm.startswith("sm_"):
            raise SystemExit("error: device sm missing")
        if not isinstance(device.get("compute_major"), int):
            raise SystemExit("error: device compute_major missing")
        if not isinstance(device.get("compute_minor"), int):
            raise SystemExit("error: device compute_minor missing")

if status == "probe-complete":
    # Full invariants in both loose and strict modes.
    validate_probe_complete()
else:
    # Non-complete states must carry a path-free reason_code.
    if reason is None:
        raise SystemExit("error: non-complete status requires reason_code")

# Strict mode differs only by requiring probe-complete.
if require_device and status != "probe-complete":
    raise SystemExit("error: strict mode requires status=probe-complete")

print("ok", flush=True)
PY

output_dir="$(dirname -- "${output_path}")"
mkdir -p "${output_dir}"
printf '%s\n' "${json}" > "${output_path}"
# Print only the operator-supplied output path (not probe-internal paths).
printf '%s\n' "${output_path}"
