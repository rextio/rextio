# CUDA Driver API inventory validation (Windows + Linux)

The Train C validation tool is a repository-only, no-dependency Rust probe; it
is not installed as part of the PyPI package. It collects bounded host facts
before a future CUDA provider exists and is
**not** CUDA support, a provider implementation, or a performance test.

Supported probe hosts:

| Host | Driver library load rule |
| --- | --- |
| Windows x86_64 | `nvcuda.dll` via `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32` only |
| Linux x86_64 | arch-local reviewed absolute `libcuda.so.1` candidates only |
| Linux aarch64 | arch-local reviewed absolute `libcuda.so.1` candidates only |

All other OS/arch combinations emit a deterministic `UNSUPPORTED_TARGET`
report. Every report carries `support_claim: false`.

## Prerequisites

### Windows

- Windows x64
- PowerShell 5.1+ or PowerShell 7
- a Rust `x86_64-pc-windows-msvc` toolchain (`cargo` on `PATH`)
- optionally, an installed NVIDIA display driver and NVIDIA GPU

### Linux

- Linux x86_64 or aarch64
- bash, `cargo`, and `python3` (schema checks in the validation wrapper)
- optionally, an installed NVIDIA driver (`libcuda.so.1`) and NVIDIA GPU

The CUDA toolkit and `nvcc` are not required. The probe uses only the driver
library already installed by the NVIDIA driver (or mounted by WSL2 /
NVIDIA-container / Jetson layouts from the arch-local reviewed path set).

## Build and write a report

### Windows (PowerShell)

From a PowerShell prompt at the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\validate-windows-cuda.ps1 `
  -OutputPath .\.rextio\reports\cuda-driver-probe.json `
  -Release

Get-Content .\.rextio\reports\cuda-driver-probe.json
```

### Linux loose mode (default; may validate no-GPU hosts)

```bash
./scripts/validate-linux-cuda.sh \
  --output ./.rextio/reports/cuda-driver-probe.json \
  --release

cat ./.rextio/reports/cuda-driver-probe.json
```

On Linux x86_64/aarch64, accepted reports always have `platform_supported:
true` and status only in `probe-complete` | `unavailable` | `error` (never
`unsupported`, which is reserved for non-supported hosts such as macOS). Loose
mode may validate no-GPU hosts. Ordinary CI uses this loose path and is
**not** real-GPU evidence.

### Linux strict real-GPU mode (owner command)

On a trusted NVIDIA Linux host/container with a visible GPU, require a completed
device inventory:

```bash
REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1 ./scripts/validate-linux-cuda.sh \
  --output ./.rextio/reports/cuda-driver-probe.json \
  --require-device \
  --release
```

Both loose and strict modes fully validate `probe-complete` driver/version/
count/device invariants when that status appears. Strict mode
(`--require-device` and/or `REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1`) differs only
by requiring `status == "probe-complete"`.

That remains host inventory evidence only. It is still **not** CUDA support or
certification.

`-OutputPath` / `--output` is required and may point elsewhere. Build output
defaults to a temporary directory; use `-TargetDirectory` / `--target-dir` to
choose it. Both scripts refuse any report whose `support_claim` is not `false`.

### Opt-in real-toolchain E2E

Windows:

```powershell
$env:REXTIO_WINDOWS_CUDA_PROBE = "1"
py -3.11 -m pytest tests\e2e\test_windows_cuda_probe_real_toolchain.py -q
```

Linux loose:

```bash
REXTIO_LINUX_CUDA_PROBE=1 python3 -m pytest \
  tests/e2e/test_linux_cuda_probe_real_toolchain.py -q
```

Linux strict (owner real-GPU command):

```bash
REXTIO_LINUX_CUDA_PROBE=1 REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1 \
  python3 -m pytest tests/e2e/test_linux_cuda_probe_real_toolchain.py -q
```

Hosts without the opt-in flags skip those E2Es. In the ordinary `e2e` CI job at
Python 3.11:

- **ubuntu-latest and macos-latest** each run host `cargo test` for the probe
  (macOS covers the deterministic `UNSUPPORTED_TARGET` unit path).
- **ubuntu-latest only** additionally runs `rustup target add
  aarch64-unknown-linux-gnu` + `cargo check --target aarch64-unknown-linux-gnu`
  (compile coverage only; not an aarch64 execution) and the **loose**
  `validate-linux-cuda.sh` wrapper (wrapper builds the host binary; no separate
  `cargo build` step). GitHub-hosted runners typically have no GPU, so
  `LIBCUDA_SO_NOT_FOUND` / `LIBCUDA_SO_LOAD_FAILED` are expected and accepted.
- A separate **windows-latest** job compiles and tests the dependency-free
  `x86_64-pc-windows-msvc` probe, then runs `validate-windows-cuda.ps1` and
  validates its JSON schema and invariant `support_claim: false`. An absent
  NVIDIA driver/GPU is an accepted `unavailable` report, not a failed job.

None of these CI lanes is real-GPU evidence or CUDA certification.

## What the report means

### Windows x64

The tool loads `nvcuda.dll` through Kernel32 with
`LOAD_LIBRARY_SEARCH_SYSTEM32`, excluding the current directory and `PATH` from
DLL resolution.

### Linux x86_64

Candidates are arch-local only (foreign multiarch paths are never probed).
Specialized mounts are ordered before generic distro paths:

1. `/usr/lib/wsl/lib/libcuda.so.1` (WSL2 NVIDIA driver mount)
2. `/usr/local/nvidia/lib64/libcuda.so.1` (NVIDIA-container runtime mount)
3. `/usr/local/nvidia/lib/libcuda.so.1` (NVIDIA-container runtime mount)
4. `/usr/lib/x86_64-linux-gnu/libcuda.so.1` (Debian/Ubuntu multiarch)
5. `/usr/lib64/libcuda.so.1`
6. `/usr/lib/libcuda.so.1`

### Linux aarch64

1. `/usr/local/nvidia/lib64/libcuda.so.1` (NVIDIA-container runtime mount)
2. `/usr/local/nvidia/lib/libcuda.so.1` (NVIDIA-container runtime mount)
3. `/usr/lib/aarch64-linux-gnu/tegra/libcuda.so.1` (Jetson)
4. `/usr/lib/aarch64-linux-gnu/libcuda.so.1` (Debian/Ubuntu multiarch)
5. `/usr/lib64/libcuda.so.1`
6. `/usr/lib/libcuda.so.1`

### Provenance guard (not a hard sandbox)

For each candidate the probe:

1. requires an absolute reviewed candidate path for the current architecture;
2. canonicalizes symlink candidates;
3. `dlopen`s only the canonical regular-file target;
4. requires that target to remain under reviewed system roots
   (`/usr/lib`, `/usr/lib64`, `/usr/local/nvidia/lib`, `/usr/local/nvidia/lib64`);
5. rejects a group- or world-writable canonical regular-file leaf and any
   group- or world-writable directory ancestry (`mode & 0o022 != 0`);
6. opens with explicit `RTLD_NOW | RTLD_LOCAL`;
7. never emits `dlerror` text or filesystem paths in the JSON report.

If no candidate entry exists: `LIBCUDA_SO_NOT_FOUND`. If a candidate exists but
cannot be provenance-accepted or `dlopen`ed: `LIBCUDA_SO_LOAD_FAILED`.

This is a **provenance guard**, not a security sandbox. Absolute top-level
selection does **not** neutralize process `LD_PRELOAD` or transitive
`DT_NEEDED` resolution from the loaded driver. Before `cuInit` the probe sets
`CUDA_FORCE_PRELOAD_LIBRARIES=0` and `CUDA_DISABLE_JIT=1` for this standalone
process only. Run the probe only on a trusted host/container filesystem.

### Shared inventory surface

On both platforms the probe resolves only:

- `cuInit`
- `cuDriverGetVersion`
- `cuDeviceGetCount`
- `cuDeviceGet`
- `cuDeviceGetName`
- `cuDeviceComputeCapability`

It reports the Rust target OS/architecture/environment, whether the driver
library loaded, the driver API version, and devices in ordinal order with a
sanitized name and SM compute capability. Missing libraries, symbols, devices,
or failed driver calls are structured `unavailable`/`error` results rather
than fabricated successes. The report never includes the full environment,
user paths, host name, account name, or arbitrary driver text.

## What it does not prove

The probe never creates a CUDA context, allocates or transfers memory, creates
a stream, loads a module, launches a kernel, links generated Rust, or exercises
Torch/TensorFlow/CuPy interoperation. It does not check toolkit or `nvcc`
compatibility. It therefore proves only that the bounded Driver API inventory
calls worked on that machine. Every report carries `support_claim: false`, even
when one or more GPUs are enumerated.

Real first-party CUDA certification will require the future provider contract,
an exact runtime/toolkit/profile matrix, context/stream/memory lifetime tests,
generated-artifact execution, numerical equivalence, and real-device CI.
