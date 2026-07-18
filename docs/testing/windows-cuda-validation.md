# Windows CUDA inventory validation

The Train C validation tool is an unpublished, no-dependency Rust probe. It is
for collecting bounded Windows facts before a future CUDA provider exists. It
is **not** CUDA support, a provider implementation, or a performance test.

## Prerequisites

- Windows x64
- PowerShell 5.1+ or PowerShell 7
- a Rust `x86_64-pc-windows-msvc` toolchain (`cargo` on `PATH`)
- optionally, an installed NVIDIA display driver and NVIDIA GPU

The CUDA toolkit and `nvcc` are not required. The probe uses only the driver
library already installed by the NVIDIA driver.

## Build and write a report

From a PowerShell prompt at the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\validate-windows-cuda.ps1 `
  -OutputPath .\.rextio\reports\windows-cuda-probe.json `
  -Release

Get-Content .\.rextio\reports\windows-cuda-probe.json
```

`-OutputPath` is required and may point elsewhere. Build output defaults to a
temporary directory; use `-TargetDirectory C:\some\directory` to choose it.
The script validates the schema and refuses any report whose
`support_claim` is not `false`.

To run the opt-in Python E2E around the PowerShell workflow:

```powershell
$env:REXTIO_WINDOWS_CUDA_PROBE = "1"
py -3.11 -m pytest tests\e2e\test_windows_cuda_probe_real_toolchain.py -q
```

Ordinary macOS/Linux CI skips that E2E. The Rust crate itself still compiles
and tests there, emitting a deterministic `UNSUPPORTED_TARGET` report.

## What the report means

On Windows x64 the tool loads `nvcuda.dll` through Kernel32 with
`LOAD_LIBRARY_SEARCH_SYSTEM32`, excluding the current directory and `PATH` from
DLL resolution, and resolves only:

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
