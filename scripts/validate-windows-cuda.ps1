[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$TargetDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) "rextio-cuda-driver-probe"),

    [switch]$Release
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This validation wrapper runs only on Windows."
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    throw "cargo was not found. Install the Rust MSVC toolchain and rerun this script."
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot "tools\cuda-driver-probe\Cargo.toml"
$cargoArguments = @(
    "build",
    "--locked",
    "--manifest-path", $manifestPath,
    "--target-dir", $TargetDirectory
)
$profileDirectory = "debug"
if ($Release) {
    $cargoArguments += "--release"
    $profileDirectory = "release"
}

& $cargo.Source @cargoArguments
if ($LASTEXITCODE -ne 0) {
    throw "The CUDA driver probe failed to compile (cargo exit code $LASTEXITCODE)."
}

$probePath = Join-Path $TargetDirectory "$profileDirectory\rextio-cuda-driver-probe.exe"
if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
    throw "The compiled probe was not found at the expected target path."
}

$probeOutput = @(& $probePath)
if ($LASTEXITCODE -ne 0) {
    throw "The CUDA driver probe failed to run (exit code $LASTEXITCODE)."
}
$json = [string]::Join([Environment]::NewLine, $probeOutput).Trim()
try {
    $report = $json | ConvertFrom-Json
}
catch {
    throw "The CUDA driver probe did not emit valid JSON."
}

if ($report.schema_version -ne "1" -or $report.probe -ne "rextio-cuda-driver-probe") {
    throw "The CUDA driver probe emitted an unknown report schema."
}
if ($report.support_claim -ne $false) {
    throw "The probe report must never make a CUDA support claim."
}
if ($report.target.os -ne "windows") {
    throw "The Windows validation wrapper expected a windows target report."
}

$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $resolvedOutputPath,
    $json + [Environment]::NewLine,
    $utf8WithoutBom
)

Write-Output $resolvedOutputPath
