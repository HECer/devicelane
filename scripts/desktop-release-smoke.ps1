param([switch]$ExerciseLifecycle)
$ErrorActionPreference = "Stop"

$TemporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$Root = if ($env:DEVICELANE_SMOKE_ROOT) { [IO.Path]::GetFullPath($env:DEVICELANE_SMOKE_ROOT) } else { Join-Path $TemporaryRoot "devicelane-smoke" }
$Service = if ($env:DEVICELANE_SERVICE_BINARY) { [IO.Path]::GetFullPath($env:DEVICELANE_SERVICE_BINARY) } else { Join-Path $PSScriptRoot "..\target\release\devicelane-service.exe" }
$Cli = Join-Path (Split-Path $Service) "devicelane.exe"
$Identity = if ($ExerciseLifecycle) { Join-Path $env:LOCALAPPDATA "DeviceLane\service\identity" } else { Join-Path $Root "identity" }
$Marker = Join-Path $Identity "smoke.identity"

if (-not (Test-Path -LiteralPath $Service -PathType Leaf)) { throw "DEVICELANE_SERVICE_BINARY is missing: $Service" }
New-Item -ItemType Directory -Force -Path $Identity | Out-Null
if (-not (Test-Path -LiteralPath $Marker)) { Set-Content -LiteralPath $Marker -Value "identity-preservation-marker" -NoNewline }

# Production installers place signed binaries in an administrator-owned, non-writable location.
# A writable installation root invalidates the release boundary: installation root must not be writable.
# This check does not claim a TOCTOU guarantee; platform signatures remain authoritative.
if ($ExerciseLifecycle) {
    $env:DEVICELANE_SERVICE_BINARY = $Service
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-install
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-status
    & $Cli status --local --json | ConvertFrom-Json | Out-Null
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-repair
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-logs
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-autostart-disable
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-autostart-enable
    & (Join-Path $PSScriptRoot "setup-windows.ps1") --service-uninstall
}
if (-not (Test-Path -LiteralPath $Marker)) { throw "uninstall did not preserve identity" }
Write-Output "DeviceLane Windows first-run install/status/repair/logs/autostart/uninstall identity smoke passed."
