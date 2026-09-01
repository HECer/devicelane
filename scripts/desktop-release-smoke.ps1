param(
    [switch]$ExerciseLifecycle,
    [switch]$NativeInstallGate,
    [switch]$PayloadOnly,
    [string]$Artifact = $env:DEVICELANE_DESKTOP_ARTIFACT
)
$ErrorActionPreference = "Stop"
$TemporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$Root = if ($env:DEVICELANE_SMOKE_ROOT) { [IO.Path]::GetFullPath($env:DEVICELANE_SMOKE_ROOT) } else { Join-Path $TemporaryRoot "devicelane-smoke" }
$InstallRoot = Join-Path $Root "installed"
$Identity = if ($NativeInstallGate) { Join-Path $env:LOCALAPPDATA "DeviceLane\service\identity" } else { Join-Path $Root "identity" }
$Marker = Join-Path $Identity "smoke.identity"
$env:DEVICELANE_DESKTOP_ARTIFACT = $Artifact
New-Item -ItemType Directory -Force -Path $Identity | Out-Null
if (-not (Test-Path -LiteralPath $Marker)) { Set-Content -LiteralPath $Marker -Value "identity-preservation-marker" -NoNewline }

function Resolve-InstalledFile([string]$Pattern) {
    $Matches = @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -File -Filter $Pattern)
    if ($Matches.Count -ne 1) { throw "expected exactly one installed $Pattern, found $($Matches.Count)" }
    if ($Matches[0].Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "installed asset must not be a reparse point" }
    $Resolved = [IO.Path]::GetFullPath($Matches[0].FullName)
    if (-not $Resolved.StartsWith(([IO.Path]::GetFullPath($InstallRoot) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw "installed asset escaped the MSI root" }
    return $Resolved
}

function Invoke-LocalStatusWithRetry([string]$Cli) {
    for ($Attempt = 0; $Attempt -lt 100; $Attempt++) {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $Snapshot = & $Cli status --local --json 2>$null
            $ExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $PreviousPreference
        }
        if ($ExitCode -eq 0) { return ($Snapshot | ConvertFrom-Json) }
        Start-Sleep -Milliseconds 100
    }
    throw "installed CLI could not reach the service before the deadline"
}

function Invoke-InstalledLifecycle {
    $Service = Resolve-InstalledFile "devicelane-service*.exe"
    $Cli = Resolve-InstalledFile "devicelane.exe"
    $Desktop = Resolve-InstalledFile "devicelane-desktop.exe"
    $Lifecycle = Resolve-InstalledFile "setup-windows.ps1"
    $env:DEVICELANE_SERVICE_BINARY = $Service
    & $Lifecycle --service-install
    & $Lifecycle --service-status
    Invoke-LocalStatusWithRetry $Cli | Out-Null
    & $Desktop --smoke-probe | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "installed desktop bridge probe failed" }
    & $Lifecycle --service-repair
    & $Lifecycle --service-status
    Invoke-LocalStatusWithRetry $Cli | Out-Null
    & $Lifecycle --service-logs | Out-Null
    & $Lifecycle --service-autostart-disable
    & $Lifecycle --service-autostart-enable
    & $Lifecycle --service-uninstall
    if (-not (Test-Path -LiteralPath $Marker)) { throw "uninstall did not preserve identity" }
}

if ($ExerciseLifecycle) { $PayloadOnly = $true }
if (($NativeInstallGate -and $PayloadOnly) -or (-not $NativeInstallGate -and -not $PayloadOnly)) {
    throw "choose exactly one of -NativeInstallGate or -PayloadOnly"
}
if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf) -or [IO.Path]::GetExtension($Artifact) -ne ".msi") { throw "DEVICELANE_DESKTOP_ARTIFACT must be one MSI" }

# Production uses a signed, administrator-owned location: installation root must not be writable.
# Temporary extraction roots are writable and make no TOCTOU security guarantee.
# PayloadOnly is for non-elevated local diagnosis and cannot satisfy native installation acceptance.
if ($PayloadOnly) {
    if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf) -or [IO.Path]::GetExtension($Artifact) -ne ".msi") { throw "DEVICELANE_DESKTOP_ARTIFACT must be one MSI" }
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    $AdminLog = Join-Path $Root "msi-administrative-install.log"
    $Install = Start-Process msiexec.exe -ArgumentList @('/a', $Artifact, '/qn', '/norestart', '/l*v', $AdminLog, "TARGETDIR=$InstallRoot") -Wait -PassThru
    if ($Install.ExitCode -ne 0) { throw "MSI administrative extraction failed: $($Install.ExitCode); log: $AdminLog" }
    try {
        Invoke-InstalledLifecycle
    } finally {
        if (-not ([IO.Path]::GetFullPath($InstallRoot)).StartsWith(([IO.Path]::GetFullPath($Root) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw "refusing to remove an install root outside the smoke root" }
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
}

# NativeInstallGate requires elevated MSI /i and /x; failure is final and never falls back to /a.
if ($NativeInstallGate) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    $MsiLog = Join-Path $Root "msi-install.log"
    $Install = Start-Process msiexec.exe -ArgumentList @('/i', $Artifact, '/qn', '/norestart', '/l*v', $MsiLog, "INSTALLDIR=$InstallRoot") -Wait -PassThru
    if ($Install.ExitCode -ne 0) { throw "MSI native install failed: $($Install.ExitCode); log: $MsiLog" }
    try { Invoke-InstalledLifecycle } finally {
        $RemoveLog = Join-Path $Root "msi-uninstall.log"
        $Remove = Start-Process msiexec.exe -ArgumentList @('/x', $Artifact, '/qn', '/norestart', '/l*v', $RemoveLog) -Wait -PassThru
        if ($Remove.ExitCode -ne 0) { throw "MSI native uninstall failed: $($Remove.ExitCode); log: $RemoveLog" }
    }
}
if (-not (Test-Path -LiteralPath $Marker)) { throw "uninstall did not preserve identity" }
Write-Output "DeviceLane Windows native MSI install/launch/status/repair/logs/autostart/uninstall identity smoke passed."
