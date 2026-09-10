param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Second)
$ErrorActionPreference = "Stop"
$Root = Join-Path $env:RUNNER_TEMP "devicelane-repro-msi"

function Expand-And-Manifest([string]$Msi, [string]$Name) {
    $Destination = Join-Path $Root $Name
    $PackageCopy = Join-Path $Destination ([IO.Path]::GetFileName($Msi))
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $Process = Start-Process msiexec.exe -ArgumentList @('/a', $Msi, '/qn', '/norestart', "TARGETDIR=$Destination") -Wait -PassThru
    if ($Process.ExitCode -ne 0) { throw "cannot extract MSI payload: $Msi" }
    # Administrative extraction copies the MSI container itself into TARGETDIR.
    # Compare installed payload entries, not that container copy; its package-level
    # bookkeeping is outside the normalized payload described by the release gate.
    return @(Get-ChildItem -LiteralPath $Destination -Recurse -Force | Where-Object { $_.FullName -ne $PackageCopy } | ForEach-Object {
        $Relative = [IO.Path]::GetRelativePath($Destination, $_.FullName).Replace('\', '/')
        $Type = if ($_.PSIsContainer) { "directory" } elseif ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { "reparse" } else { "file" }
        $Hash = if ($Type -eq "file") { (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant() } else { "-" }
        $Link = if ($_.LinkTarget) { $_.LinkTarget } else { "-" }
        $Acl = Get-Acl -LiteralPath $_.FullName
        "$Relative type=$Type hash=$Hash Attributes=$([int]$_.Attributes) link=$Link Sddl=$($Acl.Sddl)"
    } | Sort-Object)
}

$FirstManifest = Expand-And-Manifest $First "first"
$SecondManifest = Expand-And-Manifest $Second "second"
$Difference = Compare-Object $FirstManifest $SecondManifest
if ($Difference) { $Difference | Format-Table | Out-String | Write-Error; throw "unsigned MSI payloads differ" }
Write-Output "unsigned MSI normalized payloads are reproducible"
