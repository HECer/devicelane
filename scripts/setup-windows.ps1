$ErrorActionPreference = "Stop"

$TaskName = "DeviceLane Registry"
$Mode = "bootstrap"
$AgentPeer = $null
$ListenAddress = "0.0.0.0:7443"
$IdentityDir = Join-Path $env:LOCALAPPDATA "DeviceLane\registry\identity"
$LogDir = Join-Path $env:LOCALAPPDATA "DeviceLane\registry\logs"

for ($Index = 0; $Index -lt $args.Count; $Index++) {
    switch ($args[$Index]) {
        "--controller-install" { $Mode = "install" }
        "--controller-status" { $Mode = "status" }
        "--controller-uninstall" { $Mode = "uninstall" }
        "--agent-peer" {
            $Index++
            if ($Index -ge $args.Count) { throw "--agent-peer requires a value" }
            $AgentPeer = $args[$Index]
        }
        "--controller-listen" {
            $Index++
            if ($Index -ge $args.Count) { throw "--controller-listen requires a value" }
            $ListenAddress = $args[$Index]
        }
        "--controller-identity-dir" {
            $Index++
            if ($Index -ge $args.Count) { throw "--controller-identity-dir requires a value" }
            $IdentityDir = [System.IO.Path]::GetFullPath($args[$Index])
        }
        "--controller-log-dir" {
            $Index++
            if ($Index -ge $args.Count) { throw "--controller-log-dir requires a value" }
            $LogDir = [System.IO.Path]::GetFullPath($args[$Index])
        }
        default { throw "unknown option: $($args[$Index])" }
    }
}

if ($Mode -eq "status") {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $Task) {
        Write-Output "DeviceLane controller is not installed."
        exit 1
    }
    $Info = Get-ScheduledTaskInfo -TaskName $TaskName
    [pscustomobject]@{
        TaskName = $Task.TaskName
        State = $Task.State
        LastRunTime = $Info.LastRunTime
        LastTaskResult = $Info.LastTaskResult
        Command = $Task.Actions[0].Execute
        Arguments = $Task.Actions[0].Arguments
    } | Format-List
    exit 0
}

if ($Mode -eq "uninstall") {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $Task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Write-Output "DeviceLane controller task removed. Identity and logs were preserved."
    exit 0
}

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
New-Item -ItemType Directory -Force -Path ".mesh\registry", ".mesh\agent", ".mesh\cli", ".mesh\workspaces" | Out-Null
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& ".\target\debug\mesh-cli.exe" doctor --identity ".mesh\cli"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Mode -ne "install") { exit 0 }
if ([string]::IsNullOrWhiteSpace($AgentPeer)) { throw "--controller-install requires --agent-peer AGENT_PEER_ID" }
if ($AgentPeer -notmatch "^[A-Za-z0-9._:-]+$") { throw "invalid --agent-peer value" }
if ($ListenAddress -notmatch "^[A-Za-z0-9.:[\]-]+:[0-9]+$") { throw "invalid --controller-listen value" }

New-Item -ItemType Directory -Force -Path $IdentityDir, $LogDir | Out-Null
$RegistryExe = (Resolve-Path ".\target\debug\mesh-registry.exe").Path
$RegistryLog = Join-Path $LogDir "registry.log"

function ConvertTo-PowerShellLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

$RegistryCommand = "& $(ConvertTo-PowerShellLiteral $RegistryExe) --listen $(ConvertTo-PowerShellLiteral $ListenAddress) --identity $(ConvertTo-PowerShellLiteral $IdentityDir) --offline-after-ms 5000 --agent-peer $(ConvertTo-PowerShellLiteral $AgentPeer) *>> $(ConvertTo-PowerShellLiteral $RegistryLog)"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$RegistryCommand`""
$UserId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Per-user DeviceLane registry controller" | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Output "DeviceLane controller installed or repaired for $UserId."
Write-Output "Identity: $IdentityDir"
Write-Output "Logs: $LogDir"
Write-Output "Listen: $ListenAddress"
