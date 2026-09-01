$ErrorActionPreference = "Stop"

$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentUserSid = $CurrentIdentity.User.Value
$UserId = $CurrentIdentity.Name
$TaskName = "DeviceLane Registry-$CurrentUserSid"
$Root = Split-Path -Parent $PSScriptRoot
$DeployDir = Join-Path $env:LOCALAPPDATA "DeviceLane\registry\bin"
$DeployedRegistryExe = Join-Path $DeployDir "mesh-registry.exe"
$LegacyRegistryExe = Join-Path $Root "target\debug\mesh-registry.exe"
$Mode = "bootstrap"
$AgentPeer = $null
$ListenAddress = $null
$IdentityDir = $null
$LogDir = $null

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
        "--controller-identity" {
            $Index++
            if ($Index -ge $args.Count) { throw "--controller-identity requires a value" }
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

if ($Mode -eq "install") {
    foreach ($RequiredOption in @(
        @{ Name = "--agent-peer"; Value = $AgentPeer },
        @{ Name = "--controller-listen"; Value = $ListenAddress },
        @{ Name = "--controller-identity"; Value = $IdentityDir },
        @{ Name = "--controller-log-dir"; Value = $LogDir }
    )) {
        if ([string]::IsNullOrWhiteSpace($RequiredOption.Value)) {
            throw "--controller-install requires explicit $($RequiredOption.Name)"
        }
    }
    if ($AgentPeer -notmatch "^[A-Za-z0-9._:-]+$") { throw "invalid --agent-peer value" }
    if ($ListenAddress -notmatch "^[A-Za-z0-9.:[\]-]+:(?<port>[0-9]+)$") { throw "invalid --controller-listen value" }
    $ListenPort = 0
    if (-not [int]::TryParse($Matches.port, [ref]$ListenPort) -or $ListenPort -lt 1 -or $ListenPort -gt 65535) {
        throw "--controller-listen port must be between 1 and 65535"
    }
}

function Assert-CurrentUserTask($Task) {
    $PrincipalId = [string]$Task.Principal.UserId
    if ($PrincipalId -match "^S-[0-9-]+$") {
        $PrincipalSid = $PrincipalId
    } else {
        try {
            $PrincipalSid = ([System.Security.Principal.NTAccount]$PrincipalId).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            throw "refusing to manage a DeviceLane task with an unknown principal"
        }
    }
    if ($PrincipalSid -ine $CurrentUserSid) {
        throw "refusing to manage a DeviceLane task owned by another user"
    }
    if ([System.IO.Path]::GetFileName($Task.Actions[0].Execute) -ine "powershell.exe") {
        throw "refusing to manage a DeviceLane task with an unexpected action"
    }
    $Arguments = [string]$Task.Actions[0].Arguments
    $VersionedPathPattern = [regex]::Escape((Join-Path $DeployDir "mesh-registry-")) + "[0-9a-f]{32}\.exe"
    $OwnsDeployedPath = $Arguments -match $VersionedPathPattern
    $OwnsLegacyPath = $Arguments.IndexOf($LegacyRegistryExe, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    if (-not ($OwnsDeployedPath -or $OwnsLegacyPath)) {
        throw "refusing to manage a DeviceLane task outside this user's deployment"
    }
}

function Invoke-ControllerActivation($ExistingTask, $Operations) {
    $NewRegistered = $false
    try {
        & ($Operations["StageBinary"])
        if ($null -ne $ExistingTask) {
            & ($Operations["StopOld"])
        }
        & ($Operations["ActivateBinary"])
        & ($Operations["RegisterNew"])
        $NewRegistered = $true
        & ($Operations["StartNew"])
        if ((& ($Operations["GetState"])) -ne "Running") {
            throw "new DeviceLane controller task did not remain running"
        }
    } catch {
        $ActivationError = $_
        $RollbackErrors = [System.Collections.Generic.List[string]]::new()
        if ($NewRegistered) {
            try { & ($Operations["StopFailedNew"]) } catch { $RollbackErrors.Add("stop failed task: $_") }
            try { & ($Operations["UnregisterFailedNew"]) } catch { $RollbackErrors.Add("unregister failed task: $_") }
        }
        if ($null -ne $ExistingTask) {
            try { & ($Operations["RestoreOld"]) $ExistingTask } catch { $RollbackErrors.Add("restore previous definition: $_") }
            try { & ($Operations["StartOld"]) } catch { $RollbackErrors.Add("restart previous task: $_") }
            try {
                if ((& ($Operations["GetState"])) -ne "Running") {
                    $RollbackErrors.Add("previous task did not return to Running")
                }
            } catch {
                $RollbackErrors.Add("verify previous task: $_")
            }
        } else {
            try { & ($Operations["VerifyAbsent"]) } catch { $RollbackErrors.Add("verify failed task removal: $_") }
        }
        try { & ($Operations["CleanupStage"]) } catch { $RollbackErrors.Add("clean staged binary: $_") }
        try { & ($Operations["CleanupFailedVersion"]) } catch { $RollbackErrors.Add("clean failed binary: $_") }
        if ($RollbackErrors.Count -gt 0) {
            Write-Warning "controller activation failed; rollback issues: $($RollbackErrors -join '; ')"
        }
        throw $ActivationError
    }
}

if ($Mode -eq "status") {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $Task) {
        Write-Output "DeviceLane controller is not installed."
        exit 1
    }
    Assert-CurrentUserTask $Task
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
        Assert-CurrentUserTask $Task
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Write-Output "DeviceLane controller task removed. Identity and logs were preserved."
    exit 0
}

Set-Location $Root
New-Item -ItemType Directory -Force -Path ".mesh\registry", ".mesh\agent", ".mesh\cli", ".mesh\workspaces" | Out-Null
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& ".\target\debug\mesh-cli.exe" doctor --identity ".mesh\cli"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Mode -ne "install") { exit 0 }

New-Item -ItemType Directory -Force -Path $IdentityDir, $LogDir, $DeployDir | Out-Null
$BuildId = [guid]::NewGuid().ToString("N")
$StagedRegistryExe = Join-Path $DeployDir "mesh-registry-$BuildId.stage"
$DeployedRegistryExe = Join-Path $DeployDir "mesh-registry-$BuildId.exe"
$BuiltRegistryExe = (Resolve-Path ".\target\debug\mesh-registry.exe").Path
$RegistryLog = Join-Path $LogDir "registry.log"

function ConvertTo-PowerShellLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

$RegistryCommand = "& $(ConvertTo-PowerShellLiteral $DeployedRegistryExe) --listen $(ConvertTo-PowerShellLiteral $ListenAddress) --identity $(ConvertTo-PowerShellLiteral $IdentityDir) --offline-after-ms 5000 --agent-peer $(ConvertTo-PowerShellLiteral $AgentPeer) *>> $(ConvertTo-PowerShellLiteral $RegistryLog)"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$RegistryCommand`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask) {
    Assert-CurrentUserTask $ExistingTask
}
$Operations = @{
    StageBinary = { Copy-Item -LiteralPath $BuiltRegistryExe -Destination $StagedRegistryExe }
    StopOld = { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
    ActivateBinary = { Move-Item -LiteralPath $StagedRegistryExe -Destination $DeployedRegistryExe }
    RegisterNew = { Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "Per-user DeviceLane registry controller" -Force | Out-Null }
    StartNew = { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop; Start-Sleep -Milliseconds 500 }
    GetState = { (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State.ToString() }
    StopFailedNew = { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
    UnregisterFailedNew = { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
    VerifyAbsent = { if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { throw "failed DeviceLane task remains registered" } }
    RestoreOld = { param($OldTask); Register-ScheduledTask -InputObject $OldTask -TaskName $TaskName -Force | Out-Null }
    StartOld = { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop; Start-Sleep -Milliseconds 500 }
    CleanupStage = { if (Test-Path -LiteralPath $StagedRegistryExe) { Remove-Item -LiteralPath $StagedRegistryExe -Force } }
    CleanupFailedVersion = { if (Test-Path -LiteralPath $DeployedRegistryExe) { Remove-Item -LiteralPath $DeployedRegistryExe -Force } }
}
Invoke-ControllerActivation -ExistingTask $ExistingTask -Operations $Operations
$StartedTask = Get-ScheduledTask -TaskName $TaskName
Assert-CurrentUserTask $StartedTask
Write-Output "DeviceLane controller installed or repaired for $UserId."
Write-Output "Identity: $IdentityDir"
Write-Output "Logs: $LogDir"
Write-Output "Listen: $ListenAddress"
