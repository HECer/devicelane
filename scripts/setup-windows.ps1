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
$ServiceTaskName = "DeviceLane Service-$CurrentUserSid"
$ServiceDeployDir = Join-Path $env:LOCALAPPDATA "DeviceLane\service\bin"
$ServiceIdentityDir = Join-Path $env:LOCALAPPDATA "DeviceLane\service\identity"
$ServiceRuntimeDir = Join-Path $env:LOCALAPPDATA "DeviceLane\service\runtime"
$ServiceLogDir = Join-Path $env:LOCALAPPDATA "DeviceLane\service\logs"

for ($Index = 0; $Index -lt $args.Count; $Index++) {
    switch ($args[$Index]) {
        "--controller-install" { $Mode = "install" }
        "--controller-status" { $Mode = "status" }
        "--controller-uninstall" { $Mode = "uninstall" }
        "--service-install" { $Mode = "service-install" }
        "--service-repair" { $Mode = "service-install" }
        "--service-status" { $Mode = "service-status" }
        "--service-autostart-enable" { $Mode = "service-autostart-enable" }
        "--service-autostart-disable" { $Mode = "service-autostart-disable" }
        "--service-logs" { $Mode = "service-logs" }
        "--service-uninstall" { $Mode = "service-uninstall" }
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

function Invoke-ServiceActivation($ExistingTask, $Operations) {
    $NewRegistered = $false
    try {
        & ($Operations["StageBinary"])
        if ($null -ne $ExistingTask) { & ($Operations["StopOld"]) }
        & ($Operations["ActivateBinary"])
        $NewRegistered = $true
        & ($Operations["RegisterNew"])
        & ($Operations["StartNew"])
        if ((& ($Operations["GetState"])) -ne "Running") {
            throw "new DeviceLane service task did not remain running"
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
                if ((& ($Operations["GetState"])) -ne "Running") { $RollbackErrors.Add("previous service task did not return to Running") }
            } catch { $RollbackErrors.Add("verify previous task: $_") }
        } else {
            try { & ($Operations["VerifyAbsent"]) } catch { $RollbackErrors.Add("verify failed task removal: $_") }
        }
        try { & ($Operations["CleanupStage"]) } catch { $RollbackErrors.Add("clean staged binary: $_") }
        try { & ($Operations["CleanupFailedVersion"]) } catch { $RollbackErrors.Add("clean failed binary: $_") }
        if ($RollbackErrors.Count -gt 0) { Write-Warning "service activation failed; rollback issues: $($RollbackErrors -join '; ')" }
        throw $ActivationError
    }
}

if ($Mode -eq "service-status") {
    $ServiceTask = Get-ScheduledTask -TaskName $ServiceTaskName -ErrorAction SilentlyContinue
    if ($null -eq $ServiceTask) { Write-Output "DeviceLane service is not installed."; exit 1 }
    [pscustomobject]@{ Installed = $true; Running = $ServiceTask.State -eq "Running"; Autostart = $ServiceTask.State -ne "Disabled"; Logs = $ServiceLogDir } | Format-List
    exit 0
}
if ($Mode -eq "service-autostart-enable") { Enable-ScheduledTask -TaskName $ServiceTaskName | Out-Null; Start-ScheduledTask -TaskName $ServiceTaskName; exit 0 }
if ($Mode -eq "service-autostart-disable") { Stop-ScheduledTask -TaskName $ServiceTaskName -ErrorAction SilentlyContinue; Disable-ScheduledTask -TaskName $ServiceTaskName | Out-Null; exit 0 }
if ($Mode -eq "service-logs") { Write-Output $ServiceLogDir; exit 0 }
if ($Mode -eq "service-uninstall") {
    Stop-ScheduledTask -TaskName $ServiceTaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $ServiceTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $ServiceDeployDir -Filter "devicelane-service-*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Output "DeviceLane service removed. Identity and logs were preserved."
    exit 0
}
if ($Mode -eq "service-install") {
    Set-Location $Root
    cargo build --release --bin devicelane-service
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    New-Item -ItemType Directory -Force -Path $ServiceDeployDir, $ServiceIdentityDir, $ServiceRuntimeDir, $ServiceLogDir | Out-Null
    $ExistingServiceTask = Get-ScheduledTask -TaskName $ServiceTaskName -ErrorAction SilentlyContinue
    $ServiceBuildId = [guid]::NewGuid().ToString("N")
    $ServiceExe = Join-Path $ServiceDeployDir "devicelane-service-$ServiceBuildId.exe"
    $ServiceStage = "$ServiceExe.stage"
    $BuiltServiceExe = (Resolve-Path ".\target\release\devicelane-service.exe").Path
    $ServiceArguments = "--identity `"$ServiceIdentityDir`" --runtime-dir `"$ServiceRuntimeDir`" --log-dir `"$ServiceLogDir`" --role workstation --foreground"
    $ServiceAction = New-ScheduledTaskAction -Execute $ServiceExe -Argument $ServiceArguments
    $ServiceTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
    $ServicePrincipal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
    $ServiceSettings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    $ServiceOperations = @{
        StageBinary = { Copy-Item -LiteralPath $BuiltServiceExe -Destination $ServiceStage }
        StopOld = { Stop-ScheduledTask -TaskName $ServiceTaskName -ErrorAction Stop }
        ActivateBinary = { Move-Item -LiteralPath $ServiceStage -Destination $ServiceExe }
        RegisterNew = { Register-ScheduledTask -TaskName $ServiceTaskName -Action $ServiceAction -Trigger $ServiceTrigger -Principal $ServicePrincipal -Settings $ServiceSettings -Description "Per-user DeviceLane service" -Force | Out-Null }
        StartNew = { Start-ScheduledTask -TaskName $ServiceTaskName -ErrorAction Stop; Start-Sleep -Milliseconds 500 }
        GetState = { (Get-ScheduledTask -TaskName $ServiceTaskName -ErrorAction Stop).State.ToString() }
        StopFailedNew = { Stop-ScheduledTask -TaskName $ServiceTaskName -ErrorAction Stop }
        UnregisterFailedNew = { Unregister-ScheduledTask -TaskName $ServiceTaskName -Confirm:$false -ErrorAction Stop }
        VerifyAbsent = { if ($null -ne (Get-ScheduledTask -TaskName $ServiceTaskName -ErrorAction SilentlyContinue)) { throw "failed DeviceLane service task remains registered" } }
        RestoreOld = { param($OldTask); Register-ScheduledTask -InputObject $OldTask -TaskName $ServiceTaskName -Force | Out-Null }
        StartOld = { Start-ScheduledTask -TaskName $ServiceTaskName -ErrorAction Stop; Start-Sleep -Milliseconds 500 }
        CleanupStage = { if (Test-Path -LiteralPath $ServiceStage) { Remove-Item -LiteralPath $ServiceStage -Force } }
        CleanupFailedVersion = { if (Test-Path -LiteralPath $ServiceExe) { Remove-Item -LiteralPath $ServiceExe -Force } }
    }
    Invoke-ServiceActivation -ExistingTask $ExistingServiceTask -Operations $ServiceOperations
    Write-Output "DeviceLane service installed or repaired for $UserId."
    exit 0
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
