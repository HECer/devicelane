$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
New-Item -ItemType Directory -Force -Path ".mesh\registry", ".mesh\agent", ".mesh\cli", ".mesh\workspaces" | Out-Null
cargo build --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& ".\target\debug\mesh-cli.exe" doctor --identity ".mesh\cli"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
