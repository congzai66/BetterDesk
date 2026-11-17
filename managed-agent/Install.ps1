param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$DeviceId,
    [Parameter(Mandatory=$true)][string]$DeviceToken,
    [string]$RustDeskPath = "$env:ProgramFiles\RustDesk\rustdesk.exe",
    [string]$BinaryPath = "$PSScriptRoot\BetterDeskManagedAgent.exe",
    [string]$InstallDir = "$env:ProgramFiles\BetterDesk",
    [string]$TLSCAFile = ""
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated Administrator PowerShell.'
}
if ($ServerUrl -notlike 'wss://*') { throw 'ServerUrl must use wss:// so passwords are never sent over plaintext WebSocket.' }
foreach ($path in @($BinaryPath, $RustDeskPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file not found: $path" }
}
$DataDir = "$env:ProgramData\BetterDesk"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
$TargetBinary = Join-Path $InstallDir 'betterdesk-managed-agent.exe'
Copy-Item -LiteralPath $BinaryPath -Destination $TargetBinary -Force
$Config = [ordered]@{
    server_url = $ServerUrl
    device_id = $DeviceId
    device_token = $DeviceToken
    rustdesk_path = $RustDeskPath
    state_path = (Join-Path $DataDir 'managed-state.json')
}
if ($TLSCAFile) {
    if (-not (Test-Path -LiteralPath $TLSCAFile -PathType Leaf)) { throw "TLS CA file not found: $TLSCAFile" }
    $Config.tls_ca_file = $TLSCAFile
}
$ConfigPath = Join-Path $DataDir 'managed-agent.json'
$ConfigJson = $Config | ConvertTo-Json
[System.IO.File]::WriteAllText($ConfigPath, $ConfigJson, (New-Object System.Text.UTF8Encoding($false)))

# Administrators and SYSTEM only: the config contains a device credential.
icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

& $TargetBinary -install -config $ConfigPath
if ($LASTEXITCODE -ne 0) { throw "Agent service installation failed with exit code $LASTEXITCODE" }
Write-Host "BetterDesk managed credential agent installed for device $DeviceId."
Write-Host 'Do not enable RustDesk disable-change-permanent-password on managed endpoints.'
