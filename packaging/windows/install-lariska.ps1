<#
.SYNOPSIS
    Installs the Lariska endpoint inventory agent as a Windows service.

.DESCRIPTION
    Copies lariska.exe into Program Files, writes the configuration and the
    provisioning key into ProgramData with an ACL that admits only SYSTEM and
    the local Administrators group, then registers and starts the service via
    sc.exe. Re-running the script over an existing installation stops the
    service, replaces the binary and configuration, and starts it again; the
    state directory (agent identity and delivery spool) is left alone so a
    reinstall keeps the device's identity on the server.

.PARAMETER ServerUrl
    Base URL of the Shapoclyack API, e.g. https://shapoclyack.example.internal.

.PARAMETER ProvisioningKey
    Provisioning key minted for the tenant this endpoint belongs to.

.PARAMETER AllowPlainHttp
    Permit a plain-http ServerUrl. The agent refuses one otherwise, because the
    provisioning key and the inventory would cross the network in the clear.
    For a lab stand only.

.PARAMETER TlsCaFile
    PEM bundle for an internal CA terminating the API's TLS. Copied next to the
    configuration.

.EXAMPLE
    .\install-lariska.ps1 -ServerUrl https://shapoclyack.corp -ProvisioningKey pk_...

.EXAMPLE
    .\install-lariska.ps1 -ServerUrl http://192.168.68.115:8080 -ProvisioningKey pk_... -AllowPlainHttp
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ServerUrl,
    [Parameter(Mandatory = $true)][string] $ProvisioningKey,
    [switch] $AllowPlainHttp,
    [string] $TlsCaFile,
    [string] $SourceExe = (Join-Path $PSScriptRoot 'lariska.exe'),
    [string] $ServiceName = 'Lariska'
)

$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'Lariska'
$DataDir    = Join-Path $env:ProgramData 'Lariska'
$ConfigDir  = Join-Path $DataDir 'config'
$StateDir   = Join-Path $DataDir 'state'
$ConfigFile = Join-Path $ConfigDir 'lariska.toml'
$KeyFile    = Join-Path $ConfigDir 'provisioning.key'

function Write-Step([string] $Message) { Write-Host "==> $Message" }

# --- preconditions ----------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal] $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This installer must run from an elevated (Administrator) PowerShell.'
}

if (-not (Test-Path -LiteralPath $SourceExe)) {
    throw "lariska.exe not found at $SourceExe. Pass -SourceExe with its path."
}

if (-not $AllowPlainHttp -and -not $ServerUrl.StartsWith('https://')) {
    throw "ServerUrl must be https:// unless -AllowPlainHttp is given (got '$ServerUrl')."
}

if ($TlsCaFile -and -not (Test-Path -LiteralPath $TlsCaFile)) {
    throw "TLS CA bundle not found at $TlsCaFile."
}

# --- stop an existing service so the binary is not locked -------------------

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Stopping the existing '$ServiceName' service"
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

# --- directories ------------------------------------------------------------

Write-Step 'Creating directories'
foreach ($dir in @($InstallDir, $ConfigDir, $StateDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# The config holds the provisioning key and the state directory holds the
# delivery spool: both are readable only by SYSTEM and local Administrators,
# with inheritance switched off so a permissive ProgramData ACL cannot widen
# them back.
Write-Step 'Restricting ACLs on the data directories'
foreach ($dir in @($ConfigDir, $StateDir)) {
    & icacls.exe $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $dir (exit $LASTEXITCODE)." }
}

# --- files ------------------------------------------------------------------

Write-Step "Installing the binary into $InstallDir"
Copy-Item -LiteralPath $SourceExe -Destination (Join-Path $InstallDir 'lariska.exe') -Force

Write-Step 'Writing the provisioning key'
# -NoNewline: the agent reads the file as the key, and a trailing newline would
# be part of it.
Set-Content -LiteralPath $KeyFile -Value $ProvisioningKey -NoNewline -Encoding ascii

$caLine = ''
if ($TlsCaFile) {
    $installedCa = Join-Path $ConfigDir 'ca.pem'
    Copy-Item -LiteralPath $TlsCaFile -Destination $installedCa -Force
    $caLine = "tls_ca_file = '$installedCa'"
}

$plainHttpLine = ''
if ($AllowPlainHttp) { $plainHttpLine = 'allow_plain_http = true' }

Write-Step 'Writing the configuration'
$config = @"
# Written by install-lariska.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').
# See packaging/windows/lariska.example.toml for every supported key.
server_url = "$ServerUrl"
provisioning_key_file = '$KeyFile'
state_dir = '$StateDir'
inventory_interval_secs = 3600
heartbeat_interval_secs = 60
request_timeout_secs = 30
log_level = "info"
$plainHttpLine
$caLine
"@
Set-Content -LiteralPath $ConfigFile -Value $config -Encoding utf8

# --- validate before handing the service a config it will reject ------------

Write-Step 'Validating the configuration'
& (Join-Path $InstallDir 'lariska.exe') check-config --config $ConfigFile
if ($LASTEXITCODE -ne 0) { throw "check-config rejected $ConfigFile (exit $LASTEXITCODE)." }

# --- service ----------------------------------------------------------------

if (-not $existing) {
    Write-Step "Registering the '$ServiceName' service"
    # sc.exe wants the space after each `name=`; PowerShell keeps them as
    # separate arguments, which is what it parses.
    & sc.exe create $ServiceName binPath= "`"$(Join-Path $InstallDir 'lariska.exe')`" --winservice" start= auto DisplayName= 'Lariska Endpoint Agent' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed (exit $LASTEXITCODE)." }
    & sc.exe description $ServiceName 'Cross-platform endpoint inventory agent for Shapoclyack' | Out-Null
}

Write-Step 'Starting the service'
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

Write-Host ''
Write-Host "Lariska is installed and running against $ServerUrl."
Write-Host "  binary  $InstallDir\lariska.exe"
Write-Host "  config  $ConfigFile"
Write-Host "  state   $StateDir"
Write-Host ''
Write-Host 'Service log lines go to the Application event log, source "Lariska".'
Write-Host 'To read the most recent ones:'
Write-Host '  Get-WinEvent -LogName Application -MaxEvents 40 |'
Write-Host '    Where-Object ProviderName -eq "Lariska" | Format-List TimeCreated, Message'
