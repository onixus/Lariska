<#
.SYNOPSIS
    Removes the Lariska Windows service and its binary.

.DESCRIPTION
    Stops and deletes the service and removes the install directory. The data
    directory is kept by default: it holds the agent identity, so a reinstall
    keeps reporting as the same device instead of appearing as a second one.
    Pass -PurgeData to remove it as well.

.EXAMPLE
    .\uninstall-lariska.ps1

.EXAMPLE
    .\uninstall-lariska.ps1 -PurgeData
#>
[CmdletBinding()]
param(
    [switch] $PurgeData,
    [string] $ServiceName = 'Lariska'
)

$ErrorActionPreference = 'Stop'

$InstallDir = Join-Path $env:ProgramFiles 'Lariska'
$DataDir    = Join-Path $env:ProgramData 'Lariska'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal] $identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must run from an elevated (Administrator) PowerShell.'
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Write-Host "==> Stopping '$ServiceName'"
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Write-Host "==> Deleting the '$ServiceName' service"
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed (exit $LASTEXITCODE)." }
} else {
    Write-Host "==> No '$ServiceName' service registered; nothing to stop"
}

if (Test-Path -LiteralPath $InstallDir) {
    Write-Host "==> Removing $InstallDir"
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

if ($PurgeData) {
    if (Test-Path -LiteralPath $DataDir) {
        Write-Host "==> Removing $DataDir (identity, config and spool)"
        Remove-Item -LiteralPath $DataDir -Recurse -Force
    }
} elseif (Test-Path -LiteralPath $DataDir) {
    Write-Host "==> Keeping $DataDir (pass -PurgeData to remove the agent identity too)"
}

Write-Host ''
Write-Host 'Lariska is uninstalled.'
