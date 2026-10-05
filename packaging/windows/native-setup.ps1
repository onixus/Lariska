param([Parameter(Mandatory=$true)][string]$InstallDir, [switch]$Remove)
$ErrorActionPreference = 'Stop'
if ($Remove) {
    Stop-ScheduledTask -TaskName 'LariskaUpdater' -ErrorAction SilentlyContinue
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName 'LariskaUpdater' -ErrorAction SilentlyContinue).State -eq 'Running') {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Lariska updater did not stop before removal' }
        Start-Sleep -Milliseconds 100
    }
    Unregister-ScheduledTask -TaskName 'LariskaUpdater' -Confirm:$false -ErrorAction SilentlyContinue
    exit 0
}
function Protect-Directory([string]$Path, [bool]$AgentWrite = $false) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point refused: $Path" }
        $existing = Get-Acl -LiteralPath $Path
        $ownerSid = $existing.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Untrusted directory owner: $Path" }
        foreach ($ace in $existing.Access) {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            $writes = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
            if ($ace.AccessControlType -eq 'Allow' -and ($ace.FileSystemRights -band $writes) -and $sid -notin @('S-1-5-18', 'S-1-5-32-544') -and -not ($AgentWrite -and $sid -eq 'S-1-5-19')) { throw "Untrusted writable directory: $Path" }
        }
    } else { New-Item -ItemType Directory -Path $Path | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $access = if ($AgentWrite) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')), $access, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-Directory "$env:ProgramData\Lariska"
Protect-Directory "$env:ProgramData\Lariska\config"
Protect-Directory "$env:ProgramData\Lariska\state" $true
Protect-Directory "$env:ProgramData\LariskaUpdater"
$stable = "$env:ProgramData\LariskaUpdater\supervisor.exe"
if (Test-Path -LiteralPath $stable) {
    if ((Get-Item -LiteralPath $stable -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Stable supervisor must be a regular file' }
} else { Copy-Item -LiteralPath "$InstallDir\lariska-updater.exe" -Destination $stable }
# This private watchdog is deliberately never replaced by an endpoint update.
# Its process must survive the MSI transaction that replaces lariska.exe.
if (-not (Get-ScheduledTask -TaskName 'LariskaUpdater' -ErrorAction SilentlyContinue)) {
    $action = New-ScheduledTaskAction -Execute $stable -Argument 'update-supervisor --config "C:\ProgramData\Lariska\config\lariska.toml"'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'LariskaUpdater' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}
# Enrollment, rollback seeding, and starting both components are admin actions.

& "$env:SystemRoot\System32\sc.exe" failure Lariska reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure Lariska service failure recovery' }
& "$env:SystemRoot\System32\sc.exe" failureflag Lariska 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure Lariska service failure reporting' }
