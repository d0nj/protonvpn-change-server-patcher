#requires -Version 5.1
<#
.SYNOPSIS
    Removes the scheduled task and, with -Restore, restores the original
    Proton VPN client assembly.
#>
[CmdletBinding()]
param(
    [switch]$Restore
)

$ErrorActionPreference = 'Stop'
$TaskName = 'ProtonVPN ChangeServer Patcher'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting elevation..."
    Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", $(if ($Restore) { '-Restore' }))
    exit $LASTEXITCODE
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Scheduled task '$TaskName' removed."

$dst = Join-Path $env:LOCALAPPDATA 'ProtonChangeServerPatcher\Set-ProtonChangeServerPatch.ps1'
if (Test-Path $dst) {
    if ($Restore) {
        & $dst -Action Restore
    } else {
        Write-Host "Client assembly left as-is. Run with -Restore to undo the patch."
    }
}
