#requires -Version 5.1
<#
.SYNOPSIS
    Installs the Proton VPN change-server patcher: copies the script to a stable
    location and registers a scheduled task that re-applies the patch at logon
    and every 30 minutes (so client updates are patched automatically).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$TaskName = 'ProtonVPN ChangeServer Patcher'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting elevation..."
    Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit $LASTEXITCODE
}

$installDir = Join-Path $env:LOCALAPPDATA 'ProtonChangeServerPatcher'
$dst = Join-Path $installDir 'Set-ProtonChangeServerPatch.ps1'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Force -Path (Join-Path $PSScriptRoot 'Set-ProtonChangeServerPatch.ps1') -Destination $dst

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dst`" -Action Patch"
$trigger = @(
    New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 3650)
)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Scheduled task '$TaskName' registered (logon + every 30 minutes)."

Write-Host "Applying patch now..."
& $dst -Action Patch
Write-Host "Done. Logs: $installDir\patcher.log"
