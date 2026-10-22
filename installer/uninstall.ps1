[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Retain','Remove')][string]$Data)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) { throw 'Uninstall requires an elevated PowerShell.' }
$destination = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'Project Sentinel'))
$config = Get-Content -LiteralPath (Join-Path $destination 'installation.json') -Raw | ConvertFrom-Json
$expectedBackend = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Project Sentinel\data'))
$expectedCollector = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Project Sentinel\collector'))
# Never recursively delete a configurable/computed target without exact allowlist checks.
if ([IO.Path]::GetFullPath($config.backend_data) -ne $expectedBackend -or
    [IO.Path]::GetFullPath($config.collector_data) -ne $expectedCollector -or
    $destination -ne (Join-Path $env:ProgramFiles 'Project Sentinel')) { throw 'Unexpected installation paths; no deletion performed.' }
if ((Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse point.' }
$service = Get-Service -Name ProjectSentinelCollector -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name ProjectSentinelCollector
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
    & sc.exe delete ProjectSentinelCollector | Out-Null
    if ($LASTEXITCODE) { throw 'Service removal failed.' }
}
if ($Data -eq 'Remove') {
    foreach ($directory in @($expectedBackend,$expectedCollector)) {
        if (Test-Path -LiteralPath $directory) {
            if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse point.' }
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
    }
}
# Launch this script from the extracted package, not the directory being removed.
if ($PSScriptRoot -eq $destination) { throw 'Run uninstall.ps1 from the extracted package so installed files can be removed.' }
Remove-Item -LiteralPath $destination -Recurse -Force
Write-Host "Removed Sentinel binaries/service. Data choice: $Data. Source workspace data is untouched."
