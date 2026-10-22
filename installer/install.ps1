# Run elevated in a disposable Windows VM until lifecycle acceptance is complete.
[CmdletBinding()]
param([string]$ImportDataDirectory)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    throw 'Run installation from an elevated PowerShell under the intended dashboard user.'
}
$destination = Join-Path $env:ProgramFiles 'Project Sentinel'
$backendData = Join-Path $env:LOCALAPPDATA 'Project Sentinel\data'
$collectorData = Join-Path $env:ProgramData 'Project Sentinel\collector'
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($PSScriptRoot -eq $destination) { throw 'Run install.ps1 from an extracted package, outside Program Files.' }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
foreach ($file in $manifest) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $file.path))
    if (-not $candidate.StartsWith($PSScriptRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest path.' }
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne $file.sha256) { throw "Package integrity failure: $($file.path)" }
}
$service = Get-Service -Name ProjectSentinelCollector -ErrorAction SilentlyContinue
if ($service) { Stop-Service -Name ProjectSentinelCollector; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90)) }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
foreach ($file in Get-ChildItem -LiteralPath $PSScriptRoot) {
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Recurse -Force
}
# Protect all privileged executable/config paths, including upgrades to a preexisting directory.
& icacls.exe $destination /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null
if ($LASTEXITCODE) { throw 'Installation ACL failed.' }
foreach ($directory in @($backendData,$collectorData)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
& icacls.exe $backendData /inheritance:r /grant:r "*$($ownerSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE) { throw 'Backend data ACL failed.' }
& icacls.exe $collectorData /inheritance:r /grant:r "*$($ownerSid):(OI)(CI)RX" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE) { throw 'Collector state ACL failed.' }
if ($ImportDataDirectory) {
    if (Test-Path -LiteralPath (Join-Path $backendData 'sentinel.db')) { throw 'Existing installed accounts preserved; import refused because a database already exists.' }
    foreach ($name in @('sentinel.db','ingestion.json')) {
        Copy-Item -LiteralPath (Join-Path $ImportDataDirectory $name) -Destination $backendData
    }
}
$env:SENTINEL_DATABASE_PATH = Join-Path $backendData 'sentinel.db'
$env:SENTINEL_RESOURCE_ROOT = Join-Path $destination 'app'
$runtime = Join-Path $destination 'runtime\python.exe'
if (Test-Path -LiteralPath $env:SENTINEL_DATABASE_PATH) {
    # SQLite's backup API makes a consistent private upgrade backup, even with read activity.
    & $runtime -I -c 'import os,sqlite3; p=os.environ["SENTINEL_DATABASE_PATH"]; a=sqlite3.connect(p); b=sqlite3.connect(p+".pre-upgrade.db"); a.backup(b); b.close(); a.close()'
    if ($LASTEXITCODE) { throw 'Database backup failed.' }
}
Push-Location -LiteralPath (Join-Path $destination 'app')
try {
    & $runtime -I -m alembic upgrade head
    if ($LASTEXITCODE) { throw 'Database upgrade failed; backup retained.' }
    & $runtime -I -m sentinel.collector --provision --data-dir $backendData
    if ($LASTEXITCODE) { throw 'Credential provisioning failed.' }
} finally { Pop-Location }
@{backend_data=$backendData; collector_data=$collectorData; owner_sid=$ownerSid} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'installation.json') -Encoding UTF8
if (-not $service) {
    New-Service -Name ProjectSentinelCollector -BinaryPathName ('"' + (Join-Path $destination 'SentinelService.exe') + '"') -StartupType Automatic -DisplayName 'Project Sentinel read-only collector' | Out-Null
}
& sc.exe failure ProjectSentinelCollector reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
if ($LASTEXITCODE) { throw 'Service recovery setup failed.' }
Start-Service -Name ProjectSentinelCollector
Write-Host "Installed. Run $destination\Start-Sentinel.cmd from a normal, unelevated session."
Write-Host 'The collector service buffers while the dashboard is closed; a full queue pauses collection.'
Write-Host 'Use Get-Service ProjectSentinelCollector for status. No auditing settings were changed.'
