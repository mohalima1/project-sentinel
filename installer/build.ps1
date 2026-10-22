# Reproducible dependency/runtime inputs; outputs are unsigned development packages.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $root 'artifacts\packages'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bundle = Join-Path $buildRoot "Sentinel-$stamp"
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
Push-Location -LiteralPath $root
try {
    & uv sync --locked --python 3.12.13
    if ($LASTEXITCODE) { throw 'Locked environment failed.' }
    & npm.cmd --prefix frontend ci
    if ($LASTEXITCODE) { throw 'Frontend install failed.' }
    & npm.cmd --prefix frontend run build
    if ($LASTEXITCODE) { throw 'Frontend build failed.' }
    $pythonInfo = & .\.venv\Scripts\python.exe -c 'import sys,json; print(json.dumps(dict(base=sys.base_prefix,version=list(sys.version_info[:3]))))'
    if ($LASTEXITCODE) { throw 'Cannot locate Python runtime.' }
    $pythonInfo = $pythonInfo | ConvertFrom-Json
    if (($pythonInfo.version -join '.') -ne '3.12.13') { throw 'Package requires exact Python 3.12.13.' }
    Copy-Item -LiteralPath $pythonInfo.base -Destination (Join-Path $bundle 'runtime') -Recurse
    $runtime = Join-Path $bundle 'runtime\python.exe'
    $requirements = Join-Path $bundle 'requirements.lock'
    & uv export --locked --no-dev --no-emit-project --format requirements-txt --output-file $requirements
    if ($LASTEXITCODE) { throw 'Dependency export failed.' }
    & uv pip install --python $runtime --require-hashes --no-deps --break-system-packages -r $requirements
    if ($LASTEXITCODE) { throw 'Runtime dependency install failed.' }
    $package = Join-Path $bundle 'runtime\Lib\site-packages\sentinel'
    Get-ChildItem -LiteralPath (Join-Path $root 'backend\sentinel') -Recurse -File |
        Where-Object { $_.Extension -in @('.py', '.ps1') } | ForEach-Object {
            $relative = $_.FullName.Substring((Join-Path $root 'backend\sentinel').Length + 1)
            $destination = Join-Path $package $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destination
        }
    $app = Join-Path $bundle 'app'
    New-Item -ItemType Directory -Path (Join-Path $app 'frontend') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'frontend\dist') -Destination (Join-Path $app 'frontend\dist') -Recurse
    Copy-Item -LiteralPath (Join-Path $root 'migrations') -Destination (Join-Path $app 'migrations') -Recurse
    Copy-Item -LiteralPath (Join-Path $root 'alembic.ini') -Destination $app
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'installed_launch.py') -Destination $app
    foreach ($name in @('install.ps1','uninstall.ps1','README.md')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $bundle
    }
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $bundle
    Copy-Item -LiteralPath (Join-Path $root 'uv.lock') -Destination $bundle
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /optimize /target:exe /platform:x64 "/out:$bundle\SentinelService.exe" /reference:System.ServiceProcess.dll /reference:System.Web.Extensions.dll (Join-Path $PSScriptRoot 'SentinelService.cs')
    if ($LASTEXITCODE) { throw 'Service host compilation failed.' }
    '@echo off', '"%~dp0runtime\python.exe" -I "%~dp0app\installed_launch.py"', 'if errorlevel 1 pause' |
        Set-Content -LiteralPath (Join-Path $bundle 'Start-Sentinel.cmd') -Encoding ASCII
    $manifest = Get-ChildItem -LiteralPath $bundle -Recurse -File | ForEach-Object {
        @{ path=$_.FullName.Substring($bundle.Length+1); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    }
    ConvertTo-Json -InputObject @($manifest) -Depth 3 | Set-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Encoding UTF8
    Compress-Archive -LiteralPath $bundle -DestinationPath "$bundle.zip" -CompressionLevel Optimal
    Write-Host "Built unsigned Windows x64 package: $bundle.zip"
    Write-Host 'Install/service/reboot/upgrade/uninstall require disposable VM acceptance before release.'
} finally { Pop-Location }
exit 0
