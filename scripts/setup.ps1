$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    & uv sync --locked --python 3.12
    if ($LASTEXITCODE -ne 0) { throw 'Python environment setup failed.' }
    & npm.cmd --prefix frontend ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    & npm.cmd --prefix frontend run build
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard build failed.' }

    # Restrict only this project's data directory, never an arbitrary parent.
    $dataDirectory = Join-Path $projectRoot 'data'
    New-Item -ItemType Directory -Force -Path $dataDirectory | Out-Null
    $dataAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $dataAcl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $dataAcl.SetOwner($currentUser)
    foreach ($identity in @($currentUser.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($identity)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )
        $dataAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $dataDirectory -AclObject $dataAcl
    if ($env:SENTINEL_DATABASE_PATH) {
        Write-Warning 'Custom database path set: restrict its directory permissions separately.'
    }
    & uv run --locked alembic upgrade head
    if ($LASTEXITCODE -ne 0) { throw 'Database migration failed.' }
    & uv run --locked python -m sentinel.collector --provision
    if ($LASTEXITCODE -ne 0) { throw 'Collector credential provisioning failed.' }
    Write-Host 'Setup complete. Double-click Start-Sentinel.cmd to open your dashboard.'
    Write-Host 'No registration or password is required for local launcher access.'
} finally {
    Pop-Location
}
