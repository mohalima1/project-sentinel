param(
    [ValidateSet('System','Security','Microsoft-Windows-TaskScheduler/Operational',
      'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-Sysmon/Operational',
      'services','tasks','startup','administrators','software','audit_policy')][string]$Source,
    [long]$After = 0, [string]$AnchorHash = '', [switch]$HasCursor
)
. (Join-Path $PSScriptRoot 'windows_cursor.ps1')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ProgressPreference = 'SilentlyContinue'
function Hash-Text([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Read-Events([string]$Filter, [int]$Limit = 100) {
    try { return @(Get-WinEvent -LogName $Source -FilterXPath $Filter -Oldest -MaxEvents $Limit -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}
try {
    $items = @{}
    switch ($Source) {
        'services' {
            Get-CimInstance Win32_Service | ForEach-Object {
                $items[$_.Name] = @{Name=$_.Name; DisplayName=$_.DisplayName; PathName=$_.PathName;
                    StartMode=$_.StartMode; StartName=$_.StartName}
            }
        }
        'tasks' {
            Get-ScheduledTask | Sort-Object TaskPath,TaskName | ForEach-Object {
                $key = $_.TaskPath + $_.TaskName
                $items[$key] = @{TaskName=$_.TaskName; TaskPath=$_.TaskPath;
                    Xml=(Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath)}
            }
        }
        'administrators' {
            Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
                $items[$_.SID.Value] = @{SID=$_.SID.Value; Name=$_.Name; ObjectClass=$_.ObjectClass;
                    PrincipalSource=[string]$_.PrincipalSource}
            }
        }
        'startup' {
            foreach ($hive in @('HKLM:','HKCU:')) {
                foreach ($relative in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')) {
                    $path = "$hive\$relative"
                    if (Test-Path -LiteralPath $path) {
                        $key = Get-Item -LiteralPath $path
                        foreach ($name in $key.GetValueNames()) {
                            $items["$path\$name"] = @{Location=$path; Name=$name; Command=[string]$key.GetValue($name)}
                        }
                    }
                }
            }
            foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
                if ($folder -and (Test-Path -LiteralPath $folder)) {
                    Get-ChildItem -LiteralPath $folder -File | ForEach-Object {
                        $items[$_.FullName] = @{Path=$_.FullName; SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}
                    }
                }
            }
        }
        'software' {
            foreach ($hive in @('HKLM:','HKCU:')) {
                foreach ($relative in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                    $path = "$hive\$relative"
                    if (Test-Path -LiteralPath $path) {
                        Get-ChildItem -LiteralPath $path | ForEach-Object {
                            $p = Get-ItemProperty -LiteralPath $_.PSPath
                            if ($p.DisplayName) {
                                $items[$_.Name] = @{Name=$p.DisplayName; Version=$p.DisplayVersion;
                                    Publisher=$p.Publisher; InstallLocation=$p.InstallLocation; RegistryKey=$_.Name}
                            }
                        }
                    }
                }
            }
        }
        'audit_policy' {
            $oldPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            $raw = & "$env:SystemRoot\System32\auditpol.exe" /get /category:* /r 2>&1
            $ErrorActionPreference = $oldPreference
            if ($LASTEXITCODE -ne 0) { throw "auditpol query failed: $($raw -join ' ')" }
            @{status='available'; raw=($raw -join "`n"); note='Read-only audit policy query; inspect required subcategories. Sentinel does not change audit settings.'} | ConvertTo-Json -Depth 8 -Compress
            exit 0
        }
        default {
            $info = Get-WinEvent -ListLog $Source
            if (-not $info.IsEnabled) {
                @{status='disabled'; error='Windows channel is disabled; Sentinel does not enable it.'} | ConvertTo-Json -Compress
                exit 0
            }
            $old = @(Read-Events '*' 1)
            if (-not $old.Count) {
                @{status='available'; oldest=0; newest=0; anchor=$null; events=@(); start_record=0} | ConvertTo-Json -Compress
                exit 0
            }
            $latest = Get-WinEvent -LogName $Source -MaxEvents 1
            $oldest = [long]$old[0].RecordId
            $newest = [long]$latest.RecordId
            $anchor = $null
            if ($After -gt 0) {
                $found = @(Read-Events "*[System[EventRecordID=$After]]" 1)
                if ($found.Count) { $anchor = $found[0].ToXml() }
            }
            $reset = ($After -gt $newest) -or ($anchor -and $AnchorHash -and ((Hash-Text $anchor) -ne $AnchorHash))
            $start = Get-SentinelStartRecord -After $After -Newest $newest -HasCursor ([bool]$HasCursor) -Reset ([bool]$reset)
            $events = @(Read-Events "*[System[EventRecordID > $start]]" 100 | ForEach-Object { $_.ToXml() })
            @{status='available'; oldest=$oldest; newest=$newest; anchor=$anchor; reset=[bool]$reset;
                start_record=($start+1); events=$events} | ConvertTo-Json -Depth 12 -Compress
            exit 0
        }
    }
    @{status='available'; items=$items; identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;
        scope='Machine plus current collector user profile; other users profiles are not enumerated.'} | ConvertTo-Json -Depth 16 -Compress
} catch {
    $message = $_.Exception.Message
    $status = 'error'
    if ($_.Exception -is [UnauthorizedAccessException] -or $message -match 'access.*denied|unauthorized|privilege|0x00000522') { $status='denied' }
    elseif ($_.FullyQualifiedErrorId -match 'NoMatchingLogsFound|CommandNotFoundException') { $status='unavailable' }
    @{status=$status; error=$message; error_id=$_.FullyQualifiedErrorId} | ConvertTo-Json -Depth 4 -Compress
}
