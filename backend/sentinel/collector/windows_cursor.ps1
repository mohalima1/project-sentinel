function Get-SentinelStartRecord([long]$After, [long]$Newest, [bool]$HasCursor, [bool]$Reset) {
    if ($Reset) { return [long]0 }
    if (-not $HasCursor) { return [long][Math]::Max(0, $Newest - 200) }
    return $After
}
